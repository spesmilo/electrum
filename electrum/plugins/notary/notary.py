#!/usr/bin/env python
#
# Electrum - Lightweight Bitcoin Client
# Copyright (C) 2022 Thomas Voegtlin
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.


"""
Todo:
  - reorgs: use child tx
  - use leveldb
"""

import os, time
import attr, json
import asyncio
import random
from functools import partial
from contextlib import asynccontextmanager

import electrum_ecc as ecc
import electrum_aionostr as aionostr

from electrum.util import log_exceptions, ignore_exceptions, MyEncoder, UserFacingException
from electrum.invoices import PR_PAID
from electrum.crypto import sha256
from electrum.plugin import BasePlugin, hook
from electrum.logging import Logger
from electrum.bitcoin import DUST_LIMIT_P2WSH
from electrum.bitcoin import construct_script, opcodes, redeem_script_to_address, address_to_script, construct_witness
from electrum.transaction import PartialTxInput, PartialTxOutput, TxOutpoint, PartialTransaction, Transaction
from electrum.json_db import JsonDB, StoredDict, StoredObject
from electrum.lnutil import hex_to_bytes
from electrum.fee_policy import FeePolicy
from electrum.lnsweep import SweepInfo
from electrum import constants

from typing import TYPE_CHECKING, List, Dict

def round_up_division(a: int, b:int) -> int:
    return int(a // b) + (a % b > 0)

def is_power_of_two(x):
    return x == pow(2, x.bit_length() - 1)

def node_hash(left, right):
    return sha256(b"Node:" + left + right)

def leaf_hash(event_id:str, rhash:bytes, pubkey:bytes):
    return sha256(b"Leaf:" + bytes.fromhex(event_id) + rhash + (pubkey if pubkey else b''))

def make_output_script(csv_delay, root_hash: bytes) -> bytes:
    redeem_script = construct_script([csv_delay, opcodes.OP_CHECKSEQUENCEVERIFY, opcodes.OP_DROP, root_hash, opcodes.OP_DROP, opcodes.OP_TRUE])
    address = redeem_script_to_address('p2wsh', redeem_script)
    scriptpubkey = address_to_script(address)
    return redeem_script, scriptpubkey


PROOF_VERSION = 0
FAST_INTERVAL = 5
SLOW_INTERVAL = 60
MIN_FEE = DUST_LIMIT_P2WSH

@attr.s
class NotarizationRequest(StoredObject):
    event_id  = attr.ib(type=str)
    rhash     = attr.ib(type=bytes, converter=hex_to_bytes)
    log_fee   = attr.ib(type=int)
    pubkey    = attr.ib(type=bytes, converter=hex_to_bytes)
    signature = attr.ib(type=bytes, converter=hex_to_bytes)
    confirmed_txid = attr.ib(type=bool)
    txids = attr.ib(type=str) # unconfirmed, sequence

    def fee_sats(self):
        return pow(2, self.log_fee) if self.log_fee is not None else 0

    def leaf_hash(self):
        return leaf_hash(self.event_id, self.rhash, self.pubkey)


@attr.s
class Proof(StoredObject):
    hashes     = attr.ib(type=bytes, converter=hex_to_bytes)
    index      = attr.ib(type=int)   # position in merkle tree

    def get_root(self, leaf: bytes) -> bytes:
        assert type(leaf) is bytes
        h = leaf
        j = self.index
        for h2 in self.get_hashes():
            h = node_hash(h, h2) if j%2 == 0 else node_hash(h2, h)
            j = j >> 1
        return h

    def get_hashes(self) -> list:
        return [self.hashes[i:i+32] for i in range(0, len(self.hashes), 32)]


class Tree(dict):

    def get_root(self):
        h, p = list(self.items())[0]
        h = bytes.fromhex(h)
        return p.get_root(h)


class NotaryDB(JsonDB):

    def __init__(self, config):
        self.config = config
        data = self.read()
        JsonDB.__init__(
            self, data,
            encoder=MyEncoder,
        )
        self.data = StoredDict(self.data, self)

    @property
    def storage_path(self):
        return os.path.join(self.config.path, "notary_db")

    def read(self):
        if not os.path.exists(self.storage_path):
            return '{}'
        with open(self.storage_path, "r", encoding='utf-8') as f:
            return f.read()

    def write(self):
        s = self.dump()
        with open(self.storage_path, "w", encoding='utf-8') as f:
            f.write(s)

    def _convert_dict_value(self, path, v):
        key = path[-1]
        if key == 'requests':
            v = dict((k, NotarizationRequest(**x)) for k, x in v.items())
        if key == 'mempool':
            v = dict((k, (b, Transaction(c)) ) for k, (b,c) in v.items())
        if len(path) > 1 and path[-2] == 'proofs':
            v = dict((k, Proof(**x) ) for k, x in v.items())
        if isinstance(v, dict):
            v = self._convert_dict(path, v)
        return v



class Notary(Logger):

    def __init__(self, config, wallet):
        Logger.__init__(self)
        self.wallet = wallet
        self.config = config
        self.config.WALLET_SPEND_CONFIRMED_ONLY = False
        self.config.WALLET_COIN_CHOOSER_OUTPUT_ROUNDING = False
        self.db = NotaryDB(self.config)
        self.requests = self.db.get_dict('requests')
        self.proofs = self.db.get_dict('proofs')     # rhash -> txid -> proof
        self.roots = self.db.get_dict('roots')       # txid -> csv, index, roots
        self.mempool = self.db.get_dict('mempool')   # txid -> (rhashes, tx)
        print("mempol", list(self.mempool.keys()))
        xpub = self.wallet.keystore.get_master_public_key()  # type: str
        privkey = sha256('notary:' + xpub)
        pubkey = ecc.ECPrivkey(privkey).get_public_key_bytes()[1:]
        self.nostr_privkey = privkey.hex()
        self.nostr_pubkey = pubkey.hex()
        self.logger.info(f'nostr pubkey: {self.nostr_pubkey}')
        self.publish_queue = asyncio.Queue()
        self.last_time = 0

    def notary_fee(self, amount_sat):
        if amount_sat <= 8:
            return amount_sat
        elif amount_sat <= 32:
            return amount_sat // 2
        elif amount_sat <= 256:
            return amount_sat // 4
        else:
            return amount_sat // 8

    def add_request(self, event_id: str, fee:int, pubkey:str = None, signature:str = None):
        log_fee = fee.bit_length() - 1
        if fee != pow(2, log_fee):
            raise UserFacingException('fee must be a power of 2')
        if pubkey is not None:
            pubkey = bytes.fromhex(pubkey)
            signature = bytes.fromhex(signature)
            ecc.verify_signature(pubkey, signature, 'Upvote:' + event_id + ':%d'%fee)
        # payment request for the notary
        total = fee + self.notary_fee(fee)
        req_key = self.wallet.create_request(amount_sat=total, exp_delay=3600, message=event_id, address=None)
        payment_request = self.wallet.get_request(req_key)
        assert payment_request.payment_hash == bytes.fromhex(req_key)
        request = NotarizationRequest(
            event_id       = event_id,
            rhash          = payment_request.payment_hash,
            pubkey         = pubkey,
            signature      = signature,
            log_fee        = log_fee,
            confirmed_txid = None,
            txids          = "",
        )
        self.requests[req_key] = request
        self.db.write()
        r = self.wallet.export_request(payment_request)
        return {
            'invoice': r['lightning_invoice'],
            'rhash': r['rhash'],
        }

    def get_forest_root(self, roots: dict) -> bytes:
        root_hash = bytes(32)
        K = max(roots.keys())
        for i in range(K+1):
            _hash = roots.get(i) or bytes(32)
            root_hash = sha256(root_hash + _hash)
        return root_hash

    async def verify_proof(self, proof) -> int:
        """ return the burnt amount and number of confirmations """
        # 1. verify that the hash of the leaf is in the root of the tree
        event_id = proof["event_id"]
        rhash = bytes.fromhex(proof["rhash"])
        pubkey = bytes.fromhex(proof.get("pubkey") or "")
        leaf = leaf_hash(event_id, rhash, pubkey)
        hashes = ''.join(proof["hashes"])
        index = proof["index"]
        p = Proof(hashes=hashes, index=index)
        roots = dict([(int(k), bytes.fromhex(v)) for k, v in proof["roots"].items()])
        root = p.get_root(leaf)
        for k, v in roots.items():
            if root == v:
                break
        else:
            raise UserFacingException("Leaf not in root hash")
        proof_length = len(hashes) // 64
        leaf_value = pow(2, k - proof_length)
        #print(f'root value: {pow(2, k)}, proof_length: {proof_length}, leaf_value: {leaf_value}')
        # 2. verify that the transaction is in the blockchain (or mempool if blockheight is 0)
        outpoint = proof["outpoint"]
        txid, out_index = outpoint.split(':')
        out_index = int(out_index)
        tx = await self.wallet.network.get_transaction(txid)
        if not tx:
            raise UserFacingException("Transaction not found")
        tx = Transaction(tx)
        tx_mined_status = self.wallet.adb.get_tx_height(txid)
        height = tx_mined_status.height()
        proof_height = proof["block_height"]
        if proof_height and height != proof_height:
            raise UserFacingException(f"Block height mismatch {height} != {proof_height}")
        # fixme: add tx for performance
        #self.wallet.adb.add_transaction(tx, allow_unrelated=True)
        # 3. verify that the scriptpubkey of one tx output commits to the root hash of the Merkle forest
        root_hash = self.get_forest_root(roots)
        csv_delay = proof["csv_delay"]
        redeem_script, scriptpubkey = make_output_script(csv_delay, root_hash)
        txo = tx.outputs()[out_index]
        if txo.scriptpubkey != scriptpubkey:
            raise UserFacingException("Root hash not in transaction")
        # 4. verify that the amount burnt by the tx equals the sum of tree roots
        assert txo.value == sum([pow(2, k) for k in roots.keys()])
        return {"leaf_value":leaf_value, "confirmations": tx_mined_status.conf, "total_value": txo.value}

    async def sweep(self, proof):
        outpoint = proof["outpoint"]
        txid, out_index = outpoint.split(':')
        out_index = int(out_index)
        tx = await self.wallet.network.get_transaction(txid)
        if not tx:
            raise UserFacingException("Transaction not found")
        tx = Transaction(tx)
        txo = tx.outputs()[out_index]
        roots = dict([(int(k), bytes.fromhex(v)) for k, v in proof["roots"].items()])
        csv_delay = proof["csv_delay"]
        root_hash = self.get_forest_root(roots)
        redeem_script, scriptpubkey = make_output_script(csv_delay, root_hash)
        prevout = TxOutpoint(txid=bytes.fromhex(txid), out_idx=0)
        txin = PartialTxInput(prevout=prevout)
        txin._trusted_value_sats = txo.value
        txin.witness_script = redeem_script
        txin.nsequence = csv_delay
        txin.script_sig = b''
        txin.privkey = sha256(b'42') # dummy privkey
        txin.make_witness = lambda x: construct_witness([redeem_script])
        sweep_info = SweepInfo(
            txin=txin,
            cltv_abs=None,
            txout=None,
            name='local_anchor',
            can_be_batched=True,
        )
        self.wallet.txbatcher.add_sweep_input('notary', sweep_info)


    def get_proof(self, rhash_hex: str):
        try:
            request = self.requests[rhash_hex]
        except KeyError:
            raise UserFacingException("Request not found")
        if self.wallet.lnworker.get_payment_status(request.rhash) != PR_PAID:
            raise UserFacingException("Waiting for payment")
        txid = request.confirmed_txid
        if not txid and request.txids:
            txid = request.txids[-64:]
        if not txid:
            raise UserFacingException("Transaction not broadcast yet")
        proof = self.proofs[rhash_hex][txid]
        leaf = request.leaf_hash()
        csv_delay, out_index, roots = self.roots[txid]
        root = proof.get_root(leaf).hex()
        assert root in roots.values()
        tx_mined_status = self.wallet.adb.get_tx_height(txid)
        height = max(0, tx_mined_status.height())
        r = {}
        r["version"] = PROOF_VERSION
        r["chain"] = constants.net.rev_genesis_bytes().hex()
        r["index"] = proof.index
        r["hashes"] = [h.hex() for h in proof.get_hashes()]
        r["event_id"] = request.event_id
        r["rhash"] = rhash_hex
        r["outpoint"] = txid + ':%d'%out_index
        r["roots"] = roots
        r["block_height"] = height
        r["csv_delay"] = csv_delay
        if request.pubkey:
            r["pubkey"] = request.pubkey.hex()
            r["signature"] = request.signature.hex()
        return r

    def create_tree(self, requests) -> Tree:
        """ total amount in requests must be a power of two
        """
        target_fee = int(sum(r.fee_sats() for r in requests))
        assert target_fee == pow(2, target_fee.bit_length() - 1)
        requests.reverse()
        N = len(requests)
        #print(f"creating new tree {target_fee} with {N} requests")#, [t.fee_sats() for t in requests])
        # create array of leafs hashes
        _hashes = {} # height -> hashes

        leafs = set()
        # K is the height of the tree
        K = target_fee.bit_length() - requests[0].log_fee
        L = requests[0].log_fee
        #print(f"K={K}")
        for k in range(K, 0, -1):
            _hashes[k] = []
            # if we are not at the highest level, hash items from upper level
            if k < K:
                upper = _hashes[k+1]
                for i in range(len(upper)//2):
                    h = node_hash(upper[2*i], upper[2*i+1])
                    _hashes[k].append(h)
            # add leaves from our list of requests
            if requests:
                while requests and requests[0].log_fee == L:
                    request, requests = requests[0], requests[1:]
                    leaf = request.leaf_hash()
                    _hashes[k].append(leaf)
                    leafs.add(leaf)

            #print(f"hashes at k={k}: {len(_hashes[k])}")
            L = L + 1

        # we are done
        assert requests == []
        assert len(_hashes[1]) == 1
        root = _hashes[1][0]
        # extract proof for each leaf
        tree = Tree()
        for k in range(K, 1, -1):
            #print("level k=", k, len(_hashes[k]))
            for i, h in enumerate(_hashes[k]):
                # skip inner nodes
                if h not in leafs:
                    continue
                index = i
                proof_hashes = b''
                j = index
                for kk in range(k, 1, -1):
                    neighbor = j + 1 if j % 2 == 0 else j - 1
                    proof_hashes += _hashes[kk][neighbor]
                    j = j >> 1
                assert j == 0
                #print(f"found leaf {h.hex()} at {(k, i)}. index={index}, proof length={len(proof)}")
                #print(f"proof: {[x.hex() for x in proof]}")
                #assert h == root
                p = Proof(proof_hashes, index)
                assert p.get_root(h) == root
                tree[h.hex()] = p

        if K == 1:
            tree[root.hex()] = Proof(b'', 0)

        #assert len(tree) == N
        return tree

    def get_unprocessed_requests(self):
        requests = self.requests.values()
        # filter requests that are already in our forest
        def is_not_processed(request):
            return request.confirmed_txid is None
        requests = list(filter(is_not_processed, requests))
        # filter out unpaid requests
        requests = list(filter(lambda x: self.wallet.lnworker.get_payment_status(x.rhash) == PR_PAID, requests))
        # sort by fee
        requests = sorted(requests, key=lambda x: -x.fee_sats())
        new = [r for r in requests if len(r.txids) == 0]
        if not new:
            # nothing to do
            return
        # decide whether it is economical to wait more
        notary_fees = sum([self.notary_fee(r.fee_sats()) for r in new])
        cost = 153
        r = min(notary_fees, cost)
        interval = (r * FAST_INTERVAL + (cost - r) * SLOW_INTERVAL) // cost
        now = int(time.time())
        delta_time = now - self.last_time
        if delta_time < interval:
            return
        print(f'notary_fees: {notary_fees} interval: {interval}')
        self.last_time = now
        return requests

    def create_forest(self, requests)-> Dict[int, dict]:
        """ build Merkle forest from requests """
        assert len(requests) > 0
        requests = requests[::] # copy, because we will side effect it
        total_fee = int(sum(r.fee_sats() for r in requests))
        # the fee of each request will be a power of two.
        subsidy = max(0, MIN_FEE - total_fee)
        # break the subsidy into powers of two
        subsidies = []
        while subsidy:
            log_fee = subsidy.bit_length() - 1
            r = NotarizationRequest(
                event_id  = random.randbytes(32).hex(),
                rhash     = random.randbytes(32),
                pubkey    = None,
                signature = None,
                log_fee   = log_fee,
                confirmed_txid = None,
                txids      = "",
            )
            requests.append(r)
            v = pow(2, log_fee)
            subsidy -= v
            subsidies.append(v)
        requests = sorted(requests, key=lambda x: -x.fee_sats())
        print(f"create_forest: {len(requests)} requests, {total_fee} sats. subsidy: {sum(subsidies)}")
        forest = {}
        total_fee = int(sum(r.fee_sats() for r in requests))
        while total_fee:
            level = total_fee.bit_length() - 1
            target = pow(2, level)
            #print(f"level {level} target {target}")
            # pick requests so that their sum is a power of two
            s = 0
            subset = []
            for r in requests:
                s += r.fee_sats()
                subset.append(r)
                assert s <= target
                if s == target:
                    requests = requests[len(subset):]
                    break
            else:
                continue
            total_fee -= target
            tree = self.create_tree(subset)
            forest[level] = tree
        return forest

    def create_new_tx(self, coin, root_hash, value, fee_policy:FeePolicy, csv_delay):
        redeem_script, scriptpubkey = make_output_script(csv_delay, root_hash)
        output = PartialTxOutput(
            scriptpubkey=scriptpubkey,
            value=value,
        )
        tx = self.wallet.make_unsigned_transaction(
            coins=[coin],
            outputs=[output],
            rbf=True,
            fee_policy=fee_policy,
        )
        self.wallet.sign_transaction(tx, None)
        for i, txo in enumerate(tx.outputs()):
            if txo == output:
                break
        else:
            raise
        return tx, i

    def get_parent_coin(self):
        # pick confirmed coin, large enough
        coins = self.wallet.get_spendable_coins(nonlocal_only=True)
        if not coins:
            raise Exception('not enough funds')
        maxv = max(c.value_sats() for c in coins)
        for coin in coins:
            if coin.value_sats() == maxv:
                break
        else:
            raise Exception('not enough funds')
        return coin

    def get_change_utxo(self, tx):
        assert len(tx.outputs()) == 2
        for i, o in enumerate(tx.outputs()):
            if o.address is not None:
                break
        else:
            raise Exception()
        prevout = TxOutpoint(txid=bytes.fromhex(tx.txid()), out_idx=i)
        utxo = PartialTxInput(prevout=prevout, is_coinbase_output=False)
        utxo._trusted_address = o.address
        utxo._trusted_value_sats = o.value
        return utxo

    def prune_verified(self):
        # prune verified tx and all its parents
        requests = []
        mempool_keys = list(self.mempool.keys())
        for txid in mempool_keys:
            tx_mined_status = self.wallet.adb.get_tx_height(txid)
            if tx_mined_status.height() > 0:
                print('pruning mempool')
                indices, tx = self.mempool[txid]
                change = self.get_change_utxo(tx) # we will use it for next tx
                self.mempool.clear() #pop(txid)
                self.db.put('last_txid', None)
                # mark requests as processed:
                for rhash in indices:
                    r = self.requests[rhash]
                    r.confirmed_txid = txid
                    r.txids = "" # todo: cleanup db
                    requests.append(r)
                break
        return requests

    def create_tx(self, forest, csv_delay):
        """create a single tx with the current forest"""
        last_txid = self.db.get('last_txid')
        if last_txid is None:
            coin = self.get_parent_coin() #
            fee_policy = FeePolicy('feerate:%d'%self.config.NOTARY_FEERATE)
        else:
            relay_feerate = self.wallet.relayfee()
            _, rbf_tx = self.mempool[last_txid]
            rbf_tx = PartialTransaction.from_tx(rbf_tx) # rm existing signatures
            rbf_tx.add_info_from_wallet(self.wallet)#, ignore_network_issues=False)
            assert len(rbf_tx.inputs()) == 1
            coin = rbf_tx.inputs()[0]
            current_fee = rbf_tx.get_fee()
            vsize = rbf_tx.estimated_size()
            # we are not going to increase vsize
            extra_fee = round_up_division(relay_feerate * vsize, 1000)
            new_fee = current_fee + extra_fee
            self.logger.info(f"tx size: {vsize}; extra fee: {extra_fee}")
            fee_policy = FeePolicy('fixed:%d'%new_fee)

        value = sum([pow(2, k) for k in forest.keys()])
        root_hash = self.get_forest_hash(forest)
        tx, index = self.create_new_tx(coin, root_hash, value, fee_policy=fee_policy, csv_delay=csv_delay)
        return tx, index

    def get_forest_hash(self, forest):
        root_hash = bytes(32)
        K = max(forest.keys())
        for i in range(K+1):
            tree = forest.get(i)
            _hash = tree.get_root() if tree else bytes(32)
            root_hash = sha256(root_hash + _hash)
        return root_hash

    def save_proofs(self, forest, requests, txid, out_index, csv_delay):
        indices = [x.rhash.hex() for x in requests]
        for rhash in indices:
            r = self.requests[rhash]
            leaf = r.leaf_hash().hex()
            # get proof from forest
            for k, tree in forest.items():
                if leaf in tree:
                    proof = tree[leaf]
                    break
            else:
                raise Exception()
            r.txids += txid
            if rhash not in self.proofs:
                self.proofs[rhash] = {}
            self.proofs[rhash][txid] = proof
            self.roots[txid] = csv_delay, out_index, dict([(k, tree.get_root().hex()) for k, tree in forest.items()])

    async def publish_proof(self, request, relay_manager):
        rhash_hex = request.rhash.hex()
        proof = self.get_proof(rhash_hex)
        json_proof = json.dumps(proof, cls=MyEncoder)
        # the first value of a single letter tag is indexed and can be filtered for
        tags = [
            ['e', request.event_id],      # event id
            ['p', request.pubkey],        # event pubkey
            ['v', str(request.fee_sats())],  # upvote value in satoshis
            ['expiration', str(int(time.time() + 60))], # only if unconfirmed
            #['d', rhash_hex],
        ]
        try:
            event_id = await aionostr._add_event(
                relay_manager,
                kind=30021, # addressable
                tags=tags,
                content=json_proof,
                private_key=self.nostr_privkey)
        except asyncio.TimeoutError as e:
            self.logger.info(f"failed to publish proof: {rhash_hex}")
            return

    @asynccontextmanager
    async def nostr_manager(self):
        manager_logger = self.logger.getChild('aionostr')
        manager_logger.setLevel("INFO")  # set to INFO because DEBUG is very spammy
        async with aionostr.Manager(
                relays=self.config.NOSTR_RELAYS.split(','),
                private_key=self.nostr_privkey,
                proxy=None,
                log=manager_logger
        ) as manager:
            yield manager

    @log_exceptions
    async def publish_proofs(self):
        async with self.nostr_manager() as relay_manager:
            await relay_manager.connect()
            self.logger.info(f'nostr is connected')
            connected_relays = relay_manager.relays
            print(f'connected relays: {[relay.url for relay in connected_relays]}')
            while True:
                request = await self.publish_queue.get()
                await self.publish_proof(request, relay_manager)

    @log_exceptions
    async def run(self):
        while True:
            await asyncio.sleep(1)
            verified = self.prune_verified()
            for r in verified:
                self.publish_queue.put_nowait(r)
            requests = self.get_unprocessed_requests()
            if not requests:
                continue
            indices = [x.rhash.hex() for x in requests]
            forest = self.create_forest(requests)
            print(f"forest: {list(sorted(forest.keys()))}")
            csv_delay = self.config.NOTARY_CSV_DELAY
            tx, out_index = self.create_tx(forest, csv_delay)
            txid = tx.txid()
            print(f'new tx: {txid}')
            self.save_proofs(forest, requests, txid, out_index, csv_delay)
            self.mempool[txid] = indices, tx
            self.db.put('last_txid', txid)
            self.db.write()
            #self.wallet.save_db()
            if not await self.wallet.network.try_broadcasting(tx, 'level'):
                print('could not broadcast tx', tx.txid())
            for r in requests:
                self.publish_queue.put_nowait(r)

