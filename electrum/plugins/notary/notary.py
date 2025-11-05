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
from electrum.bitcoin import construct_script, opcodes, redeem_script_to_address, address_to_script, construct_witness, make_op_return
from electrum.transaction import PartialTxInput, PartialTxOutput, TxOutpoint, PartialTransaction, Transaction
from electrum.json_db import JsonDB, StoredDict, StoredObject
from electrum.lnutil import hex_to_bytes
from electrum.fee_policy import FeePolicy
from electrum.lnsweep import SweepInfo
from electrum import constants

from typing import TYPE_CHECKING, List, Dict

def round_up_division(a: int, b:int) -> int:
    return int(a // b) + (a % b > 0)

def int_to_bytes(x: int) -> bytes:
    assert type(x) == int
    return x.to_bytes(8, 'big')

def bytes_to_int(x: bytes) -> int:
    assert type(x) == bytes
    assert len(x) == 8
    return int.from_bytes(x, 'big')

def node_hash(left_h, left_v:int, right_h, right_v:int):
    return sha256(b"Node:" + left_h + int_to_bytes(left_v) + right_h + int_to_bytes(right_v))

def leaf_hash(event_id:str, value:int, rhash:bytes, pubkey:bytes):
    return sha256(b"Leaf:" + bytes.fromhex(event_id) + int_to_bytes(value) + rhash + (pubkey if pubkey else b''))

def make_output_script(csv_delay: int) -> bytes:
    redeem_script = construct_script([csv_delay, opcodes.OP_CHECKSEQUENCEVERIFY, opcodes.OP_DROP, opcodes.OP_TRUE])
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
    value     = attr.ib(type=int)
    pubkey    = attr.ib(type=bytes, converter=hex_to_bytes)
    signature = attr.ib(type=bytes, converter=hex_to_bytes)
    confirmed_txid = attr.ib(type=bool)
    txids = attr.ib(type=str) # unconfirmed, sequence

    def leaf_hash(self):
        return leaf_hash(self.event_id, self.value, self.rhash, self.pubkey)


@attr.s
class Proof(StoredObject):
    hashes     = attr.ib(type=bytes, converter=hex_to_bytes)
    values     = attr.ib(type=bytes, converter=hex_to_bytes)
    index      = attr.ib(type=int)   # position in merkle tree

    def get_root(self, leaf_h: bytes, leaf_v:int) -> bytes:
        h, v = leaf_h, leaf_v
        j = self.index
        for h2, v2 in self.get_hashes():
            h = node_hash(h, v, h2, v2) if j%2 == 0 else node_hash(h2, v2, h, v)
            v += v2
            j = j >> 1
        return h, v

    def get_hashes(self) -> list:
        N = len(self.hashes)//32
        assert N*32 == len(self.hashes)
        assert N*8 == len(self.values)
        return [(self.hashes[i*32:(i+1)*32], bytes_to_int(self.values[i*8:(i+1)*8])) for i in range(N)]


class Tree(dict):

    def get_root(self):
        k, proof = list(self.items())[0]
        h, v = k
        return proof.get_root(h, v)


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
        self.roots = self.db.get_dict('roots')       # txid -> root_hash, root_value
        self.mempool = self.db.get_dict('mempool')   # txid -> (rhashes, tx)
        print("mempool", list(self.mempool.keys()))
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

    def add_request(self, event_id: str, value:int, pubkey:str = None, signature:str = None):
        if pubkey is not None:
            pubkey = bytes.fromhex(pubkey)
            signature = bytes.fromhex(signature)
            ecc.verify_signature(pubkey, signature, 'Upvote:' + event_id + ':%d'%value)
        # payment request for the notary
        total_amount = value + self.notary_fee(value)
        req_key = self.wallet.create_request(amount_sat=total_amount, exp_delay=3600, message=event_id, address=None)
        payment_request = self.wallet.get_request(req_key)
        assert payment_request.payment_hash == bytes.fromhex(req_key)
        request = NotarizationRequest(
            event_id       = event_id,
            rhash          = payment_request.payment_hash,
            pubkey         = pubkey,
            signature      = signature,
            value          = value,
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

    def parse_tx(self, tx):
        tx = Transaction(tx)
        for txo in tx.outputs():
            if txo.scriptpubkey.startswith(bytes([opcodes.OP_RETURN])):
                data = txo.scriptpubkey[2:]
                root_hash = data[0:32]
                csv_delay = bytes_to_int(data[32:])
                break
        else:
            raise Exception('op_return output not found')

        redeem_script, scriptpubkey = make_output_script(csv_delay)
        for i, txo in enumerate(tx.outputs()):
            if txo.scriptpubkey == scriptpubkey:
                break
        else:
            raise Exception('burn output not found')
        return root_hash, csv_delay, txo, i, redeem_script

    async def verify_proof(self, proof) -> int:
        """ return the burnt amount and number of confirmations """
        # 1. verify that the hash of the leaf is in the root of the tree
        event_id = proof["event_id"]
        rhash = bytes.fromhex(proof["rhash"])
        pubkey = bytes.fromhex(proof.get("pubkey") or "")
        leaf_value = proof["leaf_value"]
        leaf_h = leaf_hash(event_id, leaf_value, rhash, pubkey)
        hashes = b''
        values = b''
        for x in proof["merkle_hashes"]:
            h, v = x.split(':')
            hashes += bytes.fromhex(h)
            values += int_to_bytes(int(v))
        index = proof["merkle_index"]
        p = Proof(hashes=hashes, values=values, index=index)
        root_hash, root_v = p.get_root(leaf_h, leaf_value)
        # 2. verify that the transaction is in the blockchain (or mempool if blockheight is 0)
        txid = proof["txid"]
        tx = await self.wallet.network.get_transaction(txid)
        if not tx:
            raise UserFacingException("Transaction not found")
        _root_hash, csv_delay, txo, index, redeem_script = self.parse_tx(tx)
        if _root_hash != root_hash:
            raise UserFacingException('root mismatch')
        # 4. verify that the amount burnt by the tx equals the sum of tree roots
        if txo.value != root_v:
            raise UserFacingException('value mismatch')
        tx_mined_status = self.wallet.adb.get_tx_height(txid)
        height = tx_mined_status.height()
        proof_height = proof["block_height"]
        if proof_height and height != proof_height:
            raise UserFacingException(f"Block height mismatch {height} != {proof_height}")
        # fixme: add tx for performance
        #self.wallet.adb.add_transaction(tx, allow_unrelated=True)
        return {"confirmations": tx_mined_status.conf, "output_value": txo.value, "csv_delay":csv_delay, "root_hash":root_hash.hex()}

    async def sweep(self, txid):
        tx = await self.wallet.network.get_transaction(txid)
        if not tx:
            raise UserFacingException("Transaction not found")
        _root_hash, csv_delay, txo, index, redeem_script = self.parse_tx(tx)
        tx_mined_status = self.wallet.adb.get_tx_height(txid)
        conf = tx_mined_status.conf
        if conf < csv_delay:
            raise UserFacingException(f"CSV not reached {conf=} < {csv_delay=}")
        prevout = TxOutpoint(txid=bytes.fromhex(txid), out_idx=index)
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
            name='notary',
            can_be_batched=True,
            dust_override=True,
        )
        self.wallet.txbatcher.add_sweep_input('notary', sweep_info)
        return prevout.to_str()

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
        root_h, root_v = self.roots[txid]
        assert bytes.fromhex(root_h), root_v == proof.get_root(leaf)
        #assert root in roots.values()
        tx_mined_status = self.wallet.adb.get_tx_height(txid)
        height = max(0, tx_mined_status.height())
        r = {}
        r["version"] = PROOF_VERSION
        r["chain"] = constants.net.rev_genesis_bytes().hex()
        r["merkle_index"] = proof.index
        r["merkle_hashes"] = [h.hex()+':%d'%v for (h, v) in proof.get_hashes()]
        r["event_id"] = request.event_id
        r["rhash"] = rhash_hex
        r["txid"] = txid
        r["leaf_value"] = request.value
        r["block_height"] = height
        if request.pubkey:
            r["pubkey"] = request.pubkey.hex()
            r["signature"] = request.signature.hex()
        return r

    def create_tree(self, requests)-> Dict[int, dict]:
        """ build Merkle forest from requests """
        assert len(requests) > 0
        requests = requests[::] # copy, because we will side effect it
        total_value = int(sum(r.value for r in requests))
        # the fee of each request will be a power of two.
        subsidy = max(0, MIN_FEE - total_value)
        # break the subsidy into powers of two
        if subsidy:
            r = NotarizationRequest(
                event_id  = random.randbytes(32).hex(),
                rhash     = random.randbytes(32),
                pubkey    = None,
                signature = None,
                value     = subsidy,
                confirmed_txid = None,
                txids      = "",
            )
            requests.append(r)
        requests = sorted(requests, key=lambda x: -x.value)
        requests.reverse()
        # number of requests
        N = len(requests)
        # height of the tree
        K = (N-1).bit_length()
        print(f"create_tree: {K=}, {N} requests, {total_value} sats. subsidy: {subsidy}")
        assert pow(2, K) - N >= 0
        # create array of leafs hashes
        _hashes = {} # height -> list of hashes
        _hashes[K] = [(r.leaf_hash(), r.value) for r in requests]
        _hashes[K] += [(bytes(32), 0)] * (pow(2, K) - N)

        for k in range(K-1, -1, -1):
            _hashes[k] = []
            # if we are not at the highest level, hash items from upper level
            upper = _hashes[k+1]
            for i in range(len(upper)//2):
                left_h, left_v = upper[2*i]
                right_h, right_v = upper[2*i+1]
                h = node_hash(left_h, left_v, right_h, right_v)
                value = left_v + right_v
                _hashes[k].append((h, value))

        # we are done
        assert len(_hashes[0]) == 1
        root = _hashes[0][0]
        root_h, root_v = root
        # extract proof for each leaf
        tree = Tree()
        for i, leaf in enumerate(_hashes[K]):
            index = i
            proof_hashes = b''
            proof_v = b''
            j = index
            for kk in range(K, 0, -1):
                neighbor = j + 1 if j % 2 == 0 else j - 1
                h, v = _hashes[kk][neighbor]
                proof_hashes += h
                proof_v += int_to_bytes(v)
                j = j >> 1
            assert j == 0
            #print(f"found leaf {h.hex()} at {(k, i)}. index={index}, proof length={len(proof)}")
            #print(f"proof: {[x.hex() for x in proof]}")
            #assert h == root
            p = Proof(proof_hashes, proof_v, index)
            leaf_h, leaf_v = leaf
            assert p.get_root(leaf_h, leaf_v) == (root_h, root_v)
            tree[(leaf_h, leaf_v)] = p

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
        requests = sorted(requests, key=lambda x: -x.value)
        new = [r for r in requests if len(r.txids) == 0]
        if not new:
            # nothing to do
            return
        # decide whether it is economical to wait more
        notary_fees = sum([self.notary_fee(r.value) for r in new])
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

    def create_new_tx(self, coin, root_hash, value, fee_policy:FeePolicy, csv_delay):
        redeem_script, scriptpubkey = make_output_script(csv_delay)
        outputs = [
            PartialTxOutput(
                scriptpubkey=scriptpubkey,
                value=value,
            ),
            PartialTxOutput(
                scriptpubkey=make_op_return(root_hash + int_to_bytes(csv_delay)),
                value=0,
            ),
        ]
        tx = self.wallet.make_unsigned_transaction(
            coins=[coin],
            outputs=outputs,
            rbf=True,
            fee_policy=fee_policy,
        )
        self.wallet.sign_transaction(tx, None)
        return tx

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
        #assert len(tx.outputs()) == 2
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

    def create_tx(self, tree, csv_delay):
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

        #value = sum([pow(2, k) for k in forest.keys()])
        root_hash, value = tree.get_root()
        tx = self.create_new_tx(coin, root_hash, value, fee_policy=fee_policy, csv_delay=csv_delay)
        return tx

    def save_proofs(self, tree, requests, txid, csv_delay):
        indices = [x.rhash.hex() for x in requests]
        for rhash in indices:
            r = self.requests[rhash]
            leaf = r.leaf_hash()
            value = r.value
            # get proof from forest
            if (leaf, value) in tree:
                proof = tree[(leaf, value)]
            else:
                raise Exception()
            r.txids += txid
            if rhash not in self.proofs:
                self.proofs[rhash] = {}
            self.proofs[rhash][txid] = proof
            root_h, root_value = tree.get_root()
            self.roots[txid] = root_h.hex(), root_value

    async def publish_proof(self, request, relay_manager):
        rhash_hex = request.rhash.hex()
        proof = self.get_proof(rhash_hex)
        json_proof = json.dumps(proof, cls=MyEncoder)
        # the first value of a single letter tag is indexed and can be filtered for
        tags = [
            ['e', request.event_id],      # event id
            ['p', request.pubkey],        # event pubkey
            ['v', str(request.value)],  # upvote value in satoshis
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
            tree = self.create_tree(requests)
            csv_delay = self.config.NOTARY_CSV_DELAY
            tx = self.create_tx(tree, csv_delay)
            txid = tx.txid()
            print(f'new tx: {txid}')
            self.save_proofs(tree, requests, txid, csv_delay)
            self.mempool[txid] = indices, tx
            self.db.put('last_txid', txid)
            self.db.write()
            #self.wallet.save_db()
            if not await self.wallet.network.try_broadcasting(tx, 'level'):
                print('could not broadcast tx', tx.txid())
            for r in requests:
                self.publish_queue.put_nowait(r)

