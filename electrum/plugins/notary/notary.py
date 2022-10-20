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
import os, time
import attr, json
import asyncio
import random
from functools import partial

import electrum_ecc as ecc
import electrum_aionostr as aionostr

from electrum.util import log_exceptions, ignore_exceptions, MyEncoder, UserFacingException
from electrum.invoices import PR_PAID
from electrum.crypto import sha256
from electrum.plugin import BasePlugin, hook
from electrum.logging import Logger
from electrum.bitcoin import make_op_return
from electrum.transaction import PartialTxInput, PartialTxOutput, TxOutpoint, PartialTransaction, Transaction
from electrum.crypto import sha256
from electrum.json_db import JsonDB, StoredDict, StoredObject
from electrum.lnutil import hex_to_bytes
from electrum.fee_policy import FeePolicy
from electrum.util import EventListener, event_listener

from typing import TYPE_CHECKING, List, Dict


def is_power_of_two(x):
    return x == pow(2, x.bit_length() - 1)

def node_hash(left, right):
    return sha256(b"Node:" + left + right)


# min relay fee is 1000 sats/byte => we need 256 sats
MIN_LOG_FEE = 8
MIN_FEE = pow(2, MIN_LOG_FEE)
MAX_COST = MIN_FEE
MEMPOOL_UPDATE_INTERVAL = 10


@attr.s
class NotarizationRequest(StoredObject):
    event_id  = attr.ib(type=str)
    rhash     = attr.ib(type=bytes, converter=hex_to_bytes)
    pubkey    = attr.ib(type=str) #, converter=hex_to_bytes)
    log_fee   = attr.ib(type=int)
    #pubkey    = attr.ib(type=bytes, converter=hex_to_bytes)
    #pubkey    = attr.ib(type=bytes, converter=hex_to_bytes)
    #signature = attr.ib(type=bytes, converter=hex_to_bytes)

    def fee_sats(self):
        return pow(2, self.log_fee) if self.log_fee is not None else 0

    def leaf_hash(self):
        return sha256(bytes.fromhex(self.event_id) + self.rhash)


@attr.s
class Proof(StoredObject):
    hashes     = attr.ib(type=bytes, converter=hex_to_bytes)
    index      = attr.ib(type=int)   # position in merkle tree

    def get_root(self, leaf: bytes):
        assert type(leaf) is bytes
        h = leaf
        j = self.index
        for h2 in [self.hashes[i:i+32] for i in range(0, len(self.hashes), 32)]:
            h = node_hash(h, h2) if j%2 == 0 else node_hash(h2, h)
            j = j >> 1
        return h



class NotaryDB(JsonDB):

    def __init__(self, config):
        self.config = config
        data = self.read()
        JsonDB.__init__(
            self, data,
            encoder=MyEncoder,
        )
        self.data = StoredDict(self.data, self, [])

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

    def _convert_dict(self, path, key, v):
        if key == 'requests':
            v = dict((k, NotarizationRequest(**x)) for k, x in v.items())
        if key == 'forest':
            v = dict((int(k), x) for k, x in v.items())
        if key == 'mempool_roots':
            v = dict((int(k), (a, b, Transaction(c)) ) for k, (a,b,c) in v.items())
        if path and path[-1] == 'forest':
            # fixme: non-dict type. this should not be called in setitem.
            v = dict((k, Proof(**x) if type(x) is dict else x) for k, x in v.items())
        if path and path[-1] == 'confirmed_trees':
            # fixme: non-dict type. this should not be called in setitem.
            v = dict((k, Proof(**x) if type(x) is dict else x) for k, x in v.items())
        return v



class Notary(Logger, EventListener):
    """
    todo:
      - cannot broadcast: ignore that, BUT:
      - we need to retain previous states of the forest, and to check if an old state gets mined

    """

    def __init__(self, config, wallet):
        Logger.__init__(self)
        self.register_callbacks()
        self.wallet = wallet
        self.config = config
        self.notary_fee_percent = 10
        self.config.WALLET_SPEND_CONFIRMED_ONLY = False
        self.config.WALLET_COIN_CHOOSER_OUTPUT_ROUNDING = False
        #
        self.db = NotaryDB(self.config)
        self.requests = self.db.get_dict('requests')

        self.unit_trees = {} # int -> 256-tree
        
        self.forest = self.db.get_dict('forest')                      # fee_level -> Dict[leaf, proof]
        self.mempool_roots = self.db.get_dict('mempool_roots')        # txid -> (root, unit_indexes)
        self.confirmed_trees = self.db.get_dict('confirmed_trees')    # txid -> Dict[leaf, proof]

        self._leaf_to_rhash = {}
        for r in self.requests.values():
            self._leaf_to_rhash[r.leaf_hash()] = r.rhash

        self._leafs = set() # reflects our forest
        for tree in self.forest.values():
            for leaf_hex, proof in tree.items():
                self._leafs.add(bytes.fromhex(leaf_hex))
        for tree in self.confirmed_trees.values():
            for leaf_hex, proof in tree.items():
                self._leafs.add(bytes.fromhex(leaf_hex))

        assert len(self.mempool_roots) == len(self.forest)
        print("confirmed", list(sorted(self.confirmed_trees.keys())))
        print("mempol", [b for (a,b,c) in self.mempool_roots.values()])
        print("current forest", list(sorted(self.forest.keys())))

    def get_tree_root(self, tree):
        h, p = list(tree.items())[0]
        h = bytes.fromhex(h)
        return p.get_root(h)

    def add_request(self, event_id: str, event_pubkey: str, log_fee:int, upvoter_pubkey:bytes = None, upvoter_signature:bytes = None):
        if upvoter_pubkey:
            # todo: add upvoter identity to the proof
            ecc.verify_signature(upvoter_pubkey, upvoter_signature, event_id)
        # payment request for the notary
        fee_sat = pow(2, log_fee)
        fee_sat += fee_sat * self.notary_fee_percent // 100
        req_key = self.wallet.create_request(amount_sat=fee_sat, exp_delay=3600, message=event_id, address=None)
        payment_request = self.wallet.get_request(req_key)
        assert payment_request.payment_hash == bytes.fromhex(req_key)
        request = NotarizationRequest(
            event_id,
            payment_request.payment_hash,
            event_pubkey,
            log_fee,
            #upvoter_pubkey, upvoter_signature
        )
        self._leaf_to_rhash[request.leaf_hash()] = request.rhash
        self.requests[req_key] = request
        self.db.write()
        return self.wallet.export_request(payment_request)

    def get_proof(self, rhash_hex: str):
        try:
            request = self.requests[rhash_hex]
        except KeyError:
            raise UserFacingException("Request not found")
        leaf_hash = request.leaf_hash().hex()
        for txid, tree in self.confirmed_trees.items():
            for leaf, proof in tree.items():
                if leaf == leaf_hash:
                    root = proof.get_root(bytes.fromhex(leaf)).hex()
                    break
            else:
                continue
            break
        else:
            for k, tree in self.forest.items():
                for leaf, proof in tree.items():
                    if leaf == leaf_hash:
                        root, txid, tx = self.mempool_roots[k]
                        root = proof.get_root(bytes.fromhex(leaf)).hex()
                        break
                else:
                    continue
                break
            else:
                raise UserFacingException("proof not found")
        r = json.loads(json.dumps(proof, cls=MyEncoder))
        r["event_id"] = request.event_id
        r["pubkey"] = request.pubkey
        r["txid"] = txid
        r["leaf"] = leaf_hash
        r["root"] = root
        return r


    def create_tree(self, target_fee, requests) -> Dict[str, Proof]:
        # a tree is a dict[key->proof]
        requests.reverse()
        N = len(requests)
        print(f"creating new tree with {N} requests")#, [t.fee_sats() for t in requests])
        # create array of leafs hashes
        _hashes = {} # height -> hashes

        # height of the tree
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
                    leaf_hash = request.leaf_hash()
                    _hashes[k].append(leaf_hash)
                    self._leafs.add(leaf_hash)

            #print(f"hashes at k={k}: {len(_hashes[k])}")
            L = L + 1

        # we are done
        assert requests == []
        assert len(_hashes[1]) == 1
        root = _hashes[1][0]
        # extract proof for each leaf
        tree = {}
        for k in range(K, 1, -1):
            #print("level k=", k, len(_hashes[k]))
            for i, h in enumerate(_hashes[k]):
                # skip inner nodes
                if h not in self._leafs:
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
            
        print(f"created new tree, K={K} {len(tree)} distinct leafs, root {root.hex()}")
        #assert len(tree) == N
        return tree

    def combine_trees(self, tree1, tree2):
        root1 = self.get_tree_root(tree1)
        root2 = self.get_tree_root(tree2)
        new_root = node_hash(root1, root2)
        for leaf, proof in tree1.items():
            proof.hashes += root2
            h = bytes.fromhex(leaf)
            assert proof.get_root(h) == new_root
        for leaf, proof in tree2.items():
            proof.hashes += root1
            proof.index += pow(2, len(proof.hashes)//32 - 1)
            h = bytes.fromhex(leaf)
            assert proof.get_root(h) == new_root
        new_tree = {}
        new_tree.update(tree1)
        new_tree.update(tree2)
        return new_tree

    def get_unprocessed_requests(self):
        requests = self.requests.values()
        # filter requests that are already in our forest
        def is_not_processed(request):
            return request.leaf_hash() not in self._leafs
        requests = list(filter(is_not_processed, requests))
        # filter out unpaid requests
        requests = list(filter(lambda x: self.wallet.lnworker.get_payment_status(x.rhash) == PR_PAID, requests))
        # sort by fee
        requests = sorted(requests, key=lambda x: -x.fee_sats())
        return requests

    def create_forest(self, sorted_requests)-> Dict[int, dict]:
        """
        build Merkle tree(s) from requests in requests
        """
        assert len(sorted_requests) > 0
        total_fee = int(sum(r.fee_sats() for r in sorted_requests))
        print(f"Creating forest. Total_fee: {total_fee} sats. {[t.fee_sats() for t in sorted_requests]}")
        # the fee of each request will be a power of two.
        target = pow(2, total_fee.bit_length() - 1)
        target = max(target, MIN_FEE)
        print(f"target_fee: {target} sats.")
        # then, sort mempool by fee, pick items until desired value is reached
        forest = {}
        s = 0
        requests = []
        for r in sorted_requests:
            s += r.fee_sats()
            requests.append(r)
            assert s <= target
            if s == target:
                forest[target] = requests
                s = 0
                requests = []
                if target > MIN_FEE:
                    target = target // 2
        # top up the fees of requests in the last tree
        if requests:
            while not is_power_of_two(len(requests)):
                requests.append(requests[-1])
            cost = MIN_FEE - sum([r.fee_sats() for r in requests])
            if cost > MAX_COST:
                print(f"cost= {cost}, giving up")
                return
            p = len(requests).bit_length() - 1
            for r in requests:
                r.log_fee = MIN_LOG_FEE - p
            forest[MIN_FEE] = requests

        for fee_level, requests in list(forest.items()):
            #print(f"forest[{fee_level}]: {[r.fee_sats() for r in requests]}")
            forest[fee_level] = self.create_tree(fee_level, requests)

        print(f"create_forest: {sorted(forest.keys(), reverse=True)}")
        return forest

    def create_new_tx(self, coin, root_hex:str , static_fee:int):
        root = bytes.fromhex(root_hex)
        outputs = [PartialTxOutput(scriptpubkey=make_op_return(root), value=0)]
        tx = self.wallet.make_unsigned_transaction(
            coins=[coin], outputs=outputs, rbf=True,
            fee_policy=FeePolicy('fixed:%d'%static_fee)
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

    def update_tree(self, i, new_tree):
        self.logger.info(f"adding tree {i} to forest {sorted(list(self.forest.keys()))}")
        while i in self.forest:
            tree = self.forest.pop(i)
            new_tree = self.combine_trees(new_tree, tree)
            i = i * 2
        self.forest[i] = new_tree

    def update_forest(self, new_forest):
        for i in sorted(new_forest.keys(), reverse=True):
            tree = new_forest[i]
            self.update_tree(i, tree)
        print(f"updated forest: {sorted(self.forest.keys(), reverse=True)}")

    def prune_verified(self):
        # prune all parents
        mempool_keys = sorted([int(x) for x in self.mempool_roots.keys()])
        found = False
        for k in mempool_keys:
            root, txid, tx = self.mempool_roots[k]
            tx_mined_status = self.wallet.adb.get_tx_height(txid)
            if tx_mined_status.height() > 0 or found:
                found = True
                self.mempool_roots.pop(k)
                tree = self.forest.pop(k)
                self.confirmed_trees[txid] = tree
                print('pruning tree', k)

    def update_mempool(self):
        mempool_keys = sorted([int(x) for x in self.mempool_roots.keys()], reverse=True)
        forest_keys = sorted([int(x) for x in self.forest.keys()], reverse=True)
        # find if we need to RBF a transaction
        rbf_txid = None
        for k in forest_keys:
            if k not in mempool_keys:
                lower_keys = [x for x in mempool_keys if x < k]
                if lower_keys:
                    K = max(lower_keys)
                    _, rbf_txid, rbf_tx = self.mempool_roots[K]
                break
            tree = self.forest[k]
            new_root = self.get_tree_root(tree).hex()
            old_root, _txid, _tx = self.mempool_roots[k]
            if old_root != new_root:
                rbf_txid = _txid
                rbf_tx = _tx
                break

        if rbf_txid is None:
            if self.mempool_roots:
                # we will create a child of the last higher mempool tx
                # fixme: assert that we are lower
                k = sorted(self.mempool_roots.keys(), reverse=True)[-1]
                parent_root, parent_txid, parent_tx = self.mempool_roots[k]
                print('parent txid', parent_txid)
                assert parent_tx.txid() == parent_txid
                coin = self.get_change_utxo(parent_tx)
                k = k // 2
            else:
                # prevout should be the last remaining from mempool
                coin = self.get_parent_coin()
        else:
            # pop roots that are going to be orphaned
            self.logger.info(f'found rbf txid {rbf_txid}')
            i = k
            while i >= MIN_FEE:
                if i in self.mempool_roots:
                    self.mempool_roots.pop(i)
                i = i // 2
            rbf_tx = PartialTransaction.from_tx(rbf_tx) # rm existing signatures
            rbf_tx.add_info_from_wallet(self.wallet)#, ignore_network_issues=False)
            assert len(rbf_tx.inputs()) == 1
            coin = rbf_tx.inputs()[0]

        i = k
        while i >= MIN_FEE:
            if i in self.forest:
                tree = self.forest[i]
                root = self.get_tree_root(tree).hex()
                tx = self.create_new_tx(coin, root, i)
                assert tx.get_fee() == i, (i, tx.get_fee()) # check that there is no fee rounding
                self.mempool_roots[i] = root, tx.txid(), tx
                print(f"new tx was added fee={tx.get_fee()}, txid={tx.txid()}")
                # next tx is child
                coin = self.get_change_utxo(tx)
            #
            i = i // 2
        # final assert
        assert len(self.forest) == len(self.mempool_roots)

    async def broadcast_transactions(self):
        for k, (root, txid, tx) in self.mempool_roots.items():
            if not await self.wallet.network.try_broadcasting(tx, 'level %d'%k):
                print('could not broadcast tx', txid)

    async def publish_tree(self, tree, transport):
        self.logger.info(f"publish tree {len(tree)}")
        for leaf, proof in tree.items():
            rhash = self._leaf_to_rhash[bytes.fromhex(leaf)] #.get(leaf, None) # we should persist that
            request = self.requests[rhash.hex()] #, None)
            # publish temporary proof
            await self.publish_proof(request, proof, transport) #bytes.fromhex(h), proof.hashes, proof.index)

    async def publish_proofs(self, transport):
        # remove processed requests from buffer
        # publish proofs; they must be updated
        for tree in self.forest.values():
            await self.publish_tree(tree, transport)
        print('published proofs')

    async def publish_proof(self, request, proof: Proof, transport):
        json_proof = json.dumps(proof, cls=MyEncoder)
        return
        # the first value of a single letter tag is indexed and can be filtered for
        tags = [
            ['e', request.event_id],      # event id
            ['p', request.pubkey],        # event pubkey
            ['v', request.log_fee],       # upvote value in satoshis
            ['expiration', str(int(time.time() + 60))]
        ]
        relay_manager = transport.get_relay_manager()
        try:
            event_id = await aionostr._add_event(
                relay_manager,
                kind=777,
                tags=tags,
                content=json_proof,
                private_key=transport.nostr_private_key)
        except asyncio.TimeoutError as e:
            self.logger.warning(f"failed to publish swap offer: {str(e)}")

    @log_exceptions
    async def run(self):
        from electrum.submarine_swaps import NostrTransport
        with NostrTransport(self.config, self.wallet.lnworker.swap_manager, self.wallet.lnworker.nostr_keypair) as transport:
            await transport.is_connected.wait()
            self.logger.info(f'nostr is connected')
            while True:
                self.prune_verified()
                requests = self.get_unprocessed_requests()
                if not requests:
                    await asyncio.sleep(MEMPOOL_UPDATE_INTERVAL)
                    continue
                print(f"{len(requests)} unprocessed requests")
                new_forest = self.create_forest(requests)
                self.add_unit_tree(new_forest)
                self.update_forest(new_forest)
                self.update_mempool()
                self.db.write()

                self.wallet.save_db()
                await self.broadcast_transactions() # this can always fail
                await self.publish_proofs(transport)

    def add_unit_tree(self, new_forest):
        n = (max(list(self.unit_trees.keys())) + 1) if self.unit_trees else 0
        self.unit_trees[n] = new_forest

    @event_listener
    async def on_event_adb_added_verified_tx(self, adb, txid):
        return
        #if adb != self.wallet.adb:
        #    return
        #for k, v in list(self.mempool_roots.items()):
        #    leaf, _txid, tx = v
        #    if txid == _txid:
        #        self._verified.add(_txid)
