#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2015 Thomas Voegtlin
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
import os
import ast
import json
import copy
import threading
from collections import defaultdict
from typing import Dict, Optional, List, Tuple, Set, Iterable, NamedTuple, Sequence

from . import util, bitcoin
from .three_keys.transaction import TxType, ThreeKeysTransaction
from .util import profiler, WalletFileException, multisig_type, TxMinedInfo
from .keystore import bip44_derivation
from .transaction import Transaction
from .logging import Logger

# seed_version is now used for the version of the wallet file

OLD_SEED_VERSION = 4        # electrum versions < 2.0
NEW_SEED_VERSION = 11       # electrum versions >= 2.0
FINAL_SEED_VERSION = 20     # electrum >= 2.7 will set this to prevent
                            # old versions from overwriting new format


JsonDBJsonEncoder = util.MyEncoder


class TxFeesValue(NamedTuple):
    fee: Optional[int] = None
    is_calculated_by_us: bool = False
    num_inputs: Optional[int] = None


class JsonDB(Logger):

    def __init__(self, raw, *, manual_upgrades):
        Logger.__init__(self)
        self.lock = threading.RLock()
        self.data = {}
        self._modified = False
        self.manual_upgrades = manual_upgrades
        self._called_after_upgrade_tasks = False
        if raw:  # loading existing db
            self.load_data(raw)
        else:  # creating new db
            self.put('seed_version', FINAL_SEED_VERSION)
            self._after_upgrade_tasks()

    def set_modified(self, b):
        with self.lock:
            self._modified = b

    def modified(self):
        return self._modified

    def modifier(func):
        def wrapper(self, *args, **kwargs):
            with self.lock:
                self._modified = True
                return func(self, *args, **kwargs)
        return wrapper

    def locked(func):
        def wrapper(self, *args, **kwargs):
            with self.lock:
                return func(self, *args, **kwargs)
        return wrapper

    @locked
    def get(self, key, default=None):
        v = self.data.get(key)
        if v is None:
            v = default
        else:
            v = copy.deepcopy(v)
        return v

    @modifier
    def put(self, key, value):
        try:
            json.dumps(key, cls=JsonDBJsonEncoder)
            json.dumps(value, cls=JsonDBJsonEncoder)
        except:
            self.logger.info(f"json error: cannot save {repr(key)} ({repr(value)})")
            return False
        if value is not None:
            if self.data.get(key) != value:
                self.data[key] = copy.deepcopy(value)
                return True
        elif key in self.data:
            self.data.pop(key)
            return True
        return False

    def commit(self):
        pass

    @locked
    def dump(self):
        return json.dumps(self.data, indent=4, sort_keys=True, cls=JsonDBJsonEncoder)

    def load_data(self, s):
        try:
            self.data = json.loads(s)
        except:
            try:
                d = ast.literal_eval(s)
                labels = d.get('labels', {})
            except Exception as e:
                raise IOError("Cannot read wallet file")
            self.data = {}
            for key, value in d.items():
                try:
                    json.dumps(key)
                    json.dumps(value)
                except:
                    self.logger.info(f'Failed to convert label to json format: {key}')
                    continue
                self.data[key] = value
        if not isinstance(self.data, dict):
            raise WalletFileException("Malformed wallet file (not dict)")

        if not self.manual_upgrades and self.requires_split():
            raise WalletFileException("This wallet has multiple accounts and must be split")

        if not self.requires_upgrade():
            self._after_upgrade_tasks()
        elif not self.manual_upgrades:
            self.upgrade()

    def requires_split(self):
        d = self.get('accounts', {})
        return len(d) > 1

    def split_accounts(self):
        result = []
        # backward compatibility with old wallets
        d = self.get('accounts', {})
        if len(d) < 2:
            return
        wallet_type = self.get('wallet_type')
        if wallet_type == 'old':
            assert len(d) == 2
            data1 = copy.deepcopy(self.data)
            data1['accounts'] = {'0': d['0']}
            data1['suffix'] = 'deterministic'
            data2 = copy.deepcopy(self.data)
            data2['accounts'] = {'/x': d['/x']}
            data2['seed'] = None
            data2['seed_version'] = None
            data2['master_public_key'] = None
            data2['wallet_type'] = 'imported'
            data2['suffix'] = 'imported'
            result = [data1, data2]

        elif wallet_type in ['bip44', 'trezor', 'keepkey', 'ledger', 'btchip', 'digitalbitbox', 'safe_t']:
            mpk = self.get('master_public_keys')
            for k in d.keys():
                i = int(k)
                x = d[k]
                if x.get("pending"):
                    continue
                xpub = mpk["x/%d'"%i]
                new_data = copy.deepcopy(self.data)
                # save account, derivation and xpub at index 0
                new_data['accounts'] = {'0': x}
                new_data['master_public_keys'] = {"x/0'": xpub}
                new_data['derivation'] = bip44_derivation(k)
                new_data['suffix'] = k
                result.append(new_data)
        else:
            raise WalletFileException("This wallet has multiple accounts and must be split")
        return result

    def requires_upgrade(self):
        return self.get_seed_version() < FINAL_SEED_VERSION

    @profiler
    def upgrade(self):
        self.logger.info('upgrading wallet format')
        if self._called_after_upgrade_tasks:
            # we need strict ordering between upgrade() and after_upgrade_tasks()
            raise Exception("'after_upgrade_tasks' must NOT be called before 'upgrade'")
        self._convert_imported()
        self._convert_wallet_type()
        self._convert_account()
        self._convert_version_13_b()
        self._convert_version_14()
        self._convert_version_15()
        self._convert_version_16()
        self._convert_version_17()
        self._convert_version_18()
        self._convert_version_19()
        self._convert_version_20()
        self.put('seed_version', FINAL_SEED_VERSION)  # just to be sure

        self._after_upgrade_tasks()

    def _after_upgrade_tasks(self):
        self._called_after_upgrade_tasks = True
        self._load_transactions()

    def _convert_wallet_type(self):
        if not self._is_upgrade_method_needed(0, 13):
            return

        wallet_type = self.get('wallet_type')
        if wallet_type == 'btchip': wallet_type = 'ledger'
        if self.get('keystore') or self.get('x1/') or wallet_type=='imported':
            return False
        assert not self.requires_split()
        seed_version = self.get_seed_version()
        seed = self.get('seed')
        xpubs = self.get('master_public_keys')
        xprvs = self.get('master_private_keys', {})
        mpk = self.get('master_public_key')
        keypairs = self.get('keypairs')
        key_type = self.get('key_type')
        if seed_version == OLD_SEED_VERSION or wallet_type == 'old':
            d = {
                'type': 'old',
                'seed': seed,
                'mpk': mpk,
            }
            self.put('wallet_type', 'standard')
            self.put('keystore', d)

        elif key_type == 'imported':
            d = {
                'type': 'imported',
                'keypairs': keypairs,
            }
            self.put('wallet_type', 'standard')
            self.put('keystore', d)

        elif wallet_type in ['xpub', 'standard']:
            xpub = xpubs["x/"]
            xprv = xprvs.get("x/")
            d = {
                'type': 'bip32',
                'xpub': xpub,
                'xprv': xprv,
                'seed': seed,
            }
            self.put('wallet_type', 'standard')
            self.put('keystore', d)

        elif wallet_type in ['bip44']:
            xpub = xpubs["x/0'"]
            xprv = xprvs.get("x/0'")
            d = {
                'type': 'bip32',
                'xpub': xpub,
                'xprv': xprv,
            }
            self.put('wallet_type', 'standard')
            self.put('keystore', d)

        elif wallet_type in ['trezor', 'keepkey', 'ledger', 'digitalbitbox', 'safe_t']:
            xpub = xpubs["x/0'"]
            derivation = self.get('derivation', bip44_derivation(0))
            d = {
                'type': 'hardware',
                'hw_type': wallet_type,
                'xpub': xpub,
                'derivation': derivation,
            }
            self.put('wallet_type', 'standard')
            self.put('keystore', d)

        elif (wallet_type == '2fa') or multisig_type(wallet_type):
            for key in xpubs.keys():
                d = {
                    'type': 'bip32',
                    'xpub': xpubs[key],
                    'xprv': xprvs.get(key),
                }
                if key == 'x1/' and seed:
                    d['seed'] = seed
                self.put(key, d)
        else:
            raise WalletFileException('Unable to tell wallet type. Is this even a wallet file?')
        # remove junk
        self.put('master_public_key', None)
        self.put('master_public_keys', None)
        self.put('master_private_keys', None)
        self.put('derivation', None)
        self.put('seed', None)
        self.put('keypairs', None)
        self.put('key_type', None)

    def _convert_version_13_b(self):
        # version 13 is ambiguous, and has an earlier and a later structure
        if not self._is_upgrade_method_needed(0, 13):
            return

        if self.get('wallet_type') == 'standard':
            if self.get('keystore').get('type') == 'imported':
                pubkeys = self.get('keystore').get('keypairs').keys()
                d = {'change': []}
                receiving_addresses = []
                for pubkey in pubkeys:
                    addr = bitcoin.pubkey_to_address('p2pkh', pubkey)
                    receiving_addresses.append(addr)
                d['receiving'] = receiving_addresses
                self.put('addresses', d)
                self.put('pubkeys', None)

        self.put('seed_version', 13)

    def _convert_version_14(self):
        # convert imported wallets for 3.0
        if not self._is_upgrade_method_needed(13, 13):
            return

        if self.get('wallet_type') =='imported':
            addresses = self.get('addresses')
            if type(addresses) is list:
                addresses = dict([(x, None) for x in addresses])
                self.put('addresses', addresses)
        elif self.get('wallet_type') == 'standard':
            if self.get('keystore').get('type')=='imported':
                addresses = set(self.get('addresses').get('receiving'))
                pubkeys = self.get('keystore').get('keypairs').keys()
                assert len(addresses) == len(pubkeys)
                d = {}
                for pubkey in pubkeys:
                    addr = bitcoin.pubkey_to_address('p2pkh', pubkey)
                    assert addr in addresses
                    d[addr] = {
                        'pubkey': pubkey,
                        'redeem_script': None,
                        'type': 'p2pkh'
                    }
                self.put('addresses', d)
                self.put('pubkeys', None)
                self.put('wallet_type', 'imported')
        self.put('seed_version', 14)

    def _convert_version_15(self):
        if not self._is_upgrade_method_needed(14, 14):
            return
        if self.get('seed_type') == 'segwit':
            # should not get here; get_seed_version should have caught this
            raise Exception('unsupported derivation (development segwit, v14)')
        self.put('seed_version', 15)

    def _convert_version_16(self):
        # fixes issue #3193 for Imported_Wallets with addresses
        # also, previous versions allowed importing any garbage as an address
        #       which we now try to remove, see pr #3191
        if not self._is_upgrade_method_needed(15, 15):
            return

        def remove_address(addr):
            def remove_from_dict(dict_name):
                d = self.get(dict_name, None)
                if d is not None:
                    d.pop(addr, None)
                    self.put(dict_name, d)

            def remove_from_list(list_name):
                lst = self.get(list_name, None)
                if lst is not None:
                    s = set(lst)
                    s -= {addr}
                    self.put(list_name, list(s))

            # note: we don't remove 'addr' from self.get('addresses')
            remove_from_dict('addr_history')
            remove_from_dict('labels')
            remove_from_dict('payment_requests')
            remove_from_list('frozen_addresses')

        if self.get('wallet_type') == 'imported':
            addresses = self.get('addresses')
            assert isinstance(addresses, dict)
            addresses_new = dict()
            for address, details in addresses.items():
                if not bitcoin.is_address(address):
                    remove_address(address)
                    continue
                if details is None:
                    addresses_new[address] = {}
                else:
                    addresses_new[address] = details
            self.put('addresses', addresses_new)

        self.put('seed_version', 16)

    def _convert_version_17(self):
        # delete pruned_txo; construct spent_outpoints
        if not self._is_upgrade_method_needed(16, 16):
            return

        self.put('pruned_txo', None)

        transactions = self.get('transactions', {})  # txid -> raw_tx
        spent_outpoints = defaultdict(dict)
        for txid, raw_tx in transactions.items():
            tx = Transaction(raw_tx)
            for txin in tx.inputs():
                if txin.is_coinbase():
                    continue
                prevout_hash = txin.prevout.txid.hex()
                prevout_n = txin.prevout.out_idx
                spent_outpoints[prevout_hash][str(prevout_n)] = txid
        self.put('spent_outpoints', spent_outpoints)

        self.put('seed_version', 17)

    def _convert_version_18(self):
        # delete verified_tx3 as its structure changed
        if not self._is_upgrade_method_needed(17, 17):
            return
        self.put('verified_tx3', None)
        self.put('seed_version', 18)

    def _convert_version_19(self):
        # delete tx_fees as its structure changed
        if not self._is_upgrade_method_needed(18, 18):
            return
        self.put('tx_fees', None)
        self.put('seed_version', 19)

    def _convert_version_20(self):
        # store 'derivation' (prefix) and 'root_fingerprint' in all xpub-based keystores.
        # store explicit None values if we cannot retroactively determine them
        if not self._is_upgrade_method_needed(19, 19):
            return

        from .bip32 import BIP32Node, convert_bip32_intpath_to_strpath
        # note: This upgrade method reimplements bip32.root_fp_and_der_prefix_from_xkey.
        #       This is done deliberately, to avoid introducing that method as a dependency to this upgrade.
        for ks_name in ('keystore', *['x{}/'.format(i) for i in range(1, 16)]):
            ks = self.get(ks_name, None)
            if ks is None: continue
            xpub = ks.get('xpub', None)
            if xpub is None: continue
            bip32node = BIP32Node.from_xkey(xpub)
            # derivation prefix
            derivation_prefix = ks.get('derivation', None)
            if derivation_prefix is None:
                assert bip32node.depth >= 0, bip32node.depth
                if bip32node.depth == 0:
                    derivation_prefix = 'm'
                elif bip32node.depth == 1:
                    child_number_int = int.from_bytes(bip32node.child_number, 'big')
                    derivation_prefix = convert_bip32_intpath_to_strpath([child_number_int])
                ks['derivation'] = derivation_prefix
            # root fingerprint
            root_fingerprint = ks.get('ckcc_xfp', None)
            if root_fingerprint is not None:
                root_fingerprint = root_fingerprint.to_bytes(4, byteorder="little", signed=False).hex().lower()
            if root_fingerprint is None:
                if bip32node.depth == 0:
                    root_fingerprint = bip32node.calc_fingerprint_of_this_node().hex().lower()
                elif bip32node.depth == 1:
                    root_fingerprint = bip32node.fingerprint.hex()
            ks['root_fingerprint'] = root_fingerprint
            ks.pop('ckcc_xfp', None)
            self.put(ks_name, ks)

        self.put('seed_version', 20)

    def _convert_imported(self):
        if not self._is_upgrade_method_needed(0, 13):
            return

        # '/x' is the internal ID for imported accounts
        d = self.get('accounts', {}).get('/x', {}).get('imported',{})
        if not d:
            return False
        addresses = []
        keypairs = {}
        for addr, v in d.items():
            pubkey, privkey = v
            if privkey:
                keypairs[pubkey] = privkey
            else:
                addresses.append(addr)
        if addresses and keypairs:
            raise WalletFileException('mixed addresses and privkeys')
        elif addresses:
            self.put('addresses', addresses)
            self.put('accounts', None)
        elif keypairs:
            self.put('wallet_type', 'standard')
            self.put('key_type', 'imported')
            self.put('keypairs', keypairs)
            self.put('accounts', None)
        else:
            raise WalletFileException('no addresses or privkeys')

    def _convert_account(self):
        if not self._is_upgrade_method_needed(0, 13):
            return
        self.put('accounts', None)

    def _is_upgrade_method_needed(self, min_version, max_version):
        assert min_version <= max_version
        cur_version = self.get_seed_version()
        if cur_version > max_version:
            return False
        elif cur_version < min_version:
            raise WalletFileException(
                'storage upgrade: unexpected version {} (should be {}-{})'
                .format(cur_version, min_version, max_version))
        else:
            return True

    @locked
    def get_seed_version(self):
        seed_version = self.get('seed_version')
        if not seed_version:
            seed_version = OLD_SEED_VERSION if len(self.get('master_public_key','')) == 128 else NEW_SEED_VERSION
        if seed_version > FINAL_SEED_VERSION:
            raise WalletFileException('This version of Electrum is too old to open this wallet.\n'
                                      '(highest supported storage version: {}, version of this file: {})'
                                      .format(FINAL_SEED_VERSION, seed_version))
        if seed_version==14 and self.get('seed_type') == 'segwit':
            self._raise_unsupported_version(seed_version)
        if seed_version >=12:
            return seed_version
        if seed_version not in [OLD_SEED_VERSION, NEW_SEED_VERSION]:
            self._raise_unsupported_version(seed_version)
        return seed_version

    def _raise_unsupported_version(self, seed_version):
        msg = f"Your wallet has an unsupported seed version: {seed_version}."
        if seed_version in [5, 7, 8, 9, 10, 14]:
            msg += "\n\nTo open this wallet, try 'git checkout seed_v%d'"%seed_version
        if seed_version == 6:
            # version 1.9.8 created v6 wallets when an incorrect seed was entered in the restore dialog
            msg += '\n\nThis file was created because of a bug in version 1.9.8.'
            if self.get('master_public_keys') is None and self.get('master_private_keys') is None and self.get('imported_keys') is None:
                # pbkdf2 (at that time an additional dependency) was not included with the binaries, and wallet creation aborted.
                msg += "\nIt does not contain any keys, and can safely be removed."
            else:
                # creation was complete if electrum was run from source
                msg += "\nPlease open this file with Electrum 1.9.8, and move your coins to a new wallet."
        raise WalletFileException(msg)

    @locked
    def get_txi_addresses(self, tx_hash) -> List[str]:
        """Returns list of is_mine addresses that appear as inputs in tx."""
        return list(self.txi.get(tx_hash, {}).keys())

    @locked
    def get_txo_addresses(self, tx_hash) -> List[str]:
        """Returns list of is_mine addresses that appear as outputs in tx."""
        return list(self.txo.get(tx_hash, {}).keys())

    @locked
    def get_txi_addr(self, tx_hash, address) -> Iterable[Tuple[str, int]]:
        """Returns an iterable of (prev_outpoint, value)."""
        return self.txi.get(tx_hash, {}).get(address, []).copy()

    @locked
    def get_txo_addr(self, tx_hash, address) -> Iterable[Tuple[int, int, bool]]:
        """Returns an iterable of (output_index, value, is_coinbase)."""
        return self.txo.get(tx_hash, {}).get(address, []).copy()

    @modifier
    def add_txi_addr(self, tx_hash, addr, ser, v):
        if tx_hash not in self.txi:
            self.txi[tx_hash] = {}
        d = self.txi[tx_hash]
        if addr not in d:
            # note that as this is a set, we can ignore "duplicates"
            d[addr] = set()
        d[addr].add((ser, v))

    @modifier
    def add_txo_addr(self, tx_hash, addr, n, v, is_coinbase):
        if tx_hash not in self.txo:
            self.txo[tx_hash] = {}
        d = self.txo[tx_hash]
        if addr not in d:
            # note that as this is a set, we can ignore "duplicates"
            d[addr] = set()
        d[addr].add((n, v, is_coinbase))

    @locked
    def list_txi(self):
        return list(self.txi.keys())

    @locked
    def list_txo(self):
        return list(self.txo.keys())

    @modifier
    def remove_txi(self, tx_hash):
        self.txi.pop(tx_hash, None)

    @modifier
    def remove_txo(self, tx_hash):
        self.txo.pop(tx_hash, None)

    @locked
    def list_spent_outpoints(self):
        return [(h, n)
                for h in self.spent_outpoints.keys()
                for n in self.get_spent_outpoints(h)
        ]

    @locked
    def get_spent_outpoints(self, prevout_hash):
        return list(self.spent_outpoints.get(prevout_hash, {}).keys())

    @locked
    def get_spent_outpoint(self, prevout_hash, prevout_n):
        prevout_n = str(prevout_n)
        return self.spent_outpoints.get(prevout_hash, {}).get(prevout_n)

    @modifier
    def remove_spent_outpoint(self, prevout_hash, prevout_n):
        prevout_n = str(prevout_n)
        self.spent_outpoints[prevout_hash].pop(prevout_n, None)
        if not self.spent_outpoints[prevout_hash]:
            self.spent_outpoints.pop(prevout_hash)

    @modifier
    def set_spent_outpoint(self, prevout_hash, prevout_n, tx_hash):
        prevout_n = str(prevout_n)
        if prevout_hash not in self.spent_outpoints:
            self.spent_outpoints[prevout_hash] = {}
        self.spent_outpoints[prevout_hash][prevout_n] = tx_hash

    @modifier
    def add_transaction(self, tx_hash: str, tx: Transaction) -> None:
        assert isinstance(tx, Transaction)
        self.transactions[tx_hash] = tx

    @modifier
    def remove_transaction(self, tx_hash) -> Optional[Transaction]:
        return self.transactions.pop(tx_hash, None)

    @locked
    def get_transaction(self, tx_hash: str) -> Optional[Transaction]:
        return self.transactions.get(tx_hash)

    @locked
    def list_transactions(self):
        return list(self.transactions.keys())

    @locked
    def get_history(self):
        return list(self.history.keys())

    def is_addr_in_history(self, addr):
        # does not mean history is non-empty!
        return addr in self.history

    @locked
    def get_addr_history(self, addr):
        return self.history.get(addr, [])

    @modifier
    def set_addr_history(self, addr, hist):
        self.history[addr] = hist

    @modifier
    def remove_addr_history(self, addr):
        self.history.pop(addr, None)

    @locked
    def list_verified_tx(self):
        return list(self.verified_tx.keys())

    @locked
    def get_verified_tx(self, txid):
        if txid not in self.verified_tx:
            return None
        height, timestamp, txpos, header_hash, txtype = self.verified_tx[txid]
        return TxMinedInfo(height=height,
                           conf=None,
                           timestamp=timestamp,
                           txpos=txpos,
                           header_hash=header_hash,
                           txtype=txtype)

    @modifier
    def add_verified_tx(self, txid, info):
        self.verified_tx[txid] = (info.height, info.timestamp, info.txpos, info.header_hash, info.txtype)

    @modifier
    def remove_verified_tx(self, txid):
        self.verified_tx.pop(txid, None)

    def is_in_verified_tx(self, txid):
        return txid in self.verified_tx

    @modifier
    def add_tx_fee_from_server(self, txid: str, fee_sat: Optional[int]) -> None:
        # note: when called with (fee_sat is None), rm currently saved value
        if txid not in self.tx_fees:
            self.tx_fees[txid] = TxFeesValue()
        tx_fees_value = self.tx_fees[txid]
        if tx_fees_value.is_calculated_by_us:
            return
        self.tx_fees[txid] = tx_fees_value._replace(fee=fee_sat, is_calculated_by_us=False)

    @modifier
    def add_tx_fee_we_calculated(self, txid: str, fee_sat: Optional[int]) -> None:
        if fee_sat is None:
            return
        if txid not in self.tx_fees:
            self.tx_fees[txid] = TxFeesValue()
        self.tx_fees[txid] = self.tx_fees[txid]._replace(fee=fee_sat, is_calculated_by_us=True)

    @locked
    def get_tx_fee(self, txid: str, *, trust_server=False) -> Optional[int]:
        """Returns tx_fee."""
        tx_fees_value = self.tx_fees.get(txid)
        if tx_fees_value is None:
            return None
        if not trust_server and not tx_fees_value.is_calculated_by_us:
            return None
        return tx_fees_value.fee

    @modifier
    def add_num_inputs_to_tx(self, txid: str, num_inputs: int) -> None:
        if txid not in self.tx_fees:
            self.tx_fees[txid] = TxFeesValue()
        self.tx_fees[txid] = self.tx_fees[txid]._replace(num_inputs=num_inputs)

    @locked
    def get_num_all_inputs_of_tx(self, txid: str) -> Optional[int]:
        tx_fees_value = self.tx_fees.get(txid)
        if tx_fees_value is None:
            return None
        return tx_fees_value.num_inputs

    @locked
    def get_num_ismine_inputs_of_tx(self, txid: str) -> int:
        txins = self.txi.get(txid, {})
        return sum([len(tupls) for addr, tupls in txins.items()])

    @modifier
    def remove_tx_fee(self, txid):
        self.tx_fees.pop(txid, None)

    @locked
    def get_data_ref(self, name):
        # Warning: interacts un-intuitively with 'put': certain parts
        # of 'data' will have pointers saved as separate variables.
        if name not in self.data:
            self.data[name] = {}
        return self.data[name]

    @locked
    def num_change_addresses(self):
        return len(self.change_addresses)

    @locked
    def num_receiving_addresses(self):
        return len(self.receiving_addresses)

    @locked
    def get_change_addresses(self, *, slice_start=None, slice_stop=None):
        # note: slicing makes a shallow copy
        return self.change_addresses[slice_start:slice_stop]

    @locked
    def get_receiving_addresses(self, *, slice_start=None, slice_stop=None):
        # note: slicing makes a shallow copy
        return self.receiving_addresses[slice_start:slice_stop]

    @modifier
    def add_change_address(self, addr):
        self._addr_to_addr_index[addr] = (1, len(self.change_addresses))
        self.change_addresses.append(addr)

    @modifier
    def add_receiving_address(self, addr):
        self._addr_to_addr_index[addr] = (0, len(self.receiving_addresses))
        self.receiving_addresses.append(addr)

    @locked
    def get_address_index(self, address) -> Optional[Sequence[int]]:
        return self._addr_to_addr_index.get(address)

    @modifier
    def add_imported_address(self, addr, d):
        self.imported_addresses[addr] = d

    @modifier
    def remove_imported_address(self, addr):
        self.imported_addresses.pop(addr)

    @locked
    def has_imported_address(self, addr):
        return addr in self.imported_addresses

    @locked
    def get_imported_addresses(self):
        return list(sorted(self.imported_addresses.keys()))

    @locked
    def get_imported_address(self, addr):
        return self.imported_addresses.get(addr)

    def load_addresses(self, wallet_type):
        """ called from Abstract_Wallet.__init__ """
        if wallet_type == 'imported':
            self.imported_addresses = self.get_data_ref('addresses')
        else:
            self.get_data_ref('addresses')
            for name in ['receiving', 'change']:
                if name not in self.data['addresses']:
                    self.data['addresses'][name] = []
            self.change_addresses = self.data['addresses']['change']
            self.receiving_addresses = self.data['addresses']['receiving']
            self._addr_to_addr_index = {}  # type: Dict[str, Sequence[int]]  # key: address, value: (is_change, index)
            for i, addr in enumerate(self.receiving_addresses):
                self._addr_to_addr_index[addr] = (0, i)
            for i, addr in enumerate(self.change_addresses):
                self._addr_to_addr_index[addr] = (1, i)

    @profiler
    def _load_transactions(self):
        # references in self.data
        # TODO make all these private
        # txid -> address -> set of (prev_outpoint, value)
        self.txi = self.get_data_ref('txi')  # type: Dict[str, Dict[str, Set[Tuple[str, int]]]]
        # txid -> address -> set of (output_index, value, is_coinbase)
        self.txo = self.get_data_ref('txo')  # type: Dict[str, Dict[str, Set[Tuple[int, int, bool]]]]
        self.transactions = self.get_data_ref('transactions')   # type: Dict[str, Transaction]
        self.spent_outpoints = self.get_data_ref('spent_outpoints')  # txid -> output_index -> next_txid
        self.history = self.get_data_ref('addr_history')  # address -> list of (txid, height)
        self.verified_tx = self.get_data_ref('verified_tx3')  # txid -> (height, timestamp, txpos, header_hash, txtype)
        self.tx_fees = self.get_data_ref('tx_fees')  # type: Dict[str, TxFeesValue]
        # convert raw hex transactions to Transaction objects
        for tx_hash, raw_tx in self.transactions.items():
            self.transactions[tx_hash] = Transaction(raw_tx)
        # convert list to set
        for t in self.txi, self.txo:
            for d in t.values():
                for addr, lst in d.items():
                    d[addr] = set([tuple(x) for x in lst])
        # remove unreferenced tx
        for tx_hash in list(self.transactions.keys()):
            if not self.get_txi_addresses(tx_hash) and not self.get_txo_addresses(tx_hash):
                self.logger.info(f"removing unreferenced tx: {tx_hash}")
                self.transactions.pop(tx_hash)
        # remove unreferenced outpoints
        for prevout_hash in self.spent_outpoints.keys():
            d = self.spent_outpoints[prevout_hash]
            for prevout_n, spending_txid in list(d.items()):
                if spending_txid not in self.transactions:
                    self.logger.info("removing unreferenced spent outpoint")
                    d.pop(prevout_n)
        # convert tx_fees tuples to NamedTuples
        for tx_hash, tuple_ in self.tx_fees.items():
            self.tx_fees[tx_hash] = TxFeesValue(*tuple_)

        self._upgrade_tx_to_3keys_tx()
        self._upgrade_verifier_by_tx_type()

    def _upgrade_tx_to_3keys_tx(self):
        """ Convert Transaction to ThreeKeysTransaction"""
        for tx_history in self.history.values():
            for item in tx_history:
                tx_hash = item[0]
                if len(item) == 3:
                    tx_type = TxType.from_str(item[2])
                else:
                    tx_type = TxType.NONVAULT

                tx = self.transactions.get(tx_hash, None)
                if tx:
                    three_keys_tx = ThreeKeysTransaction.from_tx(tx)
                    three_keys_tx.tx_type = tx_type
                    self.transactions[tx_hash] = three_keys_tx

    def _upgrade_verifier_by_tx_type(self):
        for key, value in self.verified_tx.items():
            if len(value) == 4:
                value.append(TxType.NONVAULT)

    @modifier
    def clear_history(self):
        self.txi.clear()
        self.txo.clear()
        self.spent_outpoints.clear()
        self.transactions.clear()
        self.history.clear()
        self.verified_tx.clear()
        self.tx_fees.clear()
