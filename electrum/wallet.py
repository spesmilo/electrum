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

# Wallet classes:
#   - Imported_Wallet: imported addresses or single keys, 0 or 1 keystore
#   - Standard_Wallet: one HD keystore, P2PKH-like scripts
#   - Multisig_Wallet: several HD keystores, M-of-N OP_CHECKMULTISIG scripts

import os
import sys
import random
import time
import json
import copy
import errno
import traceback
import operator
import math
from functools import partial
from collections import defaultdict
from numbers import Number
from decimal import Decimal
from typing import TYPE_CHECKING, List, Optional, Tuple, Union, NamedTuple, Sequence, Dict, Any, Set
from abc import ABC, abstractmethod
import itertools
import threading
import enum

from aiorpcx import TaskGroup, timeout_after, TaskTimeout, ignore_after

from .i18n import _
from .bip32 import BIP32Node, convert_bip32_intpath_to_strpath, convert_bip32_path_to_list_of_uint32
from .crypto import sha256
from . import util
from .util import (NotEnoughFunds, UserCancelled, profiler,
                   format_satoshis, format_fee_satoshis, NoDynamicFeeEstimates,
                   WalletFileException, BitcoinException,
                   InvalidPassword, format_time, timestamp_to_datetime, Satoshis,
                   Fiat, bfh, bh2u, TxMinedInfo, quantize_feerate, create_bip21_uri, OrderedDictWithIndex, parse_max_spend)
from .simple_config import SimpleConfig, FEE_RATIO_HIGH_WARNING, FEERATE_WARNING_HIGH_FEE
from .bitcoin import COIN, TYPE_ADDRESS
from .bitcoin import is_address, address_to_script, is_minikey, relayfee, dust_threshold
from .crypto import sha256d
from . import keystore
from .keystore import (load_keystore, Hardware_KeyStore, KeyStore, KeyStoreWithMPK,
                       AddressIndexGeneric, CannotDerivePubkey)
from .util import multisig_type
from .storage import StorageEncryptionVersion, WalletStorage
from .wallet_db import WalletDB
from . import transaction, bitcoin, coinchooser, paymentrequest, ecc, bip32
from .transaction import (Transaction, TxInput, UnknownTxinType, TxOutput,
                          PartialTransaction, PartialTxInput, PartialTxOutput, TxOutpoint)
from .plugin import run_hook
from .address_synchronizer import (AddressSynchronizer, TX_HEIGHT_LOCAL,
                                   TX_HEIGHT_UNCONF_PARENT, TX_HEIGHT_UNCONFIRMED, TX_HEIGHT_FUTURE)
from .invoices import Invoice, OnchainInvoice, LNInvoice
from .invoices import PR_PAID, PR_UNPAID, PR_UNKNOWN, PR_EXPIRED, PR_UNCONFIRMED, PR_TYPE_ONCHAIN, PR_TYPE_LN
from .contacts import Contacts
from .interface import NetworkException
from .mnemonic import Mnemonic
from .logging import get_logger
from .lnworker import LNWallet
from .paymentrequest import PaymentRequest
from .util import read_json_file, write_json_file, UserFacingException

if TYPE_CHECKING:
    from .network import Network
    from .exchange_rate import FxThread


_logger = get_logger(__name__)

TX_STATUS = [
    _('Unconfirmed'),
    _('Unconfirmed parent'),
    _('Not Verified'),
    _('Local'),
]


class BumpFeeStrategy(enum.Enum):
    COINCHOOSER = enum.auto()
    DECREASE_CHANGE = enum.auto()
    DECREASE_PAYMENT = enum.auto()


async def _append_utxos_to_inputs(*, inputs: List[PartialTxInput], network: 'Network',
                                  pubkey: str, txin_type: str, imax: int) -> None:
    if txin_type in ('p2pkh', 'p2wpkh', 'p2wpkh-p2sh'):
        address = bitcoin.pubkey_to_address(txin_type, pubkey)
        scripthash = bitcoin.address_to_scripthash(address)
    elif txin_type == 'p2pk':
        script = bitcoin.public_key_to_p2pk_script(pubkey)
        scripthash = bitcoin.script_to_scripthash(script)
    else:
        raise Exception(f'unexpected txin_type to sweep: {txin_type}')

    async def append_single_utxo(item):
        prev_tx_raw = await network.get_transaction(item['tx_hash'])
        prev_tx = Transaction(prev_tx_raw)
        prev_txout = prev_tx.outputs()[item['tx_pos']]
        if scripthash != bitcoin.script_to_scripthash(prev_txout.scriptpubkey.hex()):
            raise Exception('scripthash mismatch when sweeping')
        prevout_str = item['tx_hash'] + ':%d' % item['tx_pos']
        prevout = TxOutpoint.from_str(prevout_str)
        txin = PartialTxInput(prevout=prevout)
        txin.utxo = prev_tx
        txin.block_height = int(item['height'])
        txin.script_type = txin_type
        txin.pubkeys = [bfh(pubkey)]
        txin.num_sig = 1
        if txin_type == 'p2wpkh-p2sh':
            txin.redeem_script = bfh(bitcoin.p2wpkh_nested_script(pubkey))
        inputs.append(txin)

    u = await network.listunspent_for_scripthash(scripthash)
    async with TaskGroup() as group:
        for item in u:
            if len(inputs) >= imax:
                break
            await group.spawn(append_single_utxo(item))


async def sweep_preparations(privkeys, network: 'Network', imax=100):

    async def find_utxos_for_privkey(txin_type, privkey, compressed):
        pubkey = ecc.ECPrivkey(privkey).get_public_key_hex(compressed=compressed)
        await _append_utxos_to_inputs(
            inputs=inputs,
            network=network,
            pubkey=pubkey,
            txin_type=txin_type,
            imax=imax)
        keypairs[pubkey] = privkey, compressed

    inputs = []  # type: List[PartialTxInput]
    keypairs = {}
    async with TaskGroup() as group:
        for sec in privkeys:
            txin_type, privkey, compressed = bitcoin.deserialize_privkey(sec)
            await group.spawn(find_utxos_for_privkey(txin_type, privkey, compressed))
            # do other lookups to increase support coverage
            if is_minikey(sec):
                # minikeys don't have a compressed byte
                # we lookup both compressed and uncompressed pubkeys
                await group.spawn(find_utxos_for_privkey(txin_type, privkey, not compressed))
            elif txin_type == 'p2pkh':
                # WIF serialization does not distinguish p2pkh and p2pk
                # we also search for pay-to-pubkey outputs
                await group.spawn(find_utxos_for_privkey('p2pk', privkey, compressed))
    if not inputs:
        raise UserFacingException(_('No inputs found.'))
    return inputs, keypairs


async def sweep(
        privkeys,
        *,
        network: 'Network',
        config: 'SimpleConfig',
        to_address: str,
        fee: int = None,
        imax=100,
        locktime=None,
        tx_version=None) -> PartialTransaction:

    inputs, keypairs = await sweep_preparations(privkeys, network, imax)
    total = sum(txin.value_sats() for txin in inputs)
    if fee is None:
        outputs = [PartialTxOutput(scriptpubkey=bfh(bitcoin.address_to_script(to_address)),
                                   value=total)]
        tx = PartialTransaction.from_io(inputs, outputs)
        fee = config.estimate_fee(tx.estimated_size())
    if total - fee < 0:
        raise Exception(_('Not enough funds on address.') + '\nTotal: %d satoshis\nFee: %d'%(total, fee))
    if total - fee < dust_threshold(network):
        raise Exception(_('Not enough funds on address.') + '\nTotal: %d satoshis\nFee: %d\nDust Threshold: %d'%(total, fee, dust_threshold(network)))

    outputs = [PartialTxOutput(scriptpubkey=bfh(bitcoin.address_to_script(to_address)),
                               value=total - fee)]
    if locktime is None:
        locktime = get_locktime_for_new_transaction(network)

    tx = PartialTransaction.from_io(inputs, outputs, locktime=locktime, version=tx_version)
    rbf = bool(config.get('use_rbf', True))
    tx.set_rbf(rbf)
    tx.sign(keypairs)
    return tx


def get_locktime_for_new_transaction(network: 'Network') -> int:
    # if no network or not up to date, just set locktime to zero
    if not network:
        return 0
    chain = network.blockchain()
    if chain.is_tip_stale():
        return 0
    # discourage "fee sniping"
    locktime = chain.height()
    # sometimes pick locktime a bit further back, to help privacy
    # of setups that need more time (offline/multisig/coinjoin/...)
    if random.randint(0, 9) == 0:
        locktime = max(0, locktime - random.randint(0, 99))
    return locktime



class CannotBumpFee(Exception):
    def __str__(self):
        return _('Cannot bump fee') + ':\n\n' + Exception.__str__(self)

class CannotDoubleSpendTx(Exception):
    def __str__(self):
        return _('Cannot cancel transaction') + ':\n\n' + Exception.__str__(self)

class CannotCPFP(Exception):
    def __str__(self):
        return _('Cannot create child transaction') + ':\n\n' + Exception.__str__(self)

class InternalAddressCorruption(Exception):
    def __str__(self):
        return _("Wallet file corruption detected. "
                 "Please restore your wallet from seed, and compare the addresses in both files")


class TxWalletDetails(NamedTuple):
    txid: Optional[str]
    status: str
    label: str
    can_broadcast: bool
    can_bump: bool
    can_cpfp: bool
    can_dscancel: bool  # whether user can double-spend to self
    can_save_as_local: bool
    amount: Optional[int]
    fee: Optional[int]
    tx_mined_status: TxMinedInfo
    mempool_depth_bytes: Optional[int]
    can_remove: bool  # whether user should be allowed to delete tx
    is_lightning_funding_tx: bool


class Abstract_Wallet(AddressSynchronizer, ABC):
    """
    Wallet classes are created to handle various address generation methods.
    Completion states (watching-only, single account, no seed, etc) are handled inside classes.
    """

    LOGGING_SHORTCUT = 'w'
    max_change_outputs = 3
    gap_limit_for_change = 10

    txin_type: str
    wallet_type: str
    lnworker: Optional['LNWallet']

    def __init__(self, db: WalletDB, storage: Optional[WalletStorage], *, config: SimpleConfig):
        if not db.is_ready_to_be_used_by_wallet():
            raise Exception("storage not ready to be used by Abstract_Wallet")

        self.config = config
        assert self.config is not None, "config must not be None"
        self.db = db
        self.storage = storage
        # load addresses needs to be called before constructor for sanity checks
        db.load_addresses(self.wallet_type)
        self.keystore = None  # type: Optional[KeyStore]  # will be set by load_keystore
        AddressSynchronizer.__init__(self, db)

        # saved fields
        self.use_change            = db.get('use_change', True)
        self.multiple_change       = db.get('multiple_change', False)
        self._labels                = db.get_dict('labels')
        self._frozen_addresses      = set(db.get('frozen_addresses', []))
        self._frozen_coins          = db.get_dict('frozen_coins')  # type: Dict[str, bool]
        self.fiat_value            = db.get_dict('fiat_value')
        self.receive_requests      = db.get_dict('payment_requests')  # type: Dict[str, Invoice]
        self.invoices              = db.get_dict('invoices')  # type: Dict[str, Invoice]
        self._reserved_addresses   = set(db.get('reserved_addresses', []))

        self._freeze_lock = threading.Lock()  # for mutating/iterating frozen_{addresses,coins}

        self._prepare_onchain_invoice_paid_detection()
        self.calc_unused_change_addresses()
        # save wallet type the first time
        if self.db.get('wallet_type') is None:
            self.db.put('wallet_type', self.wallet_type)
        self.contacts = Contacts(self.db)
        self._coin_price_cache = {}

        self.lnworker = None

    def save_db(self):
        if self.storage:
            self.db.write(self.storage)

    def save_backup(self, backup_dir):
        new_db = WalletDB(self.db.dump(), manual_upgrades=False)

        if self.lnworker:
            channel_backups = new_db.get_dict('imported_channel_backups')
            for chan_id, chan in self.lnworker.channels.items():
                channel_backups[chan_id.hex()] = self.lnworker.create_channel_backup(chan_id)
            new_db.put('channels', None)
            new_db.put('lightning_privkey2', None)

        new_path = os.path.join(backup_dir, self.basename() + '.backup')
        new_storage = WalletStorage(new_path)
        new_storage._encryption_version = self.storage._encryption_version
        new_storage.pubkey = self.storage.pubkey
        new_db.set_modified(True)
        new_db.write(new_storage)
        return new_path

    def has_lightning(self) -> bool:
        return bool(self.lnworker)

    def can_have_lightning(self) -> bool:
        # we want static_remotekey to be a wallet address
        return self.txin_type == 'p2wpkh'

    def can_have_deterministic_lightning(self) -> bool:
        if not self.can_have_lightning():
            return False
        if not self.keystore:
            return False
        return self.keystore.can_have_deterministic_lightning_xprv()

    def can_sign_without_user_interaction_if_have_password(self) -> bool:
        return False

    def init_lightning(self, *, password) -> None:
        assert self.can_have_lightning()
        assert self.db.get('lightning_xprv') is None
        assert self.db.get('lightning_privkey2') is None
        if self.can_have_deterministic_lightning():
            assert isinstance(self.keystore, keystore.BIP32_KeyStore)
            ln_xprv = self.keystore.get_lightning_xprv(password)
            self.db.put('lightning_xprv', ln_xprv)
        else:
            seed = os.urandom(32)
            node = BIP32Node.from_rootseed(seed, xtype='standard')
            ln_xprv = node.to_xprv()
            self.db.put('lightning_privkey2', ln_xprv)
        if self.network:
            self.network.run_from_another_thread(self.stop())
        self.lnworker = LNWallet(self, ln_xprv)
        self.lnworker.maybe_enable_anchors_store_password(password)
        if self.network:
            self.start_network(self.network)

    async def stop(self):
        """Stop all networking and save DB to disk."""
        try:
            async with ignore_after(5):
                await super().stop()
                if self.network:
                    if self.lnworker:
                        await self.lnworker.stop()
                        self.lnworker = None
        finally:  # even if we get cancelled
            if any([ks.is_requesting_to_be_rewritten_to_wallet_file for ks in self.get_keystores()]):
                self.save_keystore()
            self.save_db()

    def set_up_to_date(self, b):
        super().set_up_to_date(b)
        if b: self.save_db()

    def clear_history(self):
        super().clear_history()
        self.save_db()

    def start_network(self, network):
        AddressSynchronizer.start_network(self, network)
        if network:
            if self.lnworker:
                self.lnworker.start_network(network)
                # only start gossiping when we already have channels
                if self.db.get('channels'):
                    self.network.start_gossip()

    def load_and_cleanup(self):
        self.load_keystore()
        self.test_addresses_sanity()
        super().load_and_cleanup()

    @abstractmethod
    def load_keystore(self) -> None:
        pass

    def diagnostic_name(self):
        return self.basename()

    def __str__(self):
        return self.basename()

    def get_master_public_key(self):
        return None

    def get_master_public_keys(self):
        return []

    def basename(self) -> str:
        return self.storage.basename() if self.storage else 'no name'

    def test_addresses_sanity(self) -> None:
        addrs = self.get_receiving_addresses()
        if len(addrs) > 0:
            addr = str(addrs[0])
            if not bitcoin.is_address(addr):
                neutered_addr = addr[:5] + '..' + addr[-2:]
                raise WalletFileException(f'The addresses in this wallet are not bitcoin addresses.\n'
                                          f'e.g. {neutered_addr} (length: {len(addr)})')

    def check_returned_address_for_corruption(func):
        def wrapper(self, *args, **kwargs):
            addr = func(self, *args, **kwargs)
            self.check_address_for_corruption(addr)
            return addr
        return wrapper

    def calc_unused_change_addresses(self) -> Sequence[str]:
        """Returns a list of change addresses to choose from, for usage in e.g. new transactions.
        The caller should give priority to earlier ones in the list.
        """
        with self.lock:
            # We want a list of unused change addresses.
            # As a performance optimisation, to avoid checking all addresses every time,
            # we maintain a list of "not old" addresses ("old" addresses have deeply confirmed history),
            # and only check those.
            if not hasattr(self, '_not_old_change_addresses'):
                self._not_old_change_addresses = self.get_change_addresses()
            self._not_old_change_addresses = [addr for addr in self._not_old_change_addresses
                                              if not self.address_is_old(addr)]
            unused_addrs = [addr for addr in self._not_old_change_addresses
                            if not self.is_used(addr) and not self.is_address_reserved(addr)]
            return unused_addrs

    def is_deterministic(self) -> bool:
        return self.keystore.is_deterministic()

    def _set_label(self, key: str, value: Optional[str]) -> None:
        with self.lock:
            if value is None:
                self._labels.pop(key, None)
            else:
                self._labels[key] = value

    def set_label(self, name: str, text: str = None) -> bool:
        if not name:
            return False
        changed = False
        with self.lock:
            old_text = self._labels.get(name)
            if text:
                text = text.replace("\n", " ")
                if old_text != text:
                    self._labels[name] = text
                    changed = True
            else:
                if old_text is not None:
                    self._labels.pop(name)
                    changed = True
        if changed:
            run_hook('set_label', self, name, text)
        return changed

    def import_labels(self, path):
        data = read_json_file(path)
        for key, value in data.items():
            self.set_label(key, value)

    def export_labels(self, path):
        write_json_file(path, self.get_all_labels())

    def set_fiat_value(self, txid, ccy, text, fx, value_sat):
        if not self.db.get_transaction(txid):
            return
        # since fx is inserting the thousands separator,
        # and not util, also have fx remove it
        text = fx.remove_thousands_separator(text)
        def_fiat = self.default_fiat_value(txid, fx, value_sat)
        formatted = fx.ccy_amount_str(def_fiat, commas=False)
        def_fiat_rounded = Decimal(formatted)
        reset = not text
        if not reset:
            try:
                text_dec = Decimal(text)
                text_dec_rounded = Decimal(fx.ccy_amount_str(text_dec, commas=False))
                reset = text_dec_rounded == def_fiat_rounded
            except:
                # garbage. not resetting, but not saving either
                return False
        if reset:
            d = self.fiat_value.get(ccy, {})
            if d and txid in d:
                d.pop(txid)
            else:
                # avoid saving empty dict
                return True
        else:
            if ccy not in self.fiat_value:
                self.fiat_value[ccy] = {}
            self.fiat_value[ccy][txid] = text
        return reset

    def get_fiat_value(self, txid, ccy):
        fiat_value = self.fiat_value.get(ccy, {}).get(txid)
        try:
            return Decimal(fiat_value)
        except:
            return

    def is_mine(self, address) -> bool:
        if not address: return False
        return bool(self.get_address_index(address))

    def is_change(self, address) -> bool:
        if not self.is_mine(address):
            return False
        return self.get_address_index(address)[0] == 1

    @abstractmethod
    def get_address_index(self, address: str) -> Optional[AddressIndexGeneric]:
        pass

    @abstractmethod
    def get_address_path_str(self, address: str) -> Optional[str]:
        """Returns derivation path str such as "m/0/5" to address,
        or None if not applicable.
        """
        pass

    @abstractmethod
    def get_redeem_script(self, address: str) -> Optional[str]:
        pass

    @abstractmethod
    def get_witness_script(self, address: str) -> Optional[str]:
        pass

    @abstractmethod
    def get_txin_type(self, address: str) -> str:
        """Return script type of wallet address."""
        pass

    def export_private_key(self, address: str, password: Optional[str]) -> str:
        if self.is_watching_only():
            raise Exception(_("This is a watching-only wallet"))
        if not is_address(address):
            raise Exception(f"Invalid bitcoin address: {address}")
        if not self.is_mine(address):
            raise Exception(_('Address not in wallet.') + f' {address}')
        index = self.get_address_index(address)
        pk, compressed = self.keystore.get_private_key(index, password)
        txin_type = self.get_txin_type(address)
        serialized_privkey = bitcoin.serialize_privkey(pk, compressed, txin_type)
        return serialized_privkey

    def export_private_key_for_path(self, path: Union[Sequence[int], str], password: Optional[str]) -> str:
        raise Exception("this wallet is not deterministic")

    @abstractmethod
    def get_public_keys(self, address: str) -> Sequence[str]:
        pass

    def get_public_keys_with_deriv_info(self, address: str) -> Dict[bytes, Tuple[KeyStoreWithMPK, Sequence[int]]]:
        """Returns a map: pubkey -> (keystore, derivation_suffix)"""
        return {}

    def is_lightning_funding_tx(self, txid: Optional[str]) -> bool:
        if not self.lnworker or txid is None:
            return False
        return any([chan.funding_outpoint.txid == txid
                    for chan in self.lnworker.channels.values()])

    def get_tx_info(self, tx: Transaction) -> TxWalletDetails:
        tx_wallet_delta = self.get_wallet_delta(tx)
        is_relevant = tx_wallet_delta.is_relevant
        is_any_input_ismine = tx_wallet_delta.is_any_input_ismine
        fee = tx_wallet_delta.fee
        exp_n = None
        can_broadcast = False
        can_bump = False
        can_cpfp = False
        tx_hash = tx.txid()  # note: txid can be None! e.g. when called from GUI tx dialog
        is_lightning_funding_tx = self.is_lightning_funding_tx(tx_hash)
        tx_we_already_have_in_db = self.db.get_transaction(tx_hash)
        can_save_as_local = (is_relevant and tx.txid() is not None
                             and (tx_we_already_have_in_db is None or not tx_we_already_have_in_db.is_complete()))
        label = ''
        tx_mined_status = self.get_tx_height(tx_hash)
        can_remove = ((tx_mined_status.height in [TX_HEIGHT_FUTURE, TX_HEIGHT_LOCAL])
                      # otherwise 'height' is unreliable (typically LOCAL):
                      and is_relevant
                      # don't offer during common signing flow, e.g. when watch-only wallet starts creating a tx:
                      and bool(tx_we_already_have_in_db))
        can_dscancel = False
        if tx.is_complete():
            if tx_we_already_have_in_db:
                label = self.get_label_for_txid(tx_hash)
                if tx_mined_status.height > 0:
                    if tx_mined_status.conf:
                        status = _("{} confirmations").format(tx_mined_status.conf)
                    else:
                        status = _('Not verified')
                elif tx_mined_status.height in (TX_HEIGHT_UNCONF_PARENT, TX_HEIGHT_UNCONFIRMED):
                    status = _('Unconfirmed')
                    if fee is None:
                        fee = self.get_tx_fee(tx_hash)
                    if fee and self.network and self.config.has_fee_mempool():
                        size = tx.estimated_size()
                        fee_per_byte = fee / size
                        exp_n = self.config.fee_to_depth(fee_per_byte)
                    can_bump = is_any_input_ismine and not tx.is_final()
                    can_dscancel = (is_any_input_ismine and not tx.is_final()
                                    and not all([self.is_mine(txout.address) for txout in tx.outputs()]))
                    try:
                        self.cpfp(tx, 0)
                        can_cpfp = True
                    except:
                        can_cpfp = False
                else:
                    status = _('Local')
                    can_broadcast = self.network is not None
                    can_bump = is_any_input_ismine and not tx.is_final()
            else:
                status = _("Signed")
                can_broadcast = self.network is not None
        else:
            assert isinstance(tx, PartialTransaction)
            s, r = tx.signature_count()
            status = _("Unsigned") if s == 0 else _('Partially signed') + ' (%d/%d)'%(s,r)

        if is_relevant:
            if tx_wallet_delta.is_all_input_ismine:
                assert fee is not None
                amount = tx_wallet_delta.delta + fee
            else:
                amount = tx_wallet_delta.delta
        else:
            amount = None

        if is_lightning_funding_tx:
            can_bump = False  # would change txid

        return TxWalletDetails(
            txid=tx_hash,
            status=status,
            label=label,
            can_broadcast=can_broadcast,
            can_bump=can_bump,
            can_cpfp=can_cpfp,
            can_dscancel=can_dscancel,
            can_save_as_local=can_save_as_local,
            amount=amount,
            fee=fee,
            tx_mined_status=tx_mined_status,
            mempool_depth_bytes=exp_n,
            can_remove=can_remove,
            is_lightning_funding_tx=is_lightning_funding_tx,
        )

    def get_spendable_coins(self, domain, *, nonlocal_only=False) -> Sequence[PartialTxInput]:
        confirmed_only = self.config.get('confirmed_only', False)
        with self._freeze_lock:
            frozen_addresses = self._frozen_addresses.copy()
        utxos = self.get_utxos(domain,
                               excluded_addresses=frozen_addresses,
                               mature_only=True,
                               confirmed_funding_only=confirmed_only,
                               nonlocal_only=nonlocal_only)
        utxos = [utxo for utxo in utxos if not self.is_frozen_coin(utxo)]
        return utxos

    @abstractmethod
    def get_receiving_addresses(self, *, slice_start=None, slice_stop=None) -> Sequence[str]:
        pass

    @abstractmethod
    def get_change_addresses(self, *, slice_start=None, slice_stop=None) -> Sequence[str]:
        pass

    def dummy_address(self):
        # first receiving address
        return self.get_receiving_addresses(slice_start=0, slice_stop=1)[0]

    def get_frozen_balance(self):
        with self._freeze_lock:
            frozen_addresses = self._frozen_addresses.copy()
        # note: for coins, use is_frozen_coin instead of _frozen_coins,
        #       as latter only contains *manually* frozen ones
        frozen_coins = {utxo.prevout.to_str() for utxo in self.get_utxos()
                        if self.is_frozen_coin(utxo)}
        if not frozen_coins:  # shortcut
            return self.get_balance(frozen_addresses)
        c1, u1, x1 = self.get_balance()
        c2, u2, x2 = self.get_balance(
            excluded_addresses=frozen_addresses,
            excluded_coins=frozen_coins,
        )
        return c1-c2, u1-u2, x1-x2

    def balance_at_timestamp(self, domain, target_timestamp):
        # we assume that get_history returns items ordered by block height
        # we also assume that block timestamps are monotonic (which is false...!)
        h = self.get_history(domain=domain)
        balance = 0
        for hist_item in h:
            balance = hist_item.balance
            if hist_item.tx_mined_status.timestamp is None or hist_item.tx_mined_status.timestamp > target_timestamp:
                return balance - hist_item.delta
        # return last balance
        return balance

    def get_onchain_history(self, *, domain=None):
        monotonic_timestamp = 0
        for hist_item in self.get_history(domain=domain):
            monotonic_timestamp = max(monotonic_timestamp, (hist_item.tx_mined_status.timestamp or 999_999_999_999))
            yield {
                'txid': hist_item.txid,
                'fee_sat': hist_item.fee,
                'height': hist_item.tx_mined_status.height,
                'confirmations': hist_item.tx_mined_status.conf,
                'timestamp': hist_item.tx_mined_status.timestamp,
                'monotonic_timestamp': monotonic_timestamp,
                'incoming': True if hist_item.delta>0 else False,
                'bc_value': Satoshis(hist_item.delta),
                'bc_balance': Satoshis(hist_item.balance),
                'date': timestamp_to_datetime(hist_item.tx_mined_status.timestamp),
                'label': self.get_label_for_txid(hist_item.txid),
                'txpos_in_block': hist_item.tx_mined_status.txpos,
            }

    def create_invoice(self, *, outputs: List[PartialTxOutput], message, pr, URI) -> Invoice:
        height=self.get_local_height()
        if pr:
            return OnchainInvoice.from_bip70_payreq(pr, height)
        amount = 0
        for x in outputs:
            if parse_max_spend(x.value):
                amount = '!'
                break
            else:
                amount += x.value
        timestamp = None
        exp = None
        if URI:
            timestamp = URI.get('time')
            exp = URI.get('exp')
        timestamp = timestamp or int(time.time())
        exp = exp or 0
        _id = bh2u(sha256d(repr(outputs) + "%d"%timestamp))[0:10]
        invoice = OnchainInvoice(
            type=PR_TYPE_ONCHAIN,
            amount_sat=amount,
            outputs=outputs,
            message=message,
            id=_id,
            time=timestamp,
            exp=exp,
            bip70=None,
            requestor=None,
            height=height,
        )
        return invoice

    def save_invoice(self, invoice: Invoice) -> None:
        key = self.get_key_for_outgoing_invoice(invoice)
        if not invoice.is_lightning():
            assert isinstance(invoice, OnchainInvoice)
            if self.is_onchain_invoice_paid(invoice, 0):
                self.logger.info("saving invoice... but it is already paid!")
            with self.transaction_lock:
                for txout in invoice.outputs:
                    self._invoices_from_scriptpubkey_map[txout.scriptpubkey].add(key)
        self.invoices[key] = invoice
        self.save_db()

    def clear_invoices(self):
        self.invoices = {}
        self.save_db()

    def clear_requests(self):
        self.receive_requests = {}
        self.save_db()

    def get_invoices(self):
        out = list(self.invoices.values())
        out.sort(key=lambda x:x.time)
        return out

    def get_unpaid_invoices(self):
        invoices = self.get_invoices()
        return [x for x in invoices if self.get_invoice_status(x) != PR_PAID]

    def get_invoice(self, key):
        return self.invoices.get(key)

    def import_requests(self, path):
        data = read_json_file(path)
        for x in data:
            req = Invoice.from_json(x)
            self.add_payment_request(req)

    def export_requests(self, path):
        write_json_file(path, list(self.receive_requests.values()))

    def import_invoices(self, path):
        data = read_json_file(path)
        for x in data:
            invoice = Invoice.from_json(x)
            self.save_invoice(invoice)

    def export_invoices(self, path):
        write_json_file(path, list(self.invoices.values()))

    def _get_relevant_invoice_keys_for_tx(self, tx: Transaction) -> Set[str]:
        relevant_invoice_keys = set()
        with self.transaction_lock:
            for txout in tx.outputs():
                for invoice_key in self._invoices_from_scriptpubkey_map.get(txout.scriptpubkey, set()):
                    # note: the invoice might have been deleted since, so check now:
                    if invoice_key in self.invoices:
                        relevant_invoice_keys.add(invoice_key)
        return relevant_invoice_keys

    def get_relevant_invoices_for_tx(self, tx: Transaction) -> Sequence[OnchainInvoice]:
        invoice_keys = self._get_relevant_invoice_keys_for_tx(tx)
        invoices = [self.get_invoice(key) for key in invoice_keys]
        invoices = [inv for inv in invoices if inv]  # filter out None
        for inv in invoices:
            assert isinstance(inv, OnchainInvoice), f"unexpected type {type(inv)}"
        return invoices

    def _prepare_onchain_invoice_paid_detection(self):
        # scriptpubkey -> list(invoice_keys)
        self._invoices_from_scriptpubkey_map = defaultdict(set)  # type: Dict[bytes, Set[str]]
        for invoice_key, invoice in self.invoices.items():
            if invoice.type == PR_TYPE_ONCHAIN:
                assert isinstance(invoice, OnchainInvoice)
                for txout in invoice.outputs:
                    self._invoices_from_scriptpubkey_map[txout.scriptpubkey].add(invoice_key)

    def _is_onchain_invoice_paid(self, invoice: Invoice, conf: int) -> Tuple[bool, Sequence[str]]:
        """Returns whether on-chain invoice is satisfied, and list of relevant TXIDs."""
        assert invoice.type == PR_TYPE_ONCHAIN
        assert isinstance(invoice, OnchainInvoice)
        invoice_amounts = defaultdict(int)  # type: Dict[bytes, int]  # scriptpubkey -> value_sats
        for txo in invoice.outputs:  # type: PartialTxOutput
            invoice_amounts[txo.scriptpubkey] += 1 if parse_max_spend(txo.value) else txo.value
        relevant_txs = []
        with self.transaction_lock:
            for invoice_scriptpubkey, invoice_amt in invoice_amounts.items():
                scripthash = bitcoin.script_to_scripthash(invoice_scriptpubkey.hex())
                prevouts_and_values = self.db.get_prevouts_by_scripthash(scripthash)
                total_received = 0
                for prevout, v in prevouts_and_values:
                    tx_height = self.get_tx_height(prevout.txid.hex())
                    if tx_height.height > 0 and tx_height.height <= invoice.height:
                        continue
                    if tx_height.conf < conf:
                        continue
                    total_received += v
                    relevant_txs.append(prevout.txid.hex())
                # check that there is at least one TXO, and that they pay enough.
                # note: "at least one TXO" check is needed for zero amount invoice (e.g. OP_RETURN)
                if len(prevouts_and_values) == 0:
                    return False, []
                if total_received < invoice_amt:
                    return False, []
        return True, relevant_txs

    def is_onchain_invoice_paid(self, invoice: Invoice, conf: int) -> bool:
        return self._is_onchain_invoice_paid(invoice, conf)[0]

    def _maybe_set_tx_label_based_on_invoices(self, tx: Transaction) -> bool:
        # note: this is not done in 'get_default_label' as that would require deserializing each tx
        tx_hash = tx.txid()
        labels = []
        for invoice in self.get_relevant_invoices_for_tx(tx):
            if invoice.message:
                labels.append(invoice.message)
        if labels and not self._labels.get(tx_hash, ''):
            self.set_label(tx_hash, "; ".join(labels))
        return bool(labels)

    def add_transaction(self, tx, *, allow_unrelated=False):
        is_known = bool(self.db.get_transaction(tx.txid()))
        tx_was_added = super().add_transaction(tx, allow_unrelated=allow_unrelated)
        if tx_was_added and not is_known:
            self._maybe_set_tx_label_based_on_invoices(tx)
            if self.lnworker:
                self.lnworker.maybe_add_backup_from_tx(tx)
        return tx_was_added

    @profiler
    def get_full_history(self, fx=None, *, onchain_domain=None, include_lightning=True):
        transactions_tmp = OrderedDictWithIndex()
        # add on-chain txns
        onchain_history = self.get_onchain_history(domain=onchain_domain)
        for tx_item in onchain_history:
            txid = tx_item['txid']
            transactions_tmp[txid] = tx_item
        # add lnworker onchain transactions
        lnworker_history = self.lnworker.get_onchain_history() if self.lnworker and include_lightning else {}
        for txid, item in lnworker_history.items():
            if txid in transactions_tmp:
                tx_item = transactions_tmp[txid]
                tx_item['group_id'] = item.get('group_id')  # for swaps
                tx_item['label'] = item['label']
                tx_item['type'] = item['type']
                ln_value = Decimal(item['amount_msat']) / 1000   # for channel open/close tx
                tx_item['ln_value'] = Satoshis(ln_value)
            else:
                if item['type'] == 'swap':
                    # swap items do not have all the fields. We can skip skip them
                    # because they will eventually be in onchain_history
                    # TODO: use attr.s objects instead of dicts
                    continue
                transactions_tmp[txid] = item
                ln_value = Decimal(item['amount_msat']) / 1000   # for channel open/close tx
                item['ln_value'] = Satoshis(ln_value)
        # add lightning_transactions
        lightning_history = self.lnworker.get_lightning_history() if self.lnworker and include_lightning else {}
        for tx_item in lightning_history.values():
            txid = tx_item.get('txid')
            ln_value = Decimal(tx_item['amount_msat']) / 1000
            tx_item['lightning'] = True
            tx_item['ln_value'] = Satoshis(ln_value)
            key = tx_item.get('txid') or tx_item['payment_hash']
            transactions_tmp[key] = tx_item
        # sort on-chain and LN stuff into new dict, by timestamp
        # (we rely on this being a *stable* sort)
        transactions = OrderedDictWithIndex()
        for k, v in sorted(list(transactions_tmp.items()),
                           key=lambda x: x[1].get('monotonic_timestamp') or x[1].get('timestamp') or float('inf')):
            transactions[k] = v
        now = time.time()
        balance = 0
        for item in transactions.values():
            # add on-chain and lightning values
            value = Decimal(0)
            if item.get('bc_value'):
                value += item['bc_value'].value
            if item.get('ln_value'):
                value += item.get('ln_value').value
            # note: 'value' and 'balance' has msat precision (as LN has msat precision)
            item['value'] = Satoshis(value)
            balance += value
            item['balance'] = Satoshis(balance)
            if fx and fx.is_enabled() and fx.get_history_config():
                txid = item.get('txid')
                if not item.get('lightning') and txid:
                    fiat_fields = self.get_tx_item_fiat(tx_hash=txid, amount_sat=value, fx=fx, tx_fee=item['fee_sat'])
                    item.update(fiat_fields)
                else:
                    timestamp = item['timestamp'] or now
                    fiat_value = value / Decimal(bitcoin.COIN) * fx.timestamp_rate(timestamp)
                    item['fiat_value'] = Fiat(fiat_value, fx.ccy)
                    item['fiat_default'] = True
        return transactions

    @profiler
    def get_detailed_history(
            self,
            from_timestamp=None,
            to_timestamp=None,
            fx=None,
            show_addresses=False,
            from_height=None,
            to_height=None):
        # History with capital gains, using utxo pricing
        # FIXME: Lightning capital gains would requires FIFO
        if (from_timestamp is not None or to_timestamp is not None) \
                and (from_height is not None or to_height is not None):
            raise Exception('timestamp and block height based filtering cannot be used together')

        show_fiat = fx and fx.is_enabled() and fx.get_history_config()
        out = []
        income = 0
        expenditures = 0
        capital_gains = Decimal(0)
        fiat_income = Decimal(0)
        fiat_expenditures = Decimal(0)
        now = time.time()
        for item in self.get_onchain_history():
            timestamp = item['timestamp']
            if from_timestamp and (timestamp or now) < from_timestamp:
                continue
            if to_timestamp and (timestamp or now) >= to_timestamp:
                continue
            height = item['height']
            if from_height is not None and from_height > height > 0:
                continue
            if to_height is not None and (height >= to_height or height <= 0):
                continue
            tx_hash = item['txid']
            tx = self.db.get_transaction(tx_hash)
            tx_fee = item['fee_sat']
            item['fee'] = Satoshis(tx_fee) if tx_fee is not None else None
            if show_addresses:
                item['inputs'] = list(map(lambda x: x.to_json(), tx.inputs()))
                item['outputs'] = list(map(lambda x: {'address': x.get_ui_address_str(), 'value': Satoshis(x.value)},
                                           tx.outputs()))
            # fixme: use in and out values
            value = item['bc_value'].value
            if value < 0:
                expenditures += -value
            else:
                income += value
            # fiat computations
            if show_fiat:
                fiat_fields = self.get_tx_item_fiat(tx_hash=tx_hash, amount_sat=value, fx=fx, tx_fee=tx_fee)
                fiat_value = fiat_fields['fiat_value'].value
                item.update(fiat_fields)
                if value < 0:
                    capital_gains += fiat_fields['capital_gain'].value
                    fiat_expenditures += -fiat_value
                else:
                    fiat_income += fiat_value
            out.append(item)
        # add summary
        if out:
            first_item = out[0]
            last_item = out[-1]
            if from_height or to_height:
                start_height = from_height
                end_height = to_height
            else:
                start_height = first_item['height'] - 1
                end_height = last_item['height']

            b = first_item['bc_balance'].value
            v = first_item['bc_value'].value
            start_balance = None if b is None or v is None else b - v
            end_balance = last_item['bc_balance'].value

            if from_timestamp is not None and to_timestamp is not None:
                start_timestamp = from_timestamp
                end_timestamp = to_timestamp
            else:
                start_timestamp = first_item['timestamp']
                end_timestamp = last_item['timestamp']

            start_coins = self.get_utxos(
                domain=None,
                block_height=start_height,
                confirmed_funding_only=True,
                confirmed_spending_only=True,
                nonlocal_only=True)
            end_coins = self.get_utxos(
                domain=None,
                block_height=end_height,
                confirmed_funding_only=True,
                confirmed_spending_only=True,
                nonlocal_only=True)

            def summary_point(timestamp, height, balance, coins):
                date = timestamp_to_datetime(timestamp)
                out = {
                    'date': date,
                    'block_height': height,
                    'BTC_balance': Satoshis(balance),
                }
                if show_fiat:
                    ap = self.acquisition_price(coins, fx.timestamp_rate, fx.ccy)
                    lp = self.liquidation_price(coins, fx.timestamp_rate, timestamp)
                    out['acquisition_price'] = Fiat(ap, fx.ccy)
                    out['liquidation_price'] = Fiat(lp, fx.ccy)
                    out['unrealized_gains'] = Fiat(lp - ap, fx.ccy)
                    out['fiat_balance'] = Fiat(fx.historical_value(balance, date), fx.ccy)
                    out['BTC_fiat_price'] = Fiat(fx.historical_value(COIN, date), fx.ccy)
                return out

            summary_start = summary_point(start_timestamp, start_height, start_balance, start_coins)
            summary_end = summary_point(end_timestamp, end_height, end_balance, end_coins)
            flow = {
                'BTC_incoming': Satoshis(income),
                'BTC_outgoing': Satoshis(expenditures)
            }
            if show_fiat:
                flow['fiat_currency'] = fx.ccy
                flow['fiat_incoming'] = Fiat(fiat_income, fx.ccy)
                flow['fiat_outgoing'] = Fiat(fiat_expenditures, fx.ccy)
                flow['realized_capital_gains'] = Fiat(capital_gains, fx.ccy)
            summary = {
                'begin': summary_start,
                'end': summary_end,
                'flow': flow,
            }

        else:
            summary = {}
        return {
            'transactions': out,
            'summary': summary
        }

    def acquisition_price(self, coins, price_func, ccy):
        return Decimal(sum(self.coin_price(coin.prevout.txid.hex(), price_func, ccy, self.get_txin_value(coin)) for coin in coins))

    def liquidation_price(self, coins, price_func, timestamp):
        p = price_func(timestamp)
        return sum([coin.value_sats() for coin in coins]) * p / Decimal(COIN)

    def default_fiat_value(self, tx_hash, fx, value_sat):
        return value_sat / Decimal(COIN) * self.price_at_timestamp(tx_hash, fx.timestamp_rate)

    def get_tx_item_fiat(
            self,
            *,
            tx_hash: str,
            amount_sat: int,
            fx: 'FxThread',
            tx_fee: Optional[int],
    ) -> Dict[str, Any]:
        item = {}
        fiat_value = self.get_fiat_value(tx_hash, fx.ccy)
        fiat_default = fiat_value is None
        fiat_rate = self.price_at_timestamp(tx_hash, fx.timestamp_rate)
        fiat_value = fiat_value if fiat_value is not None else self.default_fiat_value(tx_hash, fx, amount_sat)
        fiat_fee = tx_fee / Decimal(COIN) * fiat_rate if tx_fee is not None else None
        item['fiat_currency'] = fx.ccy
        item['fiat_rate'] = Fiat(fiat_rate, fx.ccy)
        item['fiat_value'] = Fiat(fiat_value, fx.ccy)
        item['fiat_fee'] = Fiat(fiat_fee, fx.ccy) if fiat_fee is not None else None
        item['fiat_default'] = fiat_default
        if amount_sat < 0:
            acquisition_price = - amount_sat / Decimal(COIN) * self.average_price(tx_hash, fx.timestamp_rate, fx.ccy)
            liquidation_price = - fiat_value
            item['acquisition_price'] = Fiat(acquisition_price, fx.ccy)
            cg = liquidation_price - acquisition_price
            item['capital_gain'] = Fiat(cg, fx.ccy)
        return item

    def get_label(self, key: str) -> str:
        # key is typically: address / txid / LN-payment-hash-hex
        return self._labels.get(key) or ''

    def get_label_for_txid(self, tx_hash: str) -> str:
        return self._labels.get(tx_hash) or self._get_default_label_for_txid(tx_hash)

    def _get_default_label_for_txid(self, tx_hash: str) -> str:
        # if no inputs are ismine, concat labels of output addresses
        if not self.db.get_txi_addresses(tx_hash):
            labels = []
            for addr in self.db.get_txo_addresses(tx_hash):
                label = self._labels.get(addr)
                if label:
                    labels.append(label)
            return ', '.join(labels)
        return ''

    def get_all_labels(self) -> Dict[str, str]:
        with self.lock:
            return copy.copy(self._labels)

    def get_tx_status(self, tx_hash, tx_mined_info: TxMinedInfo):
        extra = []
        height = tx_mined_info.height
        conf = tx_mined_info.conf
        timestamp = tx_mined_info.timestamp
        if height == TX_HEIGHT_FUTURE:
            assert conf < 0, conf
            num_blocks_remainining = -conf
            return 2, f'in {num_blocks_remainining} blocks'
        if conf == 0:
            tx = self.db.get_transaction(tx_hash)
            if not tx:
                return 2, 'unknown'
            is_final = tx and tx.is_final()
            if not is_final:
                extra.append('rbf')
            fee = self.get_tx_fee(tx_hash)
            if fee is not None:
                size = tx.estimated_size()
                fee_per_byte = fee / size
                extra.append(format_fee_satoshis(fee_per_byte) + ' sat/b')
            if fee is not None and height in (TX_HEIGHT_UNCONF_PARENT, TX_HEIGHT_UNCONFIRMED) \
               and self.config.has_fee_mempool():
                exp_n = self.config.fee_to_depth(fee_per_byte)
                if exp_n is not None:
                    extra.append('%.2f MB'%(exp_n/1000000))
            if height == TX_HEIGHT_LOCAL:
                status = 3
            elif height == TX_HEIGHT_UNCONF_PARENT:
                status = 1
            elif height == TX_HEIGHT_UNCONFIRMED:
                status = 0
            else:
                status = 2  # not SPV verified
        else:
            status = 3 + min(conf, 6)
        time_str = format_time(timestamp) if timestamp else _("unknown")
        status_str = TX_STATUS[status] if status < 4 else time_str
        if extra:
            status_str += ' [%s]'%(', '.join(extra))
        return status, status_str

    def relayfee(self):
        return relayfee(self.network)

    def dust_threshold(self):
        return dust_threshold(self.network)

    def get_unconfirmed_base_tx_for_batching(self) -> Optional[Transaction]:
        candidate = None
        for hist_item in self.get_history():
            # tx should not be mined yet
            if hist_item.tx_mined_status.conf > 0: continue
            # conservative future proofing of code: only allow known unconfirmed types
            if hist_item.tx_mined_status.height not in (TX_HEIGHT_UNCONFIRMED,
                                                        TX_HEIGHT_UNCONF_PARENT,
                                                        TX_HEIGHT_LOCAL):
                continue
            # tx should be "outgoing" from wallet
            if hist_item.delta >= 0:
                continue
            tx = self.db.get_transaction(hist_item.txid)
            if not tx:
                continue
            # is_mine outputs should not be spent yet
            # to avoid cancelling our own dependent transactions
            txid = tx.txid()
            if any([self.is_mine(o.address) and self.db.get_spent_outpoint(txid, output_idx)
                    for output_idx, o in enumerate(tx.outputs())]):
                continue
            # all inputs should be is_mine
            if not all([self.is_mine(self.get_txin_address(txin)) for txin in tx.inputs()]):
                continue
            # do not mutate LN funding txs, as that would change their txid
            if self.is_lightning_funding_tx(txid):
                continue
            # tx must have opted-in for RBF (even if local, for consistency)
            if tx.is_final():
                continue
            # prefer txns already in mempool (vs local)
            if hist_item.tx_mined_status.height == TX_HEIGHT_LOCAL:
                candidate = tx
                continue
            return tx
        return candidate

    def get_change_addresses_for_new_transaction(
            self, preferred_change_addr=None, *, allow_reusing_used_change_addrs: bool = True,
    ) -> List[str]:
        change_addrs = []
        if preferred_change_addr:
            if isinstance(preferred_change_addr, (list, tuple)):
                change_addrs = list(preferred_change_addr)
            else:
                change_addrs = [preferred_change_addr]
        elif self.use_change:
            # Recalc and get unused change addresses
            addrs = self.calc_unused_change_addresses()
            # New change addresses are created only after a few
            # confirmations.
            if addrs:
                # if there are any unused, select all
                change_addrs = addrs
            else:
                # if there are none, take one randomly from the last few
                if not allow_reusing_used_change_addrs:
                    return []
                addrs = self.get_change_addresses(slice_start=-self.gap_limit_for_change)
                change_addrs = [random.choice(addrs)] if addrs else []
        for addr in change_addrs:
            assert is_address(addr), f"not valid bitcoin address: {addr}"
            # note that change addresses are not necessarily ismine
            # in which case this is a no-op
            self.check_address_for_corruption(addr)
        max_change = self.max_change_outputs if self.multiple_change else 1
        return change_addrs[:max_change]

    def get_single_change_address_for_new_transaction(
            self, preferred_change_addr=None, *, allow_reusing_used_change_addrs: bool = True,
    ) -> Optional[str]:
        addrs = self.get_change_addresses_for_new_transaction(
            preferred_change_addr=preferred_change_addr,
            allow_reusing_used_change_addrs=allow_reusing_used_change_addrs,
        )
        if addrs:
            return addrs[0]
        return None

    @check_returned_address_for_corruption
    def get_new_sweep_address_for_channel(self) -> str:
        # Recalc and get unused change addresses
        addrs = self.calc_unused_change_addresses()
        if addrs:
            selected_addr = addrs[0]
        else:
            # if there are none, take one randomly from the last few
            addrs = self.get_change_addresses(slice_start=-self.gap_limit_for_change)
            if addrs:
                selected_addr = random.choice(addrs)
            else:  # fallback for e.g. imported wallets
                selected_addr = self.get_receiving_address()
        assert is_address(selected_addr), f"not valid bitcoin address: {selected_addr}"
        return selected_addr

    def make_unsigned_transaction(
            self, *,
            coins: Sequence[PartialTxInput],
            outputs: List[PartialTxOutput],
            fee=None,
            change_addr: str = None,
            is_sweep=False,
            rbf=False) -> PartialTransaction:

        if not coins:  # any bitcoin tx must have at least 1 input by consensus
            raise NotEnoughFunds()
        if any([c.already_has_some_signatures() for c in coins]):
            raise Exception("Some inputs already contain signatures!")

        # prevent side-effect with '!'
        outputs = copy.deepcopy(outputs)

        # check outputs
        i_max = []
        i_max_sum = 0
        for i, o in enumerate(outputs):
            weight = parse_max_spend(o.value)
            if weight:
                i_max_sum += weight
                i_max.append((weight, i))

        if fee is None and self.config.fee_per_kb() is None:
            raise NoDynamicFeeEstimates()

        for item in coins:
            self.add_input_info(item)

        # Fee estimator
        if fee is None:
            fee_estimator = self.config.estimate_fee
        elif isinstance(fee, Number):
            fee_estimator = lambda size: fee
        elif callable(fee):
            fee_estimator = fee
        else:
            raise Exception(f'Invalid argument fee: {fee}')

        if len(i_max) == 0:
            # Let the coin chooser select the coins to spend
            coin_chooser = coinchooser.get_coin_chooser(self.config)
            # If there is an unconfirmed RBF tx, merge with it
            base_tx = self.get_unconfirmed_base_tx_for_batching()
            if self.config.get('batch_rbf', False) and base_tx:
                # make sure we don't try to spend change from the tx-to-be-replaced:
                coins = [c for c in coins if c.prevout.txid.hex() != base_tx.txid()]
                is_local = self.get_tx_height(base_tx.txid()).height == TX_HEIGHT_LOCAL
                base_tx = PartialTransaction.from_tx(base_tx)
                base_tx.add_info_from_wallet(self)
                base_tx_fee = base_tx.get_fee()
                relayfeerate = Decimal(self.relayfee()) / 1000
                original_fee_estimator = fee_estimator
                def fee_estimator(size: Union[int, float, Decimal]) -> int:
                    size = Decimal(size)
                    lower_bound = base_tx_fee + round(size * relayfeerate)
                    lower_bound = lower_bound if not is_local else 0
                    return int(max(lower_bound, original_fee_estimator(size)))
                txi = base_tx.inputs()
                txo = list(filter(lambda o: not self.is_change(o.address), base_tx.outputs()))
                old_change_addrs = [o.address for o in base_tx.outputs() if self.is_change(o.address)]
            else:
                txi = []
                txo = []
                old_change_addrs = []
            # change address. if empty, coin_chooser will set it
            change_addrs = self.get_change_addresses_for_new_transaction(change_addr or old_change_addrs)
            tx = coin_chooser.make_tx(
                coins=coins,
                inputs=txi,
                outputs=list(outputs) + txo,
                change_addrs=change_addrs,
                fee_estimator_vb=fee_estimator,
                dust_threshold=self.dust_threshold())
        else:
            # "spend max" branch
            # note: This *will* spend inputs with negative effective value (if there are any).
            #       Given as the user is spending "max", and so might be abandoning the wallet,
            #       try to include all UTXOs, otherwise leftover might remain in the UTXO set
            #       forever. see #5433
            # note: Actually it might be the case that not all UTXOs from the wallet are
            #       being spent if the user manually selected UTXOs.
            sendable = sum(map(lambda c: c.value_sats(), coins))
            for (_,i) in i_max:
                outputs[i].value = 0
            tx = PartialTransaction.from_io(list(coins), list(outputs))
            fee = fee_estimator(tx.estimated_size())
            amount = sendable - tx.output_value() - fee
            if amount < 0:
                raise NotEnoughFunds()
            distr_amount = 0
            for (weight, i) in i_max:
                val = int((amount/i_max_sum) * weight)
                outputs[i].value = val
                distr_amount += val

            (x,i) = i_max[-1]
            outputs[i].value += (amount - distr_amount)
            tx = PartialTransaction.from_io(list(coins), list(outputs))

        # Timelock tx to current height.
        tx.locktime = get_locktime_for_new_transaction(self.network)

        tx.set_rbf(rbf)
        tx.add_info_from_wallet(self)
        run_hook('make_unsigned_transaction', self, tx)
        return tx

    def mktx(self, *,
             outputs: List[PartialTxOutput],
             password=None, fee=None, change_addr=None,
             domain=None, rbf=False, nonlocal_only=False,
             tx_version=None, sign=True) -> PartialTransaction:
        coins = self.get_spendable_coins(domain, nonlocal_only=nonlocal_only)
        tx = self.make_unsigned_transaction(
            coins=coins,
            outputs=outputs,
            fee=fee,
            change_addr=change_addr,
            rbf=rbf)
        if tx_version is not None:
            tx.version = tx_version
        if sign:
            self.sign_transaction(tx, password)
        return tx

    def is_frozen_address(self, addr: str) -> bool:
        return addr in self._frozen_addresses

    def is_frozen_coin(self, utxo: PartialTxInput) -> bool:
        prevout_str = utxo.prevout.to_str()
        frozen = self._frozen_coins.get(prevout_str, None)
        # note: there are three possible states for 'frozen':
        #       True/False if the user explicitly set it,
        #       None otherwise
        if frozen is None:
            return self._is_coin_small_and_unconfirmed(utxo)
        return bool(frozen)

    def _is_coin_small_and_unconfirmed(self, utxo: PartialTxInput) -> bool:
        """If true, the coin should not be spent.
        The idea here is that an attacker might send us a UTXO in a
        large low-fee unconfirmed tx that will ~never confirm. If we
        spend it as part of a tx ourselves, that too will not confirm
        (unless we use a high fee but that might not be worth it for
        a small value UTXO).
        In particular, this test triggers for large "dusting transactions"
        that are used for advertising purposes by some entities.
        see #6960
        """
        # confirmed UTXOs are fine; check this first for performance:
        block_height = utxo.block_height
        assert block_height is not None
        if block_height > 0:
            return False
        # exempt large value UTXOs
        value_sats = utxo.value_sats()
        assert value_sats is not None
        threshold = self.config.get('unconf_utxo_freeze_threshold', 5_000)
        if value_sats >= threshold:
            return False
        # if funding tx has any is_mine input, then UTXO is fine
        funding_tx = self.db.get_transaction(utxo.prevout.txid.hex())
        if funding_tx is None:
            # we should typically have the funding tx available;
            # might not have it e.g. while not up_to_date
            return True
        if any(self.is_mine(self.get_txin_address(txin))
               for txin in funding_tx.inputs()):
            return False
        return True

    def set_frozen_state_of_addresses(self, addrs: Sequence[str], freeze: bool) -> bool:
        """Set frozen state of the addresses to FREEZE, True or False"""
        if all(self.is_mine(addr) for addr in addrs):
            with self._freeze_lock:
                if freeze:
                    self._frozen_addresses |= set(addrs)
                else:
                    self._frozen_addresses -= set(addrs)
                self.db.put('frozen_addresses', list(self._frozen_addresses))
                return True
        return False

    def set_frozen_state_of_coins(self, utxos: Sequence[str], freeze: bool) -> None:
        """Set frozen state of the utxos to FREEZE, True or False"""
        # basic sanity check that input is not garbage: (see if raises)
        [TxOutpoint.from_str(utxo) for utxo in utxos]
        with self._freeze_lock:
            for utxo in utxos:
                self._frozen_coins[utxo] = bool(freeze)

    def is_address_reserved(self, addr: str) -> bool:
        # note: atm 'reserved' status is only taken into consideration for 'change addresses'
        return addr in self._reserved_addresses

    def set_reserved_state_of_address(self, addr: str, *, reserved: bool) -> None:
        if not self.is_mine(addr):
            return
        with self.lock:
            if reserved:
                self._reserved_addresses.add(addr)
            else:
                self._reserved_addresses.discard(addr)
            self.db.put('reserved_addresses', list(self._reserved_addresses))

    def can_export(self):
        return not self.is_watching_only() and hasattr(self.keystore, 'get_private_key')

    def address_is_old(self, address: str, *, req_conf: int = 3) -> bool:
        """Returns whether address has any history that is deeply confirmed.
        Used for reorg-safe(ish) gap limit roll-forward.
        """
        max_conf = -1
        h = self.db.get_addr_history(address)
        needs_spv_check = not self.config.get("skipmerklecheck", False)
        for tx_hash, tx_height in h:
            if needs_spv_check:
                tx_age = self.get_tx_height(tx_hash).conf
            else:
                if tx_height <= 0:
                    tx_age = 0
                else:
                    tx_age = self.get_local_height() - tx_height + 1
            max_conf = max(max_conf, tx_age)
        return max_conf >= req_conf

    def bump_fee(
            self,
            *,
            tx: Transaction,
            txid: str = None,
            new_fee_rate: Union[int, float, Decimal],
            coins: Sequence[PartialTxInput] = None,
            strategies: Sequence[BumpFeeStrategy] = None,
    ) -> PartialTransaction:
        """Increase the miner fee of 'tx'.
        'new_fee_rate' is the target min rate in sat/vbyte
        'coins' is a list of UTXOs we can choose from as potential new inputs to be added
        """
        txid = txid or tx.txid()
        assert txid
        assert tx.txid() in (None, txid)
        if not isinstance(tx, PartialTransaction):
            tx = PartialTransaction.from_tx(tx)
        assert isinstance(tx, PartialTransaction)
        tx.remove_signatures()
        if tx.is_final():
            raise CannotBumpFee(_('Transaction is final'))
        new_fee_rate = quantize_feerate(new_fee_rate)  # strip excess precision
        try:
            # note: this might download input utxos over network
            tx.add_info_from_wallet(self, ignore_network_issues=False)
        except NetworkException as e:
            raise CannotBumpFee(repr(e))
        old_tx_size = tx.estimated_size()
        old_fee = tx.get_fee()
        assert old_fee is not None
        old_fee_rate = old_fee / old_tx_size  # sat/vbyte
        if new_fee_rate <= old_fee_rate:
            raise CannotBumpFee(_("The new fee rate needs to be higher than the old fee rate."))

        if not strategies:
            strategies = [BumpFeeStrategy.COINCHOOSER, BumpFeeStrategy.DECREASE_CHANGE]
        tx_new = None
        exc = None
        for strat in strategies:
            try:
                if strat == BumpFeeStrategy.COINCHOOSER:
                    tx_new = self._bump_fee_through_coinchooser(
                        tx=tx,
                        txid=txid,
                        new_fee_rate=new_fee_rate,
                        coins=coins,
                    )
                elif strat == BumpFeeStrategy.DECREASE_CHANGE:
                    tx_new = self._bump_fee_through_decreasing_change(
                        tx=tx, new_fee_rate=new_fee_rate)
                elif strat == BumpFeeStrategy.DECREASE_PAYMENT:
                    tx_new = self._bump_fee_through_decreasing_payment(
                        tx=tx, new_fee_rate=new_fee_rate)
                else:
                    raise NotImplementedError(f"unexpected strategy: {strat}")
            except CannotBumpFee as e:
                exc = e
            else:
                strat_used = strat
                break
        if tx_new is None:
            assert exc
            raise exc  # all strategies failed, re-raise last exception

        target_min_fee = new_fee_rate * tx_new.estimated_size()
        actual_fee = tx_new.get_fee()
        if actual_fee + 1 < target_min_fee:
            raise CannotBumpFee(
                f"bump_fee fee target was not met (strategy: {strat_used}). "
                f"got {actual_fee}, expected >={target_min_fee}. "
                f"target rate was {new_fee_rate}")
        tx_new.locktime = get_locktime_for_new_transaction(self.network)
        tx_new.set_rbf(True)
        tx_new.add_info_from_wallet(self)
        return tx_new

    def _bump_fee_through_coinchooser(
            self,
            *,
            tx: PartialTransaction,
            txid: str,
            new_fee_rate: Union[int, Decimal],
            coins: Sequence[PartialTxInput] = None,
    ) -> PartialTransaction:
        """Increase the miner fee of 'tx'.

        - keeps all inputs
        - keeps all not is_mine outputs,
        - allows adding new inputs
        """
        assert txid
        tx = copy.deepcopy(tx)
        tx.add_info_from_wallet(self)
        assert tx.get_fee() is not None
        old_inputs = list(tx.inputs())
        old_outputs = list(tx.outputs())
        # change address
        old_change_addrs = [o.address for o in old_outputs if self.is_change(o.address)]
        change_addrs = self.get_change_addresses_for_new_transaction(old_change_addrs)
        # which outputs to keep?
        if old_change_addrs:
            fixed_outputs = list(filter(lambda o: not self.is_change(o.address), old_outputs))
        else:
            if all(self.is_mine(o.address) for o in old_outputs):
                # all outputs are is_mine and none of them are change.
                # we bail out as it's unclear what the user would want!
                # the coinchooser bump fee method is probably not a good idea in this case
                raise CannotBumpFee(_('All outputs are non-change is_mine'))
            old_not_is_mine = list(filter(lambda o: not self.is_mine(o.address), old_outputs))
            if old_not_is_mine:
                fixed_outputs = old_not_is_mine
            else:
                fixed_outputs = old_outputs
        if not fixed_outputs:
            raise CannotBumpFee(_('Could not figure out which outputs to keep'))

        if coins is None:
            coins = self.get_spendable_coins(None)
        # make sure we don't try to spend output from the tx-to-be-replaced:
        coins = [c for c in coins if c.prevout.txid.hex() != txid]
        for item in coins:
            self.add_input_info(item)
        def fee_estimator(size):
            return self.config.estimate_fee_for_feerate(fee_per_kb=new_fee_rate*1000, size=size)
        coin_chooser = coinchooser.get_coin_chooser(self.config)
        try:
            return coin_chooser.make_tx(
                coins=coins,
                inputs=old_inputs,
                outputs=fixed_outputs,
                change_addrs=change_addrs,
                fee_estimator_vb=fee_estimator,
                dust_threshold=self.dust_threshold())
        except NotEnoughFunds as e:
            raise CannotBumpFee(e)

    def _bump_fee_through_decreasing_change(
            self,
            *,
            tx: PartialTransaction,
            new_fee_rate: Union[int, Decimal],
    ) -> PartialTransaction:
        """Increase the miner fee of 'tx'.

        - keeps all inputs
        - no new inputs are added
        - allows decreasing and removing outputs (change is decreased first)
        This is less "safe" than "coinchooser" method as it might end up decreasing
        e.g. a payment to a merchant; but e.g. if the user has sent "Max" previously,
        this is the only way to RBF.
        """
        tx = copy.deepcopy(tx)
        tx.add_info_from_wallet(self)
        assert tx.get_fee() is not None
        inputs = tx.inputs()
        outputs = tx._outputs  # note: we will mutate this directly

        # use own outputs
        s = list(filter(lambda o: self.is_mine(o.address), outputs))
        # ... unless there is none
        if not s:
            s = outputs
            x_fee = run_hook('get_tx_extra_fee', self, tx)
            if x_fee:
                x_fee_address, x_fee_amount = x_fee
                s = list(filter(lambda o: o.address != x_fee_address, s))
        if not s:
            raise CannotBumpFee('No outputs at all??')

        # prioritize low value outputs, to get rid of dust
        s = sorted(s, key=lambda o: o.value)
        for o in s:
            target_fee = int(math.ceil(tx.estimated_size() * new_fee_rate))
            delta = target_fee - tx.get_fee()
            i = outputs.index(o)
            if o.value - delta >= self.dust_threshold():
                new_output_value = o.value - delta
                assert isinstance(new_output_value, int)
                outputs[i].value = new_output_value
                delta = 0
                break
            else:
                del outputs[i]
                # note: we mutated the outputs of tx, which will affect
                #       tx.estimated_size() in the next iteration
        if delta > 0:
            raise CannotBumpFee(_('Could not find suitable outputs'))

        return PartialTransaction.from_io(inputs, outputs)

    def _bump_fee_through_decreasing_payment(
            self,
            *,
            tx: PartialTransaction,
            new_fee_rate: Union[int, Decimal],
    ) -> PartialTransaction:
        """Increase the miner fee of 'tx'.

        - keeps all inputs
        - no new inputs are added
        - decreases payment outputs (not change!). Each non-ismine output is decreased
          proportionally to their byte-size.
        """
        tx = copy.deepcopy(tx)
        tx.add_info_from_wallet(self)
        assert tx.get_fee() is not None
        inputs = tx.inputs()
        outputs = tx.outputs()

        # select non-ismine outputs
        s = [(idx, out) for (idx, out) in enumerate(outputs)
             if not self.is_mine(out.address)]
        # exempt 2fa fee output if present
        x_fee = run_hook('get_tx_extra_fee', self, tx)
        if x_fee:
            x_fee_address, x_fee_amount = x_fee
            s = [(idx, out) for (idx, out) in s if out.address != x_fee_address]
        if not s:
            raise CannotBumpFee("Cannot find payment output")

        del_out_idxs = set()
        tx_size = tx.estimated_size()
        cur_fee = tx.get_fee()
        # Main loop. Each iteration decreases value of all selected outputs.
        # The number of iterations is bounded by len(s) as only the final iteration
        # can *not remove* any output.
        for __ in range(len(s) + 1):
            target_fee = int(math.ceil(tx_size * new_fee_rate))
            delta_total = target_fee - cur_fee
            if delta_total <= 0:
                break
            out_size_total = sum(Transaction.estimated_output_size_for_script(out.scriptpubkey.hex())
                                 for (idx, out) in s if idx not in del_out_idxs)
            for idx, out in s:
                out_size = Transaction.estimated_output_size_for_script(out.scriptpubkey.hex())
                delta = int(math.ceil(delta_total * out_size / out_size_total))
                if out.value - delta >= self.dust_threshold():
                    new_output_value = out.value - delta
                    assert isinstance(new_output_value, int)
                    outputs[idx].value = new_output_value
                    cur_fee += delta
                else:  # remove output
                    tx_size -= out_size
                    cur_fee += out.value
                    del_out_idxs.add(idx)
        if delta_total > 0:
            raise CannotBumpFee(_('Could not find suitable outputs'))

        outputs = [out for (idx, out) in enumerate(outputs) if idx not in del_out_idxs]
        return PartialTransaction.from_io(inputs, outputs)

    def cpfp(self, tx: Transaction, fee: int) -> Optional[PartialTransaction]:
        txid = tx.txid()
        for i, o in enumerate(tx.outputs()):
            address, value = o.address, o.value
            if self.is_mine(address):
                break
        else:
            raise CannotCPFP(_("Could not find suitable output"))
        coins = self.get_addr_utxo(address)
        item = coins.get(TxOutpoint.from_str(txid+':%d'%i))
        if not item:
            raise CannotCPFP(_("Could not find coins for output"))
        inputs = [item]
        out_address = (self.get_single_change_address_for_new_transaction(allow_reusing_used_change_addrs=False)
                       or self.get_unused_address()
                       or address)
        output_value = value - fee
        if output_value < self.dust_threshold():
            raise CannotCPFP(_("The output value remaining after fee is too low."))
        outputs = [PartialTxOutput.from_address_and_value(out_address, output_value)]
        locktime = get_locktime_for_new_transaction(self.network)
        tx_new = PartialTransaction.from_io(inputs, outputs, locktime=locktime)
        tx_new.set_rbf(True)
        tx_new.add_info_from_wallet(self)
        return tx_new

    def dscancel(
            self, *, tx: Transaction, new_fee_rate: Union[int, float, Decimal]
    ) -> PartialTransaction:
        """Double-Spend-Cancel: cancel an unconfirmed tx by double-spending
        its inputs, paying ourselves.
        'new_fee_rate' is the target min rate in sat/vbyte
        """
        if not isinstance(tx, PartialTransaction):
            tx = PartialTransaction.from_tx(tx)
        assert isinstance(tx, PartialTransaction)
        tx.remove_signatures()

        if tx.is_final():
            raise CannotDoubleSpendTx(_('Transaction is final'))
        new_fee_rate = quantize_feerate(new_fee_rate)  # strip excess precision
        try:
            # note: this might download input utxos over network
            tx.add_info_from_wallet(self, ignore_network_issues=False)
        except NetworkException as e:
            raise CannotDoubleSpendTx(repr(e))
        old_tx_size = tx.estimated_size()
        old_fee = tx.get_fee()
        assert old_fee is not None
        old_fee_rate = old_fee / old_tx_size  # sat/vbyte
        if new_fee_rate <= old_fee_rate:
            raise CannotDoubleSpendTx(_("The new fee rate needs to be higher than the old fee rate."))
        # grab all ismine inputs
        inputs = [txin for txin in tx.inputs()
                  if self.is_mine(self.get_txin_address(txin))]
        value = sum([txin.value_sats() for txin in inputs])
        # figure out output address
        old_change_addrs = [o.address for o in tx.outputs() if self.is_mine(o.address)]
        out_address = (self.get_single_change_address_for_new_transaction(old_change_addrs)
                       or self.get_receiving_address())
        locktime = get_locktime_for_new_transaction(self.network)
        outputs = [PartialTxOutput.from_address_and_value(out_address, value)]
        tx_new = PartialTransaction.from_io(inputs, outputs, locktime=locktime)
        new_tx_size = tx_new.estimated_size()
        new_fee = max(
            new_fee_rate * new_tx_size,
            old_fee + self.relayfee() * new_tx_size / Decimal(1000),  # BIP-125 rules 3 and 4
        )
        new_fee = int(math.ceil(new_fee))
        output_value = value - new_fee
        if output_value < self.dust_threshold():
            raise CannotDoubleSpendTx(_("The output value remaining after fee is too low."))
        outputs = [PartialTxOutput.from_address_and_value(out_address, value - new_fee)]
        tx_new = PartialTransaction.from_io(inputs, outputs, locktime=locktime)
        tx_new.set_rbf(True)
        tx_new.add_info_from_wallet(self)
        return tx_new

    @abstractmethod
    def _add_input_sig_info(self, txin: PartialTxInput, address: str, *, only_der_suffix: bool) -> None:
        pass

    def _add_txinout_derivation_info(self, txinout: Union[PartialTxInput, PartialTxOutput],
                                     address: str, *, only_der_suffix: bool) -> None:
        pass  # implemented by subclasses

    def _add_input_utxo_info(
            self,
            txin: PartialTxInput,
            *,
            address: str = None,
            ignore_network_issues: bool = True,
    ) -> None:
        # We prefer to include UTXO (full tx) for every input.
        # We cannot include UTXO if the prev tx is not signed yet though (chain of unsigned txs),
        # in which case we might include a WITNESS_UTXO.
        address = address or txin.address
        if txin.witness_utxo is None and txin.is_segwit() and address:
            received, spent = self.get_addr_io(address)
            item = received.get(txin.prevout.to_str())
            if item:
                txin_value = item[1]
                txin.witness_utxo = TxOutput.from_address_and_value(address, txin_value)
        if txin.utxo is None:
            txin.utxo = self.get_input_tx(txin.prevout.txid.hex(), ignore_network_issues=ignore_network_issues)
        txin.ensure_there_is_only_one_utxo()

    def _learn_derivation_path_for_address_from_txinout(self, txinout: Union[PartialTxInput, PartialTxOutput],
                                                        address: str) -> bool:
        """Tries to learn the derivation path for an address (potentially beyond gap limit)
        using data available in given txin/txout.
        Returns whether the address was found to be is_mine.
        """
        return False  # implemented by subclasses

    def add_input_info(
            self,
            txin: PartialTxInput,
            *,
            only_der_suffix: bool = False,
            ignore_network_issues: bool = True,
    ) -> None:
        address = self.get_txin_address(txin)
        # note: we add input utxos regardless of is_mine
        self._add_input_utxo_info(txin, ignore_network_issues=ignore_network_issues, address=address)
        if not self.is_mine(address):
            is_mine = self._learn_derivation_path_for_address_from_txinout(txin, address)
            if not is_mine:
                return
        # set script_type first, as later checks might rely on it:
        txin.script_type = self.get_txin_type(address)
        txin.num_sig = self.m if isinstance(self, Multisig_Wallet) else 1
        if txin.redeem_script is None:
            try:
                redeem_script_hex = self.get_redeem_script(address)
                txin.redeem_script = bfh(redeem_script_hex) if redeem_script_hex else None
            except UnknownTxinType:
                pass
        if txin.witness_script is None:
            try:
                witness_script_hex = self.get_witness_script(address)
                txin.witness_script = bfh(witness_script_hex) if witness_script_hex else None
            except UnknownTxinType:
                pass
        self._add_input_sig_info(txin, address, only_der_suffix=only_der_suffix)

    def can_sign(self, tx: Transaction) -> bool:
        if not isinstance(tx, PartialTransaction):
            return False
        if tx.is_complete():
            return False
        # add info to inputs if we can; otherwise we might return a false negative:
        tx.add_info_from_wallet(self)
        for txin in tx.inputs():
            # note: is_mine check needed to avoid false positives.
            #       just because keystore could sign, txin does not necessarily belong to wallet.
            #       Example: we have p2pkh-like addresses and txin is a multisig that involves our pubkey.
            if not self.is_mine(txin.address):
                continue
            for k in self.get_keystores():
                if k.can_sign_txin(txin):
                    return True
        return False

    def get_input_tx(self, tx_hash: str, *, ignore_network_issues=False) -> Optional[Transaction]:
        # First look up an input transaction in the wallet where it
        # will likely be.  If co-signing a transaction it may not have
        # all the input txs, in which case we ask the network.
        tx = self.db.get_transaction(tx_hash)
        if not tx and self.network and self.network.has_internet_connection():
            try:
                raw_tx = self.network.run_from_another_thread(
                    self.network.get_transaction(tx_hash, timeout=10))
            except NetworkException as e:
                self.logger.info(f'got network error getting input txn. err: {repr(e)}. txid: {tx_hash}. '
                                 f'if you are intentionally offline, consider using the --offline flag')
                if not ignore_network_issues:
                    raise e
            else:
                tx = Transaction(raw_tx)
        if not tx and not ignore_network_issues:
            raise NetworkException('failed to get prev tx from network')
        return tx

    def add_output_info(self, txout: PartialTxOutput, *, only_der_suffix: bool = False) -> None:
        address = txout.address
        if not self.is_mine(address):
            is_mine = self._learn_derivation_path_for_address_from_txinout(txout, address)
            if not is_mine:
                return
        txout.script_type = self.get_txin_type(address)
        txout.is_mine = True
        txout.is_change = self.is_change(address)
        if isinstance(self, Multisig_Wallet):
            txout.num_sig = self.m
        self._add_txinout_derivation_info(txout, address, only_der_suffix=only_der_suffix)
        if txout.redeem_script is None:
            try:
                redeem_script_hex = self.get_redeem_script(address)
                txout.redeem_script = bfh(redeem_script_hex) if redeem_script_hex else None
            except UnknownTxinType:
                pass
        if txout.witness_script is None:
            try:
                witness_script_hex = self.get_witness_script(address)
                txout.witness_script = bfh(witness_script_hex) if witness_script_hex else None
            except UnknownTxinType:
                pass

    def sign_transaction(self, tx: Transaction, password) -> Optional[PartialTransaction]:
        if self.is_watching_only():
            return
        if not isinstance(tx, PartialTransaction):
            return
        # add info to a temporary tx copy; including xpubs
        # and full derivation paths as hw keystores might want them
        tmp_tx = copy.deepcopy(tx)
        tmp_tx.add_info_from_wallet(self, include_xpubs=True)
        # sign. start with ready keystores.
        for k in sorted(self.get_keystores(), key=lambda ks: ks.ready_to_sign(), reverse=True):
            try:
                if k.can_sign(tmp_tx):
                    k.sign_transaction(tmp_tx, password)
            except UserCancelled:
                continue
        # remove sensitive info; then copy back details from temporary tx
        tmp_tx.remove_xpubs_and_bip32_paths()
        tx.combine_with_other_psbt(tmp_tx)
        tx.add_info_from_wallet(self, include_xpubs=False)
        return tx

    def try_detecting_internal_addresses_corruption(self) -> None:
        pass

    def check_address_for_corruption(self, addr: str) -> None:
        pass

    def get_unused_addresses(self) -> Sequence[str]:
        domain = self.get_receiving_addresses()
        # TODO we should index receive_requests by id
        in_use_by_request = [k for k in self.receive_requests.keys()
                             if self.get_request_status(k) != PR_EXPIRED]
        in_use_by_request = set(in_use_by_request)
        return [addr for addr in domain if not self.is_used(addr)
                and addr not in in_use_by_request]

    @check_returned_address_for_corruption
    def get_unused_address(self) -> Optional[str]:
        """Get an unused receiving address, if there is one.
        Note: there might NOT be one available!
        """
        addrs = self.get_unused_addresses()
        if addrs:
            return addrs[0]

    @check_returned_address_for_corruption
    def get_receiving_address(self) -> str:
        """Get a receiving address. Guaranteed to always return an address."""
        unused_addr = self.get_unused_address()
        if unused_addr:
            return unused_addr
        domain = self.get_receiving_addresses()
        if not domain:
            raise Exception("no receiving addresses in wallet?!")
        choice = domain[0]
        for addr in domain:
            if not self.is_used(addr):
                if addr not in self.receive_requests.keys():
                    return addr
                else:
                    choice = addr
        return choice

    def create_new_address(self, for_change: bool = False):
        raise Exception("this wallet cannot generate new addresses")

    def import_address(self, address: str) -> str:
        raise Exception("this wallet cannot import addresses")

    def import_addresses(self, addresses: List[str], *,
                         write_to_disk=True) -> Tuple[List[str], List[Tuple[str, str]]]:
        raise Exception("this wallet cannot import addresses")

    def delete_address(self, address: str) -> None:
        raise Exception("this wallet cannot delete addresses")

    def get_onchain_request_status(self, r: OnchainInvoice) -> Tuple[bool, Optional[int]]:
        address = r.get_address()
        amount = r.get_amount_sat()
        received, sent = self.get_addr_io(address)
        l = []
        for txo, x in received.items():
            h, v, is_cb = x
            txid, n = txo.split(':')
            tx_height = self.get_tx_height(txid)
            height = tx_height.height
            if height > 0 and height <= r.height:
                continue
            conf = tx_height.conf
            l.append((conf, v))
        vsum = 0
        for conf, v in reversed(sorted(l)):
            vsum += v
            if vsum >= amount:
                return True, conf
        return False, None

    def get_request_URI(self, req: OnchainInvoice) -> str:
        addr = req.get_address()
        message = self.get_label(addr)
        amount = req.amount_sat
        extra_query_params = {}
        if req.time:
            extra_query_params['time'] = str(int(req.time))
        if req.exp:
            extra_query_params['exp'] = str(int(req.exp))
        #if req.get('name') and req.get('sig'):
        #    sig = bfh(req.get('sig'))
        #    sig = bitcoin.base_encode(sig, base=58)
        #    extra_query_params['name'] = req['name']
        #    extra_query_params['sig'] = sig
        uri = create_bip21_uri(addr, amount, message, extra_query_params=extra_query_params)
        return str(uri)

    def check_expired_status(self, r: Invoice, status):
        if r.is_lightning() and r.exp == 0:
            status = PR_EXPIRED  # for BOLT-11 invoices, exp==0 means 0 seconds
        if status == PR_UNPAID and r.exp > 0 and r.time + r.exp < time.time():
            status = PR_EXPIRED
        return status

    def get_invoice_status(self, invoice: Invoice):
        if invoice.is_lightning():
            status = self.lnworker.get_invoice_status(invoice) if self.lnworker else PR_UNKNOWN
        else:
            if self.is_onchain_invoice_paid(invoice, 1):
                status =PR_PAID
            elif self.is_onchain_invoice_paid(invoice, 0):
                status = PR_UNCONFIRMED
            else:
                status = PR_UNPAID
        return self.check_expired_status(invoice, status)

    def get_request_status(self, key):
        r = self.get_request(key)
        if r is None:
            return PR_UNKNOWN
        if r.is_lightning():
            assert isinstance(r, LNInvoice)
            status = self.lnworker.get_payment_status(bfh(r.rhash)) if self.lnworker else PR_UNKNOWN
        else:
            assert isinstance(r, OnchainInvoice)
            paid, conf = self.get_onchain_request_status(r)
            if not paid:
                status = PR_UNPAID
            elif conf == 0:
                status = PR_UNCONFIRMED
            else:
                status = PR_PAID
        return self.check_expired_status(r, status)

    def get_request(self, key):
        return self.receive_requests.get(key)

    def get_formatted_request(self, key):
        x = self.receive_requests.get(key)
        if x:
            return self.export_request(x)

    def export_request(self, x: Invoice) -> Dict[str, Any]:
        key = self.get_key_for_receive_request(x)
        status = self.get_request_status(key)
        status_str = x.get_status_str(status)
        is_lightning = x.is_lightning()
        d = {
            'is_lightning': is_lightning,
            'amount_BTC': format_satoshis(x.get_amount_sat()),
            'message': x.message,
            'timestamp': x.time,
            'expiration': x.exp,
            'status': status,
            'status_str': status_str,
        }
        if is_lightning:
            assert isinstance(x, LNInvoice)
            d['rhash'] = x.rhash
            d['invoice'] = x.invoice
            d['amount_msat'] = x.get_amount_msat()
            if self.lnworker and status == PR_UNPAID:
                d['can_receive'] = self.lnworker.can_receive_invoice(x)
        else:
            assert isinstance(x, OnchainInvoice)
            paid, conf = self.get_onchain_request_status(x)
            d['amount_sat'] = x.get_amount_sat()
            d['address'] = x.get_address()
            d['URI'] = self.get_request_URI(x)
            if conf is not None:
                d['confirmations'] = conf
        # add URL if we are running a payserver
        payserver = self.config.get_netaddress('payserver_address')
        if payserver:
            root = self.config.get('payserver_root', '/r')
            use_ssl = bool(self.config.get('ssl_keyfile'))
            protocol = 'https' if use_ssl else 'http'
            base = '%s://%s:%d'%(protocol, payserver.host, payserver.port)
            d['view_url'] = base + root + '/pay?id=' + key
            if use_ssl and 'URI' in d:
                request_url = base + '/bip70/' + key + '.bip70'
                d['bip70_url'] = request_url
        return d

    def export_invoice(self, x: Invoice) -> Dict[str, Any]:
        status = self.get_invoice_status(x)
        status_str = x.get_status_str(status)
        is_lightning = x.is_lightning()
        d = {
            'is_lightning': is_lightning,
            'amount_BTC': format_satoshis(x.get_amount_sat()),
            'message': x.message,
            'timestamp': x.time,
            'expiration': x.exp,
            'status': status,
            'status_str': status_str,
        }
        if is_lightning:
            assert isinstance(x, LNInvoice)
            d['invoice'] = x.invoice
            d['amount_msat'] = x.get_amount_msat()
            if self.lnworker and status == PR_UNPAID:
                d['can_pay'] = self.lnworker.can_pay_invoice(x)
        else:
            assert isinstance(x, OnchainInvoice)
            amount_sat = x.get_amount_sat()
            assert isinstance(amount_sat, (int, str, type(None)))
            d['amount_sat'] = amount_sat
            d['outputs'] = [y.to_legacy_tuple() for y in x.outputs]
            if x.bip70:
                d['bip70'] = x.bip70
                d['requestor'] = x.requestor
        return d

    def receive_tx_callback(self, tx_hash, tx, tx_height):
        super().receive_tx_callback(tx_hash, tx, tx_height)
        self._update_request_statuses_touched_by_tx(tx_hash)

    def add_verified_tx(self, tx_hash, info):
        super().add_verified_tx(tx_hash, info)
        self._update_request_statuses_touched_by_tx(tx_hash)

    def undo_verifications(self, blockchain, above_height):
        reorged_txids = super().undo_verifications(blockchain, above_height)
        for txid in reorged_txids:
            self._update_request_statuses_touched_by_tx(txid)

    def _update_request_statuses_touched_by_tx(self, tx_hash: str) -> None:
        # FIXME in some cases if tx2 replaces unconfirmed tx1 in the mempool, we are not called.
        #       For a given receive request, if tx1 touches it but tx2 does not, then
        #       we were called when tx1 was added, but we will not get called when tx2 replaces tx1.
        tx = self.db.get_transaction(tx_hash)
        if tx is None:
            return
        for txo in tx.outputs():
            addr = txo.address
            if addr in self.receive_requests:
                status = self.get_request_status(addr)
                util.trigger_callback('request_status', self, addr, status)

    def make_payment_request(self, address, amount_sat, message, expiration):
        # TODO maybe merge with wallet.create_invoice()...
        #      note that they use incompatible "id"
        amount_sat = amount_sat or 0
        timestamp = int(time.time())
        _id = bh2u(sha256d(address + "%d"%timestamp))[0:10]
        expiration = expiration or 0
        return OnchainInvoice(
            type=PR_TYPE_ONCHAIN,
            outputs=[PartialTxOutput.from_address_and_value(address, amount_sat)],
            message=message,
            time=timestamp,
            amount_sat=amount_sat,
            exp=expiration,
            id=_id,
            bip70=None,
            requestor=None,
            height=self.get_local_height(),
        )

    def sign_payment_request(self, key, alias, alias_addr, password):  # FIXME this is broken
        req = self.receive_requests.get(key)
        assert isinstance(req, OnchainInvoice)
        alias_privkey = self.export_private_key(alias_addr, password)
        pr = paymentrequest.make_unsigned_request(req)
        paymentrequest.sign_request_with_alias(pr, alias, alias_privkey)
        req.bip70 = pr.raw.hex()
        req['name'] = pr.pki_data
        req['sig'] = bh2u(pr.signature)
        self.receive_requests[key] = req

    @classmethod
    def get_key_for_outgoing_invoice(cls, invoice: Invoice) -> str:
        """Return the key to use for this invoice in self.invoices."""
        if invoice.is_lightning():
            assert isinstance(invoice, LNInvoice)
            key = invoice.rhash
        else:
            assert isinstance(invoice, OnchainInvoice)
            key = invoice.id
        return key

    def get_key_for_receive_request(self, req: Invoice, *, sanity_checks: bool = False) -> str:
        """Return the key to use for this invoice in self.receive_requests."""
        if not req.is_lightning():
            assert isinstance(req, OnchainInvoice)
            addr = req.get_address()
            if sanity_checks:
                if not bitcoin.is_address(addr):
                    raise Exception(_('Invalid Bitcoin address.'))
                if not self.is_mine(addr):
                    raise Exception(_('Address not in wallet.'))
            key = addr
        else:
            assert isinstance(req, LNInvoice)
            key = req.rhash
        return key

    def add_payment_request(self, req: Invoice, *, write_to_disk: bool = True):
        key = self.get_key_for_receive_request(req, sanity_checks=True)
        message = req.message
        self.receive_requests[key] = req
        self.set_label(key, message)  # should be a default label
        if write_to_disk:
            self.save_db()
        return req

    def delete_request(self, key):
        """ lightning or on-chain """
        if key in self.receive_requests:
            self.remove_payment_request(key)
        elif self.lnworker:
            self.lnworker.delete_payment(key)

    def delete_invoice(self, key):
        """ lightning or on-chain """
        if key in self.invoices:
            self.invoices.pop(key)
        elif self.lnworker:
            self.lnworker.delete_payment(key)

    def remove_payment_request(self, addr) -> bool:
        found = False
        if addr in self.receive_requests:
            found = True
            self.receive_requests.pop(addr)
            self.save_db()
        return found

    def get_sorted_requests(self) -> List[Invoice]:
        """ sorted by timestamp """
        out = [self.get_request(x) for x in self.receive_requests.keys()]
        out = [x for x in out if x is not None]
        out.sort(key=lambda x: x.time)
        return out

    def get_unpaid_requests(self):
        out = [self.get_request(x) for x in self.receive_requests.keys() if self.get_request_status(x) != PR_PAID]
        out = [x for x in out if x is not None]
        out.sort(key=lambda x: x.time)
        return out

    @abstractmethod
    def get_fingerprint(self) -> str:
        """Returns a string that can be used to identify this wallet.
        Used e.g. by Labels plugin, and LN channel backups.
        Returns empty string "" for wallets that don't have an ID.
        """
        pass

    def can_import_privkey(self):
        return False

    def can_import_address(self):
        return False

    def can_delete_address(self):
        return False

    def has_password(self):
        return self.has_keystore_encryption() or self.has_storage_encryption()

    def can_have_keystore_encryption(self):
        return self.keystore and self.keystore.may_have_password()

    def get_available_storage_encryption_version(self) -> StorageEncryptionVersion:
        """Returns the type of storage encryption offered to the user.

        A wallet file (storage) is either encrypted with this version
        or is stored in plaintext.
        """
        if isinstance(self.keystore, Hardware_KeyStore):
            return StorageEncryptionVersion.XPUB_PASSWORD
        else:
            return StorageEncryptionVersion.USER_PASSWORD

    def has_keystore_encryption(self):
        """Returns whether encryption is enabled for the keystore.

        If True, e.g. signing a transaction will require a password.
        """
        if self.can_have_keystore_encryption():
            return self.db.get('use_encryption', False)
        return False

    def has_storage_encryption(self):
        """Returns whether encryption is enabled for the wallet file on disk."""
        return self.storage and self.storage.is_encrypted()

    @classmethod
    def may_have_password(cls):
        return True

    def check_password(self, password):
        if self.has_keystore_encryption():
            self.keystore.check_password(password)
        if self.has_storage_encryption():
            self.storage.check_password(password)

    def update_password(self, old_pw, new_pw, *, encrypt_storage: bool = True):
        if old_pw is None and self.has_password():
            raise InvalidPassword()
        self.check_password(old_pw)
        if self.lnworker:
            self.lnworker.maybe_enable_anchors_store_password(new_pw)
        if self.storage:
            if encrypt_storage:
                enc_version = self.get_available_storage_encryption_version()
            else:
                enc_version = StorageEncryptionVersion.PLAINTEXT
            self.storage.set_password(new_pw, enc_version)
        # make sure next storage.write() saves changes
        self.db.set_modified(True)

        # note: Encrypting storage with a hw device is currently only
        #       allowed for non-multisig wallets. Further,
        #       Hardware_KeyStore.may_have_password() == False.
        #       If these were not the case,
        #       extra care would need to be taken when encrypting keystores.
        self._update_password_for_keystore(old_pw, new_pw)
        encrypt_keystore = self.can_have_keystore_encryption()
        self.db.set_keystore_encryption(bool(new_pw) and encrypt_keystore)
        self.save_db()

    @abstractmethod
    def _update_password_for_keystore(self, old_pw: Optional[str], new_pw: Optional[str]) -> None:
        pass

    def sign_message(self, address, message, password):
        index = self.get_address_index(address)
        return self.keystore.sign_message(index, message, password)

    def decrypt_message(self, pubkey: str, message, password) -> bytes:
        addr = self.pubkeys_to_address([pubkey])
        index = self.get_address_index(addr)
        return self.keystore.decrypt_message(index, message, password)

    @abstractmethod
    def pubkeys_to_address(self, pubkeys: Sequence[str]) -> Optional[str]:
        pass

    def price_at_timestamp(self, txid, price_func):
        """Returns fiat price of bitcoin at the time tx got confirmed."""
        timestamp = self.get_tx_height(txid).timestamp
        return price_func(timestamp if timestamp else time.time())

    def average_price(self, txid, price_func, ccy) -> Decimal:
        """ Average acquisition price of the inputs of a transaction """
        input_value = 0
        total_price = 0
        txi_addresses = self.db.get_txi_addresses(txid)
        if not txi_addresses:
            return Decimal('NaN')
        for addr in txi_addresses:
            d = self.db.get_txi_addr(txid, addr)
            for ser, v in d:
                input_value += v
                total_price += self.coin_price(ser.split(':')[0], price_func, ccy, v)
        return total_price / (input_value/Decimal(COIN))

    def clear_coin_price_cache(self):
        self._coin_price_cache = {}

    def coin_price(self, txid, price_func, ccy, txin_value) -> Decimal:
        """
        Acquisition price of a coin.
        This assumes that either all inputs are mine, or no input is mine.
        """
        if txin_value is None:
            return Decimal('NaN')
        cache_key = "{}:{}:{}".format(str(txid), str(ccy), str(txin_value))
        result = self._coin_price_cache.get(cache_key, None)
        if result is not None:
            return result
        if self.db.get_txi_addresses(txid):
            result = self.average_price(txid, price_func, ccy) * txin_value/Decimal(COIN)
            self._coin_price_cache[cache_key] = result
            return result
        else:
            fiat_value = self.get_fiat_value(txid, ccy)
            if fiat_value is not None:
                return fiat_value
            else:
                p = self.price_at_timestamp(txid, price_func)
                return p * txin_value/Decimal(COIN)

    def is_billing_address(self, addr):
        # overridden for TrustedCoin wallets
        return False

    @abstractmethod
    def is_watching_only(self) -> bool:
        pass

    def get_keystore(self) -> Optional[KeyStore]:
        return self.keystore

    def get_keystores(self) -> Sequence[KeyStore]:
        return [self.keystore] if self.keystore else []

    @abstractmethod
    def save_keystore(self):
        pass

    @abstractmethod
    def has_seed(self) -> bool:
        pass

    @abstractmethod
    def get_all_known_addresses_beyond_gap_limit(self) -> Set[str]:
        pass

    def create_transaction(self, outputs, *, fee=None, feerate=None, change_addr=None, domain_addr=None, domain_coins=None,
              unsigned=False, rbf=None, password=None, locktime=None):
        if fee is not None and feerate is not None:
            raise Exception("Cannot specify both 'fee' and 'feerate' at the same time!")
        coins = self.get_spendable_coins(domain_addr)
        if domain_coins is not None:
            coins = [coin for coin in coins if (coin.prevout.to_str() in domain_coins)]
        if feerate is not None:
            fee_per_kb = 1000 * Decimal(feerate)
            fee_estimator = partial(SimpleConfig.estimate_fee_for_feerate, fee_per_kb)
        else:
            fee_estimator = fee
        tx = self.make_unsigned_transaction(
            coins=coins,
            outputs=outputs,
            fee=fee_estimator,
            change_addr=change_addr)
        if locktime is not None:
            tx.locktime = locktime
        if rbf is None:
            rbf = bool(self.config.get('use_rbf', True))
        tx.set_rbf(rbf)
        if not unsigned:
            self.sign_transaction(tx, password)
        return tx

    def get_warning_for_risk_of_burning_coins_as_fees(self, tx: 'PartialTransaction') -> Optional[str]:
        """Returns a warning message if there is risk of burning coins as fees if we sign.
        Note that if not all inputs are ismine, e.g. coinjoin, the risk is not just about fees.

        Note:
            - legacy sighash does not commit to any input amounts
            - BIP-0143 sighash only commits to the *corresponding* input amount
            - BIP-taproot sighash commits to *all* input amounts
        """
        assert isinstance(tx, PartialTransaction)
        # if we have all full previous txs, we *know* all the input amounts -> fine
        if all([txin.utxo for txin in tx.inputs()]):
            return None
        # a single segwit input -> fine
        if len(tx.inputs()) == 1 and tx.inputs()[0].is_segwit() and tx.inputs()[0].witness_utxo:
            return None
        # coinjoin or similar
        if any([not self.is_mine(txin.address) for txin in tx.inputs()]):
            return (_("Warning") + ": "
                    + _("The input amounts could not be verified as the previous transactions are missing.\n"
                        "The amount of money being spent CANNOT be verified."))
        # some inputs are legacy
        if any([not txin.is_segwit() for txin in tx.inputs()]):
            return (_("Warning") + ": "
                    + _("The fee could not be verified. Signing non-segwit inputs is risky:\n"
                        "if this transaction was maliciously modified before you sign,\n"
                        "you might end up paying a higher mining fee than displayed."))
        # all inputs are segwit
        # https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2017-August/014843.html
        return (_("Warning") + ": "
                + _("If you received this transaction from an untrusted device, "
                    "do not accept to sign it more than once,\n"
                    "otherwise you could end up paying a different fee."))

    def get_tx_fee_warning(
            self, *,
            invoice_amt: int,
            tx_size: int,
            fee: int) -> Optional[Tuple[bool, str, str]]:

        feerate = Decimal(fee) / tx_size  # sat/byte
        fee_ratio = Decimal(fee) / invoice_amt if invoice_amt else 1
        long_warning = None
        short_warning = None
        allow_send = True
        if feerate < self.relayfee() / 1000:
            long_warning = (
                    _("This transaction requires a higher fee, or it will not be propagated by your current server.") + " "
                    + _("Try to raise your transaction fee, or use a server with a lower relay fee."))
            short_warning = _("below relay fee") + "!"
            allow_send = False
        elif fee_ratio >= FEE_RATIO_HIGH_WARNING:
            long_warning = (
                    _('Warning') + ': ' + _("The fee for this transaction seems unusually high.")
                    + f' ({fee_ratio*100:.2f}% of amount)')
            short_warning = _("high fee ratio") + "!"
        elif feerate > FEERATE_WARNING_HIGH_FEE / 1000:
            long_warning = (
                    _('Warning') + ': ' + _("The fee for this transaction seems unusually high.")
                    + f' (feerate: {feerate:.2f} sat/byte)')
            short_warning = _("high fee rate") + "!"
        if long_warning is None:
            return None
        else:
            return allow_send, long_warning, short_warning


class Simple_Wallet(Abstract_Wallet):
    # wallet with a single keystore

    def is_watching_only(self):
        return self.keystore.is_watching_only()

    def _update_password_for_keystore(self, old_pw, new_pw):
        if self.keystore and self.keystore.may_have_password():
            self.keystore.update_password(old_pw, new_pw)
            self.save_keystore()

    def save_keystore(self):
        self.db.put('keystore', self.keystore.dump())

    @abstractmethod
    def get_public_key(self, address: str) -> Optional[str]:
        pass

    def get_public_keys(self, address: str) -> Sequence[str]:
        return [self.get_public_key(address)]

    def get_redeem_script(self, address: str) -> Optional[str]:
        txin_type = self.get_txin_type(address)
        if txin_type in ('p2pkh', 'p2wpkh', 'p2pk'):
            return None
        if txin_type == 'p2wpkh-p2sh':
            pubkey = self.get_public_key(address)
            return bitcoin.p2wpkh_nested_script(pubkey)
        if txin_type == 'address':
            return None
        raise UnknownTxinType(f'unexpected txin_type {txin_type}')

    def get_witness_script(self, address: str) -> Optional[str]:
        return None


class Imported_Wallet(Simple_Wallet):
    # wallet made of imported addresses

    wallet_type = 'imported'
    txin_type = 'address'

    def __init__(self, db, storage, *, config):
        Abstract_Wallet.__init__(self, db, storage, config=config)
        self.use_change = db.get('use_change', False)

    def is_watching_only(self):
        return self.keystore is None

    def can_import_privkey(self):
        return bool(self.keystore)

    def load_keystore(self):
        self.keystore = load_keystore(self.db, 'keystore') if self.db.get('keystore') else None

    def save_keystore(self):
        self.db.put('keystore', self.keystore.dump())

    def can_import_address(self):
        return self.is_watching_only()

    def can_delete_address(self):
        return True

    def has_seed(self):
        return False

    def is_deterministic(self):
        return False

    def is_change(self, address):
        return False

    def get_all_known_addresses_beyond_gap_limit(self) -> Set[str]:
        return set()

    def get_fingerprint(self):
        return ''

    def get_addresses(self):
        # note: overridden so that the history can be cleared
        return self.db.get_imported_addresses()

    def get_receiving_addresses(self, **kwargs):
        return self.get_addresses()

    def get_change_addresses(self, **kwargs):
        return self.get_addresses()

    def import_addresses(self, addresses: List[str], *,
                         write_to_disk=True) -> Tuple[List[str], List[Tuple[str, str]]]:
        good_addr = []  # type: List[str]
        bad_addr = []  # type: List[Tuple[str, str]]
        for address in addresses:
            if not bitcoin.is_address(address):
                bad_addr.append((address, _('invalid address')))
                continue
            if self.db.has_imported_address(address):
                bad_addr.append((address, _('address already in wallet')))
                continue
            good_addr.append(address)
            self.db.add_imported_address(address, {})
            self.add_address(address)
        if write_to_disk:
            self.save_db()
        return good_addr, bad_addr

    def import_address(self, address: str) -> str:
        good_addr, bad_addr = self.import_addresses([address])
        if good_addr and good_addr[0] == address:
            return address
        else:
            raise BitcoinException(str(bad_addr[0][1]))

    def delete_address(self, address: str) -> None:
        if not self.db.has_imported_address(address):
            return
        if len(self.get_addresses()) <= 1:
            raise UserFacingException("cannot delete last remaining address from wallet")
        transactions_to_remove = set()  # only referred to by this address
        transactions_new = set()  # txs that are not only referred to by address
        with self.lock:
            for addr in self.db.get_history():
                details = self.get_address_history(addr)
                if addr == address:
                    for tx_hash, height in details:
                        transactions_to_remove.add(tx_hash)
                else:
                    for tx_hash, height in details:
                        transactions_new.add(tx_hash)
            transactions_to_remove -= transactions_new
            self.db.remove_addr_history(address)
            for tx_hash in transactions_to_remove:
                self.remove_transaction(tx_hash)
        self.set_label(address, None)
        self.remove_payment_request(address)
        self.set_frozen_state_of_addresses([address], False)
        pubkey = self.get_public_key(address)
        self.db.remove_imported_address(address)
        if pubkey:
            # delete key iff no other address uses it (e.g. p2pkh and p2wpkh for same key)
            for txin_type in bitcoin.WIF_SCRIPT_TYPES.keys():
                try:
                    addr2 = bitcoin.pubkey_to_address(txin_type, pubkey)
                except NotImplementedError:
                    pass
                else:
                    if self.db.has_imported_address(addr2):
                        break
            else:
                self.keystore.delete_imported_key(pubkey)
                self.save_keystore()
        self.save_db()

    def get_change_addresses_for_new_transaction(self, *args, **kwargs) -> List[str]:
        # for an imported wallet, if all "change addresses" are already used,
        # it is probably better to send change back to the "from address", than to
        # send it to another random used address and link them together, hence
        # we force "allow_reusing_used_change_addrs=False"
        return super().get_change_addresses_for_new_transaction(
            *args,
            **{**kwargs, "allow_reusing_used_change_addrs": False},
        )

    def calc_unused_change_addresses(self) -> Sequence[str]:
        with self.lock:
            unused_addrs = [addr for addr in self.get_change_addresses()
                            if not self.is_used(addr) and not self.is_address_reserved(addr)]
            return unused_addrs

    def is_mine(self, address) -> bool:
        if not address: return False
        return self.db.has_imported_address(address)

    def get_address_index(self, address) -> Optional[str]:
        # returns None if address is not mine
        return self.get_public_key(address)

    def get_address_path_str(self, address):
        return None

    def get_public_key(self, address) -> Optional[str]:
        x = self.db.get_imported_address(address)
        return x.get('pubkey') if x else None

    def import_private_keys(self, keys: List[str], password: Optional[str], *,
                            write_to_disk=True) -> Tuple[List[str], List[Tuple[str, str]]]:
        good_addr = []  # type: List[str]
        bad_keys = []  # type: List[Tuple[str, str]]
        for key in keys:
            try:
                txin_type, pubkey = self.keystore.import_privkey(key, password)
            except Exception as e:
                bad_keys.append((key, _('invalid private key') + f': {e}'))
                continue
            if txin_type not in ('p2pkh', 'p2wpkh', 'p2wpkh-p2sh'):
                bad_keys.append((key, _('not implemented type') + f': {txin_type}'))
                continue
            addr = bitcoin.pubkey_to_address(txin_type, pubkey)
            good_addr.append(addr)
            self.db.add_imported_address(addr, {'type':txin_type, 'pubkey':pubkey})
            self.add_address(addr)
        self.save_keystore()
        if write_to_disk:
            self.save_db()
        return good_addr, bad_keys

    def import_private_key(self, key: str, password: Optional[str]) -> str:
        good_addr, bad_keys = self.import_private_keys([key], password=password)
        if good_addr:
            return good_addr[0]
        else:
            raise BitcoinException(str(bad_keys[0][1]))

    def get_txin_type(self, address):
        return self.db.get_imported_address(address).get('type', 'address')

    @profiler
    def try_detecting_internal_addresses_corruption(self):
        # we check only a random sample, for performance
        addresses = self.get_addresses()
        addresses = random.sample(addresses, min(len(addresses), 10))
        for addr_found in addresses:
            self.check_address_for_corruption(addr_found)

    def check_address_for_corruption(self, addr):
        if addr and self.is_mine(addr):
            pubkey = self.get_public_key(addr)
            if not pubkey:
                return
            txin_type = self.get_txin_type(addr)
            if txin_type == 'address':
                return
            if addr != bitcoin.pubkey_to_address(txin_type, pubkey):
                raise InternalAddressCorruption()

    def _add_input_sig_info(self, txin, address, *, only_der_suffix):
        if not self.is_mine(address):
            return
        if txin.script_type in ('unknown', 'address'):
            return
        elif txin.script_type in ('p2pkh', 'p2wpkh', 'p2wpkh-p2sh'):
            pubkey = self.get_public_key(address)
            if not pubkey:
                return
            txin.pubkeys = [bfh(pubkey)]
        else:
            raise Exception(f'Unexpected script type: {txin.script_type}. '
                            f'Imported wallets are not implemented to handle this.')

    def pubkeys_to_address(self, pubkeys):
        pubkey = pubkeys[0]
        # FIXME This is slow.
        #       Ideally we would re-derive the address from the pubkey and the txin_type,
        #       but we don't know the txin_type, and we only have an addr->txin_type map.
        #       so instead a linear search of reverse-lookups is done...
        for addr in self.db.get_imported_addresses():
            if self.db.get_imported_address(addr)['pubkey'] == pubkey:
                return addr
        return None

    def decrypt_message(self, pubkey: str, message, password) -> bytes:
        # this is significantly faster than the implementation in the superclass
        return self.keystore.decrypt_message(pubkey, message, password)


class Deterministic_Wallet(Abstract_Wallet):

    def __init__(self, db, storage, *, config):
        self._ephemeral_addr_to_addr_index = {}  # type: Dict[str, Sequence[int]]
        Abstract_Wallet.__init__(self, db, storage, config=config)
        self.gap_limit = db.get('gap_limit', 20)
        # generate addresses now. note that without libsecp this might block
        # for a few seconds!
        self.synchronize()
        # lightning_privkey2 is not deterministic (legacy wallets, bip39)
        ln_xprv = self.db.get('lightning_xprv') or self.db.get('lightning_privkey2')
        # lnworker can only be initialized once receiving addresses are available
        # therefore we instantiate lnworker in DeterministicWallet
        self.lnworker = LNWallet(self, ln_xprv) if ln_xprv else None

    def has_seed(self):
        return self.keystore.has_seed()

    def get_addresses(self):
        # note: overridden so that the history can be cleared.
        # addresses are ordered based on derivation
        out = self.get_receiving_addresses()
        out += self.get_change_addresses()
        return out

    def get_receiving_addresses(self, *, slice_start=None, slice_stop=None):
        return self.db.get_receiving_addresses(slice_start=slice_start, slice_stop=slice_stop)

    def get_change_addresses(self, *, slice_start=None, slice_stop=None):
        return self.db.get_change_addresses(slice_start=slice_start, slice_stop=slice_stop)

    @profiler
    def try_detecting_internal_addresses_corruption(self):
        addresses_all = self.get_addresses()
        # sample 1: first few
        addresses_sample1 = addresses_all[:10]
        # sample2: a few more randomly selected
        addresses_rand = addresses_all[10:]
        addresses_sample2 = random.sample(addresses_rand, min(len(addresses_rand), 10))
        for addr_found in itertools.chain(addresses_sample1, addresses_sample2):
            self.check_address_for_corruption(addr_found)

    def check_address_for_corruption(self, addr):
        if addr and self.is_mine(addr):
            if addr != self.derive_address(*self.get_address_index(addr)):
                raise InternalAddressCorruption()

    def get_seed(self, password):
        return self.keystore.get_seed(password)

    def change_gap_limit(self, value):
        '''This method is not called in the code, it is kept for console use'''
        value = int(value)
        if value >= self.min_acceptable_gap():
            self.gap_limit = value
            self.db.put('gap_limit', self.gap_limit)
            self.save_db()
            return True
        else:
            return False

    def num_unused_trailing_addresses(self, addresses):
        k = 0
        for addr in addresses[::-1]:
            if self.db.get_addr_history(addr):
                break
            k += 1
        return k

    def min_acceptable_gap(self) -> int:
        # fixme: this assumes wallet is synchronized
        n = 0
        nmax = 0
        addresses = self.get_receiving_addresses()
        k = self.num_unused_trailing_addresses(addresses)
        for addr in addresses[0:-k]:
            if self.address_is_old(addr):
                n = 0
            else:
                n += 1
                nmax = max(nmax, n)
        return nmax + 1

    @abstractmethod
    def derive_pubkeys(self, c: int, i: int) -> Sequence[str]:
        pass

    def derive_address(self, for_change: int, n: int) -> str:
        for_change = int(for_change)
        pubkeys = self.derive_pubkeys(for_change, n)
        return self.pubkeys_to_address(pubkeys)

    def export_private_key_for_path(self, path: Union[Sequence[int], str], password: Optional[str]) -> str:
        if isinstance(path, str):
            path = convert_bip32_path_to_list_of_uint32(path)
        pk, compressed = self.keystore.get_private_key(path, password)
        txin_type = self.get_txin_type()  # assumes no mixed-scripts in wallet
        return bitcoin.serialize_privkey(pk, compressed, txin_type)

    def get_public_keys_with_deriv_info(self, address: str):
        der_suffix = self.get_address_index(address)
        der_suffix = [int(x) for x in der_suffix]
        return {k.derive_pubkey(*der_suffix): (k, der_suffix)
                for k in self.get_keystores()}

    def _add_input_sig_info(self, txin, address, *, only_der_suffix):
        self._add_txinout_derivation_info(txin, address, only_der_suffix=only_der_suffix)

    def _add_txinout_derivation_info(self, txinout, address, *, only_der_suffix):
        if not self.is_mine(address):
            return
        pubkey_deriv_info = self.get_public_keys_with_deriv_info(address)
        txinout.pubkeys = sorted([pk for pk in list(pubkey_deriv_info)])
        for pubkey in pubkey_deriv_info:
            ks, der_suffix = pubkey_deriv_info[pubkey]
            fp_bytes, der_full = ks.get_fp_and_derivation_to_be_used_in_partial_tx(der_suffix,
                                                                                   only_der_suffix=only_der_suffix)
            txinout.bip32_paths[pubkey] = (fp_bytes, der_full)

    def create_new_address(self, for_change: bool = False):
        assert type(for_change) is bool
        with self.lock:
            n = self.db.num_change_addresses() if for_change else self.db.num_receiving_addresses()
            address = self.derive_address(int(for_change), n)
            self.db.add_change_address(address) if for_change else self.db.add_receiving_address(address)
            self.add_address(address)
            if for_change:
                # note: if it's actually "old", it will get filtered later
                self._not_old_change_addresses.append(address)
            return address

    def synchronize_sequence(self, for_change):
        limit = self.gap_limit_for_change if for_change else self.gap_limit
        while True:
            num_addr = self.db.num_change_addresses() if for_change else self.db.num_receiving_addresses()
            if num_addr < limit:
                self.create_new_address(for_change)
                continue
            if for_change:
                last_few_addresses = self.get_change_addresses(slice_start=-limit)
            else:
                last_few_addresses = self.get_receiving_addresses(slice_start=-limit)
            if any(map(self.address_is_old, last_few_addresses)):
                self.create_new_address(for_change)
            else:
                break

    @AddressSynchronizer.with_local_height_cached
    def synchronize(self):
        with self.lock:
            self.synchronize_sequence(False)
            self.synchronize_sequence(True)

    def get_all_known_addresses_beyond_gap_limit(self):
        # note that we don't stop at first large gap
        found = set()

        def process_addresses(addrs, gap_limit):
            rolling_num_unused = 0
            for addr in addrs:
                if self.db.get_addr_history(addr):
                    rolling_num_unused = 0
                else:
                    if rolling_num_unused >= gap_limit:
                        found.add(addr)
                    rolling_num_unused += 1

        process_addresses(self.get_receiving_addresses(), self.gap_limit)
        process_addresses(self.get_change_addresses(), self.gap_limit_for_change)
        return found

    def get_address_index(self, address) -> Optional[Sequence[int]]:
        return self.db.get_address_index(address) or self._ephemeral_addr_to_addr_index.get(address)

    def get_address_path_str(self, address):
        intpath = self.get_address_index(address)
        if intpath is None:
            return None
        return convert_bip32_intpath_to_strpath(intpath)

    def _learn_derivation_path_for_address_from_txinout(self, txinout, address):
        for ks in self.get_keystores():
            pubkey, der_suffix = ks.find_my_pubkey_in_txinout(txinout, only_der_suffix=True)
            if der_suffix is not None:
                # note: we already know the pubkey belongs to the keystore,
                #       but the script template might be different
                if len(der_suffix) != 2: continue
                try:
                    my_address = self.derive_address(*der_suffix)
                except CannotDerivePubkey:
                    my_address = None
                if my_address == address:
                    self._ephemeral_addr_to_addr_index[address] = list(der_suffix)
                    return True
        return False

    def get_master_public_keys(self):
        return [self.get_master_public_key()]

    def get_fingerprint(self):
        return self.get_master_public_key()

    def get_txin_type(self, address=None):
        return self.txin_type


class Simple_Deterministic_Wallet(Simple_Wallet, Deterministic_Wallet):

    """ Deterministic Wallet with a single pubkey per address """

    def __init__(self, db, storage, *, config):
        Deterministic_Wallet.__init__(self, db, storage, config=config)

    def get_public_key(self, address):
        sequence = self.get_address_index(address)
        pubkeys = self.derive_pubkeys(*sequence)
        return pubkeys[0]

    def load_keystore(self):
        self.keystore = load_keystore(self.db, 'keystore')
        try:
            xtype = bip32.xpub_type(self.keystore.xpub)
        except:
            xtype = 'standard'
        self.txin_type = 'p2pkh' if xtype == 'standard' else xtype

    def get_master_public_key(self):
        return self.keystore.get_master_public_key()

    def derive_pubkeys(self, c, i):
        return [self.keystore.derive_pubkey(c, i).hex()]

    def can_sign_without_user_interaction_if_have_password(self) -> bool:
        if (isinstance(self.keystore, keystore.Software_KeyStore)
                and not self.keystore.is_watching_only()):
            return True
        return False


class Standard_Wallet(Simple_Deterministic_Wallet):
    wallet_type = 'standard'

    def pubkeys_to_address(self, pubkeys):
        pubkey = pubkeys[0]
        return bitcoin.pubkey_to_address(self.txin_type, pubkey)


class Multisig_Wallet(Deterministic_Wallet):
    # generic m of n

    def __init__(self, db, storage, *, config):
        self.wallet_type = db.get('wallet_type')
        self.m, self.n = multisig_type(self.wallet_type)
        Deterministic_Wallet.__init__(self, db, storage, config=config)

    def get_public_keys(self, address):
        return [pk.hex() for pk in self.get_public_keys_with_deriv_info(address)]

    def pubkeys_to_address(self, pubkeys):
        redeem_script = self.pubkeys_to_scriptcode(pubkeys)
        return bitcoin.redeem_script_to_address(self.txin_type, redeem_script)

    def pubkeys_to_scriptcode(self, pubkeys: Sequence[str]) -> str:
        return transaction.multisig_script(sorted(pubkeys), self.m)

    def get_redeem_script(self, address):
        txin_type = self.get_txin_type(address)
        pubkeys = self.get_public_keys(address)
        scriptcode = self.pubkeys_to_scriptcode(pubkeys)
        if txin_type == 'p2sh':
            return scriptcode
        elif txin_type == 'p2wsh-p2sh':
            return bitcoin.p2wsh_nested_script(scriptcode)
        elif txin_type == 'p2wsh':
            return None
        raise UnknownTxinType(f'unexpected txin_type {txin_type}')

    def get_witness_script(self, address):
        txin_type = self.get_txin_type(address)
        pubkeys = self.get_public_keys(address)
        scriptcode = self.pubkeys_to_scriptcode(pubkeys)
        if txin_type == 'p2sh':
            return None
        elif txin_type in ('p2wsh-p2sh', 'p2wsh'):
            return scriptcode
        raise UnknownTxinType(f'unexpected txin_type {txin_type}')

    def derive_pubkeys(self, c, i):
        return [k.derive_pubkey(c, i).hex() for k in self.get_keystores()]

    def load_keystore(self):
        self.keystores = {}
        for i in range(self.n):
            name = 'x%d/'%(i+1)
            self.keystores[name] = load_keystore(self.db, name)
        self.keystore = self.keystores['x1/']
        xtype = bip32.xpub_type(self.keystore.xpub)
        self.txin_type = 'p2sh' if xtype == 'standard' else xtype

    def save_keystore(self):
        for name, k in self.keystores.items():
            self.db.put(name, k.dump())

    def get_keystore(self):
        return self.keystores.get('x1/')

    def get_keystores(self):
        return [self.keystores[i] for i in sorted(self.keystores.keys())]

    def can_have_keystore_encryption(self):
        return any([k.may_have_password() for k in self.get_keystores()])

    def _update_password_for_keystore(self, old_pw, new_pw):
        for name, keystore in self.keystores.items():
            if keystore.may_have_password():
                keystore.update_password(old_pw, new_pw)
                self.db.put(name, keystore.dump())

    def check_password(self, password):
        for name, keystore in self.keystores.items():
            if keystore.may_have_password():
                keystore.check_password(password)
        if self.has_storage_encryption():
            self.storage.check_password(password)

    def get_available_storage_encryption_version(self):
        # multisig wallets are not offered hw device encryption
        return StorageEncryptionVersion.USER_PASSWORD

    def has_seed(self):
        return self.keystore.has_seed()

    def is_watching_only(self):
        return all([k.is_watching_only() for k in self.get_keystores()])

    def get_master_public_key(self):
        return self.keystore.get_master_public_key()

    def get_master_public_keys(self):
        return [k.get_master_public_key() for k in self.get_keystores()]

    def get_fingerprint(self):
        return ''.join(sorted(self.get_master_public_keys()))


wallet_types = ['standard', 'multisig', 'imported']

def register_wallet_type(category):
    wallet_types.append(category)

wallet_constructors = {
    'standard': Standard_Wallet,
    'old': Standard_Wallet,
    'xpub': Standard_Wallet,
    'imported': Imported_Wallet
}

def register_constructor(wallet_type, constructor):
    wallet_constructors[wallet_type] = constructor

# former WalletFactory
class Wallet(object):
    """The main wallet "entry point".
    This class is actually a factory that will return a wallet of the correct
    type when passed a WalletStorage instance."""

    def __new__(self, db: 'WalletDB', storage: Optional[WalletStorage], *, config: SimpleConfig):
        wallet_type = db.get('wallet_type')
        WalletClass = Wallet.wallet_class(wallet_type)
        wallet = WalletClass(db, storage, config=config)
        return wallet

    @staticmethod
    def wallet_class(wallet_type):
        if multisig_type(wallet_type):
            return Multisig_Wallet
        if wallet_type in wallet_constructors:
            return wallet_constructors[wallet_type]
        raise WalletFileException("Unknown wallet type: " + str(wallet_type))


def create_new_wallet(*, path, config: SimpleConfig, passphrase=None, password=None,
                      encrypt_file=True, seed_type=None, gap_limit=None) -> dict:
    """Create a new wallet"""
    storage = WalletStorage(path)
    if storage.file_exists():
        raise Exception("Remove the existing wallet first!")
    db = WalletDB('', manual_upgrades=False)

    seed = Mnemonic('en').make_seed(seed_type=seed_type)
    k = keystore.from_seed(seed, passphrase)
    db.put('keystore', k.dump())
    db.put('wallet_type', 'standard')
    if k.can_have_deterministic_lightning_xprv():
        db.put('lightning_xprv', k.get_lightning_xprv(None))
    if gap_limit is not None:
        db.put('gap_limit', gap_limit)
    wallet = Wallet(db, storage, config=config)
    wallet.update_password(old_pw=None, new_pw=password, encrypt_storage=encrypt_file)
    wallet.synchronize()
    msg = "Please keep your seed in a safe place; if you lose it, you will not be able to restore your wallet."
    wallet.save_db()
    return {'seed': seed, 'wallet': wallet, 'msg': msg}


def restore_wallet_from_text(text, *, path, config: SimpleConfig,
                             passphrase=None, password=None, encrypt_file=True,
                             gap_limit=None) -> dict:
    """Restore a wallet from text. Text can be a seed phrase, a master
    public key, a master private key, a list of bitcoin addresses
    or bitcoin private keys."""
    storage = WalletStorage(path)
    if storage.file_exists():
        raise Exception("Remove the existing wallet first!")
    db = WalletDB('', manual_upgrades=False)
    text = text.strip()
    if keystore.is_address_list(text):
        wallet = Imported_Wallet(db, storage, config=config)
        addresses = text.split()
        good_inputs, bad_inputs = wallet.import_addresses(addresses, write_to_disk=False)
        # FIXME tell user about bad_inputs
        if not good_inputs:
            raise Exception("None of the given addresses can be imported")
    elif keystore.is_private_key_list(text, allow_spaces_inside_key=False):
        k = keystore.Imported_KeyStore({})
        db.put('keystore', k.dump())
        wallet = Imported_Wallet(db, storage, config=config)
        keys = keystore.get_private_keys(text, allow_spaces_inside_key=False)
        good_inputs, bad_inputs = wallet.import_private_keys(keys, None, write_to_disk=False)
        # FIXME tell user about bad_inputs
        if not good_inputs:
            raise Exception("None of the given privkeys can be imported")
    else:
        if keystore.is_master_key(text):
            k = keystore.from_master_key(text)
        elif keystore.is_seed(text):
            k = keystore.from_seed(text, passphrase)
            if k.can_have_deterministic_lightning_xprv():
                db.put('lightning_xprv', k.get_lightning_xprv(None))
        else:
            raise Exception("Seed or key not recognized")
        db.put('keystore', k.dump())
        db.put('wallet_type', 'standard')
        if gap_limit is not None:
            db.put('gap_limit', gap_limit)
        wallet = Wallet(db, storage, config=config)
    assert not storage.file_exists(), "file was created too soon! plaintext keys might have been written to disk"
    wallet.update_password(old_pw=None, new_pw=password, encrypt_storage=encrypt_file)
    wallet.synchronize()
    msg = ("This wallet was restored offline. It may contain more addresses than displayed. "
           "Start a daemon and use load_wallet to sync its history.")
    wallet.save_db()
    return {'wallet': wallet, 'msg': msg}


def check_password_for_directory(config: SimpleConfig, old_password, new_password=None) -> Tuple[bool, bool]:
    """Checks password against all wallets, returns whether they can be unified and whether they are already.
    If new_password is not None, update all wallet passwords to new_password.
    """
    dirname = os.path.dirname(config.get_wallet_path())
    failed = []
    is_unified = True
    for filename in os.listdir(dirname):
        path = os.path.join(dirname, filename)
        if not os.path.isfile(path):
            continue
        basename = os.path.basename(path)
        storage = WalletStorage(path)
        if not storage.is_encrypted():
            is_unified = False
            # it is a bit wasteful load the wallet here, but that is fine
            # because we are progressively enforcing storage encryption.
            try:
                db = WalletDB(storage.read(), manual_upgrades=False)
                wallet = Wallet(db, storage, config=config)
            except:
                _logger.exception(f'failed to load {basename}:')
                failed.append(basename)
                continue
            if wallet.has_keystore_encryption():
                try:
                    wallet.check_password(old_password)
                except:
                    failed.append(basename)
                    continue
                if new_password:
                    wallet.update_password(old_password, new_password)
            else:
                if new_password:
                    wallet.update_password(None, new_password)
            continue
        if not storage.is_encrypted_with_user_pw():
            failed.append(basename)
            continue
        try:
            storage.check_password(old_password)
        except:
            failed.append(basename)
            continue
        try:
            db = WalletDB(storage.read(), manual_upgrades=False)
            wallet = Wallet(db, storage, config=config)
        except:
            _logger.exception(f'failed to load {basename}:')
            failed.append(basename)
            continue
        try:
            wallet.check_password(old_password)
        except:
            failed.append(basename)
            continue
        if new_password:
            wallet.update_password(old_password, new_password)
    can_be_unified = failed == []
    is_unified = can_be_unified and is_unified
    return can_be_unified, is_unified


def update_password_for_directory(config: SimpleConfig, old_password, new_password) -> bool:
    " returns whether password is unified "
    if new_password is None:
        # we opened a non-encrypted wallet
        return False
    can_be_unified, is_unified = check_password_for_directory(config, old_password, None)
    if not can_be_unified:
        return False
    if is_unified and old_password == new_password:
        return True
    check_password_for_directory(config, old_password, new_password)
    return True
