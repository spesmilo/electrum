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
#   - Imported_Wallet: imported address, no keystore
#   - Standard_Wallet: one keystore, P2PKH
#   - Multisig_Wallet: several keystores, P2SH


import os
import sys
import random
import time
import json
import copy
import errno
import traceback
from functools import partial
from numbers import Number
from decimal import Decimal
from typing import TYPE_CHECKING, List, Optional, Tuple, Union, NamedTuple, Sequence

from .i18n import _
from .util import (NotEnoughFunds, UserCancelled, profiler,
                   format_satoshis, format_fee_satoshis, NoDynamicFeeEstimates,
                   WalletFileException, BitcoinException,
                   InvalidPassword, format_time, timestamp_to_datetime, Satoshis,
                   Fiat, bfh, bh2u, TxMinedInfo, quantize_feerate)
from .bitcoin import (COIN, TYPE_ADDRESS, is_address, address_to_script,
                      is_minikey, relayfee, dust_threshold)
from .crypto import sha256d
from . import keystore
from .keystore import load_keystore, Hardware_KeyStore
from .util import multisig_type
from .storage import STO_EV_PLAINTEXT, STO_EV_USER_PW, STO_EV_XPUB_PW, WalletStorage
from . import transaction, bitcoin, coinchooser, paymentrequest, ecc, bip32
from .transaction import Transaction, TxOutput, TxOutputHwInfo
from .plugin import run_hook
from .address_synchronizer import (AddressSynchronizer, TX_HEIGHT_LOCAL,
                                   TX_HEIGHT_UNCONF_PARENT, TX_HEIGHT_UNCONFIRMED)
from .paymentrequest import (PR_PAID, PR_UNPAID, PR_UNKNOWN, PR_EXPIRED,
                             InvoiceStore)
from .contacts import Contacts
from .interface import RequestTimedOut
from .ecc_fast import is_using_fast_ecc
from .mnemonic import Mnemonic
from .logging import get_logger

if TYPE_CHECKING:
    from .network import Network
    from .simple_config import SimpleConfig


_logger = get_logger(__name__)

TX_STATUS = [
    _('Unconfirmed'),
    _('Unconfirmed parent'),
    _('Not Verified'),
    _('Local'),
]


def append_utxos_to_inputs(inputs, network: 'Network', pubkey, txin_type, imax):
    if txin_type != 'p2pk':
        address = bitcoin.pubkey_to_address(txin_type, pubkey)
        scripthash = bitcoin.address_to_scripthash(address)
    else:
        script = bitcoin.public_key_to_p2pk_script(pubkey)
        scripthash = bitcoin.script_to_scripthash(script)
        address = '(pubkey)'

    u = network.run_from_another_thread(network.listunspent_for_scripthash(scripthash))
    for item in u:
        if len(inputs) >= imax:
            break
        item['address'] = address
        item['type'] = txin_type
        item['prevout_hash'] = item['tx_hash']
        item['prevout_n'] = int(item['tx_pos'])
        item['pubkeys'] = [pubkey]
        item['x_pubkeys'] = [pubkey]
        item['signatures'] = [None]
        item['num_sig'] = 1
        inputs.append(item)

def sweep_preparations(privkeys, network: 'Network', imax=100):

    def find_utxos_for_privkey(txin_type, privkey, compressed):
        pubkey = ecc.ECPrivkey(privkey).get_public_key_hex(compressed=compressed)
        append_utxos_to_inputs(inputs, network, pubkey, txin_type, imax)
        keypairs[pubkey] = privkey, compressed
    inputs = []
    keypairs = {}
    for sec in privkeys:
        txin_type, privkey, compressed = bitcoin.deserialize_privkey(sec)
        find_utxos_for_privkey(txin_type, privkey, compressed)
        # do other lookups to increase support coverage
        if is_minikey(sec):
            # minikeys don't have a compressed byte
            # we lookup both compressed and uncompressed pubkeys
            find_utxos_for_privkey(txin_type, privkey, not compressed)
        elif txin_type == 'p2pkh':
            # WIF serialization does not distinguish p2pkh and p2pk
            # we also search for pay-to-pubkey outputs
            find_utxos_for_privkey('p2pk', privkey, compressed)
    if not inputs:
        raise Exception(_('No inputs found. (Note that inputs need to be confirmed)'))
        # FIXME actually inputs need not be confirmed now, see https://github.com/kyuupichan/electrumx/issues/365
    return inputs, keypairs


def sweep(privkeys, network: 'Network', config: 'SimpleConfig', recipient, fee=None, imax=100,
          *, locktime=None, tx_version=None):
    inputs, keypairs = sweep_preparations(privkeys, network, imax)
    total = sum(i.get('value') for i in inputs)
    if fee is None:
        outputs = [TxOutput(TYPE_ADDRESS, recipient, total)]
        tx = Transaction.from_io(inputs, outputs)
        fee = config.estimate_fee(tx.estimated_size())
    if total - fee < 0:
        raise Exception(_('Not enough funds on address.') + '\nTotal: %d satoshis\nFee: %d'%(total, fee))
    if total - fee < dust_threshold(network):
        raise Exception(_('Not enough funds on address.') + '\nTotal: %d satoshis\nFee: %d\nDust Threshold: %d'%(total, fee, dust_threshold(network)))

    outputs = [TxOutput(TYPE_ADDRESS, recipient, total - fee)]
    if locktime is None:
        locktime = get_locktime_for_new_transaction(network)

    tx = Transaction.from_io(inputs, outputs, locktime=locktime, version=tx_version)
    tx.set_rbf(True)
    tx.sign(keypairs)
    return tx


def get_locktime_for_new_transaction(network: 'Network') -> int:
    # if no network or not up to date, just set locktime to zero
    if not network:
        return 0
    chain = network.blockchain()
    header = chain.header_at_tip()
    if not header:
        return 0
    STALE_DELAY = 8 * 60 * 60  # in seconds
    if header['timestamp'] + STALE_DELAY < time.time():
        return 0
    # discourage "fee sniping"
    locktime = chain.height()
    # sometimes pick locktime a bit further back, to help privacy
    # of setups that need more time (offline/multisig/coinjoin/...)
    if random.randint(0, 9) == 0:
        locktime = max(0, locktime - random.randint(0, 99))
    return locktime



class CannotBumpFee(Exception): pass


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
    amount: Optional[int]
    fee: Optional[int]
    tx_mined_status: TxMinedInfo
    mempool_depth_bytes: Optional[int]


class Abstract_Wallet(AddressSynchronizer):
    """
    Wallet classes are created to handle various address generation methods.
    Completion states (watching-only, single account, no seed, etc) are handled inside classes.
    """

    LOGGING_SHORTCUT = 'w'
    max_change_outputs = 3
    gap_limit_for_change = 6

    def __init__(self, storage: WalletStorage):
        if not storage.is_ready_to_be_used_by_wallet():
            raise Exception("storage not ready to be used by Abstract_Wallet")

        self.storage = storage
        # load addresses needs to be called before constructor for sanity checks
        self.storage.db.load_addresses(self.wallet_type)
        AddressSynchronizer.__init__(self, storage.db)

        # saved fields
        self.use_change            = storage.get('use_change', True)
        self.multiple_change       = storage.get('multiple_change', False)
        self.labels                = storage.get('labels', {})
        self.frozen_addresses      = set(storage.get('frozen_addresses', []))
        self.frozen_coins          = set(storage.get('frozen_coins', []))  # set of txid:vout strings
        self.fiat_value            = storage.get('fiat_value', {})
        self.receive_requests      = storage.get('payment_requests', {})

        self.calc_unused_change_addresses()

        # save wallet type the first time
        if self.storage.get('wallet_type') is None:
            self.storage.put('wallet_type', self.wallet_type)

        # invoices and contacts
        self.invoices = InvoiceStore(self.storage)
        self.contacts = Contacts(self.storage)

        self._coin_price_cache = {}

    def stop_threads(self):
        super().stop_threads()
        self.storage.write()

    def set_up_to_date(self, b):
        super().set_up_to_date(b)
        if b: self.storage.write()

    def clear_history(self):
        super().clear_history()
        self.storage.write()

    def load_and_cleanup(self):
        self.load_keystore()
        self.test_addresses_sanity()
        super().load_and_cleanup()

    def diagnostic_name(self):
        return self.basename()

    def __str__(self):
        return self.basename()

    def get_master_public_key(self):
        return None

    def basename(self):
        return os.path.basename(self.storage.path)

    def test_addresses_sanity(self):
        addrs = self.get_receiving_addresses()
        if len(addrs) > 0:
            addr = str(addrs[0])
            if not bitcoin.is_address(addr):
                neutered_addr = addr[:5] + '..' + addr[-2:]
                raise WalletFileException(f'The addresses in this wallet are not bitcoin addresses.\n'
                                          f'e.g. {neutered_addr} (length: {len(addr)})')

    def calc_unused_change_addresses(self):
        with self.lock:
            if hasattr(self, '_unused_change_addresses'):
                addrs = self._unused_change_addresses
            else:
                addrs = self.get_change_addresses()
            self._unused_change_addresses = [addr for addr in addrs if
                                            self.get_address_history_len(addr) == 0]
            return list(self._unused_change_addresses)

    def is_deterministic(self):
        return self.keystore.is_deterministic()

    def set_label(self, name, text = None):
        changed = False
        old_text = self.labels.get(name)
        if text:
            text = text.replace("\n", " ")
            if old_text != text:
                self.labels[name] = text
                changed = True
        else:
            if old_text is not None:
                self.labels.pop(name)
                changed = True
        if changed:
            run_hook('set_label', self, name, text)
            self.storage.put('labels', self.labels)
        return changed

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
        self.storage.put('fiat_value', self.fiat_value)
        return reset

    def get_fiat_value(self, txid, ccy):
        fiat_value = self.fiat_value.get(ccy, {}).get(txid)
        try:
            return Decimal(fiat_value)
        except:
            return

    def is_mine(self, address):
        return bool(self.get_address_index(address))

    def is_change(self, address):
        if not self.is_mine(address):
            return False
        return self.get_address_index(address)[0]

    def get_address_index(self, address):
        raise NotImplementedError()

    def get_redeem_script(self, address):
        return None

    def export_private_key(self, address, password):
        if self.is_watching_only():
            raise Exception(_("This is a watching-only wallet"))
        if not is_address(address):
            raise Exception(f"Invalid bitcoin address: {address}")
        if not self.is_mine(address):
            raise Exception(_('Address not in wallet.') + f' {address}')
        index = self.get_address_index(address)
        pk, compressed = self.keystore.get_private_key(index, password)
        txin_type = self.get_txin_type(address)
        redeem_script = self.get_redeem_script(address)
        serialized_privkey = bitcoin.serialize_privkey(pk, compressed, txin_type)
        return serialized_privkey, redeem_script

    def get_public_keys(self, address):
        return [self.get_public_key(address)]

    def is_found(self):
        return True
        #return self.history.values() != [[]] * len(self.history)

    def get_tx_info(self, tx) -> TxWalletDetails:
        is_relevant, is_mine, v, fee = self.get_wallet_delta(tx)
        exp_n = None
        can_broadcast = False
        can_bump = False
        label = ''
        tx_hash = tx.txid()
        tx_mined_status = self.get_tx_height(tx_hash)
        if tx.is_complete():
            if self.db.get_transaction(tx_hash):
                label = self.get_label(tx_hash)
                if tx_mined_status.height > 0:
                    if tx_mined_status.conf:
                        status = _("{} confirmations").format(tx_mined_status.conf)
                    else:
                        status = _('Not verified')
                elif tx_mined_status.height in (TX_HEIGHT_UNCONF_PARENT, TX_HEIGHT_UNCONFIRMED):
                    status = _('Unconfirmed')
                    if fee is None:
                        fee = self.db.get_tx_fee(tx_hash)
                    if fee and self.network and self.network.config.has_fee_mempool():
                        size = tx.estimated_size()
                        fee_per_byte = fee / size
                        exp_n = self.network.config.fee_to_depth(fee_per_byte)
                    can_bump = is_mine and not tx.is_final()
                else:
                    status = _('Local')
                    can_broadcast = self.network is not None
                    can_bump = is_mine and not tx.is_final()
            else:
                status = _("Signed")
                can_broadcast = self.network is not None
        else:
            s, r = tx.signature_count()
            status = _("Unsigned") if s == 0 else _('Partially signed') + ' (%d/%d)'%(s,r)

        if is_relevant:
            if is_mine:
                if fee is not None:
                    amount = v + fee
                else:
                    amount = v
            else:
                amount = v
        else:
            amount = None

        return TxWalletDetails(
            txid=tx_hash,
            status=status,
            label=label,
            can_broadcast=can_broadcast,
            can_bump=can_bump,
            amount=amount,
            fee=fee,
            tx_mined_status=tx_mined_status,
            mempool_depth_bytes=exp_n,
        )

    def get_spendable_coins(self, domain, config, *, nonlocal_only=False):
        confirmed_only = config.get('confirmed_only', False)
        utxos = self.get_utxos(domain,
                               excluded_addresses=self.frozen_addresses,
                               mature_only=True,
                               confirmed_only=confirmed_only,
                               nonlocal_only=nonlocal_only)
        utxos = [utxo for utxo in utxos if not self.is_frozen_coin(utxo)]
        return utxos

    def get_receiving_addresses(self, *, slice_start=None, slice_stop=None) -> Sequence:
        raise NotImplementedError()  # implemented by subclasses

    def get_change_addresses(self, *, slice_start=None, slice_stop=None) -> Sequence:
        raise NotImplementedError()  # implemented by subclasses

    def dummy_address(self):
        # first receiving address
        return self.get_receiving_addresses(slice_start=0, slice_stop=1)[0]

    def get_frozen_balance(self):
        if not self.frozen_coins:  # shortcut
            return self.get_balance(self.frozen_addresses)
        c1, u1, x1 = self.get_balance()
        c2, u2, x2 = self.get_balance(excluded_addresses=self.frozen_addresses,
                                      excluded_coins=self.frozen_coins)
        return c1-c2, u1-u2, x1-x2

    def balance_at_timestamp(self, domain, target_timestamp):
        # we assume that get_history returns items ordered by block height
        # we also assume that block timestamps are monotonic (which is false...!)
        h = self.get_history(domain)
        balance = 0
        for tx_hash, tx_mined_status, value, balance in h:
            if tx_mined_status.timestamp is None or tx_mined_status.timestamp > target_timestamp:
                return balance - value
        # return last balance
        return balance

    @profiler
    def get_full_history(self, domain=None, from_timestamp=None, to_timestamp=None,
                         fx=None, show_addresses=False, show_fees=False,
                         from_height=None, to_height=None):
        if (from_timestamp is not None or to_timestamp is not None) \
                and (from_height is not None or to_height is not None):
            raise Exception('timestamp and block height based filtering cannot be used together')
        out = []
        income = 0
        expenditures = 0
        capital_gains = Decimal(0)
        fiat_income = Decimal(0)
        fiat_expenditures = Decimal(0)
        h = self.get_history(domain)
        now = time.time()
        for tx_hash, tx_mined_status, value, balance in h:
            timestamp = tx_mined_status.timestamp
            if from_timestamp and (timestamp or now) < from_timestamp:
                continue
            if to_timestamp and (timestamp or now) >= to_timestamp:
                continue
            height = tx_mined_status.height
            if from_height is not None and height < from_height:
                continue
            if to_height is not None and height >= to_height:
                continue
            tx = self.db.get_transaction(tx_hash)
            item = {
                'txid': tx_hash,
                'height': height,
                'confirmations': tx_mined_status.conf,
                'timestamp': timestamp,
                'incoming': True if value>0 else False,
                'value': Satoshis(value),
                'balance': Satoshis(balance),
                'date': timestamp_to_datetime(timestamp),
                'label': self.get_label(tx_hash),
                'txpos_in_block': tx_mined_status.txpos,
            }
            tx_fee = None
            if show_fees:
                tx_fee = self.get_tx_fee(tx)
                item['fee'] = Satoshis(tx_fee) if tx_fee is not None else None
            if show_addresses:
                item['inputs'] = list(map(lambda x: dict((k, x[k]) for k in ('prevout_hash', 'prevout_n')), tx.inputs()))
                item['outputs'] = list(map(lambda x:{'address':x.address, 'value':Satoshis(x.value)},
                                           tx.get_outputs_for_UI()))
            # value may be None if wallet is not fully synchronized
            if value is None:
                continue
            # fixme: use in and out values
            if value < 0:
                expenditures += -value
            else:
                income += value
            # fiat computations
            if fx and fx.is_enabled() and fx.get_history_config():
                fiat_fields = self.get_tx_item_fiat(tx_hash, value, fx, tx_fee)
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
            b, v = out[0]['balance'].value, out[0]['value'].value
            start_balance = None if b is None or v is None else b - v
            end_balance = out[-1]['balance'].value
            if from_timestamp is not None and to_timestamp is not None:
                start_date = timestamp_to_datetime(from_timestamp)
                end_date = timestamp_to_datetime(to_timestamp)
            else:
                start_date = None
                end_date = None
            summary = {
                'start_date': start_date,
                'end_date': end_date,
                'from_height': from_height,
                'to_height': to_height,
                'start_balance': Satoshis(start_balance),
                'end_balance': Satoshis(end_balance),
                'incoming': Satoshis(income),
                'outgoing': Satoshis(expenditures)
            }
            if fx and fx.is_enabled() and fx.get_history_config():
                unrealized = self.unrealized_gains(domain, fx.timestamp_rate, fx.ccy)
                summary['fiat_currency'] = fx.ccy
                summary['fiat_capital_gains'] = Fiat(capital_gains, fx.ccy)
                summary['fiat_incoming'] = Fiat(fiat_income, fx.ccy)
                summary['fiat_outgoing'] = Fiat(fiat_expenditures, fx.ccy)
                summary['fiat_unrealized_gains'] = Fiat(unrealized, fx.ccy)
                summary['fiat_start_balance'] = Fiat(fx.historical_value(start_balance, start_date), fx.ccy)
                summary['fiat_end_balance'] = Fiat(fx.historical_value(end_balance, end_date), fx.ccy)
                summary['fiat_start_value'] = Fiat(fx.historical_value(COIN, start_date), fx.ccy)
                summary['fiat_end_value'] = Fiat(fx.historical_value(COIN, end_date), fx.ccy)
        else:
            summary = {}
        return {
            'transactions': out,
            'summary': summary
        }

    def default_fiat_value(self, tx_hash, fx, value_sat):
        return value_sat / Decimal(COIN) * self.price_at_timestamp(tx_hash, fx.timestamp_rate)

    def get_tx_item_fiat(self, tx_hash, value, fx, tx_fee):
        item = {}
        fiat_value = self.get_fiat_value(tx_hash, fx.ccy)
        fiat_default = fiat_value is None
        fiat_rate = self.price_at_timestamp(tx_hash, fx.timestamp_rate)
        fiat_value = fiat_value if fiat_value is not None else self.default_fiat_value(tx_hash, fx, value)
        fiat_fee = tx_fee / Decimal(COIN) * fiat_rate if tx_fee is not None else None
        item['fiat_currency'] = fx.ccy
        item['fiat_rate'] = Fiat(fiat_rate, fx.ccy)
        item['fiat_value'] = Fiat(fiat_value, fx.ccy)
        item['fiat_fee'] = Fiat(fiat_fee, fx.ccy) if fiat_fee else None
        item['fiat_default'] = fiat_default
        if value < 0:
            acquisition_price = - value / Decimal(COIN) * self.average_price(tx_hash, fx.timestamp_rate, fx.ccy)
            liquidation_price = - fiat_value
            item['acquisition_price'] = Fiat(acquisition_price, fx.ccy)
            cg = liquidation_price - acquisition_price
            item['capital_gain'] = Fiat(cg, fx.ccy)
        return item

    def get_label(self, tx_hash):
        label = self.labels.get(tx_hash, '')
        if label is '':
            label = self.get_default_label(tx_hash)
        return label

    def get_default_label(self, tx_hash):
        if not self.db.get_txi(tx_hash):
            labels = []
            for addr in self.db.get_txo(tx_hash):
                label = self.labels.get(addr)
                if label:
                    labels.append(label)
            return ', '.join(labels)
        return ''

    def get_tx_status(self, tx_hash, tx_mined_info: TxMinedInfo):
        extra = []
        height = tx_mined_info.height
        conf = tx_mined_info.conf
        timestamp = tx_mined_info.timestamp
        if conf == 0:
            tx = self.db.get_transaction(tx_hash)
            if not tx:
                return 2, 'unknown'
            is_final = tx and tx.is_final()
            if not is_final:
                extra.append('rbf')
            fee = self.get_wallet_delta(tx)[3]
            if fee is None:
                fee = self.db.get_tx_fee(tx_hash)
            if fee is not None:
                size = tx.estimated_size()
                fee_per_byte = fee / size
                extra.append(format_fee_satoshis(fee_per_byte) + ' sat/b')
            if fee is not None and height in (TX_HEIGHT_UNCONF_PARENT, TX_HEIGHT_UNCONFIRMED) \
               and self.network and self.network.config.has_fee_mempool():
                exp_n = self.network.config.fee_to_depth(fee_per_byte)
                if exp_n:
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
        for tx_hash, tx_mined_status, delta, balance in self.get_history():
            # tx should not be mined yet
            if tx_mined_status.conf > 0: continue
            # tx should be "outgoing" from wallet
            if delta >= 0:
                continue
            tx = self.db.get_transaction(tx_hash)
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
            # prefer txns already in mempool (vs local)
            if tx_mined_status.height == TX_HEIGHT_LOCAL:
                candidate = tx
                continue
            # tx must have opted-in for RBF
            if tx.is_final(): continue
            return tx
        return candidate

    def get_change_addresses_for_new_transaction(self, preferred_change_addr=None) -> List[str]:
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
                addrs = self.get_change_addresses(slice_start=-self.gap_limit_for_change)
                change_addrs = [random.choice(addrs)] if addrs else []
        for addr in change_addrs:
            assert is_address(addr), f"not valid bitcoin address: {addr}"
            # note that change addresses are not necessarily ismine
            # in which case this is a no-op
            self.check_address(addr)
        max_change = self.max_change_outputs if self.multiple_change else 1
        return change_addrs[:max_change]

    def make_unsigned_transaction(self, coins, outputs, config, fixed_fee=None,
                                  change_addr=None, is_sweep=False):
        # check outputs
        i_max = None
        for i, o in enumerate(outputs):
            if o.type == TYPE_ADDRESS:
                if not is_address(o.address):
                    raise Exception("Invalid bitcoin address: {}".format(o.address))
            if o.value == '!':
                if i_max is not None:
                    raise Exception("More than one output set to spend max")
                i_max = i

        if fixed_fee is None and config.fee_per_kb() is None:
            raise NoDynamicFeeEstimates()

        for item in coins:
            self.add_input_info(item)

        # Fee estimator
        if fixed_fee is None:
            fee_estimator = config.estimate_fee
        elif isinstance(fixed_fee, Number):
            fee_estimator = lambda size: fixed_fee
        elif callable(fixed_fee):
            fee_estimator = fixed_fee
        else:
            raise Exception('Invalid argument fixed_fee: %s' % fixed_fee)

        if i_max is None:
            # Let the coin chooser select the coins to spend
            coin_chooser = coinchooser.get_coin_chooser(config)
            # If there is an unconfirmed RBF tx, merge with it
            base_tx = self.get_unconfirmed_base_tx_for_batching()
            if config.get('batch_rbf', False) and base_tx:
                # make sure we don't try to spend change from the tx-to-be-replaced:
                coins = [c for c in coins if c['prevout_hash'] != base_tx.txid()]
                is_local = self.get_tx_height(base_tx.txid()).height == TX_HEIGHT_LOCAL
                base_tx = Transaction(base_tx.serialize())
                base_tx.deserialize(force_full_parse=True)
                base_tx.remove_signatures()
                base_tx.add_inputs_info(self)
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
            tx = coin_chooser.make_tx(coins, txi, outputs[:] + txo, change_addrs,
                                      fee_estimator, self.dust_threshold())
        else:
            # "spend max" branch
            # note: This *will* spend inputs with negative effective value (if there are any).
            #       Given as the user is spending "max", and so might be abandoning the wallet,
            #       try to include all UTXOs, otherwise leftover might remain in the UTXO set
            #       forever. see #5433
            # note: Actually it might be the case that not all UTXOs from the wallet are
            #       being spent if the user manually selected UTXOs.
            sendable = sum(map(lambda x:x['value'], coins))
            outputs[i_max] = outputs[i_max]._replace(value=0)
            tx = Transaction.from_io(coins, outputs[:])
            fee = fee_estimator(tx.estimated_size())
            amount = sendable - tx.output_value() - fee
            if amount < 0:
                raise NotEnoughFunds()
            outputs[i_max] = outputs[i_max]._replace(value=amount)
            tx = Transaction.from_io(coins, outputs[:])

        # Timelock tx to current height.
        tx.locktime = get_locktime_for_new_transaction(self.network)
        run_hook('make_unsigned_transaction', self, tx)
        return tx

    def mktx(self, outputs, password, config, fee=None, change_addr=None,
             domain=None, rbf=False, nonlocal_only=False, *, tx_version=None):
        coins = self.get_spendable_coins(domain, config, nonlocal_only=nonlocal_only)
        tx = self.make_unsigned_transaction(coins, outputs, config, fee, change_addr)
        tx.set_rbf(rbf)
        if tx_version is not None:
            tx.version = tx_version
        self.sign_transaction(tx, password)
        return tx

    def is_frozen_address(self, addr: str) -> bool:
        return addr in self.frozen_addresses

    def is_frozen_coin(self, utxo) -> bool:
        # utxo is either a txid:vout str, or a dict
        utxo = self._utxo_str_from_utxo(utxo)
        return utxo in self.frozen_coins

    def set_frozen_state_of_addresses(self, addrs, freeze: bool):
        """Set frozen state of the addresses to FREEZE, True or False"""
        if all(self.is_mine(addr) for addr in addrs):
            # FIXME take lock?
            if freeze:
                self.frozen_addresses |= set(addrs)
            else:
                self.frozen_addresses -= set(addrs)
            self.storage.put('frozen_addresses', list(self.frozen_addresses))
            return True
        return False

    def set_frozen_state_of_coins(self, utxos, freeze: bool):
        """Set frozen state of the utxos to FREEZE, True or False"""
        utxos = {self._utxo_str_from_utxo(utxo) for utxo in utxos}
        # FIXME take lock?
        if freeze:
            self.frozen_coins |= set(utxos)
        else:
            self.frozen_coins -= set(utxos)
        self.storage.put('frozen_coins', list(self.frozen_coins))

    @staticmethod
    def _utxo_str_from_utxo(utxo: Union[dict, str]) -> str:
        """Return a txid:vout str"""
        if isinstance(utxo, dict):
            return "{}:{}".format(utxo['prevout_hash'], utxo['prevout_n'])
        assert isinstance(utxo, str), f"utxo should be a str, not {type(utxo)}"
        # just assume it is already of the correct format
        return utxo

    def wait_until_synchronized(self, callback=None):
        def wait_for_wallet():
            self.set_up_to_date(False)
            while not self.is_up_to_date():
                if callback:
                    msg = "{}\n{} {}".format(
                        _("Please wait..."),
                        _("Addresses generated:"),
                        len(self.get_addresses()))
                    callback(msg)
                time.sleep(0.1)
        def wait_for_network():
            while not self.network.is_connected():
                if callback:
                    msg = "{} \n".format(_("Connecting..."))
                    callback(msg)
                time.sleep(0.1)
        # wait until we are connected, because the user
        # might have selected another server
        if self.network:
            self.logger.info("waiting for network...")
            wait_for_network()
            self.logger.info("waiting while wallet is syncing...")
            wait_for_wallet()
        else:
            self.synchronize()

    def can_export(self):
        return not self.is_watching_only() and hasattr(self.keystore, 'get_private_key')

    def address_is_old(self, address, age_limit=2):
        age = -1
        h = self.db.get_addr_history(address)
        for tx_hash, tx_height in h:
            if tx_height <= 0:
                tx_age = 0
            else:
                tx_age = self.get_local_height() - tx_height + 1
            if tx_age > age:
                age = tx_age
        return age > age_limit

    def bump_fee(self, *, tx, new_fee_rate, config) -> Transaction:
        """Increase the miner fee of 'tx'.
        'new_fee_rate' is the target min rate in sat/vbyte
        """
        if tx.is_final():
            raise CannotBumpFee(_('Cannot bump fee') + ': ' + _('transaction is final'))
        new_fee_rate = quantize_feerate(new_fee_rate)  # strip excess precision
        old_tx_size = tx.estimated_size()
        old_fee = self.get_tx_fee(tx)
        if old_fee is None:
            raise CannotBumpFee(_('Cannot bump fee') + ': ' + _('current fee unknown'))
        old_fee_rate = old_fee / old_tx_size  # sat/vbyte
        if new_fee_rate <= old_fee_rate:
            raise CannotBumpFee(_('Cannot bump fee') + ': ' + _("The new fee rate needs to be higher than the old fee rate."))

        try:
            # method 1: keep all inputs, keep all not is_mine outputs,
            #           allow adding new inputs
            tx_new = self._bump_fee_through_coinchooser(
                tx=tx, new_fee_rate=new_fee_rate, config=config)
            method_used = 1
        except CannotBumpFee:
            # method 2: keep all inputs, no new inputs are added,
            #           allow decreasing and removing outputs (change is decreased first)
            # This is less "safe" as it might end up decreasing e.g. a payment to a merchant;
            # but e.g. if the user has sent "Max" previously, this is the only way to RBF.
            tx_new = self._bump_fee_through_decreasing_outputs(
                tx=tx, new_fee_rate=new_fee_rate)
            method_used = 2

        target_min_fee = new_fee_rate * tx_new.estimated_size()
        actual_fee = tx_new.get_fee()
        if actual_fee + 1 < target_min_fee:
            raise Exception(f"bump_fee fee target was not met (method: {method_used}). "
                            f"got {actual_fee}, expected >={target_min_fee}. "
                            f"target rate was {new_fee_rate}")

        tx_new.locktime = get_locktime_for_new_transaction(self.network)
        return tx_new

    def _bump_fee_through_coinchooser(self, *, tx, new_fee_rate, config):
        tx = Transaction(tx.serialize())
        tx.deserialize(force_full_parse=True)  # need to parse inputs
        tx.remove_signatures()
        tx.add_inputs_info(self)
        old_inputs = tx.inputs()[:]
        old_outputs = tx.outputs()[:]
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
                raise CannotBumpFee(_('Cannot bump fee') + ': all outputs are non-change is_mine')
            old_not_is_mine = list(filter(lambda o: not self.is_mine(o.address), old_outputs))
            if old_not_is_mine:
                fixed_outputs = old_not_is_mine
            else:
                fixed_outputs = old_outputs

        coins = self.get_spendable_coins(None, config)
        for item in coins:
            self.add_input_info(item)
        def fee_estimator(size):
            return config.estimate_fee_for_feerate(fee_per_kb=new_fee_rate*1000, size=size)
        coin_chooser = coinchooser.get_coin_chooser(config)
        try:
            return coin_chooser.make_tx(coins, old_inputs, fixed_outputs, change_addrs,
                                        fee_estimator, self.dust_threshold())
        except NotEnoughFunds as e:
            raise CannotBumpFee(e)

    def _bump_fee_through_decreasing_outputs(self, *, tx, new_fee_rate):
        tx = Transaction(tx.serialize())
        tx.deserialize(force_full_parse=True)  # need to parse inputs
        tx.remove_signatures()
        tx.add_inputs_info(self)
        inputs = tx.inputs()
        outputs = tx.outputs()

        # use own outputs
        s = list(filter(lambda o: self.is_mine(o.address), outputs))
        # ... unless there is none
        if not s:
            s = outputs
            x_fee = run_hook('get_tx_extra_fee', self, tx)
            if x_fee:
                x_fee_address, x_fee_amount = x_fee
                s = filter(lambda o: o.address != x_fee_address, s)
        if not s:
            raise CannotBumpFee(_('Cannot bump fee') + ': no outputs at all??')

        # prioritize low value outputs, to get rid of dust
        s = sorted(s, key=lambda o: o.value)
        for o in s:
            target_fee = int(round(tx.estimated_size() * new_fee_rate))
            delta = target_fee - tx.get_fee()
            i = outputs.index(o)
            if o.value - delta >= self.dust_threshold():
                new_output_value = o.value - delta
                assert isinstance(new_output_value, int)
                outputs[i] = o._replace(value=new_output_value)
                delta = 0
                break
            else:
                del outputs[i]
                delta -= o.value
                # note: delta might be negative now, in which case
                # the value of the next output will be increased
        if delta > 0:
            raise CannotBumpFee(_('Cannot bump fee') + ': ' + _('could not find suitable outputs'))

        return Transaction.from_io(inputs, outputs)

    def cpfp(self, tx, fee):
        txid = tx.txid()
        for i, o in enumerate(tx.outputs()):
            address, value = o.address, o.value
            if o.type == TYPE_ADDRESS and self.is_mine(address):
                break
        else:
            return
        coins = self.get_addr_utxo(address)
        item = coins.get(txid+':%d'%i)
        if not item:
            return
        self.add_input_info(item)
        inputs = [item]
        out_address = self.get_unused_address() or address
        outputs = [TxOutput(TYPE_ADDRESS, out_address, value - fee)]
        locktime = get_locktime_for_new_transaction(self.network)
        return Transaction.from_io(inputs, outputs, locktime=locktime)

    def add_input_sig_info(self, txin, address):
        raise NotImplementedError()  # implemented by subclasses

    def add_input_info(self, txin):
        address = self.get_txin_address(txin)
        if self.is_mine(address):
            txin['address'] = address
            txin['type'] = self.get_txin_type(address)
            # segwit needs value to sign
            if txin.get('value') is None:
                received, spent = self.get_addr_io(address)
                item = received.get(txin['prevout_hash']+':%d'%txin['prevout_n'])
                if item:
                    txin['value'] = item[1]
            self.add_input_sig_info(txin, address)

    def can_sign(self, tx):
        if tx.is_complete():
            return False
        # add info to inputs if we can; otherwise we might return a false negative:
        tx.add_inputs_info(self)
        for k in self.get_keystores():
            if k.can_sign(tx):
                return True
        return False

    def get_input_tx(self, tx_hash, ignore_timeout=False):
        # First look up an input transaction in the wallet where it
        # will likely be.  If co-signing a transaction it may not have
        # all the input txs, in which case we ask the network.
        tx = self.db.get_transaction(tx_hash)
        if not tx and self.network:
            try:
                raw_tx = self.network.run_from_another_thread(
                    self.network.get_transaction(tx_hash, timeout=10))
            except RequestTimedOut as e:
                self.logger.info(f'getting input txn from network timed out for {tx_hash}')
                if not ignore_timeout:
                    raise e
            else:
                tx = Transaction(raw_tx)
        return tx

    def add_hw_info(self, tx):
        # add previous tx for hw wallets
        for txin in tx.inputs():
            tx_hash = txin['prevout_hash']
            # segwit inputs might not be needed for some hw wallets
            ignore_timeout = Transaction.is_segwit_input(txin)
            txin['prev_tx'] = self.get_input_tx(tx_hash, ignore_timeout)
        # add output info for hw wallets
        info = {}
        xpubs = self.get_master_public_keys()
        for txout in tx.outputs():
            _type, addr, amount = txout
            if self.is_mine(addr):
                index = self.get_address_index(addr)
                pubkeys = self.get_public_keys(addr)
                # sort xpubs using the order of pubkeys
                sorted_pubkeys, sorted_xpubs = zip(*sorted(zip(pubkeys, xpubs)))
                num_sig = self.m if isinstance(self, Multisig_Wallet) else None
                info[addr] = TxOutputHwInfo(index, sorted_xpubs, num_sig, self.txin_type)
        tx.output_info = info

    def sign_transaction(self, tx, password):
        if self.is_watching_only():
            return
        tx.add_inputs_info(self)
        # hardware wallets require extra info
        if any([(isinstance(k, Hardware_KeyStore) and k.can_sign(tx)) for k in self.get_keystores()]):
            self.add_hw_info(tx)
        # sign. start with ready keystores.
        for k in sorted(self.get_keystores(), key=lambda ks: ks.ready_to_sign(), reverse=True):
            try:
                if k.can_sign(tx):
                    k.sign_transaction(tx, password)
            except UserCancelled:
                continue
        return tx

    def try_detecting_internal_addresses_corruption(self):
        pass

    def check_address(self, addr):
        pass

    def check_returned_address(func):
        def wrapper(self, *args, **kwargs):
            addr = func(self, *args, **kwargs)
            self.check_address(addr)
            return addr
        return wrapper

    def get_unused_addresses(self):
        # fixme: use slots from expired requests
        domain = self.get_receiving_addresses()
        return [addr for addr in domain if not self.db.get_addr_history(addr)
                and addr not in self.receive_requests.keys()]

    @check_returned_address
    def get_unused_address(self):
        addrs = self.get_unused_addresses()
        if addrs:
            return addrs[0]

    @check_returned_address
    def get_receiving_address(self):
        # always return an address
        domain = self.get_receiving_addresses()
        if not domain:
            return
        choice = domain[0]
        for addr in domain:
            if not self.db.get_addr_history(addr):
                if addr not in self.receive_requests.keys():
                    return addr
                else:
                    choice = addr
        return choice

    def get_payment_status(self, address, amount):
        local_height = self.get_local_height()
        received, sent = self.get_addr_io(address)
        l = []
        for txo, x in received.items():
            h, v, is_cb = x
            txid, n = txo.split(':')
            info = self.db.get_verified_tx(txid)
            if info:
                conf = local_height - info.height
            else:
                conf = 0
            l.append((conf, v))
        vsum = 0
        for conf, v in reversed(sorted(l)):
            vsum += v
            if vsum >= amount:
                return True, conf
        return False, None

    def get_payment_request(self, addr, config):
        r = self.receive_requests.get(addr)
        if not r:
            return
        out = copy.copy(r)
        out['URI'] = 'bitcoin:' + addr + '?amount=' + format_satoshis(out.get('amount'))
        status, conf = self.get_request_status(addr)
        out['status'] = status
        if conf is not None:
            out['confirmations'] = conf
        # check if bip70 file exists
        rdir = config.get('requests_dir')
        if rdir:
            key = out.get('id', addr)
            path = os.path.join(rdir, 'req', key[0], key[1], key)
            if os.path.exists(path):
                baseurl = 'file://' + rdir
                rewrite = config.get('url_rewrite')
                if rewrite:
                    try:
                        baseurl = baseurl.replace(*rewrite)
                    except BaseException as e:
                        self.logger.info(f'Invalid config setting for "url_rewrite". err: {e}')
                out['request_url'] = os.path.join(baseurl, 'req', key[0], key[1], key, key)
                out['URI'] += '&r=' + out['request_url']
                out['index_url'] = os.path.join(baseurl, 'index.html') + '?id=' + key
                websocket_server_announce = config.get('websocket_server_announce')
                if websocket_server_announce:
                    out['websocket_server'] = websocket_server_announce
                else:
                    out['websocket_server'] = config.get('websocket_server', 'localhost')
                websocket_port_announce = config.get('websocket_port_announce')
                if websocket_port_announce:
                    out['websocket_port'] = websocket_port_announce
                else:
                    out['websocket_port'] = config.get('websocket_port', 9999)
        return out

    def get_request_status(self, key):
        r = self.receive_requests.get(key)
        if r is None:
            return PR_UNKNOWN
        address = r['address']
        amount = r.get('amount')
        timestamp = r.get('time', 0)
        if timestamp and type(timestamp) != int:
            timestamp = 0
        expiration = r.get('exp')
        if expiration and type(expiration) != int:
            expiration = 0
        conf = None
        if amount:
            if self.is_up_to_date():
                paid, conf = self.get_payment_status(address, amount)
                status = PR_PAID if paid else PR_UNPAID
                if status == PR_UNPAID and expiration is not None and time.time() > timestamp + expiration:
                    status = PR_EXPIRED
            else:
                status = PR_UNKNOWN
        else:
            status = PR_UNKNOWN
        return status, conf

    def make_payment_request(self, addr, amount, message, expiration):
        timestamp = int(time.time())
        _id = bh2u(sha256d(addr + "%d"%timestamp))[0:10]
        r = {'time':timestamp, 'amount':amount, 'exp':expiration, 'address':addr, 'memo':message, 'id':_id}
        return r

    def sign_payment_request(self, key, alias, alias_addr, password):
        req = self.receive_requests.get(key)
        alias_privkey = self.export_private_key(alias_addr, password)[0]
        pr = paymentrequest.make_unsigned_request(req)
        paymentrequest.sign_request_with_alias(pr, alias, alias_privkey)
        req['name'] = pr.pki_data
        req['sig'] = bh2u(pr.signature)
        self.receive_requests[key] = req
        self.storage.put('payment_requests', self.receive_requests)

    def add_payment_request(self, req, config):
        addr = req['address']
        if not bitcoin.is_address(addr):
            raise Exception(_('Invalid Bitcoin address.'))
        if not self.is_mine(addr):
            raise Exception(_('Address not in wallet.'))

        amount = req.get('amount')
        message = req.get('memo')
        self.receive_requests[addr] = req
        self.storage.put('payment_requests', self.receive_requests)
        self.set_label(addr, message) # should be a default label

        rdir = config.get('requests_dir')
        if rdir and amount is not None:
            key = req.get('id', addr)
            pr = paymentrequest.make_request(config, req)
            path = os.path.join(rdir, 'req', key[0], key[1], key)
            if not os.path.exists(path):
                try:
                    os.makedirs(path)
                except OSError as exc:
                    if exc.errno != errno.EEXIST:
                        raise
            with open(os.path.join(path, key), 'wb') as f:
                f.write(pr.SerializeToString())
            # reload
            req = self.get_payment_request(addr, config)
            with open(os.path.join(path, key + '.json'), 'w', encoding='utf-8') as f:
                f.write(json.dumps(req))
        return req

    def remove_payment_request(self, addr, config):
        if addr not in self.receive_requests:
            return False
        r = self.receive_requests.pop(addr)
        rdir = config.get('requests_dir')
        if rdir:
            key = r.get('id', addr)
            for s in ['.json', '']:
                n = os.path.join(rdir, 'req', key[0], key[1], key, key + s)
                if os.path.exists(n):
                    os.unlink(n)
        self.storage.put('payment_requests', self.receive_requests)
        return True

    def get_sorted_requests(self, config):
        keys = map(lambda x: (self.get_address_index(x), x), self.receive_requests.keys())
        sorted_keys = sorted(filter(lambda x: x[0] is not None, keys))
        return [self.get_payment_request(x[1], config) for x in sorted_keys]

    def get_fingerprint(self):
        raise NotImplementedError()

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

    def get_available_storage_encryption_version(self):
        """Returns the type of storage encryption offered to the user.

        A wallet file (storage) is either encrypted with this version
        or is stored in plaintext.
        """
        if isinstance(self.keystore, Hardware_KeyStore):
            return STO_EV_XPUB_PW
        else:
            return STO_EV_USER_PW

    def has_keystore_encryption(self):
        """Returns whether encryption is enabled for the keystore.

        If True, e.g. signing a transaction will require a password.
        """
        if self.can_have_keystore_encryption():
            return self.storage.get('use_encryption', False)
        return False

    def has_storage_encryption(self):
        """Returns whether encryption is enabled for the wallet file on disk."""
        return self.storage.is_encrypted()

    @classmethod
    def may_have_password(cls):
        return True

    def check_password(self, password):
        if self.has_keystore_encryption():
            self.keystore.check_password(password)
        self.storage.check_password(password)

    def update_password(self, old_pw, new_pw, encrypt_storage=False):
        if old_pw is None and self.has_password():
            raise InvalidPassword()
        self.check_password(old_pw)

        if encrypt_storage:
            enc_version = self.get_available_storage_encryption_version()
        else:
            enc_version = STO_EV_PLAINTEXT
        self.storage.set_password(new_pw, enc_version)

        # note: Encrypting storage with a hw device is currently only
        #       allowed for non-multisig wallets. Further,
        #       Hardware_KeyStore.may_have_password() == False.
        #       If these were not the case,
        #       extra care would need to be taken when encrypting keystores.
        self._update_password_for_keystore(old_pw, new_pw)
        encrypt_keystore = self.can_have_keystore_encryption()
        self.storage.set_keystore_encryption(bool(new_pw) and encrypt_keystore)
        self.storage.write()

    def sign_message(self, address, message, password):
        index = self.get_address_index(address)
        return self.keystore.sign_message(index, message, password)

    def decrypt_message(self, pubkey, message, password) -> bytes:
        addr = self.pubkeys_to_address(pubkey)
        index = self.get_address_index(addr)
        return self.keystore.decrypt_message(index, message, password)

    def txin_value(self, txin):
        txid = txin['prevout_hash']
        prev_n = txin['prevout_n']
        for addr in self.db.get_txo(txid):
            d = self.db.get_txo_addr(txid, addr)
            for n, v, cb in d:
                if n == prev_n:
                    return v
        # may occur if wallet is not synchronized
        return None

    def price_at_timestamp(self, txid, price_func):
        """Returns fiat price of bitcoin at the time tx got confirmed."""
        timestamp = self.get_tx_height(txid).timestamp
        return price_func(timestamp if timestamp else time.time())

    def unrealized_gains(self, domain, price_func, ccy):
        coins = self.get_utxos(domain)
        now = time.time()
        p = price_func(now)
        ap = sum(self.coin_price(coin['prevout_hash'], price_func, ccy, self.txin_value(coin)) for coin in coins)
        lp = sum([coin['value'] for coin in coins]) * p / Decimal(COIN)
        return lp - ap

    def average_price(self, txid, price_func, ccy):
        """ Average acquisition price of the inputs of a transaction """
        input_value = 0
        total_price = 0
        for addr in self.db.get_txi(txid):
            d = self.db.get_txi_addr(txid, addr)
            for ser, v in d:
                input_value += v
                total_price += self.coin_price(ser.split(':')[0], price_func, ccy, v)
        return total_price / (input_value/Decimal(COIN))

    def clear_coin_price_cache(self):
        self._coin_price_cache = {}

    def coin_price(self, txid, price_func, ccy, txin_value):
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
        if self.db.get_txi(txid):
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
        # overloaded for TrustedCoin wallets
        return False

    def is_watching_only(self) -> bool:
        raise NotImplementedError()


class Simple_Wallet(Abstract_Wallet):
    # wallet with a single keystore

    def get_keystore(self):
        return self.keystore

    def get_keystores(self):
        return [self.keystore]

    def is_watching_only(self):
        return self.keystore.is_watching_only()

    def _update_password_for_keystore(self, old_pw, new_pw):
        if self.keystore and self.keystore.may_have_password():
            self.keystore.update_password(old_pw, new_pw)
            self.save_keystore()

    def save_keystore(self):
        self.storage.put('keystore', self.keystore.dump())


class Imported_Wallet(Simple_Wallet):
    # wallet made of imported addresses

    wallet_type = 'imported'
    txin_type = 'address'

    def __init__(self, storage):
        Abstract_Wallet.__init__(self, storage)

    def is_watching_only(self):
        return self.keystore is None

    def get_keystores(self):
        return [self.keystore] if self.keystore else []

    def can_import_privkey(self):
        return bool(self.keystore)

    def load_keystore(self):
        self.keystore = load_keystore(self.storage, 'keystore') if self.storage.get('keystore') else None
        # fixme: a reference to addresses is needed
        if self.keystore:
            self.keystore.addresses = self.db.imported_addresses

    def save_keystore(self):
        self.storage.put('keystore', self.keystore.dump())

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

    def get_master_public_keys(self):
        return []

    def is_beyond_limit(self, address):
        return False

    def get_fingerprint(self):
        return ''

    def get_addresses(self):
        # note: overridden so that the history can be cleared
        return self.db.get_imported_addresses()

    def get_receiving_addresses(self, **kwargs):
        return self.get_addresses()

    def get_change_addresses(self, **kwargs):
        return []

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
            self.storage.write()
        return good_addr, bad_addr

    def import_address(self, address: str) -> str:
        good_addr, bad_addr = self.import_addresses([address])
        if good_addr and good_addr[0] == address:
            return address
        else:
            raise BitcoinException(str(bad_addr[0][1]))

    def delete_address(self, address):
        if not self.db.has_imported_address(address):
            return
        transactions_to_remove = set()  # only referred to by this address
        transactions_new = set()  # txs that are not only referred to by address
        with self.lock:
            for addr in self.db.get_history():
                details = self.db.get_addr_history(addr)
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
                self.db.remove_tx_fee(tx_hash)
                self.db.remove_verified_tx(tx_hash)
                self.unverified_tx.pop(tx_hash, None)
                self.db.remove_transaction(tx_hash)
        self.set_label(address, None)
        self.remove_payment_request(address, {})
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
        self.storage.write()

    def is_mine(self, address):
        return self.db.has_imported_address(address)

    def get_address_index(self, address):
        # returns None if address is not mine
        return self.get_public_key(address)

    def get_public_key(self, address):
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
            self.db.add_imported_address(addr, {'type':txin_type, 'pubkey':pubkey, 'redeem_script':None})
            self.add_address(addr)
        self.save_keystore()
        if write_to_disk:
            self.storage.write()
        return good_addr, bad_keys

    def import_private_key(self, key: str, password: Optional[str]) -> str:
        good_addr, bad_keys = self.import_private_keys([key], password=password)
        if good_addr:
            return good_addr[0]
        else:
            raise BitcoinException(str(bad_keys[0][1]))

    def get_redeem_script(self, address):
        d = self.db.get_imported_address(address)
        redeem_script = d['redeem_script']
        return redeem_script

    def get_txin_type(self, address):
        return self.db.get_imported_address(address).get('type', 'address')

    def add_input_sig_info(self, txin, address):
        if self.is_watching_only():
            x_pubkey = 'fd' + address_to_script(address)
            txin['x_pubkeys'] = [x_pubkey]
            txin['signatures'] = [None]
            return
        if txin['type'] in ['p2pkh', 'p2wpkh', 'p2wpkh-p2sh']:
            pubkey = self.db.get_imported_address(address)['pubkey']
            txin['num_sig'] = 1
            txin['x_pubkeys'] = [pubkey]
            txin['signatures'] = [None]
        else:
            raise NotImplementedError('imported wallets for p2sh are not implemented')

    def pubkeys_to_address(self, pubkey):
        for addr in self.db.get_imported_addresses():
            if self.db.get_imported_address(addr)['pubkey'] == pubkey:
                return addr

class Deterministic_Wallet(Abstract_Wallet):

    def __init__(self, storage):
        Abstract_Wallet.__init__(self, storage)
        self.gap_limit = storage.get('gap_limit', 20)
        # generate addresses now. note that without libsecp this might block
        # for a few seconds!
        self.synchronize()

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
        if not is_using_fast_ecc():
            self.logger.info("internal address corruption test skipped due to missing libsecp256k1")
            return
        addresses_all = self.get_addresses()
        # sample 1: first few
        addresses_sample1 = addresses_all[:10]
        # sample2: a few more randomly selected
        addresses_rand = addresses_all[10:]
        addresses_sample2 = random.sample(addresses_rand, min(len(addresses_rand), 10))
        for addr_found in addresses_sample1 + addresses_sample2:
            self.check_address(addr_found)

    def check_address(self, addr):
        if addr and self.is_mine(addr):
            if addr != self.derive_address(*self.get_address_index(addr)):
                raise InternalAddressCorruption()

    def get_seed(self, password):
        return self.keystore.get_seed(password)

    def add_seed(self, seed, pw):
        self.keystore.add_seed(seed, pw)

    def change_gap_limit(self, value):
        '''This method is not called in the code, it is kept for console use'''
        if value >= self.min_acceptable_gap():
            self.gap_limit = value
            self.storage.put('gap_limit', self.gap_limit)
            self.storage.write()
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

    def min_acceptable_gap(self):
        # fixme: this assumes wallet is synchronized
        n = 0
        nmax = 0
        addresses = self.get_receiving_addresses()
        k = self.num_unused_trailing_addresses(addresses)
        for addr in addresses[0:-k]:
            if self.db.get_addr_history(addr):
                n = 0
            else:
                n += 1
                nmax = max(nmax, n)
        return nmax + 1

    def derive_address(self, for_change, n):
        x = self.derive_pubkeys(for_change, n)
        return self.pubkeys_to_address(x)

    def create_new_address(self, for_change=False):
        assert type(for_change) is bool
        with self.lock:
            n = self.db.num_change_addresses() if for_change else self.db.num_receiving_addresses()
            address = self.derive_address(for_change, n)
            self.db.add_change_address(address) if for_change else self.db.add_receiving_address(address)
            self.add_address(address)
            if for_change:
                # note: if it's actually used, it will get filtered later
                self._unused_change_addresses.append(address)
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

    def synchronize(self):
        with self.lock:
            self.synchronize_sequence(False)
            self.synchronize_sequence(True)

    def is_beyond_limit(self, address):
        is_change, i = self.get_address_index(address)
        limit = self.gap_limit_for_change if is_change else self.gap_limit
        if i < limit:
            return False
        slice_start = max(0, i - limit)
        slice_stop = max(0, i)
        if is_change:
            prev_addresses = self.get_change_addresses(slice_start=slice_start, slice_stop=slice_stop)
        else:
            prev_addresses = self.get_receiving_addresses(slice_start=slice_start, slice_stop=slice_stop)
        for addr in prev_addresses:
            if self.db.get_addr_history(addr):
                return False
        return True

    def get_address_index(self, address):
        return self.db.get_address_index(address)

    def get_master_public_keys(self):
        return [self.get_master_public_key()]

    def get_fingerprint(self):
        return self.get_master_public_key()

    def get_txin_type(self, address):
        return self.txin_type


class Simple_Deterministic_Wallet(Simple_Wallet, Deterministic_Wallet):

    """ Deterministic Wallet with a single pubkey per address """

    def __init__(self, storage):
        Deterministic_Wallet.__init__(self, storage)

    def get_public_key(self, address):
        sequence = self.get_address_index(address)
        pubkey = self.get_pubkey(*sequence)
        return pubkey

    def load_keystore(self):
        self.keystore = load_keystore(self.storage, 'keystore')
        try:
            xtype = bip32.xpub_type(self.keystore.xpub)
        except:
            xtype = 'standard'
        self.txin_type = 'p2pkh' if xtype == 'standard' else xtype

    def get_pubkey(self, c, i):
        return self.derive_pubkeys(c, i)

    def add_input_sig_info(self, txin, address):
        derivation = self.get_address_index(address)
        x_pubkey = self.keystore.get_xpubkey(*derivation)
        txin['x_pubkeys'] = [x_pubkey]
        txin['signatures'] = [None]
        txin['num_sig'] = 1

    def get_master_public_key(self):
        return self.keystore.get_master_public_key()

    def derive_pubkeys(self, c, i):
        return self.keystore.derive_pubkey(c, i)






class Standard_Wallet(Simple_Deterministic_Wallet):
    wallet_type = 'standard'

    def pubkeys_to_address(self, pubkey):
        return bitcoin.pubkey_to_address(self.txin_type, pubkey)


class Multisig_Wallet(Deterministic_Wallet):
    # generic m of n
    gap_limit = 20

    def __init__(self, storage):
        self.wallet_type = storage.get('wallet_type')
        self.m, self.n = multisig_type(self.wallet_type)
        Deterministic_Wallet.__init__(self, storage)

    def get_pubkeys(self, c, i):
        return self.derive_pubkeys(c, i)

    def get_public_keys(self, address):
        sequence = self.get_address_index(address)
        return self.get_pubkeys(*sequence)

    def pubkeys_to_address(self, pubkeys):
        redeem_script = self.pubkeys_to_redeem_script(pubkeys)
        return bitcoin.redeem_script_to_address(self.txin_type, redeem_script)

    def pubkeys_to_redeem_script(self, pubkeys):
        return transaction.multisig_script(sorted(pubkeys), self.m)

    def get_redeem_script(self, address):
        pubkeys = self.get_public_keys(address)
        redeem_script = self.pubkeys_to_redeem_script(pubkeys)
        return redeem_script

    def derive_pubkeys(self, c, i):
        return [k.derive_pubkey(c, i) for k in self.get_keystores()]

    def load_keystore(self):
        self.keystores = {}
        for i in range(self.n):
            name = 'x%d/'%(i+1)
            self.keystores[name] = load_keystore(self.storage, name)
        self.keystore = self.keystores['x1/']
        xtype = bip32.xpub_type(self.keystore.xpub)
        self.txin_type = 'p2sh' if xtype == 'standard' else xtype

    def save_keystore(self):
        for name, k in self.keystores.items():
            self.storage.put(name, k.dump())

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
                self.storage.put(name, keystore.dump())

    def check_password(self, password):
        for name, keystore in self.keystores.items():
            if keystore.may_have_password():
                keystore.check_password(password)
        self.storage.check_password(password)

    def get_available_storage_encryption_version(self):
        # multisig wallets are not offered hw device encryption
        return STO_EV_USER_PW

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

    def add_input_sig_info(self, txin, address):
        # x_pubkeys are not sorted here because it would be too slow
        # they are sorted in transaction.get_sorted_pubkeys
        # pubkeys is set to None to signal that x_pubkeys are unsorted
        derivation = self.get_address_index(address)
        x_pubkeys_expected = [k.get_xpubkey(*derivation) for k in self.get_keystores()]
        x_pubkeys_actual = txin.get('x_pubkeys')
        # if 'x_pubkeys' is already set correctly (ignoring order, as above), leave it.
        # otherwise we might delete signatures
        if x_pubkeys_actual and set(x_pubkeys_actual) == set(x_pubkeys_expected):
            return
        txin['x_pubkeys'] = x_pubkeys_expected
        txin['pubkeys'] = None
        # we need n place holders
        txin['signatures'] = [None] * self.n
        txin['num_sig'] = self.m


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

    def __new__(self, storage):
        wallet_type = storage.get('wallet_type')
        WalletClass = Wallet.wallet_class(wallet_type)
        wallet = WalletClass(storage)
        return wallet

    @staticmethod
    def wallet_class(wallet_type):
        if multisig_type(wallet_type):
            return Multisig_Wallet
        if wallet_type in wallet_constructors:
            return wallet_constructors[wallet_type]
        raise WalletFileException("Unknown wallet type: " + str(wallet_type))


def create_new_wallet(*, path, passphrase=None, password=None, encrypt_file=True, segwit=True, gap_limit=None):
    """Create a new wallet"""
    storage = WalletStorage(path)
    if storage.file_exists():
        raise Exception("Remove the existing wallet first!")

    seed_type = 'segwit' if segwit else 'standard'
    seed = Mnemonic('en').make_seed(seed_type)
    k = keystore.from_seed(seed, passphrase)
    storage.put('keystore', k.dump())
    storage.put('wallet_type', 'standard')
    if gap_limit is not None:
        storage.put('gap_limit', gap_limit)
    wallet = Wallet(storage)
    wallet.update_password(old_pw=None, new_pw=password, encrypt_storage=encrypt_file)
    wallet.synchronize()
    msg = "Please keep your seed in a safe place; if you lose it, you will not be able to restore your wallet."

    wallet.storage.write()
    return {'seed': seed, 'wallet': wallet, 'msg': msg}


def restore_wallet_from_text(text, *, path, network=None,
                             passphrase=None, password=None, encrypt_file=True,
                             gap_limit=None):
    """Restore a wallet from text. Text can be a seed phrase, a master
    public key, a master private key, a list of bitcoin addresses
    or bitcoin private keys."""
    storage = WalletStorage(path)
    if storage.file_exists():
        raise Exception("Remove the existing wallet first!")

    text = text.strip()
    if keystore.is_address_list(text):
        wallet = Imported_Wallet(storage)
        addresses = text.split()
        good_inputs, bad_inputs = wallet.import_addresses(addresses, write_to_disk=False)
        # FIXME tell user about bad_inputs
        if not good_inputs:
            raise Exception("None of the given addresses can be imported")
    elif keystore.is_private_key_list(text, allow_spaces_inside_key=False):
        k = keystore.Imported_KeyStore({})
        storage.put('keystore', k.dump())
        wallet = Imported_Wallet(storage)
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
        else:
            raise Exception("Seed or key not recognized")
        storage.put('keystore', k.dump())
        storage.put('wallet_type', 'standard')
        if gap_limit is not None:
            storage.put('gap_limit', gap_limit)
        wallet = Wallet(storage)

    assert not storage.file_exists(), "file was created too soon! plaintext keys might have been written to disk"
    wallet.update_password(old_pw=None, new_pw=password, encrypt_storage=encrypt_file)
    wallet.synchronize()

    if network:
        wallet.start_network(network)
        _logger.info("Recovering wallet...")
        wallet.wait_until_synchronized()
        wallet.stop_threads()
        # note: we don't wait for SPV
        msg = "Recovery successful" if wallet.is_found() else "Found no history for this wallet"
    else:
        msg = ("This wallet was restored offline. It may contain more addresses than displayed. "
               "Start a daemon (not offline) to sync history.")

    wallet.storage.write()
    return {'wallet': wallet, 'msg': msg}
