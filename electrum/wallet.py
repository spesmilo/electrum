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
import binascii
from functools import partial
from numbers import Number
from decimal import Decimal
from io import StringIO, BytesIO
from .bitcoin import hash160_to_b58_address

from .i18n import _
from .util import (NotEnoughFunds, PrintError, UserCancelled, profiler,
                   format_satoshis, format_fee_satoshis, NoDynamicFeeEstimates,
                   TimeoutException, WalletFileException, BitcoinException,
                   InvalidPassword, format_time)

from .bitcoin import *
from .version import *
from .keystore import load_keystore, Hardware_KeyStore, xpubkey_to_address, xpubkey_to_pubkey
from .storage import multisig_type, STO_EV_PLAINTEXT, STO_EV_USER_PW, STO_EV_XPUB_PW

from . import transaction, bitcoin, coinchooser, paymentrequest, contacts
from .transaction import Transaction, TxOutput, multisig_script
from .plugin import run_hook
from .address_synchronizer import (AddressSynchronizer, TX_HEIGHT_LOCAL,
                                   TX_HEIGHT_UNCONF_PARENT, TX_HEIGHT_UNCONFIRMED)

from .paymentrequest import PR_PAID, PR_UNPAID, PR_UNKNOWN, PR_EXPIRED
from .paymentrequest import InvoiceStore
from .contacts import Contacts

TX_STATUS = [
    _('Unconfirmed'),
    _('Unconfirmed parent'),
    _('Not Verified'),
    _('Local'),
]

def relayfee(network):
    from .simple_config import FEERATE_DEFAULT_RELAY
    MAX_RELAY_FEE = 50000
    f = network.relay_fee if network and network.relay_fee else FEERATE_DEFAULT_RELAY
    return min(f, MAX_RELAY_FEE)

def dust_threshold(network):
    # Change <= dust threshold is added to the tx fee
#    return 182 * 3 * relayfee(network) / 1000
    return 0


def append_utxos_to_inputs(inputs, network, pubkey, txin_type, imax):
    if txin_type != 'p2pk':
        address = bitcoin.pubkey_to_address(txin_type, pubkey)
        scripthash = bitcoin.address_to_scripthash(address)
    else:
        script = bitcoin.public_key_to_p2pk_script(pubkey)
        scripthash = bitcoin.script_to_scripthash(script)
        address = '(pubkey)'

    u = network.listunspent_for_scripthash(scripthash)
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

def sweep_preparations(privkeys, network, imax=100):

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


def sweep(privkeys, network, config, recipient, fee=None, imax=100):
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
    locktime = network.get_local_height()

    tx = Transaction.from_io(inputs, outputs, locktime=locktime)
    tx.BIP_LI01_sort()
    tx.set_rbf(True)
    tx.sign(keypairs)
    return tx



class CannotBumpFee(Exception): pass




class Abstract_Wallet(AddressSynchronizer):
    """
    Wallet classes are created to handle various address generation methods.
    Completion states (watching-only, single account, no seed, etc) are handled inside classes.
    """

    max_change_outputs = 3
    gap_limit_for_change = 6
    verbosity_filter = 'w'

    def __init__(self, storage):
        AddressSynchronizer.__init__(self, storage)

        self.electrum_version = ELECTRUM_VERSION
        # saved fields
        self.use_change            = storage.get('use_change', True)
        self.multiple_change       = storage.get('multiple_change', False)
        self.labels                = storage.get('labels', {})
        self.frozen_addresses      = set(storage.get('frozen_addresses',[]))
        self.registered_addresses  = set(storage.get('registered_addresses', []))
        self.pending_addresses     = set(storage.get('pending_addresses', []))
        self.fiat_value            = storage.get('fiat_value', {})
        self.receive_requests      = storage.get('payment_requests', {})
        self.contracts             = storage.get('contracts', [])


        # save wallet type the first time
        if self.storage.get('wallet_type') is None:
            self.storage.put('wallet_type', self.wallet_type)

        # invoices and contacts
        self.invoices = InvoiceStore(self.storage)
        self.contacts = Contacts(self.storage)

        self.coin_price_cache = {}

    def get_block_height(self):
        return self.network.get_local_height()

    def load_and_cleanup(self):
        self.load_keystore()
        self.load_addresses()
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

    def save_addresses(self):
        self.storage.put('addresses', {'receiving':self.receiving_addresses, 'change':self.change_addresses, 'encryption':self.encryption_addresses})

    def load_addresses(self):
        d = self.storage.get('addresses', {})
        if type(d) != dict: d={}
        self.receiving_addresses = d.get('receiving', [])
        self.change_addresses = d.get('change', [])
        self.encryption_addresses = d.get('encryption', [])

    def test_addresses_sanity(self):
        addrs = self.get_receiving_addresses()
        if len(addrs) > 0:
            if not bitcoin.is_address(addrs[0]):
                raise WalletFileException('The addresses in this wallet are not bitcoin addresses.')

    def synchronize(self):
        pass

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
            if old_text:
                self.labels.pop(name)
                changed = True
        if changed:
            run_hook('set_label', self, name, text)
            self.storage.put('labels', self.labels)
        return changed

    def set_fiat_value(self, txid, ccy, text):
        if txid not in self.transactions:
            return
        if not text:
            d = self.fiat_value.get(ccy, {})
            if d and txid in d:
                d.pop(txid)
            else:
                return
        else:
            try:
                Decimal(text)
            except:
                return
        if ccy not in self.fiat_value:
            self.fiat_value[ccy] = {}
        self.fiat_value[ccy][txid] = text
        self.storage.put('fiat_value', self.fiat_value)

    def get_fiat_value(self, txid, ccy):
        fiat_value = self.fiat_value.get(ccy, {}).get(txid)
        try:
            return Decimal(fiat_value)
        except:
            return

    def is_mine(self, address):
        if not super().is_mine(address):
            return False
        try:
            self.get_address_index(address)
        except KeyError:
            return False
        return True

    def is_change(self, address):
        if not self.is_mine(address):
            return False
        return self.get_address_index(address)[0]

    def get_address_index(self, address):
        raise NotImplementedError()

    def get_redeem_script(self, address):
        return None

    def export_private_key(self, address, password, includeRedeemScript = True):
        if self.is_watching_only():
            return []
        index = self.get_address_index(address)

        # Go through all contracts and no contract to find the
        # private key that corresponds to the address in our wallet
        pk, compressed = self.get_tweaked_private_key(address, index, password, self.get_txin_type(address))

        txin_type = self.get_txin_type(address)
        serialized_privkey = bitcoin.serialize_privkey(pk, compressed, txin_type)

        if includeRedeemScript:
            redeem_script = self.get_redeem_script(address)
            return serialized_privkey, redeem_script
        #Exclude redeem script
        return serialized_privkey, None

    def get_public_keys(self, address, tweaked=True):
        return [self.get_public_key(address, tweaked)]

    def is_found(self):
        return self.history.values() != [[]] * len(self.history)

    def get_tx_info(self, tx):
        is_relevant, is_mine, v, fee = self.get_wallet_delta(tx)
        exp_n = None
        can_broadcast = False
        can_bump = False
        label = ''
        height = conf = timestamp = None
        tx_hash = tx.txid()
        if tx.is_complete():
            if tx_hash in self.transactions.keys():
                label = self.get_label(tx_hash)
                tx_mined_status = self.get_tx_height(tx_hash)
                height, conf = tx_mined_status.height, tx_mined_status.conf
                if height > 0:
                    if conf:
                        status = _("{} confirmations").format(conf)
                    else:
                        status = _('Not verified')
                elif height in (TX_HEIGHT_UNCONF_PARENT, TX_HEIGHT_UNCONFIRMED):
                    status = _('Unconfirmed')
                    if fee is None:
                        fee = self.tx_fees.get(tx_hash)
                    if fee and self.network and self.network.config.has_fee_mempool():
                        size = tx.estimated_size()
                        fee_per_byte = fee / size
                        exp_n = self.network.config.fee_to_depth(fee_per_byte)
                    can_bump = is_mine and not tx.is_final()
                else:
                    status = _('Local')
                    can_broadcast = self.network is not None
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

        return tx_hash, status, label, can_broadcast, can_bump, amount, fee, height, conf, timestamp, exp_n

    def get_spendable_coins(self, domain, config):
        confirmed_only = config.get('confirmed_only', False)
        return self.get_utxos(domain, excluded=self.frozen_addresses, mature=True, confirmed_only=confirmed_only)

    def dummy_address(self):
        return self.get_receiving_addresses()[0]

    def get_frozen_balance(self):
        return self.get_balance(self.frozen_addresses)

    def balance_at_timestamp(self, domain, target_timestamp):
        h = self.get_history(domain)
        balance = 0
        for tx_hash, tx_mined_status, value, balance in h:
            if tx_mined_status.timestamp > target_timestamp:
                return balance - value
        # return last balance
        return balance

    @profiler
    def get_full_history(self, domain=None, from_timestamp=None, to_timestamp=None, fx=None, show_addresses=False):
        from .util import timestamp_to_datetime, Satoshis, Fiat
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
            item = {
                'txid': tx_hash,
                'height': tx_mined_status.height,
                'confirmations': tx_mined_status.conf,
                'timestamp': timestamp,
                'value': Satoshis(value),
                'balance': Satoshis(balance),
                'date': timestamp_to_datetime(timestamp),
                'label': self.get_label(tx_hash),
            }
            if show_addresses:
                tx = self.transactions.get(tx_hash)
                item['inputs'] = list(map(lambda x: dict((k, x[k]) for k in ('prevout_hash', 'prevout_n')), tx.inputs()))
                item['outputs'] = list(map(lambda x:{'address':x[0], 'value':Satoshis(x[1]), 'asset':x[2]}, tx.get_outputs()))
            # value may be None if wallet is not fully synchronized
            if value is None:
                continue
            # fixme: use in and out values
            if value < 0:
                expenditures += -value
            else:
                income += value
            # fiat computations
            if fx and fx.is_enabled():
                fiat_value = self.get_fiat_value(tx_hash, fx.ccy)
                fiat_default = fiat_value is None
                fiat_value = fiat_value if fiat_value is not None else value / Decimal(COIN) * self.price_at_timestamp(tx_hash, fx.timestamp_rate)  #
                item['fiat_value'] = Fiat(fiat_value, fx.ccy)
                item['fiat_default'] = fiat_default
                if value < 0:
                    acquisition_price = - value / Decimal(COIN) * self.average_price(tx_hash, fx.timestamp_rate, fx.ccy)
                    liquidation_price = - fiat_value
                    item['acquisition_price'] = Fiat(acquisition_price, fx.ccy)
                    cg = liquidation_price - acquisition_price
                    item['capital_gain'] = Fiat(cg, fx.ccy)
                    capital_gains += cg
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
                'start_balance': Satoshis(start_balance),
                'end_balance': Satoshis(end_balance),
                'income': Satoshis(income),
                'expenditures': Satoshis(expenditures)
            }
            if fx and fx.is_enabled():
                unrealized = self.unrealized_gains(domain, fx.timestamp_rate, fx.ccy)
                summary['capital_gains'] = Fiat(capital_gains, fx.ccy)
                summary['fiat_income'] = Fiat(fiat_income, fx.ccy)
                summary['fiat_expenditures'] = Fiat(fiat_expenditures, fx.ccy)
                summary['unrealized_gains'] = Fiat(unrealized, fx.ccy)
                summary['start_fiat_balance'] = Fiat(fx.historical_value(start_balance, start_date), fx.ccy)
                summary['end_fiat_balance'] = Fiat(fx.historical_value(end_balance, end_date), fx.ccy)
                summary['start_fiat_value'] = Fiat(fx.historical_value(COIN, start_date), fx.ccy)
                summary['end_fiat_value'] = Fiat(fx.historical_value(COIN, end_date), fx.ccy)
        else:
            summary = {}
        return {
            'transactions': out,
            'summary': summary
        }

    def get_label(self, tx_hash):
        label = self.labels.get(tx_hash, '')
        if label is '':
            label = self.get_default_label(tx_hash)
        return label

    def get_default_label(self, tx_hash):
        if self.txi.get(tx_hash) == {}:
            d = self.txo.get(tx_hash, {})
            labels = []
            for addr in d.keys():
                label = self.labels.get(addr)
                if label:
                    labels.append(label)
            return ', '.join(labels)
        return ''

    def get_tx_status(self, tx_hash, tx_mined_status):
        extra = []
        height = tx_mined_status.height
        conf = tx_mined_status.conf
        timestamp = tx_mined_status.timestamp
        if conf == 0:
            tx = self.transactions.get(tx_hash)
            if not tx:
                return 2, 'unknown'
            is_final = tx and tx.is_final()
            if not is_final:
                extra.append('rbf')
            fee = self.get_wallet_delta(tx)[3]
            if fee is None:
                fee = self.tx_fees.get(tx_hash)
            if fee is not None:
                size = tx.estimated_size()
                fee_per_byte = fee / size
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
                status = 2
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


    def make_unsigned_transaction(self, inputs, outputs, config, fixed_fee=None,
                                  change_addr=None, is_sweep=False, b_allow_zerospend: bool = False):
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

        # Avoid index-out-of-range with inputs[0] below
        if not inputs:
            raise NotEnoughFunds()

        if fixed_fee is None and config.fee_per_kb() is None:
            raise NoDynamicFeeEstimates()

        for item in inputs:
            self.add_input_info(item)

        # change address
        if change_addr:
            change_addrs = [change_addr]
        else:
            addrs = self.get_change_addresses(whitelistedOnly=True)[-self.gap_limit_for_change:]
            if self.use_change and addrs:
                # New change addresses are created only after a few
                # confirmations.  Select the unused addresses within the
                # gap limit; if none take one at random
                change_addrs = [addr for addr in addrs if
                                self.get_num_tx(addr) == 0]
                if not change_addrs:
                    change_addrs = [random.choice(addrs)]
            else:
                # coin_chooser will set change address
                change_addrs = []

              # Fee estimator
        if fixed_fee is None:
            fee_estimator = config.estimate_fee
        elif isinstance(fixed_fee, Number):
            fee_estimator = lambda size: fixed_fee
        elif callable(fixed_fee):
            fee_estimator = fixed_fee
        else:
            raise Exception('Invalid argument fixed_fee: %s' % fixed_fee)


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
            max_change = self.max_change_outputs if self.multiple_change else 1
            coin_chooser = coinchooser.get_coin_chooser(config)
            tx = coin_chooser.make_tx(inputs, outputs, change_addrs[:max_change],
                                      fee_estimator, self.dust_threshold(), b_allow_zerospend)
        else:
            # FIXME?? this might spend inputs with negative effective value...
            sendable = sum(map(lambda x:x['value'], inputs))
            outputs[i_max] = outputs[i_max]._replace(value=0)
            tx = Transaction.from_io(inputs, outputs[:])
            fee = fee_estimator(tx.estimated_size())
            amount = sendable - tx.output_value() - fee
            if amount < 0:
                raise NotEnoughFunds()

            # add asset information to output
            outputs[i_max] = outputs[i_max]._replace(value=amount)
            input_map = coinchooser.get_input_asset_map(inputs)

            asset_outputs = [TxOutput(o.type, o.address, value, 1, asset, 1)
                for o in outputs for (asset, value) in coinchooser.get_asset_outputs(o.value, input_map)]

            # add fee output
            tx = Transaction.from_io(inputs, asset_outputs[:])
            tx.add_outputs(TxOutput(TYPE_SCRIPT, '', value, 1, asset, 1)
                for (asset, value) in coinchooser.get_asset_outputs(tx.get_fee(), input_map))

        # Sort the inputs and outputs deterministically
        tx.BIP_LI01_sort()
        # Timelock tx to current height.
        tx.locktime = self.get_local_height()
        run_hook('make_unsigned_transaction', self, tx)
        return tx

    def mktx(self, outputs, password, config, fee=None, change_addr=None, domain=None):
        coins = self.get_spendable_coins(domain, config)
        tx = self.make_unsigned_transaction(coins, outputs, config, fee, change_addr)
        self.sign_transaction(tx, password)
        return tx

    def is_frozen(self, addr):
        return addr in self.frozen_addresses

    def is_pending(self, addr):
        return addr in self.pending_addresses

    def is_registered(self, addr):
        return addr in self.registered_addresses

    def get_pending_addresses(self):
        return self.pending_addresses

    def set_frozen_state(self, addrs, freeze):
        '''Set frozen state of the addresses to FREEZE, True or False'''
        if all(self.is_mine(addr) for addr in addrs):
            if freeze:
                self.frozen_addresses |= set(addrs)
            else:
                self.frozen_addresses -= set(addrs)
            self.storage.put('frozen_addresses', list(self.frozen_addresses))
            return True
        return False

    def set_registered_state(self, addrs,  reg: bool):
        '''Set registered state of the addresses to STATE, True or False'''
        if all(self.is_mine(addr) for addr in addrs):
            if reg:
                self.registered_addresses |= set(addrs)
            else:
                self.registered_addresses -= set(addrs)
            self.storage.put('registered_addresses', list(self.registered_addresses))
            return True
        return False

    def set_pending_state(self, addrs, pend: bool):
        '''Set pending state of the addresses to STATE, True or False'''
        if all(self.is_mine(addr) for addr in addrs):
            if pend:
                self.pending_addresses |= set(addrs)
            else:
                self.pending_addresses -= set(addrs)
            self.storage.put('pending_addresses', list(self.pending_addresses))
            return True
        return False

    def wait_until_synchronized(self, callback=None):
        def wait_for_wallet():
            self.set_up_to_date(False)
            while not self.is_up_to_date():
                if callback:
                    msg = "%s\n%s %d"%(
                        _("Please wait..."),
                        _("Addresses generated:"),
                        len(self.addresses(True)))
                    callback(msg)
                time.sleep(0.1)
        def wait_for_network():
            while not self.network.is_connected():
                if callback:
                    msg = "%s \n" % (_("Connecting..."))
                    callback(msg)
                time.sleep(0.1)
        # wait until we are connected, because the user
        # might have selected another server
        if self.network:
            wait_for_network()
            wait_for_wallet()
        else:
            self.synchronize()

    def can_export(self):
        return not self.is_watching_only() and hasattr(self.keystore, 'get_private_key')

    def address_is_old(self, address, age_limit=2):
        age = -1
        h = self.history.get(address, [])
        for tx_hash, tx_height in h:
            if tx_height <= 0:
                tx_age = 0
            else:
                tx_age = self.get_local_height() - tx_height + 1
            if tx_age > age:
                age = tx_age
        return age > age_limit

    def bump_fee(self, tx, delta):
        if tx.is_final():
            raise CannotBumpFee(_('Cannot bump fee') + ': ' + _('transaction is final'))
        tx = Transaction(tx.serialize())
        tx.deserialize(force_full_parse=True)  # need to parse inputs
        inputs = copy.deepcopy(tx.inputs())
        outputs = copy.deepcopy(tx.outputs())
        for txin in inputs:
            txin['signatures'] = [None] * len(txin['signatures'])
            self.add_input_info(txin)
        # use own outputs
        s = list(filter(lambda x: self.is_mine(x[1]), outputs))
        # ... unless there is none
        if not s:
            s = outputs
            x_fee = run_hook('get_tx_extra_fee', self, tx)
            if x_fee:
                x_fee_address, x_fee_amount = x_fee
                s = filter(lambda x: x[1]!=x_fee_address, s)

        # prioritize low value outputs, to get rid of dust
        s = sorted(s, key=lambda x: x[2])
        for o in s:
            i = outputs.index(o)
            if o.value - delta >= self.dust_threshold():
                outputs[i] = o._replace(value=o.value-delta)
                delta = 0
                break
            else:
                del outputs[i]
                delta -= o.value
                if delta > 0:
                    continue
        if delta > 0:
            raise CannotBumpFee(_('Cannot bump fee') + ': ' + _('could not find suitable outputs'))
        locktime = self.get_local_height()
        tx_new = Transaction.from_io(inputs, outputs, locktime=locktime)
        tx_new.BIP_LI01_sort()
        return tx_new

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
        outputs = [TxOutput(TYPE_ADDRESS, address, value - fee)]
        locktime = self.get_local_height()
        # note: no need to call tx.BIP_LI01_sort() here - single input/output
        return Transaction.from_io(inputs, outputs, locktime=locktime)

    def add_input_sig_info(self, txin, address):
        raise NotImplementedError()  # implemented by subclasses

    def add_input_info(self, txin):
        address = txin['address']
        if self.is_mine(address):
            txin['type'] = self.get_txin_type(address)
            # segwit needs value to sign
            if txin.get('value') is None and Transaction.is_input_value_needed(txin):
                received, spent = self.get_addr_io(address)
                item = received.get(txin['prevout_hash']+':%d'%txin['prevout_n'])
                tx_height, value, asset, is_cb = item
                txin['value'] = value
            self.add_input_sig_info(txin, address)

    def add_input_info_to_all_inputs(self, tx):
        if tx.is_complete():
            return
        for txin in tx.inputs():
            self.add_input_info(txin)

    def can_sign(self, tx):
        if tx.is_complete():
            return False
        # add info to inputs if we can; otherwise we might return a false negative:
        self.add_input_info_to_all_inputs(tx)  # though note that this is a side-effect
        for k in self.get_keystores():
            if k.can_sign(tx):
                return True
        return False

    def get_input_tx(self, tx_hash, ignore_timeout=False):
        # First look up an input transaction in the wallet where it
        # will likely be.  If co-signing a transaction it may not have
        # all the input txs, in which case we ask the network.
        tx = self.transactions.get(tx_hash, None)
        if not tx and self.network:
            try:
                tx = Transaction(self.network.get_transaction(tx_hash))
            except TimeoutException as e:
                self.print_error('getting input txn from network timed out for {}'.format(tx_hash))
                if not ignore_timeout:
                    raise e
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
                info[addr] = index, sorted_xpubs, self.m if isinstance(self, Multisig_Wallet) else None
        tx.output_info = info

    def sign_transaction(self, tx, password):
        if self.is_watching_only():
            return
        self.add_input_info_to_all_inputs(tx)
        # hardware wallets require extra info
        if any([(isinstance(k, Hardware_KeyStore) and k.can_sign(tx)) for k in self.get_keystores()]):
            self.add_hw_info(tx)
        # sign. start with ready keystores.
        for k in sorted(self.get_keystores(), key=lambda ks: ks.ready_to_sign(), reverse=True):
            try:
                if k.can_sign(tx):
                    k.check_password(password)
                    # Add private keys
                    keypairs = k.get_tx_derivations(tx)
                    for x_pubkey, (derivation, address) in keypairs.items():
                        keypairs[x_pubkey] = self.get_tweaked_private_key(address, derivation, password, self.get_txin_type(address))
                    k.sign_transaction(tx, keypairs)
            except UserCancelled:
                continue
        return tx

    def get_unused_addresses(self):
        # fixme: use slots from expired requests
        domain = self.get_receiving_addresses()
        return [addr for addr in domain if not self.history.get(addr)
                and addr not in self.receive_requests.keys()]

    def get_unused_address(self):
        addrs = self.get_unused_addresses()
        if addrs:
            return addrs[0]

    def get_receiving_address(self):
        # always return an address
        domain = self.get_receiving_addresses()
        if not domain:
            return
        choice = domain[0]
        for addr in domain:
            if not self.history.get(addr):
                if addr not in self.receive_requests.keys():
                    return addr
                else:
                    choice = addr
        return choice

    def get_unused_encryption_address(self):
        addrs = self.get_unused_encryption_addresses()
        if addrs:
            return addrs[0]


    def get_unused_encryption_addresses(self):
        domain = self.get_encryption_addresses()
        return [addr for addr in domain if not self.history.get(addr)
                and addr not in self.receive_requests.keys()]

    def get_payment_status(self, address, amount):
        local_height = self.get_local_height()
        received, sent = self.get_addr_io(address)
        l = []
        for txo, x in received.items():
            h, v, a, is_cb = x
            txid, n = txo.split(':')
            info = self.verified_tx.get(txid)
            if info:
                conf = local_height - info.height
            else:
                conf = 0
            l.append((conf, v, a))
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
                        self.print_stderr('Invalid config setting for "url_rewrite". err:', e)
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
        _id = bh2u(Hash(addr + "%d"%timestamp))[0:10]
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
            raise Exception(_('Invalid Ocean address.'))
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
        def f(addr):
            try:
                return self.get_address_index(addr)
            except:
                return
        keys = map(lambda x: (f(x), x), self.receive_requests.keys())
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

    def get_tweaked_private_key(self, address, sequence, password, aType='p2pkh'):
        if aType == 'p2pkh':
            for contract_hash in self.contracts + [None]:
                pk, compressed = self.keystore.get_private_key(sequence, password, contract_hash)
                pubkey_from_priv = ecc.ECPrivkey(pk).get_public_key_hex(compressed=compressed)
                if address == self.pubkeys_to_address(pubkey_from_priv):
                    return pk, compressed
        #May need to somehow modify this code to check p2sh validity in the case where there are several contracts
        #TODO: if multiple contracts are used this code needs to be changed to verify that the private key is valid instead of returning the first one
        elif aType == 'p2sh':
            for contract_hash in self.contracts + [None]:
                pk, compressed = self.keystore.get_private_key(sequence, password, contract_hash)
                return pk, compressed
        # This exception will probably never be thrown since we allow
        # non-tweaked addresses in the above loop (by using 'None')
        # Might want to remove that to stop people from generating
        # addresses without first importing the terms and conditions file
        raise WalletFileException('Private key not found. The corresponding '
            'address might have been derived without tweaking or incorrect tweaking.')

    def get_tweaked_public_key(self, address, pubkey):
        for contract_hash in self.contracts + [None]:
            tweaked_pubkey = self.tweak_pubkeys(pubkey, contract_hash)
            if address == self.pubkeys_to_address(tweaked_pubkey):
                return tweaked_pubkey
        raise WalletFileException('Public key not found. The corresponding '
        'address might have been derived without tweaking or incorrect tweaking.')

    def get_tweaked_multi_public_keys(self, address, pubkeys, m, shouldSort = True):
        for contract_hash in self.contracts + [None]:
            unsorted_tweaked_pubkeys = self.tweak_pubkeys(pubkeys, contract_hash)
            tweaked_pubkeys = sorted(unsorted_tweaked_pubkeys)
            redeem_script = multisig_script(tweaked_pubkeys, m) 
            tempAddr = bitcoin.hash160_to_p2sh(hash_160(bfh(redeem_script)))
            if tempAddr == address:
                if shouldSort:
                    return tweaked_pubkeys
                #Return unsorted pubkeys
                return unsorted_tweaked_pubkeys
        raise WalletFileException('Public keys not found. The corresponding '
        'address might have been derived without tweaking or incorrect tweaking.')

    def sign_message(self, address, message, password):
        index = self.get_address_index(address)
        priv, compressed = self.get_tweaked_private_key(address, index, password, self.get_txin_type(address))
        return self.keystore.sign_message(priv, compressed, message)

    def decrypt_message(self, pubkey, message, password):
        addr = self.pubkeys_to_address(pubkey)
        index = self.get_address_index(addr)
        priv, compressed = self.get_tweaked_private_key(addr, index, password, self.get_txin_type(address))
        return self.keystore.decrypt_message(priv, compressed, message)

    def get_depending_transactions(self, tx_hash):
        """Returns all (grand-)children of tx_hash in this wallet."""
        children = set()
        # TODO rewrite this to use self.spent_outpoints
        for other_hash, tx in self.transactions.items():
            for input in (tx.inputs()):
                if input["prevout_hash"] == tx_hash:
                    children.add(other_hash)
                    children |= self.get_depending_transactions(other_hash)
        return children

    def txin_value(self, txin):
        txid = txin['prevout_hash']
        prev_n = txin['prevout_n']
        for address, d in self.txo.get(txid, {}).items():
            for n, v, a, cb in d:
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
        for addr, d in self.txi.get(txid, {}).items():
            for ser, v in d:
                input_value += v
                total_price += self.coin_price(ser.split(':')[0], price_func, ccy, v)
        return total_price / (input_value/Decimal(COIN))

    def coin_price(self, txid, price_func, ccy, txin_value):
        """
        Acquisition price of a coin.
        This assumes that either all inputs are mine, or no input is mine.
        """
        if txin_value is None:
            return Decimal('NaN')
        cache_key = "{}:{}:{}".format(str(txid), str(ccy), str(txin_value))
        result = self.coin_price_cache.get(cache_key, None)
        if result is not None:
            return result
        if self.txi.get(txid, {}) != {}:
            result = self.average_price(txid, price_func, ccy) * txin_value/Decimal(COIN)
            self.coin_price_cache[cache_key] = result
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

    def parse_policy_tx(self, tx: transaction.Transaction, parent_window):
        if self.parse_registeraddress_tx(tx, parent_window):
            return True
        if self.parse_whitelist_tx(tx):
            return True
        return False

    #Get the address the transaction fee was paid from
    def get_from_addresses(self, tx):
        from_addresses=[]
        input_addresses = set()
        for txin in  tx.inputs():
            input_addresses.add(self.get_txin_address(txin))
        return input_addresses

    def derive_onboard_priv_key(self, onboardAddress, parent_window, return_serialized=False):
        #Check that this wallet holds the onboard user private key
        if not self.is_mine(onboardAddress):
            return None

        password=None

        if self.storage.is_encrypted() or self.storage.get('use_encryption'):
            if self.storage.is_encrypted_with_hw_device():
                #TODO - sort out what to do for encrypted wallets.
                return None
            else:
                if self.has_keystore_encryption():
                    if return_serialized == False:
                        msg = _('Received encrypted address whitelist onboarding transaction.') + '\n' + _('Please enter your password to update wallet whitelist status.')
                    else:
                        msg = _('Exporting the onboarding private key.') + '\n' + _('Please enter your password.')
                    password = parent_window.password_dialog(msg, parent=parent_window.top_level_window())
                    if not password:
                        return None
        try: 
            onboardUserKey_serialized, redeem_script = self.export_private_key(onboardAddress, password=password, includeRedeemScript=False)  
            if return_serialized: 
                return onboardUserKey_serialized
            #Deserialize it
            txin_type, secret_bytes, compressed = bitcoin.deserialize_privkey(onboardUserKey_serialized)
            _onboardUserKey=ecc.ECPrivkey(secret_bytes)
            return _onboardUserKey
                
        except Exception as e:
            print(e)
            return None

    def parse_registeraddress_data(self, data, tx, parent_window):
        # We must have already been assigned a kyc public key
        if self.kyc_pubkey == None:
            return False

        fromAddresses = self.get_from_addresses(tx)
        if fromAddresses == None:
            return False

        fromAddress=None
        for address in fromAddresses:
            if self.is_mine(address):
                fromAddress=address
                break

        if fromAddress == None:
            return False



        password=None
        if self.storage.is_encrypted() or self.storage.get('use_encryption'):
            if self.storage.is_encrypted_with_hw_device():
                #TODO - sort out what to do for encrypted wallets.
                return False
            else:
                if self.has_keystore_encryption():
                    msg = _('Received encrypted address whitelist registration transaction.') + '\n' + _('Please enter your password to update wallet whitelist status.')
                    password = parent_window.password_dialog(msg, parent=parent_window.top_level_window())
                    if not password:
                        return False

        try:
            fromKey_serialized, redeem_script=self.export_private_key(fromAddress, password=password)
            txin_type, secret_bytes, compressed = bitcoin.deserialize_privkey(fromKey_serialized)
            fromKey=ecc.ECPrivkey(secret_bytes)
        except Exception:
            return False

        try:
            plaintext=fromKey.decrypt_message(data, ephemeral_pubkey_bytes=bfh(self.kyc_pubkey), decode=binascii.unhexlify)
        except Exception:
            return False


        self.parse_ratx_addresses(plaintext)

        return True

    def parse_onboard_data(self, data, parent_window):
        pubKeySize=33
        addressSize=20
        minPayloadSize=2

        i1=0
        i2=33
        if(len(data)<2*pubKeySize+minPayloadSize):
            return False

        kyc_pubkey=data[i1:i2]
        #Check if this is a onboarding TX
        try:
            _kyc_pubkey=ecc.ECPubkey(kyc_pubkey)
        except ecc.InvalidECPointException:
            return False
        except ValueError:
            return False
        i1=i2
        i2+=33
        userOnboardPubKey = data[i1:i2]
        try:
            _userOnboardPubKey=ecc.ECPubkey(userOnboardPubKey)
        except InvalidECPointException:
            return False
        except ValueError:
            return False
        #Check that this wallet holds the onboard user private key
        onboardAddress=bitcoin.public_key_to_p2pkh(userOnboardPubKey)
        _onboardUserKey = self.derive_onboard_priv_key(onboardAddress, parent_window)
        if _onboardUserKey is None:
            print('Failed to retrieve the onboarding private key from the address')
            return False
        i1=i2
        ciphertext=data[i1:]
        try:
            plaintext, ephemeral=_onboardUserKey.decrypt_message(ciphertext, get_ephemeral=True, decode=binascii.unhexlify)
        except Exception:
            return False
        #Confirm that this was encrypted by the kyc private key owner
        if not ephemeral == _kyc_pubkey:
            return False
        self.parse_ratx_addresses(plaintext)

        self.set_kyc_pubkey(bh2u(kyc_pubkey))
        self.set_onboard_address(onboardAddress)

        return True

    def parse_ratx_addresses(self, data):
        #Add addresses to the list of registered addresses
        #First 20 bytes == address
        #Next 33 bytes == untweaked public key
        #If it is a multisig wallet then we need to account for the extra byte of N and an extra byte of M
        i3 = 0
        ptlen = len(data)
        addrs = []
        multiSize = 0
        addrType = constants.net.ADDRTYPE_P2PKH
        #string of is contained in multisig addresses (e.g.: 2of2)
        if "of" in self.wallet_type:
            multiSize = 1
            addrType = constants.net.ADDRTYPE_P2SH

        moreLeft = True
        nBytesInSegment = 0
        i1 = 0
        while moreLeft is True:
            #2 bytes for n and m of multisig if the wallet is multisig type
            i1 = i1 + nBytesInSegment + multiSize*2
            #address key id
            i2 = i1 + 20
            #first public key of the address (the only if its p2pkh)
            i3 = i2 + 33
            bkupI = i2

            if i3 > ptlen:
                break


            nMultisig=0
            #if it is a multisig wallet get the remaining public keys (N)
            if multiSize != 0:
                nMultisig = int.from_bytes(bytes(data[i1-1:i1]), "big")
                for i in range(nMultisig):
                    pubkeyBytes = bytes(data[bkupI:i3])
                    bkupI = i3
                    i3 += 33
                        
                    if i3 > ptlen:
                        moreLeft = False
                        break

            addrbytes=bytes(data[i1:i2])

            addrs.append(hash160_to_b58_address(addrbytes, addrType))

            #Calculate the number of bytes in the current segment so we know where to read the next address
            nBytesInSegment = 20 + (multiSize > 0)*(nMultisig-1)*33 + 33 

        self.set_pending_state(addrs, False)
        self.set_registered_state(addrs, True)

    def get_zero_address(self):
        return hash160_to_b58_address(bytearray.fromhex('0'*40) , constants.net.ADDRTYPE_P2PKH)

    def parse_registeraddress_tx(self, tx: transaction.Transaction, parent_window):
        decoded=dict()
        data=None
        outputs = tx.outputs()
        for output in outputs:
            transaction.parse_scriptSig(decoded, bfh(output.scriptPubKey))
            if len(decoded) is not 0:
                txtype=decoded['type']
                if txtype == 'registeraddress':
                    data=decoded['data']
                    break
                else:
                    decoded=[]

        if data is None:
            return False

        if self.parse_onboard_data(data, parent_window):
            return True

        if self.parse_registeraddress_data(data, tx, parent_window):
            return True

        return False


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

    def save_keystore(self):
        self.storage.put('keystore', self.keystore.dump())

    def load_addresses(self):
        self.addresses = self.storage.get('addresses', {})
        # fixme: a reference to addresses is needed
        if self.keystore:
            self.keystore.addresses = self.addresses

    def save_addresses(self):
        self.storage.put('addresses', self.addresses)

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
        return sorted(self.addresses.keys())

    def get_receiving_addresses(self):
        return self.get_addresses()

    def get_change_addresses(self, whitelistedOnly=False):
        return []

    def import_address(self, address):
        if not bitcoin.is_address(address):
            return ''
        if address in self.addresses:
            return ''
        self.addresses[address] = {}
        self.add_address(address)
        self.save_addresses()
        self.save_transactions(write=True)
        return address

    def delete_address(self, address):
        if address not in self.addresses:
            return

        transactions_to_remove = set()  # only referred to by this address
        transactions_new = set()  # txs that are not only referred to by address
        with self.lock:
            for addr, details in self.history.items():
                if addr == address:
                    for tx_hash, height in details:
                        transactions_to_remove.add(tx_hash)
                else:
                    for tx_hash, height in details:
                        transactions_new.add(tx_hash)
            transactions_to_remove -= transactions_new
            self.history.pop(address, None)

            for tx_hash in transactions_to_remove:
                self.remove_transaction(tx_hash)
                self.tx_fees.pop(tx_hash, None)
                self.verified_tx.pop(tx_hash, None)
                self.unverified_tx.pop(tx_hash, None)
                self.transactions.pop(tx_hash, None)
            self.save_verified_tx()
        self.save_transactions()

        self.set_label(address, None)
        self.remove_payment_request(address, {})
        self.set_frozen_state([address], False)

        pubkey = self.get_public_key(address)
        self.addresses.pop(address)
        if pubkey:
            # delete key iff no other address uses it (e.g. p2pkh and p2wpkh for same key)
            for txin_type in bitcoin.WIF_SCRIPT_TYPES.keys():
                try:
                    addr2 = bitcoin.pubkey_to_address(txin_type, pubkey)
                except NotImplementedError:
                    pass
                else:
                    if addr2 in self.addresses:
                        break
            else:
                self.keystore.delete_imported_key(pubkey)
                self.save_keystore()
        self.save_addresses()

        self.storage.write()

    def get_address_index(self, address):
        return self.get_public_key(address)

    def get_public_key(self, address):
        return self.addresses[address].get('pubkey')

    def import_private_key(self, sec, pw, redeem_script=None):
        try:
            txin_type, pubkey = self.keystore.import_privkey(sec, pw)
        except Exception:
            neutered_privkey = str(sec)[:3] + '..' + str(sec)[-2:]
            raise BitcoinException('Invalid private key: {}'.format(neutered_privkey))
        if txin_type in ['p2pkh', 'p2wpkh', 'p2wpkh-p2sh']:
            if redeem_script is not None:
                raise BitcoinException('Cannot use redeem script with script type {}'.format(txin_type))
            addr = bitcoin.pubkey_to_address(txin_type, pubkey)
        elif txin_type in ['p2sh', 'p2wsh', 'p2wsh-p2sh']:
            if redeem_script is None:
                raise BitcoinException('Redeem script required for script type {}'.format(txin_type))
            addr = bitcoin.redeem_script_to_address(txin_type, redeem_script)
        else:
            raise NotImplementedError(txin_type)
        self.addresses[addr] = {'type':txin_type, 'pubkey':pubkey, 'redeem_script':redeem_script}
        self.save_keystore()
        self.add_address(addr)
        self.save_addresses()
        self.save_transactions(write=True)
        return addr

    def get_redeem_script(self, address):
        d = self.addresses[address]
        redeem_script = d['redeem_script']
        return redeem_script

    def get_txin_type(self, address):
        return self.addresses[address].get('type', 'address')

    def add_input_sig_info(self, txin, address):
        if self.is_watching_only():
            x_pubkey = 'fd' + address_to_script(address)
            txin['x_pubkeys'] = [x_pubkey]
            txin['signatures'] = [None]
            return
        if txin['type'] in ['p2pkh', 'p2wpkh', 'p2wpkh-p2sh']:
            pubkey = self.addresses[address]['pubkey']
            txin['num_sig'] = 1
            txin['x_pubkeys'] = [pubkey]
            txin['signatures'] = [None]
        else:
            raise NotImplementedError('imported wallets for p2sh are not implemented')

    def pubkeys_to_address(self, pubkey):
        for addr, v in self.addresses.items():
            if v.get('pubkey') == pubkey:
                return addr

class Deterministic_Wallet(Abstract_Wallet):

    def __init__(self, storage):
        Abstract_Wallet.__init__(self, storage)
        self.gap_limit = storage.get('gap_limit', 100)

    def has_seed(self):
        return self.keystore.has_seed()

    def get_addresses(self):
        # note: overridden so that the history can be cleared.
        # addresses are ordered based on derivation
        out = []
        out += self.get_receiving_addresses()
        out += self.get_change_addresses()
        return out

    def get_receiving_addresses(self):
        return self.receiving_addresses

    def get_encryption_addresses(self):
        return self.encryption_addresses

    def get_change_addresses(self, whitelistedOnly=False):
        if whitelistedOnly:
            return [addr for addr in self.change_addresses if self.is_registered(addr)]
        return self.change_addresses

    def get_seed(self, password):
        return self.keystore.get_seed(password)

    def add_seed(self, seed, pw):
        self.keystore.add_seed(seed, pw)

    def change_gap_limit(self, value):
        '''This method is not called in the code, it is kept for console use'''
        if value >= self.gap_limit:
            self.gap_limit = value
            self.storage.put('gap_limit', self.gap_limit)
            return True
        elif value >= self.min_acceptable_gap():
            addresses = self.get_receiving_addresses()
            k = self.num_unused_trailing_addresses(addresses)
            n = len(addresses) - k + value
            self.receiving_addresses = self.receiving_addresses[0:n]
            self.gap_limit = value
            self.storage.put('gap_limit', self.gap_limit)
            self.save_addresses()
            return True
        else:
            return False

    def num_unused_trailing_addresses(self, addresses):
        k = 0
        for a in addresses[::-1]:
            if self.history.get(a):break
            k = k + 1
        return k

    def min_acceptable_gap(self):
        # fixme: this assumes wallet is synchronized
        n = 0
        nmax = 0
        addresses = self.get_receiving_addresses()
        k = self.num_unused_trailing_addresses(addresses)
        for a in addresses[0:-k]:
            if self.history.get(a):
                n = 0
            else:
                n += 1
                if n > nmax: nmax = n
        return nmax + 1

    def load_addresses(self):
        super().load_addresses()
        self._addr_to_addr_index = {}  # key: address, value: (is_change, index)
        for i, addr in enumerate(self.receiving_addresses):
            self._addr_to_addr_index[addr] = (False, i)
        for i, addr in enumerate(self.change_addresses):
            self._addr_to_addr_index[addr] = (True, i)
        for i, addr in enumerate(self.encryption_addresses):
            self._addr_to_addr_index[addr] = (True, False, i)

    def create_new_address(self, for_change:bool=False, for_encryption:bool=False):
        with self.lock:
            if for_encryption:
                for_change=False
            if for_change:
                addr_list=self.change_addresses
            elif for_encryption:
                addr_list=self.encryption_addresses
            else:
                addr_list=self.receiving_addresses
            n = len(addr_list)
            x = self.derive_pubkeys(for_change, n, for_encryption)
            if self.contracts:
                x = self.tweak_pubkeys(x, self.contracts[-1])
            address = self.pubkeys_to_address(x)
            addr_list.append(address)
            if for_encryption:
                self._addr_to_addr_index[address] = (for_encryption, for_change, n)
            else:
                self._addr_to_addr_index[address] = (for_change, n)
            self.save_addresses()
            self.add_address(address)
            return address

    def synchronize_sequence(self, for_change, for_encryption=False):
        limit = self.gap_limit_for_change if for_change else self.gap_limit
        while True:
            if for_encryption:
                addresses=self.get_encryption_addresses()
            elif for_change:
                addresses = self.get_change_addresses()
            else:
                addresses = self.get_receiving_addresses()

            if len(addresses) < limit:
                self.create_new_address(for_change, for_encryption)
                continue
            if list(map(lambda a: self.address_is_old(a), addresses[-limit:] )) == limit*[False]:
                break
            else:
                self.create_new_address(for_change, for_encryption)

    def synchronize(self):
        with self.lock:
            self.synchronize_sequence(False)
            self.synchronize_sequence(True)
            self.synchronize_sequence(False, True)

    def is_beyond_limit(self, address):
        is_encryption=False
        r = self.get_address_index(address)
        if len(r) == 2:
            is_change, i = r
        else:
            is_encryption, is_change, i = r
        if is_encryption:
            is_change=False
            addr_list = self.get_encryption_addresses()
        elif is_change:
            addr_list = self.get_change_addresses()
        else:
            addr_list = self.get_receiving_addresses()
        limit = self.gap_limit_for_change if is_change else self.gap_limit
        if i < limit:
            return False
        prev_addresses = addr_list[max(0, i - limit):max(0, i)]
        for addr in prev_addresses:
            if self.history.get(addr):
                return False
        return True

    def get_address_index(self, address):
        return self._addr_to_addr_index[address]

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

    def get_pubkey(self, c, i, for_encryption=False):
        return self.derive_pubkeys(c, i, for_encryption)

    def get_public_key(self, address, tweaked=True):
        r = self.get_address_index(address)
        if len(r) == 3:
            e, c, i = self.get_address_index(address)
        else:
            c, i = self.get_address_index(address)
            e = False

        pubkey = self.get_pubkey(c, i, e)

        if tweaked:
            return self.get_tweaked_public_key(address, pubkey)
        return pubkey

    def load_keystore(self):
        self.keystore = load_keystore(self.storage, 'keystore')
        try:
            xtype = bitcoin.xpub_type(self.keystore.xpub)
        except:
            xtype = 'standard'
        self.txin_type = 'p2pkh' if xtype == 'standard' else xtype

    def add_input_sig_info(self, txin, address):
        derivation = self.get_address_index(address)
        x_pubkey = self.keystore.get_xpubkey(*derivation)
        # Get pubkey derived with the correct contract tweak
        pubkey = self.get_public_key(address)
        txin['pubkeys'] = [pubkey]
        txin['x_pubkeys'] = [x_pubkey]
        txin['signatures'] = [None]
        txin['num_sig'] = 1

    def get_master_public_key(self):
        return self.keystore.get_master_public_key()

    def derive_pubkeys(self, c, i, e=False):
        return self.keystore.derive_pubkey(c, i, e)

    def tweak_pubkeys(self, c, t):
        return self.keystore.tweak_pubkey(c, t)





class Standard_Wallet(Simple_Deterministic_Wallet):
    wallet_type = 'standard'

    def pubkeys_to_address(self, pubkey):
        return bitcoin.pubkey_to_address(self.txin_type, pubkey)

    def get_kyc_string(self, password=None):
        address=self.get_unused_encryption_address()
        if address == None:
            return False, "No wallet encryption keys available."
        onboardUserPubKey=self.get_public_key(address)

        onboardUserKey_serialized, redeem_script=self.export_private_key(address, password)
        txin_type = self.get_txin_type(address)
        txin_type, secret_bytes, compressed = bitcoin.deserialize_privkey(onboardUserKey_serialized)
        onboardUserKey=ecc.ECPrivkey(secret_bytes)
        # onboardUserKey=ecc.ECPrivKey.normalize_secret_bytes(onboardUserKey)

        onboardPubKey=self.get_unassigned_kyc_pubkey()
        if onboardPubKey is None:
            return False, "No unassigned KYC public keys available. Please ensure that the wallet is connected to the network."

        ss = StringIO()

        addrs=self.get_addresses()

        address_pubkey_list = []
        for addr in addrs:
            line="{} {}".format(addr, ''.join(self.get_public_keys(addr, False)))
            address_pubkey_list.append(line)
            ss.write(line)
            ss.write("\n")

        #Encrypt the addresses string
        encrypted = ecc.ECPubkey(bfh(onboardPubKey)).encrypt_message(bytes(ss.getvalue(), 'utf-8'), ephemeral=onboardUserKey)

        ss2 = StringIO()
        str_encrypted=str(encrypted)
        #Remove the b'' characters (first 2 and last characters)
        str_encrypted=str_encrypted[2:]
        str_encrypted=str_encrypted[:-1]
        ss2.write("{} {} {}\n".format(onboardPubKey, ''.join(onboardUserPubKey), str(len(str_encrypted))))
        ss2.write(str_encrypted)
        kyc_string=ss2.getvalue()

        return True, kyc_string

    def dumpkycfile(self, filename=None, password=None):
        kycfile_string = self.get_kyc_string(password)

        if filename:
            f=open(filename, 'w')
            f.write(kycfile_string)
            f.close()
            return True
        return False

    def register_addresses(self, addrs):
        self.set_registered_state(addrs, True)
        self.start_register_address_transaction_builder(addrs)

    def register_address(self, addr):
        self.set_registered_state(addr, True)
        self.start_register_address_transaction_builder(addrs)

class Multisig_Wallet(Deterministic_Wallet):
    # generic m of n
    gap_limit = 100

    def __init__(self, storage):
        self.wallet_type = storage.get('wallet_type')
        self.m, self.n = multisig_type(self.wallet_type)
        Deterministic_Wallet.__init__(self, storage)

    def get_kyc_string(self, password=None):
        address=self.get_unused_encryption_address()
        if address == None:
            return "No wallet encryption keys available."
        onboardUserPubKey=self.get_public_key(address)

        onboardUserKey_serialized, redeem_script = self.export_private_key(address, password, False)   
        txin_type, secret_bytes, compressed = bitcoin.deserialize_privkey(onboardUserKey_serialized)
        onboardUserKey=ecc.ECPrivkey(secret_bytes)
      
        onboardPubKey=self.get_unassigned_kyc_pubkey()
        if onboardPubKey is None:
            return "No unassigned KYC public keys available."

        ss = StringIO()

        addrs=self.get_addresses()

        address_pubkey_list = []
        for addr in addrs:
            line="{} {}".format(self.m, addr)
            untweakedKeys = self.get_public_keys(addr, False)
            tweakedKeys = self.get_tweaked_multi_public_keys(addr, untweakedKeys, self.m, False)
            tweakedKeysSorted = self.get_public_keys(addr, True)
            sortedUntweaked = []
            for i in range(len(tweakedKeysSorted)):
                for j in range(len(tweakedKeys)):
                    if tweakedKeys[j] == tweakedKeysSorted[i]:
                        sortedUntweaked.append(untweakedKeys[j])
                        break
            for pub in sortedUntweaked:
                line+=" {}".format(pub)
            address_pubkey_list.append(line)
            ss.write(line)
            ss.write("\n")

        #Encrypt the addresses string
        encrypted = ecc.ECPubkey(onboardPubKey).encrypt_message(bytes(ss.getvalue(), 'utf-8'), ephemeral=onboardUserKey)

        ss2 = StringIO()
        str_encrypted=str(encrypted)
        #Remove the b'' characters (first 2 and last characters)
        str_encrypted=str_encrypted[2:]
        str_encrypted=str_encrypted[:-1]
        ss2.write("{} {} {}\n".format(bh2u(onboardPubKey), ''.join(onboardUserPubKey), str(len(str_encrypted))))
        ss2.write(str_encrypted)
        kyc_string=ss2.getvalue()

        return kyc_string

    def dumpkycfile(self, filename=None, password=None):
        kycfile_string = self.get_kyc_string(password)

        if filename:
            f=open(filename, 'w')
            f.write(kycfile_string)
            f.close()
            return True
        return False

    def get_public_key(self, address, tweaked=True):
        r = self.get_address_index(address)
        if len(r) == 3:
            e, c, i = self.get_address_index(address)
        else:
            c, i = self.get_address_index(address)
            e = False

        pubkey = self.keystore.derive_pubkey(c, i, e)

        if tweaked:
            return self.get_tweaked_public_key(address, pubkey)
        return pubkey

    def get_pubkeys(self, c, i):
        return self.derive_pubkeys(c, i)

    def get_public_keys(self, address, tweaked=True):
        sequence = self.get_address_index(address)
        pubkeys = self.get_pubkeys(*sequence)
        if tweaked:
            tweaked_pubkeys = self.get_tweaked_multi_public_keys(address, pubkeys, self.m)
            return tweaked_pubkeys
        return pubkeys

    def pubkeys_to_address(self, pubkeys):
        #Case when only a singular pubkey is passed that is not inside a list (encryption) it is a string
        if(len(pubkeys) >= 33):
            return bitcoin.pubkey_to_address('p2pkh', pubkeys)
        else:
            if len(pubkeys) != 1 and self.txin_type == 'p2sh':
                redeem_script = self.pubkeys_to_redeem_script(pubkeys)
                return bitcoin.redeem_script_to_address(self.txin_type, redeem_script)
            #Case when a singular pubkey is passed but it is inside a list (encryption)
            else:
                return bitcoin.pubkey_to_address('p2pkh', pubkeys[0])

    def pubkeys_to_redeem_script(self, pubkeys):
        #Edge case when a single pubkey is passed to create a redeem script(should not theorhetically happen in our wallet)
        if(len(pubkeys) >= 33):
            return multisig_script([pubkeys], self.m)
        return multisig_script(sorted(pubkeys), self.m)

    def get_redeem_script(self, address):
        pubkeys = self.get_public_keys(address)
        redeem_script = self.pubkeys_to_redeem_script(pubkeys)
        return redeem_script

    def derive_pubkeys(self, c, i, e=False):
        if e:  
            return [self.keystore.derive_pubkey(c, i, e)]
        #Not for encryption
        return [k.derive_pubkey(c, i, e) for k in self.get_keystores()]

    def tweak_pubkeys(self, c, t):
        #Only a single pubkey is passed (string)
        if len(c) >= 33 :
            return [self.keystore.tweak_pubkey(c, t)]
        else:
            return [self.keystore.tweak_pubkey(cv, t) for cv in c]

    def load_keystore(self):
        self.keystores = {}
        for i in range(self.n):
            name = 'x%d/'%(i+1)
            self.keystores[name] = load_keystore(self.storage, name)
        self.keystore = self.keystores['x1/']
        xtype = bitcoin.xpub_type(self.keystore.xpub)
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
        return not any([not k.is_watching_only() for k in self.get_keystores()])

    def get_master_public_key(self):
        return self.keystore.get_master_public_key()

    def get_master_public_keys(self):
        return [k.get_master_public_key() for k in self.get_keystores()]

    def get_fingerprint(self):
        return ''.join(sorted(self.get_master_public_keys()))

    def add_input_sig_info(self, txin, address):
        derivation = self.get_address_index(address)
        x_pubkeys_expected = [k.get_xpubkey(*derivation) for k in self.get_keystores()]
        pubkeys = [xpubkey_to_pubkey(x) for x in x_pubkeys_expected]
        pubkeys = self.tweak_pubkeys(pubkeys, self.contracts[-1])
        pubkeys, x_pubkeys_expected = zip(*sorted(zip(pubkeys, x_pubkeys_expected)))
        x_pubkeys_actual = txin.get('x_pubkeys')
        pubkeys_actual =  txin.get('pubkeys')
        # if 'x_pubkeys' is already set correctly (ignoring order, as above), leave it.
        # otherwise we might delete signatures
        if x_pubkeys_actual and pubkeys_actual and set(x_pubkeys_actual) == set(x_pubkeys_expected):
            return
        txin['x_pubkeys'] = list(x_pubkeys_expected)
        txin['pubkeys'] = list(pubkeys)
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

    def __new__(self, storage, contract=None):
         # update contract hash
        storage.update_contracts(contract)

        wallet_type = storage.get('wallet_type')
        WalletClass = Wallet.wallet_class(wallet_type)
        wallet = WalletClass(storage)
        # Convert hardware wallets restored with older versions of
        # Electrum to BIP44 wallets.  A hardware wallet does not have
        # a seed and plugins do not need to handle having one.
        rwc = getattr(wallet, 'restore_wallet_class', None)
        if rwc and storage.get('seed', ''):
            storage.print_error("converting wallet type to " + rwc.wallet_type)
            storage.put('wallet_type', rwc.wallet_type)
            wallet = rwc(storage)
        return wallet

    @staticmethod
    def wallet_class(wallet_type):
        if multisig_type(wallet_type):
            return Multisig_Wallet
        if wallet_type in wallet_constructors:
            return wallet_constructors[wallet_type]
        raise WalletFileException("Unknown wallet type: " + str(wallet_type))
