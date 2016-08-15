import base64
import re
import threading

from binascii import hexlify, unhexlify
from functools import partial

from electrum.account import BIP32_Account
from electrum.bitcoin import (bc_address_to_hash_160, xpub_from_pubkey,
                              public_key_to_bc_address, EncodeBase58Check,
                              TYPE_ADDRESS, TYPE_SCRIPT)
from electrum.i18n import _
from electrum.plugins import BasePlugin, hook
from electrum.transaction import (deserialize, is_extended_pubkey,
                                  Transaction, x_to_xpub)
from electrum.keystore import Hardware_KeyStore

from ..hw_wallet import HW_PluginBase


# TREZOR initialization methods
TIM_NEW, TIM_RECOVER, TIM_MNEMONIC, TIM_PRIVKEY = range(0, 4)

class TrezorCompatibleKeyStore(Hardware_KeyStore):

    def load(self, storage, name):
        self.xpub = storage.get('master_public_keys', {}).get(name)
        self.account_id = storage.get('account_id')

    def get_derivation(self):
        return "m/44'/0'/%d'"%self.account_id

    def get_client(self, force_pair=True):
        return self.plugin.get_client(self, force_pair)

    def init_xpub(self):
        client = self.get_client()
        self.xpub = client.get_xpub(self.get_derivation())

    def decrypt_message(self, pubkey, message, password):
        raise RuntimeError(_('Electrum and %s encryption and decryption are currently incompatible') % self.device)
        address = public_key_to_bc_address(pubkey.decode('hex'))
        client = self.get_client()
        address_path = self.address_id(address)
        address_n = client.expand_path(address_path)
        payload = base64.b64decode(message)
        nonce, message, msg_hmac = payload[:33], payload[33:-8], payload[-8:]
        result = client.decrypt_message(address_n, nonce, message, msg_hmac)
        return result.message

    def sign_message(self, sequence, message, password):
        client = self.get_client()
        address_path = self.get_derivation() + "/%d/%d"%sequence
        address_n = client.expand_path(address_path)
        msg_sig = client.sign_message('Bitcoin', address_n, message)
        return msg_sig.signature

    def sign_transaction(self, tx, password):
        if tx.is_complete():
            return
        # previous transactions used as inputs
        prev_tx = {}
        # path of the xpubs that are involved
        xpub_path = {}
        for txin in tx.inputs():
            tx_hash = txin['prevout_hash']
            prev_tx[tx_hash] = txin['prev_tx'] 
            for x_pubkey in txin['x_pubkeys']:
                if not is_extended_pubkey(x_pubkey):
                    continue
                xpub = x_to_xpub(x_pubkey)
                if xpub == self.get_master_public_key():
                    xpub_path[xpub] = self.get_derivation()

        self.plugin.sign_transaction(self, tx, prev_tx, xpub_path)


class TrezorCompatiblePlugin(HW_PluginBase):
    # Derived classes provide:
    #
    #  class-static variables: client_class, firmware_URL, handler_class,
    #     libraries_available, libraries_URL, minimum_firmware,
    #     wallet_class, ckd_public, types, HidTransport

    MAX_LABEL_LEN = 32

    def __init__(self, parent, config, name):
        HW_PluginBase.__init__(self, parent, config, name)
        self.main_thread = threading.current_thread()
        # FIXME: move to base class when Ledger is fixed
        if self.libraries_available:
            self.device_manager().register_devices(self.DEVICE_IDS)

    def _try_hid(self, device):
        self.print_error("Trying to connect over USB...")
        if device.interface_number == 1:
            pair = [None, device.path]
        else:
            pair = [device.path, None]

        try:
            return self.hid_transport(pair)
        except BaseException as e:
            raise
            self.print_error("cannot connect at", device.path, str(e))
            return None
 
    def _try_bridge(self, device):
        self.print_error("Trying to connect over Trezor Bridge...")

        try:
            return self.bridge_transport({'path': hexlify(device.path)})
        except BaseException as e:
            self.print_error("cannot connect to bridge", str(e))
            return None

    def create_client(self, device, handler):
        transport = self._try_bridge(device) or self._try_hid(device)
        if not transport:
            self.print_error("cannot connect to device")
            return

        self.print_error("connected to device at", device.path)

        client = self.client_class(transport, handler, self)

        # Try a ping for device sanity
        try:
            client.ping('t')
        except BaseException as e:
            self.print_error("ping failed", str(e))
            return None

        if not client.atleast_version(*self.minimum_firmware):
            msg = (_('Outdated %s firmware for device labelled %s. Please '
                     'download the updated firmware from %s') %
                   (self.device, client.label(), self.firmware_URL))
            handler.show_error(msg)
            return None

        return client

    def get_client(self, keystore, force_pair=True):
        # All client interaction should not be in the main GUI thread
        assert self.main_thread != threading.current_thread()
        devmgr = self.device_manager()
        client = devmgr.client_for_keystore(self, keystore, force_pair)
        if client:
            client.used()
        return client

    def initialize_device(self, keystore):
        # Initialization method
        msg = _("Choose how you want to initialize your %s.\n\n"
                "The first two methods are secure as no secret information "
                "is entered into your computer.\n\n"
                "For the last two methods you input secrets on your keyboard "
                "and upload them to your %s, and so you should "
                "only do those on a computer you know to be trustworthy "
                "and free of malware."
        ) % (self.device, self.device)

        methods = [
            # Must be short as QT doesn't word-wrap radio button text
            _("Let the device generate a completely new seed randomly"),
            _("Recover from a seed you have previously written down"),
            _("Upload a BIP39 mnemonic to generate the seed"),
            _("Upload a master private key")
        ]

        method = keystore.handler.query_choice(msg, methods)
        (item, label, pin_protection, passphrase_protection) \
            = wallet.handler.request_trezor_init_settings(method, self.device)

        if method == TIM_RECOVER and self.device == 'TREZOR':
            # Warn user about firmware lameness
            keystore.handler.show_error(_(
                "You will be asked to enter 24 words regardless of your "
                "seed's actual length.  If you enter a word incorrectly or "
                "misspell it, you cannot change it or go back - you will need "
                "to start again from the beginning.\n\nSo please enter "
                "the words carefully!"))

        language = 'english'

        def initialize_method():
            client = self.get_client(keystore)

            if method == TIM_NEW:
                strength = 64 * (item + 2)  # 128, 192 or 256
                client.reset_device(True, strength, passphrase_protection,
                                    pin_protection, label, language)
            elif method == TIM_RECOVER:
                word_count = 6 * (item + 2)  # 12, 18 or 24
                client.step = 0
                client.recovery_device(word_count, passphrase_protection,
                                       pin_protection, label, language)
            elif method == TIM_MNEMONIC:
                pin = pin_protection  # It's the pin, not a boolean
                client.load_device_by_mnemonic(str(item), pin,
                                               passphrase_protection,
                                               label, language)
            else:
                pin = pin_protection  # It's the pin, not a boolean
                client.load_device_by_xprv(item, pin, passphrase_protection,
                                           label, language)
            # After successful initialization create accounts
            keystore.init_xpub()
            #wallet.create_main_account()

        return initialize_method

    def setup_device(self, keystore, on_done, on_error):
        '''Called when creating a new wallet.  Select the device to use.  If
        the device is uninitialized, go through the intialization
        process.  Then create the wallet accounts.'''
        devmgr = self.device_manager()
        device_info = devmgr.select_device(keystore, self)
        devmgr.pair_wallet(keystore, device_info.device.id_)
        if device_info.initialized:
            task = keystore.init_xpub
        else:
            task = self.initialize_device(keystore)
        keystore.thread.add(task, on_done=on_done, on_error=on_error)

    def sign_transaction(self, keystore, tx, prev_tx, xpub_path):
        self.prev_tx = prev_tx
        self.xpub_path = xpub_path
        client = self.get_client(keystore)
        inputs = self.tx_inputs(tx, True)
        outputs = self.tx_outputs(keystore.get_derivation(), tx)
        signed_tx = client.sign_tx('Bitcoin', inputs, outputs)[1]
        raw = signed_tx.encode('hex')
        tx.update_signatures(raw)

    def show_address(self, wallet, address):
        client = self.get_client(wallet.keystore)
        if not client.atleast_version(1, 3):
            wallet.handler.show_error(_("Your device firmware is too old"))
            return
        address_path = wallet.address_id(address)
        address_n = client.expand_path(address_path)
        client.get_address('Bitcoin', address_n, True)

    def tx_inputs(self, tx, for_sig=False):
        inputs = []
        for txin in tx.inputs():
            txinputtype = self.types.TxInputType()
            if txin.get('is_coinbase'):
                prev_hash = "\0"*32
                prev_index = 0xffffffff  # signed int -1
            else:
                if for_sig:
                    x_pubkeys = txin['x_pubkeys']
                    if len(x_pubkeys) == 1:
                        x_pubkey = x_pubkeys[0]
                        xpub, s = BIP32_Account.parse_xpubkey(x_pubkey)
                        xpub_n = self.client_class.expand_path(self.xpub_path[xpub])
                        txinputtype.address_n.extend(xpub_n + s)
                    else:
                        def f(x_pubkey):
                            if is_extended_pubkey(x_pubkey):
                                xpub, s = BIP32_Account.parse_xpubkey(x_pubkey)
                            else:
                                xpub = xpub_from_pubkey(x_pubkey.decode('hex'))
                                s = []
                            node = self.ckd_public.deserialize(xpub)
                            return self.types.HDNodePathType(node=node, address_n=s)
                        pubkeys = map(f, x_pubkeys)
                        multisig = self.types.MultisigRedeemScriptType(
                            pubkeys=pubkeys,
                            signatures=map(lambda x: x.decode('hex') if x else '', txin.get('signatures')),
                            m=txin.get('num_sig'),
                        )
                        txinputtype = self.types.TxInputType(
                            script_type=self.types.SPENDMULTISIG,
                            multisig=multisig
                        )
                        # find which key is mine
                        for x_pubkey in x_pubkeys:
                            if is_extended_pubkey(x_pubkey):
                                xpub, s = BIP32_Account.parse_xpubkey(x_pubkey)
                                if xpub in self.xpub_path:
                                    xpub_n = self.client_class.expand_path(self.xpub_path[xpub])
                                    txinputtype.address_n.extend(xpub_n + s)
                                    break

                prev_hash = unhexlify(txin['prevout_hash'])
                prev_index = txin['prevout_n']

            txinputtype.prev_hash = prev_hash
            txinputtype.prev_index = prev_index

            if 'scriptSig' in txin:
                script_sig = txin['scriptSig'].decode('hex')
                txinputtype.script_sig = script_sig

            if 'sequence' in txin:
                sequence = txin['sequence']
                txinputtype.sequence = sequence

            inputs.append(txinputtype)

        return inputs

    def tx_outputs(self, derivation, tx):
        outputs = []
        for i, (_type, address, amount) in enumerate(tx.outputs()):
            txoutputtype = self.types.TxOutputType()
            txoutputtype.amount = amount
            change, index = tx.output_info[i]
            if _type == TYPE_SCRIPT:
                txoutputtype.script_type = self.types.PAYTOOPRETURN
                txoutputtype.op_return_data = address[2:]
            elif _type == TYPE_ADDRESS:
                if change is not None:
                    address_path = "%s/%d/%d"%(derivation, change, index)
                    address_n = self.client_class.expand_path(address_path)
                    txoutputtype.address_n.extend(address_n)
                else:
                    txoutputtype.address = address
                addrtype, hash_160 = bc_address_to_hash_160(address)
                if addrtype == 0:
                    txoutputtype.script_type = self.types.PAYTOADDRESS
                elif addrtype == 5:
                    txoutputtype.script_type = self.types.PAYTOSCRIPTHASH
                else:
                    raise BaseException('addrtype')
            else:
                raise BaseException('addrtype')
            outputs.append(txoutputtype)

        return outputs

    def electrum_tx_to_txtype(self, tx):
        t = self.types.TransactionType()
        d = deserialize(tx.raw)
        t.version = d['version']
        t.lock_time = d['lockTime']
        inputs = self.tx_inputs(tx)
        t.inputs.extend(inputs)
        for vout in d['outputs']:
            o = t.bin_outputs.add()
            o.amount = vout['value']
            o.script_pubkey = vout['scriptPubKey'].decode('hex')
        return t

    # This function is called from the trezor libraries (via tx_api)
    def get_tx(self, tx_hash):
        tx = self.prev_tx[tx_hash]
        return self.electrum_tx_to_txtype(tx)

    @staticmethod
    def is_valid_seed(seed):
        return True
