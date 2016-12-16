import base64
import re
import threading

from binascii import hexlify, unhexlify
from functools import partial

from electrum.bitcoin import (bc_address_to_hash_160, xpub_from_pubkey,
                              public_key_to_bc_address, EncodeBase58Check,
                              TYPE_ADDRESS, TYPE_SCRIPT)
from electrum.i18n import _
from electrum.plugins import BasePlugin, hook
from electrum.transaction import deserialize, Transaction
from electrum.keystore import Hardware_KeyStore, is_xpubkey, parse_xpubkey

from ..hw_wallet import HW_PluginBase


# TREZOR initialization methods
TIM_NEW, TIM_RECOVER, TIM_MNEMONIC, TIM_PRIVKEY = range(0, 4)

class TrezorCompatibleKeyStore(Hardware_KeyStore):

    def get_derivation(self):
        return self.derivation

    def get_client(self, force_pair=True):
        return self.plugin.get_client(self, force_pair)

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
                if not is_xpubkey(x_pubkey):
                    continue
                xpub, s = parse_xpubkey(x_pubkey)
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
        # disable bridge because it seems to never returns if keepkey is plugged
        #transport = self._try_bridge(device) or self._try_hid(device)
        transport = self._try_hid(device)
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
            self.print_error(msg)
            handler.show_error(msg)
            return None

        return client

    def get_client(self, keystore, force_pair=True):
        # All client interaction should not be in the main GUI thread
        assert self.main_thread != threading.current_thread()
        devmgr = self.device_manager()
        handler = keystore.handler
        with devmgr.hid_lock:
            client = devmgr.client_for_keystore(self, handler, keystore, force_pair)
        # returns the client for a given keystore. can use xpub
        if client:
            client.used()
        return client

    def initialize_device(self, device_id, wizard, handler):
        # Initialization method
        msg = _("Choose how you want to initialize your %s.\n\n"
                "The first two methods are secure as no secret information "
                "is entered into your computer.\n\n"
                "For the last two methods you input secrets on your keyboard "
                "and upload them to your %s, and so you should "
                "only do those on a computer you know to be trustworthy "
                "and free of malware."
        ) % (self.device, self.device)
        choices = [
            # Must be short as QT doesn't word-wrap radio button text
            (TIM_NEW, _("Let the device generate a completely new seed randomly")),
            (TIM_RECOVER, _("Recover from a seed you have previously written down")),
            (TIM_MNEMONIC, _("Upload a BIP39 mnemonic to generate the seed")),
            (TIM_PRIVKEY, _("Upload a master private key"))
        ]
        def f(method):
            import threading
            settings = self.request_trezor_init_settings(wizard, method, self.device)
            t = threading.Thread(target = self._initialize_device, args=(settings, method, device_id, wizard, handler))
            t.setDaemon(True)
            t.start()
            wizard.loop.exec_()
        wizard.choice_dialog(title=_('Initialize Device'), message=msg, choices=choices, run_next=f)

    def _initialize_device(self, settings, method, device_id, wizard, handler):
        item, label, pin_protection, passphrase_protection = settings

        if method == TIM_RECOVER and self.device == 'TREZOR':
            # Warn user about firmware lameness
            handler.show_error(_(
                "You will be asked to enter 24 words regardless of your "
                "seed's actual length.  If you enter a word incorrectly or "
                "misspell it, you cannot change it or go back - you will need "
                "to start again from the beginning.\n\nSo please enter "
                "the words carefully!"))

        language = 'english'
        devmgr = self.device_manager()
        client = devmgr.client_by_id(device_id)

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
        wizard.loop.exit(0)

    def setup_device(self, device_info, wizard):
        '''Called when creating a new wallet.  Select the device to use.  If
        the device is uninitialized, go through the intialization
        process.'''
        devmgr = self.device_manager()
        device_id = device_info.device.id_
        client = devmgr.client_by_id(device_id)
        # fixme: we should use: client.handler = wizard
        client.handler = self.create_handler(wizard)
        if not device_info.initialized:
            self.initialize_device(device_id, wizard, client.handler)
        client.get_xpub('m')
        client.used()

    def get_xpub(self, device_id, derivation, wizard):
        devmgr = self.device_manager()
        client = devmgr.client_by_id(device_id)
        client.handler = wizard
        xpub = client.get_xpub(derivation)
        client.used()
        return xpub

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
            keystore.handler.show_error(_("Your device firmware is too old"))
            return
        change, index = wallet.get_address_index(address)
        derivation = wallet.keystore.derivation
        address_path = "%s/%d/%d"%(derivation, change, index)
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
                        xpub, s = parse_xpubkey(x_pubkey)
                        xpub_n = self.client_class.expand_path(self.xpub_path[xpub])
                        txinputtype.address_n.extend(xpub_n + s)
                    else:
                        def f(x_pubkey):
                            if is_xpubkey(x_pubkey):
                                xpub, s = parse_xpubkey(x_pubkey)
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
                            if is_xpubkey(x_pubkey):
                                xpub, s = parse_xpubkey(x_pubkey)
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
        has_change = False

        for _type, address, amount in tx.outputs():
            info = tx.output_info.get(address)
            if info is not None and not has_change:
                has_change = True # no more than one change address
                addrtype, hash_160 = bc_address_to_hash_160(address)
                index, xpubs, m = info
                if addrtype == 0:
                    address_n = self.client_class.expand_path(derivation + "/%d/%d"%index)
                    txoutputtype = self.types.TxOutputType(
                        amount = amount,
                        script_type = self.types.PAYTOADDRESS,
                        address_n = address_n,
                    )
                elif addrtype == 5:
                    address_n = self.client_class.expand_path("/%d/%d"%index)
                    nodes = map(self.ckd_public.deserialize, xpubs)
                    pubkeys = [ self.types.HDNodePathType(node=node, address_n=address_n) for node in nodes]
                    multisig = self.types.MultisigRedeemScriptType(
                        pubkeys = pubkeys,
                        signatures = [b''] * len(pubkeys),
                        m = m)
                    txoutputtype = self.types.TxOutputType(
                        multisig = multisig,
                        amount = amount,
                        script_type = self.types.PAYTOMULTISIG)
            else:
                txoutputtype = self.types.TxOutputType()
                txoutputtype.amount = amount
                if _type == TYPE_SCRIPT:
                    txoutputtype.script_type = self.types.PAYTOOPRETURN
                    txoutputtype.op_return_data = address[2:]
                elif _type == TYPE_ADDRESS:
                    addrtype, hash_160 = bc_address_to_hash_160(address)
                    if addrtype == 0:
                        txoutputtype.script_type = self.types.PAYTOADDRESS
                    elif addrtype == 5:
                        txoutputtype.script_type = self.types.PAYTOSCRIPTHASH
                    else:
                        raise BaseException('addrtype')
                    txoutputtype.address = address

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
