from binascii import hexlify, unhexlify
import traceback
import sys

from electroncash.util import bfh, bh2u, versiontuple, UserCancelled
from electroncash.bitcoin import (b58_address_to_hash160, xpub_from_pubkey, deserialize_xpub,
                                  TYPE_ADDRESS, TYPE_SCRIPT)
from electroncash.i18n import _
from electroncash.networks import NetworkConstants
from electroncash.plugins import BasePlugin, Device
from electroncash.transaction import deserialize
from electroncash.keystore import Hardware_KeyStore, is_xpubkey, parse_xpubkey
from electroncash.address import ScriptOutput

from ..hw_wallet import HW_PluginBase


# TREZOR initialization methods
TIM_NEW, TIM_RECOVER, TIM_MNEMONIC, TIM_PRIVKEY = range(0, 4)
RECOVERY_TYPE_SCRAMBLED_WORDS, RECOVERY_TYPE_MATRIX = range(0, 2)


class TrezorKeyStore(Hardware_KeyStore):
    hw_type = 'trezor'
    device = 'TREZOR'

    def get_derivation(self):
        return self.derivation

    def get_client(self, force_pair=True):
        return self.plugin.get_client(self, force_pair)

    def decrypt_message(self, sequence, message, password):
        raise RuntimeError(_('Encryption and decryption are not implemented by {}').format(self.device))

    def sign_message(self, sequence, message, password):
        client = self.get_client()
        address_path = self.get_derivation() + "/%d/%d"%sequence
        address_n = client.expand_path(address_path)
        msg_sig = client.sign_message(self.plugin.get_coin_name(), address_n, message)
        return msg_sig.signature

    def sign_transaction(self, tx, password):
        if tx.is_complete():
            return
        # path of the xpubs that are involved
        xpub_path = {}
        for txin in tx.inputs():
            pubkeys, x_pubkeys = tx.get_sorted_pubkeys(txin)
            tx_hash = txin['prevout_hash']
            for x_pubkey in x_pubkeys:
                if not is_xpubkey(x_pubkey):
                    continue
                xpub, s = parse_xpubkey(x_pubkey)
                if xpub == self.get_master_public_key():
                    xpub_path[xpub] = self.get_derivation()

        self.plugin.sign_transaction(self, tx, xpub_path)

    def needs_prevtx(self):
        # Trezor doesn't neeed previous transactions for Bitcoin Cash
        return False


class TrezorPlugin(HW_PluginBase):
    firmware_URL = 'https://wallet.trezor.io'
    libraries_URL = 'https://github.com/trezor/python-trezor'
    minimum_firmware = (1, 5, 2)
    keystore_class = TrezorKeyStore
    minimum_library = (0, 9, 0)

    MAX_LABEL_LEN = 32

    def __init__(self, parent, config, name):
        HW_PluginBase.__init__(self, parent, config, name)

        try:
            # Minimal test if python-trezor is installed
            import trezorlib
            try:
                library_version = trezorlib.__version__
            except AttributeError:
                # python-trezor only introduced __version__ in 0.9.0
                library_version = 'unknown'
            if library_version == 'unknown' or \
                    versiontuple(library_version) < self.minimum_library:
                self.libraries_available_message = (
                        _("Library version for '{}' is too old.").format(name)
                        + '\nInstalled: {}, Needed: {}'
                        .format(library_version, self.minimum_library))
                self.print_stderr(self.libraries_available_message)
                raise ImportError()
            self.libraries_available = True
        except ImportError:
            self.libraries_available = False
            return

        from . import client
        from . import transport
        import trezorlib.messages
        self.client_class = client.TrezorClient
        self.types = trezorlib.messages
        self.DEVICE_IDS = ('TREZOR',)

        self.transport_handler = transport.TrezorTransport()
        self.device_manager().register_enumerate_func(self.enumerate)

    def enumerate(self):
        devices = self.transport_handler.enumerate_devices()
        return [Device(d.get_path(), -1, d.get_path(), 'TREZOR', 0) for d in devices]

    def create_client(self, device, handler):
        try:
            self.print_error("connecting to device at", device.path)
            transport = self.transport_handler.get_transport(device.path)
        except BaseException as e:
            self.print_error("cannot connect at", device.path, str(e))
            return None

        if not transport:
            self.print_error("cannot connect at", device.path)
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
            msg = (_('Outdated {} firmware for device labelled {}. Please '
                     'download the updated firmware from {}')
                   .format(self.device, client.label(), self.firmware_URL))
            self.print_error(msg)
            handler.show_error(msg)
            return None

        return client

    def get_client(self, keystore, force_pair=True):
        devmgr = self.device_manager()
        handler = keystore.handler
        with devmgr.hid_lock:
            client = devmgr.client_for_keystore(self, handler, keystore, force_pair)
        # returns the client for a given keystore. can use xpub
        if client:
            client.used()
        return client

    def get_coin_name(self):
        # Note: testnet supported only by unofficial firmware
        return "Bcash Testnet" if NetworkConstants.TESTNET else "Bcash"

    def initialize_device(self, device_id, wizard, handler):
        # Initialization method
        msg = _("Choose how you want to initialize your {}.\n\n"
                "The first two methods are secure as no secret information "
                "is entered into your computer.\n\n"
                "For the last two methods you input secrets on your keyboard "
                "and upload them to your {}, and so you should "
                "only do those on a computer you know to be trustworthy "
                "and free of malware."
        ).format(self.device, self.device)
        choices = [
            # Must be short as QT doesn't word-wrap radio button text
            (TIM_NEW, _("Let the device generate a completely new seed randomly")),
            (TIM_RECOVER, _("Recover from a seed you have previously written down")),
            (TIM_MNEMONIC, _("Upload a BIP39 mnemonic to generate the seed")),
            (TIM_PRIVKEY, _("Upload a master private key"))
        ]
        devmgr = self.device_manager()
        client = devmgr.client_by_id(device_id)
        model = client.get_trezor_model()
        def f(method):
            import threading
            settings = self.request_trezor_init_settings(wizard, method, model)
            t = threading.Thread(target=self._initialize_device_safe, args=(settings, method, device_id, wizard, handler))
            t.setDaemon(True)
            t.start()
            exit_code = wizard.loop.exec_()
            if exit_code != 0:
                # this method (initialize_device) was called with the expectation
                # of leaving the device in an initialized state when finishing.
                # signal that this is not the case:
                raise UserCancelled()
        wizard.choice_dialog(title=_('Initialize Device'), message=msg, choices=choices, run_next=f)

    def _initialize_device_safe(self, settings, method, device_id, wizard, handler):
        exit_code = 0
        try:
            self._initialize_device(settings, method, device_id, wizard, handler)
        except UserCancelled:
            exit_code = 1
        except BaseException as e:
            traceback.print_exc(file=sys.stderr)
            handler.show_error(str(e))
            exit_code = 1
        finally:
            wizard.loop.exit(exit_code)

    def _initialize_device(self, settings, method, device_id, wizard, handler):
        item, label, pin_protection, passphrase_protection, recovery_type = settings

        if method == TIM_RECOVER and recovery_type == RECOVERY_TYPE_SCRAMBLED_WORDS:
            handler.show_warning(_(
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
            u2f_counter = 0
            skip_backup = False
            client.reset_device(True, strength, passphrase_protection,
                                pin_protection, label, language,
                                u2f_counter, skip_backup)
        elif method == TIM_RECOVER:
            word_count = 6 * (item + 2)  # 12, 18 or 24
            client.step = 0
            if recovery_type == RECOVERY_TYPE_SCRAMBLED_WORDS:
                recovery_type_trezor = self.types.RecoveryDeviceType.ScrambledWords
            else:
                recovery_type_trezor = self.types.RecoveryDeviceType.Matrix
            client.recovery_device(word_count, passphrase_protection,
                                   pin_protection, label, language,
                                   type=recovery_type_trezor)
            if recovery_type == RECOVERY_TYPE_MATRIX:
                handler.close_matrix_dialog()
        elif method == TIM_MNEMONIC:
            pin = pin_protection  # It's the pin, not a boolean
            client.load_device_by_mnemonic(str(item), pin,
                                           passphrase_protection,
                                           label, language)
        else:
            pin = pin_protection  # It's the pin, not a boolean
            client.load_device_by_xprv(item, pin, passphrase_protection,
                                       label, language)

    def _make_node_path(self, xpub, address_n):
        _, depth, fingerprint, child_num, chain_code, key = deserialize_xpub(xpub)
        node = self.types.HDNodeType(
            depth=depth,
            fingerprint=int.from_bytes(fingerprint, 'big'),
            child_num=int.from_bytes(child_num, 'big'),
            chain_code=chain_code,
            public_key=key,
        )
        return self.types.HDNodePathType(node=node, address_n=address_n)

    def setup_device(self, device_info, wizard):
        '''Called when creating a new wallet.  Select the device to use.  If
        the device is uninitialized, go through the intialization
        process.'''
        devmgr = self.device_manager()
        device_id = device_info.device.id_
        client = devmgr.client_by_id(device_id)
        if client is None:
            raise Exception(_('Failed to create a client for this device.') + '\n' +
                            _('Make sure it is in the correct state.'))
        # fixme: we should use: client.handler = wizard
        client.handler = self.create_handler(wizard)
        if not device_info.initialized:
            self.initialize_device(device_id, wizard, client.handler)
        client.get_xpub('m', 'standard')
        client.used()

    def get_xpub(self, device_id, derivation, xtype, wizard):
        devmgr = self.device_manager()
        client = devmgr.client_by_id(device_id)
        client.handler = wizard
        xpub = client.get_xpub(derivation, xtype)
        client.used()
        return xpub

    def get_trezor_input_script_type(self, is_multisig):
        if is_multisig:
            return self.types.InputScriptType.SPENDMULTISIG
        else:
            return self.types.InputScriptType.SPENDADDRESS

    def sign_transaction(self, keystore, tx, xpub_path):
        self.xpub_path = xpub_path
        client = self.get_client(keystore)
        inputs = self.tx_inputs(tx, True)
        outputs = self.tx_outputs(keystore.get_derivation(), tx, client)
        signed_tx = client.sign_tx(self.get_coin_name(), inputs, outputs, lock_time=tx.locktime)[1]
        raw = bh2u(signed_tx)
        tx.update_signatures(raw)

    def show_address(self, wallet, address, keystore=None):
        if keystore is None:
            keystore = wallet.get_keystore()
        client = self.get_client(keystore)
        if not client.atleast_version(1, 3):
            keystore.handler.show_error(_("Your device firmware is too old"))
            return
        change, index = wallet.get_address_index(address)
        derivation = keystore.derivation
        address_path = "%s/%d/%d"%(derivation, change, index)
        address_n = client.expand_path(address_path)
        xpubs = wallet.get_master_public_keys()
        if len(xpubs) == 1:
            script_type = self.get_trezor_input_script_type(is_multisig=False)
            client.get_address(self.get_coin_name(), address_n, True, script_type=script_type)
        else:
            def f(xpub):
                return self._make_node_path(xpub, [change, index])
            pubkeys = wallet.get_public_keys(address)
            # sort xpubs using the order of pubkeys
            sorted_pubkeys, sorted_xpubs = zip(*sorted(zip(pubkeys, xpubs)))
            pubkeys = list(map(f, sorted_xpubs))
            multisig = self.types.MultisigRedeemScriptType(
               pubkeys=pubkeys,
               signatures=[b''] * wallet.n,
               m=wallet.m,
            )
            script_type = self.get_trezor_input_script_type(is_multisig=True)
            client.get_address(self.get_coin_name(), address_n, True, multisig=multisig, script_type=script_type)

    def tx_inputs(self, tx, for_sig=False):
        inputs = []
        for txin in tx.inputs():
            txinputtype = self.types.TxInputType()
            if txin['type'] == 'coinbase':
                prev_hash = "\0"*32
                prev_index = 0xffffffff  # signed int -1
            else:
                if for_sig:
                    x_pubkeys = txin['x_pubkeys']
                    if len(x_pubkeys) == 1:
                        x_pubkey = x_pubkeys[0]
                        xpub, s = parse_xpubkey(x_pubkey)
                        xpub_n = self.client_class.expand_path(self.xpub_path[xpub])
                        txinputtype._extend_address_n(xpub_n + s)
                        txinputtype.script_type = self.get_trezor_input_script_type(is_multisig=False)
                    else:
                        def f(x_pubkey):
                            if is_xpubkey(x_pubkey):
                                xpub, s = parse_xpubkey(x_pubkey)
                            else:
                                xpub = xpub_from_pubkey('standard', bfh(x_pubkey))
                                s = []
                            return self._make_node_path(xpub, s)
                        pubkeys = list(map(f, x_pubkeys))
                        multisig = self.types.MultisigRedeemScriptType(
                            pubkeys=pubkeys,
                            signatures=list(map(lambda x: bfh(x)[:-1] if x else b'', txin.get('signatures'))),
                            m=txin.get('num_sig'),
                        )
                        script_type = self.get_trezor_input_script_type(is_multisig=True)
                        txinputtype = self.types.TxInputType(
                            script_type=script_type,
                            multisig=multisig
                        )
                        # find which key is mine
                        for x_pubkey in x_pubkeys:
                            if is_xpubkey(x_pubkey):
                                xpub, s = parse_xpubkey(x_pubkey)
                                if xpub in self.xpub_path:
                                    xpub_n = self.client_class.expand_path(self.xpub_path[xpub])
                                    txinputtype._extend_address_n(xpub_n + s)
                                    break

                prev_hash = unhexlify(txin['prevout_hash'])
                prev_index = txin['prevout_n']

            if 'value' in txin:
                txinputtype.amount = txin['value']
            txinputtype.prev_hash = prev_hash
            txinputtype.prev_index = prev_index

            if 'scriptSig' in txin:
                script_sig = bfh(txin['scriptSig'])
                txinputtype.script_sig = script_sig

            txinputtype.sequence = txin.get('sequence', 0xffffffff - 1)

            inputs.append(txinputtype)

        return inputs

    def tx_outputs(self, derivation, tx, client):

        def create_output_by_derivation(info):
            index, xpubs, m = info
            if len(xpubs) == 1:
                script_type = self.types.OutputScriptType.PAYTOADDRESS
                address_n = self.client_class.expand_path(derivation + "/%d/%d" % index)
                txoutputtype = self.types.TxOutputType(
                    amount=amount,
                    script_type=script_type,
                    address_n=address_n,
                )
            else:
                script_type = self.types.OutputScriptType.PAYTOMULTISIG
                address_n = self.client_class.expand_path("/%d/%d" % index)
                pubkeys = [self._make_node_path(xpub, address_n) for xpub in xpubs]
                multisig = self.types.MultisigRedeemScriptType(
                    pubkeys=pubkeys,
                    signatures=[b''] * len(pubkeys),
                    m=m)
                txoutputtype = self.types.TxOutputType(
                    multisig=multisig,
                    amount=amount,
                    address_n=self.client_class.expand_path(derivation + "/%d/%d" % index),
                    script_type=script_type)
            return txoutputtype

        def create_output_by_address():
            txoutputtype = self.types.TxOutputType()
            txoutputtype.amount = amount
            if _type == TYPE_SCRIPT:
                script = address.to_script()
                # We only support OP_RETURN with one constant push
                if (script[0] == 0x6a and amount == 0 and
                    script[1] == len(script) - 2 and
                    script[1] <= 75):
                    txoutputtype.script_type = self.types.OutputScriptType.PAYTOOPRETURN
                    txoutputtype.op_return_data = script[2:]
                else:
                    raise Exception(_("Unsupported output script."))
            elif _type == TYPE_ADDRESS:
                txoutputtype.script_type = self.types.OutputScriptType.PAYTOADDRESS
                addr_format = address.FMT_LEGACY
                if client.get_trezor_model() == 'T':
                    if client.atleast_version(2, 0, 8):
                        addr_format = address.FMT_UI
                    elif client.atleast_version(2, 0, 7):
                        addr_format = address.FMT_CASHADDR
                else:
                    if client.atleast_version(1, 6, 2):
                        addr_format = address.FMT_UI
                txoutputtype.address = address.to_full_string(addr_format)
            return txoutputtype

        outputs = []
        has_change = False

        for _type, address, amount in tx.outputs():
            info = tx.output_info.get(address)
            if info is not None and not has_change:
                has_change = True # no more than one change address
                txoutputtype = create_output_by_derivation(info)
            else:
                txoutputtype = create_output_by_address()
            outputs.append(txoutputtype)

        return outputs

    # This function is called from the TREZOR libraries (via tx_api)
    def get_tx(self, tx_hash):
        # for electron-cash previous tx is never needed, since it uses
        # bip-143 signatures.
        return None
