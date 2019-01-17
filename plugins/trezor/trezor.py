from binascii import hexlify, unhexlify
from collections import defaultdict
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


try:
    import trezorlib
    import trezorlib.transport

    from .clientbase import (TrezorClientBase, parse_path)

    from trezorlib.messages import (
        RecoveryDeviceType, HDNodeType, HDNodePathType,
        InputScriptType, OutputScriptType, MultisigRedeemScriptType,
        TxInputType, TxOutputType, TxOutputBinType, TransactionType, SignTx)

    RECOVERY_TYPE_SCRAMBLED_WORDS = RecoveryDeviceType.ScrambledWords
    RECOVERY_TYPE_MATRIX = RecoveryDeviceType.Matrix

    TREZORLIB = True
except Exception as e:
    import traceback
    traceback.print_exc()
    TREZORLIB = False

    RECOVERY_TYPE_SCRAMBLED_WORDS, RECOVERY_TYPE_MATRIX = range(2)


# TREZOR initialization methods
TIM_NEW, TIM_RECOVER = range(2)

TREZOR_PRODUCT_KEY = 'Trezor'


class TrezorKeyStore(Hardware_KeyStore):
    hw_type = 'trezor'
    device = TREZOR_PRODUCT_KEY

    def get_derivation(self):
        return self.derivation

    def get_client(self, force_pair=True):
        return self.plugin.get_client(self, force_pair)

    def decrypt_message(self, sequence, message, password):
        raise RuntimeError(_('Encryption and decryption are not implemented by {}').format(self.device))

    def sign_message(self, sequence, message, password):
        client = self.get_client()
        address_path = self.get_derivation() + "/%d/%d"%sequence
        msg_sig = client.sign_message(address_path, message)
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


class LibraryFoundButUnusable(Exception):
    def __init__(self, library_version='unknown'):
        self.library_version = library_version


class TrezorPlugin(HW_PluginBase):
    # Derived classes provide:
    #
    #  class-static variables: client_class, firmware_URL, handler_class,
    #     libraries_available, libraries_URL, minimum_firmware,
    #     wallet_class, types

    firmware_URL = 'https://wallet.trezor.io'
    libraries_URL = 'https://github.com/trezor/python-trezor'
    minimum_firmware = (1, 5, 2)
    keystore_class = TrezorKeyStore
    minimum_library = (0, 11, 0)
    maximum_library = (0, 12)

    DEVICE_IDS = (TREZOR_PRODUCT_KEY,)

    MAX_LABEL_LEN = 32

    def __init__(self, parent, config, name):
        super().__init__(parent, config, name)

        self.libraries_available = self.check_libraries_available()
        if not self.libraries_available:
            return
        self.device_manager().register_enumerate_func(self.enumerate)

    def check_libraries_available(self) -> bool:
        def version_str(t):
            return ".".join(str(i) for i in t)

        try:
            # this might raise ImportError or LibraryFoundButUnusable
            library_version = self.get_library_version()
            # if no exception so far, we might still raise LibraryFoundButUnusable
            if (library_version == 'unknown'
                    or versiontuple(library_version) < self.minimum_library
                    or hasattr(self, "maximum_library") and versiontuple(library_version) >= self.maximum_library):
                raise LibraryFoundButUnusable(library_version=library_version)
        except ImportError:
            return False
        except LibraryFoundButUnusable as e:
            library_version = e.library_version
            max_version_str = version_str(self.maximum_library) if hasattr(self, "maximum_library") else "inf"
            self.libraries_available_message = (
                    _("Library version for '{}' is incompatible.").format(self.name)
                    + '\nInstalled: {}, Needed: {} <= x < {}'
                    .format(library_version, version_str(self.minimum_library), max_version_str))
            self.print_stderr(self.libraries_available_message)
            return False

        return True

    def get_library_version(self):
        import trezorlib
        try:
            version = trezorlib.__version__
        except Exception:
            version = 'unknown'
        if TREZORLIB:
            return version
        else:
            raise LibraryFoundButUnusable(library_version=version)

    def enumerate(self):
        devices = trezorlib.transport.enumerate_devices()
        return [Device(path=d.get_path(),
                       interface_number=-1,
                       id_=d.get_path(),
                       product_key=TREZOR_PRODUCT_KEY,
                       usage_page=0)
                for d in devices]

    def create_client(self, device, handler):
        try:
            self.print_error("connecting to device at", device.path)
            transport = trezorlib.transport.get_transport(device.path)
        except BaseException as e:
            self.print_error("cannot connect at", device.path, str(e))
            return None

        if not transport:
            self.print_error("cannot connect at", device.path)
            return

        self.print_error("connected to device at", device.path)
        return TrezorClientBase(transport, handler, self)

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
            handler.show_error(_(
                "You will be asked to enter 24 words regardless of your "
                "seed's actual length.  If you enter a word incorrectly or "
                "misspell it, you cannot change it or go back - you will need "
                "to start again from the beginning.\n\nSo please enter "
                "the words carefully!"))

        devmgr = self.device_manager()
        client = devmgr.client_by_id(device_id)

        if method == TIM_NEW:
            client.reset_device(
                strength=64 * (item + 2),  # 128, 192 or 256
                passphrase_protection=passphrase_protection,
                pin_protection=pin_protection,
                label=label)
        elif method == TIM_RECOVER:
            client.recover_device(
                recovery_type=recovery_type,
                word_count=6 * (item + 2),  # 12, 18 or 24
                passphrase_protection=passphrase_protection,
                pin_protection=pin_protection,
                label=label)
        else:
            raise RuntimeError("Unsupported recovery method")

    def _make_node_path(self, xpub, address_n):
        _, depth, fingerprint, child_num, chain_code, key = deserialize_xpub(xpub)
        node = HDNodeType(
            depth=depth,
            fingerprint=int.from_bytes(fingerprint, 'big'),
            child_num=int.from_bytes(child_num, 'big'),
            chain_code=chain_code,
            public_key=key,
        )
        return HDNodePathType(node=node, address_n=address_n)

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
        if not client.is_uptodate():
            raise Exception(_('Outdated {} firmware for device labelled {}. Please '
                              'download the updated firmware from {}')
                            .format(self.device, client.label(), self.firmware_URL))
        # fixme: we should use: client.handler = wizard
        client.handler = self.create_handler(wizard)
        creating = not device_info.initialized
        if creating:
            self.initialize_device(device_id, wizard, client.handler)
        client.get_xpub('m', 'standard', creating)
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
            return InputScriptType.SPENDMULTISIG
        else:
            return InputScriptType.SPENDADDRESS

    def sign_transaction(self, keystore, tx, xpub_path):
        client = self.get_client(keystore)
        inputs = self.tx_inputs(tx, xpub_path, True)
        outputs = self.tx_outputs(keystore.get_derivation(), tx, client)
        details = SignTx(lock_time=tx.locktime)
        signed_tx = client.sign_tx(self.get_coin_name(), inputs, outputs, details=details,prev_txes=defaultdict(TransactionType))[1]
        raw = bh2u(signed_tx)
        tx.update_signatures(raw)

    def show_address(self, wallet, address, keystore=None):
        if keystore is None:
            keystore = wallet.get_keystore()
        deriv_suffix = wallet.get_address_index(address)
        derivation = keystore.derivation
        address_path = "%s/%d/%d"%(derivation, *deriv_suffix)

        # prepare multisig, if available
        xpubs = wallet.get_master_public_keys()
        if len(xpubs) > 1:
            def f(xpub):
                return self._make_node_path(xpub, [change, index])
            pubkeys = wallet.get_public_keys(address)
            # sort xpubs using the order of pubkeys
            sorted_pairs = sorted(zip(pubkeys, xpubs))
            multisig = self._make_multisig(
                wallet.m,
                [(xpub, deriv_suffix) for _, xpub in sorted_pairs])
        else:
            multisig = None
        script_type = self.get_trezor_input_script_type(multisig is not None)
        client = self.get_client(keystore)
        client.show_address(address_path, script_type, multisig)

    def tx_inputs(self, tx, xpub_path, for_sig=False):
        inputs = []
        for txin in tx.inputs():
            txinputtype = TxInputType()
            if txin['type'] == 'coinbase':
                prev_hash = b"\0"*32
                prev_index = 0xffffffff  # signed int -1
            else:
                if for_sig:
                    x_pubkeys = txin['x_pubkeys']
                    xpubs = [parse_xpubkey(x) for x in x_pubkeys]
                    multisig = self._make_multisig(txin.get('num_sig'), xpubs, txin.get('signatures'))
                    script_type = self.get_trezor_input_script_type(multisig is not None)
                    txinputtype = TxInputType(
                        script_type=script_type,
                        multisig=multisig)
                    # find which key is mine
                    for xpub, deriv in xpubs:
                        if xpub in xpub_path:
                            xpub_n = parse_path(xpub_path[xpub])
                            txinputtype.address_n = xpub_n + deriv
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

    def _make_multisig(self, m, xpubs, signatures=None):
        if len(xpubs) == 1:
            return None

        pubkeys = [self._make_node_path(xpub, deriv) for xpub, deriv in xpubs]
        if signatures is None:
            signatures = [b''] * len(pubkeys)
        elif len(signatures) != len(pubkeys):
            raise RuntimeError('Mismatched number of signatures')
        else:
            signatures = [bfh(x)[:-1] if x else b'' for x in signatures]

        return MultisigRedeemScriptType(
            pubkeys=pubkeys,
            signatures=signatures,
            m=m)

    def tx_outputs(self, derivation, tx, client):

        def create_output_by_derivation():
            deriv = parse_path("/%d/%d" % index)
            multisig = self._make_multisig(m, [(xpub, deriv) for xpub in xpubs])
            script_type = OutputScriptType.PAYTOADDRESS if multisig is None else OutputScriptType.PAYTOMULTISIG

            txoutputtype = TxOutputType(
                multisig=multisig,
                amount=amount,
                address_n=parse_path(derivation + "/%d/%d" % index),
                script_type=script_type)
            return txoutputtype

        def create_output_by_address():
            txoutputtype = TxOutputType()
            txoutputtype.amount = amount
            if _type == TYPE_SCRIPT:
                script = address.to_script()
                # We only support OP_RETURN with one constant push
                if (script[0] == 0x6a and amount == 0 and
                    script[1] == len(script) - 2 and
                    script[1] <= 75):
                    txoutputtype.script_type = OutputScriptType.PAYTOOPRETURN
                    txoutputtype.op_return_data = script[2:]
                else:
                    raise Exception(_("Unsupported output script."))
            elif _type == TYPE_ADDRESS:
                txoutputtype.script_type = OutputScriptType.PAYTOADDRESS
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
        any_output_on_change_branch = self.is_any_tx_output_on_change_branch(tx)

        for _type, address, amount in tx.outputs():
            use_create_by_derivation = False
            info = tx.output_info.get(address)
            if info is not None and not has_change:
                index, xpubs, m = info
                on_change_branch = index[0] == 1
                # prioritise hiding outputs on the 'change' branch from user
                # because no more than one change address allowed
                # note: ^ restriction can be removed once we require fw
                # that has https://github.com/trezor/trezor-mcu/pull/306
                if on_change_branch == any_output_on_change_branch:
                    use_create_by_derivation = True
                    has_change = True

            if use_create_by_derivation:
                txoutputtype = create_output_by_derivation()
            else:
                txoutputtype = create_output_by_address()
            outputs.append(txoutputtype)

        return outputs

    def is_any_tx_output_on_change_branch(self, tx):
        if not tx.output_info:
            return False
        for _type, address, _amount in tx.outputs():
            info = tx.output_info.get(address)
            if info is not None and info[0][0] == 1:
                    return True
        return False

    # This function is called from the TREZOR libraries (via tx_api)
    def get_tx(self, tx_hash):
        # for electron-cash previous tx is never needed, since it uses
        # bip-143 signatures.
        return None
