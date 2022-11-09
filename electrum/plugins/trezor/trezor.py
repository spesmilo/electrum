import traceback
import sys
from typing import NamedTuple, Any, Optional, Dict, Union, List, Tuple, TYPE_CHECKING

from electrum.util import bfh, bh2u, versiontuple, UserCancelled, UserFacingException
from electrum.bip32 import BIP32Node, convert_bip32_path_to_list_of_uint32 as parse_path
from electrum import constants
from electrum.i18n import _
from electrum.plugin import Device, runs_in_hwd_thread
from electrum.transaction import Transaction, PartialTransaction, PartialTxInput, PartialTxOutput
from electrum.keystore import Hardware_KeyStore
from electrum.base_wizard import ScriptTypeNotSupported, HWD_SETUP_NEW_WALLET
from electrum.logging import get_logger

from ..hw_wallet import HW_PluginBase
from ..hw_wallet.plugin import (is_any_tx_output_on_change_branch, trezor_validate_op_return_output_and_get_data,
                                LibraryFoundButUnusable, OutdatedHwFirmwareException,
                                get_xpubs_and_der_suffixes_from_txinout)

_logger = get_logger(__name__)


try:
    import trezorlib
    import trezorlib.transport
    from trezorlib.transport.bridge import BridgeTransport, call_bridge

    from .clientbase import TrezorClientBase

    from trezorlib.messages import (
        Capability, BackupType, RecoveryDeviceType, HDNodeType, HDNodePathType,
        InputScriptType, OutputScriptType, MultisigRedeemScriptType,
        TxInputType, TxOutputType, TxOutputBinType, TransactionType, AmountUnit)

    from trezorlib.client import PASSPHRASE_ON_DEVICE

    TREZORLIB = True
except Exception as e:
    if not (isinstance(e, ModuleNotFoundError) and e.name == 'trezorlib'):
        _logger.exception('error importing trezor plugin deps')
    TREZORLIB = False

    class _EnumMissing:
        def __init__(self):
            self.counter = 0
            self.values = {}

        def __getattr__(self, key):
            if key not in self.values:
                self.values[key] = self.counter
                self.counter += 1
            return self.values[key]

    Capability = _EnumMissing()
    BackupType = _EnumMissing()
    RecoveryDeviceType = _EnumMissing()
    AmountUnit = _EnumMissing()

    PASSPHRASE_ON_DEVICE = object()


# Trezor initialization methods
TIM_NEW, TIM_RECOVER = range(2)

TREZOR_PRODUCT_KEY = 'Trezor'


class TrezorKeyStore(Hardware_KeyStore):
    hw_type = 'trezor'
    device = TREZOR_PRODUCT_KEY

    plugin: 'TrezorPlugin'

    def decrypt_message(self, sequence, message, password):
        raise UserFacingException(_('Encryption and decryption are not implemented by {}').format(self.device))

    def sign_message(self, sequence, message, password, *, script_type=None):
        client = self.get_client()
        address_path = self.get_derivation_prefix() + "/%d/%d"%sequence
        script_type = self.plugin.get_trezor_input_script_type(script_type)
        msg_sig = client.sign_message(address_path, message, script_type=script_type)
        return msg_sig.signature

    def sign_transaction(self, tx, password):
        if tx.is_complete():
            return
        # previous transactions used as inputs
        prev_tx = {}
        for txin in tx.inputs():
            tx_hash = txin.prevout.txid.hex()
            if txin.utxo is None:
                raise UserFacingException(_('Missing previous tx.'))
            prev_tx[tx_hash] = txin.utxo

        self.plugin.sign_transaction(self, tx, prev_tx)


class TrezorInitSettings(NamedTuple):
    word_count: int
    label: str
    pin_enabled: bool
    passphrase_enabled: bool
    recovery_type: Any = None
    backup_type: int = BackupType.Bip39
    no_backup: bool = False


class TrezorPlugin(HW_PluginBase):
    # Derived classes provide:
    #
    #  class-static variables: client_class, firmware_URL, handler_class,
    #     libraries_available, libraries_URL, minimum_firmware,
    #     wallet_class, types

    firmware_URL = 'https://wallet.trezor.io'
    libraries_URL = 'https://pypi.org/project/trezor/'
    minimum_firmware = (1, 5, 2)
    keystore_class = TrezorKeyStore
    minimum_library = (0, 13, 0)
    maximum_library = (0, 14)
    SUPPORTED_XTYPES = ('standard', 'p2wpkh-p2sh', 'p2wpkh', 'p2wsh-p2sh', 'p2wsh')
    DEVICE_IDS = (TREZOR_PRODUCT_KEY,)

    MAX_LABEL_LEN = 32

    def __init__(self, parent, config, name):
        super().__init__(parent, config, name)

        self.libraries_available = self.check_libraries_available()
        if not self.libraries_available:
            return
        self.device_manager().register_enumerate_func(self.enumerate)
        self._is_bridge_available = None

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

    @runs_in_hwd_thread
    def is_bridge_available(self) -> bool:
        # Testing whether the Bridge is available can take several seconds
        # (when it is not), as it is slow to timeout, hence we cache it.
        if self._is_bridge_available is None:
            try:
                call_bridge("enumerate")
            except Exception:
                self._is_bridge_available = False
                # never again try with Bridge due to slow timeout
                BridgeTransport.ENABLED = False
            else:
                self._is_bridge_available = True
        return self._is_bridge_available

    @runs_in_hwd_thread
    def enumerate(self):
        # Set lower timeout for UDP enumeration (used for emulator).
        # The default of 10 sec is very long, and I often hit it for some reason on Windows (no emu running),
        # blocking the whole enumeration.
        from trezorlib.transport.udp import UdpTransport
        trezorlib.transport.udp.SOCKET_TIMEOUT = 1
        # If there is a bridge, prefer that.
        # On Windows, the bridge runs as Admin (and Electrum usually does not),
        # so the bridge has better chances of finding devices. see #5420
        # This also avoids duplicate entries.
        if self.is_bridge_available():
            devices = BridgeTransport.enumerate()
        else:
            devices = trezorlib.transport.enumerate_devices()
        return [Device(path=d.get_path(),
                       interface_number=-1,
                       id_=d.get_path(),
                       product_key=TREZOR_PRODUCT_KEY,
                       usage_page=0,
                       transport_ui_string=d.get_path())
                for d in devices]

    @runs_in_hwd_thread
    def create_client(self, device, handler):
        try:
            self.logger.info(f"connecting to device at {device.path}")
            transport = trezorlib.transport.get_transport(device.path)
        except BaseException as e:
            self.logger.info(f"cannot connect at {device.path} {e}")
            return None

        if not transport:
            self.logger.info(f"cannot connect at {device.path}")
            return

        self.logger.info(f"connected to device at {device.path}")
        # note that this call can still raise!
        return TrezorClientBase(transport, handler, self)

    @runs_in_hwd_thread
    def get_client(self, keystore, force_pair=True, *,
                   devices=None, allow_user_interaction=True) -> Optional['TrezorClientBase']:
        client = super().get_client(keystore, force_pair,
                                    devices=devices,
                                    allow_user_interaction=allow_user_interaction)
        # returns the client for a given keystore. can use xpub
        if client:
            client.used()
        return client

    def get_coin_name(self):
        return "Testnet" if constants.net.TESTNET else "Bitcoin"

    def initialize_device(self, device_id, wizard, handler):
        # Initialization method
        msg = _("Choose how you want to initialize your {}.").format(self.device, self.device)
        choices = [
            # Must be short as QT doesn't word-wrap radio button text
            (TIM_NEW, _("Let the device generate a completely new seed randomly")),
            (TIM_RECOVER, _("Recover from a seed you have previously written down")),
        ]
        def f(method):
            import threading
            settings = self.request_trezor_init_settings(wizard, method, device_id)
            t = threading.Thread(target=self._initialize_device_safe, args=(settings, method, device_id, wizard, handler))
            t.daemon = True
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
            self.logger.exception('')
            handler.show_error(repr(e))
            exit_code = 1
        finally:
            wizard.loop.exit(exit_code)

    @runs_in_hwd_thread
    def _initialize_device(self, settings: TrezorInitSettings, method, device_id, wizard, handler):
        if method == TIM_RECOVER and settings.recovery_type == RecoveryDeviceType.ScrambledWords:
            handler.show_error(_(
                "You will be asked to enter 24 words regardless of your "
                "seed's actual length.  If you enter a word incorrectly or "
                "misspell it, you cannot change it or go back - you will need "
                "to start again from the beginning.\n\nSo please enter "
                "the words carefully!"),
                blocking=True)

        devmgr = self.device_manager()
        client = devmgr.client_by_id(device_id)
        if not client:
            raise Exception(_("The device was disconnected."))

        if method == TIM_NEW:
            strength_from_word_count = {12: 128, 18: 192, 20: 128, 24: 256, 33: 256}
            client.reset_device(
                strength=strength_from_word_count[settings.word_count],
                passphrase_protection=settings.passphrase_enabled,
                pin_protection=settings.pin_enabled,
                label=settings.label,
                backup_type=settings.backup_type,
                no_backup=settings.no_backup)
        elif method == TIM_RECOVER:
            client.recover_device(
                recovery_type=settings.recovery_type,
                word_count=settings.word_count,
                passphrase_protection=settings.passphrase_enabled,
                pin_protection=settings.pin_enabled,
                label=settings.label)
            if settings.recovery_type == RecoveryDeviceType.Matrix:
                handler.close_matrix_dialog()
        else:
            raise RuntimeError("Unsupported recovery method")

    def _make_node_path(self, xpub, address_n):
        bip32node = BIP32Node.from_xkey(xpub)
        node = HDNodeType(
            depth=bip32node.depth,
            fingerprint=int.from_bytes(bip32node.fingerprint, 'big'),
            child_num=int.from_bytes(bip32node.child_number, 'big'),
            chain_code=bip32node.chaincode,
            public_key=bip32node.eckey.get_public_key_bytes(compressed=True),
        )
        return HDNodePathType(node=node, address_n=address_n)

    def setup_device(self, device_info, wizard, purpose):
        device_id = device_info.device.id_
        client = self.scan_and_create_client_for_device(device_id=device_id, wizard=wizard)

        if not client.is_uptodate():
            msg = (_('Outdated {} firmware for device labelled {}. Please '
                     'download the updated firmware from {}')
                   .format(self.device, client.label(), self.firmware_URL))
            raise OutdatedHwFirmwareException(msg)

        if not device_info.initialized:
            self.initialize_device(device_id, wizard, client.handler)
        is_creating_wallet = purpose == HWD_SETUP_NEW_WALLET
        wizard.run_task_without_blocking_gui(
            task=lambda: client.get_xpub('m', 'standard', creating=is_creating_wallet))
        client.used()
        return client

    def get_xpub(self, device_id, derivation, xtype, wizard):
        if xtype not in self.SUPPORTED_XTYPES:
            raise ScriptTypeNotSupported(_('This type of script is not supported with {}.').format(self.device))
        client = self.scan_and_create_client_for_device(device_id=device_id, wizard=wizard)
        xpub = client.get_xpub(derivation, xtype)
        client.used()
        return xpub

    def get_trezor_input_script_type(self, electrum_txin_type: str):
        if electrum_txin_type in ('p2wpkh', 'p2wsh'):
            return InputScriptType.SPENDWITNESS
        if electrum_txin_type in ('p2wpkh-p2sh', 'p2wsh-p2sh'):
            return InputScriptType.SPENDP2SHWITNESS
        if electrum_txin_type in ('p2pkh',):
            return InputScriptType.SPENDADDRESS
        if electrum_txin_type in ('p2sh',):
            return InputScriptType.SPENDMULTISIG
        if electrum_txin_type in ('p2tr',):
            return InputScriptType.SPENDTAPROOT
        raise ValueError('unexpected txin type: {}'.format(electrum_txin_type))

    def get_trezor_output_script_type(self, electrum_txin_type: str):
        if electrum_txin_type in ('p2wpkh', 'p2wsh'):
            return OutputScriptType.PAYTOWITNESS
        if electrum_txin_type in ('p2wpkh-p2sh', 'p2wsh-p2sh'):
            return OutputScriptType.PAYTOP2SHWITNESS
        if electrum_txin_type in ('p2pkh',):
            return OutputScriptType.PAYTOADDRESS
        if electrum_txin_type in ('p2sh',):
            return OutputScriptType.PAYTOMULTISIG
        if electrum_txin_type in ('p2tr',):
            return OutputScriptType.PAYTOTAPROOT
        raise ValueError('unexpected txin type: {}'.format(electrum_txin_type))

    def get_trezor_amount_unit(self):
        if self.config.decimal_point == 0:
            return AmountUnit.SATOSHI
        elif self.config.decimal_point == 2:
            return AmountUnit.MICROBITCOIN
        elif self.config.decimal_point == 5:
            return AmountUnit.MILLIBITCOIN
        else:
            return AmountUnit.BITCOIN

    @runs_in_hwd_thread
    def sign_transaction(self, keystore, tx: PartialTransaction, prev_tx):
        prev_tx = {bfh(txhash): self.electrum_tx_to_txtype(tx) for txhash, tx in prev_tx.items()}
        client = self.get_client(keystore)
        inputs = self.tx_inputs(tx, for_sig=True, keystore=keystore)
        outputs = self.tx_outputs(tx, keystore=keystore)
        signatures, _ = client.sign_tx(self.get_coin_name(),
                                       inputs, outputs,
                                       lock_time=tx.locktime,
                                       version=tx.version,
                                       amount_unit=self.get_trezor_amount_unit(),
                                       serialize=False,
                                       prev_txes=prev_tx)
        signatures = [(bh2u(x) + '01') for x in signatures]
        tx.update_signatures(signatures)

    @runs_in_hwd_thread
    def show_address(self, wallet, address, keystore=None):
        if keystore is None:
            keystore = wallet.get_keystore()
        if not self.show_address_helper(wallet, address, keystore):
            return
        deriv_suffix = wallet.get_address_index(address)
        derivation = keystore.get_derivation_prefix()
        address_path = "%s/%d/%d"%(derivation, *deriv_suffix)
        script_type = self.get_trezor_input_script_type(wallet.txin_type)

        # prepare multisig, if available:
        xpubs = wallet.get_master_public_keys()
        if len(xpubs) > 1:
            pubkeys = wallet.get_public_keys(address)
            # sort xpubs using the order of pubkeys
            sorted_pairs = sorted(zip(pubkeys, xpubs))
            multisig = self._make_multisig(
                wallet.m,
                [(xpub, deriv_suffix) for pubkey, xpub in sorted_pairs])
        else:
            multisig = None

        client = self.get_client(keystore)
        client.show_address(address_path, script_type, multisig)

    def tx_inputs(self, tx: Transaction, *, for_sig=False, keystore: 'TrezorKeyStore' = None):
        inputs = []
        for txin in tx.inputs():
            if txin.is_coinbase_input():
                txinputtype = TxInputType(
                    prev_hash=b"\x00"*32,
                    prev_index=0xffffffff,  # signed int -1
                )
            else:
                txinputtype = TxInputType(
                    prev_hash=txin.prevout.txid,
                    prev_index=txin.prevout.out_idx,
                )
                if for_sig:
                    assert isinstance(tx, PartialTransaction)
                    assert isinstance(txin, PartialTxInput)
                    assert keystore
                    if len(txin.pubkeys) > 1:
                        xpubs_and_deriv_suffixes = get_xpubs_and_der_suffixes_from_txinout(tx, txin)
                        txinputtype.multisig = self._make_multisig(txin.num_sig, xpubs_and_deriv_suffixes)
                    txinputtype.script_type = self.get_trezor_input_script_type(txin.script_type)
                    my_pubkey, full_path = keystore.find_my_pubkey_in_txinout(txin)
                    if full_path:
                        txinputtype.address_n = full_path

            txinputtype.amount = txin.value_sats()
            txinputtype.script_sig = txin.script_sig
            txinputtype.sequence = txin.nsequence

            inputs.append(txinputtype)

        return inputs

    def _make_multisig(self, m, xpubs):
        if len(xpubs) == 1:
            return None
        pubkeys = [self._make_node_path(xpub, deriv) for xpub, deriv in xpubs]
        return MultisigRedeemScriptType(
            pubkeys=pubkeys,
            signatures=[b''] * len(pubkeys),
            m=m)

    def tx_outputs(self, tx: PartialTransaction, *, keystore: 'TrezorKeyStore'):

        def create_output_by_derivation():
            script_type = self.get_trezor_output_script_type(txout.script_type)
            if len(txout.pubkeys) > 1:
                xpubs_and_deriv_suffixes = get_xpubs_and_der_suffixes_from_txinout(tx, txout)
                multisig = self._make_multisig(txout.num_sig, xpubs_and_deriv_suffixes)
            else:
                multisig = None
            my_pubkey, full_path = keystore.find_my_pubkey_in_txinout(txout)
            assert full_path
            txoutputtype = TxOutputType(
                multisig=multisig,
                amount=txout.value,
                address_n=full_path,
                script_type=script_type)
            return txoutputtype

        def create_output_by_address():
            if address:
                return TxOutputType(
                    amount=txout.value,
                    script_type=OutputScriptType.PAYTOADDRESS,
                    address=address,
                )
            else:
                return TxOutputType(
                    amount=txout.value,
                    script_type=OutputScriptType.PAYTOOPRETURN,
                    op_return_data=trezor_validate_op_return_output_and_get_data(txout),
                )

        outputs = []
        has_change = False
        any_output_on_change_branch = is_any_tx_output_on_change_branch(tx)

        for txout in tx.outputs():
            address = txout.address
            use_create_by_derivation = False

            if txout.is_mine and not has_change:
                # prioritise hiding outputs on the 'change' branch from user
                # because no more than one change address allowed
                # note: ^ restriction can be removed once we require fw
                # that has https://github.com/trezor/trezor-mcu/pull/306
                if txout.is_change == any_output_on_change_branch:
                    use_create_by_derivation = True
                    has_change = True

            if use_create_by_derivation:
                txoutputtype = create_output_by_derivation()
            else:
                txoutputtype = create_output_by_address()
            outputs.append(txoutputtype)

        return outputs

    def electrum_tx_to_txtype(self, tx: Optional[Transaction]):
        t = TransactionType()
        if tx is None:
            # probably for segwit input and we don't need this prev txn
            return t
        tx.deserialize()
        t.version = tx.version
        t.lock_time = tx.locktime
        t.inputs = self.tx_inputs(tx)
        t.bin_outputs = [
            TxOutputBinType(amount=o.value, script_pubkey=o.scriptpubkey)
            for o in tx.outputs()
        ]
        return t
