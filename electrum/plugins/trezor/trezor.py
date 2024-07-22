from typing import NamedTuple, Any, Optional, TYPE_CHECKING, Sequence

from electrum.util import bfh, UserCancelled, UserFacingException
from electrum.bip32 import BIP32Node
from electrum import descriptor
from electrum import constants
from electrum.i18n import _
from electrum.plugin import Device, runs_in_hwd_thread
from electrum.transaction import Transaction, PartialTransaction, PartialTxInput, Sighash
from electrum.keystore import Hardware_KeyStore
from electrum.logging import get_logger

from electrum.plugins.hw_wallet import HW_PluginBase
from electrum.plugins.hw_wallet.plugin import is_any_tx_output_on_change_branch, \
    trezor_validate_op_return_output_and_get_data, LibraryFoundButUnusable, OutdatedHwFirmwareException

if TYPE_CHECKING:
    from electrum.plugin import DeviceInfo
    from electrum.wizard import NewWalletWizard

_logger = get_logger(__name__)


try:
    import trezorlib
    import trezorlib.transport
    from trezorlib.transport.bridge import BridgeTransport, call_bridge

    from .clientbase import TrezorClientBase, RecoveryDeviceInputMethod

    from trezorlib.messages import (
        Capability, BackupType, HDNodeType, HDNodePathType,
        InputScriptType, OutputScriptType, MultisigRedeemScriptType,
        TxInputType, TxOutputType, TxOutputBinType, TransactionType, AmountUnit)

    from trezorlib.client import PASSPHRASE_ON_DEVICE
    import trezorlib.log
    #trezorlib.log.enable_debug_output()

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
    RecoveryDeviceInputMethod = _EnumMissing()
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

    def has_support_for_slip_19_ownership_proofs(self) -> bool:
        return True

    def add_slip_19_ownership_proofs_to_tx(self, tx: 'PartialTransaction', password) -> None:
        assert isinstance(tx, PartialTransaction)
        client = self.get_client()
        assert isinstance(client, TrezorClientBase), client
        for txin in tx.inputs():
            if txin.is_coinbase_input():
                continue
            # note: we add proofs even for txin.is_complete() inputs.
            if not txin.is_mine:
                continue
            assert txin.scriptpubkey
            desc = txin.script_descriptor
            assert desc
            trezor_multisig = None
            if multi := desc.get_simple_multisig():
                # trezor_multisig = self._make_multisig(multi)
                raise Exception("multisig not supported for slip-19 ownership proof")
            trezor_script_type = self.plugin.get_trezor_input_script_type(desc.to_legacy_electrum_script_type())
            my_pubkey, full_path = self.find_my_pubkey_in_txinout(txin)
            if full_path:
                trezor_address_n = full_path
            else:
                continue
            proof, _proof_sig = client.get_ownership_proof(
                coin_name=self.plugin.get_coin_name(),
                n=trezor_address_n,
                multisig=trezor_multisig,
                script_type=trezor_script_type,
            )
            txin.slip_19_ownership_proof = proof


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

    @runs_in_hwd_thread
    def _initialize_device(self, settings: TrezorInitSettings, method, device_id, handler):
        if method == TIM_RECOVER and settings.recovery_type == RecoveryDeviceInputMethod.ScrambledWords:
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
            if settings.recovery_type == RecoveryDeviceInputMethod.Matrix:
                handler.close_matrix_dialog()
        else:
            raise RuntimeError("Unsupported recovery method")

    def _make_node_path(self, xpub: str, address_n: Sequence[int]):
        bip32node = BIP32Node.from_xkey(xpub)
        node = HDNodeType(
            depth=bip32node.depth,
            fingerprint=int.from_bytes(bip32node.fingerprint, 'big'),
            child_num=int.from_bytes(bip32node.child_number, 'big'),
            chain_code=bip32node.chaincode,
            public_key=bip32node.eckey.get_public_key_bytes(compressed=True),
        )
        return HDNodePathType(node=node, address_n=address_n)

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
        outputs = self.tx_outputs(tx, keystore=keystore, firmware_version=client.client.version)
        signatures, _ = client.sign_tx(self.get_coin_name(),
                                       inputs, outputs,
                                       lock_time=tx.locktime,
                                       version=tx.version,
                                       amount_unit=self.get_trezor_amount_unit(),
                                       serialize=False,
                                       prev_txes=prev_tx)
        sighash = Sighash.to_sigbytes(Sighash.ALL)
        signatures = [((sig + sighash) if sig else None) for sig in signatures]
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
        desc = wallet.get_script_descriptor_for_address(address)
        if multi := desc.get_simple_multisig():
            multisig = self._make_multisig(multi)
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
                    if txin.is_complete() or not txin.is_mine:  # we don't sign
                        txinputtype.script_type = InputScriptType.EXTERNAL
                        assert txin.scriptpubkey
                        txinputtype.script_pubkey = txin.scriptpubkey
                        # note: we add the ownership proof, if present, regardless of txin.is_complete().
                        #       The "Trezor One" model always requires it for external inputs. (see #8910)
                        if not txin.is_mine and txin.slip_19_ownership_proof:
                            txinputtype.ownership_proof = txin.slip_19_ownership_proof
                    else:  # we sign
                        desc = txin.script_descriptor
                        assert desc
                        if multi := desc.get_simple_multisig():
                            txinputtype.multisig = self._make_multisig(multi)
                        txinputtype.script_type = self.get_trezor_input_script_type(desc.to_legacy_electrum_script_type())
                        my_pubkey, full_path = keystore.find_my_pubkey_in_txinout(txin)
                        if full_path:
                            txinputtype.address_n = full_path
                    # Add witness if any. This is useful when signing a tx (for_sig=True)
                    # that has some already pre-signed external inputs.
                    txinputtype.witness = txin.witness

            txinputtype.amount = txin.value_sats()
            txinputtype.script_sig = txin.script_sig
            txinputtype.sequence = txin.nsequence

            inputs.append(txinputtype)

        return inputs

    def _make_multisig(self, desc: descriptor.MultisigDescriptor):
        pubkeys = []
        for pubkey_provider in desc.pubkeys:
            assert not pubkey_provider.is_range()
            assert pubkey_provider.extkey is not None
            xpub = pubkey_provider.pubkey
            der_suffix = pubkey_provider.get_der_suffix_int_list()
            pubkeys.append(self._make_node_path(xpub, der_suffix))
        return MultisigRedeemScriptType(
            pubkeys=pubkeys,
            signatures=[b''] * len(pubkeys),
            m=desc.thresh)

    def tx_outputs(self, tx: PartialTransaction, *, keystore: 'TrezorKeyStore', firmware_version: Sequence[int]):

        def create_output_by_derivation():
            desc = txout.script_descriptor
            assert desc
            script_type = self.get_trezor_output_script_type(desc.to_legacy_electrum_script_type())
            if multi := desc.get_simple_multisig():
                multisig = self._make_multisig(multi)
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

            if txout.is_mine:
                if tuple(firmware_version) >= (1, 6, 1):
                    use_create_by_derivation = True
                else:
                    if not has_change:
                        # prioritise hiding outputs on the 'change' branch from user
                        # because no more than one change address allowed
                        # note: ^ restriction can be removed once we require fw 1.6.1
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

    def wizard_entry_for_device(self, device_info: 'DeviceInfo', *, new_wallet=True) -> str:
        if new_wallet:  # new wallet
            return 'trezor_not_initialized' if not device_info.initialized else 'trezor_start'
        else:  # unlock existing wallet
            return 'trezor_unlock'

    # insert trezor pages in new wallet wizard
    def extend_wizard(self, wizard: 'NewWalletWizard'):
        views = {
            'trezor_start': {
                'next': 'trezor_xpub',
            },
            'trezor_xpub': {
                'next': lambda d: wizard.wallet_password_view(d) if wizard.last_cosigner(d) else 'multisig_cosigner_keystore',
                'accept': wizard.maybe_master_pubkey,
                'last': lambda d: wizard.is_single_password() and wizard.last_cosigner(d)
            },
            'trezor_not_initialized': {
                'next': 'trezor_choose_new_recover',
            },
            'trezor_choose_new_recover': {
                'next': 'trezor_do_init',
            },
            'trezor_do_init': {
                'next': 'trezor_start',
            },
            'trezor_unlock': {
                'last': True
            },
        }
        wizard.navmap_merge(views)
