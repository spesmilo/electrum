import time
from struct import pack

from electrum import ecc
from electrum.i18n import _
from electrum.util import UserCancelled, UserFacingException
from electrum.keystore import bip39_normalize_passphrase
from electrum.bip32 import BIP32Node, convert_bip32_strpath_to_intpath as parse_path
from electrum.logging import Logger
from electrum.plugin import runs_in_hwd_thread
from electrum.plugins.hw_wallet.plugin import OutdatedHwFirmwareException, HardwareClientBase

from trezorlib.client import TrezorClient, PASSPHRASE_ON_DEVICE
from trezorlib.exceptions import TrezorFailure, Cancelled, OutdatedFirmwareError
from trezorlib.messages import WordRequestType, FailureType, ButtonRequestType
import trezorlib.btc
import trezorlib.device

try:
    # trezor >= 0.13.9
    from trezorlib.messages import RecoveryDeviceInputMethod
except ImportError:
    # Backward compatibility for trezor < 0.13.9
    from trezorlib.messages import RecoveryDeviceType as RecoveryDeviceInputMethod


MESSAGES = {
    ButtonRequestType.ConfirmOutput:
        _("Confirm the transaction output on your {} device"),
    ButtonRequestType.ResetDevice:
        _("Complete the initialization process on your {} device"),
    ButtonRequestType.ConfirmWord:
        _("Write down the seed word shown on your {}"),
    ButtonRequestType.WipeDevice:
        _("Confirm on your {} that you want to wipe it clean"),
    ButtonRequestType.ProtectCall:
        _("Confirm on your {} device the message to sign"),
    ButtonRequestType.SignTx:
        _("Confirm the total amount spent and the transaction fee on your {} device"),
    ButtonRequestType.Address:
        _("Confirm wallet address on your {} device"),
    ButtonRequestType._Deprecated_ButtonRequest_PassphraseType:
        _("Choose on your {} device where to enter your passphrase"),
    ButtonRequestType.PassphraseEntry:
        _("Please enter your passphrase on the {} device"),
    'default': _("Check your {} device to continue"),
}


class TrezorClientBase(HardwareClientBase, Logger):
    def __init__(self, transport, handler, plugin):
        HardwareClientBase.__init__(self, plugin=plugin)
        if plugin.is_outdated_fw_ignored():
            TrezorClient.is_outdated = lambda *args, **kwargs: False
        self.client = TrezorClient(transport, ui=self)
        self.device = plugin.device
        self.handler = handler
        Logger.__init__(self)

        self.msg = None
        self.creating_wallet = False

        self.in_flow = False

        self.used()

    def run_flow(self, message=None, creating_wallet=False):
        if self.in_flow:
            raise RuntimeError("Overlapping call to run_flow")

        self.in_flow = True
        self.msg = message
        self.creating_wallet = creating_wallet
        self.prevent_timeouts()
        return self

    def end_flow(self):
        self.in_flow = False
        self.msg = None
        self.creating_wallet = False
        self.handler.finished()
        self.used()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, e, traceback):
        self.end_flow()
        if e is not None:
            if isinstance(e, Cancelled):
                raise UserCancelled() from e
            elif isinstance(e, TrezorFailure):
                raise RuntimeError(str(e)) from e
            elif isinstance(e, OutdatedFirmwareError):
                raise OutdatedHwFirmwareException(e) from e
            else:
                return False
        return True

    @property
    def features(self):
        return self.client.features

    def __str__(self):
        return "%s/%s" % (self.label(), self.features.device_id)

    def label(self):
        return self.features.label

    def get_soft_device_id(self):
        return self.features.device_id

    def is_initialized(self):
        return self.features.initialized

    def is_pairable(self):
        return not self.features.bootloader_mode

    @runs_in_hwd_thread
    def has_usable_connection_with_device(self):
        if self.in_flow:
            return True

        try:
            self.client.init_device()
        except BaseException:
            return False
        return True

    def used(self):
        self.last_operation = time.time()

    def prevent_timeouts(self):
        self.last_operation = float('inf')

    @runs_in_hwd_thread
    def timeout(self, cutoff):
        '''Time out the client if the last operation was before cutoff.'''
        if self.last_operation < cutoff:
            self.logger.info("timed out")
            self.clear_session()

    def i4b(self, x):
        return pack('>I', x)

    @runs_in_hwd_thread
    def get_xpub(self, bip32_path, xtype, creating=False):
        address_n = parse_path(bip32_path)
        with self.run_flow(creating_wallet=creating):
            node = trezorlib.btc.get_public_node(self.client, address_n).node
        return BIP32Node(xtype=xtype,
                         eckey=ecc.ECPubkey(node.public_key),
                         chaincode=node.chain_code,
                         depth=node.depth,
                         fingerprint=self.i4b(node.fingerprint),
                         child_number=self.i4b(node.child_num)).to_xpub()

    @runs_in_hwd_thread
    def toggle_passphrase(self):
        if self.features.passphrase_protection:
            msg = _("Confirm on your {} device to disable passphrases")
        else:
            msg = _("Confirm on your {} device to enable passphrases")
        enabled = not self.features.passphrase_protection
        with self.run_flow(msg):
            trezorlib.device.apply_settings(self.client, use_passphrase=enabled)

    @runs_in_hwd_thread
    def change_label(self, label):
        with self.run_flow(_("Confirm the new label on your {} device")):
            trezorlib.device.apply_settings(self.client, label=label)

    @runs_in_hwd_thread
    def change_homescreen(self, homescreen):
        with self.run_flow(_("Confirm on your {} device to change your home screen")):
            trezorlib.device.apply_settings(self.client, homescreen=homescreen)

    @runs_in_hwd_thread
    def set_pin(self, remove):
        if remove:
            msg = _("Confirm on your {} device to disable PIN protection")
        elif self.features.pin_protection:
            msg = _("Confirm on your {} device to change your PIN")
        else:
            msg = _("Confirm on your {} device to set a PIN")
        with self.run_flow(msg):
            trezorlib.device.change_pin(self.client, remove)

    @runs_in_hwd_thread
    def clear_session(self):
        '''Clear the session to force pin (and passphrase if enabled)
        re-entry.  Does not leak exceptions.'''
        self.logger.info(f"clear session: {self}")
        self.prevent_timeouts()
        try:
            self.client.clear_session()
        except BaseException as e:
            # If the device was removed it has the same effect...
            self.logger.info(f"clear_session: ignoring error {e}")

    @runs_in_hwd_thread
    def close(self):
        '''Called when Our wallet was closed or the device removed.'''
        self.logger.info("closing client")
        self.clear_session()

    @runs_in_hwd_thread
    def is_uptodate(self):
        if self.client.is_outdated():
            return False
        return self.client.version >= self.plugin.minimum_firmware

    def get_trezor_model(self):
        """Returns '1' for Trezor One, 'T' for Trezor T, etc."""
        return self.features.model

    def device_model_name(self):
        model = self.get_trezor_model()
        if model == '1':
            return "Trezor One"
        elif model == 'T':
            return "Trezor T"
        elif model == "Safe 3":
            return "Trezor Safe 3"
        return None

    @runs_in_hwd_thread
    def show_address(self, address_str, script_type, multisig=None):
        coin_name = self.plugin.get_coin_name()
        address_n = parse_path(address_str)
        with self.run_flow():
            return trezorlib.btc.get_address(
                self.client,
                coin_name,
                address_n,
                show_display=True,
                script_type=script_type,
                multisig=multisig)

    @runs_in_hwd_thread
    def sign_message(self, address_str, message, *, script_type):
        coin_name = self.plugin.get_coin_name()
        address_n = parse_path(address_str)
        with self.run_flow():
            return trezorlib.btc.sign_message(
                self.client,
                coin_name,
                address_n,
                message,
                script_type=script_type,
                no_script_type=True)

    @runs_in_hwd_thread
    def recover_device(self, recovery_type, *args, **kwargs):
        input_callback = self.mnemonic_callback(recovery_type)
        with self.run_flow():
            return trezorlib.device.recover(
                self.client,
                *args,
                input_callback=input_callback,
                type=recovery_type,
                **kwargs)

    # ========= Unmodified trezorlib methods =========

    @runs_in_hwd_thread
    def sign_tx(self, *args, **kwargs):
        with self.run_flow():
            return trezorlib.btc.sign_tx(self.client, *args, **kwargs)

    @runs_in_hwd_thread
    def get_ownership_id(self, *args, **kwargs):
        with self.run_flow():
            return trezorlib.btc.get_ownership_id(self.client, *args, **kwargs)

    @runs_in_hwd_thread
    def get_ownership_proof(self, *args, **kwargs):
        with self.run_flow():
            return trezorlib.btc.get_ownership_proof(self.client, *args, **kwargs)

    @runs_in_hwd_thread
    def reset_device(self, *args, **kwargs):
        with self.run_flow():
            return trezorlib.device.reset(self.client, *args, **kwargs)

    @runs_in_hwd_thread
    def wipe_device(self, *args, **kwargs):
        with self.run_flow():
            return trezorlib.device.wipe(self.client, *args, **kwargs)

    # ========= UI methods ==========

    def button_request(self, br):
        message = self.msg or MESSAGES.get(br.code) or MESSAGES['default']
        self.handler.show_message(message.format(self.device), self.client.cancel)

    def get_pin(self, code=None):
        show_strength = True
        if code == 2:
            msg = _("Enter a new PIN for your {}:")
        elif code == 3:
            msg = (_("Re-enter the new PIN for your {}.\n\n"
                     "NOTE: the positions of the numbers have changed!"))
        else:
            msg = _("Enter your current {} PIN:")
            show_strength = False
        pin = self.handler.get_pin(msg.format(self.device), show_strength=show_strength)
        if not pin:
            raise Cancelled
        # check PIN length. Depends on model and firmware version
        # https://github.com/trezor/trezor-firmware/issues/1167
        limit = 9
        if self.get_trezor_model() == "1":
            if (1, 10, 0) <= self.client.version:
                limit = 50
        else:
            if (2, 4, 0) <= self.client.version:
                limit = 50
        if len(pin) > limit:
            self.handler.show_error(_('The PIN cannot be longer than {} characters.').format(limit))
            raise Cancelled
        return pin

    def get_passphrase(self, available_on_device):
        if self.creating_wallet:
            msg = _("Enter a passphrase to generate this wallet.  Each time "
                    "you use this wallet your {} will prompt you for the "
                    "passphrase.  If you forget the passphrase you cannot "
                    "access the bitcoins in the wallet.").format(self.device)
        else:
            msg = _("Enter the passphrase to unlock this wallet:")

        self.handler.passphrase_on_device = available_on_device
        passphrase = self.handler.get_passphrase(msg, self.creating_wallet)
        if passphrase is PASSPHRASE_ON_DEVICE:
            return passphrase
        if passphrase is None:
            raise Cancelled
        passphrase = bip39_normalize_passphrase(passphrase)
        length = len(passphrase)
        if length > 50:
            self.handler.show_error(_("Too long passphrase ({} > 50 chars).").format(length))
            raise Cancelled
        return passphrase

    def _matrix_char(self, matrix_type):
        num = 9 if matrix_type == WordRequestType.Matrix9 else 6
        char = self.handler.get_matrix(num)
        if char == 'x':
            raise Cancelled
        return char

    def mnemonic_callback(self, recovery_type):
        if recovery_type is None:
            return None

        if recovery_type == RecoveryDeviceInputMethod.Matrix:
            return self._matrix_char

        step = 0
        def word_callback(_ignored):
            nonlocal step
            step += 1
            msg = _("Step {}/24.  Enter seed word as explained on your {}:").format(step, self.device)
            word = self.handler.get_word(msg)
            if not word:
                raise Cancelled
            return word
        return word_callback
