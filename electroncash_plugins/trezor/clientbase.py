import time
from struct import pack

from electroncash.i18n import _
from electroncash.util import PrintError, UserCancelled
from electroncash.keystore import bip39_normalize_passphrase
from electroncash.bitcoin import serialize_xpub

from trezorlib.client import TrezorClient, PASSPHRASE_ON_DEVICE
from trezorlib.exceptions import TrezorFailure, Cancelled, OutdatedFirmwareError, TrezorException
from trezorlib.messages import WordRequestType, FailureType, RecoveryDeviceType, ButtonRequestType
import trezorlib.btc
import trezorlib.device

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


def parse_path(n):
    """Convert bip32 path to list of uint32 integers with prime flags
    m/0/-1/1' -> [0, 0x80000001, 0x80000001]

    based on code in trezorlib
    """
    path = []
    BIP32_PRIME = 0x80000000
    for x in n.split('/')[1:]:
        if x == '': continue
        prime = 0
        if x.endswith("'"):
            x = x.replace('\'', '')
            prime = BIP32_PRIME
        if x.startswith('-'):
            prime = BIP32_PRIME
        path.append(abs(int(x)) | prime)
    return path


class TrezorClientBase(PrintError):
    def __init__(self, transport, handler, plugin):
        self.client = TrezorClient(transport, ui=self)
        self.plugin = plugin
        self.device = plugin.device
        self.handler = handler

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

    def __exit__(self, exc_type, exc_value, traceback):
        self.end_flow()
        if exc_value is not None:
            if issubclass(exc_type, Cancelled):
                raise UserCancelled from exc_value
            elif issubclass(exc_type, TrezorFailure):
                raise RuntimeError(str(exc_value)) from exc_value
            elif issubclass(exc_type, OutdatedFirmwareError):
                raise UserFacingException(exc_value) from exc_value
            else:
                return False
        return True

    @property
    def features(self):
        return self.client.features

    def __str__(self):
        return "%s/%s" % (self.label(), self.features.device_id)

    def label(self):
        '''The name given by the user to the device.'''
        return "An unnamed trezor" if self.features.label is None else self.features.label

    def is_initialized(self):
        '''True if initialized, False if wiped.'''
        return self.features.initialized

    def is_pairable(self):
        return not self.features.bootloader_mode

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

    def timeout(self, cutoff):
        '''Time out the client if the last operation was before cutoff.'''
        if self.last_operation < cutoff:
            self.print_error("timed out")
            self.clear_session()

    def i4b(self, x):
        return pack('>I', x)

    def get_xpub(self, bip32_path, xtype, creating=False):
        address_n = parse_path(bip32_path)
        with self.run_flow(creating_wallet=creating):
            node = trezorlib.btc.get_public_node(self.client, address_n).node
        return serialize_xpub(xtype, node.chain_code, node.public_key, node.depth, self.i4b(node.fingerprint), self.i4b(node.child_num))

    def toggle_passphrase(self):
        if self.features.passphrase_protection:
            msg = _("Confirm on your {} device to disable passphrases")
        else:
            msg = _("Confirm on your {} device to enable passphrases")
        enabled = not self.features.passphrase_protection
        with self.run_flow(msg):
            trezorlib.device.apply_settings(self.client, use_passphrase=enabled)

    def change_label(self, label):
        with self.run_flow(_("Confirm the new label on your {} device")):
            trezorlib.device.apply_settings(self.client, label=label)

    def change_homescreen(self, homescreen):
        with self.run_flow(_("Confirm on your {} device to change your home screen")):
            trezorlib.device.apply_settings(self.client, homescreen=homescreen)

    def set_pin(self, remove):
        if remove:
            msg = _("Confirm on your {} device to disable PIN protection")
        elif self.features.pin_protection:
            msg = _("Confirm on your {} device to change your PIN")
        else:
            msg = _("Confirm on your {} device to set a PIN")
        with self.run_flow(msg):
            trezorlib.device.change_pin(self.client, remove)

    def clear_session(self):
        '''Clear the session to force pin (and passphrase if enabled)
        re-entry.  Does not leak exceptions.'''
        self.print_error("clear session:", self)
        self.prevent_timeouts()
        try:
            self.client.clear_session()
        except BaseException as e:
            # If the device was removed it has the same effect...
            self.print_error("clear_session: ignoring error", str(e))

    def close(self):
        '''Called when Our wallet was closed or the device removed.'''
        self.print_error("closing client")
        self.clear_session()

    def atleast_version(self, major, minor=0, patch=0):
        return self.client.version >= (major, minor, patch)

    def is_uptodate(self):
        if self.client.is_outdated():
            return False
        return self.client.version >= self.plugin.minimum_firmware

    def get_trezor_model(self):
        """Returns '1' for Trezor One, 'T' for Trezor T."""
        return self.features.model

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

    def sign_message(self, address_str, message):
        coin_name = self.plugin.get_coin_name()
        address_n = parse_path(address_str)
        with self.run_flow():
            return trezorlib.btc.sign_message(
                self.client,
                coin_name,
                address_n,
                message)

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

    def sign_tx(self, *args, **kwargs):
        with self.run_flow():
            return trezorlib.btc.sign_tx(self.client, *args, **kwargs)

    def reset_device(self, *args, **kwargs):
        with self.run_flow():
            return trezorlib.device.reset(self.client, *args, **kwargs)

    def wipe_device(self, *args, **kwargs):
        with self.run_flow():
            return trezorlib.device.wipe(self.client, *args, **kwargs)

    # ========= UI methods ==========

    def button_request(self, code):
        message = self.msg or MESSAGES.get(code) or MESSAGES['default']
        def on_cancel():
            try:
                self.client.cancel()
            except TrezorException as e:
                self.print_error("Exception during cancel call:", repr(e))
                self.handler.show_error(_("The {} device is now in an inconsistent state."
                                          "\n\nYou may have to unplug the device and plug it back in and restart what you were doing.")
                                        .format(self.device))
            finally:
                # HACK. This is to get out of the situation with a stuck install wizard
                # when there is a client error after user hits "cancel" in the GUI.
                # Unfortunately the libusb transport is buggy as hell... and there is
                # no way to cancel an in-process command that I can tell.
                #
                # See trezor.py initialize_device() function for the caller that
                # expects this code to be here and exit its event loop.
                loops = getattr(self.handler, '_loops', None)
                if loops and loops[0].isRunning():
                    loops[0].exit(3)
        self.handler.show_message(message.format(self.device), on_cancel)

    def get_pin(self, code=None):
        if code == 2:
            msg = _("Enter a new PIN for your {}:")
        elif code == 3:
            msg = (_("Re-enter the new PIN for your {}.\n\n"
                     "NOTE: the positions of the numbers have changed!"))
        else:
            msg = _("Enter your current {} PIN:")
        pin = self.handler.get_pin(msg.format(self.device))
        if not pin:
            raise Cancelled
        if len(pin) > 9:
            self.handler.show_error(_('The PIN cannot be longer than 9 characters.'))
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

        if recovery_type == RecoveryDeviceType.Matrix:
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
