import time
from struct import pack

from electrum import ecc
from electrum.i18n import _
from electrum.util import UserCancelled
from electrum.keystore import bip39_normalize_passphrase
from electrum.bip32 import BIP32Node, convert_bip32_path_to_list_of_uint32
from electrum.logging import Logger


class GuiMixin(object):
    # Requires: self.proto, self.device

    # ref: https://github.com/trezor/trezor-common/blob/44dfb07cfaafffada4b2ce0d15ba1d90d17cf35e/protob/types.proto#L89
    messages = {
        3: _("Confirm the transaction output on your {} device"),
        4: _("Confirm internal entropy on your {} device to begin"),
        5: _("Write down the seed word shown on your {}"),
        6: _("Confirm on your {} that you want to wipe it clean"),
        7: _("Confirm on your {} device the message to sign"),
        8: _("Confirm the total amount spent and the transaction fee on your "
             "{} device"),
        10: _("Confirm wallet address on your {} device"),
        14: _("Choose on your {} device where to enter your passphrase"),
        'default': _("Check your {} device to continue"),
    }

    def callback_Failure(self, msg):
        # BaseClient's unfortunate call() implementation forces us to
        # raise exceptions on failure in order to unwind the stack.
        # However, making the user acknowledge they cancelled
        # gets old very quickly, so we suppress those.  The NotInitialized
        # one is misnamed and indicates a passphrase request was cancelled.
        if msg.code in (self.types.FailureType.PinCancelled,
                        self.types.FailureType.ActionCancelled,
                        self.types.FailureType.NotInitialized):
            raise UserCancelled()
        raise RuntimeError(msg.message)

    def callback_ButtonRequest(self, msg):
        message = self.msg
        if not message:
            message = self.messages.get(msg.code, self.messages['default'])
        self.handler.show_message(message.format(self.device), self.cancel)
        return self.proto.ButtonAck()

    def callback_PinMatrixRequest(self, msg):
        if msg.type == 2:
            msg = _("Enter a new PIN for your {}:")
        elif msg.type == 3:
            msg = (_("Re-enter the new PIN for your {}.\n\n"
                     "NOTE: the positions of the numbers have changed!"))
        else:
            msg = _("Enter your current {} PIN:")
        pin = self.handler.get_pin(msg.format(self.device))
        if len(pin) > 9:
            self.handler.show_error(_('The PIN cannot be longer than 9 characters.'))
            pin = ''  # to cancel below
        if not pin:
            return self.proto.Cancel()
        return self.proto.PinMatrixAck(pin=pin)

    def callback_PassphraseRequest(self, req):
        if req and hasattr(req, 'on_device') and req.on_device is True:
            return self.proto.PassphraseAck()

        if self.creating_wallet:
            msg = _("Enter a passphrase to generate this wallet.  Each time "
                    "you use this wallet your {} will prompt you for the "
                    "passphrase.  If you forget the passphrase you cannot "
                    "access the bitcoins in the wallet.").format(self.device)
        else:
            msg = _("Enter the passphrase to unlock this wallet:")
        passphrase = self.handler.get_passphrase(msg, self.creating_wallet)
        if passphrase is None:
            return self.proto.Cancel()
        passphrase = bip39_normalize_passphrase(passphrase)

        ack = self.proto.PassphraseAck(passphrase=passphrase)
        length = len(ack.passphrase)
        if length > 50:
            self.handler.show_error(_("Too long passphrase ({} > 50 chars).").format(length))
            return self.proto.Cancel()
        return ack

    def callback_PassphraseStateRequest(self, msg):
        return self.proto.PassphraseStateAck()

    def callback_WordRequest(self, msg):
        self.step += 1
        msg = _("Step {}/24.  Enter seed word as explained on "
                "your {}:").format(self.step, self.device)
        word = self.handler.get_word(msg)
        # Unfortunately the device can't handle self.proto.Cancel()
        return self.proto.WordAck(word=word)


class SafeTClientBase(GuiMixin, Logger):

    def __init__(self, handler, plugin, proto):
        assert hasattr(self, 'tx_api')  # ProtocolMixin already constructed?
        self.proto = proto
        self.device = plugin.device
        self.handler = handler
        self.tx_api = plugin
        self.types = plugin.types
        self.msg = None
        self.creating_wallet = False
        Logger.__init__(self)
        self.used()

    def __str__(self):
        return "%s/%s" % (self.label(), self.features.device_id)

    def label(self):
        '''The name given by the user to the device.'''
        return self.features.label

    def is_initialized(self):
        '''True if initialized, False if wiped.'''
        return self.features.initialized

    def is_pairable(self):
        return not self.features.bootloader_mode

    def has_usable_connection_with_device(self):
        try:
            res = self.ping("electrum pinging device")
            assert res == "electrum pinging device"
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
            self.logger.info("timed out")
            self.clear_session()

    @staticmethod
    def expand_path(n):
        return convert_bip32_path_to_list_of_uint32(n)

    def cancel(self):
        '''Provided here as in keepkeylib but not safetlib.'''
        self.transport.write(self.proto.Cancel())

    def i4b(self, x):
        return pack('>I', x)

    def get_xpub(self, bip32_path, xtype):
        address_n = self.expand_path(bip32_path)
        creating = False
        node = self.get_public_node(address_n, creating).node
        return BIP32Node(xtype=xtype,
                         eckey=ecc.ECPubkey(node.public_key),
                         chaincode=node.chain_code,
                         depth=node.depth,
                         fingerprint=self.i4b(node.fingerprint),
                         child_number=self.i4b(node.child_num)).to_xpub()

    def toggle_passphrase(self):
        if self.features.passphrase_protection:
            self.msg = _("Confirm on your {} device to disable passphrases")
        else:
            self.msg = _("Confirm on your {} device to enable passphrases")
        enabled = not self.features.passphrase_protection
        self.apply_settings(use_passphrase=enabled)

    def change_label(self, label):
        self.msg = _("Confirm the new label on your {} device")
        self.apply_settings(label=label)

    def change_homescreen(self, homescreen):
        self.msg = _("Confirm on your {} device to change your home screen")
        self.apply_settings(homescreen=homescreen)

    def set_pin(self, remove):
        if remove:
            self.msg = _("Confirm on your {} device to disable PIN protection")
        elif self.features.pin_protection:
            self.msg = _("Confirm on your {} device to change your PIN")
        else:
            self.msg = _("Confirm on your {} device to set a PIN")
        self.change_pin(remove)

    def clear_session(self):
        '''Clear the session to force pin (and passphrase if enabled)
        re-entry.  Does not leak exceptions.'''
        self.logger.info(f"clear session: {self}")
        self.prevent_timeouts()
        try:
            super(SafeTClientBase, self).clear_session()
        except BaseException as e:
            # If the device was removed it has the same effect...
            self.logger.info(f"clear_session: ignoring error {e}")

    def get_public_node(self, address_n, creating):
        self.creating_wallet = creating
        return super(SafeTClientBase, self).get_public_node(address_n)

    def close(self):
        '''Called when Our wallet was closed or the device removed.'''
        self.logger.info("closing client")
        self.clear_session()
        # Release the device
        self.transport.close()

    def firmware_version(self):
        f = self.features
        return (f.major_version, f.minor_version, f.patch_version)

    def atleast_version(self, major, minor=0, patch=0):
        return self.firmware_version() >= (major, minor, patch)

    @staticmethod
    def wrapper(func):
        '''Wrap methods to clear any message box they opened.'''

        def wrapped(self, *args, **kwargs):
            try:
                self.prevent_timeouts()
                return func(self, *args, **kwargs)
            finally:
                self.used()
                self.handler.finished()
                self.creating_wallet = False
                self.msg = None

        return wrapped

    @staticmethod
    def wrap_methods(cls):
        for method in ['apply_settings', 'change_pin',
                       'get_address', 'get_public_node',
                       'load_device_by_mnemonic', 'load_device_by_xprv',
                       'recovery_device', 'reset_device', 'sign_message',
                       'sign_tx', 'wipe_device']:
            setattr(cls, method, cls.wrapper(getattr(cls, method)))
