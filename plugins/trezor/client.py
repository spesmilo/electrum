from sys import stderr

from electrum.i18n import _
from electrum.util import PrintError


class GuiMixin(object):
    # Requires: self.proto, self.device

    messages = {
        3: _("Confirm transaction outputs on %s device to continue"),
        8: _("Confirm transaction fee on %s device to continue"),
        7: _("Confirm message to sign on %s device to continue"),
        10: _("Confirm address on %s device to continue"),
        'change pin': _("Confirm PIN change on %s device to continue"),
        'default': _("Check %s device to continue"),
        'label': _("Confirm label change on %s device to continue"),
        'remove pin': _("Confirm removal of PIN on %s device to continue"),
        'passphrase': _("Confirm on %s device to continue"),
    }

    def callback_ButtonRequest(self, msg):
        msg_code = self.msg_code_override or msg.code
        message = self.messages.get(msg_code, self.messages['default'])

        if msg.code in [3, 8] and hasattr(self, 'cancel'):
            cancel_callback = self.cancel
        else:
            cancel_callback = None

        self.handler().show_message(message % self.device, cancel_callback)
        return self.proto.ButtonAck()

    def callback_PinMatrixRequest(self, msg):
        if msg.type == 1:
            msg = _("Enter your current %s PIN:")
        elif msg.type == 2:
            msg = _("Enter a new %s PIN:")
        elif msg.type == 3:
            msg = (_("Please re-enter your new %s PIN.\n"
                     "Note the numbers have been shuffled!"))
        else:
            msg = _("Please enter %s PIN")
        pin = self.handler().get_pin(msg % self.device)
        if not pin:
            return self.proto.Cancel()
        return self.proto.PinMatrixAck(pin=pin)

    def callback_PassphraseRequest(self, req):
        msg = _("Please enter your %s passphrase")
        passphrase = self.handler().get_passphrase(msg % self.device)
        if passphrase is None:
            return self.proto.Cancel()
        return self.proto.PassphraseAck(passphrase=passphrase)

    def callback_WordRequest(self, msg):
        msg = _("Enter seed word as explained on your %s") % self.device
        word = self.handler().get_word(msg)
        if word is None:
            return self.proto.Cancel()
        return self.proto.WordAck(word=word)


def trezor_client_class(protocol_mixin, base_client, proto):
    '''Returns a class dynamically.'''

    class TrezorClient(protocol_mixin, GuiMixin, base_client, PrintError):

        def __init__(self, transport, path, plugin):
            base_client.__init__(self, transport)
            protocol_mixin.__init__(self, transport)
            self.proto = proto
            self.device = plugin.device
            self.path = path
            self.wallet = None
            self.plugin = plugin
            self.tx_api = plugin
            self.msg_code_override = None

        def __str__(self):
            return "%s/%s/%s" % (self.label(), self.device_id(), self.path)

        def label(self):
            '''The name given by the user to the device.'''
            return self.features.label

        def device_id(self):
            '''The device serial number.'''
            return self.features.device_id

        def is_initialized(self):
            '''True if initialized, False if wiped.'''
            return self.features.initialized

        def pair_wallet(self, wallet):
            self.wallet = wallet

        def handler(self):
            assert self.wallet and self.wallet.handler
            return self.wallet.handler

        # Copied from trezorlib/client.py as there it is not static, sigh
        @staticmethod
        def expand_path(n):
            '''Convert bip32 path to list of uint32 integers with prime flags
            0/-1/1' -> [0, 0x80000001, 0x80000001]'''
            path = []
            for x in n.split('/'):
                prime = 0
                if x.endswith("'"):
                    x = x.replace('\'', '')
                    prime = TrezorClient.PRIME_DERIVATION_FLAG
                if x.startswith('-'):
                    prime = TrezorClient.PRIME_DERIVATION_FLAG
                path.append(abs(int(x)) | prime)
            return path

        def first_address(self, wallet, derivation):
            assert not self.wallet
            # Assign the wallet so we have a handler
            self.wallet = wallet
            try:
                return self.address_from_derivation(derivation)
            finally:
                self.wallet = None

        def address_from_derivation(self, derivation):
            return self.get_address('Bitcoin', self.expand_path(derivation))

        def toggle_passphrase(self):
            self.msg_code_override = 'passphrase'
            try:
                enabled = not self.features.passphrase_protection
                self.apply_settings(use_passphrase=enabled)
            finally:
                self.msg_code_override = None

        def change_label(self, label):
            self.msg_code_override = 'label'
            try:
                self.apply_settings(label=label)
            finally:
                self.msg_code_override = None

        def set_pin(self, remove):
            self.msg_code_override = 'remove pin' if remove else 'change pin'
            try:
                self.change_pin(remove)
            finally:
                self.msg_code_override = None

        def clear_session(self):
            '''Clear the session to force pin (and passphrase if enabled)
            re-entry.  Does not leak exceptions.'''
            self.print_error("clear session:", self)
            try:
                super(TrezorClient, self).clear_session()
            except BaseException as e:
                # If the device was removed it has the same effect...
                self.print_error("clear_session: ignoring error", str(e))
                pass

        def close(self):
            '''Called when Our wallet was closed or the device removed.'''
            self.print_error("disconnected")
            self.clear_session()
            # Release the device
            self.transport.close()

        def firmware_version(self):
            f = self.features
            return (f.major_version, f.minor_version, f.patch_version)

        def atleast_version(self, major, minor=0, patch=0):
            return cmp(self.firmware_version(), (major, minor, patch))


    def wrapper(func):
        '''Wrap base class methods to show exceptions and clear
        any dialog box it opened.'''

        def wrapped(self, *args, **kwargs):
            handler = self.handler()
            try:
                return func(self, *args, **kwargs)
            except BaseException as e:
                handler.show_error(str(e))
                raise e
            finally:
                handler.finished()

        return wrapped

    cls = TrezorClient
    for method in ['apply_settings', 'change_pin', 'get_address',
                   'get_public_node', 'load_device_by_mnemonic',
                   'load_device_by_xprv', 'recovery_device',
                   'reset_device', 'sign_message', 'sign_tx', 'wipe_device']:
        setattr(cls, method, wrapper(getattr(cls, method)))

    return cls
