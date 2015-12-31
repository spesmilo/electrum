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
    }

    def callback_ButtonRequest(self, msg):
        msg_code = self.msg_code_override or msg.code
        message = self.messages.get(msg_code, self.messages['default'])

        if msg.code in [3, 8] and hasattr(self, 'cancel'):
            cancel_callback = self.cancel
        else:
            cancel_callback = None

        self.handler.show_message(message % self.device, cancel_callback)
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
        pin = self.handler.get_pin(msg % self.device)
        if not pin:
            return self.proto.Cancel()
        return self.proto.PinMatrixAck(pin=pin)

    def callback_PassphraseRequest(self, req):
        msg = _("Please enter your %s passphrase")
        passphrase = self.handler.get_passphrase(msg % self.device)
        if passphrase is None:
            return self.proto.Cancel()
        return self.proto.PassphraseAck(passphrase=passphrase)

    def callback_WordRequest(self, msg):
        # TODO
        stderr.write("Enter one word of mnemonic:\n")
        stderr.flush()
        word = raw_input()
        return self.proto.WordAck(word=word)


def trezor_client_class(protocol_mixin, base_client, proto):
    '''Returns a class dynamically.'''

    class TrezorClient(protocol_mixin, GuiMixin, base_client, PrintError):

        def __init__(self, transport, plugin):
            base_client.__init__(self, transport)
            protocol_mixin.__init__(self, transport)
            self.proto = proto
            self.device = plugin.device
            self.handler = None
            self.plugin = plugin
            self.tx_api = plugin
            self.bad = False
            self.msg_code_override = None
            self.proper_device = False
            self.checked_device = False

        def check_proper_device(self, wallet):
            try:
                self.ping('t')
            except BaseException as e:
                self.plugin.give_error(
                    __("%s device not detected.  Continuing in watching-only "
                       "mode.") % self.device + "\n\n" + str(e))
            if not self.is_proper_device(wallet):
                self.plugin.give_error(_('Wrong device or password'))

        def is_proper_device(self, wallet):
            if not self.checked_device:
                addresses = wallet.addresses(False)
                if not addresses:   # Wallet being created?
                    return True

                address = addresses[0]
                address_id = wallet.address_id(address)
                path = self.expand_path(address_id)
                self.checked_device = True
                try:
                    device_address = self.get_address('Bitcoin', path)
                    self.proper_device = (device_address == address)
                except:
                    self.proper_device = False
                wallet.proper_device = self.proper_device

            return self.proper_device

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

        def firmware_version(self):
            f = self.features
            return (f.major_version, f.minor_version, f.patch_version)

        def atleast_version(self, major, minor=0, patch=0):
            return cmp(self.firmware_version(), (major, minor, patch))

        def call_raw(self, msg):
            try:
                return base_client.call_raw(self, msg)
            except:
                self.print_error("Marking %s client bad" % self.device)
                self.bad = True
                raise

    return TrezorClient
