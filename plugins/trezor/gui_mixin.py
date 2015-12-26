from sys import stderr

from electrum.i18n import _

class GuiMixin(object):
    # Requires: self.protcol, self.device

    def __init__(self, *args, **kwargs):
        super(GuiMixin, self).__init__(*args, **kwargs)

    def callback_ButtonRequest(self, msg):
        if msg.code == 3:
            message = _("Confirm transaction outputs on %s device to continue")
        elif msg.code == 8:
            message = _("Confirm transaction fee on %s device to continue")
        elif msg.code == 7:
            message = _("Confirm message to sign on %s device to continue")
        elif msg.code == 10:
            message = _("Confirm address on %s device to continue")
        else:
            message = _("Check %s device to continue")

        if msg.code in [3, 8] and hasattr(self, 'cancel'):
            cancel_callback = self.cancel
        else:
            cancel_callback = None

        self.handler.show_message(message % self.device, cancel_callback)
        return self.protocol.ButtonAck()

    def callback_PinMatrixRequest(self, msg):
        if msg.type == 1:
            msg = _("Please enter %s current PIN")
        elif msg.type == 2:
            msg = _("Please enter %s new PIN")
        elif msg.type == 3:
            msg = _("Please enter %s new PIN again")
        else:
            msg = _("Please enter %s PIN")
        pin = self.handler.get_pin(msg % self.device)
        if not pin:
            return self.protocol.Cancel()
        return self.protocol.PinMatrixAck(pin=pin)

    def callback_PassphraseRequest(self, req):
        msg = _("Please enter your %s passphrase")
        passphrase = self.handler.get_passphrase(msg % self.device)
        if passphrase is None:
            return self.protocol.Cancel()
        return self.protocol.PassphraseAck(passphrase=passphrase)

    def callback_WordRequest(self, msg):
        #TODO
        stderr.write("Enter one word of mnemonic:\n")
        stderr.flush()
        word = raw_input()
        return self.protocol.WordAck(word=word)
