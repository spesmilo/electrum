from PyQt4.Qt import QVBoxLayout, QDialog, QMessageBox
from PyQt4.QtGui import QLabel
from sys import stderr
from trezorlib.client import proto, BaseClient, ProtocolMixin
from trezorlib.pinmatrix import PinMatrixWidget

from electrum.i18n import _
from gui.qt.util import ok_cancel_buttons


def log(msg):
    stderr.write("%s\n" % msg)
    stderr.flush()

class TrezorQtGuiMixin(object):

    def __init__(self, *args, **kwargs):
        super(TrezorQtGuiMixin, self).__init__(*args, **kwargs)

    @staticmethod
    def alert(msg):
        QMessageBox.critical(None, _('Error'), msg, _('OK'))

    def callback_ButtonRequest(self, msg):
        i = QMessageBox.question(None, _('Trezor'), _("Please check request on Trezor's screen"), _('OK'), _('Cancel'))
        if i == 0:
            return proto.ButtonAck()
        return proto.Cancel()    

    def callback_PinMatrixRequest(self, msg):
        if msg.type == 1:
            desc = 'old PIN'
        elif msg.type == 2:
            desc = 'new PIN'
        elif msg.type == 3:
            desc = 'new PIN again'
        else:
            desc = 'PIN'

        pin = self.pin_dialog(msg="Please enter Trezor %s" % desc)
        if not pin:
            return proto.Cancel()
        return proto.PinMatrixAck(pin=pin)

    def callback_PassphraseRequest(self, msg):
        passphrase = self.password_dialog()
        if passphrase is None:
            QMessageBox.critical(None, _('Error'), _("Password request canceled"), _('OK'))
            return proto.Cancel()
        return proto.PassphraseAck(passphrase=passphrase)

    def callback_WordRequest(self, msg):
        #TODO
        log("Enter one word of mnemonic: ")
        word = raw_input()
        return proto.WordAck(word=word)

    def password_dialog(self, msg=None):
        if not msg:
            msg = _("Please enter your Trezor password")
        else:
            msg = _(msg)
        from password_dialog import make_password_dialog, run_password_dialog
        d = QDialog()
        d.setModal(1)
        d.setLayout( make_password_dialog(d, None, msg, False) )
        return run_password_dialog(d, None, None)[2]

    def pin_dialog(self, msg):
        d = QDialog(None)
        d.setModal(1)
        d.setWindowTitle(_("Enter PIN"))
        matrix = PinMatrixWidget()

        vbox = QVBoxLayout()
        vbox.addWidget(QLabel(msg))
        vbox.addWidget(matrix)
        vbox.addLayout(ok_cancel_buttons(d))
        d.setLayout(vbox)

        if not d.exec_(): return
        return str(matrix.get_value())

class QtGuiTrezorClient(ProtocolMixin, TrezorQtGuiMixin, BaseClient):
    pass
