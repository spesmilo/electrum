from PyQt4.Qt import QApplication, QMessageBox, QDialog, QInputDialog, QLineEdit, QVBoxLayout, QLabel, QThread, SIGNAL
import PyQt4.QtCore as QtCore
from electrum_ltc_gui.qt.password_dialog import make_password_dialog, run_password_dialog

class Plugin(LedgerPlugin):

    @hook
    def load_wallet(self, wallet, window):
        self.wallet = wallet
        self.wallet.plugin = self
        if self.handler is None:
            self.handler = BTChipQTHandler(window)
        if self.btchip_is_connected():
            if not self.wallet.check_proper_device():
                QMessageBox.information(window, _('Error'), _("This wallet does not match your Ledger device"), _('OK'))
                self.wallet.force_watching_only = True
        else:
            QMessageBox.information(window, _('Error'), _("Ledger device not detected.\nContinuing in watching-only mode."), _('OK'))
            self.wallet.force_watching_only = True


class BTChipQTHandler:

    def __init__(self, win):
        self.win = win
        self.win.connect(win, SIGNAL('btchip_done'), self.dialog_stop)
        self.win.connect(win, SIGNAL('btchip_message_dialog'), self.message_dialog)
        self.win.connect(win, SIGNAL('btchip_auth_dialog'), self.auth_dialog)
        self.done = threading.Event()

    def stop(self):
        self.win.emit(SIGNAL('btchip_done'))

    def show_message(self, msg):
        self.message = msg
        self.win.emit(SIGNAL('btchip_message_dialog'))

    def prompt_auth(self, msg):
        self.done.clear()
        self.message = msg
        self.win.emit(SIGNAL('btchip_auth_dialog'))
        self.done.wait()
        return self.response

    def auth_dialog(self):
        response = QInputDialog.getText(None, "Ledger Wallet Authentication", self.message, QLineEdit.Password)
        if not response[1]:
            self.response = None
        else:
            self.response = str(response[0])
        self.done.set()

    def message_dialog(self):
        self.d = QDialog()
        self.d.setModal(1)
        self.d.setWindowTitle('Ledger')
        self.d.setWindowFlags(self.d.windowFlags() | QtCore.Qt.WindowStaysOnTopHint)
        l = QLabel(self.message)
        vbox = QVBoxLayout(self.d)
        vbox.addWidget(l)
        self.d.show()

    def dialog_stop(self):
        if self.d is not None:
            self.d.hide()
            self.d = None
