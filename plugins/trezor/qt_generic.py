from unicodedata import normalize
import threading

from PyQt4.Qt import QVBoxLayout, QLabel, SIGNAL
import PyQt4.QtCore as QtCore
from electrum_ltc_gui.qt.main_window import ElectrumWindow
from electrum_ltc_gui.qt.installwizard import InstallWizard
from electrum_ltc_gui.qt.password_dialog import PasswordDialog
from electrum_ltc_gui.qt.util import *

from electrum_ltc.i18n import _

class QtHandler:
    '''An interface between the GUI (here, QT) and the device handling
    logic for handling I/O.  This is a generic implementation of the
    Trezor protocol; derived classes can customize it.'''

    # Derived classes must provide:
    #   device      a string, e.g. "Trezor"
    #   pin_matrix_widget_class

    def __init__(self, win):
        win.connect(win, SIGNAL('message_done'), self.dialog_stop)
        win.connect(win, SIGNAL('message_dialog'), self.message_dialog)
        win.connect(win, SIGNAL('pin_dialog'), self.pin_dialog)
        win.connect(win, SIGNAL('passphrase_dialog'), self.passphrase_dialog)
        self.win = win
        self.done = threading.Event()
        self.dialog = None

    def stop(self):
        self.win.emit(SIGNAL('message_done'))

    def show_message(self, msg, cancel_callback=None):
        self.win.emit(SIGNAL('message_dialog'), msg, cancel_callback)

    def get_pin(self, msg):
        self.done.clear()
        self.win.emit(SIGNAL('pin_dialog'), msg)
        self.done.wait()
        return self.response

    def get_passphrase(self, msg):
        self.done.clear()
        self.win.emit(SIGNAL('passphrase_dialog'), msg)
        self.done.wait()
        return self.passphrase

    def pin_dialog(self, msg):
        d = WindowModalDialog(self.win, _("Enter PIN"))
        matrix = self.pin_matrix_widget_class()
        vbox = QVBoxLayout()
        vbox.addWidget(QLabel(msg))
        vbox.addWidget(matrix)
        vbox.addLayout(Buttons(CancelButton(d), OkButton(d)))
        d.setLayout(vbox)
        if not d.exec_():
            self.response = None  # FIXME: this is lost?
        self.response = str(matrix.get_value())
        self.done.set()

    def passphrase_dialog(self, msg):
        if type(self.win) is ElectrumWindow:
            msg = _("Please enter your %s passphrase") % self.device
            passphrase = self.win.password_dialog(msg)
        else:
            assert type(self.win) is InstallWizard
            d = PasswordDialog(self.win, None, None, msg, False)
            confirmed, p, passphrase = d.run()

        if passphrase is None:
            self.win.show_critical(_("Passphrase request canceled"))
        else:
            passphrase = normalize('NFKD', unicode(passphrase))
        self.passphrase = passphrase
        self.done.set()

    def message_dialog(self, msg, cancel_callback):
        # Called more than once during signing, to confirm output and fee
        self.dialog_stop()
        msg = _('Please check your %s Device') % self.device
        dialog = self.dialog = WindowModalDialog(self.win, msg)
        l = QLabel(msg)
        vbox = QVBoxLayout(dialog)
        if cancel_callback:
            vbox.addLayout(Buttons(CancelButton(dialog)))
            dialog.connect(dialog, SIGNAL('rejected()'), cancel_callback)
        vbox.addWidget(l)
        dialog.show()

    def dialog_stop(self):
        if self.dialog:
            self.dialog.hide()
            self.dialog = None
