import threading
from functools import partial

from PyQt4.QtGui import *
from PyQt4.QtCore import *
import PyQt4.QtCore as QtCore
import PyQt4.QtGui as QtGui

from electrum_ltc.plugins import hook
from electrum_ltc.i18n import _
from electrum_ltc_gui.qt import HelpButton, EnterButton
from electrum_ltc_gui.qt.util import ThreadedButton, Buttons, CancelButton, OkButton

from labels import LabelsPlugin


class Plugin(LabelsPlugin):

    def __init__(self, *args):
        LabelsPlugin.__init__(self, *args)
        self.obj = QObject()

    def requires_settings(self):
        return True

    def settings_widget(self, window):
        return EnterButton(_('Settings'),
                           partial(self.settings_dialog, window))

    def settings_dialog(self, window):
        d = QDialog(window)
        vbox = QVBoxLayout(d)
        layout = QGridLayout()
        vbox.addLayout(layout)
        layout.addWidget(QLabel("Label sync options: "), 2, 0)
        self.upload = ThreadedButton("Force upload",
                                     partial(self.push_thread, window.wallet),
                                     self.done_processing)
        layout.addWidget(self.upload, 2, 1)
        self.download = ThreadedButton("Force download",
                                       partial(self.pull_thread, window.wallet, True),
                                       self.done_processing)
        layout.addWidget(self.download, 2, 2)
        self.accept = OkButton(d, _("Done"))
        vbox.addLayout(Buttons(CancelButton(d), self.accept))
        if d.exec_():
            return True
        else:
            return False

    def on_pulled(self, wallet):
        self.obj.emit(SIGNAL('labels_changed'), wallet)

    def done_processing(self):
        QMessageBox.information(None, _("Labels synchronised"),
                                _("Your labels have been synchronised."))

    @hook
    def on_new_window(self, window):
        window.connect(window.app, SIGNAL('labels_changed'), window.update_tabs)
        self.start_wallet(window.wallet)

    @hook
    def on_close_window(self, window):
        self.wallets.pop(window.wallet)

