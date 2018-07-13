from functools import partial
import traceback
import sys

from PyQt5.QtGui import *
from PyQt5.QtCore import *
from PyQt5.QtWidgets import (QHBoxLayout, QLabel, QVBoxLayout)

from electrum_ltc.plugin import hook
from electrum_ltc.i18n import _
from electrum_ltc.gui.qt import EnterButton
from electrum_ltc.gui.qt.util import ThreadedButton, Buttons
from electrum_ltc.gui.qt.util import WindowModalDialog, OkButton

from .labels import LabelsPlugin


class QLabelsSignalObject(QObject):
    labels_changed_signal = pyqtSignal(object)


class Plugin(LabelsPlugin):

    def __init__(self, *args):
        LabelsPlugin.__init__(self, *args)
        self.obj = QLabelsSignalObject()

    def requires_settings(self):
        return True

    def settings_widget(self, window):
        return EnterButton(_('Settings'),
                           partial(self.settings_dialog, window))

    def settings_dialog(self, window):
        wallet = window.parent().wallet
        d = WindowModalDialog(window, _("Label Settings"))
        hbox = QHBoxLayout()
        hbox.addWidget(QLabel("Label sync options:"))
        upload = ThreadedButton("Force upload",
                                partial(self.push_thread, wallet),
                                partial(self.done_processing_success, d),
                                partial(self.done_processing_error, d))
        download = ThreadedButton("Force download",
                                  partial(self.pull_thread, wallet, True),
                                  partial(self.done_processing_success, d),
                                  partial(self.done_processing_error, d))
        vbox = QVBoxLayout()
        vbox.addWidget(upload)
        vbox.addWidget(download)
        hbox.addLayout(vbox)
        vbox = QVBoxLayout(d)
        vbox.addLayout(hbox)
        vbox.addSpacing(20)
        vbox.addLayout(Buttons(OkButton(d)))
        return bool(d.exec_())

    def on_pulled(self, wallet):
        self.obj.labels_changed_signal.emit(wallet)

    def done_processing_success(self, dialog, result):
        dialog.show_message(_("Your labels have been synchronised."))

    def done_processing_error(self, dialog, result):
        traceback.print_exception(*result, file=sys.stderr)
        dialog.show_error(_("Error synchronising labels") + ':\n' + str(result[:2]))

    @hook
    def load_wallet(self, wallet, window):
        # FIXME if the user just enabled the plugin, this hook won't be called
        # as the wallet is already loaded, and hence the plugin will be in
        # a non-functional state for that window
        self.obj.labels_changed_signal.connect(window.update_tabs)
        self.start_wallet(wallet)

    @hook
    def on_close_window(self, window):
        self.stop_wallet(window.wallet)
