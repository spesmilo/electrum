from functools import partial
import traceback
import sys
from typing import TYPE_CHECKING

from PyQt6.QtCore import QObject, pyqtSignal
from PyQt6.QtWidgets import (QHBoxLayout, QLabel, QVBoxLayout)

from electrum.plugin import hook
from electrum.i18n import _
from electrum.gui.qt.util import ThreadedButton, Buttons, EnterButton, WindowModalDialog, OkButton

from .labels import LabelsPlugin

if TYPE_CHECKING:
    from electrum.gui.qt import ElectrumGui
    from electrum.gui.qt.main_window import ElectrumWindow
    from electrum.wallet import Abstract_Wallet

class QLabelsSignalObject(QObject):
    labels_changed_signal = pyqtSignal(object)


class Plugin(LabelsPlugin):

    def __init__(self, *args):
        LabelsPlugin.__init__(self, *args)
        self.obj = QLabelsSignalObject()
        self._init_qt_received = False

    def requires_settings(self):
        return True

    def settings_widget(self, window: WindowModalDialog):
        return EnterButton(_('Settings'),
                           partial(self.settings_dialog, window))

    def settings_dialog(self, window: WindowModalDialog):
        wallet = window.parent().wallet
        if not wallet.get_fingerprint():
            window.show_error(_("{} plugin does not support this type of wallet.")
                              .format("Label Sync"))
            return
        d = WindowModalDialog(window, _("Label Settings"))
        hbox = QHBoxLayout()
        hbox.addWidget(QLabel("Label sync options:"))
        upload = ThreadedButton("Force upload",
                                partial(self.push, wallet),
                                partial(self.done_processing_success, d),
                                partial(self.done_processing_error, d))
        download = ThreadedButton("Force download",
                                  partial(self.pull, wallet, True),
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
        return bool(d.exec())

    def on_pulled(self, wallet):
        self.obj.labels_changed_signal.emit(wallet)

    def done_processing_success(self, dialog, result):
        dialog.show_message(_("Your labels have been synchronised."))

    def done_processing_error(self, dialog, exc_info):
        self.logger.error("Error synchronising labels", exc_info=exc_info)
        dialog.show_error(_("Error synchronising labels") + f':\n{repr(exc_info[1])}')

    @hook
    def init_qt(self, gui: 'ElectrumGui'):
        if self._init_qt_received:  # only need/want the first signal
            return
        self._init_qt_received = True
        # If the user just enabled the plugin, the 'load_wallet' hook would not
        # get called for already loaded wallets, hence we call it manually for those:
        for window in gui.windows:
            self.load_wallet(window.wallet, window)

    @hook
    def load_wallet(self, wallet: 'Abstract_Wallet', window: 'ElectrumWindow'):
        self.obj.labels_changed_signal.connect(window.update_tabs)
        self.start_wallet(wallet)

    @hook
    def on_close_window(self, window):
        try:
            self.obj.labels_changed_signal.disconnect(window.update_tabs)
        except TypeError:
            pass  # 'method' object is not connected
        self.stop_wallet(window.wallet)
