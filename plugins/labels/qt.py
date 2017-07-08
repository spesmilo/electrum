from functools import partial

from PyQt4.QtGui import *
from PyQt4.QtCore import *

from electrum.plugins import hook
from electrum.i18n import _
from electrum_gui.qt import EnterButton
from electrum_gui.qt.util import ThreadedButton, Buttons
from electrum_gui.qt.util import WindowModalDialog, OkButton

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
        wallet = window.parent().wallet
        d = WindowModalDialog(window, _("Label Settings"))
        hbox = QHBoxLayout()
        hbox.addWidget(QLabel("Label sync options:"))
        upload = ThreadedButton("Force upload",
                                partial(self.push_thread, wallet),
                                partial(self.done_processing, d))
        download = ThreadedButton("Force download",
                                  partial(self.pull_thread, wallet, True),
                                  partial(self.done_processing, d))
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
        self.obj.emit(SIGNAL('labels_changed'), wallet)

    def done_processing(self, dialog, result):
        dialog.show_message(_("Your labels have been synchronised."))

    @hook
    def on_new_window(self, window):
        window.connect(window.app, SIGNAL('labels_changed'), window.update_tabs)
        self.start_wallet(window.wallet)

    @hook
    def on_close_window(self, window):
        self.stop_wallet(window.wallet)
