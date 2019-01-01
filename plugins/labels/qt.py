from functools import partial

from PyQt5.QtGui import *
from PyQt5.QtCore import *
from PyQt5.QtWidgets import (QHBoxLayout, QLabel, QVBoxLayout)

from electroncash.plugins import hook
from electroncash.i18n import _
from electroncash_gui.qt import EnterButton
from electroncash_gui.qt.main_window import ElectrumWindow
from electroncash_gui.qt.util import ThreadedButton, Buttons
from electroncash_gui.qt.util import WindowModalDialog, OkButton, WaitingDialog
from electroncash.util import Weak

from .labels import LabelsPlugin


class LabelsSignalObject(QObject):
    ''' Signals need to be members of a QObject, hence why this class exists. '''
    labels_changed_signal = pyqtSignal(object)
    wallet_not_synched_signal = pyqtSignal(object)
    request_exception_signal = pyqtSignal(object, object)


def window_parent(w):
    # this is needed because WindowModalDialog overrides window.parent
    if callable(w.parent): return w.parent()
    return w.parent

class Plugin(LabelsPlugin):

    def __init__(self, *args):
        LabelsPlugin.__init__(self, *args)
        self.obj = LabelsSignalObject()
        self.wallet_windows = {}
        self.initted = False

    def requires_settings(self):
        return True

    def settings_widget(self, window):
        while window and window_parent(window) and not isinstance(window_parent(window), ElectrumWindow):
            # MacOS fixup -- find window.parent() because we can end up with window.parent() not an ElectrumWindow
            window = window_parent(window)
        windowRef = Weak.ref(window)
        return EnterButton(_('Settings'),
                           partial(self.settings_dialog, windowRef))

    def settings_dialog(self, windowRef):
        window = windowRef() # NB: window is the internal plugins dialog and not the wallet window
        if not window or not isinstance(window_parent(window), ElectrumWindow): return
        wallet = window_parent(window).wallet
        d = WindowModalDialog(window.top_level_window(), _("Label Settings"))
        d.ok_button = OkButton(d)
        dlgRef = Weak.ref(d)
        if wallet in self.wallets:
            class MySigs(QObject):
                ok_button_disable_sig = pyqtSignal(bool)
            d.sigs = MySigs(d)
            d.sigs.ok_button_disable_sig.connect(d.ok_button.setDisabled) # disable ok button while the TaskThread runs ..
            hbox = QHBoxLayout()
            hbox.addWidget(QLabel(_("LabelSync options:")))
            upload = ThreadedButton("Force upload",
                                    partial(Weak(self.do_force_upload), wallet, dlgRef),
                                    partial(Weak(self.done_processing), dlgRef),
                                    partial(Weak(self.error_processing), dlgRef))
            download = ThreadedButton("Force download",
                                      partial(Weak(self.do_force_download), wallet, dlgRef),
                                      partial(Weak(self.done_processing), dlgRef),
                                      partial(Weak(self.error_processing), dlgRef))
            d.thread_buts = (upload, download)
            d.finished.connect(partial(Weak(self.on_dlg_finished), dlgRef))
            vbox = QVBoxLayout()
            vbox.addWidget(upload)
            vbox.addWidget(download)
            hbox.addLayout(vbox)
            vbox = QVBoxLayout(d)
            vbox.addLayout(hbox)
        else:
            vbox = QVBoxLayout(d)
            if wallet.network:
                # has network, so the fact that the wallet isn't in the list means it's incompatible
                l = QLabel('<b>' + _("LabelSync not supported for this wallet type") + '</b>')
                l.setAlignment(Qt.AlignCenter)
                vbox.addWidget(l)
                l = QLabel(_("(Only deterministic wallets are supported)"))
                l.setAlignment(Qt.AlignCenter)
                vbox.addWidget(l)
            else:
                # Does not have network, so we won't speak of incompatibility, but instead remind user offline mode means OFFLINE! ;)
                l = QLabel(_("You are using Electron Cash in offline mode; restart Electron Cash if you want to get connected"))
                l.setWordWrap(True)
                vbox.addWidget(l)
        vbox.addSpacing(20)
        vbox.addLayout(Buttons(d.ok_button))
        return bool(d.exec_())
    
    def on_dlg_finished(self, dlgRef, result_code):
        ''' Wait for any threaded buttons that may be still extant so we don't get a crash '''
        #self.print_error("Dialog finished with code", result_code)
        dlg = dlgRef()
        if dlg:
            upload, download = dlg.thread_buts
            if upload.thread and upload.thread.isRunning():
                upload.thread.stop(); upload.thread.wait()
            if download.thread and download.thread.isRunning():
                download.thread.stop(); download.thread.wait()

    def do_force_upload(self, wallet, dlgRef):
        # this runs in a NON-GUI thread
        dlg = dlgRef()
        if dlg: dlg.sigs.ok_button_disable_sig.emit(True) # block window closing prematurely which can cause a temporary hang until thread completes
        self.push_thread(wallet)

    def do_force_download(self, wallet, dlgRef):
        # this runs in a NON-GUI thread
        dlg = dlgRef()
        if dlg: dlg.sigs.ok_button_disable_sig.emit(True) # block window closing prematurely which can cause a temporary hang until thread completes
        self.pull_thread(wallet, True)

    def done_processing(self, dlgRef, result):
        # this runs in the GUI thread
        dlg = dlgRef()
        if dlg:
            dlg.ok_button.setEnabled(True)
            self._ok_synched(dlg)

    def _ok_synched(self, window):
        if window.isVisible():
            window.show_message(_("Your labels have been synchronised."))

    def error_processing(self, dlgRef, exc_info):
        dlg = dlgRef()
        if dlg:
            dlg.ok_button.setEnabled(True)
            self._notok_synch(dlg, exc_info)

    def _notok_synch(self, window, exc_info):
        if window.isVisible():
            window.show_warning(_("LabelSync error:") + "\n\n" + str(exc_info[1]))

    def on_request_exception(self, wallet, exc_info):
        # not main thread
        self.obj.request_exception_signal.emit(wallet, exc_info)

    def request_exception_slot(self, wallet, exc_info):
        # main thread
        window = self.wallet_windows.get(wallet, None)
        if window: self._notok_synch(window, exc_info)

    def start_wallet(self, wallet, window=None):
        ret = super().start_wallet(wallet)
        if ret and window:
            self.wallet_windows[wallet] = window
        return ret

    def stop_wallet(self, wallet):
        ret = super().stop_wallet(wallet)
        window = self.wallet_windows.pop(wallet, None)
        return ret

    def on_pulled(self, wallet):
        # not main thread
        super().on_pulled(wallet) # super just logs to print_error
        self.obj.labels_changed_signal.emit(wallet)

    def on_labels_changed(self, wallet):
        # main thread
        window = self.wallet_windows.get(wallet, None)
        if window:
            #self.print_error("On labels changed", wallet.basename())
            window.update_labels()

    def on_wallet_not_synched(self, wallet):
        # not main thread
        self.obj.wallet_not_synched_signal.emit(wallet)

    def wallet_not_synched_slot(self, wallet):
        # main thread
        window = self.wallet_windows.get(wallet, None)
        if window:
            if window.question(_("LabelSync detected that this wallet is not synched with the label server.")
                               + "\n\n" + _("Synchronize now?")):
                WaitingDialog(window, _("Synchronizing..."),
                              partial(self.pull_thread, wallet, True),
                              lambda *args: self._ok_synched(window),
                              lambda exc: self._notok_synch(window, exc))

    def on_close(self):
        if not self.initted:
            return
        try: self.obj.labels_changed_signal.disconnect(self.on_labels_changed)
        except TypeError: pass # not connected
        try: self.obj.wallet_not_synched_signal.disconnect(self.wallet_not_synched_slot)
        except TypeError: pass # not connected
        try: self.obj.request_exception_signal.disconnect(self.request_exception_slot)
        except TypeError: pass # not connected
        super().on_close()
        assert 0==len(self.wallet_windows), "LabelSync still had extant wallet_windows!"
        self.initted = False

    @hook
    def on_new_window(self, window):
        return self.start_wallet(window.wallet, window)

    @hook
    def on_close_window(self, window):
        return self.stop_wallet(window.wallet)

    @hook
    def init_qt(self, gui):
        if self.initted:
            return
        self.on_init()
        # connect signals. this needs to happen first as below on_new_window depends on these being active
        self.obj.labels_changed_signal.connect(self.on_labels_changed)
        self.obj.wallet_not_synched_signal.connect(self.wallet_not_synched_slot)
        self.obj.request_exception_signal.connect(self.request_exception_slot)

        ct, ct2 = 0, 0
        for window in gui.windows:
            if self.on_new_window(window):
                ct2 += 1
            ct += 1

        self.initted = True
        self.print_error("Initialized (had {} extant windows, added {}).".format(ct,ct2))

