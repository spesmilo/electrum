#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2025 The Electrum Developers
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
import threading

from PyQt6.QtCore import pyqtSignal, pyqtSlot

from electrum.i18n import _
from electrum.plugin import hook

from electrum.gui.qml.qewallet import QEWallet
from electrum.gui.common_qt.plugins import PluginQObject

from .labels import LabelsPlugin


class Plugin(LabelsPlugin):

    class QSignalObject(PluginQObject):
        labelsChanged = pyqtSignal()
        uploadSuccess = pyqtSignal()
        uploadFailed = pyqtSignal()
        downloadSuccess = pyqtSignal()
        downloadFailed = pyqtSignal()

        _name = _('LabelSync Plugin')

        def __init__(self, plugin, parent):
            super().__init__(plugin, parent)

        @pyqtSlot(result=str)
        def settingsComponent(self): return '../../../plugins/labels/Labels.qml'

        @pyqtSlot()
        def upload(self):
            assert self.plugin

            self._busy = True
            self.busyChanged.emit()

            self.plugin.push_async()

        def upload_finished(self, result):
            if result:
                self.uploadSuccess.emit()
            else:
                self.uploadFailed.emit()
            self._busy = False
            self.busyChanged.emit()

        @pyqtSlot()
        def download(self):
            assert self.plugin

            self._busy = True
            self.busyChanged.emit()

            self.plugin.pull_async()

        def download_finished(self, result):
            if result:
                self.downloadSuccess.emit()
            else:
                self.downloadFailed.emit()
            self._busy = False
            self.busyChanged.emit()

    def __init__(self, *args):
        LabelsPlugin.__init__(self, *args)
        self._app = None
        self.so = None

    @hook
    def load_wallet(self, wallet):
        self.logger.debug(f'plugin enabled for wallet "{str(wallet)}"')
        self.start_wallet(wallet)

    def push_async(self):
        if not self._app.daemon.currentWallet:
            self.logger.error('No current wallet')
            self.so.download_finished(False)
            return

        wallet = self._app.daemon.currentWallet.wallet

        def push_thread(_wallet):
            try:
                self.push(_wallet)
                self.so.upload_finished(True)
                self._app.appController.userNotify.emit(_('Labels uploaded'))
            except Exception as e:
                self.logger.error(repr(e))
                self.so.upload_finished(False)
                self._app.appController.userNotify.emit(repr(e))

        threading.Thread(target=push_thread, args=[wallet]).start()

    def pull_async(self):
        if not self._app.daemon.currentWallet:
            self.logger.error('No current wallet')
            self.so.download_finished(False)
            return

        wallet = self._app.daemon.currentWallet.wallet

        def pull_thread(_wallet):
            try:
                self.pull(_wallet, True)
                self.so.download_finished(True)
                self._app.appController.userNotify.emit(_('Labels downloaded'))
            except Exception as e:
                self.logger.error(repr(e))
                self.so.download_finished(False)
                self._app.appController.userNotify.emit(repr(e))

        threading.Thread(target=pull_thread, args=[wallet]).start()

    def on_pulled(self, wallet):
        _wallet = QEWallet.getInstanceFor(wallet)
        self.logger.debug('wallet ' + ('found' if _wallet else 'not found'))

    @hook
    def init_qml(self, app):
        self.logger.debug(f'init_qml hook called, gui={str(type(app))}')
        self.logger.debug(f'app={self._app!r}, so={self.so!r}')
        self._app = app
        # important: QSignalObject needs to be parented, as keeping a ref
        # in the plugin is not enough to avoid gc
        self.so = Plugin.QSignalObject(self, self._app)

        # If the user just enabled the plugin, the 'load_wallet' hook would not
        # get called for already loaded wallets, hence we call it manually for those:
        for wallet_name, wallet in app.daemon.daemon._wallets.items():
            self.load_wallet(wallet)
