import os
import signal
import sys
import traceback
import threading
from typing import Optional, TYPE_CHECKING, List

try:
    import PyQt5
except Exception:
    sys.exit("Error: Could not import PyQt5 on Linux systems, you may try 'sudo apt-get install python3-pyqt5'")

try:
    import PyQt5.QtQml
except Exception:
    sys.exit("Error: Could not import PyQt5.QtQml on Linux systems, you may try 'sudo apt-get install python3-pyqt5.qtquick'")

from PyQt5.QtCore import pyqtProperty, pyqtSignal, QObject, QUrl
from PyQt5.QtGui import QGuiApplication
from PyQt5.QtQml import qmlRegisterType, QQmlComponent, QQmlApplicationEngine
from PyQt5.QtQuick import QQuickView
import PyQt5.QtCore as QtCore
import PyQt5.QtQml as QtQml

from electrum.i18n import _, set_language
from electrum.plugin import run_hook
from electrum.base_wizard import GoBack
from electrum.util import (UserCancelled, profiler,
                           WalletFileException, BitcoinException, get_new_wallet_name)
from electrum.wallet import Wallet, Abstract_Wallet
from electrum.wallet_db import WalletDB
from electrum.logging import Logger

if TYPE_CHECKING:
    from electrum.daemon import Daemon
    from electrum.simple_config import SimpleConfig
    from electrum.plugin import Plugins

from .qenetwork import QENetwork, QEDaemon, QEWalletListModel
from .qewallet import *
from .qeqr import QEQR

class ElectrumQmlApplication(QGuiApplication):
    def __init__(self, args, daemon):
        super().__init__(args)

        qmlRegisterType(QEWalletListModel, 'QElectrum', 1, 0, 'QEWalletListModel')
        qmlRegisterType(QEWallet, 'QElectrum', 1, 0, 'QEWallet')

        self.engine = QQmlApplicationEngine(parent=self)
        self.context = self.engine.rootContext()
        self.qen = QENetwork(daemon.network)
        self.context.setContextProperty('Network', self.qen)
        self.qed = QEDaemon(daemon)
        self.context.setContextProperty('Daemon', self.qed)
        self.qeqr = QEQR()
        self.context.setContextProperty('QR', self.qeqr)
        self.engine.load(QUrl('electrum/gui/qml/components/main.qml'))

class ElectrumGui(Logger):

    @profiler
    def __init__(self, config: 'SimpleConfig', daemon: 'Daemon', plugins: 'Plugins'):
        # TODO set_language(config.get('language', get_default_language()))
        Logger.__init__(self)
        self.logger.info(f"Qml GUI starting up... Qt={QtCore.QT_VERSION_STR}, PyQt={QtCore.PYQT_VERSION_STR}")
        # Uncomment this call to verify objects are being properly
        # GC-ed when windows are closed
        #network.add_jobs([DebugMem([Abstract_Wallet, SPV, Synchronizer,
        #                            ElectrumWindow], interval=5)])
        QtCore.QCoreApplication.setAttribute(QtCore.Qt.AA_X11InitThreads)
        if hasattr(QtCore.Qt, "AA_ShareOpenGLContexts"):
            QtCore.QCoreApplication.setAttribute(QtCore.Qt.AA_ShareOpenGLContexts)
#        if hasattr(QGuiApplication, 'setDesktopFileName'):
#            QGuiApplication.setDesktopFileName('electrum.desktop')
        self.gui_thread = threading.current_thread()
        self.config = config
        self.daemon = daemon
        self.plugins = plugins
        self.app = ElectrumQmlApplication(sys.argv, self.daemon)

        # TODO when plugin support. run_hook('init_qml', self)

    def close(self):
#        for window in self.windows:
#            window.close()
#        if self.network_dialog:
#            self.network_dialog.close()
#        if self.lightning_dialog:
#            self.lightning_dialog.close()
#        if self.watchtower_dialog:
#            self.watchtower_dialog.close()
        self.app.quit()

    def main(self):
        self.app.exec_()

    def stop(self):
        self.logger.info('closing GUI')
        self.app.quit()
