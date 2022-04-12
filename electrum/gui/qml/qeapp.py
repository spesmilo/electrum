import re
import queue
import time
import os

from PyQt5.QtCore import pyqtSlot, pyqtSignal, QObject, QUrl, QLocale, qInstallMessageHandler, QTimer
from PyQt5.QtGui import QGuiApplication, QFontDatabase
from PyQt5.QtQml import qmlRegisterType, QQmlApplicationEngine

from electrum.logging import Logger, get_logger
from electrum import version

from .qeconfig import QEConfig
from .qedaemon import QEDaemon, QEWalletListModel
from .qenetwork import QENetwork
from .qewallet import QEWallet
from .qeqr import QEQRParser, QEQRImageProvider
from .qewalletdb import QEWalletDB
from .qebitcoin import QEBitcoin
from .qefx import QEFX
from .qetxfinalizer import QETxFinalizer

notification = None

class QEAppController(QObject):
    userNotify = pyqtSignal(str)

    def __init__(self, qedaemon):
        super().__init__()
        self.logger = get_logger(__name__)

        self._qedaemon = qedaemon

        # set up notification queue and notification_timer
        self.user_notification_queue = queue.Queue()
        self.user_notification_last_time = 0

        self.notification_timer = QTimer(self)
        self.notification_timer.setSingleShot(False)
        self.notification_timer.setInterval(500)  # msec
        self.notification_timer.timeout.connect(self.on_notification_timer)

        self._qedaemon.walletLoaded.connect(self.on_wallet_loaded)

        self.userNotify.connect(self.notifyAndroid)

    def on_wallet_loaded(self):
        qewallet = self._qedaemon.currentWallet
        # attach to the wallet user notification events
        # connect only once
        try:
            qewallet.userNotify.disconnect(self.on_wallet_usernotify)
        except:
            pass
        qewallet.userNotify.connect(self.on_wallet_usernotify)

    def on_wallet_usernotify(self, wallet, message):
        self.logger.debug(message)
        self.user_notification_queue.put(message)
        if not self.notification_timer.isActive():
            self.logger.debug('starting app notification timer')
            self.notification_timer.start()

    def on_notification_timer(self):
        if self.user_notification_queue.qsize() == 0:
            self.logger.debug('queue empty, stopping app notification timer')
            self.notification_timer.stop()
            return
        now = time.time()
        rate_limit = 20  # seconds
        if self.user_notification_last_time + rate_limit > now:
            return
        self.user_notification_last_time = now
        self.logger.info("Notifying GUI about new user notifications")
        try:
            self.userNotify.emit(self.user_notification_queue.get_nowait())
        except queue.Empty:
            pass

    def notifyAndroid(self, message):
        try:
            # TODO: lazy load not in UI thread please
            global notification
            if not notification:
                from plyer import notification
            icon = (os.path.dirname(os.path.realpath(__file__))
                    + '/../icons/electrum.png')
            notification.notify('Electrum', message, app_icon=icon, app_name='Electrum')
        except ImportError:
            self.logger.error('Notification: needs plyer; `sudo python3 -m pip install plyer`')

    @pyqtSlot('QString')
    def textToClipboard(self, text):
        QGuiApplication.clipboard().setText(text)

    @pyqtSlot(result='QString')
    def clipboardToText(self):
        return QGuiApplication.clipboard().text()

class ElectrumQmlApplication(QGuiApplication):

    _valid = True

    def __init__(self, args, config, daemon):
        super().__init__(args)

        self.logger = get_logger(__name__)

        ElectrumQmlApplication._daemon = daemon

        qmlRegisterType(QEWalletListModel, 'org.electrum', 1, 0, 'WalletListModel')
        qmlRegisterType(QEWallet, 'org.electrum', 1, 0, 'Wallet')
        qmlRegisterType(QEWalletDB, 'org.electrum', 1, 0, 'WalletDB')
        qmlRegisterType(QEBitcoin, 'org.electrum', 1, 0, 'Bitcoin')
        qmlRegisterType(QEQRParser, 'org.electrum', 1, 0, 'QRParser')
        qmlRegisterType(QEFX, 'org.electrum', 1, 0, 'FX')
        qmlRegisterType(QETxFinalizer, 'org.electrum', 1, 0, 'TxFinalizer')

        self.engine = QQmlApplicationEngine(parent=self)
        self.engine.addImportPath('./qml')

        self.qr_ip = QEQRImageProvider()
        self.engine.addImageProvider('qrgen', self.qr_ip)

        # add a monospace font as we can't rely on device having one
        self.fixedFont = 'PT Mono'
        if (QFontDatabase.addApplicationFont('electrum/gui/qml/fonts/PTMono-Regular.ttf') < 0 and
            QFontDatabase.addApplicationFont('electrum/gui/qml/fonts/PTMono-Bold.ttf') < 0):
                self.logger.warning('Could not load font PT Mono')
                self.fixedFont = 'Monospace' # hope for the best

        self.context = self.engine.rootContext()
        self._qeconfig = QEConfig(config)
        self._qenetwork = QENetwork(daemon.network)
        self._qedaemon = QEDaemon(daemon)
        self._appController = QEAppController(self._qedaemon)
        self.context.setContextProperty('AppController', self._appController)
        self.context.setContextProperty('Config', self._qeconfig)
        self.context.setContextProperty('Network', self._qenetwork)
        self.context.setContextProperty('Daemon', self._qedaemon)
        self.context.setContextProperty('FixedFont', self.fixedFont)
        self.context.setContextProperty('BUILD', {
            'electrum_version': version.ELECTRUM_VERSION,
            'apk_version': version.APK_VERSION,
            'protocol_version': version.PROTOCOL_VERSION
        })

        qInstallMessageHandler(self.message_handler)

        # get notified whether root QML document loads or not
        self.engine.objectCreated.connect(self.objectCreated)

    # slot is called after loading root QML. If object is None, it has failed.
    @pyqtSlot('QObject*', 'QUrl')
    def objectCreated(self, object, url):
        if object is None:
            self._valid = False
        self.engine.objectCreated.disconnect(self.objectCreated)

    def message_handler(self, line, funct, file):
        # filter out common harmless messages
        if re.search('file:///.*TypeError: Cannot read property.*null$', file):
            return
        self.logger.warning(file)
