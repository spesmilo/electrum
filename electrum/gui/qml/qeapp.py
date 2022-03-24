import re

from PyQt5.QtCore import pyqtSlot, QObject, QUrl, QLocale, qInstallMessageHandler
from PyQt5.QtGui import QGuiApplication, QFontDatabase
from PyQt5.QtQml import qmlRegisterType, QQmlApplicationEngine #, QQmlComponent

from electrum.logging import Logger, get_logger

from .qeconfig import QEConfig
from .qedaemon import QEDaemon, QEWalletListModel
from .qenetwork import QENetwork
from .qewallet import QEWallet
from .qeqr import QEQR, QEQRImageProvider
from .qewalletdb import QEWalletDB
from .qebitcoin import QEBitcoin

class ElectrumQmlApplication(QGuiApplication):

    _config = None
    _daemon = None
    _singletons = {}

    def __init__(self, args, config, daemon):
        super().__init__(args)

        self.logger = get_logger(__name__)

        ElectrumQmlApplication._config = config
        ElectrumQmlApplication._daemon = daemon

        qmlRegisterType(QEWalletListModel, 'org.electrum', 1, 0, 'WalletListModel')
        qmlRegisterType(QEWallet, 'org.electrum', 1, 0, 'Wallet')
        qmlRegisterType(QEWalletDB, 'org.electrum', 1, 0, 'WalletDB')
        qmlRegisterType(QEBitcoin, 'org.electrum', 1, 0, 'Bitcoin')

        self.engine = QQmlApplicationEngine(parent=self)
        self.engine.addImportPath('./qml')

        self.qr_ip = QEQRImageProvider()
        self.engine.addImageProvider('qrgen', self.qr_ip)

        # add a monospace font as we can't rely on device having one
        if QFontDatabase.addApplicationFont('electrum/gui/qml/fonts/PTMono-Regular.ttf') < 0:
            self.logger.warning('Could not load font PTMono-Regular.ttf')
            self.fixedFont = 'Monospace' # hope for the best
        else:
            self.fixedFont = 'PT Mono'

        self.context = self.engine.rootContext()
        self._singletons['config'] = QEConfig(config)
        self._singletons['network'] = QENetwork(daemon.network)
        self._singletons['daemon'] = QEDaemon(daemon)
        self._singletons['qr'] = QEQR()
        self.context.setContextProperty('Config', self._singletons['config'])
        self.context.setContextProperty('Network', self._singletons['network'])
        self.context.setContextProperty('Daemon', self._singletons['daemon'])
        self.context.setContextProperty('QR', self._singletons['qr'])
        self.context.setContextProperty('FixedFont', self.fixedFont)

        qInstallMessageHandler(self.message_handler)

        # get notified whether root QML document loads or not
        self.engine.objectCreated.connect(self.objectCreated)


    _valid = True

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


