import re
import queue
import time
import os

from PyQt5.QtCore import pyqtSlot, pyqtSignal, pyqtProperty, QObject, QUrl, QLocale, qInstallMessageHandler, QTimer
from PyQt5.QtGui import QGuiApplication, QFontDatabase
from PyQt5.QtQml import qmlRegisterType, qmlRegisterUncreatableType, QQmlApplicationEngine

from electrum import version
from electrum.logging import Logger, get_logger
from electrum.util import BITCOIN_BIP21_URI_SCHEME, LIGHTNING_URI_SCHEME

from .qeconfig import QEConfig
from .qedaemon import QEDaemon, QEWalletListModel
from .qenetwork import QENetwork
from .qewallet import QEWallet
from .qeqr import QEQRParser, QEQRImageProvider, QEQRImageProviderHelper
from .qewalletdb import QEWalletDB
from .qebitcoin import QEBitcoin
from .qefx import QEFX
from .qetxfinalizer import QETxFinalizer, QETxFeeBumper
from .qeinvoice import QEInvoice, QEInvoiceParser, QEUserEnteredPayment
from .qerequestdetails import QERequestDetails
from .qetypes import QEAmount
from .qeaddressdetails import QEAddressDetails
from .qetxdetails import QETxDetails
from .qechannelopener import QEChannelOpener
from .qelnpaymentdetails import QELnPaymentDetails
from .qechanneldetails import QEChannelDetails
from .qeswaphelper import QESwapHelper
from .qewizard import QENewWalletWizard, QEServerConnectWizard

notification = None

class QEAppController(QObject):
    userNotify = pyqtSignal(str)
    uriReceived = pyqtSignal(str)

    _dummy = pyqtSignal()

    def __init__(self, qedaemon, plugins):
        super().__init__()
        self.logger = get_logger(__name__)

        self._qedaemon = qedaemon
        self._plugins = plugins

        # set up notification queue and notification_timer
        self.user_notification_queue = queue.Queue()
        self.user_notification_last_time = 0

        self.notification_timer = QTimer(self)
        self.notification_timer.setSingleShot(False)
        self.notification_timer.setInterval(500)  # msec
        self.notification_timer.timeout.connect(self.on_notification_timer)

        self._qedaemon.walletLoaded.connect(self.on_wallet_loaded)

        self.userNotify.connect(self.notifyAndroid)

        self.bindIntent()

    def on_wallet_loaded(self):
        qewallet = self._qedaemon.currentWallet
        if not qewallet:
            return
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
            self.logger.warning('Notification: needs plyer; `sudo python3 -m pip install plyer`')
        except Exception as e:
            self.logger.error(repr(e))

    def bindIntent(self):
        try:
            from android import activity
            from jnius import autoclass
            PythonActivity = autoclass('org.kivy.android.PythonActivity')
            mactivity = PythonActivity.mActivity
            self.on_new_intent(mactivity.getIntent())
            activity.bind(on_new_intent=self.on_new_intent)
        except Exception as e:
            self.logger.error(f'unable to bind intent: {repr(e)}')

    def on_new_intent(self, intent):
        data = str(intent.getDataString())
        scheme = str(intent.getScheme()).lower()
        if scheme == BITCOIN_BIP21_URI_SCHEME or scheme == LIGHTNING_URI_SCHEME:
            self.uriReceived.emit(data)

    @pyqtSlot(str, str)
    def doShare(self, data, title):
        #if platform != 'android':
            #return
        try:
            from jnius import autoclass, cast
        except ImportError:
            self.logger.error('Share: needs jnius. Platform not Android?')
            return

        JS = autoclass('java.lang.String')
        Intent = autoclass('android.content.Intent')
        sendIntent = Intent()
        sendIntent.setAction(Intent.ACTION_SEND)
        sendIntent.setType("text/plain")
        sendIntent.putExtra(Intent.EXTRA_TEXT, JS(data))
        pythonActivity = autoclass('org.kivy.android.PythonActivity')
        currentActivity = cast('android.app.Activity', pythonActivity.mActivity)
        it = Intent.createChooser(sendIntent, cast('java.lang.CharSequence', JS(title)))
        currentActivity.startActivity(it)

    @pyqtSlot('QString')
    def textToClipboard(self, text):
        QGuiApplication.clipboard().setText(text)

    @pyqtSlot(result='QString')
    def clipboardToText(self):
        return QGuiApplication.clipboard().text()

    @pyqtSlot(str, result=QObject)
    def plugin(self, plugin_name):
        self.logger.debug(f'now {self._plugins.count()} plugins loaded')
        plugin = self._plugins.get(plugin_name)
        self.logger.debug(f'plugin with name {plugin_name} is {str(type(plugin))}')
        if plugin and hasattr(plugin,'so'):
            return plugin.so
        else:
            self.logger.debug('None!')
            return None

    @pyqtProperty('QVariant', notify=_dummy)
    def plugins(self):
        s = []
        for item in self._plugins.descriptions:
            self.logger.info(item)
            s.append({
                'name': item,
                'fullname': self._plugins.descriptions[item]['fullname'],
                'enabled': bool(self._plugins.get(item))
                })

        self.logger.debug(f'{str(s)}')
        return s

    @pyqtSlot(str, bool)
    def setPluginEnabled(self, plugin, enabled):
        if enabled:
            self._plugins.enable(plugin)
        else:
            self._plugins.disable(plugin)


class ElectrumQmlApplication(QGuiApplication):

    _valid = True

    def __init__(self, args, config, daemon, plugins):
        super().__init__(args)

        self.logger = get_logger(__name__)

        ElectrumQmlApplication._daemon = daemon

        qmlRegisterType(QEWallet, 'org.electrum', 1, 0, 'Wallet')
        qmlRegisterType(QEWalletDB, 'org.electrum', 1, 0, 'WalletDB')
        qmlRegisterType(QEBitcoin, 'org.electrum', 1, 0, 'Bitcoin')
        qmlRegisterType(QEQRParser, 'org.electrum', 1, 0, 'QRParser')
        qmlRegisterType(QEFX, 'org.electrum', 1, 0, 'FX')
        qmlRegisterType(QETxFinalizer, 'org.electrum', 1, 0, 'TxFinalizer')
        qmlRegisterType(QEInvoice, 'org.electrum', 1, 0, 'Invoice')
        qmlRegisterType(QEInvoiceParser, 'org.electrum', 1, 0, 'InvoiceParser')
        qmlRegisterType(QEUserEnteredPayment, 'org.electrum', 1, 0, 'UserEnteredPayment')
        qmlRegisterType(QEAddressDetails, 'org.electrum', 1, 0, 'AddressDetails')
        qmlRegisterType(QETxDetails, 'org.electrum', 1, 0, 'TxDetails')
        qmlRegisterType(QEChannelOpener, 'org.electrum', 1, 0, 'ChannelOpener')
        qmlRegisterType(QELnPaymentDetails, 'org.electrum', 1, 0, 'LnPaymentDetails')
        qmlRegisterType(QEChannelDetails, 'org.electrum', 1, 0, 'ChannelDetails')
        qmlRegisterType(QESwapHelper, 'org.electrum', 1, 0, 'SwapHelper')
        qmlRegisterType(QERequestDetails, 'org.electrum', 1, 0, 'RequestDetails')
        qmlRegisterType(QETxFeeBumper, 'org.electrum', 1, 0, 'TxFeeBumper')

        qmlRegisterUncreatableType(QEAmount, 'org.electrum', 1, 0, 'Amount', 'Amount can only be used as property')
        qmlRegisterUncreatableType(QENewWalletWizard, 'org.electrum', 1, 0, 'NewWalletWizard', 'NewWalletWizard can only be used as property')
        qmlRegisterUncreatableType(QEServerConnectWizard, 'org.electrum', 1, 0, 'ServerConnectWizard', 'ServerConnectWizard can only be used as property')

        self.engine = QQmlApplicationEngine(parent=self)

        screensize = self.primaryScreen().size()

        self.qr_ip = QEQRImageProvider((7/8)*min(screensize.width(), screensize.height()))
        self.engine.addImageProvider('qrgen', self.qr_ip)
        self.qr_ip_h = QEQRImageProviderHelper((7/8)*min(screensize.width(), screensize.height()))

        # add a monospace font as we can't rely on device having one
        self.fixedFont = 'PT Mono'
        not_loaded = QFontDatabase.addApplicationFont('electrum/gui/qml/fonts/PTMono-Regular.ttf') < 0
        not_loaded = QFontDatabase.addApplicationFont('electrum/gui/qml/fonts/PTMono-Bold.ttf') < 0 and not_loaded
        if not_loaded:
            self.logger.warning('Could not load font PT Mono')
            self.fixedFont = 'Monospace' # hope for the best

        self.context = self.engine.rootContext()
        self.plugins = plugins
        self._qeconfig = QEConfig(config)
        self._qenetwork = QENetwork(daemon.network, self._qeconfig)
        self.daemon = QEDaemon(daemon)
        self.appController = QEAppController(self.daemon, self.plugins)
        self._maxAmount = QEAmount(is_max=True)
        self.context.setContextProperty('AppController', self.appController)
        self.context.setContextProperty('Config', self._qeconfig)
        self.context.setContextProperty('Network', self._qenetwork)
        self.context.setContextProperty('Daemon', self.daemon)
        self.context.setContextProperty('FixedFont', self.fixedFont)
        self.context.setContextProperty('MAX', self._maxAmount)
        self.context.setContextProperty('QRIP', self.qr_ip_h)
        self.context.setContextProperty('BUILD', {
            'electrum_version': version.ELECTRUM_VERSION,
            'apk_version': version.APK_VERSION,
            'protocol_version': version.PROTOCOL_VERSION
        })

        self.plugins.load_plugin('trustedcoin')

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
