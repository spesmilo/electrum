import re
import queue
import time
import os
import sys
import html
import threading
from typing import TYPE_CHECKING, Set

from PyQt6.QtCore import (pyqtSlot, pyqtSignal, pyqtProperty, QObject, QT_VERSION_STR, PYQT_VERSION_STR,
                          qInstallMessageHandler, QTimer, QSortFilterProxyModel)
from PyQt6.QtGui import QGuiApplication, QFontDatabase
from PyQt6.QtQml import qmlRegisterType, QQmlApplicationEngine

import electrum
from electrum import version, constants
from electrum.i18n import _
from electrum.logging import Logger, get_logger
from electrum.bip21 import BITCOIN_BIP21_URI_SCHEME, LIGHTNING_URI_SCHEME
from electrum.base_crash_reporter import BaseCrashReporter, EarlyExceptionsQueue
from electrum.network import Network
from electrum.plugin import run_hook

from .qeconfig import QEConfig
from .qedaemon import QEDaemon
from .qenetwork import QENetwork
from .qewallet import QEWallet
from .qeqr import QEQRParser, QEQRImageProvider, QEQRImageProviderHelper
from .qeqrscanner import QEQRScanner
from .qebitcoin import QEBitcoin
from .qefx import QEFX
from .qetxfinalizer import QETxFinalizer, QETxRbfFeeBumper, QETxCpfpFeeBumper, QETxCanceller
from .qeinvoice import QEInvoice, QEInvoiceParser
from .qerequestdetails import QERequestDetails
from .qetypes import QEAmount
from .qeaddressdetails import QEAddressDetails
from .qetxdetails import QETxDetails
from .qechannelopener import QEChannelOpener
from .qelnpaymentdetails import QELnPaymentDetails
from .qechanneldetails import QEChannelDetails
from .qeswaphelper import QESwapHelper
from .qewizard import QENewWalletWizard, QEServerConnectWizard
from .qemodelfilter import QEFilterProxyModel
from .qebip39recovery import QEBip39RecoveryListModel

if TYPE_CHECKING:
    from electrum.simple_config import SimpleConfig
    from electrum.wallet import Abstract_Wallet
    from electrum.daemon import Daemon
    from electrum.plugin import Plugins

if 'ANDROID_DATA' in os.environ:
    from jnius import autoclass, cast
    from android import activity

    jpythonActivity = autoclass('org.kivy.android.PythonActivity').mActivity
    jHfc = autoclass('android.view.HapticFeedbackConstants')
    jString = autoclass('java.lang.String')
    jIntent = autoclass('android.content.Intent')
    jview = jpythonActivity.getWindow().getDecorView()

notification = None


class QEAppController(BaseCrashReporter, QObject):
    _dummy = pyqtSignal()
    userNotify = pyqtSignal(str, str)
    uriReceived = pyqtSignal(str)
    showException = pyqtSignal('QVariantMap')
    sendingBugreport = pyqtSignal()
    sendingBugreportSuccess = pyqtSignal(str)
    sendingBugreportFailure = pyqtSignal(str)
    secureWindowChanged = pyqtSignal()
    wantCloseChanged = pyqtSignal()

    def __init__(self, qeapp: 'ElectrumQmlApplication', qedaemon: 'QEDaemon', plugins: 'Plugins'):
        BaseCrashReporter.__init__(self, None, None, None)
        QObject.__init__(self)

        self._app = qeapp
        self._qedaemon = qedaemon
        self._plugins = plugins
        self.config = qedaemon.daemon.config

        self._crash_user_text = ''
        self._app_started = False
        self._intent = ''
        self._secureWindow = False

        # set up notification queue and notification_timer
        self.user_notification_queue = queue.Queue()
        self.user_notification_last_time = 0

        self.notification_timer = QTimer(self)
        self.notification_timer.setSingleShot(False)
        self.notification_timer.setInterval(500)  # msec
        self.notification_timer.timeout.connect(self.on_notification_timer)

        self._qedaemon.walletLoaded.connect(self.on_wallet_loaded)

        self.userNotify.connect(self.doNotify)

        if self.isAndroid():
            self.bindIntent()

        self._want_close = False

    def on_wallet_loaded(self):
        qewallet = self._qedaemon.currentWallet
        if not qewallet:
            return

        # register wallet in Exception_Hook
        Exception_Hook.maybe_setup(config=qewallet.wallet.config, wallet=qewallet.wallet)

        # attach to the wallet user notification events
        # connect only once
        try:
            qewallet.userNotify.disconnect(self.on_wallet_usernotify)
        except Exception:
            pass
        qewallet.userNotify.connect(self.on_wallet_usernotify)

    def on_wallet_usernotify(self, wallet, message):
        self.logger.debug(message)
        self.user_notification_queue.put((wallet,message))
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
            wallet, message = self.user_notification_queue.get_nowait()
            self.userNotify.emit(str(wallet), message)
        except queue.Empty:
            pass

    def doNotify(self, wallet_name, message):
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
        if not self.isAndroid():
            return
        try:
            self.on_new_intent(jpythonActivity.getIntent())
            activity.bind(on_new_intent=self.on_new_intent)
        except Exception as e:
            self.logger.error(f'unable to bind intent: {repr(e)}')

    def on_new_intent(self, intent):
        if not self._app_started:
            self._intent = intent
            return

        data = str(intent.getDataString())
        self.logger.debug(f'received intent: {repr(data)}')
        scheme = str(intent.getScheme()).lower()
        if scheme == BITCOIN_BIP21_URI_SCHEME or scheme == LIGHTNING_URI_SCHEME:
            self.uriReceived.emit(data)

    def startupFinished(self):
        self._app_started = True
        if self._intent:
            self.on_new_intent(self._intent)

    @pyqtProperty(bool, notify=wantCloseChanged)
    def wantClose(self):
        return self._want_close

    @wantClose.setter
    def wantClose(self, want_close):
        if want_close != self._want_close:
            self._want_close = want_close
            self.wantCloseChanged.emit()

    @pyqtSlot(str, str)
    def doShare(self, data, title):
        if not self.isAndroid():
            return

        sendIntent = jIntent()
        sendIntent.setAction(jIntent.ACTION_SEND)
        sendIntent.setType("text/plain")
        sendIntent.putExtra(jIntent.EXTRA_TEXT, jString(data))
        it = jIntent.createChooser(sendIntent, cast('java.lang.CharSequence', jString(title)))
        jpythonActivity.startActivity(it)

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
        if plugin and hasattr(plugin, 'so'):
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
    def setPluginEnabled(self, plugin: str, enabled: bool):
        if enabled:
            self._plugins.enable(plugin)
            # note: all enabled plugins will receive this hook:
            run_hook('init_qml', self._app)
        else:
            self._plugins.disable(plugin)

    @pyqtSlot(str, result=bool)
    def isPluginEnabled(self, plugin: str):
        return bool(self._plugins.get(plugin))

    @pyqtSlot(result=bool)
    def isAndroid(self):
        return 'ANDROID_DATA' in os.environ

    @pyqtSlot(result='QVariantMap')
    def crashData(self):
        return {
            'traceback': self.get_traceback_info(),
            'extra': self.get_additional_info(),
            'reportstring': self.get_report_string()
        }

    @pyqtSlot(object, object, object, object)
    def crash(self, config, e, text, tb):
        self.exc_args = (e, text, tb)  # for BaseCrashReporter
        self.showException.emit(self.crashData())

    @pyqtSlot()
    def sendReport(self):
        network = Network.get_instance()
        proxy = network.proxy

        def report_task():
            try:
                response = BaseCrashReporter.send_report(self, network.asyncio_loop, proxy)
            except Exception as e:
                self.logger.error('There was a problem with the automatic reporting', exc_info=e)
                self.sendingBugreportFailure.emit(_('There was a problem with the automatic reporting:') + '<br/>' +
                                        repr(e)[:120] + '<br/><br/>' +
                                        _("Please report this issue manually") +
                                        f' <a href="{constants.GIT_REPO_ISSUES_URL}">on GitHub</a>.')
            else:
                text = response.text
                if response.url:
                    text += f" You can track further progress on <a href='{response.url}'>GitHub</a>."
                self.sendingBugreportSuccess.emit(text)

        self.sendingBugreport.emit()
        threading.Thread(target=report_task, daemon=True).start()

    @pyqtSlot()
    def showNever(self):
        self.config.SHOW_CRASH_REPORTER = False

    @pyqtSlot(str)
    def setCrashUserText(self, text):
        self._crash_user_text = text

    def _get_traceback_str_to_display(self) -> str:
        # The msg_box that shows the report uses rich_text=True, so
        # if traceback contains special HTML characters, e.g. '<',
        # they need to be escaped to avoid formatting issues.
        traceback_str = super()._get_traceback_str_to_display()
        return html.escape(traceback_str).replace('&#x27;', '&apos;')

    def get_user_description(self):
        return self._crash_user_text

    def get_wallet_type(self):
        wallet_types = Exception_Hook._INSTANCE.wallet_types_seen
        return ",".join(wallet_types)

    @pyqtSlot()
    def haptic(self):
        if not self.isAndroid():
            return
        jview.performHapticFeedback(jHfc.VIRTUAL_KEY)

    @pyqtProperty(bool, notify=secureWindowChanged)
    def secureWindow(self):
        return self._secureWindow

    @secureWindow.setter
    def secureWindow(self, secure):
        if not self.isAndroid():
            return
        if self.config.GUI_QML_ALWAYS_ALLOW_SCREENSHOTS:
            return
        if self._secureWindow != secure:
            jpythonActivity.setSecureWindow(secure)
            self._secureWindow = secure
            self.secureWindowChanged.emit()


class ElectrumQmlApplication(QGuiApplication):

    _valid = True

    def __init__(self, args, *, config: 'SimpleConfig', daemon: 'Daemon', plugins: 'Plugins'):
        super().__init__(args)

        self.logger = get_logger(__name__)

        ElectrumQmlApplication._daemon = daemon

        # TODO QT6 order of declaration is important now?
        qmlRegisterType(QEAmount, 'org.electrum', 1, 0, 'Amount')
        qmlRegisterType(QENewWalletWizard, 'org.electrum', 1, 0, 'QNewWalletWizard')
        qmlRegisterType(QEServerConnectWizard, 'org.electrum', 1, 0, 'QServerConnectWizard')
        qmlRegisterType(QEFilterProxyModel, 'org.electrum', 1, 0, 'FilterProxyModel')
        qmlRegisterType(QSortFilterProxyModel, 'org.electrum', 1, 0, 'QSortFilterProxyModel')

        qmlRegisterType(QEWallet, 'org.electrum', 1, 0, 'Wallet')
        qmlRegisterType(QEBitcoin, 'org.electrum', 1, 0, 'Bitcoin')
        qmlRegisterType(QEQRParser, 'org.electrum', 1, 0, 'QRParser')
        qmlRegisterType(QEQRScanner, 'org.electrum', 1, 0, 'QRScanner')
        qmlRegisterType(QEFX, 'org.electrum', 1, 0, 'FX')
        qmlRegisterType(QETxFinalizer, 'org.electrum', 1, 0, 'TxFinalizer')
        qmlRegisterType(QEInvoice, 'org.electrum', 1, 0, 'Invoice')
        qmlRegisterType(QEInvoiceParser, 'org.electrum', 1, 0, 'InvoiceParser')
        qmlRegisterType(QEAddressDetails, 'org.electrum', 1, 0, 'AddressDetails')
        qmlRegisterType(QETxDetails, 'org.electrum', 1, 0, 'TxDetails')
        qmlRegisterType(QEChannelOpener, 'org.electrum', 1, 0, 'ChannelOpener')
        qmlRegisterType(QELnPaymentDetails, 'org.electrum', 1, 0, 'LnPaymentDetails')
        qmlRegisterType(QEChannelDetails, 'org.electrum', 1, 0, 'ChannelDetails')
        qmlRegisterType(QESwapHelper, 'org.electrum', 1, 0, 'SwapHelper')
        qmlRegisterType(QERequestDetails, 'org.electrum', 1, 0, 'RequestDetails')
        qmlRegisterType(QETxRbfFeeBumper, 'org.electrum', 1, 0, 'TxRbfFeeBumper')
        qmlRegisterType(QETxCpfpFeeBumper, 'org.electrum', 1, 0, 'TxCpfpFeeBumper')
        qmlRegisterType(QETxCanceller, 'org.electrum', 1, 0, 'TxCanceller')
        qmlRegisterType(QEBip39RecoveryListModel, 'org.electrum', 1, 0, 'Bip39RecoveryListModel')

        # TODO QT6: these were declared as uncreatable, but that doesn't seem to work for pyqt6
        # qmlRegisterUncreatableType(QEAmount, 'org.electrum', 1, 0, 'Amount', 'Amount can only be used as property')
        # qmlRegisterUncreatableType(QENewWalletWizard, 'org.electrum', 1, 0, 'QNewWalletWizard', 'QNewWalletWizard can only be used as property')
        # qmlRegisterUncreatableType(QEServerConnectWizard, 'org.electrum', 1, 0, 'QServerConnectWizard', 'QServerConnectWizard can only be used as property')
        # qmlRegisterUncreatableType(QEFilterProxyModel, 'org.electrum', 1, 0, 'FilterProxyModel', 'FilterProxyModel can only be used as property')
        # qmlRegisterUncreatableType(QSortFilterProxyModel, 'org.electrum', 1, 0, 'QSortFilterProxyModel', 'QSortFilterProxyModel can only be used as property')

        self.engine = QQmlApplicationEngine(parent=self)

        screensize = self.primaryScreen().size()

        qr_size = min(screensize.width(), screensize.height()) * 7/8
        self.qr_ip = QEQRImageProvider(qr_size)
        self.engine.addImageProvider('qrgen', self.qr_ip)
        self.qr_ip_h = QEQRImageProviderHelper(qr_size)

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
        self.daemon = QEDaemon(daemon, self.plugins)
        self.appController = QEAppController(self, self.daemon, self.plugins)
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
            'protocol_version': version.PROTOCOL_VERSION,
            'qt_version': QT_VERSION_STR,
            'pyqt_version': PYQT_VERSION_STR
        })
        self.context.setContextProperty('UI_UNIT_NAME', {
            "FEERATE_SAT_PER_VBYTE": electrum.util.UI_UNIT_NAME_FEERATE_SAT_PER_VBYTE,
            "FEERATE_SAT_PER_VB":    electrum.util.UI_UNIT_NAME_FEERATE_SAT_PER_VB,
            "TXSIZE_VBYTES":         electrum.util.UI_UNIT_NAME_TXSIZE_VBYTES,
            "MEMPOOL_MB":            electrum.util.UI_UNIT_NAME_MEMPOOL_MB,
        })

        self.plugins.load_internal_plugin('trustedcoin')

        qInstallMessageHandler(self.message_handler)

        # get notified whether root QML document loads or not
        self.engine.objectCreated.connect(self.objectCreated)

    # slot is called after loading root QML. If object is None, it has failed.
    @pyqtSlot('QObject*', 'QUrl')
    def objectCreated(self, object, url):
        if object is None:
            self._valid = False
        self.engine.objectCreated.disconnect(self.objectCreated)
        self.appController.startupFinished()

    def message_handler(self, line, funct, file):
        # filter out common harmless messages
        if re.search('file:///.*TypeError: Cannot read property.*null$', file):
            return
        self.logger.warning(file)


class Exception_Hook(QObject, Logger):
    _report_exception = pyqtSignal(object, object, object, object)

    _INSTANCE = None  # type: Optional[Exception_Hook]  # singleton

    def __init__(self, *, config: 'SimpleConfig', slot):
        QObject.__init__(self)
        Logger.__init__(self)
        assert self._INSTANCE is None, "Exception_Hook is supposed to be a singleton"
        self.config = config
        self.wallet_types_seen = set()  # type: Set[str]

        sys.excepthook = self.handler
        threading.excepthook = self.handler

        self._report_exception.connect(slot)
        EarlyExceptionsQueue.set_hook_as_ready()

    @classmethod
    def maybe_setup(cls, *, config: 'SimpleConfig', wallet: 'Abstract_Wallet' = None, slot = None) -> None:
        if not config.SHOW_CRASH_REPORTER:
            EarlyExceptionsQueue.set_hook_as_ready()  # flush already queued exceptions
            return
        if not cls._INSTANCE:
            cls._INSTANCE = Exception_Hook(config=config, slot=slot)
        if wallet:
            cls._INSTANCE.wallet_types_seen.add(wallet.wallet_type)

    def handler(self, *exc_info):
        self.logger.error('exception caught by crash reporter', exc_info=exc_info)
        self._report_exception.emit(self.config, *exc_info)
