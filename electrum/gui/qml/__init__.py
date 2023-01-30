import os
import signal
import sys
import threading
import traceback
from typing import TYPE_CHECKING

try:
    import PyQt5
except Exception:
    sys.exit("Error: Could not import PyQt5 on Linux systems, you may try 'sudo apt-get install python3-pyqt5'")

try:
    import PyQt5.QtQml
except Exception:
    sys.exit("Error: Could not import PyQt5.QtQml on Linux systems, you may try 'sudo apt-get install python3-pyqt5.qtquick'")

from PyQt5.QtCore import (Qt, QCoreApplication, QObject, QLocale, QTranslator, QTimer, pyqtSignal,
                          QT_VERSION_STR, PYQT_VERSION_STR)
from PyQt5.QtGui import QGuiApplication

from electrum.i18n import set_language, languages, language
from electrum.plugin import run_hook
from electrum.util import profiler
from electrum.logging import Logger

if TYPE_CHECKING:
    from electrum.daemon import Daemon
    from electrum.simple_config import SimpleConfig
    from electrum.plugin import Plugins
    from electrum.wallet import Abstract_Wallet

from .qeapp import ElectrumQmlApplication, Exception_Hook

class ElectrumTranslator(QTranslator):
    def __init__(self, parent=None):
        super().__init__(parent)

    def translate(self, context, source_text, disambiguation, n):
        if source_text == "":
            return ""
        return language.gettext(source_text)


class ElectrumGui(Logger):

    @profiler
    def __init__(self, config: 'SimpleConfig', daemon: 'Daemon', plugins: 'Plugins'):
        set_language(config.get('language', self.get_default_language()))
        Logger.__init__(self)
        #os.environ['QML_IMPORT_TRACE'] = '1'
        #os.environ['QT_DEBUG_PLUGINS'] = '1'

        self.logger.info(f"Qml GUI starting up... Qt={QT_VERSION_STR}, PyQt={PYQT_VERSION_STR}")
        self.logger.info("CWD=%s" % os.getcwd())
        # Uncomment this call to verify objects are being properly
        # GC-ed when windows are closed
        #network.add_jobs([DebugMem([Abstract_Wallet, SPV, Synchronizer,
        #                            ElectrumWindow], interval=5)])
        QCoreApplication.setAttribute(Qt.AA_X11InitThreads)
        if hasattr(Qt, "AA_ShareOpenGLContexts"):
            QCoreApplication.setAttribute(Qt.AA_ShareOpenGLContexts)
        if hasattr(QGuiApplication, 'setDesktopFileName'):
            QGuiApplication.setDesktopFileName('electrum.desktop')
        if hasattr(Qt, "AA_EnableHighDpiScaling"):
            QCoreApplication.setAttribute(Qt.AA_EnableHighDpiScaling)

        if "QT_QUICK_CONTROLS_STYLE" not in os.environ:
            os.environ["QT_QUICK_CONTROLS_STYLE"] = "Material"

        self.gui_thread = threading.current_thread()
        self.plugins = plugins
        self.app = ElectrumQmlApplication(sys.argv, config, daemon, plugins)
        self.translator = ElectrumTranslator()
        self.app.installTranslator(self.translator)

        # timer
        self.timer = QTimer(self.app)
        self.timer.setSingleShot(False)
        self.timer.setInterval(500)  # msec
        self.timer.timeout.connect(lambda: None) # periodically enter python scope

        # hook for crash reporter
        Exception_Hook.maybe_setup(config=config, slot=self.app.appController.crash)

        # Initialize any QML plugins
        run_hook('init_qml', self)
        self.app.engine.load('electrum/gui/qml/components/main.qml')

    def close(self):
        self.app.quit()

    def main(self):
        if not self.app._valid:
            return

        self.timer.start()
        signal.signal(signal.SIGINT, lambda *args: self.stop())

        self.logger.info('Entering main loop')
        self.app.exec_()

    def stop(self):
        self.logger.info('closing GUI')
        self.app.quit()

    def get_default_language(self):
        name = QLocale.system().name()
        return name if name in languages else 'en_UK'
