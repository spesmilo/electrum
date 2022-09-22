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

from PyQt5.QtCore import QLocale, QTimer
from PyQt5.QtGui import QGuiApplication
import PyQt5.QtCore as QtCore

from electrum.i18n import set_language, languages
from electrum.plugin import run_hook
from electrum.util import (profiler)
from electrum.logging import Logger

if TYPE_CHECKING:
    from electrum.daemon import Daemon
    from electrum.simple_config import SimpleConfig
    from electrum.plugin import Plugins

from .qeapp import ElectrumQmlApplication

class ElectrumGui(Logger):

    @profiler
    def __init__(self, config: 'SimpleConfig', daemon: 'Daemon', plugins: 'Plugins'):
        set_language(config.get('language', self.get_default_language()))
        Logger.__init__(self)
        #os.environ['QML_IMPORT_TRACE'] = '1'
        #os.environ['QT_DEBUG_PLUGINS'] = '1'

        self.logger.info(f"Qml GUI starting up... Qt={QtCore.QT_VERSION_STR}, PyQt={QtCore.PYQT_VERSION_STR}")
        self.logger.info("CWD=%s" % os.getcwd())
        # Uncomment this call to verify objects are being properly
        # GC-ed when windows are closed
        #network.add_jobs([DebugMem([Abstract_Wallet, SPV, Synchronizer,
        #                            ElectrumWindow], interval=5)])
        QtCore.QCoreApplication.setAttribute(QtCore.Qt.AA_X11InitThreads)
        if hasattr(QtCore.Qt, "AA_ShareOpenGLContexts"):
            QtCore.QCoreApplication.setAttribute(QtCore.Qt.AA_ShareOpenGLContexts)
        if hasattr(QGuiApplication, 'setDesktopFileName'):
            QGuiApplication.setDesktopFileName('electrum.desktop')
        if hasattr(QtCore.Qt, "AA_EnableHighDpiScaling"):
            QtCore.QCoreApplication.setAttribute(QtCore.Qt.AA_EnableHighDpiScaling);

        if not "QT_QUICK_CONTROLS_STYLE" in os.environ:
            os.environ["QT_QUICK_CONTROLS_STYLE"] = "Material"

        self.gui_thread = threading.current_thread()
        self.plugins = plugins
        self.app = ElectrumQmlApplication(sys.argv, config, daemon, plugins)
        # timer
        self.timer = QTimer(self.app)
        self.timer.setSingleShot(False)
        self.timer.setInterval(500)  # msec
        self.timer.timeout.connect(lambda: None) # periodically enter python scope

        sys.excepthook = self.excepthook
        threading.excepthook = self.texcepthook

        # Initialize any QML plugins
        run_hook('init_qml', self)
        self.app.engine.load('electrum/gui/qml/components/main.qml')

    def close(self):
        self.app.quit()

    def excepthook(self, exc_type, exc_value, exc_tb):
        tb = "".join(traceback.format_exception(exc_type, exc_value, exc_tb))
        self.logger.exception(tb)
        self.app._valid = False
        self.close()

    def texcepthook(self, arg):
        tb = "".join(traceback.format_exception(arg.exc_type, arg.exc_value, arg.exc_tb))
        self.logger.exception(tb)
        self.app._valid = False
        self.close()

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

