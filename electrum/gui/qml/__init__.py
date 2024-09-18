import os
import signal
import sys
import threading
from typing import TYPE_CHECKING

try:
    import PyQt6
except Exception as e:
    from electrum import GuiImportError
    raise GuiImportError(
        "Error: Could not import PyQt6. On Linux systems, "
        "you may try 'sudo apt-get install python3-pyqt6'") from e

try:
    import PyQt6.QtQml
except Exception as e:
    from electrum import GuiImportError
    raise GuiImportError(
        "Error: Could not import PyQt6.QtQml. On Linux systems, "
        "you may try 'sudo apt-get install python3-pyqt6.qtquick'") from e

from PyQt6.QtCore import (Qt, QCoreApplication, QLocale, QTranslator, QTimer, QT_VERSION_STR, PYQT_VERSION_STR)
from PyQt6.QtGui import QGuiApplication

from electrum.i18n import _
from electrum.plugin import run_hook
from electrum.util import profiler
from electrum.logging import Logger
from electrum.gui import BaseElectrumGui

if TYPE_CHECKING:
    from electrum.daemon import Daemon
    from electrum.simple_config import SimpleConfig
    from electrum.plugin import Plugins

from .qeapp import ElectrumQmlApplication, Exception_Hook


class ElectrumTranslator(QTranslator):
    def __init__(self, parent=None):
        super().__init__(parent)

    def translate(self, context, source_text, disambiguation, n):
        return _(source_text, context=context)


class ElectrumGui(BaseElectrumGui, Logger):
    @profiler
    def __init__(self, config: 'SimpleConfig', daemon: 'Daemon', plugins: 'Plugins'):
        BaseElectrumGui.__init__(self, config=config, daemon=daemon, plugins=plugins)
        Logger.__init__(self)

        # uncomment to debug plugin and import tracing
        # os.environ['QML_IMPORT_TRACE'] = '1'
        # os.environ['QT_DEBUG_PLUGINS'] = '1'

        os.environ['QT_ANDROID_DISABLE_ACCESSIBILITY'] = '1'

        # set default locale to en_GB. This is for l10n (e.g. number formatting, number input etc),
        # but not for i18n, which is handled by the Translator
        # this can be removed once the backend wallet is fully l10n aware
        QLocale.setDefault(QLocale('en_GB'))

        self.logger.info(f"Qml GUI starting up... Qt={QT_VERSION_STR}, PyQt={PYQT_VERSION_STR}")
        self.logger.info("CWD=%s" % os.getcwd())
        # Uncomment this call to verify objects are being properly
        # GC-ed when windows are closed
        #network.add_jobs([DebugMem([Abstract_Wallet, SPV, Synchronizer,
        #                            ElectrumWindow], interval=5)])

        if hasattr(Qt, "AA_ShareOpenGLContexts"):
            QCoreApplication.setAttribute(Qt.AA_ShareOpenGLContexts)
        if hasattr(QGuiApplication, 'setDesktopFileName'):
            QGuiApplication.setDesktopFileName('electrum.desktop')

        if "QT_QUICK_CONTROLS_STYLE" not in os.environ:
            os.environ["QT_QUICK_CONTROLS_STYLE"] = "Material"

        self.gui_thread = threading.current_thread()
        self.app = ElectrumQmlApplication(sys.argv, config=config, daemon=daemon, plugins=plugins)
        self.translator = ElectrumTranslator()
        self.app.installTranslator(self.translator)

        # timer
        self.timer = QTimer(self.app)
        self.timer.setSingleShot(False)
        self.timer.setInterval(500)  # msec
        self.timer.timeout.connect(lambda: None)  # periodically enter python scope

        # hook for crash reporter
        Exception_Hook.maybe_setup(config=config, slot=self.app.appController.crash)

        # Initialize any QML plugins
        run_hook('init_qml', self.app)
        self.app.engine.load('electrum/gui/qml/components/main.qml')

    def close(self):
        self.app.quit()

    def main(self):
        if not self.app._valid:
            return

        self.timer.start()
        signal.signal(signal.SIGINT, lambda *args: self._handle_sigint())

        self.logger.info('Entering main loop')
        self.app.exec()

    def _handle_sigint(self):
        self.app.appController.wantClose = True
        self.stop()

    def stop(self):
        self.logger.info('closing GUI')
        self.app.quit()
