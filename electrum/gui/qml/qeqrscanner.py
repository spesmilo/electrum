import os

from PyQt6.QtCore import pyqtProperty, pyqtSignal, pyqtSlot, QObject, Qt
from PyQt6.QtGui import QGuiApplication

from electrum.gui.qml.qetypes import QEBytes
from electrum.util import send_exception_to_crash_reporter
from electrum.logging import get_logger
from electrum.i18n import _


if 'ANDROID_DATA' in os.environ:
    from jnius import autoclass
    from android import activity

    jpythonActivity = autoclass('org.kivy.android.PythonActivity').mActivity
    jString = autoclass('java.lang.String')
    jIntent = autoclass('android.content.Intent')


class QEQRScanner(QObject):
    _logger = get_logger(__name__)

    foundText = pyqtSignal(str)
    foundBinary = pyqtSignal(QEBytes)

    finished = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._hint = _("Scan a QR code.")
        self.finished.connect(self._unbind, Qt.ConnectionType.QueuedConnection)

        self.destroyed.connect(lambda: self.on_destroy())

    def on_destroy(self):
        self._unbind()

    @pyqtProperty(str)
    def hint(self):
        return self._hint

    @hint.setter
    def hint(self, v: str):
        self._hint = v

    @pyqtSlot()
    def open(self):
        if 'ANDROID_DATA' not in os.environ:
            self._scan_qr_non_android()
            return
        jSimpleScannerActivity = autoclass("org.electrum.qr.SimpleScannerActivity")
        intent = jIntent(jpythonActivity, jSimpleScannerActivity)
        intent.putExtra(jIntent.EXTRA_TEXT, jString(self._hint))

        activity.bind(on_activity_result=self.on_qr_activity_result)
        jpythonActivity.startActivityForResult(intent, 0)

    def on_qr_activity_result(self, requestCode, resultCode, intent):
        try:
            if resultCode == -1:  # RESULT_OK:
                if (contents := intent.getStringExtra(jString("text"))) is not None:
                    self.foundText.emit(contents)
                if (contents := intent.getByteArrayExtra(jString("binary"))) is not None:
                    self._binary_content = QEBytes(bytes(contents.tolist()))
                    self.foundBinary.emit(self._binary_content)
        except Exception as e:  # exc would otherwise get lost
            send_exception_to_crash_reporter(e)
        finally:
            self.finished.emit()

    @pyqtSlot()
    def _unbind(self):
        if 'ANDROID_DATA' in os.environ:
            activity.unbind(on_activity_result=self.on_qr_activity_result)

    def _scan_qr_non_android(self):
        data = QGuiApplication.clipboard().text()
        self.foundText.emit(data)
        self.finished.emit()
        return
