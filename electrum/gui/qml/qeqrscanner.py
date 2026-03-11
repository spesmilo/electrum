import os

from PyQt6.QtCore import pyqtProperty, pyqtSignal, pyqtSlot, QObject, Qt
from PyQt6.QtGui import QGuiApplication

from electrum.gui.qml.qetypes import QEBytes, QEUR
from electrum.util import send_exception_to_crash_reporter
from electrum.logging import get_logger
from electrum.i18n import _
from electrum.ur.ur_decoder import URDecoder


if 'ANDROID_DATA' in os.environ:
    from jnius import autoclass, PythonJavaClass, java_method
    from android import activity

    jpythonActivity = autoclass('org.kivy.android.PythonActivity').mActivity
    jString = autoclass('java.lang.String')
    jIntent = autoclass('android.content.Intent')


    class QRPartCallback(PythonJavaClass):
        __javainterfaces__ = ['org/electrum/qr/ScanCallback']
        __javacontext__ = 'app'

        def __init__(self, handler):
            super().__init__()
            self.handler = handler

        @java_method('(Ljava/lang/String;[B)Z')
        def onPart(self, text, binary):
            return self.handler(text, binary)


class QEQRScanner(QObject):
    REQUEST_CODE_SIMPLE_SCANNER_ACTIVITY = 30368  # random 16 bit int

    _logger = get_logger(__name__)

    foundText = pyqtSignal(str)
    foundBinary = pyqtSignal(QEBytes)
    foundUR = pyqtSignal(QEUR)

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

        self._result = None
        self._decoder = URDecoder()
        self._callback = QRPartCallback(self._on_part)
        jSimpleScannerActivity.setCallback(self._callback)

        intent = jIntent(jpythonActivity, jSimpleScannerActivity)
        intent.putExtra(jIntent.EXTRA_TEXT, jString(self._hint))

        activity.bind(on_activity_result=self.on_qr_activity_result)
        jpythonActivity.startActivityForResult(intent, self.REQUEST_CODE_SIMPLE_SCANNER_ACTIVITY)

    @pyqtSlot()
    def close(self):
        # no-op to prevent qml type error
        pass

    def _on_part(self, text, binary):
        if text:
            self._result = str(text)
            if text.lower().startswith('ur:'):
                self._decoder.receive_part(text)
                if not self._decoder.is_complete():
                    return False
        elif binary:
            self._result = bytes(binary)
        return True

    def on_qr_activity_result(self, requestCode, resultCode, intent):
        if requestCode != self.REQUEST_CODE_SIMPLE_SCANNER_ACTIVITY:
            self._logger.warning(f"got activity result with invalid {requestCode=}")
            return
        try:
            if resultCode == -1:  # RESULT_OK:
                if self._decoder.is_complete():
                    self._ur_content = QEUR(self._decoder.result_message())
                    self.foundUR.emit(self._ur_content)
                elif isinstance(self._result, str):
                    self.foundText.emit(self._result)
                elif isinstance(self._result, bytes):
                    self._binary_content = QEBytes(self._result)
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
