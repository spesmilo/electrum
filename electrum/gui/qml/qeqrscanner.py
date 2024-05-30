import os

from PyQt6.QtCore import pyqtProperty, pyqtSignal, pyqtSlot, QObject, Qt
from PyQt6.QtGui import QGuiApplication

from electrum.util import send_exception_to_crash_reporter, UserFacingException
from electrum.simple_config import SimpleConfig
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

    found = pyqtSignal()

    finished = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._hint = _("Scan a QR code.")
        self._scan_data = ""  # decoded qr code result
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

    @pyqtProperty(str)
    def scanData(self):
        return self._scan_data

    @scanData.setter
    def scanData(self, v: str):
        self._scan_data = v

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
                contents = intent.getStringExtra(jString("text"))
                self.scanData = contents
                self.found.emit()
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
        self.scanData = data
        self.found.emit()
        self.finished.emit()
        return
        # from electrum import qrscanner
        # from .qeapp import ElectrumQmlApplication
        # daemon = ElectrumQmlApplication._daemon
        # config = daemon.config  # type: SimpleConfig
        # try:
        #     video_dev = config.get_video_device()
        #     data = qrscanner.scan_barcode(video_dev)
        #     if data is not None:
        #         self.scanData = data
        #         self.found.emit()
        # except UserFacingException as e:
        #     self._logger.warning(f'camera error: {e!r}')
        #     #self.show_error(e)
        # except Exception as e:
        #     self._logger.exception('camera error')
        #     #self.show_error(repr(e))
