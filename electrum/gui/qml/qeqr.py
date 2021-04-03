from PyQt5.QtCore import pyqtProperty, pyqtSignal, pyqtSlot, QObject, QUrl

from electrum.logging import get_logger

from PIL import Image
from ctypes import *

class QEQR(QObject):
    def __init__(self, text=None, parent=None):
        super().__init__(parent)
        self._text = text

    _logger = get_logger(__name__)
    scan_ready_changed = pyqtSignal()

    _ready = True

    @pyqtSlot('QImage')
    def scanImage(self, image=None):
        if not self._ready:
            self._logger.warning("Already processing an image. Check 'ready' property before calling scanImage")
            return
        self._ready = False
        self.scan_ready_changed.emit()

        pilimage = self.convertToPILImage(image)
        self.parseQR(pilimage)

        self._ready = True

    def logImageStats(self, image):
        self._logger.info('width: ' + str(image.width()))
        self._logger.info('height: ' + str(image.height()))
        self._logger.info('depth: ' + str(image.depth()))
        self._logger.info('format: ' + str(image.format()))

    def convertToPILImage(self, image) -> Image:
        self.logImageStats(image)

        rawimage = image.constBits()
        # assumption: pixels are 32 bits ARGB
        numbytes = image.width() * image.height() * 4

        self._logger.info(type(rawimage))
        buf = bytearray(numbytes)
        c_buf = (c_byte * numbytes).from_buffer(buf)
        memmove(c_buf, c_void_p(rawimage.__int__()), numbytes)
        buf2 = bytes(buf)

        return Image.frombytes('RGBA', (image.width(), image.height()), buf2, 'raw')

    def parseQR(self, image):
        # TODO
        pass

    @pyqtProperty(bool, notify=scan_ready_changed)
    def ready(self):
        return self._ready

