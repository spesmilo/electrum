from PyQt5.QtCore import pyqtProperty, pyqtSignal, pyqtSlot, QObject, QUrl
from PyQt5.QtGui import QImage
from PyQt5.QtQuick import QQuickImageProvider

from electrum.logging import get_logger

import qrcode
#from qrcode.image.styledpil import StyledPilImage
#from qrcode.image.styles.moduledrawers import *

from PIL import Image, ImageQt

from ctypes import *

class QEQR(QObject):
    def __init__(self, text=None, parent=None):
        super().__init__(parent)
        self._text = text

    _logger = get_logger(__name__)

    scanReadyChanged = pyqtSignal()
    imageChanged = pyqtSignal()

    _scanReady = True
    _image = None

    @pyqtSlot('QImage')
    def scanImage(self, image=None):
        if not self._scanReady:
            self._logger.warning("Already processing an image. Check 'ready' property before calling scanImage")
            return
        self._scanReady = False
        self.scanReadyChanged.emit()

        pilimage = self.convertToPILImage(image)
        self.parseQR(pilimage)

        self._scanReady = True

    def logImageStats(self, image):
        self._logger.info('width: ' + str(image.width()))
        self._logger.info('height: ' + str(image.height()))
        self._logger.info('depth: ' + str(image.depth()))
        self._logger.info('format: ' + str(image.format()))

    def convertToPILImage(self, image): # -> Image:
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

    @pyqtProperty(bool, notify=scanReadyChanged)
    def scanReady(self):
        return self._scanReady

    @pyqtProperty('QImage', notify=imageChanged)
    def image(self):
        return self._image

class QEQRImageProvider(QQuickImageProvider):
    def __init__(self, parent=None):
        super().__init__(QQuickImageProvider.Image)

    _logger = get_logger(__name__)

    def requestImage(self, qstr, size):
        self._logger.debug('QR requested for %s' % qstr)
        qr = qrcode.QRCode(version=1, box_size=8, border=2)
        qr.add_data(qstr)
        qr.make(fit=True)

        pimg = qr.make_image(fill_color='black', back_color='white') #image_factory=StyledPilImage, module_drawer=CircleModuleDrawer())
        qimg = ImageQt.ImageQt(pimg)
        return qimg, qimg.size()
