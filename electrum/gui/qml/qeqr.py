import asyncio
import qrcode
from qrcode.exceptions import DataOverflowError

import math
import urllib

from PIL import ImageQt

from PyQt6.QtCore import pyqtProperty, pyqtSignal, pyqtSlot, QObject, QRect
from PyQt6.QtGui import QImage, QColor
from PyQt6.QtQuick import QQuickImageProvider
from PyQt6.QtMultimedia import QVideoSink

from electrum.logging import get_logger
from electrum.qrreader import get_qr_reader
from electrum.i18n import _
from electrum.util import profiler, get_asyncio_loop


class QEQRParser(QObject):
    _logger = get_logger(__name__)

    busyChanged = pyqtSignal()
    dataChanged = pyqtSignal()
    sizeChanged = pyqtSignal()
    videoSinkChanged = pyqtSignal()

    def __init__(self, text=None, parent=None):
        super().__init__(parent)

        self._busy = False
        self._data = None
        self._video_sink = None

        self._text = text
        self.qrreader = get_qr_reader()
        if not self.qrreader:
            raise Exception(_("The platform QR detection library is not available."))

    @pyqtProperty(QVideoSink, notify=videoSinkChanged)
    def videoSink(self):
        return self._video_sink

    @videoSink.setter
    def videoSink(self, sink: QVideoSink):
        if self._video_sink != sink:
            self._video_sink = sink
            self._video_sink.videoFrameChanged.connect(self.onVideoFrame)

    def onVideoFrame(self, videoframe):
        if self._busy or self._data:
            return

        self._busy = True
        self.busyChanged.emit()

        if not videoframe.isValid():
            self._logger.debug('invalid frame')
            return

        async def co_parse_qr(frame):
            image = frame.toImage()
            self._parseQR(image)

        asyncio.run_coroutine_threadsafe(co_parse_qr(videoframe), get_asyncio_loop())

    def _parseQR(self, image: QImage):
        self._size = min(image.width(), image.height())
        self.sizeChanged.emit()
        img_crop_rect = self._get_crop(image, self._size)
        frame_cropped = image.copy(img_crop_rect)

        # Convert to Y800 / GREY FourCC (single 8-bit channel)
        frame_y800 = frame_cropped.convertToFormat(QImage.Format.Format_Grayscale8)
        self.frame_id = 0
        # Read the QR codes from the frame
        self.qrreader_res = self.qrreader.read_qr_code(
            frame_y800.constBits().__int__(),
            frame_y800.sizeInBytes(),
            frame_y800.bytesPerLine(),
            frame_y800.width(),
            frame_y800.height(),
            self.frame_id
            )

        if len(self.qrreader_res) > 0:
            result = self.qrreader_res[0]
            self._data = result
            self.dataChanged.emit()

        self._busy = False
        self.busyChanged.emit()

    def _get_crop(self, image: QImage, scan_size: int) -> QRect:
        """Returns a QRect that is scan_size x scan_size in the middle of the resolution"""
        scan_pos_x = (image.width() - scan_size) // 2
        scan_pos_y = (image.height() - scan_size) // 2
        return QRect(scan_pos_x, scan_pos_y, scan_size, scan_size)

    @pyqtProperty(bool, notify=busyChanged)
    def busy(self):
        return self._busy

    @pyqtProperty(int, notify=sizeChanged)
    def size(self):
        return self._size

    @pyqtProperty(str, notify=dataChanged)
    def data(self):
        if not self._data:
            return ''
        return self._data.data

    @pyqtSlot()
    def reset(self):
        self._data = None
        self.dataChanged.emit()


class QEQRImageProvider(QQuickImageProvider):
    def __init__(self, max_size, parent=None):
        super().__init__(QQuickImageProvider.ImageType.Image)
        self._max_size = max_size
        self.qimg = None

    _logger = get_logger(__name__)

    @profiler
    def requestImage(self, qstr, size):
        # Qt does a urldecode before passing the string here
        # but BIP21 (and likely other uri based specs) requires urlencoding,
        # so we re-encode percent-quoted if a known 'scheme' is found in the string
        # (unknown schemes might be found when a colon is in a serialized TX, which
        # leads to mangling of the tx, so we check for supported schemes.)
        uri = urllib.parse.urlparse(qstr)
        if uri.scheme and uri.scheme in ['bitcoin', 'lightning']:
            # urlencode request parameters
            query = urllib.parse.parse_qs(uri.query)
            query = urllib.parse.urlencode(query, doseq=True, quote_via=urllib.parse.quote)
            uri = uri._replace(query=query)
            qstr = urllib.parse.urlunparse(uri)

        qr = qrcode.QRCode(version=1, border=2)
        qr.add_data(qstr)

        # calculate best box_size
        pixelsize = min(self._max_size, 400)
        try:
            modules = 17 + 4 * qr.best_fit() + qr.border * 2
            qr.box_size = math.floor(pixelsize/modules)

            qr.make(fit=True)

            pimg = qr.make_image(fill_color='black', back_color='white')
            self.qimg = ImageQt.ImageQt(pimg)
        except DataOverflowError:
            # fake it
            modules = 17 + qr.border * 2
            box_size = math.floor(pixelsize/modules)
            self.qimg = QImage(box_size * modules, box_size * modules, QImage.Format.Format_RGB32)
            self.qimg.fill(QColor('gray'))
        return self.qimg, self.qimg.size()


# helper for placing icon exactly where it should go on the QR code
# pyqt5 is unwilling to accept slots on QEQRImageProvider, so we need to define
# a separate class (sigh)
class QEQRImageProviderHelper(QObject):
    def __init__(self, max_size, parent=None):
        super().__init__(parent)
        self._max_size = max_size

    @pyqtSlot(str, result='QVariantMap')
    def getDimensions(self, qstr):
        qr = qrcode.QRCode(version=1, border=2)
        qr.add_data(qstr)

        # calculate best box_size
        pixelsize = min(self._max_size, 400)
        try:
            modules = 17 + 4 * qr.best_fit() + qr.border * 2
            valid = True
        except DataOverflowError:
            # fake it
            modules = 17 + qr.border * 2
            valid = False

        qr.box_size = math.floor(pixelsize/modules)
        # calculate icon width in modules
        icon_modules = int(modules / 5)
        icon_modules += (icon_modules+1) % 2  # force odd

        return {
            'modules': modules,
            'box_size': qr.box_size,
            'icon_modules': icon_modules,
            'valid': valid
        }
