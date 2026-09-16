import qrcode
from qrcode.exceptions import DataOverflowError

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import math
import urllib

from PyQt6 import sip
from PyQt6.QtCore import pyqtProperty, pyqtSignal, pyqtSlot, QObject
from PyQt6.QtGui import QImage, QColor
from PyQt6.QtQuick import QQuickImageProvider
try:
    from PyQt6.QtMultimedia import QVideoFrame, QVideoFrameFormat, QVideoSink
    # Pixel formats whose first plane is an 8-bit luma image, which the QR reader can decode as is.
    _PF = QVideoFrameFormat.PixelFormat
    _LUMA_PLANE_FORMATS = frozenset({
        _PF.Format_Y8,
        _PF.Format_NV12, _PF.Format_NV21,
        _PF.Format_YUV420P, _PF.Format_YV12, _PF.Format_YUV422P,
        _PF.Format_IMC1, _PF.Format_IMC2, _PF.Format_IMC3, _PF.Format_IMC4,
    })
except ImportError:
    # Stub QVideoSink for unit tests without the multimedia dependencies.
    # QR scanning requires QtMultimedia on all platforms.
    from PyQt6.QtCore import QObject as QVideoSink
    _LUMA_PLANE_FORMATS = frozenset()

from electrum.logging import get_logger
from electrum.qrreader import get_qr_reader
from electrum.util import profiler
from electrum.gui.common_qt.util import draw_qr


_logger = get_logger(__name__)


@contextmanager
def _luma_image(frame: 'QVideoFrame'):
    """Yields the frame as an 8-bit luma image: (buffer, buffer_size, stride, width, height).

    Camera frames are usually planar or semi-planar YUV, whose first plane already is such
    an image, so it is yielded straight from the mapped frame, without any pixel conversion
    or copy. Frames in other pixel formats are converted via QImage.
    """
    if frame.pixelFormat() in _LUMA_PLANE_FORMATS and frame.map(QVideoFrame.MapMode.ReadOnly):
        try:
            width, stride = frame.width(), frame.bytesPerLine(0)
            if 0 < width <= stride:
                # Android reports a YUV_420_888 plane as ending with the last row's pixels
                # rather than its padding. Drop that row then, so the view fits the buffer.
                height = min(frame.height(), frame.mappedBytes(0) // stride)
                if height > 0:
                    _logger.debug("decoding luma plane of camera frame in-place", only_once=True)
                    yield frame.bits(0).__int__(), height * stride, stride, width, height
                    return
        finally:
            frame.unmap()
    _logger.debug("converting camera frame to grayscale via QImage", only_once=True)
    image = frame.toImage().convertToFormat(QImage.Format.Format_Grayscale8)
    if image.isNull():
        raise ValueError(f'cannot convert video frame to an image. pixel format: {frame.pixelFormat()}')
    yield image.constBits().__int__(), image.sizeInBytes(), image.bytesPerLine(), image.width(), image.height()


class QEQRParser(QObject):
    _logger = get_logger(__name__)

    dataChanged = pyqtSignal()
    videoSinkChanged = pyqtSignal()

    def __init__(self, text=None, parent=None):
        super().__init__(parent)

        self._busy = False
        self._data = None
        self._video_sink = None

        self._text = text
        self.qrreader = get_qr_reader()

        self._decoder = ThreadPoolExecutor(max_workers=1, thread_name_prefix='QEQRParser')
        decoder = self._decoder
        self.destroyed.connect(lambda: decoder.shutdown(wait=False))

    @pyqtProperty(QVideoSink, notify=videoSinkChanged)
    def videoSink(self):
        return self._video_sink

    @videoSink.setter
    def videoSink(self, sink: QVideoSink):
        if self._video_sink != sink:
            if self._video_sink is not None:
                self._video_sink.videoFrameChanged.disconnect(self.onVideoFrame)
            self._video_sink = sink
            if self._video_sink is not None:
                self._video_sink.videoFrameChanged.connect(self.onVideoFrame)
            self.videoSinkChanged.emit()

    def onVideoFrame(self, videoframe):
        if self._busy or self._data:
            return

        if not videoframe.isValid():
            self._logger.debug('invalid frame')
            return

        self._busy = True

        # keep a reference to frame data on python side, otherwise Qt can free it after the function returns
        frame = QVideoFrame(videoframe)
        self._decoder.submit(self._decode_frame, frame)

    def _decode_frame(self, frame: 'QVideoFrame'):
        # Runs on the worker thread. Signals emitted here are queued to the GUI thread.
        try:
            with _luma_image(frame) as (buffer, buffer_size, stride, width, height):
                # only the centre square of the image is scanned
                size = min(width, height)
                results = self.qrreader.read_qr_code(
                    buffer, buffer_size, stride, width, height,
                    crop=((width - size) // 2, (height - size) // 2, size, size),
                )
            if results:
                self._data = results[0]
                self.dataChanged.emit()
        except Exception as e:
            if isinstance(e, RuntimeError) and sip.isdeleted(self):
                return  # the parser was destroyed while decoding
            self._logger.exception('Error parsing QR frame')
        finally:
            self._busy = False

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
    MAX_QR_PIXELSIZE = 400
    ERROR_CORRECT_LEVEL = qrcode.constants.ERROR_CORRECT_M
    # ^ note: this is higher than for desktop. but on desktop we don't put a logo in the middle.
    QR_BORDER = 2

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

        qr = qrcode.main.QRCode(border=self.QR_BORDER, error_correction=self.ERROR_CORRECT_LEVEL)

        # calculate best box_size
        pixelsize = min(self._max_size, self.MAX_QR_PIXELSIZE)
        try:
            qr.add_data(qstr)
            modules = len(qr.get_matrix())
            qr.box_size = math.floor(pixelsize/modules)
            qr.make(fit=True)
            self.qimg = QImage(modules * qr.box_size, modules * qr.box_size, QImage.Format.Format_RGB32)
            draw_qr(qr=qr, paint_device=self.qimg)
        except (ValueError, qrcode.exceptions.DataOverflowError):
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
        qr = qrcode.QRCode(
            border=QEQRImageProvider.QR_BORDER,
            error_correction=QEQRImageProvider.ERROR_CORRECT_LEVEL,
        )

        # calculate best box_size
        pixelsize = min(self._max_size, QEQRImageProvider.MAX_QR_PIXELSIZE)
        try:
            qr.add_data(qstr)
            modules = len(qr.get_matrix())
            valid = True
        except (ValueError, qrcode.exceptions.DataOverflowError):
            # fake it
            modules = 17 + qr.border * 2
            valid = False

        qr.box_size = math.floor(pixelsize/modules)
        # calculate icon width in modules
        icon_modules = int(modules / 5)
        icon_modules += (icon_modules+1) % 2  # force odd

        return {
            'qr_pixelsize': modules * qr.box_size,
            'icon_pixelsize': icon_modules * qr.box_size,
            'valid': valid
        }
