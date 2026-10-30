import qrcode
from qrcode.exceptions import DataOverflowError

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import math
from typing import Optional, Tuple
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

from electrum.bcur import URScanCollector, UREncoder
from electrum.logging import get_logger
from electrum.qrreader import get_qr_reader
from electrum.util import profiler
from electrum.gui.common_qt.util import draw_qr, tx_to_qr_data
from electrum.transaction import tx_from_any

from .qeconfig import QEConfig


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
    urProgressChanged = pyqtSignal()

    def __init__(self, text=None, parent=None):
        super().__init__(parent)

        self._busy = False
        self._data = None
        self._video_sink = None
        self._ur_collector = URScanCollector()  # only used on the decoder thread
        self._ur_progress = None  # type: Optional[Tuple[int, int]]

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

    @pyqtSlot('QVariant')
    def decodeFrameOneShot(self, frame: 'QVideoFrame'):
        """
        Decodes frame even if the decoder is already busy (with a preview frame)
        Allows a manual 'tap-to-focus'-like image capture for devices without autofocus:
        https://github.com/spesmilo/electrum/issues/10383
        """
        if self._data or not frame.isValid():
            return
        self._logger.debug(f"one-shot frame decode")
        self._decoder.submit(self._decode_frame, QVideoFrame(frame))

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
            texts = []
            for result in results:
                try:
                    texts.append(result.data.decode('utf-8'))
                except UnicodeDecodeError:
                    self._logger.warning('ignoring QR code: payload is not valid UTF-8 text')
            if texts:
                data = self._ur_collector.add_frame(texts)
                self._update_ur_progress()
                if data is not None:
                    self._data = data
                    self.dataChanged.emit()
        except Exception as e:
            if isinstance(e, RuntimeError) and sip.isdeleted(self):
                return  # the parser was destroyed while decoding
            self._logger.exception('Error parsing QR frame')
        finally:
            self._busy = False

    def _update_ur_progress(self):
        # runs on the decoder thread
        progress = self._ur_collector.progress
        if progress != self._ur_progress:
            self._ur_progress = progress
            self.urProgressChanged.emit()

    def _reset_ur(self):
        # runs on the decoder thread
        self._ur_collector.reset()
        self._update_ur_progress()

    @pyqtProperty(bool, notify=urProgressChanged)
    def urInProgress(self):
        return self._ur_progress is not None

    @pyqtProperty(int, notify=urProgressChanged)
    def urPartsReceived(self):
        progress = self._ur_progress  # written by the decoder thread, so read it only once
        return progress[0] if progress else 0

    @pyqtProperty(int, notify=urProgressChanged)
    def urPartsTotal(self):
        progress = self._ur_progress
        return progress[1] if progress else 0

    @pyqtProperty(str, notify=dataChanged)
    def data(self):
        return self._data or ''

    @pyqtSlot()
    def reset(self):
        self._data = None
        self._decoder.submit(self._reset_ur)
        self.dataChanged.emit()


class QEQRImageProvider(QQuickImageProvider):
    MAX_QR_PIXELSIZE = 400
    ERROR_CORRECT_LEVEL = qrcode.constants.ERROR_CORRECT_M
    # ^ note: this is higher than for desktop. but on desktop we don't put a logo in the middle.
    QR_BORDER = 2
    MIN_BOX_SIZE = 2  # pixels per module, draw_qr refuses to draw smaller ones

    def __init__(self, max_size, parent=None):
        super().__init__(QQuickImageProvider.ImageType.Image)
        self._max_size = max_size

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
            qimg = QImage(modules * qr.box_size, modules * qr.box_size, QImage.Format.Format_RGB32)
            draw_qr(qr=qr, paint_device=qimg, min_boxsize=self.MIN_BOX_SIZE)
        except (ValueError, qrcode.exceptions.DataOverflowError):
            # fake it
            modules = 17 + qr.border * 2
            box_size = math.floor(pixelsize/modules)
            qimg = QImage(box_size * modules, box_size * modules, QImage.Format.Format_RGB32)
            qimg.fill(QColor('gray'))
        return qimg, qimg.size()


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

    def _max_version(self) -> int:
        """Returns the largest QR version that the 'qrgen' provider can draw."""
        pixelsize = min(self._max_size, QEQRImageProvider.MAX_QR_PIXELSIZE)
        max_modules = int(pixelsize // QEQRImageProvider.MIN_BOX_SIZE)
        return min(40, (max_modules - 2 * QEQRImageProvider.QR_BORDER - 17) // 4)

    @pyqtSlot(str, result='QVariantMap')
    def getTxExportData(self, tx_text: str) -> dict:
        if not tx_text:  # the binding can be evaluated before the dialog's 'psbt' is set
            return {'text': '', 'qr_text': '', 'ur_type': '', 'ur_payload': '', 'data_stripped': False}
        tx = tx_from_any(tx_text, sanitize=False)
        qr_data, data_stripped = tx_to_qr_data(
            tx,
            config=QEConfig.instance.config,
            error_correction=QEQRImageProvider.ERROR_CORRECT_LEVEL,
            max_version=self._max_version(),
        )
        ur_type = ur_payload = ''
        if isinstance(qr_data, UREncoder):
            ur_type = qr_data.ur_type
            if qr_data.is_single_part:
                qr_data = qr_data.next_part()
            else:
                ur_payload, qr_data = qr_data.payload.hex(), ''
        return {
            'text': str(tx),  # for copy/share: network tx if complete, else PSBT
            'qr_text': qr_data,  # for a static QR code
            'ur_type': ur_type,  # set if the QR code is a UR
            'ur_payload': ur_payload,  # set for an animated QR code (instead of qr_text)
            'data_stripped': data_stripped,
        }


class QEURQREncoder(QObject):
    """Generates the parts of a multi-part UR, to show it as animated QR code."""

    urChanged = pyqtSignal()
    currentPartChanged = pyqtSignal()

    def __init__(self, parent: Optional[QObject] = None) -> None:
        super().__init__(parent)
        self._ur_type = ''
        self._payload = ''
        self._encoder: Optional[UREncoder] = None
        self._current_part = ''

    @pyqtProperty(str, notify=urChanged)
    def urType(self) -> str:
        return self._ur_type

    @urType.setter
    def urType(self, ur_type: str) -> None:
        if self._ur_type != ur_type:
            self._ur_type = ur_type
            self._update_encoder()

    @pyqtProperty(str, notify=urChanged)
    def payload(self) -> str:
        """hex"""
        return self._payload

    @payload.setter
    def payload(self, payload: str) -> None:
        if self._payload != payload:
            self._payload = payload
            self._update_encoder()

    @pyqtProperty(bool, notify=urChanged)
    def isMultiPart(self) -> bool:
        return self._encoder is not None and not self._encoder.is_single_part

    @pyqtProperty(str, notify=currentPartChanged)
    def currentPart(self) -> str:
        return self._current_part

    @pyqtSlot()
    def nextPart(self) -> None:
        self._current_part = self._encoder.next_part() if self._encoder else ''
        self.currentPartChanged.emit()

    def _update_encoder(self) -> None:
        self._encoder = None
        if self._ur_type and self._payload:
            config = QEConfig.instance.config
            self._encoder = UREncoder(
                self._ur_type, bytes.fromhex(self._payload), max_fragment_len=config.GUI_UR_MAX_FRAGMENT_LEN)
        self.urChanged.emit()
        self.nextPart()
