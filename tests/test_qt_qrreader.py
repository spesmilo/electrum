import sys
import unittest
from unittest.mock import Mock, patch

import qrcode

try:
    from PyQt6.QtCore import QRect
    from PyQt6.QtGui import QColor, QImage, QPainter
except ImportError:
    raise unittest.SkipTest('PyQt6 is not installed')

from electrum.gui.qt import qrreader
from electrum.qrreader import QrCodeResult, zxing

from . import ElectrumTestCase

try:
    from PyQt6.QtMultimedia import QCamera
except ImportError:
    qtmultimedia = None
else:
    from electrum.gui.qt.qrreader import qtmultimedia
    from electrum.gui.qt.qrreader.qtmultimedia import camera_dialog


class TestQtQrReader(ElectrumTestCase):
    def test_linux_camera_uses_qtmultimedia(self):
        config, callback = Mock(), Mock()
        with patch.object(sys, 'platform', 'linux'), \
                patch.object(qrreader, '_has_camera_permission', return_value=True), \
                patch.object(qrreader, '_scan_qrcode_using_qtmultimedia') as scan:
            qrreader.scan_qrcode_from_camera(parent=None, config=config, callback=callback)
        scan.assert_called_once_with(parent=None, config=config, callback=callback)

    def test_denied_camera_permission_reports_failure(self):
        callback = Mock()
        with patch.object(qrreader, '_has_camera_permission', return_value=False), \
                patch.object(qrreader, '_scan_qrcode_using_qtmultimedia') as scan:
            qrreader._scan_qrcode_from_camera(parent=None, config=Mock(), callback=callback)
        scan.assert_not_called()
        callback.assert_called_once()
        success, error, result = callback.call_args.args
        self.assertFalse(success)
        self.assertTrue(error)
        self.assertIsNone(result)

    def test_null_image_is_not_decoded(self):
        with patch.object(qrreader, 'get_qr_reader') as reader:
            self.assertEqual(qrreader.scan_qr_from_image(QImage()), [])
        reader.assert_not_called()

    def test_missing_qtmultimedia_reports_failure(self):
        callback = Mock()
        with patch.dict(sys.modules, {'electrum.gui.qt.qrreader.qtmultimedia': None}), \
                self.assertLogs(qrreader._logger, level='ERROR'):
            qrreader._scan_qrcode_using_qtmultimedia(parent=None, config=Mock(), callback=callback)
        callback.assert_called_once()
        success, error, result = callback.call_args.args
        self.assertFalse(success)
        self.assertTrue(error)
        self.assertIsNone(result)


@unittest.skipIf(qtmultimedia is None, 'PyQt6.QtMultimedia is not installed')
class TestQtCameraReader(ElectrumTestCase):
    def test_linux_camera_enumeration_preserves_device_paths(self):
        camera = Mock()
        camera.description.return_value = 'USB Camera'
        camera.id.return_value = b'/dev/video2'
        with patch.object(sys, 'platform', 'linux'), \
                patch('PyQt6.QtMultimedia.QMediaDevices.videoInputs', return_value=[camera]):
            self.assertEqual(qrreader.find_system_cameras(), {'USB Camera': '/dev/video2'})

    def test_camera_error_rejects_scan(self):
        dialog = Mock()
        dialog._error_message = None
        dialog._ok_done = False
        camera_dialog.QrReaderCameraDialog._on_camera_error(
            dialog, QCamera.Error.CameraError, 'Camera disconnected')
        self.assertEqual(dialog._error_message, 'Camera disconnected')
        dialog.reject.assert_called_once_with()

    def test_startup_failure_cleans_up_dialog_and_allows_retry(self):
        config, callback, dialog = Mock(), Mock(), Mock()
        config.get_video_device.return_value = '/dev/video2'
        dialog.start_scan.side_effect = qtmultimedia.NoCamerasFound('Camera is unavailable')
        with patch.object(qrreader, '_qr_dialog', None), \
                patch.object(qtmultimedia, 'QrReaderCameraDialog', return_value=dialog):
            qrreader._scan_qrcode_using_qtmultimedia(parent=None, config=config, callback=callback)
            self.assertIsNone(qrreader._qr_dialog)
            dialog._boilerplate_cleanup.assert_called_once_with()
            dialog.deleteLater.assert_called_once_with()
            callback.assert_called_once_with(False, 'Camera is unavailable', None)
            dialog.start_scan.side_effect = None
            qrreader._scan_qrcode_using_qtmultimedia(parent=None, config=config, callback=callback)
            self.assertEqual(dialog.start_scan.call_count, 2)
            dialog.start_scan.assert_called_with('/dev/video2')

    def test_cancel_releases_dialog_and_calls_callback(self):
        callback, dialog = Mock(), Mock()
        with patch.object(qrreader, '_qr_dialog', None), \
                patch.object(qtmultimedia, 'QrReaderCameraDialog', return_value=dialog):
            qrreader._scan_qrcode_using_qtmultimedia(parent=None, config=Mock(), callback=callback)
            finish_callback = dialog.qr_finished.connect.call_args.args[0]
            finish_callback(False, '', '')
            self.assertIsNone(qrreader._qr_dialog)
        dialog.deleteLater.assert_called_once_with()
        callback.assert_called_once_with(False, '', '')

    def test_decoder_error_does_not_escape_frame_callback(self):
        dialog = Mock()
        frame = QImage(21, 21, QImage.Format.Format_RGB32)
        dialog._ok_done = False
        dialog.frame_id = 0
        dialog.resolution = frame.size()
        dialog.last_qr_scan_ts = 0
        dialog.qr_crop = QRect(0, 0, frame.width(), frame.height())
        dialog.flip_x.isChecked.return_value = False
        dialog.image_effect = None
        dialog.qrreader.interval.return_value = 0
        dialog.qrreader.read_qr_code.side_effect = UnicodeDecodeError('utf8', b'\xff', 0, 1, 'invalid')
        dialog.validator.validate_results.return_value.accepted = False
        with patch.object(camera_dialog, 'QPixmap'):
            camera_dialog.QrReaderCameraDialog._on_frame_available(dialog, frame)
        self.assertEqual(dialog.qrreader_res, [])
        dialog.validator.validate_results.assert_called_once_with([])
        dialog.accept.assert_not_called()
        results = [QrCodeResult('next frame', (10, 10), [])]
        dialog.qrreader.read_qr_code.side_effect = None
        dialog.qrreader.read_qr_code.return_value = results
        dialog.validator.validate_results.return_value.accepted = True
        camera_dialog.QrReaderCameraDialog._on_frame_available(dialog, frame)
        self.assertEqual(dialog.qrreader_res, results)
        dialog.accept.assert_called_once_with()


@unittest.skipIf(zxing.LIBZXING is None, 'Build libZXing with contrib/make_zxing.sh')
class TestQtQrImages(ElectrumTestCase):
    @staticmethod
    def make_image(data, *, border=4):
        qr = qrcode.QRCode(box_size=3, border=border)
        qr.add_data(data)
        matrix = qr.get_matrix()
        image = QImage(len(matrix[0]) * 3, len(matrix) * 3, QImage.Format.Format_RGB32)
        image.fill(QColor('white'))
        painter = QPainter(image)
        for y, row in enumerate(matrix):
            for x, module in enumerate(row):
                if module:
                    painter.fillRect(x * 3, y * 3, 3, 3, QColor('black'))
        painter.end()
        return image

    def test_decode_image_with_padded_grayscale_rows(self):
        text = 'bitcoin:test?message=café\x00test'
        image = self.make_image(text.encode('utf-8'))
        grayscale = image.convertToFormat(QImage.Format.Format_Grayscale8)
        self.assertGreater(grayscale.bytesPerLine(), grayscale.width())
        results = qrreader.scan_qr_from_image(image)
        self.assertEqual([result.data for result in results], [text])

    def test_decode_image_without_quiet_zone(self):
        image = self.make_image('no border', border=0)
        results = qrreader.scan_qr_from_image(image)
        self.assertEqual([result.data for result in results], ['no border'])

    def test_decode_multiple_codes_from_image(self):
        left, right = self.make_image('left QR'), self.make_image('right QR')
        right_x = left.width() + 31
        image = QImage(right_x + right.width(), max(left.height(), right.height()), QImage.Format.Format_RGB32)
        image.fill(QColor('white'))
        painter = QPainter(image)
        painter.drawImage(0, 0, left)
        painter.drawImage(right_x, 0, right)
        painter.end()
        results = {result.data: result for result in qrreader.scan_qr_from_image(image)}
        self.assertEqual(set(results), {'left QR', 'right QR'})
        self.assertLess(results['left QR'].center[0], left.width())
        self.assertGreater(results['right QR'].center[0], right_x)
