import ctypes
import os
import unittest
from unittest.mock import Mock, patch

import qrcode

from electrum.qrreader import get_qr_reader, MissingQrDetectionLib
from electrum.qrreader import zxing


class TestQrReaderSelection(unittest.TestCase):
    def test_android_uses_zxing(self):
        with patch.dict(os.environ, {'ANDROID_DATA': '/data'}), \
                patch.object(zxing, 'ZXingQrCodeReader') as reader:
            self.assertIs(get_qr_reader(), reader.return_value)

    def test_desktop_uses_zbar(self):
        with patch.dict(os.environ):
            os.environ.pop('ANDROID_DATA', None)
            with patch('electrum.qrreader.zbar.ZbarQrCodeReader') as reader, \
                    patch.object(zxing, 'ZXingQrCodeReader') as android_reader:
                self.assertIs(get_qr_reader(), reader.return_value)
                android_reader.assert_not_called()

    def test_missing_android_library(self):
        with patch.dict(os.environ, {'ANDROID_DATA': '/data'}), \
                patch.object(zxing, 'LIBZXING', None), \
                self.assertLogs('electrum.qrreader', level='ERROR'), \
                self.assertRaises(MissingQrDetectionLib):
            get_qr_reader()


@unittest.skipIf(zxing.LIBZXING is None, 'Build libZXing with contrib/make_zxing.sh')
class TestZXingQrReader(unittest.TestCase):
    def setUp(self):
        self.reader = zxing.ZXingQrCodeReader()

    def make_image(self, data, *, padding=0, rotate=False, invert=False):
        qr = qrcode.QRCode(box_size=1, border=4)
        qr.add_data(data)
        matrix = qr.get_matrix()
        if rotate:
            matrix = list(zip(*matrix[::-1]))
        scale = 3
        width, height = len(matrix[0]) * scale, len(matrix) * scale
        stride = width + padding
        pixels = bytearray()
        for row in matrix:
            scanline = bytes(0 if bool(module) != invert else 255 for module in row for _ in range(scale))
            pixels.extend((scanline + bytes(padding)) * scale)
        buffer = ctypes.create_string_buffer(bytes(pixels))
        return buffer, len(pixels), stride, width, height

    def test_payload_and_position_with_padded_rows(self):
        text = 'bitcoin:test?message=café\x00test'
        image = self.make_image(text.encode('utf-8'), padding=7)
        results = self.reader.read_qr_code(*image)
        self.assertEqual([r.data for r in results], [text])
        result = results[0]
        self.assertEqual(len(result.points), 4)
        for x, y in result.points:
            self.assertTrue(0 <= x < image[3] and 0 <= y < image[4])
        self.assertAlmostEqual(result.center[0], image[3] / 2, delta=2)
        self.assertAlmostEqual(result.center[1], image[4] / 2, delta=2)

    def test_rotated_and_inverted_qr(self):
        results = self.reader.read_qr_code(*self.make_image('rotated', rotate=True, invert=True))
        self.assertEqual([r.data for r in results], ['rotated'])

    def test_blank_frame(self):
        pixels = ctypes.create_string_buffer(b'\xff' * (64 * 64))
        self.assertEqual(self.reader.read_qr_code(pixels, 64 * 64, 64, 64, 64), [])

    def test_invalid_utf8_does_not_break_next_scan(self):
        with self.assertRaises(UnicodeDecodeError):
            self.reader.read_qr_code(*self.make_image(b'\xff\xfe'))
        results = self.reader.read_qr_code(*self.make_image('next frame'))
        self.assertEqual([r.data for r in results], ['next frame'])

    def test_invalid_image_geometry(self):
        pixels = ctypes.create_string_buffer(64)
        invalid_images = [
            (None, 64, 8, 8, 8),
            (pixels, 64, 8, 0, 8),
            (pixels, 63, 8, 8, 8),
            (pixels, 64, 7, 8, 8),
            (pixels, 64, 8, 8, 2**32),
        ]
        for image in invalid_images:
            with self.subTest(image=image), self.assertRaises(ValueError):
                self.reader.read_qr_code(*image)

    def test_decoder_error_does_not_break_next_scan(self):
        real_lib = self.reader._lib
        mock_lib = Mock(wraps=real_lib)
        mock_lib.ZXing_ReadBarcodes.return_value = None
        with patch.object(self.reader, '_lib', mock_lib):
            with self.assertRaises(RuntimeError):
                self.reader.read_qr_code(*self.make_image('test'))
            mock_lib.ZXing_ImageView_delete.assert_called_once()
        results = self.reader.read_qr_code(*self.make_image('next frame'))
        self.assertEqual([r.data for r in results], ['next frame'])
