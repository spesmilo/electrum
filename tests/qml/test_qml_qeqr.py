import asyncio
import unittest
from unittest.mock import Mock, patch

from PyQt6.QtCore import QObject, pyqtSignal
from PyQt6.QtGui import QImage

from electrum.gui.qml.qeqr import QEQRParser
from electrum.qrreader.abstract_base import QrCodeResult


class VideoSinkMock(QObject):
    videoFrameChanged = pyqtSignal(object)


class TestQRParser(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.reader = Mock()
        self.reader.read_qr_code.return_value = [QrCodeResult('scanned text', (0, 0), [])]
        with patch('electrum.gui.qml.qeqr.get_qr_reader', return_value=self.reader):
            self.parser = QEQRParser()
        loop_patch = patch('electrum.gui.qml.qeqr.get_asyncio_loop', return_value=asyncio.get_running_loop())
        loop_patch.start()
        self.addCleanup(loop_patch.stop)
        self.frame = Mock()
        self.frame.isValid.return_value = True
        self.frame.toImage.return_value = QImage(8, 8, QImage.Format.Format_RGB32)

    async def scan(self, frame):
        self.parser.onVideoFrame(frame)

        async def wait_until_done():
            while self.parser.busy:
                await asyncio.sleep(0.001)

        await asyncio.wait_for(wait_until_done(), timeout=1)

    async def test_invalid_frame_does_not_block_scanning(self):
        invalid_frame = Mock()
        invalid_frame.isValid.return_value = False
        await self.scan(invalid_frame)
        self.reader.read_qr_code.assert_not_called()
        await self.scan(self.frame)
        self.assertEqual(self.parser.data, 'scanned text')

    async def test_null_image_does_not_block_scanning(self):
        self.frame.toImage.return_value = QImage()
        await self.scan(self.frame)
        self.reader.read_qr_code.assert_not_called()
        self.frame.toImage.return_value = QImage(8, 8, QImage.Format.Format_RGB32)
        await self.scan(self.frame)
        self.assertEqual(self.parser.data, 'scanned text')

    async def test_decode_error_does_not_block_scanning(self):
        self.reader.read_qr_code.side_effect = ValueError('cannot decode frame')
        with self.assertLogs(self.parser._logger, level='ERROR'):
            await self.scan(self.frame)
        self.assertEqual(self.parser.data, '')
        self.reader.read_qr_code.side_effect = None
        await self.scan(self.frame)
        self.assertEqual(self.parser.data, 'scanned text')

    async def test_result_stops_scanning_until_reset(self):
        await self.scan(self.frame)
        await self.scan(self.frame)
        self.reader.read_qr_code.assert_called_once()
        self.parser.reset()
        self.assertEqual(self.parser.data, '')
        await self.scan(self.frame)
        self.assertEqual(self.reader.read_qr_code.call_count, 2)
        self.assertEqual(self.parser.data, 'scanned text')

    async def test_replacing_and_clearing_video_sink(self):
        old_sink, new_sink = VideoSinkMock(), VideoSinkMock()
        self.parser.videoSink = old_sink
        self.parser.videoSink = new_sink
        old_sink.videoFrameChanged.emit(self.frame)
        self.assertFalse(self.parser.busy)
        self.parser.videoSink = None
        new_sink.videoFrameChanged.emit(self.frame)
        self.assertFalse(self.parser.busy)
        self.reader.read_qr_code.assert_not_called()
