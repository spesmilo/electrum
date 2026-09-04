#!/usr/bin/env python3
#
# Copyright (C) 2019 Axel Gembe <derago@gmail.com>
# Copyright (c) 2024 The Electrum developers
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from typing import Optional

from PyQt6.QtMultimedia import QVideoFrame, QVideoSink
from PyQt6.QtGui import QImage
from PyQt6.QtCore import QObject, QTimer, pyqtSignal

from electrum.logging import get_logger


_logger = get_logger(__name__)


class QrReaderVideoSurface(QVideoSink):
    """
    Receives QVideoFrames from QCamera, converts the newest one into a QImage and
    sends it to listeners via the frame_available signal.
    """

    frame_available = pyqtSignal(QImage)

    def __init__(self, parent: QObject = None):
        super().__init__(parent)
        self._pending_frame: Optional[QVideoFrame] = None
        self._stopped = False
        self._process_timer = QTimer(self)
        self._process_timer.setSingleShot(True)
        self._process_timer.setInterval(0)
        self._process_timer.timeout.connect(self._process_pending_frame)
        self.videoFrameChanged.connect(self._on_new_frame)

    def _on_new_frame(self, frame: QVideoFrame) -> None:
        if not frame.isValid():
            return
        if self._stopped:
            # This frame was already queued for delivery when we got stopped. The sink keeps
            # the last delivered frame (a camera buffer) alive: release it again.
            self.setVideoFrame(QVideoFrame())
            return
        # only keep the newest frame
        self._pending_frame = QVideoFrame(frame)  # keep our own reference (the received frame is owned by Qt)
        if not self._process_timer.isActive():
            self._process_timer.start()

    def _process_pending_frame(self) -> None:
        frame, self._pending_frame = self._pending_frame, None
        if frame is None:
            return
        if not frame.map(QVideoFrame.MapMode.ReadOnly):
            _logger.warning(f"failed to map video frame. pixel format: {frame.pixelFormat()}", only_once=True)
            return
        try:
            img = frame.toImage()
        finally:
            frame.unmap()
        if img.isNull():
            _logger.warning(f"failed to convert video frame to image. pixel format: {frame.pixelFormat()}", only_once=True)
            return
        self.frame_available.emit(img)

    def stop(self) -> None:
        self._stopped = True
        self._process_timer.stop()
        self._pending_frame = None
