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

from typing import List

from PyQt6.QtMultimedia import (QVideoFrame, QVideoFrameFormat, QVideoSink)
from PyQt6.QtGui import QImage
from PyQt6.QtCore import QObject, pyqtSignal

from electrum.i18n import _
from electrum.logging import get_logger


_logger = get_logger(__name__)


class QrReaderVideoSurface(QVideoSink):
    """
    Receives QVideoFrames from QCamera, converts them into a QImage, flips the X and Y axis if
    necessary and sends them to listeners via the frame_available event.
    """

    def __init__(self, parent: QObject = None):
        super().__init__(parent)
        self.videoFrameChanged.connect(self._on_new_frame)

    def _on_new_frame(self, frame: QVideoFrame) -> None:
        if not frame.isValid():
            return

        image_format = QVideoFrameFormat.imageFormatFromPixelFormat(frame.pixelFormat())
        if image_format == QVideoFrameFormat.PixelFormat.Format_Invalid:
            _logger.info(_('QR code scanner for video frame with invalid pixel format'))
            return

        if not frame.map(QVideoFrame.MapMode.ReadOnly):
            _logger.info(_('QR code scanner failed to map video frame'))
            return

        try:
            img = frame.toImage()

            # Check whether we need to flip the image on any axis
            surface_format = frame.surfaceFormat()
            flip_x = surface_format.isMirrored()
            flip_y = surface_format.scanLineDirection() == QVideoFrameFormat.Direction.BottomToTop

            # Mirror the image if needed
            if flip_x or flip_y:
                img = img.mirrored(flip_x, flip_y)

            # Create a copy of the image so the original frame data can be freed
            img = img.copy()
        finally:
            frame.unmap()

        self.frame_available.emit(img)

    frame_available = pyqtSignal(QImage)
