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

from typing import Mapping

from .camera_dialog import (QrReaderCameraDialog, CameraError, NoCamerasFound,
                            get_camera_path)
from .validator import (QrReaderValidatorResult, AbstractQrReaderValidator,
                        QrReaderValidatorCounting, QrReaderValidatorColorizing,
                        QrReaderValidatorStrong, QrReaderValidatorCounted)


def find_system_cameras() -> Mapping[str, str]:
    """Returns a camera_description -> camera_path map."""
    from PyQt6.QtMultimedia import QMediaDevices
    system_cameras = QMediaDevices.videoInputs()
    return {cam.description(): get_camera_path(cam) for cam in system_cameras}
