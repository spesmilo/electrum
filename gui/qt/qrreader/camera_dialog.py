#!/usr/bin/env python3
#
# Electron Cash - lightweight Bitcoin client
# Copyright (C) 2019 Axel Gembe <derago@gmail.com>
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

import time
from typing import List

from PyQt5.QtMultimedia import QCameraInfo, QCamera, QCameraViewfinderSettings
from PyQt5.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QCheckBox
from PyQt5.QtGui import QImage, QPixmap
from PyQt5.QtCore import QSize, QRect, Qt

from electroncash import get_config
from electroncash.i18n import _
from electroncash.util import print_error
from electroncash.qrreaders import get_qr_reader, QrCodeResult

from electroncash_gui.qt.utils import FixedAspectRatioLayout, ImageGraphicsEffect

from .video_widget import QrReaderVideoWidget
from .video_overlay import QrReaderVideoOverlay
from .video_surface import QrReaderVideoSurface
from .crop_blur_effect import QrReaderCropBlurEffect
from .validator import AbstractQrReaderValidator, QrReaderValidatorCounted, QrReaderValidatorResult

class QrReaderCameraDialog(QDialog):
    """
    Dialog for reading QR codes from a camera
    """

    # Try to crop so we have minimum 512 dimensions
    SCAN_SIZE: int = 512

    # Try to QR scan every X seconds
    QR_SCAN_PERIOD: float = 0.200  # every 200ms

    def __init__(self, parent):
        QDialog.__init__(self, parent=parent)

        self.validator: AbstractQrReaderValidator = None
        self.frame_id: int = 0
        self.qr_crop: QRect = None
        self.qrreader_res: List[QrCodeResult] = []
        self.validator_res: QrReaderValidatorResult = None
        self.last_stats_time: float = 0.0
        self.frame_counter: int = 0
        self.qr_frame_counter: int = 0
        self.last_qr_scan_ts: float = 0.0

        self.config = get_config()

        # Try to get the QR reader for this system
        self.qrreader = get_qr_reader()
        if not self.qrreader:
            raise RuntimeError(_("Cannot start QR scanner, not available."))

        # Set up the window, add the maximize button
        flags = self.windowFlags()
        flags = flags | Qt.WindowMaximizeButtonHint
        self.setWindowFlags(flags)
        self.setWindowTitle(_("Scan QR Code"))

        # Create video widget and fixed aspect ratio layout to contain it
        self.video_widget = QrReaderVideoWidget()
        self.video_overlay = QrReaderVideoOverlay()
        self.video_layout = FixedAspectRatioLayout()
        self.video_layout.addWidget(self.video_widget)
        self.video_layout.addWidget(self.video_overlay)

        # Create root layout and add the video widget layout to it
        vbox = QVBoxLayout()
        self.setLayout(vbox)
        vbox.setContentsMargins(0, 0, 0, 0)
        vbox.addLayout(self.video_layout)

        # Create a layout for the controls
        controls_layout = QHBoxLayout()
        controls_layout.setContentsMargins(10, 10, 10, 10)
        vbox.addLayout(controls_layout)

        # Flip horizontally checkbox with default coming from global config
        self.flip_x = QCheckBox()
        self.flip_x.setText(_("&Flip horizontally"))
        self.flip_x.setChecked(self.config.get('qrreader_flip_x', False))
        self.flip_x.stateChanged.connect(self._on_flip_x_changed)
        controls_layout.addWidget(self.flip_x)

        # Create the video surface and receive events when new frames arrive
        self.video_surface = QrReaderVideoSurface(self)
        self.video_surface.frame_available.connect(self._on_frame_available)

        # Create the crop blur effect
        self.crop_blur_effect = QrReaderCropBlurEffect(self)
        self.image_effect = ImageGraphicsEffect(self, self.crop_blur_effect)

    def _on_flip_x_changed(self, _state: int):
        self.config.set_key('qrreader_flip_x', self.flip_x.isChecked())

    @staticmethod
    def _get_resolution(resolutions: List[QSize], min_size: int) -> QSize:
        """
        Given a list of resolutions that the camera supports this function picks the
        lowest resolution that is at least min_size in both width and height.
        If no resolution is found, a RuntimeError is raised.
        """
        def res_list_to_str(res_list: List[QSize]) -> str:
            return ', '.join(['{}x{}'.format(r.width(), r.height()) for r in res_list])

        def check_res(res: QSize):
            return res.width() >= min_size and res.height() >= min_size

        print_error(_('QR code scanner searching for at least {0}x{0}').format(min_size))

        # Query and display all resolutions the camera supports
        format_str = _('QR code scanner camera resolutions: {}')
        print_error(format_str.format(res_list_to_str(resolutions)))

        # Filter to those that are at least min_size in both width and height
        usable_resolutions = [r for r in resolutions if check_res(r)]
        format_str = _('QR code scanner usable resolutions: {}')
        print_error(format_str.format(res_list_to_str(usable_resolutions)))

        # Raise an error if we have no usable resolutions
        if not usable_resolutions:
            raise RuntimeError(_("Cannot start QR scanner, no usable camera resolution found."))

        # Sort the usable resolutions, least number of pixels first, get the first element
        resolution = sorted(usable_resolutions, key=lambda r: r.width() * r.height())[0]
        format_str = _('QR code scanner chosen resolution is {}x{}')
        print_error(format_str.format(resolution.width(), resolution.height()))

        return resolution

    @staticmethod
    def _get_crop(resolution: QSize, scan_size: int) -> QRect:
        """
        Returns a QRect that is scan_size x scan_size in the middle of the resolution
        """
        scan_pos_x = (resolution.width() - scan_size) / 2
        scan_pos_y = (resolution.height() - scan_size) / 2
        return QRect(scan_pos_x, scan_pos_y, scan_size, scan_size)

    def scan(
            self,
            device: str = '',
            validator: AbstractQrReaderValidator = QrReaderValidatorCounted()
        ) -> List[QrCodeResult]:
        """
        Scans a QR code from the given camera device.
        If no QR code is found the returned string will be empty.
        If the camera is not found or can't be opened a RuntimeError will be raised.
        """

        self.validator = validator

        device_info = None

        for camera in QCameraInfo.availableCameras():
            if camera.deviceName() == device:
                device_info = camera
                break

        if not device_info:
            print_error(_('Failed to open selected camera, trying to use default camera'))
            device_info = QCameraInfo.defaultCamera()

        if not device_info or device_info.isNull():
            raise RuntimeError(_("Cannot start QR scanner, no usable camera found."))

        self._init_stats()
        self.qrreader_res = []
        self.validator_res = None

        camera = QCamera(device_info)
        camera.setViewfinder(self.video_surface)
        camera.setCaptureMode(QCamera.CaptureViewfinder)

        # Camera needs to be loaded to query resolutions, this tries to open the camera
        camera.load()
        if camera.status() != QCamera.LoadedStatus:
            raise RuntimeError(_("Cannot start QR scanner, camera is unavailable."))

        # Determine the optimal resolution and compute the crop rect
        camera_resolutions = camera.supportedViewfinderResolutions()
        resolution = self._get_resolution(camera_resolutions, self.SCAN_SIZE)
        self.qr_crop = self._get_crop(resolution, self.SCAN_SIZE)

        # Initialize the video widget
        self.video_widget.setMinimumSize(resolution)
        self.video_overlay.set_crop(self.qr_crop)
        self.video_overlay.set_resolution(resolution)
        self.video_layout.set_aspect_ratio(resolution.width() / resolution.height())

        # Set up the crop blur effect
        self.crop_blur_effect.setCrop(self.qr_crop)

        # Set the camera resolution
        viewfinder_settings = QCameraViewfinderSettings()
        viewfinder_settings.setResolution(resolution)
        camera.setViewfinderSettings(viewfinder_settings)

        # Counter for the QR scanner frame number
        self.frame_id = 0

        camera.start()

        self.exec()

        camera.setViewfinder(None)
        camera.stop()
        camera.unload()

        self.validator = None

        print_error(_('QR code scanner closed'))

        return ''

    def _on_frame_available(self, frame: QImage):
        self.frame_id += 1

        flip_x = self.flip_x.isChecked()

        # Only QR scan every QR_SCAN_PERIOD secs
        qr_scanned = time.time() - self.last_qr_scan_ts >= self.QR_SCAN_PERIOD
        if qr_scanned:
            self.last_qr_scan_ts = time.time()
            # Crop the frame so we only scan a SCAN_SIZE rect
            frame_cropped = frame.copy(self.qr_crop)

            # Convert to Y800 / GREY FourCC (single 8-bit channel)
            # This creates a copy, so we don't need to keep the frame around anymore
            frame_y800 = frame_cropped.convertToFormat(QImage.Format_Grayscale8)

            # Read the QR codes from the frame
            self.qrreader_res = self.qrreader.read_qr_code(
                frame_y800.constBits().__int__(), frame_y800.byteCount(), frame_y800.width(),
                frame_y800.height(), self.frame_id
                )

            # Call the validator to see if the scanned results are acceptable
            self.validator_res = self.validator.validate_results(self.qrreader_res)

            # Update the video overlay with the results
            self.video_overlay.set_results(self.qrreader_res, flip_x, self.validator_res)

            # Close the dialog if the validator accepted the result
            if self.validator_res.accepted:
                self.close()

        # Apply the crop blur effect
        if self.image_effect:
            frame = self.image_effect.apply(frame)

        # If horizontal flipping is enabled, only flip the display
        if flip_x:
            frame = frame.mirrored(True, False)

        # Display the frame in the widget
        self.video_widget.setPixmap(QPixmap.fromImage(frame))

        self._update_stats(qr_scanned)

    def _init_stats(self):
        self.last_stats_time = time.perf_counter()
        self.frame_counter = 0
        self.qr_frame_counter = 0

    def _update_stats(self, qr_scanned):
        self.frame_counter += 1
        if qr_scanned:
            self.qr_frame_counter += 1
        now = time.perf_counter()
        last_stats_delta = now - self.last_stats_time
        if last_stats_delta > 5.0:
            fps = self.frame_counter / last_stats_delta
            qr_fps = self.qr_frame_counter / last_stats_delta
            stats_format = _('QR code display running at {} FPS, scanner at {} FPS')
            print_error(stats_format.format(fps, qr_fps))
            self.frame_counter = 0
            self.qr_frame_counter = 0
            self.last_stats_time = now
