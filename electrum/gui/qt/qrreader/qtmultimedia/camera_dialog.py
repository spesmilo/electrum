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
import math
import sys
import os
from typing import List

from PyQt5.QtMultimedia import QCameraInfo, QCamera, QCameraViewfinderSettings
from PyQt5.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QCheckBox, QPushButton, QLabel
from PyQt5.QtGui import QImage, QPixmap
from PyQt5.QtCore import QSize, QRect, Qt, pyqtSignal, PYQT_VERSION

from electrum.simple_config import SimpleConfig
from electrum.i18n import _
from electrum.qrreader import get_qr_reader, QrCodeResult, MissingQrDetectionLib
from electrum.logging import Logger

from electrum.gui.qt.util import MessageBoxMixin, FixedAspectRatioLayout, ImageGraphicsEffect

from .video_widget import QrReaderVideoWidget
from .video_overlay import QrReaderVideoOverlay
from .video_surface import QrReaderVideoSurface
from .crop_blur_effect import QrReaderCropBlurEffect
from .validator import AbstractQrReaderValidator, QrReaderValidatorCounted, QrReaderValidatorResult


class CameraError(RuntimeError):
    ''' Base class of the camera-related error conditions. '''

class NoCamerasFound(CameraError):
    ''' Raised by start_scan if no usable cameras were found. Interested
    code can catch this specific exception.'''

class NoCameraResolutionsFound(CameraError):
    ''' Raised internally if no usable camera resolutions were found. '''

class QrReaderCameraDialog(Logger, MessageBoxMixin, QDialog):
    """
    Dialog for reading QR codes from a camera
    """

    # Try to crop so we have minimum 512 dimensions
    SCAN_SIZE: int = 512

    qr_finished = pyqtSignal(bool, str, object)

    def __init__(self, parent, *, config: SimpleConfig):
        ''' Note: make sure parent is a "top_level_window()" as per
        MessageBoxMixin API else bad things can happen on macOS. '''
        QDialog.__init__(self, parent=parent)
        Logger.__init__(self)

        self.validator: AbstractQrReaderValidator = None
        self.frame_id: int = 0
        self.qr_crop: QRect = None
        self.qrreader_res: List[QrCodeResult] = []
        self.validator_res: QrReaderValidatorResult = None
        self.last_stats_time: float = 0.0
        self.frame_counter: int = 0
        self.qr_frame_counter: int = 0
        self.last_qr_scan_ts: float = 0.0
        self.camera: QCamera = None
        self._error_message: str = None
        self._ok_done: bool = False
        self.camera_sc_conn = None
        self.resolution: QSize = None

        self.config = config

        # Try to get the QR reader for this system
        self.qrreader = get_qr_reader()

        # Set up the window, add the maximize button
        flags = self.windowFlags()
        flags = flags | Qt.WindowMaximizeButtonHint
        self.setWindowFlags(flags)
        self.setWindowTitle(_("Scan QR Code"))
        self.setWindowModality(Qt.WindowModal if parent else Qt.ApplicationModal)

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

        self.lowres_label = QLabel(_("Note: This camera generates frames of relatively low resolution; QR scanning accuracy may be affected"))
        self.lowres_label.setWordWrap(True)
        self.lowres_label.setAlignment(Qt.AlignVCenter | Qt.AlignHCenter)
        vbox.addWidget(self.lowres_label)
        self.lowres_label.setHidden(True)

        # Create a layout for the controls
        controls_layout = QHBoxLayout()
        controls_layout.addStretch(2)
        controls_layout.setContentsMargins(10, 10, 10, 10)
        controls_layout.setSpacing(10)
        vbox.addLayout(controls_layout)

        # Flip horizontally checkbox with default coming from global config
        self.flip_x = QCheckBox()
        self.flip_x.setText(_("&Flip horizontally"))
        self.flip_x.setChecked(bool(self.config.get('qrreader_flip_x', True)))
        self.flip_x.stateChanged.connect(self._on_flip_x_changed)
        controls_layout.addWidget(self.flip_x)

        close_but = QPushButton(_("&Close"))
        close_but.clicked.connect(self.reject)
        controls_layout.addWidget(close_but)

        # Create the video surface and receive events when new frames arrive
        self.video_surface = QrReaderVideoSurface(self)
        self.video_surface.frame_available.connect(self._on_frame_available)

        # Create the crop blur effect
        self.crop_blur_effect = QrReaderCropBlurEffect(self)
        self.image_effect = ImageGraphicsEffect(self, self.crop_blur_effect)


        # Note these should stay as queued connections becasue we use the idiom
        # self.reject() and self.accept() in this class to kill the scan --
        # and we do it from within callback functions. If you don't use
        # queued connections here, bad things can happen.
        self.finished.connect(self._boilerplate_cleanup, Qt.QueuedConnection)
        self.finished.connect(self._on_finished, Qt.QueuedConnection)

    def _on_flip_x_changed(self, _state: int):
        self.config.set_key('qrreader_flip_x', self.flip_x.isChecked())

    def _get_resolution(self, resolutions: List[QSize], min_size: int) -> QSize:
        """
        Given a list of resolutions that the camera supports this function picks the
        lowest resolution that is at least min_size in both width and height.
        If no resolution is found, NoCameraResolutionsFound is raised.
        """
        def res_list_to_str(res_list: List[QSize]) -> str:
            return ', '.join(['{}x{}'.format(r.width(), r.height()) for r in res_list])

        def check_res(res: QSize):
            return res.width() >= min_size and res.height() >= min_size

        self.logger.info('searching for at least {0}x{0}'.format(min_size))

        # Query and display all resolutions the camera supports
        format_str = 'camera resolutions: {}'
        self.logger.info(format_str.format(res_list_to_str(resolutions)))

        # Filter to those that are at least min_size in both width and height
        candidate_resolutions = []
        ideal_resolutions = [r for r in resolutions if check_res(r)]
        less_than_ideal_resolutions = [r for r in resolutions if r not in ideal_resolutions]
        format_str = 'ideal resolutions: {}, less-than-ideal resolutions: {}'
        self.logger.info(format_str.format(res_list_to_str(ideal_resolutions), res_list_to_str(less_than_ideal_resolutions)))

        # Raise an error if we have no usable resolutions
        if not ideal_resolutions and not less_than_ideal_resolutions:
            raise NoCameraResolutionsFound(_("Cannot start QR scanner, no usable camera resolution found.") + self._linux_pyqt5bug_msg())

        if not ideal_resolutions:
            self.logger.warning('No ideal resolutions found, falling back to less-than-ideal resolutions -- QR recognition may fail!')
            candidate_resolutions = less_than_ideal_resolutions
            is_ideal = False
        else:
            candidate_resolutions = ideal_resolutions
            is_ideal = True


        # Sort the usable resolutions, least number of pixels first, get the first element
        resolution = sorted(candidate_resolutions, key=lambda r: r.width() * r.height(), reverse=not is_ideal)[0]
        format_str = 'chosen resolution is {}x{}'
        self.logger.info(format_str.format(resolution.width(), resolution.height()))

        return resolution, is_ideal

    @staticmethod
    def _get_crop(resolution: QSize, scan_size: int) -> QRect:
        """
        Returns a QRect that is scan_size x scan_size in the middle of the resolution
        """
        scan_pos_x = (resolution.width() - scan_size) // 2
        scan_pos_y = (resolution.height() - scan_size) // 2
        return QRect(scan_pos_x, scan_pos_y, scan_size, scan_size)

    @staticmethod
    def _linux_pyqt5bug_msg():
        ''' Returns a string that may be appended to an exception error message
        only if on Linux and PyQt5 < 5.12.2, otherwise returns an empty string. '''
        if (sys.platform == 'linux' and PYQT_VERSION < 0x050c02 # Check if PyQt5 < 5.12.2 on linux
                # Also: this warning is not relevant to APPIMAGE; so make sure
                # we are not running from APPIMAGE.
                and not os.environ.get('APPIMAGE')):
            # In this case it's possible we couldn't detect a camera because
            # of that missing libQt5MultimediaGstTools.so problem.
            return ("\n\n" + _('If you indeed do have a usable camera connected, then this error may be caused by bugs in previous PyQt5 versions on Linux. Try installing the latest PyQt5:')
                    + "\n\n" + "python3 -m pip install --user -I pyqt5")
        return ''

    def start_scan(self, device: str = ''):
        """
        Scans a QR code from the given camera device.
        If no QR code is found the returned string will be empty.
        If the camera is not found or can't be opened NoCamerasFound will be raised.
        """

        self.validator = QrReaderValidatorCounted()
        self.validator.strong_count = 5  # FIXME: make this time based rather than framect based

        device_info = None

        for camera in QCameraInfo.availableCameras():
            if camera.deviceName() == device:
                device_info = camera
                break

        if not device_info:
            self.logger.info('Failed to open selected camera, trying to use default camera')
            device_info = QCameraInfo.defaultCamera()

        if not device_info or device_info.isNull():
            raise NoCamerasFound(_("Cannot start QR scanner, no usable camera found.") + self._linux_pyqt5bug_msg())

        self._init_stats()
        self.qrreader_res = []
        self.validator_res = None
        self._ok_done = False
        self._error_message = None

        if self.camera:
            self.logger.info("Warning: start_scan already called for this instance.")

        self.camera = QCamera(device_info)
        self.camera.setViewfinder(self.video_surface)
        self.camera.setCaptureMode(QCamera.CaptureViewfinder)

        # this operates on camera from within the signal handler, so should be a queued connection
        self.camera_sc_conn = self.camera.statusChanged.connect(self._on_camera_status_changed, Qt.QueuedConnection)
        self.camera.error.connect(self._on_camera_error)  # log the errors we get, if any, for debugging
        # Camera needs to be loaded to query resolutions, this tries to open the camera
        self.camera.load()

    _camera_status_names = {
        QCamera.UnavailableStatus: _('unavailable'),
        QCamera.UnloadedStatus: _('unloaded'),
        QCamera.UnloadingStatus: _('unloading'),
        QCamera.LoadingStatus: _('loading'),
        QCamera.LoadedStatus: _('loaded'),
        QCamera.StandbyStatus: _('standby'),
        QCamera.StartingStatus: _('starting'),
        QCamera.StoppingStatus: _('stopping'),
        QCamera.ActiveStatus: _('active')
    }

    def _get_camera_status_name(self, status: QCamera.Status):
        return self._camera_status_names.get(status, _('unknown'))

    def _set_resolution(self, resolution: QSize):
        self.resolution = resolution
        self.qr_crop = self._get_crop(resolution, self.SCAN_SIZE)

        # Initialize the video widget
        #self.video_widget.setMinimumSize(resolution)  # <-- on macOS this makes it fixed size for some reason.
        self.resize(720, 540)
        self.video_overlay.set_crop(self.qr_crop)
        self.video_overlay.set_resolution(resolution)
        self.video_layout.set_aspect_ratio(resolution.width() / resolution.height())

        # Set up the crop blur effect
        self.crop_blur_effect.setCrop(self.qr_crop)

    def _on_camera_status_changed(self, status: QCamera.Status):
        if self._ok_done:
            # camera/scan is quitting, abort.
            return

        self.logger.info('camera status changed to {}'.format(self._get_camera_status_name(status)))

        if status == QCamera.LoadedStatus:
            # Determine the optimal resolution and compute the crop rect
            camera_resolutions = self.camera.supportedViewfinderResolutions()
            try:
                resolution, was_ideal = self._get_resolution(camera_resolutions, self.SCAN_SIZE)
            except RuntimeError as e:
                self._error_message = str(e)
                self.reject()
                return
            self._set_resolution(resolution)

            # Set the camera resolution
            viewfinder_settings = QCameraViewfinderSettings()
            viewfinder_settings.setResolution(resolution)
            self.camera.setViewfinderSettings(viewfinder_settings)

            # Counter for the QR scanner frame number
            self.frame_id = 0

            self.camera.start()
            self.lowres_label.setVisible(not was_ideal)  # if they have a low res camera, show the warning label.
        elif status == QCamera.UnloadedStatus or status == QCamera.UnavailableStatus:
            self._error_message = _("Cannot start QR scanner, camera is unavailable.")
            self.reject()
        elif status == QCamera.ActiveStatus:
            self.open()

    CameraErrorStrings = {
        QCamera.NoError : "No Error",
        QCamera.CameraError : "Camera Error",
        QCamera.InvalidRequestError : "Invalid Request Error",
        QCamera.ServiceMissingError : "Service Missing Error",
        QCamera.NotSupportedFeatureError : "Unsupported Feature Error"
    }
    def _on_camera_error(self, errorCode):
        errStr = self.CameraErrorStrings.get(errorCode, "Unknown Error")
        self.logger.info(f"QCamera error: {errStr}")

    def accept(self):
        self._ok_done = True  # immediately blocks further processing
        super().accept()

    def reject(self):
        self._ok_done = True  # immediately blocks further processing
        super().reject()

    def _boilerplate_cleanup(self):
        self._close_camera()
        if self.isVisible():
            self.close()

    def _close_camera(self):
        if self.camera:
            self.camera.setViewfinder(None)
            if self.camera_sc_conn:
                self.camera.statusChanged.disconnect(self.camera_sc_conn)
                self.camera_sc_conn = None
            self.camera.unload()
            self.camera = None

    def _on_finished(self, code):
        res = ( (code == QDialog.Accepted
                    and self.validator_res and self.validator_res.accepted
                    and self.validator_res.simple_result)
                or '' )

        self.validator = None

        self.logger.info(f'closed {res}')

        self.qr_finished.emit(code == QDialog.Accepted, self._error_message, res)

    def _on_frame_available(self, frame: QImage):
        if self._ok_done:
            return

        self.frame_id += 1

        if frame.size() != self.resolution:
            self.logger.info('Getting video data at {}x{} instead of the requested {}x{}, switching resolution.'.format(
                frame.size().width(), frame.size().height(),
                self.resolution.width(), self.resolution.height()
                ))
            self._set_resolution(frame.size())

        flip_x = self.flip_x.isChecked()

        # Only QR scan every QR_SCAN_PERIOD secs
        qr_scanned = time.time() - self.last_qr_scan_ts >= self.qrreader.interval()
        if qr_scanned:
            self.last_qr_scan_ts = time.time()
            # Crop the frame so we only scan a SCAN_SIZE rect
            frame_cropped = frame.copy(self.qr_crop)

            # Convert to Y800 / GREY FourCC (single 8-bit channel)
            # This creates a copy, so we don't need to keep the frame around anymore
            frame_y800 = frame_cropped.convertToFormat(QImage.Format_Grayscale8)

            # Read the QR codes from the frame
            self.qrreader_res = self.qrreader.read_qr_code(
                frame_y800.constBits().__int__(), frame_y800.byteCount(),
                frame_y800.bytesPerLine(),
                frame_y800.width(),
                frame_y800.height(), self.frame_id
                )

            # Call the validator to see if the scanned results are acceptable
            self.validator_res = self.validator.validate_results(self.qrreader_res)

            # Update the video overlay with the results
            self.video_overlay.set_results(self.qrreader_res, flip_x, self.validator_res)

            # Close the dialog if the validator accepted the result
            if self.validator_res.accepted:
                self.accept()
                return

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
        if last_stats_delta > 1.0:  # stats every 1.0 seconds
            fps = self.frame_counter / last_stats_delta
            qr_fps = self.qr_frame_counter / last_stats_delta
            if self.validator is not None:
                self.validator.strong_count = math.ceil(qr_fps / 3)  # 1/3 of a second's worth of qr frames determines strong_count
            stats_format = 'running at {} FPS, scanner at {} FPS'
            self.logger.info(stats_format.format(fps, qr_fps))
            self.frame_counter = 0
            self.qr_frame_counter = 0
            self.last_stats_time = now
