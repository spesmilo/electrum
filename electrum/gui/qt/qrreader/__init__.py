# Copyright (C) 2021 The Electrum developers
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://www.opensource.org/licenses/mit-license.php
#
# Camera capture uses QtMultimedia on all desktop platforms; image decoding
# uses zxing-cpp. QtMultimedia is imported lazily as some distributions package
# it separately from PyQt6 (e.g. python3-pyqt6.qtmultimedia on Debian).
#
# Note: this module does not require QtMultimedia to import.

from typing import Callable, Optional, TYPE_CHECKING, Mapping, Sequence

from PyQt6.QtWidgets import QWidget
from PyQt6.QtGui import QImage
from PyQt6.QtCore import QCoreApplication
from PyQt6 import QtCore

from electrum.i18n import _
from electrum.logging import get_logger
from electrum.qrreader import get_qr_reader, QrCodeResult, MissingQrDetectionLib


if TYPE_CHECKING:
    from electrum.simple_config import SimpleConfig


_logger = get_logger(__name__)


def scan_qrcode_from_camera(
        *,
        parent: Optional[QWidget],
        config: 'SimpleConfig',
        callback: Callable[[bool, str, Optional[str]], None],
) -> None:
    """Scans QR code using camera. It handles requesting camera access permission from the OS if needed."""
    assert parent is None or isinstance(parent, QWidget), f"parent should be a QWidget, not {parent!r}"
    def do_scan():
        _scan_qrcode_from_camera(parent=parent, config=config, callback=callback)

    if _has_camera_permission():
        do_scan()
    else:
        # Request permission now. This is only a thing on macOS atm.
        # Note: this assumes we are running on the main thread. Permissions can only be requested from the main thread.
        app = QCoreApplication.instance()
        app.requestPermission(QtCore.QCameraPermission(), lambda _x: do_scan())


def scan_qr_from_image(image: QImage) -> Sequence[QrCodeResult]:
    """Might raise exception: MissingQrDetectionLib."""
    if image.isNull():
        return []
    qr_reader = get_qr_reader()
    image_y800 = image.convertToFormat(QImage.Format.Format_Grayscale8)
    return qr_reader.read_qr_code(
        image_y800.constBits().__int__(),
        image_y800.sizeInBytes(),
        image_y800.bytesPerLine(),
        image_y800.width(),
        image_y800.height(),
    )


def find_system_cameras() -> Mapping[str, str]:
    """Returns a camera_description -> camera_path map."""
    try:
        from .qtmultimedia import find_system_cameras
    except (ImportError, RuntimeError):
        _logger.exception('error importing .qtmultimedia')
        return {}
    return find_system_cameras()


# --- Internals below (not part of external API)

# Use a global to prevent multiple QR dialogs created simultaneously
_qr_dialog = None


def _scan_qrcode_using_qtmultimedia(
        *,
        parent: Optional[QWidget],
        config: 'SimpleConfig',
        callback: Callable[[bool, str, Optional[str]], None],
) -> None:
    try:
        from .qtmultimedia import QrReaderCameraDialog, CameraError
    except (ImportError, RuntimeError) as e:
        message = _("QR reader failed to load. Please install PyQt6 Qt Multimedia.") + "\n\n" + str(e)
        _logger.exception(message)
        callback(False, message, None)
        return

    global _qr_dialog
    if _qr_dialog:
        _logger.warning("QR dialog is already presented, ignoring.")
        return
    _qr_dialog = None
    try:
        _qr_dialog = QrReaderCameraDialog(parent=parent, config=config)

        def _on_qr_reader_finished(success: bool, error: str, data):
            global _qr_dialog
            if _qr_dialog:
                _qr_dialog.deleteLater()
                _qr_dialog = None
            callback(success, error, data)

        _qr_dialog.qr_finished.connect(_on_qr_reader_finished)
        _qr_dialog.start_scan(config.get_video_device())
    except (MissingQrDetectionLib, CameraError) as e:
        error = str(e)
    except Exception as e:
        _logger.exception('camera error')
        error = repr(e)
    else:
        return

    if _qr_dialog:
        _qr_dialog.qr_finished.disconnect(_on_qr_reader_finished)
        _qr_dialog._boilerplate_cleanup()
        _qr_dialog.deleteLater()
        _qr_dialog = None
    callback(False, error, None)


def _scan_qrcode_from_camera(
        *,
        parent: Optional[QWidget],
        config: 'SimpleConfig',
        callback: Callable[[bool, str, Optional[str]], None],
) -> None:
    """Scans QR code using camera."""
    assert parent is None or isinstance(parent, QWidget), f"parent should be a QWidget, not {parent!r}"
    if not _has_camera_permission():
        callback(False, _("Missing camera permission."), None)
        return
    _scan_qrcode_using_qtmultimedia(parent=parent, config=config, callback=callback)


def _has_camera_permission() -> bool:
    if not hasattr(QtCore, "QCameraPermission"):  # requires Qt 6.5+
        _logger.info(f"QtCore does not support QCameraPermission. This requires Qt 6.5+")
        return True  # hope for the best
    app = QCoreApplication.instance()
    permission_status = app.checkPermission(QtCore.QCameraPermission())
    return permission_status == QtCore.Qt.PermissionStatus.Granted
