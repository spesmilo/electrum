import sys

from electroncash.i18n import _
from electroncash.plugins import run_hook
from electroncash import util
from PyQt5.QtGui import *
from PyQt5.QtCore import *
from PyQt5.QtWidgets import QFileDialog, QAbstractButton, QWidget, QApplication, QMenu

from .util import ButtonsTextEdit, MessageBoxMixin, ColorScheme

class _QrCodeTextEdit(ButtonsTextEdit):
    def __init__(self, text=None):
        ButtonsTextEdit.__init__(self, text)
        self.qr_button = None

    def get_qr_icon(self):
        return ":icons/qrcode_white.svg" if ColorScheme.dark_scheme else ":icons/qrcode.svg"

    def showEvent(self, e):
        super().showEvent(e)
        if sys.platform in ('darwin',) and isinstance(self.qr_button, QAbstractButton):
            # on Darwin it's entirely possible that the color scheme changes
            # from underneath our feet, so force a re-set of the icon on show.
            self.qr_button.setIcon(QIcon(self.get_qr_icon()))


class ShowQRTextEdit(_QrCodeTextEdit):

    def __init__(self, text=None):
        _QrCodeTextEdit.__init__(self, text)
        self.setReadOnly(1)
        self.qr_button = self.addButton(self.get_qr_icon(), self.qr_show, _("Show as QR code"))

        run_hook('show_text_edit', self)

    def qr_show(self):
        from .qrcodewidget import QRDialog
        try:
            s = str(self.toPlainText())
        except:
            s = self.toPlainText()
        QRDialog(s).exec_()

    def contextMenuEvent(self, e):
        m = self.createStandardContextMenu()
        m.addSeparator()
        m.addAction(_("Show as QR code"), self.qr_show)
        m.exec_(e.globalPos())


class ScanQRTextEdit(_QrCodeTextEdit, MessageBoxMixin):

    def __init__(self, text="", allow_multi=False):
        _QrCodeTextEdit.__init__(self, text)
        self.allow_multi = allow_multi
        self.setReadOnly(0)
        self.qr_button = self.addButton(self.get_qr_icon(), self.qr_input, _("Read QR code"))
        qr_menu = QMenu()
        qr_menu.addAction(_("Read QR code from camera"), self.qr_input)
        qr_menu.addAction(_("Read QR from screen"), self.screenshot_input)
        self.qr_button.setMenu(qr_menu)
        self.addButton(":icons/file.png", self.file_input, _("Read text or image file"))
        run_hook('scan_text_edit', self)

    def file_input(self):
        fileName, __ = QFileDialog.getOpenFileName(self, _('Load a text file or scan an image for QR codes'))
        if not fileName:
            return

        image = QImage()
        if image.load(fileName):
            scanned_qrs = self.scan_qr_from_image(image)
            if not len(scanned_qrs):
                self.show_error(_("No QR code was found in the selected image file."), title=_("No QR code found"))
                return
            if len(scanned_qrs) > 1:
                self.show_error(_("More than one QR code was found in the selected image file."), title=_("More than one QR code found"))
                return

            self.setText(scanned_qrs[0].data)
            return

        try:
            with open(fileName, "r", encoding='utf-8') as f:
                data = f.read()
        except UnicodeDecodeError as reason:
            self.show_error(_("The selected file appears to be a binary file.") +"\n"+ _("Please ensure you only import text files."), title=_("Not a text file"))
            return
        self.setText(data)

    def screenshot_input(self):
        scanned_qr = None
        for screen in QApplication.instance().screens():
            scan_result = self.scan_qr_from_image(screen.grabWindow(0).toImage())
            if len(scan_result) > 0:
                if (scanned_qr is not None) or len(scan_result) > 1:
                    self.show_error(_("More than one QR code was found on the screen."), title=_("More than one QR code found"))
                    return
                scanned_qr = scan_result

        if scanned_qr is None:
            self.show_error(_("No QR code was found on the screen."), title=_("No QR code found"))
            return
        self.setText(scanned_qr[0].data)

    def scan_qr_from_image(self, image):
        from electroncash.qrreaders import get_qr_reader
        qr_reader = get_qr_reader()
        if not qr_reader:
            self.show_error(_("Unable to scan image.") + "\n" +
                            _("The platform QR detection library is not available."))
            return

        image_y800 = image.convertToFormat(QImage.Format_Grayscale8)
        res = qr_reader.read_qr_code(
            image_y800.constBits().__int__(), image_y800.byteCount(),
            image_y800.bytesPerLine(),
            image_y800.width(),
            image_y800.height()
        )

        return res

    # Due to the asynchronous nature of the qr reader we need to keep the
    # dialog instance as member variable to prevent reentrancy/multiple ones
    # from being presented at once.
    qr_dialog = None

    def qr_input(self, callback = None):
        if self.qr_dialog:
            # Re-entrancy prevention -- there is some lag between when the user
            # taps the QR button and the modal dialog appears.  We want to
            # prevent multiple instances of the dialog from appearing, so we
            # must do this.
            util.print_error("[ScanQRTextEdit] Warning: QR dialog is already presented, ignoring.")
            return
        from . import ElectrumGui
        if ElectrumGui.instance.warn_if_cant_import_qrreader(self):
            return
        from electroncash import get_config
        from .qrreader import QrReaderCameraDialog
        try:
            self.qr_dialog = QrReaderCameraDialog(parent=self.top_level_window())

            def _on_qr_reader_finished(success: bool, error: str, result):
                if self.qr_dialog:
                    self.qr_dialog.deleteLater(); self.qr_dialog = None
                if not success:
                    if error:
                        self.show_error(error)
                    return
                if not result:
                    result = ''
                if self.allow_multi:
                    new_text = self.text() + result + '\n'
                else:
                    new_text = result
                self.setText(new_text)
                if callback and success:
                    callback(result)

            self.qr_dialog.qr_finished.connect(_on_qr_reader_finished)
            self.qr_dialog.start_scan(get_config().get_video_device())
        except Exception as e:
            if util.is_verbose:
                import traceback
                traceback.print_exc()
            self.qr_dialog = None
            self.show_error(str(e))

    def contextMenuEvent(self, e):
        m = self.createStandardContextMenu()
        m.addSeparator()
        m.addAction(_("Read QR code from camera"), self.qr_input)
        m.addAction(_("Read QR from screen"), self.screenshot_input)
        m.addAction(_("Read text or image file"), self.file_input)
        m.exec_(e.globalPos())
