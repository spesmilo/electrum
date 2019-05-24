
from electroncash.i18n import _
from electroncash.plugins import run_hook
from electroncash import util
from PyQt5.QtGui import *
from PyQt5.QtCore import *
from PyQt5.QtWidgets import QFileDialog

from .util import ButtonsTextEdit, MessageBoxMixin, ColorScheme


class ShowQRTextEdit(ButtonsTextEdit):

    def __init__(self, text=None):
        ButtonsTextEdit.__init__(self, text)
        self.setReadOnly(1)
        icon = ":icons/qrcode_white.png" if ColorScheme.dark_scheme else ":icons/qrcode.png"
        self.addButton(icon, self.qr_show, _("Show as QR code"))

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
        m.addAction(_("Show as QR code"), self.qr_show)
        m.exec_(e.globalPos())


class ScanQRTextEdit(ButtonsTextEdit, MessageBoxMixin):

    def __init__(self, text="", allow_multi=False):
        ButtonsTextEdit.__init__(self, text)
        self.allow_multi = allow_multi
        self.setReadOnly(0)
        self.addButton(":icons/file.png", self.file_input, _("Read file"))
        icon = ":icons/qrcode_white.png" if ColorScheme.dark_scheme else ":icons/qrcode.png"
        self.addButton(icon, self.qr_input, _("Read QR code"))
        run_hook('scan_text_edit', self)

    def file_input(self):
        fileName, __ = QFileDialog.getOpenFileName(self, 'select file')
        if not fileName:
            return
        try:
            with open(fileName, "r", encoding='utf-8') as f:
                data = f.read()
        except UnicodeDecodeError as reason:
            self.show_critical(_("The selected file appears to be a binary file.") +"\n"+ _("Please ensure you only import text files."), title=_("Not a text file"))
            return
        self.setText(data)

    def qr_input(self, callback = None):
        from electroncash import get_config
        from .qrreader import QrReaderCameraDialog
        dialog = None
        try:
            dialog = QrReaderCameraDialog(parent=self.top_level_window())

            def _on_qr_reader_finished(success: bool, error: str, result):
                nonlocal dialog
                if dialog:
                    dialog.deleteLater(); dialog = None
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

            dialog.qr_finished.connect(_on_qr_reader_finished)
            dialog.start_scan(get_config().get_video_device())
        except BaseException as e:
            if util.is_verbose:
                import traceback
                traceback.print_exc()
            self.show_error(str(e))

    def contextMenuEvent(self, e):
        m = self.createStandardContextMenu()
        m.addAction(_("Read QR code"), self.qr_input)
        m.exec_(e.globalPos())
