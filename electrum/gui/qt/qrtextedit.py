from PyQt5.QtWidgets import QFileDialog

from electrum.i18n import _
from electrum.plugin import run_hook

from .util import ButtonsTextEdit, MessageBoxMixin, ColorScheme, get_parent_main_window


class ShowQRTextEdit(ButtonsTextEdit):

    def __init__(self, text=None):
        ButtonsTextEdit.__init__(self, text)
        self.setReadOnly(1)
        icon = "qrcode_white.png" if ColorScheme.dark_scheme else "qrcode.png"
        self.addButton(icon, self.qr_show, _("Show as QR code"))

        run_hook('show_text_edit', self)

    def qr_show(self):
        from .qrcodewidget import QRDialog
        try:
            s = str(self.toPlainText())
        except:
            s = self.toPlainText()
        QRDialog(s, parent=self).exec_()

    def contextMenuEvent(self, e):
        m = self.createStandardContextMenu()
        m.addAction(_("Show as QR code"), self.qr_show)
        m.exec_(e.globalPos())


class ScanQRTextEdit(ButtonsTextEdit, MessageBoxMixin):

    def __init__(self, text="", allow_multi=False):
        ButtonsTextEdit.__init__(self, text)
        self.allow_multi = allow_multi
        self.setReadOnly(0)
        self.addButton("file.png", self.file_input, _("Read file"))
        icon = "camera_white.png" if ColorScheme.dark_scheme else "camera_dark.png"
        self.addButton(icon, self.qr_input, _("Read QR code"))
        run_hook('scan_text_edit', self)

    def file_input(self):
        fileName, __ = QFileDialog.getOpenFileName(self, 'select file')
        if not fileName:
            return
        try:
            try:
                with open(fileName, "r") as f:
                    data = f.read()
            except UnicodeError as e:
                with open(fileName, "rb") as f:
                    data = f.read()
                data = data.hex()
        except BaseException as e:
            self.show_error(_('Error opening file') + ':\n' + repr(e))
        else:
            self.setText(data)

    def qr_input(self):
        from electrum import qrscanner
        main_window = get_parent_main_window(self)
        assert main_window
        config = main_window.config
        try:
            data = qrscanner.scan_barcode(config.get_video_device())
        except BaseException as e:
            self.show_error(repr(e))
            data = ''
        if not data:
            data = ''
        if self.allow_multi:
            new_text = self.text() + data + '\n'
        else:
            new_text = data
        self.setText(new_text)
        return data

    def contextMenuEvent(self, e):
        m = self.createStandardContextMenu()
        m.addAction(_("Read QR code"), self.qr_input)
        m.exec_(e.globalPos())
