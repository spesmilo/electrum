from PyQt5.QtWidgets import QFileDialog

from electrum.i18n import _
from electrum.plugin import run_hook

from .util import ButtonsTextEdit, MessageBoxMixin, ColorScheme


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
        self.addButton("file.png", self.file_input, _("Read file"))
        icon = "camera_white.png" if ColorScheme.dark_scheme else "camera_dark.png"
        self.addButton(icon, self.qr_input, _("Read QR code"))
        run_hook('scan_text_edit', self)

    def file_input(self):
        fileName, __ = QFileDialog.getOpenFileName(self, 'select file')
        if not fileName:
            return
        try:
            with open(fileName, "r") as f:
                data = f.read()
        except BaseException as e:
            self.show_error(_('Error opening file') + ':\n' + str(e))
        else:
            self.setText(data)

    def qr_input(self):
        from electrum import qrscanner, get_config
        try:
            data = qrscanner.scan_barcode(get_config().get_video_device())
        except BaseException as e:
            self.show_error(str(e))
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
