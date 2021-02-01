from PyQt5.QtWidgets import QFileDialog

from electrum.i18n import _
from electrum.plugin import run_hook
from electrum.simple_config import SimpleConfig

from .util import ButtonsTextEdit, MessageBoxMixin, ColorScheme, getOpenFileName


class ShowQRTextEdit(ButtonsTextEdit):

    def __init__(self, text=None, *, config: SimpleConfig):
        ButtonsTextEdit.__init__(self, text)
        self.config = config
        self.setReadOnly(True)
#todo uncomment when QR Read gonna be fixed
#        icon = "qrcode_white.png" if ColorScheme.dark_scheme else "qrcode.png"
#        self.addButton(icon, self.qr_show, _("Show as QR code"))
#
#        run_hook('show_text_edit', self)

    def qr_show(self):
        from .qrcodewidget import QRDialog
        try:
            s = str(self.toPlainText())
        except:
            s = self.toPlainText()
        QRDialog(
            data=s,
            parent=self,
            config=self.config,
        ).exec_()

    def contextMenuEvent(self, e):
        m = self.createStandardContextMenu()
        m.addAction(_("Show as QR code"), self.qr_show)
        m.exec_(e.globalPos())


class ScanQRTextEdit(ButtonsTextEdit, MessageBoxMixin):

    def __init__(self, text="", allow_multi=False, *, config: SimpleConfig):
        ButtonsTextEdit.__init__(self, text)
        self.allow_multi = allow_multi
        self.config = config
        self.setReadOnly(False)
        #todo uncomment when ReadFile handle only text extension and QR Read gonna be fixed
#        self.addButton("file.png", self.file_input, _("Read file"))
#        icon = "camera_white.png" if ColorScheme.dark_scheme else "camera_dark.png"
#        self.addButton(icon, self.qr_input, _("Read QR code"))
#        run_hook('scan_text_edit', self)

    def file_input(self):
        fileName = getOpenFileName(
            parent=self,
            title='select file',
            config=self.config,
        )
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
        try:
            data = qrscanner.scan_barcode(self.config.get_video_device())
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
