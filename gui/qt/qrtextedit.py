from electrum.i18n import _
from electrum.plugins import run_hook
from PyQt4.QtGui import *
from PyQt4.QtCore import *

from util import ButtonsTextEdit, MessageBoxMixin


class ShowQRTextEdit(ButtonsTextEdit):

    def __init__(self, text=None):
        ButtonsTextEdit.__init__(self, text)
        self.setReadOnly(1)
        self.addButton(":icons/qrcode.png", self.qr_show, _("Show as QR code"))

        run_hook('show_text_edit', self)

    def qr_show(self):
        from qrcodewidget import QRDialog
        try:
            s = str(self.toPlainText())
        except:
            s = unicode(self.toPlainText())
        QRDialog(s).exec_()

    def contextMenuEvent(self, e):
        m = self.createStandardContextMenu()
        m.addAction(_("Show as QR code"), self.qr_show)
        m.exec_(e.globalPos())


class ScanQRTextEdit(ButtonsTextEdit, MessageBoxMixin):

    def __init__(self, text=""):
        ButtonsTextEdit.__init__(self, text)
        self.setReadOnly(0)
        self.addButton(":icons/file.png", self.file_input, _("Read file"))
        self.addButton(":icons/qrcode.png", self.qr_input, _("Read QR code"))
        run_hook('scan_text_edit', self)

    def file_input(self):
        fileName = unicode(QFileDialog.getOpenFileName(self, 'select file'))
        if not fileName:
            return
        with open(fileName, "r") as f:
            data = f.read()
        self.setText(data)

    def qr_input(self):
        from electrum import qrscanner, get_config
        try:
            data = qrscanner.scan_qr(get_config())
        except BaseException as e:
            self.show_error(str(e))
            return ""
        if type(data) != str:
            return
        self.setText(data)
        return data

    def contextMenuEvent(self, e):
        m = self.createStandardContextMenu()
        m.addAction(_("Read QR code"), self.qr_input)
        m.exec_(e.globalPos())
