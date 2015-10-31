from electrum.i18n import _
from electrum.plugins import run_hook
from PyQt4.QtGui import *
from PyQt4.QtCore import *

from util import ButtonsTextEdit


class ShowQRTextEdit(ButtonsTextEdit):

    def __init__(self, text=None, paranoid=False):
        ButtonsTextEdit.__init__(self, text)
        self.setReadOnly(1)
        self.addButton(":icons/qrcode.png", self.qr_show, _("Show as QR code"))
        self.paranoid = paranoid

        if paranoid:
            # Paranoid flag forces the user to write down what's in the box, 
            # like Mycelium does. This is useful since many users just copy
            # and paste their code, then when disaster strikes they don't have
            # it written down anywhere.
            self.setAcceptDrops(False) # No dragging and dropping
            # Use custom context menu to remove copy/paste from menu
            self.setContextMenuPolicy(Qt.ActionsContextMenu)
            self.qaction = QAction(_("Show as QR code"), self)
            self.qaction.triggered.connect(self.qr_show)
            self.addAction(self.qaction)
            # No text selection allowed.
            self.setTextInteractionFlags(Qt.NoTextInteraction)

        run_hook('show_text_edit', self)

    def qr_show(self):
        from qrcodewidget import QRDialog
        try:
            s = str(self.toPlainText())
        except:
            s = unicode(self.toPlainText())
        QRDialog(s).exec_()

    def contextMenuEvent(self, e):
        if self.paranoid: return
        m = self.createStandardContextMenu()
        m.addAction(_("Show as QR code"), self.qr_show)
        m.exec_(e.globalPos())


class ScanQRTextEdit(ButtonsTextEdit):

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
        except BaseException, e:
            QMessageBox.warning(self, _('Error'), _(e), _('OK'))
            return ""
        if type(data) != str:
            return
        self.setText(data)
        return data

    def contextMenuEvent(self, e):
        m = self.createStandardContextMenu()
        m.addAction(_("Read QR code"), self.qr_input)
        m.exec_(e.globalPos())
