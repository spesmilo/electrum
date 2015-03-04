from electrum_grs.i18n import _
from electrum_grs.plugins import run_hook
from PyQt4.QtGui import *
from PyQt4.QtCore import *

class QRTextEdit(QPlainTextEdit):
    """Abstract class for QR-code related TextEdits. Do not use directly."""
    def __init__(self, text=None):
        super(QRTextEdit, self).__init__(text)
        self.button = QToolButton(self)
        self.button.setIcon(QIcon(":icons/qrcode.png"))
        self.button.setStyleSheet("QToolButton { border: none; padding: 0px; }")
        self.button.setVisible(True)
        self.setText = self.setPlainText

    def resizeEvent(self, e):
        o = QPlainTextEdit.resizeEvent(self, e)
        sz = self.button.sizeHint()
        frameWidth = self.style().pixelMetric(QStyle.PM_DefaultFrameWidth)
        self.button.move(self.rect().right() - frameWidth - sz.width(),
                         (self.rect().bottom() - frameWidth - sz.height()))
        return o

class ShowQRTextEdit(QRTextEdit):
    def __init__(self, text=None):
        super(ShowQRTextEdit, self).__init__(text)
        self.setReadOnly(1)
        self.button.clicked.connect(self.qr_show)
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


class ScanQRTextEdit(QRTextEdit):
    def __init__(self, win, text=""):
        super(ScanQRTextEdit,self).__init__(text)
        self.setReadOnly(0)
        self.win = win
        assert win, "You must pass a window with access to the config to ScanQRTextEdit constructor."
        if win:
            assert hasattr(win,"config"), "You must pass a window with access to the config to ScanQRTextEdit constructor."
        self.button.clicked.connect(self.qr_input)
        run_hook('scan_text_edit', self)


    def qr_input(self):
        from electrum_grs import qrscanner
        try:
            data = qrscanner.scan_qr(self.win.config)
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
