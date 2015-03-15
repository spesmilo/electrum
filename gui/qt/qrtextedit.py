from electrum_ltc.i18n import _
from electrum_ltc.plugins import run_hook
from PyQt4.QtGui import *
from PyQt4.QtCore import *

class QRTextEdit(QPlainTextEdit):
    """Abstract class for QR-code related TextEdits. Do not use directly."""
    def __init__(self, text=None):
        super(QRTextEdit, self).__init__(text)
        self.setText = self.setPlainText
        self.buttons = []

    def resizeEvent(self, e):
        o = QPlainTextEdit.resizeEvent(self, e)
        frameWidth = self.style().pixelMetric(QStyle.PM_DefaultFrameWidth)
        x = self.rect().right() - frameWidth
        y = self.rect().bottom() - frameWidth
        for button in self.buttons:
            sz = button.sizeHint()
            x -= sz.width()
            button.move(x, y - sz.height())
        return o

    def add_button(self, icon_name, on_click, tooltip):
        button = QToolButton(self)
        button.setIcon(QIcon(icon_name))
        button.setStyleSheet("QToolButton { border: none; padding: 0px; }")
        button.setVisible(True)
        button.setToolTip(tooltip)
        button.clicked.connect(on_click)
        self.buttons.append(button)
        return button




class ShowQRTextEdit(QRTextEdit):
    def __init__(self, text=None):
        super(ShowQRTextEdit, self).__init__(text)
        self.setReadOnly(1)
        self.add_button(":icons/qrcode.png", self.qr_show, _("Show as QR code"))
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
        self.add_button(":icons/qrcode.png", self.qr_input, _("Read QR code"))
        run_hook('scan_text_edit', self)

    def qr_input(self):
        from electrum_ltc import qrscanner
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
