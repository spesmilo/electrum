from electrum.i18n import _
from PyQt4.QtGui import *
from PyQt4.QtCore import *

class QRTextEdit(QPlainTextEdit):

    def __init__(self, text=None):
        QPlainTextEdit.__init__(self, text)
        self.button = QToolButton(self)
        self.button.setIcon(QIcon(":icons/qrcode.png"))
        self.button.setStyleSheet("QToolButton { border: none; padding: 0px; }")
        self.button.setVisible(True)
        self.button.clicked.connect(lambda: self.qr_show() if self.isReadOnly() else self.qr_input())
        self.setText = self.setPlainText

    def resizeEvent(self, e):
        o = QPlainTextEdit.resizeEvent(self, e)
        sz = self.button.sizeHint()
        frameWidth = self.style().pixelMetric(QStyle.PM_DefaultFrameWidth)
        self.button.move(self.rect().right() - frameWidth - sz.width(),
                         (self.rect().bottom() - frameWidth - sz.height()))
        return o

    def contextMenuEvent(self, e):
        m = self.createStandardContextMenu()
        if self.isReadOnly():
            m.addAction(_("Show as QR code"), self.qr_show)
        else:
            m.addAction(_("Read QR code"), self.qr_input)
        m.exec_(e.globalPos())

    def qr_show(self):
        from qrcodewidget import QRDialog
        try:
            s = str(self.toPlainText())
        except:
            s = unicode(self.toPlainText())
        QRDialog(s).exec_()

    def qr_input(self):
        from electrum import qrscanner
        try:
            data = qrscanner.scan_qr(self.win.config)
        except BaseException, e:
            QMessageBox.warning(self.win, _('Error'), _(e), _('OK'))
            return
        if type(data) != str:
            return
        self.setText(data)
