from electrum.i18n import _
from PyQt4.QtGui import *
from PyQt4.QtCore import *

class QRTextEdit(QTextEdit):

    def __init__(self):
        QTextEdit.__init__(self)
        self.button = QToolButton(self)
        self.button.setIcon(QIcon(":icons/qrcode.png"))
        self.button.setStyleSheet("QToolButton { border: none; padding: 0px; }")
        self.button.setVisible(True)
        self.button.clicked.connect(lambda: self.qr_show() if self.isReadOnly() else self.qr_input())
        #frameWidth = self.style().pixelMetric(QStyle.PM_DefaultFrameWidth)
        #self.setStyleSheet(QString("QLineEdit { padding-right: %1px; } ").arg(self.button.sizeHint().width() + frameWidth + 1))
        #msz = self.minimumSizeHint()
        #self.setMinimumSize(max(msz.width(), self.button.sizeHint().height() + frameWidth * 2 + 2),
        #                    max(msz.height(), self.button.sizeHint().height() + frameWidth * 2 + 2))

    def resizeEvent(self, e):
        o = QTextEdit.resizeEvent(self, e)
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
        QRDialog(str(self.toPlainText())).exec_()

    def qr_input(self):
        from electrum.plugins import run_hook
        run_hook('scan_qr_hook', self.setText)

