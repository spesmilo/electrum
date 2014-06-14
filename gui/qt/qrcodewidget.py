from PyQt4.QtGui import *
from PyQt4.QtCore import *
import PyQt4.QtCore as QtCore
import PyQt4.QtGui as QtGui

from electrum import bmp, pyqrnative


class QRCodeWidget(QWidget):

    def __init__(self, data = None):
        QWidget.__init__(self)
        self.addr = None
        self.qr = None
        if data:
            self.set_addr(data)
            self.update_qr()

    def set_addr(self, addr):
        if self.addr != addr:
            if len(addr) < 128:
                MinSize = 210
            else:
                MinSize = 500
            self.setMinimumSize(MinSize, MinSize)
            self.addr = addr
            self.qr = None
            self.update()

    def update_qr(self):
        if self.addr and not self.qr:
            for size in range(len(pyqrnative.QRUtil.PATTERN_POSITION_TABLE)): # [4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32]:
                try:
                    self.qr = pyqrnative.QRCode(size, pyqrnative.QRErrorCorrectLevel.L)
                    self.qr.addData(self.addr)
                    self.qr.make()
                    break
                except Exception:
                    self.qr=None
                    continue
            self.update()

    def paintEvent(self, e):

        if not self.addr:
            return

        black = QColor(0, 0, 0, 255)
        white = QColor(255, 255, 255, 255)

        if not self.qr:
            qp = QtGui.QPainter()
            qp.begin(self)
            qp.setBrush(white)
            qp.setPen(white)
            qp.drawRect(0, 0, 198, 198)
            qp.end()
            return
 
        k = self.qr.getModuleCount()
        qp = QtGui.QPainter()
        qp.begin(self)
        r = qp.viewport()
        boxsize = min(r.width(), r.height())*0.8/k
        size = k*boxsize
        left = (r.width() - size)/2
        top = (r.height() - size)/2         

        # Make a white margin around the QR in case of dark theme use:
        margin = 10
        qp.setBrush(white)
        qp.drawRect(left-margin, top-margin, size+(margin*2), size+(margin*2))

        for r in range(k):
            for c in range(k):
                if self.qr.isDark(r, c):
                    qp.setBrush(black)
                    qp.setPen(black)
                else:
                    qp.setBrush(white)
                    qp.setPen(white)
                qp.drawRect(left+c*boxsize, top+r*boxsize, boxsize, boxsize)
        qp.end()
        

import os
from electrum.i18n import _

class QRDialog(QDialog):

    def __init__(self, data, parent=None, title = "", show_text=False):
        QDialog.__init__(self, parent)

        d = self
        d.setModal(1)
        d.setWindowTitle(title)
        d.setMinimumSize(270, 300)
        vbox = QVBoxLayout()
        qrw = QRCodeWidget(data)
        vbox.addWidget(qrw, 1)
        if show_text:
            text = QTextEdit()
            text.setText(data)
            text.setReadOnly(True)
            vbox.addWidget(text)
        hbox = QHBoxLayout()
        hbox.addStretch(1)

        if parent:
            self.config = parent.config
            filename = os.path.join(self.config.path, "qrcode.bmp")

            def print_qr():
                bmp.save_qrcode(qrw.qr, filename)
                QMessageBox.information(None, _('Message'), _("QR code saved to file") + " " + filename, _('OK'))

            def copy_to_clipboard():
                bmp.save_qrcode(qrw.qr, filename)
                self.parent().app.clipboard().setImage(QImage(filename))
                QMessageBox.information(None, _('Message'), _("QR code saved to clipboard"), _('OK'))

                b = QPushButton(_("Copy"))
                hbox.addWidget(b)
                b.clicked.connect(copy_to_clipboard)

                b = QPushButton(_("Save"))
                hbox.addWidget(b)
                b.clicked.connect(print_qr)

        b = QPushButton(_("Close"))
        hbox.addWidget(b)
        b.clicked.connect(d.accept)
        b.setDefault(True)

        vbox.addLayout(hbox)
        d.setLayout(vbox)

