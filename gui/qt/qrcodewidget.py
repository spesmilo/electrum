from PyQt4.QtGui import *
from PyQt4.QtCore import *
import PyQt4.QtGui as QtGui

import os
import qrcode

import electrum
from electrum.i18n import _
from util import WindowModalDialog


class QRCodeWidget(QWidget):

    def __init__(self, data = None, fixedSize=False):
        QWidget.__init__(self)
        self.data = None
        self.qr = None
        self.fixedSize=fixedSize
        if fixedSize:
            self.setFixedSize(fixedSize, fixedSize)
        self.setData(data)


    def setData(self, data):
        if self.data != data:
            self.data = data
        if self.data:
            self.qr = qrcode.QRCode()
            self.qr.add_data(self.data)
            if not self.fixedSize:
                k = len(self.qr.get_matrix())
                self.setMinimumSize(k*5,k*5)
        else:
            self.qr = None

        self.update()


    def paintEvent(self, e):
        if not self.data:
            return

        black = QColor(0, 0, 0, 255)
        white = QColor(255, 255, 255, 255)

        if not self.qr:
            qp = QtGui.QPainter()
            qp.begin(self)
            qp.setBrush(white)
            qp.setPen(white)
            r = qp.viewport()
            qp.drawRect(0, 0, r.width(), r.height())
            qp.end()
            return

        matrix = self.qr.get_matrix()
        k = len(matrix)
        qp = QtGui.QPainter()
        qp.begin(self)
        r = qp.viewport()

        margin = 10
        framesize = min(r.width(), r.height())
        boxsize = int( (framesize - 2*margin)/k )
        size = k*boxsize
        left = (r.width() - size)/2
        top = (r.height() - size)/2

        # Make a white margin around the QR in case of dark theme use
        qp.setBrush(white)
        qp.setPen(white)
        qp.drawRect(left-margin, top-margin, size+(margin*2), size+(margin*2))
        qp.setBrush(black)
        qp.setPen(black)

        for r in range(k):
            for c in range(k):
                if matrix[r][c]:
                    qp.drawRect(left+c*boxsize, top+r*boxsize, boxsize - 1, boxsize - 1)
        qp.end()



class QRDialog(WindowModalDialog):

    def __init__(self, data, parent=None, title = "", show_text=False):
        WindowModalDialog.__init__(self, parent, title)

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

        config = electrum.get_config()
        if config:
            filename = os.path.join(config.path, "qrcode.png")

            def print_qr():
                p = QPixmap.grabWindow(qrw.winId())
                p.save(filename, 'png')
                self.show_message(_("QR code saved to file") + " " + filename)

            def copy_to_clipboard():
                p = QPixmap.grabWindow(qrw.winId())
                p.save(filename, 'png')
                QApplication.clipboard().setImage(QImage(filename))
                self.show_message(_("QR code copied to clipboard"))

            b = QPushButton(_("Copy"))
            hbox.addWidget(b)
            b.clicked.connect(copy_to_clipboard)

            b = QPushButton(_("Save"))
            hbox.addWidget(b)
            b.clicked.connect(print_qr)

        b = QPushButton(_("Close"))
        hbox.addWidget(b)
        b.clicked.connect(self.accept)
        b.setDefault(True)

        vbox.addLayout(hbox)
        self.setLayout(vbox)
