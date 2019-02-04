
from PyQt5.QtCore import *
from PyQt5.QtGui import *
import PyQt5.QtGui as QtGui
from PyQt5.QtWidgets import (
    QApplication, QVBoxLayout, QTextEdit, QHBoxLayout, QPushButton, QWidget)

import os
import qrcode

from electroncash import get_config, util
from electroncash.i18n import _
from .util import WindowModalDialog


class QRCodeWidget(QWidget, util.PrintError):

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
            try:
                self.qr = qrcode.QRCode()
                self.qr.add_data(self.data)
                if not self.fixedSize:
                    k = len(self.qr.get_matrix())
                    self.setMinimumSize(k*5,k*5)
            except qrcode.exceptions.DataOverflowError:
                self._bad_data(data)  # sets self.qr = None
        else:
            self.qr = None

        self.update()


    def _paint_blank(self):
        qp = QtGui.QPainter(self)
        r = qp.viewport()
        qp.fillRect(0, 0, r.width(), r.height(), self._white)
        qp.end(); del qp

    def _bad_data(self, data):
        self.print_error("Failed to generate QR image -- data too long! Data length was: {} bytes".format(len(data or '')))
        self.qr = None

    _black = QColor(0, 0, 0, 255)
    _white = QColor(255, 255, 255, 255)

    def paintEvent(self, e):
        matrix = None

        if self.data and self.qr:
            try:
                matrix = self.qr.get_matrix()
            except qrcode.exceptions.DataOverflowError:
                self._bad_data(self.data)  # sets self.qr = None

        if not matrix:
            self._paint_blank()
            return

        k = len(matrix)
        qp = QtGui.QPainter(self)
        r = qp.viewport()

        margin = 10
        framesize = min(r.width(), r.height())
        boxsize = int( (framesize - 2*margin)/k )
        size = k*boxsize
        left = (r.width() - size)/2
        top = (r.height() - size)/2

        # Make a white margin around the QR in case of dark theme use
        qp.setBrush(self._white)
        qp.setPen(self._white)
        qp.drawRect(left-margin, top-margin, size+(margin*2), size+(margin*2))
        qp.setBrush(self._black)
        qp.setPen(self._black)

        for r in range(k):
            for c in range(k):
                if matrix[r][c]:
                    qp.drawRect(left+c*boxsize, top+r*boxsize, boxsize - 1, boxsize - 1)
        qp.end(); del qp



class QRDialog(WindowModalDialog):

    def __init__(self, data, parent=None, title = "", show_text=False):
        WindowModalDialog.__init__(self, parent, title)

        vbox = QVBoxLayout()
        qrw = QRCodeWidget(data)
        qscreen = QApplication.primaryScreen()
        vbox.addWidget(qrw, 1)
        if show_text:
            text = QTextEdit()
            text.setText(data)
            text.setReadOnly(True)
            vbox.addWidget(text)
        hbox = QHBoxLayout()
        hbox.addStretch(1)

        config = get_config()
        if config:
            filename = os.path.join(config.path, "qrcode.png")

            def print_qr():
                p = qscreen.grabWindow(qrw.winId())
                p.save(filename, 'png')
                self.show_message(_("QR code saved to file") + " " + filename)

            def copy_to_clipboard():
                p = qscreen.grabWindow(qrw.winId())
                QApplication.clipboard().setPixmap(p)
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
