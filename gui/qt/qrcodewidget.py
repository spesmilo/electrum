
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWidgets import (
    QApplication, QVBoxLayout, QTextEdit, QHBoxLayout, QPushButton, QWidget,
    QSizePolicy, QToolTip)

import os
import qrcode

from electroncash import util
from electroncash.i18n import _
from .util import WindowModalDialog, MessageBoxMixin, CloseButton


class QRCodeWidget(QWidget, util.PrintError):

    def __init__(self, data = None, fixedSize=False):
        QWidget.__init__(self)
        self.data = None
        self.qr = None
        self.fixedSize = fixedSize
        self.setSizePolicy(QSizePolicy.MinimumExpanding, QSizePolicy.MinimumExpanding)
        if fixedSize:
            self.setFixedSize(fixedSize, fixedSize)
            self.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
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
                    self.updateGeometry()
            except qrcode.exceptions.DataOverflowError:
                self._bad_data(data)  # sets self.qr = None
        else:
            self.qr = None

        self.update()


    def _paint_blank(self):
        qp = QPainter(self)
        r = qp.viewport()
        qp.fillRect(0, 0, r.width(), r.height(), self._white_brush)
        qp.end(); del qp

    def _bad_data(self, data):
        self.print_error("Failed to generate QR image -- data too long! Data length was: {} bytes".format(len(data or '')))
        self.qr = None

    _black_brush = QBrush(QColor(0, 0, 0, 255))
    _white_brush = QBrush(QColor(255, 255, 255, 255))
    _black_pen = QPen(_black_brush, 1.0, join = Qt.MiterJoin)
    _white_pen = QPen(_white_brush, 1.0, join = Qt.MiterJoin)

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
        qp = QPainter(self)
        r = qp.viewport()

        margin = 5
        framesize = min(r.width(), r.height())
        boxsize = int( (framesize - 2*margin)/k )
        size = k*boxsize
        left = (r.width() - size)/2
        top = (r.height() - size)/2

        # Make a white margin around the QR in case of dark theme use
        qp.setBrush(self._white_brush)
        qp.setPen(self._white_pen)
        qp.drawRect(left-margin, top-margin, size+(margin*2), size+(margin*2))
        qp.setBrush(self._black_brush)
        qp.setPen(self._black_pen)

        for r in range(k):
            for c in range(k):
                if matrix[r][c]:
                    qp.drawRect(left+c*boxsize, top+r*boxsize, boxsize - 1, boxsize - 1)
        qp.end(); del qp


def save_to_file(qrw, parent):
    from .main_window import ElectrumWindow
    p = qrw and qrw.grab()
    if p and not p.isNull():
        filename = ElectrumWindow.static_getSaveFileName(title=_("Save QR Image"), filename="qrcode.png", parent=parent, filter="*.png")
        if filename:
            p.save(filename, 'png')
            isinstance(parent, MessageBoxMixin) and parent.show_message(_("QR code saved to file") + " " + filename)

def copy_to_clipboard(qrw, widget):
    p = qrw and qrw.grab()
    if p and not p.isNull():
        QApplication.clipboard().setPixmap(p)
        QToolTip.showText(QCursor.pos(), _("QR code copied to clipboard"), widget)


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

        weakSelf = util.Weak.ref(self)  # Qt & Python GC hygeine: don't hold references to self in non-method slots as it appears Qt+Python GC don't like this too much and may leak memory in that case.
        weakQ = util.Weak.ref(qrw)

        b = QPushButton(_("&Copy"))
        hbox.addWidget(b)
        weakBut = util.Weak.ref(b)
        b.clicked.connect(lambda: copy_to_clipboard(weakQ(), weakBut()))

        b = QPushButton(_("&Save"))
        hbox.addWidget(b)
        b.clicked.connect(lambda: save_to_file(weakQ(), weakSelf()))

        b = CloseButton(self)
        hbox.addWidget(b)

        vbox.addLayout(hbox)
        self.setLayout(vbox)
