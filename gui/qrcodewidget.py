from PyQt4.QtGui import *
from PyQt4.QtCore import *
import PyQt4.QtCore as QtCore
import PyQt4.QtGui as QtGui

import bmp, pyqrnative


class QRCodeWidget(QWidget):

    def __init__(self, data = None, size=4):
        QWidget.__init__(self)
        self.setMinimumSize(210, 210)
        self.addr = None
        self.qr = None
        self.size = size
        if data:
            self.set_addr(data)
            self.update_qr()

    def set_addr(self, addr):
        if self.addr != addr:
            self.addr = addr
            self.qr = None
            self.update()

    def update_qr(self):
        if self.addr and not self.qr:
            self.qr = pyqrnative.QRCode(self.size, pyqrnative.QRErrorCorrectLevel.L)
            self.qr.addData(self.addr)
            try:
                self.qr.make()
            except:
                self.qr=None
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
        
