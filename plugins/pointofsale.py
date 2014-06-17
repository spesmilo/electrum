import re
import platform
from decimal import Decimal
from urllib import quote

from PyQt4.QtGui import *
from PyQt4.QtCore import *
import PyQt4.QtCore as QtCore
import PyQt4.QtGui as QtGui

from electrum_gui.qt.qrcodewidget import QRCodeWidget
from electrum import BasePlugin
from electrum.i18n import _


if platform.system() == 'Windows':
    MONOSPACE_FONT = 'Lucida Console'
elif platform.system() == 'Darwin':
    MONOSPACE_FONT = 'Monaco'
else:
    MONOSPACE_FONT = 'monospace'

column_index = 4

class QR_Window(QWidget):

    def __init__(self, win):
        QWidget.__init__(self)
        self.win = win
        self.setWindowTitle('Electrum - '+_('Invoice'))
        self.setMinimumSize(800, 250)
        self.address = ''
        self.label = ''
        self.amount = 0
        self.setFocusPolicy(QtCore.Qt.NoFocus)

        main_box = QHBoxLayout()
        
        self.qrw = QRCodeWidget()
        main_box.addWidget(self.qrw, 1)

        vbox = QVBoxLayout()
        main_box.addLayout(vbox)

        self.address_label = QLabel("")
        #self.address_label.setFont(QFont(MONOSPACE_FONT))
        vbox.addWidget(self.address_label)

        self.label_label = QLabel("")
        vbox.addWidget(self.label_label)

        self.amount_label = QLabel("")
        vbox.addWidget(self.amount_label)

        vbox.addStretch(1)
        self.setLayout(main_box)


    def set_content(self, address, amount, message, url):
        address_text = "<span style='font-size: 18pt'>%s</span>" % address if address else ""
        self.address_label.setText(address_text)
        if amount:
            amount = self.win.format_amount(amount)
            amount_text = "<span style='font-size: 21pt'>%s</span> <span style='font-size: 16pt'>%s</span> " % (amount, self.win.base_unit())
        else:
            amount_text = ''
        self.amount_label.setText(amount_text)
        label_text = "<span style='font-size: 21pt'>%s</span>" % message if message else ""
        self.label_label.setText(label_text)
        self.qrw.setData(url)




class Plugin(BasePlugin):

    def fullname(self):
        return 'Point of Sale'


    def description(self):
        return _('Show payment requests in a large, separate window.')


    def init(self):
        self.window = self.gui.main_window
        self.qr_window = None
        self.toggle_QR_window(True)


    def close(self):
        self.toggle_QR_window(False)


    def close_main_window(self):
        if self.qr_window: 
            self.qr_window.close()
            self.qr_window = None


    def update_receive_qr(self, address, amount, message, url):
        self.qr_window.set_content( address, amount, message, url )

    
    def toggle_QR_window(self, show):
        if show and not self.qr_window:
            self.qr_window = QR_Window(self.gui.main_window)
            self.qr_window.setVisible(True)
            self.qr_window_geometry = self.qr_window.geometry()

        elif show and self.qr_window and not self.qr_window.isVisible():
            self.qr_window.setVisible(True)
            self.qr_window.setGeometry(self.qr_window_geometry)

        elif not show and self.qr_window and self.qr_window.isVisible():
            self.qr_window_geometry = self.qr_window.geometry()
            self.qr_window.setVisible(False)




