import sys

from PyQt4.QtGui import *
import PyQt4.QtCore as QtCore

def restore_create_dialog(wallet):
    pass


class BitcoinWidget(QWidget):

    def __init__(self, wallet):
        super(BitcoinWidget, self).__init__()
        self.wallet = wallet
        self.initUI()

    def initUI(self):
        qbtn = QPushButton('Quit', self)
        qbtn.clicked.connect(QtCore.QCoreApplication.instance().quit)
        qbtn.resize(qbtn.sizeHint())
        qbtn.move(50, 50)
        
        self.setGeometry(300, 300, 250, 150)
        self.setWindowTitle( 'Electrum ' + self.wallet.electrum_version )
        self.show()

class BitcoinGUI():

    def __init__(self, wallet):
        self.wallet = wallet

    def main(self):

        app = QApplication(sys.argv)
        w = BitcoinWidget(self.wallet)
        app.exec_()





                                                
