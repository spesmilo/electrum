import sys

# todo: see PySide

from PyQt4.QtGui import *
from PyQt4.QtCore import *
import PyQt4.QtCore as QtCore
import PyQt4.QtGui as QtGui

def restore_create_dialog(wallet):
    pass


class BitcoinWidget(QMainWindow):

    def __init__(self, wallet):
        QMainWindow.__init__(self)
        self.wallet = wallet
        tabs = QTabWidget(self)
        tabs.addTab(self.create_history_tab(), 'History')  
        tabs.addTab(self.create_send_tab(),    'Send')
        tabs.addTab(self.create_receive_tab(), 'Receive')  
        tabs.addTab(self.create_contacts_tab(),'Contacts')  
        tabs.addTab(self.create_wall_tab(),    'Wall')  
        tabs.resize(600, 400)
        tabs.show()

        self.create_status_bar()
        
        self.setGeometry(100,100,750,550)
        self.setWindowTitle( 'Electrum ' + self.wallet.electrum_version )
        self.show()


    def create_history_tab(self):
        h = [ 'ff', 'bar' ]
        qstr = QStringList((QString('foo'),QString('bar')))
        qstr_model = QtGui.QStringListModel(qstr)
        lv = QListView()
        lv.setModel(qstr_model)
        return lv

    def create_send_tab(self):
        return QLabel('heh')

    def create_receive_tab(self):
        return QLabel('heh')

    def create_contacts_tab(self):
        return QLabel('heh')

    def create_wall_tab(self):
        return QLabel(self.wallet.interface.message)

    def create_status_bar(self):
        sb = QStatusBar()
        sb.setFixedHeight(18)
        self.setStatusBar(sb)
        self.statusBar().showMessage(self.tr("test"))


class BitcoinGUI():

    def __init__(self, wallet):
        self.wallet = wallet

    def main(self):

        app = QApplication(sys.argv)
        w = BitcoinWidget(self.wallet)
        app.exec_()





                                                
