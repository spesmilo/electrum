import sys, time

# todo: see PySide

from PyQt4.QtGui import *
from PyQt4.QtCore import *
import PyQt4.QtCore as QtCore
import PyQt4.QtGui as QtGui

from wallet import format_satoshis

def restore_create_dialog(wallet):
    pass

class Sender(QtCore.QThread):
    def run(self):
        while True:
            self.emit(QtCore.SIGNAL('testsignal'))
            time.sleep(0.5)


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
        tabs.setMinimumSize(600, 400)
        tabs.show()

        self.create_status_bar()
        
        self.setGeometry(100,100,750,550)
        self.setWindowTitle( 'Electrum ' + self.wallet.electrum_version )
        self.show()

    def connect_slots(self, sender):
        self.connect(sender, QtCore.SIGNAL('testsignal'), self.update_wallet)

    def update_wallet(self):
        if self.wallet.interface.is_connected:
            if self.wallet.interface.blocks == 0:
                text = "Server not ready"
            elif not self.wallet.interface.was_polled:
                text = "Synchronizing..."
            else:
                c, u = self.wallet.get_balance()
                text =  "Balance: %s "%( format_satoshis(c) )
                if u: text +=  "[%s unconfirmed]"%( format_satoshis(u,True) )
        else:
            text = "Not connected"
        self.statusBar().showMessage(text)

        if self.wallet.interface.was_updated:
            self.textbox.setText( self.wallet.interface.message )
            self.wallet.interface.was_updated = False

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
        self.textbox = textbox = QTextEdit(self)
        textbox.setReadOnly(True)
        return textbox

    def create_status_bar(self):
        sb = QStatusBar()
        sb.setFixedHeight(18)
        self.setStatusBar(sb)


class BitcoinGUI():

    def __init__(self, wallet):
        self.wallet = wallet

    def main(self):
        s = Sender()
        s.start()
        app = QApplication(sys.argv)
        w = BitcoinWidget(self.wallet)
        w.connect_slots(s)
        app.exec_()





                                                
