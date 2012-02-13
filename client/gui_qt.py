import sys, time, datetime

# todo: see PySide

from PyQt4.QtGui import *
from PyQt4.QtCore import *
import PyQt4.QtCore as QtCore
import PyQt4.QtGui as QtGui

from wallet import format_satoshis
from decimal import Decimal

def restore_create_dialog(wallet):
    pass

class Sender(QtCore.QThread):
    def run(self):
        while True:
            self.emit(QtCore.SIGNAL('testsignal'))
            time.sleep(0.5)


class ElectrumWindow(QMainWindow):

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
        tabs.setSizePolicy(QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Expanding)
        self.setCentralWidget(tabs)
        self.create_status_bar()
        self.setGeometry(100,100,840,400)
        self.setWindowTitle( 'Electrum ' + self.wallet.electrum_version + ' - Qt')
        self.show()

        QShortcut(QKeySequence("Ctrl+W"), self, self.close)
        QShortcut(QKeySequence("Ctrl+Q"), self, self.close)
        QShortcut(QKeySequence("Ctrl+PgUp"), self, lambda: tabs.setCurrentIndex( (tabs.currentIndex() - 1 )%tabs.count() ))
        QShortcut(QKeySequence("Ctrl+PgDown"), self, lambda: tabs.setCurrentIndex( (tabs.currentIndex() + 1 )%tabs.count() ))


    def connect_slots(self, sender):
        self.connect(sender, QtCore.SIGNAL('testsignal'), self.update_wallet)


    def update_wallet(self):
        if self.wallet.interface.is_connected:
            if self.wallet.interface.blocks == 0:
                text = "Server not ready"
                icon = QIcon("icons/status_disconnected.svg")
            elif not self.wallet.interface.was_polled:
                text = "Synchronizing..."
                icon = QIcon("icons/status_waiting.svg")
            else:
                c, u = self.wallet.get_balance()
                text =  "Balance: %s "%( format_satoshis(c) )
                if u: text +=  "[%s unconfirmed]"%( format_satoshis(u,True) )
                icon = QIcon("icons/status_connected.png")
        else:
            text = "Not connected"
            icon = QIcon("icons/status_disconnected.svg")

        self.statusBar().showMessage(text)
        self.status_button.setIcon( icon )

        if self.wallet.interface.was_updated:
            self.wallet.interface.was_updated = False
            self.textbox.setText( self.wallet.interface.message )
            self.update_history_tab()
            self.update_receive_tab()
            self.update_contacts_tab()


    def create_history_tab(self):
        self.history_list = w = QTreeWidget(self)
        #print w.getContentsMargins()
        w.setColumnCount(5)
        w.setColumnWidth(0, 40) 
        w.setColumnWidth(1, 140) 
        w.setColumnWidth(2, 350) 
        w.setColumnWidth(3, 140) 
        w.setColumnWidth(4, 140) 
        w.setHeaderLabels( [ '', 'Date', 'Description', 'Amount', 'Balance'] )
        self.connect(w, SIGNAL('itemActivated(QTreeWidgetItem*, int)'), self.tx_details)
        self.connect(w, SIGNAL('itemDoubleClicked(QTreeWidgetItem*, int)'), self.tx_label_clicked)
        self.connect(w, SIGNAL('itemChanged(QTreeWidgetItem*, int)'), self.tx_label_changed)
        return w

    def tx_details(self, item, column):
        tx_hash = str(item.toolTip(0))
        tx = self.wallet.tx_history.get(tx_hash)

        if tx['height']:
            conf = self.wallet.interface.blocks - tx['height'] + 1
            time_str = datetime.datetime.fromtimestamp( tx['nTime']).isoformat(' ')[:-3]
        else:
            conf = 0
            time_str = 'pending'

        tx_details = "Transaction Details:\n\n" \
            + "Transaction ID:\n" + tx_hash + "\n\n" \
            + "Status: %d confirmations\n\n"%conf  \
            + "Date: %s\n\n"%time_str \
            + "Inputs:\n-"+ '\n-'.join(tx['inputs']) + "\n\n" \
            + "Outputs:\n-"+ '\n-'.join(tx['outputs'])

        r = self.wallet.receipts.get(tx_hash)
        if r:
            tx_details += "\n_______________________________________" \
                + '\n\nSigned URI: ' + r[2] \
                + "\n\nSigned by: " + r[0] \
                + '\n\nSignature: ' + r[1]

        QMessageBox.information(self, 'Details', tx_details, 'OK')


    def tx_label_clicked(self, item, column):
        if column==2 and item.isSelected():
            tx_hash = str(item.toolTip(0))
            self.is_edit=True
            #if not self.wallet.labels.get(tx_hash): item.setText(2,'')
            item.setFlags(Qt.ItemIsEditable|Qt.ItemIsSelectable | Qt.ItemIsUserCheckable | Qt.ItemIsEnabled | Qt.ItemIsDragEnabled)
            self.history_list.editItem( item, column )
            item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsUserCheckable | Qt.ItemIsEnabled | Qt.ItemIsDragEnabled)
            self.is_edit=False

    def tx_label_changed(self, item, column):
        if self.is_edit: 
            return
        self.is_edit=True
        tx_hash = str(item.toolTip(0))
        tx = self.wallet.tx_history.get(tx_hash)
        s = self.wallet.labels.get(tx_hash)
        text = str( item.text(2) )
        if text: 
            self.wallet.labels[tx_hash] = text
            item.setForeground(2, QBrush(QColor('black')))
        else:
            if s: self.wallet.labels.pop(tx_hash)
            text = tx['default_label']
            item.setText(2, text)
            item.setForeground(2, QBrush(QColor('gray')))
        self.is_edit=False

    def address_label_clicked(self, item, column, l):
        if column==1 and item.isSelected():
            item.setFlags(Qt.ItemIsEditable|Qt.ItemIsSelectable | Qt.ItemIsUserCheckable | Qt.ItemIsEnabled | Qt.ItemIsDragEnabled)
            l.editItem( item, column )
            item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsUserCheckable | Qt.ItemIsEnabled | Qt.ItemIsDragEnabled)

    def address_label_changed(self, item, column, l):
        addr = str(item.text(0))
        text = str( item.text(1) )
        if text:
            self.wallet.labels[addr] = text
        else:
            s = self.wallet.labels.get(addr)
            if s: self.wallet.labels.pop(addr)
        self.update_history_tab()

    def update_history_tab(self):
        self.history_list.clear()
        balance = 0
        for tx in self.wallet.get_tx_history():
            tx_hash = tx['tx_hash']
            if tx['height']:
                conf = self.wallet.interface.blocks - tx['height'] + 1
                time_str = datetime.datetime.fromtimestamp( tx['nTime']).isoformat(' ')[:-3]
                icon = QIcon("icons/confirmed.png")
            else:
                conf = 0
                time_str = 'pending'
                icon = QIcon("icons/unconfirmed.svg")
            v = tx['value']
            balance += v 
            label = self.wallet.labels.get(tx_hash)
            is_default_label = (label == '') or (label is None)
            if is_default_label: label = tx['default_label']

            item = QTreeWidgetItem( [ '', time_str, label, format_satoshis(v,True), format_satoshis(balance)] )
            item.setFont(2, QFont('monospace'))
            item.setFont(3, QFont('monospace'))
            item.setFont(4, QFont('monospace'))
            item.setToolTip(0, tx_hash)
            if is_default_label:
                item.setForeground(2, QBrush(QColor('grey')))

            item.setIcon(0, icon)
            self.history_list.insertTopLevelItem(0,item)


    def create_send_tab(self):
        w = QWidget()

        paytoEdit = QtGui.QLineEdit()
        descriptionEdit = QtGui.QLineEdit()
        amountEdit = QtGui.QLineEdit()
        feeEdit = QtGui.QLineEdit()

        grid = QtGui.QGridLayout()
        grid.setSpacing(8)
        grid.setColumnMinimumWidth(3,300)
        grid.setColumnStretch(4,1)

        grid.addWidget(QLabel('Pay to'), 1, 0)
        grid.addWidget(paytoEdit, 1, 1, 1, 3)

        grid.addWidget(QLabel('Description'), 2, 0)
        grid.addWidget(descriptionEdit, 2, 1, 1, 3)

        grid.addWidget(QLabel('Amount'), 3, 0)
        grid.addWidget(amountEdit, 3, 1, 1, 2)
        
        grid.addWidget(QLabel('Fee'), 4, 0)
        grid.addWidget(feeEdit, 4, 1, 1, 2)
        
        sendButton = QPushButton("Send")
        grid.addWidget(sendButton, 5, 1)

        clearButton = QPushButton("Clear")
        grid.addWidget(clearButton, 5, 2)

        w.setLayout(grid) 
        w.show()

        w2 = QWidget()
        vbox = QtGui.QVBoxLayout()
        vbox.addWidget(w)
        vbox.addStretch(1)
        w2.setLayout(vbox)

        return w2

    def make_address_list(self, is_recv):

        l = QTreeWidget(self)
        l.setColumnCount(3)
        l.setColumnWidth(0, 350) 
        l.setColumnWidth(1, 330)
        l.setColumnWidth(2, 20) 
        l.setHeaderLabels( ['Address', 'Label','Tx'])

        vbox = QtGui.QVBoxLayout()
        vbox.setMargin(0)
        vbox.setSpacing(0)
        vbox.addWidget(l)

        hbox = QtGui.QHBoxLayout()
        hbox.setMargin(0)
        hbox.setSpacing(0)
        qrButton = QtGui.QPushButton("QR")
        copyButton = QtGui.QPushButton("Copy to Clipboard")
        hbox.addWidget(qrButton)
        hbox.addWidget(copyButton)
        if not is_recv:
            addButton = QtGui.QPushButton("New")
            addButton.clicked.connect(self.newaddress_dialog)
            paytoButton = QtGui.QPushButton("Pay to")
            hbox.addWidget(addButton)
            hbox.addWidget(paytoButton)
        hbox.addStretch(1)
        buttons = QWidget()
        buttons.setLayout(hbox)
        vbox.addWidget(buttons)

        w = QWidget()
        w.setLayout(vbox)
        return w, l

    def create_receive_tab(self):
        w, l = self.make_address_list(True)
        self.connect(l, SIGNAL('itemDoubleClicked(QTreeWidgetItem*, int)'), lambda a, b: self.address_label_clicked(a,b,l))
        self.connect(l, SIGNAL('itemChanged(QTreeWidgetItem*, int)'), lambda a,b: self.address_label_changed(a,b,l))
        self.receive_list = l
        return w

    def create_contacts_tab(self):
        w, l = self.make_address_list(False)
        self.connect(l, SIGNAL('itemDoubleClicked(QTreeWidgetItem*, int)'), lambda a, b: self.address_label_clicked(a,b,l))
        self.connect(l, SIGNAL('itemChanged(QTreeWidgetItem*, int)'), lambda a,b: self.address_label_changed(a,b,l))
        self.connect(l, SIGNAL('itemActivated(QTreeWidgetItem*, int)'), self.show_contact_details)
        self.contacts_list = l
        return w

    def update_receive_tab(self):
        self.receive_list.clear()
        for address in self.wallet.all_addresses():
            if self.wallet.is_change(address):continue
            label = self.wallet.labels.get(address,'')
            n = 0 
            h = self.wallet.history.get(address,[])
            for item in h:
                if not item['is_in'] : n=n+1
            tx = "None" if n==0 else "%d"%n
            item = QTreeWidgetItem( [ address, label, tx] )
            item.setFont(0, QFont('monospace'))
            self.receive_list.addTopLevelItem(item)

    def show_contact_details(self, item, column):
        m = str(item.text(0))
        a = self.wallet.aliases.get(m)
        if a:
            if a[0] in self.wallet.authorities.keys():
                s = self.wallet.authorities.get(a[0])
            else:
                s = "self-signed"
            msg = 'Alias: '+ m + '\nTarget address: '+ a[1] + '\n\nSigned by: ' + s + '\nSigning address:' + a[0]
            QMessageBox.information(self, 'Alias', msg, 'OK')

    def update_contacts_tab(self):
        self.contacts_list.clear()
        for alias, v in self.wallet.aliases.items():
            s, target = v
            label = self.wallet.labels.get(alias,'')
            item = QTreeWidgetItem( [ alias, label, '-'] )
            self.contacts_list.addTopLevelItem(item)
            
        for address in self.wallet.addressbook:
            label = self.wallet.labels.get(address,'')
            n = 0 
            for item in self.wallet.tx_history.values():
                if address in item['outputs'] : n=n+1
            tx = "None" if n==0 else "%d"%n
            item = QTreeWidgetItem( [ address, label, tx] )
            item.setFont(0, QFont('monospace'))
            self.contacts_list.addTopLevelItem(item)


    def create_wall_tab(self):
        self.textbox = textbox = QTextEdit(self)
        textbox.setReadOnly(True)
        return textbox

    def create_status_bar(self):
        sb = QStatusBar()
        sb.setFixedHeight(35)

        hbox = QtGui.QHBoxLayout()
        hbox.setMargin(0)
        buttons = QWidget()
        buttons.setLayout(hbox)

        icon = QIcon("icons/lock.svg")
        b = QPushButton( icon, '' )
        b.setToolTip("Password")
        b.setFlat(True)
        b.setMaximumWidth(25)
        b.clicked.connect(self.change_password_dialog)
        hbox.addWidget(b)

        icon = QIcon("icons/preferences.svg")
        b = QPushButton( icon, '' )
        b.setToolTip("Preferences")
        b.setFlat(True)
        b.setMaximumWidth(25)
        b.clicked.connect(self.settings_dialog)
        hbox.addWidget(b)

        icon = QIcon("icons/seed.png")
        b = QPushButton( icon, '' )
        b.setToolTip("Seed")
        b.setFlat(True)
        b.setMaximumWidth(20)
        b.clicked.connect(self.show_seed_dialog)
        hbox.addWidget(b)

        icon = QIcon("icons/status_disconnected.svg")
        self.status_button = b = QPushButton( icon, '' )
        b.setToolTip("Network")
        b.setFlat(True)
        b.setMaximumWidth(25)
        b.clicked.connect(self.network_dialog)
        hbox.addWidget(b)

        sb.addPermanentWidget(buttons)
        self.setStatusBar(sb)

    def newaddress_dialog(self):

        text, ok = QtGui.QInputDialog.getText(self, 'New Contact', 'Address:')
        address = str(text)
        if ok:
            if self.wallet.is_valid(address):
                self.wallet.addressbook.append(address)
                self.wallet.save()
                self.update_contacts_tab()
            else:
                QMessageBox.warning(self, 'Error', 'Invalid Address', 'OK')

    def show_seed_dialog(self):
        import mnemonic
        if self.wallet.use_encryption:
            password = self.password_dialog()
            if not password: return
        else:
            password = None
            
        try:
            seed = self.wallet.pw_decode( self.wallet.seed, password)
        except:
            QMessageBox.warning(self, 'Error', 'Invalid Password', 'OK')
            return

        msg = "Your wallet generation seed is:\n\n" + seed \
              + "\n\nPlease keep it in a safe place; if you lose it, you will not be able to restore your wallet.\n\n" \
              + "Equivalently, your wallet seed can be stored and recovered with the following mnemonic code:\n\n\"" \
              + ' '.join(mnemonic.mn_encode(seed)) + "\""

        QMessageBox.information(self, 'Seed', msg, 'OK')


    def password_dialog(self):
        d = QDialog(self)
        d.setModal(1)

        pw = QLineEdit()
        pw.setEchoMode(2)

        grid = QGridLayout()
        grid.setSpacing(8)

        msg = 'Please enter your password'
        
        grid.addWidget(QLabel(msg), 0, 0, 1, 2)

        grid.addWidget(QLabel('Password'), 1, 0)
        grid.addWidget(pw, 1, 1)

        b = QPushButton("Cancel")
        grid.addWidget(b, 5, 1)
        b.clicked.connect(d.reject)

        b = QPushButton("OK")
        grid.addWidget(b, 5, 2)
        b.clicked.connect(d.accept)

        d.setLayout(grid) 

        if not d.exec_(): return
        return str(pw.text())

    def change_password_dialog(self):
        d = QDialog(self)
        d.setModal(1)

        pw = QLineEdit()
        pw.setEchoMode(2)
        new_pw = QLineEdit()
        new_pw.setEchoMode(2)
        conf_pw = QLineEdit()
        conf_pw.setEchoMode(2)

        grid = QGridLayout()
        grid.setSpacing(8)

        msg = 'Your wallet is encrypted. Use this dialog to change your password.\nTo disable wallet encryption, enter an empty new password.' if self.wallet.use_encryption else 'Your wallet keys are not encrypted'
        grid.addWidget(QLabel(msg), 0, 0, 1, 2)

        if self.wallet.use_encryption:
            grid.addWidget(QLabel('Password'), 1, 0)
            grid.addWidget(pw, 1, 1)

        grid.addWidget(QLabel('New Password'), 2, 0)
        grid.addWidget(new_pw, 2, 1)

        grid.addWidget(QLabel('Confirm Password'), 3, 0)
        grid.addWidget(conf_pw, 3, 1)

        b = QPushButton("Cancel")
        grid.addWidget(b, 5, 1)
        b.clicked.connect(d.reject)

        b = QPushButton("OK")
        grid.addWidget(b, 5, 2)
        b.clicked.connect(d.accept)

        d.setLayout(grid) 

        if not d.exec_(): return

        password = str(pw.text()) if self.wallet.use_encryption else None
        new_password = str(new_pw.text())
        new_password2 = str(conf_pw.text())

        try:
            seed = self.wallet.pw_decode( self.wallet.seed, password)
        except:
            QMessageBox.warning(self, 'Error', 'Incorrect Password', 'OK')
            return

        if new_password != new_password2:
            QMessageBox.warning(self, 'Error', 'Passwords do not match', 'OK')
            return

        self.wallet.update_password(seed, new_password)

    def settings_dialog(self):
        d = QDialog(self)
        d.setModal(1)

        grid = QGridLayout()
        grid.setSpacing(8)

        msg = 'These are the settings of your wallet'
        grid.addWidget(QLabel(msg), 0, 0, 1, 2)

        fee_line = QLineEdit()
        fee_line.setText("%s"% str( Decimal( self.wallet.fee)/100000000 ) )
        grid.addWidget(QLabel('Fee'), 2, 0)
        grid.addWidget(fee_line, 2, 1)

        b = QPushButton("Cancel")
        grid.addWidget(b, 5, 1)
        b.clicked.connect(d.reject)

        b = QPushButton("OK")
        grid.addWidget(b, 5, 2)
        b.clicked.connect(d.accept)

        d.setLayout(grid) 

        if not d.exec_(): return

        fee = str(fee_line.text())
        try:
            fee = int( 100000000 * Decimal(fee) )
        except:
            QMessageBox.warning(self, 'Error', 'Invalid value:%s'%fee, 'OK')
            return

        self.wallet.fee = fee
        self.wallet.save()

    def network_dialog(self, parent=True):
        wallet = self.wallet
        if parent:
            if wallet.interface.is_connected:
                status = "Connected to %s.\n%d blocks\nresponse time: %f"%(wallet.interface.host, wallet.interface.blocks, wallet.interface.rtime)
            else:
                status = "Not connected"
                host = wallet.interface.host
                port = wallet.interface.port
        else:
            import random
            status = "Please choose a server."
            host = random.choice( wallet.interface.servers )
            port = 50000

        d = QDialog(self)
        d.setModal(1)

        grid = QGridLayout()
        grid.setSpacing(8)
        grid.addWidget(QLabel(status), 0, 0, 1, 2)

        host_line = QLineEdit()
        host_line.setText("%s:%d"% (host,port) )
        grid.addWidget(QLabel('Server'), 2, 0)
        grid.addWidget(host_line, 2, 1)

        b = QPushButton("Cancel")
        grid.addWidget(b, 5, 1)
        b.clicked.connect(d.reject)

        b = QPushButton("OK")
        grid.addWidget(b, 5, 2)
        b.clicked.connect(d.accept)

        d.setLayout(grid) 

        if not d.exec_(): return
        hh = str( host_line.text() )

        try:
            if ':' in hh:
                host, port = hh.split(':')
                port = int(port)
            else:
                host = hh
                port = 50000
        except:
            show_message("error")
            if parent == None:
                sys.exit(1)
            else:
                return

        wallet.interface.set_server(host, port) 

        if parent:
            wallet.save()




class BitcoinGUI():

    def __init__(self, wallet):
        self.wallet = wallet

    def main(self):
        s = Sender()
        s.start()
        app = QApplication(sys.argv)
        w = ElectrumWindow(self.wallet)
        w.connect_slots(s)
        app.exec_()
