#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2012 thomasv@gitorious
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

import sys, time, datetime, re
from i18n import _
from util import print_error

try:
    import PyQt4
except:
    sys.exit("Error: Could not import PyQt4 on Linux systems, you may try 'sudo apt-get install python-qt4'")

from PyQt4.QtGui import *
from PyQt4.QtCore import *
import PyQt4.QtCore as QtCore
import PyQt4.QtGui as QtGui
from interface import DEFAULT_SERVERS

try:
    import icons_rc
except:
    sys.exit("Error: Could not import icons_rc.py, please generate it with: 'pyrcc4 icons.qrc -o lib/icons_rc.py'")

from wallet import format_satoshis
import bmp, mnemonic, pyqrnative, qrscanner

from decimal import Decimal

import platform

if platform.system() == 'Windows':
    MONOSPACE_FONT = 'Lucida Console'
elif platform.system() == 'Darwin':
    MONOSPACE_FONT = 'Monaco'
else:
    MONOSPACE_FONT = 'monospace'

ALIAS_REGEXP = '^(|([\w\-\.]+)@)((\w[\w\-]+\.)+[\w\-]+)$'    

def numbify(entry, is_int = False):
    text = unicode(entry.text()).strip()
    pos = entry.cursorPosition()
    chars = '0123456789'
    if not is_int: chars +='.'
    s = ''.join([i for i in text if i in chars])
    if not is_int:
        if '.' in s:
            p = s.find('.')
            s = s.replace('.','')
            s = s[:p] + '.' + s[p:p+8]
        try:
            amount = int( Decimal(s) * 100000000 )
        except:
            amount = None
    else:
        try:
            amount = int( s )
        except:
            amount = None
    entry.setText(s)
    entry.setCursorPosition(pos)
    return amount


class Timer(QtCore.QThread):
    def run(self):
        while True:
            self.emit(QtCore.SIGNAL('timersignal'))
            time.sleep(0.5)

class HelpButton(QPushButton):
    def __init__(self, text):
        QPushButton.__init__(self, '?')
        self.setFocusPolicy(Qt.NoFocus)
        self.setFixedWidth(20)
        self.clicked.connect(lambda: QMessageBox.information(self, 'Help', text, 'OK') )


class EnterButton(QPushButton):
    def __init__(self, text, func):
        QPushButton.__init__(self, text)
        self.func = func
        self.clicked.connect(func)

    def keyPressEvent(self, e):
        if e.key() == QtCore.Qt.Key_Return:
            apply(self.func,())

class MyTreeWidget(QTreeWidget):
    def __init__(self, parent):
        QTreeWidget.__init__(self, parent)
        def ddfr(item):
            if not item: return
            for i in range(0,self.viewport().height()/5):
                if self.itemAt(QPoint(0,i*5)) == item:
                    break
            else:
                return
            for j in range(0,30):
                if self.itemAt(QPoint(0,i*5 + j)) != item:
                    break
            self.emit(SIGNAL('customContextMenuRequested(const QPoint&)'), QPoint(50, i*5 + j - 1))

        self.connect(self, SIGNAL('itemActivated(QTreeWidgetItem*, int)'), ddfr)
        



class StatusBarButton(QPushButton):
    def __init__(self, icon, tooltip, func):
        QPushButton.__init__(self, icon, '')
        self.setToolTip(tooltip)
        self.setFlat(True)
        self.setMaximumWidth(25)
        self.clicked.connect(func)
        self.func = func

    def keyPressEvent(self, e):
        if e.key() == QtCore.Qt.Key_Return:
            apply(self.func,())


class QRCodeWidget(QWidget):

    def __init__(self, addr):
        super(QRCodeWidget, self).__init__()
        self.setGeometry(300, 300, 350, 350)
        self.set_addr(addr)

    def set_addr(self, addr):
        self.addr = addr
        self.qr = pyqrnative.QRCode(4, pyqrnative.QRErrorCorrectLevel.L)
        self.qr.addData(addr)
        self.qr.make()
        
    def paintEvent(self, e):
        qp = QtGui.QPainter()
        qp.begin(self)
        boxsize = 6
        size = self.qr.getModuleCount()*boxsize
        k = self.qr.getModuleCount()
        black = QColor(0, 0, 0, 255)
        white = QColor(255, 255, 255, 255)
        for r in range(k):
            for c in range(k):
                if self.qr.isDark(r, c):
                    qp.setBrush(black)
                    qp.setPen(black)
                else:
                    qp.setBrush(white)
                    qp.setPen(white)
                qp.drawRect(c*boxsize, r*boxsize, boxsize, boxsize)
        qp.end()
        

def waiting_dialog(f):

    s = Timer()
    s.start()
    w = QDialog()
    w.resize(200, 70)
    w.setWindowTitle('Electrum')
    l = QLabel('')
    vbox = QVBoxLayout()
    vbox.addWidget(l)
    w.setLayout(vbox)
    w.show()
    def ff():
        s = f()
        if s: l.setText(s)
        else: w.close()
    w.connect(s, QtCore.SIGNAL('timersignal'), ff)
    w.exec_()
    w.destroy()


def ok_cancel_buttons(dialog):
    hbox = QHBoxLayout()
    hbox.addStretch(1)
    b = QPushButton("OK")
    hbox.addWidget(b)
    b.clicked.connect(dialog.accept)
    b = QPushButton("Cancel")
    hbox.addWidget(b)
    b.clicked.connect(dialog.reject)
    return hbox


class ElectrumWindow(QMainWindow):

    def __init__(self, wallet, config):
        QMainWindow.__init__(self)
        self.wallet = wallet
        self.config = config
        self.wallet.interface.register_callback('updated', self.update_callback)
        self.wallet.interface.register_callback('connected', self.update_callback)
        self.wallet.interface.register_callback('disconnected', self.update_callback)
        self.wallet.interface.register_callback('disconnecting', self.update_callback)

        self.detailed_view = config.get('qt_detailed_view', False)

        self.funds_error = False
        self.completions = QStringListModel()

        self.tabs = tabs = QTabWidget(self)
        tabs.addTab(self.create_history_tab(), _('History') )
        if self.wallet.seed:
            tabs.addTab(self.create_send_tab(), _('Send') )
        tabs.addTab(self.create_receive_tab(), _('Receive') )
        tabs.addTab(self.create_contacts_tab(), _('Contacts') )
        tabs.addTab(self.create_wall_tab(), _('Wall') )
        tabs.setMinimumSize(600, 400)
        tabs.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.setCentralWidget(tabs)
        self.create_status_bar()

        g = self.config.get("winpos-qt",[100, 100, 840, 400])
        self.setGeometry(g[0], g[1], g[2], g[3])
        title = 'Electrum ' + self.wallet.electrum_version + '  -  ' + self.config.path
        if not self.wallet.seed: title += ' [seedless]'
        self.setWindowTitle( title )

        QShortcut(QKeySequence("Ctrl+W"), self, self.close)
        QShortcut(QKeySequence("Ctrl+Q"), self, self.close)
        QShortcut(QKeySequence("Ctrl+PgUp"), self, lambda: tabs.setCurrentIndex( (tabs.currentIndex() - 1 )%tabs.count() ))
        QShortcut(QKeySequence("Ctrl+PgDown"), self, lambda: tabs.setCurrentIndex( (tabs.currentIndex() + 1 )%tabs.count() ))
        
        self.connect(self, QtCore.SIGNAL('updatesignal'), self.update_wallet)
        self.history_list.setFocus(True)

        # dark magic fix by flatfly; https://bitcointalk.org/index.php?topic=73651.msg959913#msg959913
        if platform.system() == 'Windows':
            n = 3 if self.wallet.seed else 2
            tabs.setCurrentIndex (n)
            tabs.setCurrentIndex (0)


    def connect_slots(self, sender):
        if self.wallet.seed:
            self.connect(sender, QtCore.SIGNAL('timersignal'), self.check_recipient)
            self.previous_payto_e=''

    def check_recipient(self):
        if self.payto_e.hasFocus():
            return
        r = unicode( self.payto_e.text() )
        if r != self.previous_payto_e:
            self.previous_payto_e = r
            r = r.strip()
            if re.match('^(|([\w\-\.]+)@)((\w[\w\-]+\.)+[\w\-]+)$', r):
                try:
                    to_address = self.wallet.get_alias(r, True, self.show_message, self.question)
                except:
                    return
                if to_address:
                    s = r + '  <' + to_address + '>'
                    self.payto_e.setText(s)


    def update_callback(self):
        self.emit(QtCore.SIGNAL('updatesignal'))

    def update_wallet(self):
        if self.wallet.interface and self.wallet.interface.is_connected:
            if not self.wallet.up_to_date:
                text = _( "Synchronizing..." )
                icon = QIcon(":icons/status_waiting.png")
            else:
                c, u = self.wallet.get_balance()
                text =  _( "Balance" ) + ": %s "%( format_satoshis(c,False,self.wallet.num_zeros) )
                if u: text +=  "[%s unconfirmed]"%( format_satoshis(u,True,self.wallet.num_zeros).strip() )
                icon = QIcon(":icons/status_connected.png")
        else:
            text = _( "Not connected" )
            icon = QIcon(":icons/status_disconnected.png")

        if self.funds_error:
            text = _( "Not enough funds" )

        self.statusBar().showMessage(text)
        self.status_button.setIcon( icon )

        if self.wallet.up_to_date:
            self.textbox.setText( self.wallet.banner )
            self.update_history_tab()
            self.update_receive_tab()
            self.update_contacts_tab()
            self.update_completions()


    def create_history_tab(self):
        self.history_list = l = MyTreeWidget(self)
        l.setColumnCount(5)
        l.setColumnWidth(0, 40) 
        l.setColumnWidth(1, 140) 
        l.setColumnWidth(2, 350) 
        l.setColumnWidth(3, 140) 
        l.setColumnWidth(4, 140) 
        l.setHeaderLabels( [ '', _( 'Date' ), _( 'Description' ) , _('Amount'), _('Balance')] )
        self.connect(l, SIGNAL('itemDoubleClicked(QTreeWidgetItem*, int)'), self.tx_label_clicked)
        self.connect(l, SIGNAL('itemChanged(QTreeWidgetItem*, int)'), self.tx_label_changed)
        l.setContextMenuPolicy(Qt.CustomContextMenu)
        l.customContextMenuRequested.connect(self.create_history_menu)
        return l

    def create_history_menu(self, position):
        self.history_list.selectedIndexes() 
        item = self.history_list.currentItem()
        if not item: return
        tx_hash = str(item.toolTip(0))
        menu = QMenu()
        menu.addAction(_("Copy ID to Clipboard"), lambda: self.app.clipboard().setText(tx_hash))
        menu.addAction(_("Details"), lambda: self.tx_details(tx_hash))
        menu.addAction(_("Edit description"), lambda: self.tx_label_clicked(item,2))
        menu.exec_(self.contacts_list.viewport().mapToGlobal(position))

    def tx_details(self, tx_hash):
        tx = self.wallet.transactions.get(tx_hash)

        if tx['height']:
            conf = self.wallet.verifier.get_confirmations(tx_hash)
            time_str = datetime.datetime.fromtimestamp( tx['timestamp']).isoformat(' ')[:-3]
        else:
            conf = 0
            time_str = 'pending'

        tx_details = _("Transaction Details") +"\n\n" \
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
        tx = self.wallet.transactions.get(tx_hash)
        s = self.wallet.labels.get(tx_hash)
        text = unicode( item.text(2) )
        if text: 
            self.wallet.labels[tx_hash] = text
            item.setForeground(2, QBrush(QColor('black')))
        else:
            if s: self.wallet.labels.pop(tx_hash)
            text = tx['default_label']
            item.setText(2, text)
            item.setForeground(2, QBrush(QColor('gray')))
        self.is_edit=False

    def edit_label(self, is_recv):
        l = self.receive_list if is_recv else self.contacts_list
        c = 2 if is_recv else 1
        item = l.currentItem()
        item.setFlags(Qt.ItemIsEditable|Qt.ItemIsSelectable | Qt.ItemIsUserCheckable | Qt.ItemIsEnabled | Qt.ItemIsDragEnabled)
        l.editItem( item, c )
        item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsUserCheckable | Qt.ItemIsEnabled | Qt.ItemIsDragEnabled)

    def address_label_clicked(self, item, column, l, column_addr, column_label):
        if column==column_label and item.isSelected():
            addr = unicode( item.text(column_addr) )
            label = unicode( item.text(column_label) )
            if label in self.wallet.aliases.keys():
                return
            item.setFlags(Qt.ItemIsEditable|Qt.ItemIsSelectable | Qt.ItemIsUserCheckable | Qt.ItemIsEnabled | Qt.ItemIsDragEnabled)
            l.editItem( item, column )
            item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsUserCheckable | Qt.ItemIsEnabled | Qt.ItemIsDragEnabled)

    def address_label_changed(self, item, column, l, column_addr, column_label):
        addr = unicode( item.text(column_addr) )
        text = unicode( item.text(column_label) )
        changed = False

        if text:
            if text not in self.wallet.aliases.keys():
                old_addr = self.wallet.labels.get(text)
                if old_addr != addr:
                    self.wallet.labels[addr] = text
                    changed = True
            else:
                print_error("Error: This is one of your aliases")
                label = self.wallet.labels.get(addr,'')
                item.setText(column_label, QString(label))
        else:
            s = self.wallet.labels.get(addr)
            if s: 
                self.wallet.labels.pop(addr)
                changed = True

        if changed:
            self.wallet.update_tx_labels()
            self.update_history_tab()
            self.update_completions()


    def update_history_tab(self):
        self.history_list.clear()
        balance = 0
        for tx in self.wallet.get_tx_history():
            tx_hash = tx['tx_hash']
            if tx['height']:
                conf = self.wallet.verifier.get_confirmations(tx_hash)
                time_str = datetime.datetime.fromtimestamp( tx['timestamp']).isoformat(' ')[:-3]
                if conf == 0:
                    icon = QIcon(":icons/unconfirmed.png")
                elif conf < 6:
                    icon = QIcon(":icons/clock%d.png"%conf)
                else:
                    icon = QIcon(":icons/confirmed.png")
            else:
                conf = 0
                time_str = 'pending'
                icon = QIcon(":icons/unconfirmed.png")
            v = self.wallet.get_tx_value(tx_hash)
            balance += v 
            label = self.wallet.labels.get(tx_hash)
            is_default_label = (label == '') or (label is None)
            if is_default_label:
                label = self.wallet.get_default_label(tx_hash)

            item = QTreeWidgetItem( [ '', time_str, label, format_satoshis(v,True,self.wallet.num_zeros), format_satoshis(balance,False,self.wallet.num_zeros)] )
            item.setFont(2, QFont(MONOSPACE_FONT))
            item.setFont(3, QFont(MONOSPACE_FONT))
            item.setFont(4, QFont(MONOSPACE_FONT))
            item.setToolTip(0, tx_hash)
            if is_default_label:
                item.setForeground(2, QBrush(QColor('grey')))

            item.setIcon(0, icon)
            self.history_list.insertTopLevelItem(0,item)

        self.history_list.setCurrentItem(self.history_list.topLevelItem(0))


    def create_send_tab(self):
        w = QWidget()

        grid = QGridLayout()
        grid.setSpacing(8)
        grid.setColumnMinimumWidth(3,300)
        grid.setColumnStretch(5,1)

        self.payto_e = QLineEdit()
        grid.addWidget(QLabel(_('Pay to')), 1, 0)
        grid.addWidget(self.payto_e, 1, 1, 1, 3)
        
        def fill_from_qr():
            qrcode = qrscanner.scan_qr()
            if 'address' in qrcode:
                self.payto_e.setText(qrcode['address'])
            if 'amount' in qrcode:
                self.amount_e.setText(str(qrcode['amount']))
            if 'label' in qrcode:
                self.message_e.setText(qrcode['label'])
            if 'message' in qrcode:
                self.message_e.setText("%s (%s)" % (self.message_e.text(), qrcode['message']))
                

        if qrscanner.is_available():
            b = QPushButton(_("Scan QR code"))
            b.clicked.connect(fill_from_qr)
            grid.addWidget(b, 1, 5)
    
        grid.addWidget(HelpButton(_('Recipient of the funds.') + '\n\n' + _('You may enter a Bitcoin address, a label from your list of contacts (a list of completions will be proposed), or an alias (email-like address that forwards to a Bitcoin address)')), 1, 4)

        completer = QCompleter()
        completer.setCaseSensitivity(False)
        self.payto_e.setCompleter(completer)
        completer.setModel(self.completions)

        self.message_e = QLineEdit()
        grid.addWidget(QLabel(_('Description')), 2, 0)
        grid.addWidget(self.message_e, 2, 1, 1, 3)
        grid.addWidget(HelpButton(_('Description of the transaction (not mandatory).') + '\n\n' + _('The description is not sent to the recipient of the funds. It is stored in your wallet file, and displayed in the \'History\' tab.')), 2, 4)

        self.amount_e = QLineEdit()
        grid.addWidget(QLabel(_('Amount')), 3, 0)
        grid.addWidget(self.amount_e, 3, 1, 1, 2)
        grid.addWidget(HelpButton(
                _('Amount to be sent.') + '\n\n' \
                    + _('The amount will be displayed in red if you do not have enough funds in your wallet. Note that if you have frozen some of your addresses, the available funds will be lower than your total balance.')), 3, 3)
        
        self.fee_e = QLineEdit()
        grid.addWidget(QLabel(_('Fee')), 4, 0)
        grid.addWidget(self.fee_e, 4, 1, 1, 2) 
        grid.addWidget(HelpButton(
                _('Bitcoin transactions are in general not free. A transaction fee is paid by the sender of the funds.') + '\n\n'\
                    + _('The amount of fee can be decided freely by the sender. However, transactions with low fees take more time to be processed.') + '\n\n'\
                    + _('A suggested fee is automatically added to this field. You may override it. The suggested fee increases with the size of the transaction.')), 4, 3)
        
        b = EnterButton(_("Send"), self.do_send)
        grid.addWidget(b, 6, 1)

        b = EnterButton(_("Clear"),self.do_clear)
        grid.addWidget(b, 6, 2)

        self.payto_sig = QLabel('')
        grid.addWidget(self.payto_sig, 7, 0, 1, 4)

        QShortcut(QKeySequence("Up"), w, w.focusPreviousChild)
        QShortcut(QKeySequence("Down"), w, w.focusNextChild)
        w.setLayout(grid) 

        w2 = QWidget()
        vbox = QVBoxLayout()
        vbox.addWidget(w)
        vbox.addStretch(1)
        w2.setLayout(vbox)

        def entry_changed( is_fee ):
            self.funds_error = False
            amount = numbify(self.amount_e)
            fee = numbify(self.fee_e)
            if not is_fee: fee = None
            if amount is None:
                return
            inputs, total, fee = self.wallet.choose_tx_inputs( amount, fee )
            if not is_fee:
                self.fee_e.setText( str( Decimal( fee ) / 100000000 ) )
            if inputs:
                palette = QPalette()
                palette.setColor(self.amount_e.foregroundRole(), QColor('black'))
            else:
                palette = QPalette()
                palette.setColor(self.amount_e.foregroundRole(), QColor('red'))
                self.funds_error = True
            self.amount_e.setPalette(palette)
            self.fee_e.setPalette(palette)

        self.amount_e.textChanged.connect(lambda: entry_changed(False) )
        self.fee_e.textChanged.connect(lambda: entry_changed(True) )

        return w2


    def update_completions(self):
        l = []
        for addr,label in self.wallet.labels.items():
            if addr in self.wallet.addressbook:
                l.append( label + '  <' + addr + '>')
        l = l + self.wallet.aliases.keys()

        self.completions.setStringList(l)



    def do_send(self):

        label = unicode( self.message_e.text() )
        r = unicode( self.payto_e.text() )
        r = r.strip()

        # alias
        m1 = re.match(ALIAS_REGEXP, r)
        # label or alias, with address in brackets
        m2 = re.match('(.*?)\s*\<([1-9A-HJ-NP-Za-km-z]{26,})\>', r)
        
        if m1:
            to_address = self.wallet.get_alias(r, True, self.show_message, self.question)
            if not to_address:
                return
        elif m2:
            to_address = m2.group(2)
        else:
            to_address = r

        if not self.wallet.is_valid(to_address):
            QMessageBox.warning(self, _('Error'), _('Invalid Bitcoin Address') + ':\n' + to_address, _('OK'))
            return

        try:
            amount = int( Decimal( unicode( self.amount_e.text())) * 100000000 )
        except:
            QMessageBox.warning(self, _('Error'), _('Invalid Amount'), _('OK'))
            return
        try:
            fee = int( Decimal( unicode( self.fee_e.text())) * 100000000 )
        except:
            QMessageBox.warning(self, _('Error'), _('Invalid Fee'), _('OK'))
            return

        if self.wallet.use_encryption:
            password = self.password_dialog()
            if not password:
                return
        else:
            password = None

        try:
            tx = self.wallet.mktx( to_address, amount, label, password, fee)
        except BaseException, e:
            self.show_message(str(e))
            return
            
        h = self.wallet.send_tx(tx)
        waiting_dialog(lambda: False if self.wallet.tx_event.isSet() else _("Please wait..."))
        status, msg = self.wallet.receive_tx( h )

        if status:
            QMessageBox.information(self, '', _('Payment sent.')+'\n'+msg, _('OK'))
            self.do_clear()
            self.update_contacts_tab()
        else:
            QMessageBox.warning(self, _('Error'), msg, _('OK'))


    def set_url(self, url):
        payto, amount, label, message, signature, identity, url = self.wallet.parse_url(url, self.show_message, self.question)
        self.tabs.setCurrentIndex(1)
        label = self.wallet.labels.get(payto)
        m_addr = label + '  <'+ payto+'>' if label else payto
        self.payto_e.setText(m_addr)

        self.message_e.setText(message)
        self.amount_e.setText(amount)
        if identity:
            self.set_frozen(self.payto_e,True)
            self.set_frozen(self.amount_e,True)
            self.set_frozen(self.message_e,True)
            self.payto_sig.setText( '      The bitcoin URI was signed by ' + identity )
        else:
            self.payto_sig.setVisible(False)

    def do_clear(self):
        self.payto_sig.setVisible(False)
        for e in [self.payto_e, self.message_e, self.amount_e, self.fee_e]:
            e.setText('')
            self.set_frozen(e,False)

    def set_frozen(self,entry,frozen):
        if frozen:
            entry.setReadOnly(True)
            entry.setFrame(False)
            palette = QPalette()
            palette.setColor(entry.backgroundRole(), QColor('lightgray'))
            entry.setPalette(palette)
        else:
            entry.setReadOnly(False)
            entry.setFrame(True)
            palette = QPalette()
            palette.setColor(entry.backgroundRole(), QColor('white'))
            entry.setPalette(palette)


    def toggle_freeze(self,addr):
        if not addr: return
        if addr in self.wallet.frozen_addresses:
            self.wallet.unfreeze(addr)
        else:
            self.wallet.freeze(addr)
        self.update_receive_tab()

    def toggle_priority(self,addr):
        if not addr: return
        if addr in self.wallet.prioritized_addresses:
            self.wallet.unprioritize(addr)
        else:
            self.wallet.prioritize(addr)
        self.update_receive_tab()


    def create_list_tab(self, headers):
        "generic tab creation method"
        l = MyTreeWidget(self)
        l.setColumnCount( len(headers) )
        l.setHeaderLabels( headers )

        w = QWidget()
        vbox = QVBoxLayout()
        w.setLayout(vbox)

        vbox.setMargin(0)
        vbox.setSpacing(0)
        vbox.addWidget(l)
        buttons = QWidget()
        vbox.addWidget(buttons)

        hbox = QHBoxLayout()
        hbox.setMargin(0)
        hbox.setSpacing(0)
        buttons.setLayout(hbox)

        return l,w,hbox


    def create_receive_tab(self):
        l,w,hbox = self.create_list_tab([_('Flags'), _('Address'), _('Label'), _('Balance'), _('Tx')])
        l.setContextMenuPolicy(Qt.CustomContextMenu)
        l.customContextMenuRequested.connect(self.create_receive_menu)
        self.connect(l, SIGNAL('itemDoubleClicked(QTreeWidgetItem*, int)'), lambda a, b: self.address_label_clicked(a,b,l,1,2))
        self.connect(l, SIGNAL('itemChanged(QTreeWidgetItem*, int)'), lambda a,b: self.address_label_changed(a,b,l,1,2))
        self.receive_list = l
        self.receive_buttons_hbox = hbox
        self.details_button = EnterButton(self.details_button_text(), self.toggle_detailed_view)
        hbox.addWidget(self.details_button)
        hbox.addStretch(1)
        return w

    def details_button_text(self):
        return _('Hide details') if self.detailed_view else _('Show details')

    def toggle_detailed_view(self):
        self.detailed_view = not self.detailed_view
        self.config.set_key('qt_detailed_view', self.detailed_view, True)

        self.details_button.setText(self.details_button_text())
        self.wallet.save()
        self.update_receive_tab()
        self.update_contacts_tab()


    def create_contacts_tab(self):
        l,w,hbox = self.create_list_tab([_('Address'), _('Label'), _('Tx')])
        l.setContextMenuPolicy(Qt.CustomContextMenu)
        l.customContextMenuRequested.connect(self.create_contact_menu)
        self.connect(l, SIGNAL('itemDoubleClicked(QTreeWidgetItem*, int)'), lambda a, b: self.address_label_clicked(a,b,l,0,1))
        self.connect(l, SIGNAL('itemChanged(QTreeWidgetItem*, int)'), lambda a,b: self.address_label_changed(a,b,l,0,1))
        self.contacts_list = l
        self.contacts_buttons_hbox = hbox
        hbox.addWidget(EnterButton(_("New"), self.new_contact_dialog))
        hbox.addStretch(1)
        return w


    def create_receive_menu(self, position):
        # fixme: this function apparently has a side effect.
        # if it is not called the menu pops up several times
        #self.receive_list.selectedIndexes() 

        item = self.receive_list.itemAt(position)
        if not item: return
        addr = unicode(item.text(1))
        menu = QMenu()
        menu.addAction(_("Copy to Clipboard"), lambda: self.app.clipboard().setText(addr))
        menu.addAction(_("View QR code"),lambda: self.show_address_qrcode(addr))
        menu.addAction(_("Edit label"), lambda: self.edit_label(True))

        t = _("Unfreeze") if addr in self.wallet.frozen_addresses else _("Freeze")
        menu.addAction(t, lambda: self.toggle_freeze(addr))
        t = _("Unprioritize") if addr in self.wallet.prioritized_addresses else _("Prioritize")
        menu.addAction(t, lambda: self.toggle_priority(addr))
        menu.exec_(self.receive_list.viewport().mapToGlobal(position))


    def payto(self, x, is_alias):
        if not x: return
        if is_alias:
            label = x
            m_addr = label
        else:
            addr = x
            label = self.wallet.labels.get(addr)
            m_addr = label + '  <' + addr + '>' if label else addr
        self.tabs.setCurrentIndex(1)
        self.payto_e.setText(m_addr)
        self.amount_e.setFocus()

    def delete_contact(self, x, is_alias):
        if self.question("Do you want to remove %s from your list of contacts?"%x):
            if not is_alias and x in self.wallet.addressbook:
                self.wallet.addressbook.remove(x)
                if x in self.wallet.labels.keys():
                    self.wallet.labels.pop(x)
            elif is_alias and x in self.wallet.aliases:
                self.wallet.aliases.pop(x)
            self.update_history_tab()
            self.update_contacts_tab()
            self.update_completions()

    def create_contact_menu(self, position):
        # fixme: this function apparently has a side effect.
        # if it is not called the menu pops up several times
        #self.contacts_list.selectedIndexes() 

        item = self.contacts_list.itemAt(position)
        if not item: return
        addr = unicode(item.text(0))
        label = unicode(item.text(1))
        is_alias = label in self.wallet.aliases.keys()
        x = label if is_alias else addr
        menu = QMenu()
        menu.addAction(_("Copy to Clipboard"), lambda: self.app.clipboard().setText(addr))
        menu.addAction(_("Pay to"), lambda: self.payto(x, is_alias))
        menu.addAction(_("View QR code"),lambda: self.show_address_qrcode(addr))
        if not is_alias:
            menu.addAction(_("Edit label"), lambda: self.edit_label(False))
        else:
            menu.addAction(_("View alias details"), lambda: self.show_contact_details(label))
        menu.addAction(_("Delete"), lambda: self.delete_contact(x,is_alias))
        menu.exec_(self.contacts_list.viewport().mapToGlobal(position))


    def update_receive_tab(self):
        l = self.receive_list
        l.clear()
        l.setColumnHidden(0,not self.detailed_view)
        l.setColumnHidden(3,not self.detailed_view)
        l.setColumnHidden(4,not self.detailed_view)
        l.setColumnWidth(0, 50) 
        l.setColumnWidth(1, 310) 
        l.setColumnWidth(2, 250)
        l.setColumnWidth(3, 130) 
        l.setColumnWidth(4, 10)

        gap = 0
        is_red = False
        for address in self.wallet.all_addresses():

            if self.wallet.is_change(address) and not self.detailed_view:
                continue

            label = self.wallet.labels.get(address,'')
            n = 0 
            h = self.wallet.history.get(address,[])
            for tx_hash, tx_height in h:
                tx = self.wallet.transactions.get(tx_hash)
                if tx: n += 1

            tx = "%d "%n
            if n==0:
                if address in self.wallet.addresses:
                    gap += 1
                    if gap > self.wallet.gap_limit:
                        is_red = True
            else:
                if address in self.wallet.addresses:
                    gap = 0

            c, u = self.wallet.get_addr_balance(address)
            balance = format_satoshis( c + u, False, self.wallet.num_zeros )
            flags = self.wallet.get_address_flags(address)
            item = QTreeWidgetItem( [ flags, address, label, balance, tx] )

            item.setFont(0, QFont(MONOSPACE_FONT))
            item.setFont(1, QFont(MONOSPACE_FONT))
            item.setFont(3, QFont(MONOSPACE_FONT))
            if address in self.wallet.frozen_addresses: 
                item.setBackgroundColor(1, QColor('lightblue'))
            elif address in self.wallet.prioritized_addresses: 
                item.setBackgroundColor(1, QColor('lightgreen'))
            if is_red and address in self.wallet.addresses:
                item.setBackgroundColor(1, QColor('red'))
            l.addTopLevelItem(item)

        # we use column 1 because column 0 may be hidden
        l.setCurrentItem(l.topLevelItem(0),1)

    def show_contact_details(self, m):
        a = self.wallet.aliases.get(m)
        if a:
            if a[0] in self.wallet.authorities.keys():
                s = self.wallet.authorities.get(a[0])
            else:
                s = "self-signed"
            msg = 'Alias: '+ m + '\nTarget address: '+ a[1] + '\n\nSigned by: ' + s + '\nSigning address:' + a[0]
            QMessageBox.information(self, 'Alias', msg, 'OK')

    def update_contacts_tab(self):

        l = self.contacts_list
        l.clear()
        l.setColumnHidden(2, not self.detailed_view)
        l.setColumnWidth(0, 350) 
        l.setColumnWidth(1, 330)
        l.setColumnWidth(2, 100) 

        alias_targets = []
        for alias, v in self.wallet.aliases.items():
            s, target = v
            alias_targets.append(target)
            item = QTreeWidgetItem( [ target, alias, '-'] )
            item.setBackgroundColor(0, QColor('lightgray'))
            l.addTopLevelItem(item)
            
        for address in self.wallet.addressbook:
            if address in alias_targets: continue
            label = self.wallet.labels.get(address,'')
            n = 0 
            for item in self.wallet.transactions.values():
                if address in item['outputs'] : n=n+1
            tx = "%d"%n
            item = QTreeWidgetItem( [ address, label, tx] )
            item.setFont(0, QFont(MONOSPACE_FONT))
            l.addTopLevelItem(item)

        l.setCurrentItem(l.topLevelItem(0))

    def create_wall_tab(self):
        self.textbox = textbox = QTextEdit(self)
        textbox.setFont(QFont(MONOSPACE_FONT))
        textbox.setReadOnly(True)
        return textbox

    def create_status_bar(self):
        sb = QStatusBar()
        sb.setFixedHeight(35)
        if self.wallet.seed:
            sb.addPermanentWidget( StatusBarButton( QIcon(":icons/lock.png"), "Password", lambda: self.change_password_dialog(self.wallet, self) ) )
        sb.addPermanentWidget( StatusBarButton( QIcon(":icons/preferences.png"), "Preferences", self.settings_dialog ) )
        if self.wallet.seed:
            sb.addPermanentWidget( StatusBarButton( QIcon(":icons/seed.png"), "Seed", lambda: self.show_seed_dialog(self.wallet, self) ) )
        self.status_button = StatusBarButton( QIcon(":icons/status_disconnected.png"), "Network", lambda: self.network_dialog(self.wallet, self) ) 
        sb.addPermanentWidget( self.status_button )
        self.setStatusBar(sb)

    def new_contact_dialog(self):
        text, ok = QInputDialog.getText(self, _('New Contact'), _('Address') + ':')
        address = unicode(text)
        if ok:
            if self.wallet.is_valid(address):
                self.wallet.addressbook.append(address)
                self.wallet.save()
                self.update_contacts_tab()
                self.update_history_tab()
                self.update_completions()
            else:
                QMessageBox.warning(self, _('Error'), _('Invalid Address'), _('OK'))

    @staticmethod
    def show_seed_dialog(wallet, parent=None):
        if not wallet.seed:
            QMessageBox.information(parent, _('Message'),
                                    _('No seed'), _('OK'))
            return

        if wallet.use_encryption:
            password = parent.password_dialog()
            if not password:
                return
        else:
            password = None
            
        try:
            seed = wallet.pw_decode(wallet.seed, password)
        except:
            QMessageBox.warning(parent, _('Error'),
                                _('Incorrect Password'), _('OK'))
            return

        dialog = QDialog(None)
        dialog.setModal(1)
        dialog.setWindowTitle("Electrum")

        brainwallet = ' '.join(mnemonic.mn_encode(seed))

        msg =   _("Your wallet generation seed is") +":<p>\"" + brainwallet + "\"<p>" \
              + _("Please write down or memorize these 12 words (order is important).") + " " \
              + _("This seed will allow you to recover your wallet in case of computer failure.") + "<p>" \
              + _("WARNING: Never disclose your seed. Never type it on a website.") + "<p>"

        main_text = QLabel(msg)
        main_text.setWordWrap(True)

        logo = QLabel()
        logo.setPixmap(QPixmap(":icons/seed.png").scaledToWidth(56))

        if parent:
            app = parent.app
        else:
            app = QApplication

        copy_function = lambda: app.clipboard().setText(brainwallet)
        copy_button = QPushButton(_("Copy to Clipboard"))
        copy_button.clicked.connect(copy_function)

        show_qr_function = lambda: ElectrumWindow.show_seed_qrcode(seed)
        qr_button = QPushButton(_("View as QR Code"))
        qr_button.clicked.connect(show_qr_function)

        ok_button = QPushButton(_("OK"))
        ok_button.setDefault(True)
        ok_button.clicked.connect(dialog.accept)

        main_layout = QGridLayout()
        main_layout.addWidget(logo, 0, 0)
        main_layout.addWidget(main_text, 0, 1, 1, -1)
        main_layout.addWidget(copy_button, 1, 1)
        main_layout.addWidget(qr_button, 1, 2)
        main_layout.addWidget(ok_button, 1, 3)
        dialog.setLayout(main_layout)

        dialog.exec_()

    @staticmethod
    def show_seed_qrcode(seed):
        if not seed: return
        d = QDialog(None)
        d.setModal(1)
        d.setWindowTitle(_("Seed"))
        d.setMinimumSize(270, 300)
        vbox = QVBoxLayout()
        vbox.addWidget(QRCodeWidget(seed))
        hbox = QHBoxLayout()
        hbox.addStretch(1)
        b = QPushButton(_("OK"))
        hbox.addWidget(b)
        b.clicked.connect(d.accept)

        vbox.addLayout(hbox)
        d.setLayout(vbox)
        d.exec_()


    def show_address_qrcode(self,address):
        if not address: return
        d = QDialog(self)
        d.setModal(1)
        d.setWindowTitle(address)
        d.setMinimumSize(270, 350)
        vbox = QVBoxLayout()
        qrw = QRCodeWidget(address)
        vbox.addWidget(qrw)

        hbox = QHBoxLayout()
        amount_e = QLineEdit()
        hbox.addWidget(QLabel(_('Amount')))
        hbox.addWidget(amount_e)
        vbox.addLayout(hbox)

        #hbox = QHBoxLayout()
        #label_e = QLineEdit()
        #hbox.addWidget(QLabel('Label'))
        #hbox.addWidget(label_e)
        #vbox.addLayout(hbox)

        def amount_changed():
            amount = numbify(amount_e)
            #label = str( label_e.getText() )
            if amount is not None:
                qrw.set_addr('bitcoin:%s?amount=%s'%(address,str( Decimal(amount) /100000000)))
            else:
                qrw.set_addr( address )
            qrw.repaint()

        def do_save():
            bmp.save_qrcode(qrw.qr, "qrcode.bmp")
            self.show_message(_("QR code saved to file") + " 'qrcode.bmp'")
            
        amount_e.textChanged.connect( amount_changed )

        hbox = QHBoxLayout()
        hbox.addStretch(1)
        b = QPushButton(_("Save"))
        b.clicked.connect(do_save)
        hbox.addWidget(b)
        b = QPushButton(_("Close"))
        hbox.addWidget(b)
        b.clicked.connect(d.accept)

        vbox.addLayout(hbox)
        d.setLayout(vbox)
        d.exec_()

    def question(self, msg):
        return QMessageBox.question(self, _('Message'), msg, QMessageBox.Yes | QMessageBox.No, QMessageBox.No) == QMessageBox.Yes

    def show_message(self, msg):
        QMessageBox.information(self, _('Message'), msg, _('OK'))

    def password_dialog(self ):
        d = QDialog(self)
        d.setModal(1)

        pw = QLineEdit()
        pw.setEchoMode(2)

        vbox = QVBoxLayout()
        msg = _('Please enter your password')
        vbox.addWidget(QLabel(msg))

        grid = QGridLayout()
        grid.setSpacing(8)
        grid.addWidget(QLabel(_('Password')), 1, 0)
        grid.addWidget(pw, 1, 1)
        vbox.addLayout(grid)

        vbox.addLayout(ok_cancel_buttons(d))
        d.setLayout(vbox) 

        if not d.exec_(): return
        return unicode(pw.text())





    @staticmethod
    def change_password_dialog( wallet, parent=None ):

        if not wallet.seed:
            QMessageBox.information(parent, _('Error'), _('No seed'), _('OK'))
            return

        d = QDialog(parent)
        d.setModal(1)

        pw = QLineEdit()
        pw.setEchoMode(2)
        new_pw = QLineEdit()
        new_pw.setEchoMode(2)
        conf_pw = QLineEdit()
        conf_pw.setEchoMode(2)

        vbox = QVBoxLayout()
        if parent:
            msg = (_('Your wallet is encrypted. Use this dialog to change your password.')+'\n'+_('To disable wallet encryption, enter an empty new password.')) if wallet.use_encryption else _('Your wallet keys are not encrypted')
        else:
            msg = _("Please choose a password to encrypt your wallet keys.")+'\n'+_("Leave these fields empty if you want to disable encryption.")
        vbox.addWidget(QLabel(msg))

        grid = QGridLayout()
        grid.setSpacing(8)

        if wallet.use_encryption:
            grid.addWidget(QLabel(_('Password')), 1, 0)
            grid.addWidget(pw, 1, 1)

        grid.addWidget(QLabel(_('New Password')), 2, 0)
        grid.addWidget(new_pw, 2, 1)

        grid.addWidget(QLabel(_('Confirm Password')), 3, 0)
        grid.addWidget(conf_pw, 3, 1)
        vbox.addLayout(grid)

        vbox.addLayout(ok_cancel_buttons(d))
        d.setLayout(vbox) 

        if not d.exec_(): return

        password = unicode(pw.text()) if wallet.use_encryption else None
        new_password = unicode(new_pw.text())
        new_password2 = unicode(conf_pw.text())

        try:
            seed = wallet.pw_decode( wallet.seed, password)
        except:
            QMessageBox.warning(parent, _('Error'), _('Incorrect Password'), _('OK'))
            return

        if new_password != new_password2:
            QMessageBox.warning(parent, _('Error'), _('Passwords do not match'), _('OK'))
            return

        wallet.update_password(seed, password, new_password)

    @staticmethod
    def seed_dialog(wallet, parent=None):
        d = QDialog(parent)
        d.setModal(1)

        vbox = QVBoxLayout()
        msg = _("Please enter your wallet seed or the corresponding mnemonic list of words, and the gap limit of your wallet.")
        vbox.addWidget(QLabel(msg))

        grid = QGridLayout()
        grid.setSpacing(8)

        seed_e = QLineEdit()
        grid.addWidget(QLabel(_('Seed or mnemonic')), 1, 0)
        grid.addWidget(seed_e, 1, 1)

        gap_e = QLineEdit()
        gap_e.setText("5")
        grid.addWidget(QLabel(_('Gap limit')), 2, 0)
        grid.addWidget(gap_e, 2, 1)
        gap_e.textChanged.connect(lambda: numbify(gap_e,True))
        vbox.addLayout(grid)

        vbox.addLayout(ok_cancel_buttons(d))
        d.setLayout(vbox) 

        if not d.exec_(): return

        try:
            gap = int(unicode(gap_e.text()))
        except:
            QMessageBox.warning(None, _('Error'), 'error', 'OK')
            sys.exit(0)

        try:
            seed = unicode(seed_e.text())
            seed.decode('hex')
        except:
            print_error("Warning: Not hex, trying decode")
            try:
                seed = mnemonic.mn_decode( seed.split(' ') )
            except:
                QMessageBox.warning(None, _('Error'), _('I cannot decode this'), _('OK'))
                sys.exit(0)
        if not seed:
            QMessageBox.warning(None, _('Error'), _('No seed'), 'OK')
            sys.exit(0)
        
        wallet.seed = str(seed)
        #print repr(wallet.seed)
        wallet.gap_limit = gap
        return True



    def settings_dialog(self):
        d = QDialog(self)
        d.setModal(1)
        vbox = QVBoxLayout()
        msg = _('Here are the settings of your wallet.') + '\n'\
              + _('For more explanations, click on the help buttons next to each field.')

        label = QLabel(msg)
        label.setFixedWidth(250)
        label.setWordWrap(True)
        label.setAlignment(Qt.AlignJustify)
        vbox.addWidget(label)

        grid = QGridLayout()
        grid.setSpacing(8)
        vbox.addLayout(grid)

        fee_label = QLabel(_('Transaction fee'))
        grid.addWidget(fee_label, 2, 0)
        fee_e = QLineEdit()
        fee_e.setText("%s"% str( Decimal( self.wallet.fee)/100000000 ) )
        grid.addWidget(fee_e, 2, 1)
        msg = _('Fee per transaction input. Transactions involving multiple inputs tend to require a higher fee.') + ' ' \
            + _('Recommended value') + ': 0.001'
        grid.addWidget(HelpButton(msg), 2, 2)
        fee_e.textChanged.connect(lambda: numbify(fee_e,False))
        if not self.config.is_modifiable('fee'):
            for w in [fee_e, fee_label]: w.setEnabled(False)

        nz_label = QLabel(_('Display zeros'))
        grid.addWidget(nz_label, 3, 0)
        nz_e = QLineEdit()
        nz_e.setText("%d"% self.wallet.num_zeros)
        grid.addWidget(nz_e, 3, 1)
        msg = _('Number of zeros displayed after the decimal point. For example, if this is set to 2, "1." will be displayed as "1.00"')
        grid.addWidget(HelpButton(msg), 3, 2)
        nz_e.textChanged.connect(lambda: numbify(nz_e,True))
        if not self.config.is_modifiable('num_zeros'):
            for w in [nz_e, nz_label]: w.setEnabled(False)

        usechange_cb = QCheckBox(_('Use change addresses'))
        grid.addWidget(usechange_cb, 5, 0)
        usechange_cb.setChecked(self.wallet.use_change)
        grid.addWidget(HelpButton(_('Using change addresses makes it more difficult for other people to track your transactions. ')), 5, 2)
        if not self.config.is_modifiable('use_change'): usechange_cb.setEnabled(False)

        gap_label = QLabel(_('Gap limit'))
        grid.addWidget(gap_label, 6, 0)
        gap_e = QLineEdit()
        gap_e.setText("%d"% self.wallet.gap_limit)
        grid.addWidget(gap_e, 6, 1)
        msg =  _('The gap limit is the maximal number of contiguous unused addresses in your sequence of receiving addresses.') + '\n' \
              + _('You may increase it if you need more receiving addresses.') + '\n\n' \
              + _('Your current gap limit is') + ': %d'%self.wallet.gap_limit + '\n' \
              + _('Given the current status of your address sequence, the minimum gap limit you can use is: ') + '%d'%self.wallet.min_acceptable_gap() + '\n\n' \
              + _('Warning') + ': ' \
              + _('The gap limit parameter must be provided in order to recover your wallet from seed.') + ' ' \
              + _('Do not modify it if you do not understand what you are doing, or if you expect to recover your wallet without knowing it!') + '\n\n' 
        grid.addWidget(HelpButton(msg), 6, 2)
        gap_e.textChanged.connect(lambda: numbify(nz_e,True))
        if not self.config.is_modifiable('gap_limit'):
            for w in [gap_e, gap_label]: w.setEnabled(False)
        
        gui_label=QLabel(_('Default GUI') + ':')
        grid.addWidget(gui_label , 7, 0)
        gui_combo = QComboBox()
        gui_combo.addItems(['Lite', 'Classic', 'Gtk', 'Text'])
        index = gui_combo.findText(self.config.get("gui","classic").capitalize())
        if index==-1: index = 1
        gui_combo.setCurrentIndex(index)
        grid.addWidget(gui_combo, 7, 1)
        grid.addWidget(HelpButton(_('Select which GUI mode to use at start up. ')), 7, 2)
        if not self.config.is_modifiable('gui'):
            for w in [gui_combo, gui_label]: w.setEnabled(False)

        vbox.addLayout(ok_cancel_buttons(d))
        d.setLayout(vbox) 

        # run the dialog
        if not d.exec_(): return

        fee = unicode(fee_e.text())
        try:
            fee = int( 100000000 * Decimal(fee) )
        except:
            QMessageBox.warning(self, _('Error'), _('Invalid value') +': %s'%fee, _('OK'))
            return

        if self.wallet.fee != fee:
            self.wallet.fee = fee
            self.wallet.save()
        
        nz = unicode(nz_e.text())
        try:
            nz = int( nz )
            if nz>8: nz=8
        except:
            QMessageBox.warning(self, _('Error'), _('Invalid value')+':%s'%nz, _('OK'))
            return

        if self.wallet.num_zeros != nz:
            self.wallet.num_zeros = nz
            self.config.set_key('num_zeros', nz, True)
            self.update_history_tab()
            self.update_receive_tab()

        if self.wallet.use_change != usechange_cb.isChecked():
            self.wallet.use_change = usechange_cb.isChecked()
            self.config.set_key('use_change', self.wallet.use_change, True)
        
        try:
            n = int(gap_e.text())
        except:
            QMessageBox.warning(self, _('Error'), _('Invalid value'), _('OK'))
            return

        if self.wallet.gap_limit != n:
            r = self.wallet.change_gap_limit(n)
            if r:
                self.update_receive_tab()
                self.config.set_key('gap_limit', self.wallet.gap_limit, True)
            else:
                QMessageBox.warning(self, _('Error'), _('Invalid value'), _('OK'))
                    
        self.config.set_key("gui", str(gui_combo.currentText()).lower(), True)



    @staticmethod 
    def network_dialog(wallet, parent=None):
        interface = wallet.interface
        if parent:
            if interface.is_connected:
                status = _("Connected to")+" %s\n%d blocks"%(interface.host, wallet.verifier.height)
            else:
                status = _("Not connected")
        else:
            import random
            status = _("Please choose a server.")

        server = interface.server

        plist = {}
        if not wallet.interface.servers:
            servers_list = []
            for x in DEFAULT_SERVERS:
                h,port,protocol = x.split(':')
                servers_list.append( (h,[(protocol,port)] ) )
        else:
            servers_list = wallet.interface.servers
            for item in servers_list:
                _host, pp = item
                z = {}
                for item2 in pp:
                    _protocol, _port = item2
                    z[_protocol] = _port
                plist[_host] = z

        d = QDialog(parent)
        d.setModal(1)
        d.setWindowTitle(_('Server'))
        d.setMinimumSize(375, 20)

        vbox = QVBoxLayout()
        vbox.setSpacing(30)

        hbox = QHBoxLayout()
        l = QLabel()
        l.setPixmap(QPixmap(":icons/network.png"))
        hbox.addStretch(10)
        hbox.addWidget(l)
        hbox.addWidget(QLabel(status))
        hbox.addStretch(50)
        vbox.addLayout(hbox)


        # grid layout
        grid = QGridLayout()
        grid.setSpacing(8)
        vbox.addLayout(grid)

        # server
        server_protocol = QComboBox()
        server_host = QLineEdit()
        server_host.setFixedWidth(200)
        server_port = QLineEdit()
        server_port.setFixedWidth(60)

        protocol_names = ['TCP', 'HTTP', 'TCP/SSL', 'HTTPS']
        protocol_letters = 'thsg'
        DEFAULT_PORTS = {'t':'50001', 's':'50002', 'h':'8081', 'g':'8082'}
        server_protocol.addItems(protocol_names)

        grid.addWidget(QLabel(_('Server') + ':'), 0, 0)
        grid.addWidget(server_protocol, 0, 1)
        grid.addWidget(server_host, 0, 2)
        grid.addWidget(server_port, 0, 3)

        host, port, protocol = server.split(':')

        def change_protocol(p):
            protocol = protocol_letters[p]
            host = unicode(server_host.text())
            pp = plist.get(host,DEFAULT_PORTS)
            if protocol not in pp.keys():
                protocol = pp.keys()[0]
            port = pp[protocol]
            server_host.setText( host )
            server_port.setText( port )

        server_protocol.connect(server_protocol, SIGNAL('currentIndexChanged(int)'), change_protocol)
        
        label = _('Active Servers') if wallet.interface.servers else _('Default Servers')
        servers_list_widget = QTreeWidget(parent)
        servers_list_widget.setHeaderLabels( [ label ] )
        servers_list_widget.setMaximumHeight(150)
        for _host, _x in servers_list:
            servers_list_widget.addTopLevelItem(QTreeWidgetItem( [ _host ] ))


        def change_server(host, protocol=None):
            pp = plist.get(host,DEFAULT_PORTS)
            if protocol:
                port = pp.get(protocol)
                if not port: protocol = None
                    
            if not protocol:
                if 't' in pp.keys():
                    protocol = 't'
                    port = pp.get(protocol)
                else:
                    protocol = pp.keys()[0]
                    port = pp.get(protocol)
            
            server_host.setText( host )
            server_port.setText( port )
            server_protocol.setCurrentIndex(protocol_letters.index(protocol))

            if not plist: return
            for p in protocol_letters:
                i = protocol_letters.index(p)
                j = server_protocol.model().index(i,0)
                if p not in pp.keys():
                    server_protocol.model().setData(j, QtCore.QVariant(0), QtCore.Qt.UserRole-1)
                else:
                    server_protocol.model().setData(j, QtCore.QVariant(0,False), QtCore.Qt.UserRole-1)


        change_server(host,protocol)
        servers_list_widget.connect(servers_list_widget, SIGNAL('itemClicked(QTreeWidgetItem*, int)'), lambda x: change_server(unicode(x.text(0))))
        grid.addWidget(servers_list_widget, 1, 1, 1, 3)

        if not wallet.config.is_modifiable('server'):
            for w in [server_host, server_port, server_protocol, servers_list_widget]: w.setEnabled(False)

        # proxy setting
        proxy_mode = QComboBox()
        proxy_host = QLineEdit()
        proxy_host.setFixedWidth(200)
        proxy_port = QLineEdit()
        proxy_port.setFixedWidth(60)
        proxy_mode.addItems(['NONE', 'SOCKS4', 'SOCKS5', 'HTTP'])

        def check_for_disable(index = False):
            if proxy_mode.currentText() != 'NONE':
                proxy_host.setEnabled(True)
                proxy_port.setEnabled(True)
            else:
                proxy_host.setEnabled(False)
                proxy_port.setEnabled(False)

        check_for_disable()
        proxy_mode.connect(proxy_mode, SIGNAL('currentIndexChanged(int)'), check_for_disable)

        if not wallet.config.is_modifiable('proxy'):
            for w in [proxy_host, proxy_port, proxy_mode]: w.setEnabled(False)

        proxy_config = interface.proxy if interface.proxy else { "mode":"none", "host":"localhost", "port":"8080"}
        proxy_mode.setCurrentIndex(proxy_mode.findText(str(proxy_config.get("mode").upper())))
        proxy_host.setText(proxy_config.get("host"))
        proxy_port.setText(proxy_config.get("port"))

        grid.addWidget(QLabel(_('Proxy') + ':'), 2, 0)
        grid.addWidget(proxy_mode, 2, 1)
        grid.addWidget(proxy_host, 2, 2)
        grid.addWidget(proxy_port, 2, 3)

        # buttons
        vbox.addLayout(ok_cancel_buttons(d))
        d.setLayout(vbox) 

        if not d.exec_(): return

        server = unicode( server_host.text() ) + ':' + unicode( server_port.text() ) + ':' + (protocol_letters[server_protocol.currentIndex()])
        if proxy_mode.currentText() != 'NONE':
            proxy = { u'mode':unicode(proxy_mode.currentText()).lower(), u'host':unicode(proxy_host.text()), u'port':unicode(proxy_port.text()) }
        else:
            proxy = None

        wallet.config.set_key("proxy", proxy, True)
        wallet.config.set_key("server", server, True)
        interface.set_server(server, proxy)
                
        return True

    def closeEvent(self, event):
        g = self.geometry()
        self.config.set_key("winpos-qt", [g.left(),g.top(),g.width(),g.height()], True)
        event.accept()


class ElectrumGui:

    def __init__(self, wallet, config, app=None):
        self.wallet = wallet
        self.config = config
        if app is None:
            self.app = QApplication(sys.argv)

    def server_list_changed(self):
        pass


    def restore_or_create(self):

        msg = _("Wallet file not found.")+"\n"+_("Do you want to create a new wallet, or to restore an existing one?")
        r = QMessageBox.question(None, _('Message'), msg, _('Create'), _('Restore'), _('Cancel'), 0, 2)
        if r==2: return False
        
        is_recovery = (r==1)
        wallet = self.wallet
        # ask for the server.
        if not ElectrumWindow.network_dialog( wallet, parent=None ): return False

        # wait until we are connected, because the user might have selected another server
        if not wallet.interface.is_connected:
            waiting = lambda: False if wallet.interface.is_connected else "connecting...\n"
            waiting_dialog(waiting)

        waiting = lambda: False if wallet.up_to_date else "Please wait...\nAddresses generated: %d\nKilobytes received: %.1f"\
            %(len(wallet.all_addresses()), wallet.interface.bytes_received/1024.)

        if not is_recovery:
            wallet.new_seed(None)
            wallet.init_mpk( wallet.seed )
            wallet.up_to_date_event.clear()
            wallet.up_to_date = False
            wallet.interface.poke('synchronizer')
            waiting_dialog(waiting)
            # run a dialog indicating the seed, ask the user to remember it
            ElectrumWindow.show_seed_dialog(wallet)
            #ask for password
            ElectrumWindow.change_password_dialog(wallet)
        else:
            # ask for seed and gap.
            if not ElectrumWindow.seed_dialog( wallet ): return False
            wallet.init_mpk( wallet.seed )
            wallet.up_to_date_event.clear()
            wallet.up_to_date = False
            wallet.interface.poke('synchronizer')
            waiting_dialog(waiting)
            if wallet.is_found():
                # history and addressbook
                wallet.fill_addressbook()
                print "Recovery successful"
                wallet.save()
            else:
                QMessageBox.information(None, _('Error'), _("No transactions found for this seed"), _('OK'))

        wallet.save()
        return True

    def main(self,url):
        s = Timer()
        s.start()
        w = ElectrumWindow(self.wallet, self.config)
        if url: w.set_url(url)
        w.app = self.app
        w.connect_slots(s)
        w.update_wallet()
        w.show()

        self.app.exec_()
