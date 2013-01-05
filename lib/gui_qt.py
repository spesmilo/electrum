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
import os.path, json, util

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
import exchange_rate

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

    def __init__(self, data = None):
        QWidget.__init__(self)
        self.setMinimumSize(210, 210)
        self.addr = None
        self.qr = None
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
            self.qr = pyqrnative.QRCode(4, pyqrnative.QRErrorCorrectLevel.L)
            self.qr.addData(self.addr)
            self.qr.make()
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
        


class QR_Window(QWidget):

    def __init__(self):
        QWidget.__init__(self)
        self.setWindowTitle('Electrum - Invoice')
        self.setMinimumSize(800, 250)
        self.address = ''
        self.labe = ''
        self.amount = 0
        self.setFocusPolicy(QtCore.Qt.NoFocus)

        main_box = QHBoxLayout()
        
        self.qrw = QRCodeWidget()
        main_box.addWidget(self.qrw, 1)

        vbox = QVBoxLayout()
        main_box.addLayout(vbox)

        self.address_label = QLabel("")
        self.address_label.setFont(QFont(MONOSPACE_FONT))
        vbox.addWidget(self.address_label)

        self.label_label = QLabel("")
        vbox.addWidget(self.label_label)

        self.amount_label = QLabel("")
        vbox.addWidget(self.amount_label)

        vbox.addStretch(1)
        self.setLayout(main_box)


    def set_content(self, addr, label, amount):
        self.address = addr
        address_text = "<span style='font-size: 18pt'>%s</span>" % addr if addr else ""
        self.address_label.setText(address_text)

        self.amount = amount
        amount_text = "<span style='font-size: 21pt'>%s</span> <span style='font-size: 16pt'>BTC</span> " % format_satoshis(amount) if amount else ""
        self.amount_label.setText(amount_text)

        self.label = label
        label_text = "<span style='font-size: 21pt'>%s</span>" % label if label else ""
        self.label_label.setText(label_text)

        msg = 'bitcoin:'+self.address
        if self.amount is not None:
            msg += '?amount=%s'%(str( Decimal(self.amount) /100000000))
            if self.label is not None:
                msg += '&label=%s'%(self.label)
        elif self.label is not None:
            msg += '?label=%s'%(self.label)
            
        self.qrw.set_addr( msg )

            


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

        self.receive_tab_mode = config.get('qt_receive_tab_mode', 0)
        self.merchant_name = config.get('merchant_name', 'Invoice')

        self.qr_window = None
        self.funds_error = False
        self.completions = QStringListModel()

        self.tabs = tabs = QTabWidget(self)
        tabs.addTab(self.create_history_tab(), _('History') )
        tabs.addTab(self.create_send_tab(), _('Send') )
        tabs.addTab(self.create_receive_tab(), _('Receive') )
        tabs.addTab(self.create_contacts_tab(), _('Contacts') )
        tabs.addTab(self.create_wall_tab(), _('Wall') )
        tabs.setMinimumSize(600, 400)
        tabs.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.setCentralWidget(tabs)
        self.create_status_bar()
        self.toggle_QR_window(self.receive_tab_mode == 2)

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
        #self.connect(self, SIGNAL('editamount'), self.edit_amount)
        self.history_list.setFocus(True)
        
        self.exchanger = exchange_rate.Exchanger(self)
        self.connect(self, SIGNAL("refresh_balance()"), self.update_wallet)

        # dark magic fix by flatfly; https://bitcointalk.org/index.php?topic=73651.msg959913#msg959913
        if platform.system() == 'Windows':
            n = 3 if self.wallet.seed else 2
            tabs.setCurrentIndex (n)
            tabs.setCurrentIndex (0)

    def close(self):
        QMainWindow.close(self)
        if self.qr_window: 
            self.qr_window.close()
            self.qr_window = None

    def connect_slots(self, sender):
        self.connect(sender, QtCore.SIGNAL('timersignal'), self.timer_actions)
        self.previous_payto_e=''

    def timer_actions(self):
        if self.qr_window:
            self.qr_window.qrw.update_qr()
            
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
                text += self.create_quote_text(Decimal(c+u)/100000000)
                icon = QIcon(":icons/status_connected.png")
        else:
            text = _( "Not connected" )
            icon = QIcon(":icons/status_disconnected.png")

        if self.funds_error:
            text = _( "Not enough funds" )

        self.statusBar().showMessage(text)
        self.status_button.setIcon( icon )

        if self.wallet.up_to_date or not self.wallet.interface.is_connected:
            self.textbox.setText( self.wallet.banner )
            self.update_history_tab()
            self.update_receive_tab()
            self.update_contacts_tab()
            self.update_completions()

    def create_quote_text(self, btc_balance):
        quote_currency = self.config.get("currency", "None")
        quote_balance = self.exchanger.exchange(btc_balance, quote_currency)
        if quote_balance is None:
            quote_text = ""
        else:
            quote_text = "  (%.2f %s)" % (quote_balance, quote_currency)
        return quote_text
        
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
        tx_hash = str(item.data(0, Qt.UserRole).toString())
        if not tx_hash: return
        menu = QMenu()
        menu.addAction(_("Copy ID to Clipboard"), lambda: self.app.clipboard().setText(tx_hash))
        menu.addAction(_("Details"), lambda: self.tx_details(tx_hash))
        menu.addAction(_("Edit description"), lambda: self.tx_label_clicked(item,2))
        menu.exec_(self.contacts_list.viewport().mapToGlobal(position))


    def tx_details(self, tx_hash):
        tx_details = self.wallet.get_tx_details(tx_hash)
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
            text = self.wallet.get_default_label(tx_hash)
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

    def edit_amount(self):
        l = self.receive_list
        item = l.currentItem()
        item.setFlags(Qt.ItemIsEditable|Qt.ItemIsSelectable | Qt.ItemIsUserCheckable | Qt.ItemIsEnabled | Qt.ItemIsDragEnabled)
        l.editItem( item, 3 )
        item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsUserCheckable | Qt.ItemIsEnabled | Qt.ItemIsDragEnabled)


    def address_label_clicked(self, item, column, l, column_addr, column_label):
        if column == column_label and item.isSelected():
            addr = unicode( item.text(column_addr) )
            label = unicode( item.text(column_label) )
            if label in self.wallet.aliases.keys():
                return
            item.setFlags(Qt.ItemIsEditable|Qt.ItemIsSelectable | Qt.ItemIsUserCheckable | Qt.ItemIsEnabled | Qt.ItemIsDragEnabled)
            l.editItem( item, column )
            item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsUserCheckable | Qt.ItemIsEnabled | Qt.ItemIsDragEnabled)


    def address_label_changed(self, item, column, l, column_addr, column_label):

        if column == column_label:
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
                self.update_history_tab()
                self.update_completions()
                
            self.recv_changed(item)

        if column == 3:
            address = unicode( item.text(column_addr) )
            text = unicode( item.text(3) )
            try:
                index = self.wallet.addresses.index(address)
            except:
                return

            try:
                amount = int( Decimal(text) * 100000000 )
                item.setText(3,format_satoshis(amount,False, self.wallet.num_zeros))
            except:
                amount = self.wallet.requested_amounts.get(address)
                if amount: 
                    item.setText(3,format_satoshis(amount,False, self.wallet.num_zeros))
                else:
                    item.setText(3,"")
                return

            self.wallet.requested_amounts[address] = amount

            label = self.wallet.labels.get(address)
            if label is None:
                label = self.merchant_name + ' - %04d'%(index+1)
                self.wallet.labels[address] = label

            self.update_receive_item(self.receive_list.currentItem())
            if self.qr_window:
                self.qr_window.set_content( address, label, amount )


    def recv_changed(self, a):
        "current item changed"
        if a is not None and self.qr_window and self.qr_window.isVisible():
            address = str(a.text(1))
            label = self.wallet.labels.get(address)
            amount = self.wallet.requested_amounts.get(address)
            self.qr_window.set_content( address, label, amount )


    def update_history_tab(self):

        self.history_list.clear()
        for item in self.wallet.get_tx_history():
            tx_hash, conf, is_mine, value, fee, balance, timestamp = item
            if conf:
                try:
                    time_str = datetime.datetime.fromtimestamp( timestamp).isoformat(' ')[:-3]
                except:
                    time_str = "unknown"
                if conf == -1:
                    icon = None
                if conf == 0:
                    icon = QIcon(":icons/unconfirmed.png")
                elif conf < 6:
                    icon = QIcon(":icons/clock%d.png"%conf)
                else:
                    icon = QIcon(":icons/confirmed.png")
            else:
                time_str = 'pending'
                icon = QIcon(":icons/unconfirmed.png")

            if value is not None:
                v_str = format_satoshis(value, True, self.wallet.num_zeros)
            else:
                v_str = '--'

            balance_str = format_satoshis(balance, False, self.wallet.num_zeros)
            
            if tx_hash:
                label, is_default_label = self.wallet.get_label(tx_hash)
            else:
                label = _('Pruned transaction outputs')
                is_default_label = False

            item = QTreeWidgetItem( [ '', time_str, label, v_str, balance_str] )
            item.setFont(2, QFont(MONOSPACE_FONT))
            item.setFont(3, QFont(MONOSPACE_FONT))
            item.setFont(4, QFont(MONOSPACE_FONT))
            if value < 0:
                item.setForeground(3, QBrush(QColor("#BC1E1E")))
            if tx_hash:
                item.setData(0, Qt.UserRole, tx_hash)
                item.setToolTip(0, "%d %s\nTxId:%s" % (conf, _('Confirmations'), tx_hash) )
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
            self.update_wallet()

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
            tx = self.wallet.mktx( [(to_address, amount)], label, password, fee)
        except BaseException, e:
            self.show_message(str(e))
            return

        if self.wallet.seed:
            h = self.wallet.send_tx(tx)
            waiting_dialog(lambda: False if self.wallet.tx_event.isSet() else _("Please wait..."))
            status, msg = self.wallet.receive_tx( h )
            if status:
                QMessageBox.information(self, '', _('Payment sent.')+'\n'+msg, _('OK'))
                self.do_clear()
                self.update_contacts_tab()
            else:
                QMessageBox.warning(self, _('Error'), msg, _('OK'))
        else:
            filename = 'unsigned_tx'
            f = open(filename,'w')
            f.write(tx)
            f.close()
            QMessageBox.information(self, _('Unsigned transaction'), _("Unsigned transaction was saved to file:") + " " +filename, _('OK'))


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
        l,w,hbox = self.create_list_tab([_('Flags'), _('Address'), _('Label'), _('Requested'), _('Balance'), _('Tx')])
        l.setContextMenuPolicy(Qt.CustomContextMenu)
        l.customContextMenuRequested.connect(self.create_receive_menu)
        self.connect(l, SIGNAL('itemDoubleClicked(QTreeWidgetItem*, int)'), lambda a, b: self.address_label_clicked(a,b,l,1,2))
        self.connect(l, SIGNAL('itemChanged(QTreeWidgetItem*, int)'), lambda a,b: self.address_label_changed(a,b,l,1,2))
        self.connect(l, SIGNAL('currentItemChanged(QTreeWidgetItem*, QTreeWidgetItem*)'), lambda a,b: self.recv_changed(a))
        self.receive_list = l
        self.receive_buttons_hbox = hbox
        hbox.addStretch(1)
        return w



    def receive_tab_set_mode(self, i):
        self.receive_tab_mode = i
        self.config.set_key('qt_receive_tab_mode', self.receive_tab_mode, True)
        self.wallet.save()
        self.update_receive_tab()
        self.toggle_QR_window(self.receive_tab_mode == 2)


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


    def delete_imported_key(self, addr):
        if self.question("Do you want to remove %s from your wallet?"%addr):
            self.wallet.imported_keys.pop(addr)
            self.update_receive_tab()
            self.update_history_tab()
            self.wallet.save()


    def create_receive_menu(self, position):
        # fixme: this function apparently has a side effect.
        # if it is not called the menu pops up several times
        #self.receive_list.selectedIndexes() 

        item = self.receive_list.itemAt(position)
        if not item: return
        addr = unicode(item.text(1))
        menu = QMenu()
        menu.addAction(_("Copy to clipboard"), lambda: self.app.clipboard().setText(addr))
        if self.receive_tab_mode == 2:
            menu.addAction(_("Request amount"), lambda: self.edit_amount())
        menu.addAction(_("View QR"), lambda: ElectrumWindow.show_qrcode("Address","bitcoin:"+addr) )
        menu.addAction(_("Edit label"), lambda: self.edit_label(True))
        menu.addAction(_("Sign message"), lambda: self.sign_message(addr))
        if addr in self.wallet.imported_keys:
            menu.addAction(_("Remove from wallet"), lambda: self.delete_imported_key(addr))

        if self.receive_tab_mode == 1:
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
        menu.addAction(_("View QR code"),lambda: self.show_qrcode("Address","bitcoin:"+addr))
        if not is_alias:
            menu.addAction(_("Edit label"), lambda: self.edit_label(False))
        else:
            menu.addAction(_("View alias details"), lambda: self.show_contact_details(label))
        menu.addAction(_("Delete"), lambda: self.delete_contact(x,is_alias))
        menu.exec_(self.contacts_list.viewport().mapToGlobal(position))


    def update_receive_item(self, item):
        address = str( item.data(1,0).toString() )

        flags = self.wallet.get_address_flags(address)
        item.setData(0,0,flags)

        label = self.wallet.labels.get(address,'')
        item.setData(2,0,label)

        amount = self.wallet.requested_amounts.get(address,None)
        amount_str = format_satoshis( amount, False, self.wallet.num_zeros ) if amount is not None  else ""
        item.setData(3,0,amount_str)
        
        c, u = self.wallet.get_addr_balance(address)
        balance = format_satoshis( c + u, False, self.wallet.num_zeros )
        item.setData(4,0,balance)

        if self.receive_tab_mode == 1:
            if address in self.wallet.frozen_addresses: 
                item.setBackgroundColor(1, QColor('lightblue'))
            elif address in self.wallet.prioritized_addresses: 
                item.setBackgroundColor(1, QColor('lightgreen'))
        

    def update_receive_tab(self):
        l = self.receive_list
        
        l.clear()
        l.setColumnHidden(0, not self.receive_tab_mode == 1)
        l.setColumnHidden(3, not self.receive_tab_mode == 2)
        l.setColumnHidden(4, self.receive_tab_mode == 0)
        l.setColumnHidden(5, not self.receive_tab_mode == 1)
        l.setColumnWidth(0, 50)
        l.setColumnWidth(1, 310) 
        l.setColumnWidth(2, 200)
        l.setColumnWidth(3, 130)
        l.setColumnWidth(4, 130)
        l.setColumnWidth(5, 10)

        gap = 0
        is_red = False
        for address in self.wallet.all_addresses():

            if self.wallet.is_change(address) and self.receive_tab_mode != 1:
                continue

            n = 0 
            h = self.wallet.history.get(address,[])

            if h != ['*']: 
                for tx_hash, tx_height in h:
                    tx = self.wallet.transactions.get(tx_hash)
                    if tx: n += 1
                num_tx = "%d "%n
            else:
                n = -1
                num_tx = "*"

            if n==0:
                if address in self.wallet.addresses:
                    gap += 1
                    if gap > self.wallet.gap_limit:
                        is_red = True
            else:
                if address in self.wallet.addresses:
                    gap = 0

            item = QTreeWidgetItem( [ '', address, '', '', '', num_tx] )
            item.setFont(0, QFont(MONOSPACE_FONT))
            item.setFont(1, QFont(MONOSPACE_FONT))
            item.setFont(3, QFont(MONOSPACE_FONT))
            self.update_receive_item(item)
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

        show_qr_function = lambda: ElectrumWindow.show_qrcode(_("Seed"), seed)
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
    def show_qrcode(title, data):
        if not data: return
        d = QDialog(None)
        d.setModal(1)
        d.setWindowTitle(title)
        d.setMinimumSize(270, 300)
        vbox = QVBoxLayout()
        qrw = QRCodeWidget(data)
        vbox.addWidget(qrw, 1)
        vbox.addWidget(QLabel(data), 0, Qt.AlignHCenter)
        hbox = QHBoxLayout()
        hbox.addStretch(1)

        def print_qr(self):
            filename = "qrcode.bmp"
            bmp.save_qrcode(qrw.qr, filename)
            QMessageBox.information(None, _('Message'), _("QR code saved to file") + " " + filename, _('OK'))

        b = QPushButton(_("Print"))
        hbox.addWidget(b)
        b.clicked.connect(print_qr)

        b = QPushButton(_("Close"))
        hbox.addWidget(b)
        b.clicked.connect(d.accept)

        vbox.addLayout(hbox)
        d.setLayout(vbox)
        d.exec_()

    def sign_message(self,address):
        if not address: return
        d = QDialog(self)
        d.setModal(1)
        d.setWindowTitle('Sign Message')
        d.setMinimumSize(410, 290)

        tab_widget = QTabWidget()
        tab = QWidget()
        layout = QGridLayout(tab)

        sign_address = QLineEdit()

        sign_address.setText(address)
        layout.addWidget(QLabel(_('Address')), 1, 0)
        layout.addWidget(sign_address, 1, 1)

        sign_message = QTextEdit()
        layout.addWidget(QLabel(_('Message')), 2, 0)
        layout.addWidget(sign_message, 2, 1)
        layout.setRowStretch(2,3)

        sign_signature = QTextEdit()
        layout.addWidget(QLabel(_('Signature')), 3, 0)
        layout.addWidget(sign_signature, 3, 1)
        layout.setRowStretch(3,1)

        def do_sign():
            if self.wallet.use_encryption:
                password = self.password_dialog()
                if not password:
                    return
            else:
                password = None

            try:
                signature = self.wallet.sign_message(str(sign_address.text()), str(sign_message.toPlainText()), password)
                sign_signature.setText(signature)
            except BaseException, e:
                self.show_message(str(e))
                return

        hbox = QHBoxLayout()
        b = QPushButton(_("Sign"))
        hbox.addWidget(b)
        b.clicked.connect(do_sign)
        b = QPushButton(_("Close"))
        b.clicked.connect(d.accept)
        hbox.addWidget(b)
        layout.addLayout(hbox, 4, 1)
        tab_widget.addTab(tab, "Sign")


        tab = QWidget()
        layout = QGridLayout(tab)

        verify_address = QLineEdit()
        layout.addWidget(QLabel(_('Address')), 1, 0)
        layout.addWidget(verify_address, 1, 1)

        verify_message = QTextEdit()
        layout.addWidget(QLabel(_('Message')), 2, 0)
        layout.addWidget(verify_message, 2, 1)
        layout.setRowStretch(2,3)

        verify_signature = QTextEdit()
        layout.addWidget(QLabel(_('Signature')), 3, 0)
        layout.addWidget(verify_signature, 3, 1)
        layout.setRowStretch(3,1)

        def do_verify():
            try:
                self.wallet.verify_message(verify_address.text(), str(verify_signature.toPlainText()), str(verify_message.toPlainText()))
                self.show_message("Signature verified")
            except BaseException, e:
                self.show_message(str(e))
                return

        hbox = QHBoxLayout()
        b = QPushButton(_("Verify"))
        b.clicked.connect(do_verify)
        hbox.addWidget(b)
        b = QPushButton(_("Close"))
        b.clicked.connect(d.accept)
        hbox.addWidget(b)
        layout.addLayout(hbox, 4, 1)
        tab_widget.addTab(tab, "Verify")

        vbox = QVBoxLayout()
        vbox.addWidget(tab_widget)
        d.setLayout(vbox)
        d.exec_()

        
    def toggle_QR_window(self, show):
        if show and not self.qr_window:
            self.qr_window = QR_Window()
            self.qr_window.setVisible(True)
            self.qr_window_geometry = self.qr_window.geometry()
            item = self.receive_list.currentItem()
            if item:
                address = str(item.text(1))
                label = self.wallet.labels.get(address)
                amount = self.wallet.requested_amounts.get(address)
                self.qr_window.set_content( address, label, amount )

        elif show and self.qr_window and not self.qr_window.isVisible():
            self.qr_window.setVisible(True)
            self.qr_window.setGeometry(self.qr_window_geometry)

        elif not show and self.qr_window and self.qr_window.isVisible():
            self.qr_window_geometry = self.qr_window.geometry()
            self.qr_window.setVisible(False)

        #self.print_button.setHidden(self.qr_window is None or not self.qr_window.isVisible())
        self.receive_list.setColumnHidden(3, self.qr_window is None or not self.qr_window.isVisible())
        self.receive_list.setColumnWidth(2, 200)


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
            msg = (_('Your wallet is encrypted. Use this dialog to change your password.')+'\n'\
                   +_('To disable wallet encryption, enter an empty new password.')) \
                   if wallet.use_encryption else _('Your wallet keys are not encrypted')
        else:
            msg = _("Please choose a password to encrypt your wallet keys.")+'\n'\
                  +_("Leave these fields empty if you want to disable encryption.")
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
            return ElectrumWindow.change_password_dialog(wallet, parent) # Retry

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


    def do_import_labels(self):
        labelsFile = QFileDialog.getOpenFileName(QWidget(), "Open text file", util.user_dir(), self.tr("Text Files (labels.dat)"))
        if not labelsFile: return
        try:
            f = open(labelsFile, 'r')
            data = f.read()
            f.close()
            self.wallet.labels = json.loads(data)
            self.wallet.save()
            QMessageBox.information(None, "Labels imported", "Your labels where imported from '%s'" % str(labelsFile))
        except (IOError, os.error), reason:
            QMessageBox.critical(None, "Unable to export labels", "Electrum was unable to export your labels.\n" + str(reason))


    def do_export_labels(self):
        labels = self.wallet.labels
        try:
            labelsFile = util.user_dir() + '/labels.dat'
            f = open(labelsFile, 'w+')
            json.dump(labels, f)
            f.close()
            QMessageBox.information(None, "Labels exported", "Your labels where exported to '%s'" % str(labelsFile))
        except (IOError, os.error), reason:
            QMessageBox.critical(None, "Unable to export labels", "Electrum was unable to export your labels.\n" + str(reason))

    def do_export_history(self):
        from gui_lite import csv_transaction
        csv_transaction(self.wallet)

    def do_import_privkey(self):
        text, ok = QInputDialog.getText(self, _('Import private key'), _('Key') + ':')
        if not ok: return
        sec = str(text)
        if self.wallet.use_encryption:
            password = self.password_dialog()
            if not password:
                return
        else:
            password = None
        try:
            addr = self.wallet.import_key(sec, password)
            if not addr:
                QMessageBox.critical(None, "Unable to import key", "error")
            else:
                QMessageBox.information(None, "Key imported", addr)
                self.update_receive_tab()
                self.update_history_tab()
        except BaseException as e:
            QMessageBox.critical(None, "Unable to import key", str(e))

    def settings_dialog(self):
        d = QDialog(self)
        d.setWindowTitle(_('Electrum Settings'))
        d.setModal(1)
        vbox = QVBoxLayout()

        tabs = QTabWidget(self)
        vbox.addWidget(tabs)

        tab1 = QWidget()
        grid_ui = QGridLayout(tab1)
        grid_ui.setColumnStretch(0,1)
        tabs.addTab(tab1, _('Display') )

        nz_label = QLabel(_('Display zeros'))
        grid_ui.addWidget(nz_label, 3, 0)
        nz_e = QLineEdit()
        nz_e.setText("%d"% self.wallet.num_zeros)
        grid_ui.addWidget(nz_e, 3, 1)
        msg = _('Number of zeros displayed after the decimal point. For example, if this is set to 2, "1." will be displayed as "1.00"')
        grid_ui.addWidget(HelpButton(msg), 3, 2)
        nz_e.textChanged.connect(lambda: numbify(nz_e,True))
        if not self.config.is_modifiable('num_zeros'):
            for w in [nz_e, nz_label]: w.setEnabled(False)
        
        gui_label=QLabel(_('Default GUI') + ':')
        grid_ui.addWidget(gui_label , 7, 0)
        gui_combo = QComboBox()
        gui_combo.addItems(['Lite', 'Classic'])
        index = gui_combo.findText(self.config.get("gui","classic").capitalize())
        if index==-1: index = 1
        gui_combo.setCurrentIndex(index)
        grid_ui.addWidget(gui_combo, 7, 1)
        grid_ui.addWidget(HelpButton(_('Select which GUI mode to use at start up.'+'\n'+'Note: use the command line to access the "text" and "gtk" GUIs')), 7, 2)
        if not self.config.is_modifiable('gui'):
            for w in [gui_combo, gui_label]: w.setEnabled(False)

        lang_label=QLabel(_('Language') + ':')
        grid_ui.addWidget(lang_label , 8, 0)
        lang_combo = QComboBox()
        from i18n import languages
        lang_combo.addItems(languages.values())
        try:
            index = languages.keys().index(self.config.get("language",''))
        except:
            index = 0
        lang_combo.setCurrentIndex(index)
        grid_ui.addWidget(lang_combo, 8, 1)
        grid_ui.addWidget(HelpButton(_('Select which language is used in the GUI (after restart). ')), 8, 2)
        if not self.config.is_modifiable('language'):
            for w in [lang_combo, lang_label]: w.setEnabled(False)

        currencies = self.exchanger.get_currencies()
        currencies.insert(0, "None")

        cur_label=QLabel(_('Currency') + ':')
        grid_ui.addWidget(cur_label , 9, 0)
        cur_combo = QComboBox()
        cur_combo.addItems(currencies)
        try:
            index = currencies.index(self.config.get('currency', "None"))
        except:
            index = 0
        cur_combo.setCurrentIndex(index)
        grid_ui.addWidget(cur_combo, 9, 1)
        grid_ui.addWidget(HelpButton(_('Select which currency is used for quotes. ')), 9, 2)
        
        view_label=QLabel(_('Receive Tab') + ':')
        grid_ui.addWidget(view_label , 10, 0)
        view_combo = QComboBox()
        view_combo.addItems([_('Simple'), _('Advanced'), _('Point of Sale')])
        view_combo.setCurrentIndex(self.receive_tab_mode)
        grid_ui.addWidget(view_combo, 10, 1)
        hh = _('This selects the interaction mode of the "Receive" tab. ') + '\n\n' \
             + _('Simple') +   ': ' + _('Show only addresses and labels.') + '\n\n' \
             + _('Advanced') + ': ' + _('Show address balances and add extra menu items to freeze/prioritize addresses.') + '\n\n' \
             + _('Point of Sale') + ': ' + _('Show QR code window and amounts requested for each address. Add menu item to request amount.') + '\n\n' 
        
        grid_ui.addWidget(HelpButton(hh), 10, 2)

        # wallet tab
        tab2 = QWidget()
        grid_wallet = QGridLayout(tab2)
        grid_wallet.setColumnStretch(0,1)
        tabs.addTab(tab2, _('Wallet') )
        
        fee_label = QLabel(_('Transaction fee'))
        grid_wallet.addWidget(fee_label, 0, 0)
        fee_e = QLineEdit()
        fee_e.setText("%s"% str( Decimal( self.wallet.fee)/100000000 ) )
        grid_wallet.addWidget(fee_e, 0, 1)
        msg = _('Fee per transaction input. Transactions involving multiple inputs tend to require a higher fee.') + ' ' \
            + _('Recommended value') + ': 0.001'
        grid_wallet.addWidget(HelpButton(msg), 0, 2)
        fee_e.textChanged.connect(lambda: numbify(fee_e,False))
        if not self.config.is_modifiable('fee'):
            for w in [fee_e, fee_label]: w.setEnabled(False)

        usechange_label = QLabel(_('Use change addresses'))
        grid_wallet.addWidget(usechange_label, 1, 0)
        usechange_combo = QComboBox()
        usechange_combo.addItems(['Yes', 'No'])
        usechange_combo.setCurrentIndex(not self.wallet.use_change)
        grid_wallet.addWidget(usechange_combo, 1, 1)
        grid_wallet.addWidget(HelpButton(_('Using change addresses makes it more difficult for other people to track your transactions. ')), 1, 2)
        if not self.config.is_modifiable('use_change'): usechange_combo.setEnabled(False)

        gap_label = QLabel(_('Gap limit'))
        grid_wallet.addWidget(gap_label, 2, 0)
        gap_e = QLineEdit()
        gap_e.setText("%d"% self.wallet.gap_limit)
        grid_wallet.addWidget(gap_e, 2, 1)
        msg =  _('The gap limit is the maximal number of contiguous unused addresses in your sequence of receiving addresses.') + '\n' \
              + _('You may increase it if you need more receiving addresses.') + '\n\n' \
              + _('Your current gap limit is') + ': %d'%self.wallet.gap_limit + '\n' \
              + _('Given the current status of your address sequence, the minimum gap limit you can use is: ') + '%d'%self.wallet.min_acceptable_gap() + '\n\n' \
              + _('Warning') + ': ' \
              + _('The gap limit parameter must be provided in order to recover your wallet from seed.') + ' ' \
              + _('Do not modify it if you do not understand what you are doing, or if you expect to recover your wallet without knowing it!') + '\n\n' 
        grid_wallet.addWidget(HelpButton(msg), 2, 2)
        gap_e.textChanged.connect(lambda: numbify(nz_e,True))
        if not self.config.is_modifiable('gap_limit'):
            for w in [gap_e, gap_label]: w.setEnabled(False)

        grid_wallet.setRowStretch(3,1)


        # wallet tab
        tab3 = QWidget()
        grid_io = QGridLayout(tab3)
        grid_io.setColumnStretch(0,1)
        tabs.addTab(tab3, _('Import/Export') )
        
        grid_io.addWidget(QLabel(_('Labels')), 1, 0)
        grid_io.addWidget(EnterButton(_("Export"), self.do_export_labels), 1, 1)
        grid_io.addWidget(EnterButton(_("Import"), self.do_import_labels), 1, 2)
        grid_io.addWidget(HelpButton('Export your labels as json'), 1, 3)

        grid_io.addWidget(QLabel(_('History')), 2, 0)
        grid_io.addWidget(EnterButton(_("Export"), self.do_export_history), 2, 1)
        grid_io.addWidget(HelpButton('Export your transaction history as csv'), 2, 3)

        grid_io.addWidget(QLabel(_('Private key')), 3, 0)
        grid_io.addWidget(EnterButton(_("Import"), self.do_import_privkey), 3, 2)
        grid_io.addWidget(HelpButton('Import private key' + '\n' \
                                         + _('Warning: Imported keys are not recoverable with your seed.') + '\n' \
                                         + _('If you import keys, you will need to do backups of your wallet.')), 3, 3)

        grid_io.setRowStretch(4,1)
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

        usechange_result = usechange_combo.currentIndex() == 0
        if self.wallet.use_change != usechange_result:
            self.wallet.use_change = usechange_result
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

        need_restart = False

        gui_request = str(gui_combo.currentText()).lower()
        if gui_request != self.config.get('gui'):
            self.config.set_key('gui', gui_request, True)
            need_restart = True
            
        lang_request = languages.keys()[lang_combo.currentIndex()]
        if lang_request != self.config.get('language'):
            self.config.set_key("language", lang_request, True)
            need_restart = True
            
        cur_request = str(currencies[cur_combo.currentIndex()])
        if cur_request != self.config.get('currency', "None"):
            self.config.set_key('currency', cur_request, True)
            self.update_wallet()

        if need_restart:
            QMessageBox.warning(self, _('Success'), _('Please restart Electrum to activate the new GUI settings'), _('OK'))

        self.receive_tab_set_mode(view_combo.currentIndex())


    @staticmethod 
    def network_dialog(wallet, parent=None):
        interface = wallet.interface
        if parent:
            if interface.is_connected:
                status = _("Connected to")+" %s\n%d blocks"%(interface.host, wallet.verifier.height)
            else:
                status = _("Not connected")
            server = interface.server
        else:
            import random
            status = _("Please choose a server.") + "\n" + _("Select 'Cancel' if you are offline.")
            server = interface.server

        plist, servers_list = interface.get_servers_list()

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
        servers_list_widget.setHeaderLabels( [ label, _('Type') ] )
        servers_list_widget.setMaximumHeight(150)
        servers_list_widget.setColumnWidth(0, 240)
        for _host in servers_list.keys():
            _type = 'P' if servers_list[_host].get('pruning') else 'F'
            servers_list_widget.addTopLevelItem(QTreeWidgetItem( [ _host, _type ] ))

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


        if server:
            host, port, protocol = server.split(':')
            change_server(host,protocol)

        servers_list_widget.connect(servers_list_widget, SIGNAL('itemClicked(QTreeWidgetItem*, int)'), lambda x: change_server(unicode(x.text(0))))
        grid.addWidget(servers_list_widget, 1, 1, 1, 3)

        if not wallet.config.is_modifiable('server'):
            for w in [server_host, server_port, server_protocol, servers_list_widget]: w.setEnabled(False)

        # auto cycle
        autocycle_cb = QCheckBox('Try random servers if disconnected')
        autocycle_cb.setChecked(wallet.config.get('auto_cycle', False))
        grid.addWidget(autocycle_cb, 3, 1, 3, 2)
        if not wallet.config.is_modifiable('auto_cycle'): autocycle_cb.setEnabled(False)

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
        wallet.config.set_key('auto_cycle', autocycle_cb.isChecked(), True)
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


    def restore_or_create(self):
        msg = _("Wallet file not found.")+"\n"+_("Do you want to create a new wallet, or to restore an existing one?")
        r = QMessageBox.question(None, _('Message'), msg, _('Create'), _('Restore'), _('Cancel'), 0, 2)
        if r==2: return None
        return 'restore' if r==1 else 'create'

    def seed_dialog(self):
        return ElectrumWindow.seed_dialog( self.wallet )

    def network_dialog(self):
        return ElectrumWindow.network_dialog( self.wallet, parent=None )
        

    def show_seed(self):
        ElectrumWindow.show_seed_dialog(self.wallet)


    def password_dialog(self):
        ElectrumWindow.change_password_dialog(self.wallet)


    def restore_wallet(self):
        wallet = self.wallet
        # wait until we are connected, because the user might have selected another server
        if not wallet.interface.is_connected:
            waiting = lambda: False if wallet.interface.is_connected else "connecting...\n"
            waiting_dialog(waiting)

        waiting = lambda: False if wallet.is_up_to_date() else "Please wait...\nAddresses generated: %d\nKilobytes received: %.1f"\
            %(len(wallet.all_addresses()), wallet.interface.bytes_received/1024.)

        wallet.set_up_to_date(False)
        wallet.interface.poke('synchronizer')
        waiting_dialog(waiting)
        if wallet.is_found():
            print_error( "Recovery successful" )
        else:
            QMessageBox.information(None, _('Error'), _("No transactions found for this seed"), _('OK'))

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
