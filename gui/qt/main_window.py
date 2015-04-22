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

import sys, time, re, threading
from electrum_ltc.i18n import _, set_language
from electrum_ltc.util import print_error, print_msg
import os.path, json, ast, traceback
import shutil
import StringIO


import PyQt4
from PyQt4.QtGui import *
from PyQt4.QtCore import *
import PyQt4.QtCore as QtCore

from electrum_ltc.bitcoin import MIN_RELAY_TX_FEE, is_valid
from electrum_ltc.plugins import run_hook

import icons_rc

from electrum_ltc.util import format_satoshis, format_time, NotEnoughFunds
from electrum_ltc import Transaction
from electrum_ltc import mnemonic
from electrum_ltc import util, bitcoin, commands, Interface, Wallet
from electrum_ltc import SimpleConfig, Wallet, WalletStorage
from electrum_ltc import Imported_Wallet

from amountedit import AmountEdit, BTCAmountEdit, MyLineEdit
from network_dialog import NetworkDialog
from qrcodewidget import QRCodeWidget, QRDialog
from qrtextedit import ScanQRTextEdit, ShowQRTextEdit

from decimal import Decimal

import httplib
import socket
import webbrowser
import csv





from electrum_ltc import ELECTRUM_VERSION
import re

from util import *


class StatusBarButton(QPushButton):
    def __init__(self, icon, tooltip, func):
        QPushButton.__init__(self, icon, '')
        self.setToolTip(tooltip)
        self.setFlat(True)
        self.setMaximumWidth(25)
        self.clicked.connect(func)
        self.func = func
        self.setIconSize(QSize(25,25))

    def keyPressEvent(self, e):
        if e.key() == QtCore.Qt.Key_Return:
            apply(self.func,())


from electrum_ltc.paymentrequest import PR_UNPAID, PR_PAID, PR_EXPIRED
from electrum_ltc.paymentrequest import PaymentRequest, InvoiceStore, get_payment_request, make_payment_request

pr_icons = {
    PR_UNPAID:":icons/unpaid.png",
    PR_PAID:":icons/confirmed.png",
    PR_EXPIRED:":icons/expired.png"
}

pr_tooltips = {
    PR_UNPAID:_('Pending'),
    PR_PAID:_('Paid'),
    PR_EXPIRED:_('Expired')
}

expiration_values = [
    (_('1 hour'), 60*60),
    (_('1 day'), 24*64*64),
    (_('1 week'), 7*24*60*60),
    (_('Never'), None)
]



class ElectrumWindow(QMainWindow):
    labelsChanged = pyqtSignal()

    def __init__(self, config, network, gui_object):
        QMainWindow.__init__(self)

        self.config = config
        self.network = network
        self.gui_object = gui_object
        self.tray = gui_object.tray
        self.go_lite = gui_object.go_lite
        self.lite = None
        self.app = gui_object.app

        self.invoices = InvoiceStore(self.config)

        self.create_status_bar()
        self.need_update = threading.Event()

        self.decimal_point = config.get('decimal_point', 8)
        self.num_zeros     = int(config.get('num_zeros',0))

        self.completions = QStringListModel()

        self.tabs = tabs = QTabWidget(self)
        tabs.addTab(self.create_history_tab(), _('History') )
        tabs.addTab(self.create_send_tab(), _('Send') )
        tabs.addTab(self.create_receive_tab(), _('Receive') )
        tabs.addTab(self.create_addresses_tab(), _('Addresses') )
        tabs.addTab(self.create_contacts_tab(), _('Contacts') )
        tabs.addTab(self.create_console_tab(), _('Console') )
        tabs.setMinimumSize(600, 400)
        tabs.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.setCentralWidget(tabs)

        try:
            self.setGeometry(*self.config.get("winpos-qt"))
        except:
            self.setGeometry(100, 100, 840, 400)

        if self.config.get("is_maximized"):
            self.showMaximized()

        self.setWindowIcon(QIcon(":icons/electrum-ltc.png"))
        self.init_menubar()

        QShortcut(QKeySequence("Ctrl+W"), self, self.close)
        QShortcut(QKeySequence("Ctrl+Q"), self, self.close)
        QShortcut(QKeySequence("Ctrl+R"), self, self.update_wallet)
        QShortcut(QKeySequence("Ctrl+PgUp"), self, lambda: tabs.setCurrentIndex( (tabs.currentIndex() - 1 )%tabs.count() ))
        QShortcut(QKeySequence("Ctrl+PgDown"), self, lambda: tabs.setCurrentIndex( (tabs.currentIndex() + 1 )%tabs.count() ))

        for i in range(tabs.count()):
            QShortcut(QKeySequence("Alt+" + str(i + 1)), self, lambda i=i: tabs.setCurrentIndex(i))

        self.connect(self, QtCore.SIGNAL('update_status'), self.update_status)
        self.connect(self, QtCore.SIGNAL('banner_signal'), lambda: self.console.showMessage(self.network.banner) )
        self.connect(self, QtCore.SIGNAL('transaction_signal'), lambda: self.notify_transactions() )
        self.connect(self, QtCore.SIGNAL('payment_request_ok'), self.payment_request_ok)
        self.connect(self, QtCore.SIGNAL('payment_request_error'), self.payment_request_error)
        self.labelsChanged.connect(self.update_tabs)

        self.history_list.setFocus(True)

        # network callbacks
        if self.network:
            self.network.register_callback('updated', lambda: self.need_update.set())
            self.network.register_callback('banner', lambda: self.emit(QtCore.SIGNAL('banner_signal')))
            self.network.register_callback('status', lambda: self.emit(QtCore.SIGNAL('update_status')))
            self.network.register_callback('new_transaction', lambda: self.emit(QtCore.SIGNAL('transaction_signal')))
            self.network.register_callback('stop', self.close)

            # set initial message
            self.console.showMessage(self.network.banner)

        self.wallet = None
        self.payment_request = None
        self.qr_window = None
        self.not_enough_funds = False
        self.pluginsdialog = None

    def update_account_selector(self):
        # account selector
        accounts = self.wallet.get_account_names()
        self.account_selector.clear()
        if len(accounts) > 1:
            self.account_selector.addItems([_("All accounts")] + accounts.values())
            self.account_selector.setCurrentIndex(0)
            self.account_selector.show()
        else:
            self.account_selector.hide()

    def close_wallet(self):
        self.wallet.stop_threads()
        run_hook('close_wallet')

    def load_wallet(self, wallet):
        import electrum_ltc as electrum
        self.wallet = wallet
        self.update_wallet_format()
        # address used to create a dummy transaction and estimate transaction fee
        a = self.wallet.addresses(False)
        self.dummy_address = a[0] if a else None

        self.accounts_expanded = self.wallet.storage.get('accounts_expanded',{})
        self.current_account = self.wallet.storage.get("current_account", None)
        title = 'Electrum-LTC ' + self.wallet.electrum_version + '  -  ' + os.path.basename(self.wallet.storage.path)
        if self.wallet.is_watching_only(): title += ' [%s]' % (_('watching only'))
        self.setWindowTitle( title )
        self.update_history_tab()
        self.update_wallet()
        # Once GUI has been initialized check if we want to announce something since the callback has been called before the GUI was initialized
        self.notify_transactions()
        self.update_account_selector()
        # update menus
        self.new_account_menu.setVisible(self.wallet.can_create_accounts())
        self.private_keys_menu.setEnabled(not self.wallet.is_watching_only())
        self.password_menu.setEnabled(self.wallet.can_change_password())
        self.seed_menu.setEnabled(self.wallet.has_seed())
        self.mpk_menu.setEnabled(self.wallet.is_deterministic())
        self.import_menu.setVisible(self.wallet.can_import())
        self.export_menu.setEnabled(self.wallet.can_export())

        self.update_lock_icon()
        self.update_buttons_on_seed()
        self.update_console()

        self.clear_receive_tab()
        self.update_receive_tab()
        self.show()
        run_hook('load_wallet', wallet)


    def update_wallet_format(self):
        # convert old-format imported keys
        if self.wallet.imported_keys:
            password = self.password_dialog(_("Please enter your password in order to update imported keys")) if self.wallet.use_encryption else None
            try:
                self.wallet.convert_imported_keys(password)
            except Exception as e:
                traceback.print_exc(file=sys.stdout)
                self.show_message(str(e))
        # call synchronize to regenerate addresses in case we are offline
        if self.wallet.get_master_public_keys() and self.wallet.addresses() == []:
            self.wallet.synchronize()


    def open_wallet(self):
        wallet_folder = self.wallet.storage.path
        filename = unicode( QFileDialog.getOpenFileName(self, "Select your wallet file", wallet_folder) )
        if not filename:
            return
        try:
            storage = WalletStorage({'wallet_path': filename})
        except Exception as e:
            self.show_message(str(e))
            return
        if not storage.file_exists:
            self.show_message(_("File not found") + ' ' + filename)
            return
        # read wizard action
        try:
            wallet = Wallet(storage)
        except BaseException as e:
            QMessageBox.warning(None, _('Warning'), str(e), _('OK'))
            return
        action = wallet.get_action()
        self.hide()
        # run wizard
        if action is not None:
            wallet = self.gui_object.run_wizard(storage, action)
        else:
            wallet.start_threads(self.network)
        # keep current wallet
        if not wallet:
            self.show()
            return
        # close current wallet
        self.close_wallet()
        # load new wallet in gui
        self.load_wallet(wallet)
        # save path
        if self.config.get('wallet_path') is None:
            self.config.set_key('gui_last_wallet', filename)


    def backup_wallet(self):
        import shutil
        path = self.wallet.storage.path
        wallet_folder = os.path.dirname(path)
        filename = unicode( QFileDialog.getSaveFileName(self, _('Enter a filename for the copy of your wallet'), wallet_folder) )
        if not filename:
            return

        new_path = os.path.join(wallet_folder, filename)
        if new_path != path:
            try:
                shutil.copy2(path, new_path)
                QMessageBox.information(None,"Wallet backup created", _("A copy of your wallet file was created in")+" '%s'" % str(new_path))
            except (IOError, os.error), reason:
                QMessageBox.critical(None,"Unable to create backup", _("Electrum was unable to copy your wallet file to the specified location.")+"\n" + str(reason))


    def new_wallet(self):
        import installwizard

        wallet_folder = os.path.dirname(os.path.abspath(self.wallet.storage.path))
        i = 1
        while True:
            filename = "wallet_%d"%i
            if filename in os.listdir(wallet_folder):
                i += 1
            else:
                break

        filename = line_dialog(self, _('New Wallet'), _('Enter file name') + ':', _('OK'), filename)
        if not filename:
            return

        full_path = os.path.join(wallet_folder, filename)
        storage = WalletStorage({'wallet_path': full_path})
        if storage.file_exists:
            QMessageBox.critical(None, "Error", _("File exists"))
            return

        self.hide()
        wizard = installwizard.InstallWizard(self.config, self.network, storage)
        action, wallet_type = wizard.restore_or_create()
        if not action:
            self.show()
            return
        # close current wallet, but keep a reference to it
        self.close_wallet()
        wallet = wizard.run(action, wallet_type)
        if wallet:
            self.load_wallet(wallet)
        else:
            self.wallet.start_threads(self.network)
            self.load_wallet(self.wallet)

        self.show()



    def init_menubar(self):
        menubar = QMenuBar()

        file_menu = menubar.addMenu(_("&File"))
        file_menu.addAction(_("&Open"), self.open_wallet).setShortcut(QKeySequence.Open)
        file_menu.addAction(_("&New/Restore"), self.new_wallet).setShortcut(QKeySequence.New)
        file_menu.addAction(_("&Save Copy"), self.backup_wallet).setShortcut(QKeySequence.SaveAs)
        file_menu.addAction(_("&Quit"), self.close)

        wallet_menu = menubar.addMenu(_("&Wallet"))
        wallet_menu.addAction(_("&New contact"), self.new_contact_dialog)
        self.new_account_menu = wallet_menu.addAction(_("&New account"), self.new_account_dialog)

        wallet_menu.addSeparator()

        self.password_menu = wallet_menu.addAction(_("&Password"), self.change_password_dialog)
        self.seed_menu = wallet_menu.addAction(_("&Seed"), self.show_seed_dialog)
        self.mpk_menu = wallet_menu.addAction(_("&Master Public Keys"), self.show_master_public_keys)

        wallet_menu.addSeparator()
        labels_menu = wallet_menu.addMenu(_("&Labels"))
        labels_menu.addAction(_("&Import"), self.do_import_labels)
        labels_menu.addAction(_("&Export"), self.do_export_labels)

        self.private_keys_menu = wallet_menu.addMenu(_("&Private keys"))
        self.private_keys_menu.addAction(_("&Sweep"), self.sweep_key_dialog)
        self.import_menu = self.private_keys_menu.addAction(_("&Import"), self.do_import_privkey)
        self.export_menu = self.private_keys_menu.addAction(_("&Export"), self.export_privkeys_dialog)
        wallet_menu.addAction(_("&Export History"), self.export_history_dialog)

        tools_menu = menubar.addMenu(_("&Tools"))

        # Settings / Preferences are all reserved keywords in OSX using this as work around
        tools_menu.addAction(_("Electrum preferences") if sys.platform == 'darwin' else _("Preferences"), self.settings_dialog)
        tools_menu.addAction(_("&Network"), self.run_network_dialog)
        tools_menu.addAction(_("&Plugins"), self.plugins_dialog)
        tools_menu.addSeparator()
        tools_menu.addAction(_("&Sign/verify message"), self.sign_verify_message)
        tools_menu.addAction(_("&Encrypt/decrypt message"), self.encrypt_message)
        tools_menu.addSeparator()

        csv_transaction_menu = tools_menu.addMenu(_("&Create transaction"))
        csv_transaction_menu.addAction(_("&From CSV file"), self.do_process_from_csv_file)
        csv_transaction_menu.addAction(_("&From CSV text"), self.do_process_from_csv_text)

        raw_transaction_menu = tools_menu.addMenu(_("&Load transaction"))
        raw_transaction_menu.addAction(_("&From file"), self.do_process_from_file)
        raw_transaction_menu.addAction(_("&From text"), self.do_process_from_text)
        raw_transaction_menu.addAction(_("&From the blockchain"), self.do_process_from_txid)
        raw_transaction_menu.addAction(_("&From QR code"), self.read_tx_from_qrcode)
        self.raw_transaction_menu = raw_transaction_menu

        help_menu = menubar.addMenu(_("&Help"))
        help_menu.addAction(_("&About"), self.show_about)
        help_menu.addAction(_("&Official website"), lambda: webbrowser.open("http://electrum-ltc.org"))
        help_menu.addSeparator()
        help_menu.addAction(_("&Documentation"), lambda: webbrowser.open("http://electrum.orain.org/")).setShortcut(QKeySequence.HelpContents)
        help_menu.addAction(_("&Report Bug"), self.show_report_bug)

        self.setMenuBar(menubar)

    def show_about(self):
        QMessageBox.about(self, "Electrum-LTC",
            _("Version")+" %s" % (self.wallet.electrum_version) + "\n\n" + _("Electrum's focus is speed, with low resource usage and simplifying Litecoin. You do not need to perform regular backups, because your wallet can be recovered from a secret phrase that you can memorize or write on paper. Startup times are instant because it operates in conjunction with high-performance servers that handle the most complicated parts of the Litecoin system."))

    def show_report_bug(self):
        QMessageBox.information(self, "Electrum-LTC - " + _("Reporting Bugs"),
            _("Please report any bugs as issues on github:")+" <a href=\"https://github.com/pooler/electrum-ltc/issues\">https://github.com/pooler/electrum-ltc/issues</a>")


    def notify_transactions(self):
        if not self.network or not self.network.is_connected():
            return

        print_error("Notifying GUI")
        if len(self.network.pending_transactions_for_notifications) > 0:
            # Combine the transactions if there are more then three
            tx_amount = len(self.network.pending_transactions_for_notifications)
            if(tx_amount >= 3):
                total_amount = 0
                for tx in self.network.pending_transactions_for_notifications:
                    is_relevant, is_mine, v, fee = self.wallet.get_tx_value(tx)
                    if(v > 0):
                        total_amount += v

                self.notify(_("%(txs)s new transactions received. Total amount received in the new transactions %(amount)s %(unit)s") \
                                % { 'txs' : tx_amount, 'amount' : self.format_amount(total_amount), 'unit' : self.base_unit()})

                self.network.pending_transactions_for_notifications = []
            else:
              for tx in self.network.pending_transactions_for_notifications:
                  if tx:
                      self.network.pending_transactions_for_notifications.remove(tx)
                      is_relevant, is_mine, v, fee = self.wallet.get_tx_value(tx)
                      if(v > 0):
                          self.notify(_("New transaction received. %(amount)s %(unit)s") % { 'amount' : self.format_amount(v), 'unit' : self.base_unit()})

    def notify(self, message):
        if self.tray:
            self.tray.showMessage("Electrum-LTC", message, QSystemTrayIcon.Information, 20000)



    # custom wrappers for getOpenFileName and getSaveFileName, that remember the path selected by the user
    def getOpenFileName(self, title, filter = ""):
        directory = self.config.get('io_dir', unicode(os.path.expanduser('~')))
        fileName = unicode( QFileDialog.getOpenFileName(self, title, directory, filter) )
        if fileName and directory != os.path.dirname(fileName):
            self.config.set_key('io_dir', os.path.dirname(fileName), True)
        return fileName

    def getSaveFileName(self, title, filename, filter = ""):
        directory = self.config.get('io_dir', unicode(os.path.expanduser('~')))
        path = os.path.join( directory, filename )
        fileName = unicode( QFileDialog.getSaveFileName(self, title, path, filter) )
        if fileName and directory != os.path.dirname(fileName):
            self.config.set_key('io_dir', os.path.dirname(fileName), True)
        return fileName

    def close(self):
        if self.qr_window:
            self.qr_window.close()
        QMainWindow.close(self)
        run_hook('close_main_window')

    def connect_slots(self, sender):
        self.connect(sender, QtCore.SIGNAL('timersignal'), self.timer_actions)
        self.previous_payto_e=''

    def timer_actions(self):
        if self.need_update.is_set():
            self.update_wallet()
            self.need_update.clear()

        run_hook('timer_actions')

    def format_amount(self, x, is_diff=False, whitespaces=False):
        return format_satoshis(x, is_diff, self.num_zeros, self.decimal_point, whitespaces)


    def get_decimal_point(self):
        return self.decimal_point


    def base_unit(self):
        assert self.decimal_point in [2, 5, 8]
        if self.decimal_point == 2:
            return 'bits'
        if self.decimal_point == 5:
            return 'mLTC'
        if self.decimal_point == 8:
            return 'LTC'
        raise Exception('Unknown base unit')

    def update_status(self):
        if not self.wallet:
            return

        if self.network is None or not self.network.is_running():
            text = _("Offline")
            icon = QIcon(":icons/status_disconnected.png")

        elif self.network.is_connected():
            server_lag = self.network.get_local_height() - self.network.get_server_height()
            if not self.wallet.up_to_date:
                text = _("Synchronizing...")
                icon = QIcon(":icons/status_waiting.png")
            elif server_lag > 1:
                text = _("Server is lagging (%d blocks)"%server_lag)
                icon = QIcon(":icons/status_lagging.png")
            else:
                c, u = self.wallet.get_account_balance(self.current_account)
                text =  _( "Balance" ) + ": %s "%( self.format_amount(c) ) + self.base_unit()
                if u: text +=  " [%s unconfirmed]"%( self.format_amount(u,True).strip() )

                # append fiat balance and price from exchange rate plugin
                r = {}
                run_hook('get_fiat_status_text', c+u, r)
                quote = r.get(0)
                if quote:
                    text += "%s"%quote

                if self.tray:
                    self.tray.setToolTip(text)
                icon = QIcon(":icons/status_connected.png")
        else:
            text = _("Not connected")
            icon = QIcon(":icons/status_disconnected.png")

        self.balance_label.setText(text)
        self.status_button.setIcon( icon )


    def update_wallet(self):
        self.update_status()
        if self.wallet.up_to_date or not self.network or not self.network.is_connected():
            self.update_tabs()

    def update_tabs(self):
        self.update_history_tab()
        self.update_receive_tab()
        self.update_address_tab()
        self.update_contacts_tab()
        self.update_completions()
        self.update_invoices_list()

    def create_history_tab(self):
        from history_widget import HistoryWidget
        self.history_list = l = HistoryWidget(self)
        return l

    def show_address(self, addr):
        import address_dialog
        d = address_dialog.AddressDialog(addr, self)
        d.exec_()

    def show_transaction(self, tx):
        import transaction_dialog
        d = transaction_dialog.TxDialog(tx, self)
        d.exec_()

    def update_history_tab(self):
        domain = self.wallet.get_account_addresses(self.current_account)
        h = self.wallet.get_history(domain)
        self.history_list.update(h)

    def create_receive_tab(self):

        self.receive_grid = grid = QGridLayout()
        grid.setColumnMinimumWidth(3, 300)

        self.receive_address_e = ButtonsLineEdit()
        self.receive_address_e.addCopyButton(self.app)
        self.receive_address_e.setReadOnly(True)
        self.receive_address_label = QLabel(_('Receiving address'))
        self.receive_address_e.textChanged.connect(self.update_receive_qr)
        self.receive_address_e.setFocusPolicy(Qt.NoFocus)
        grid.addWidget(self.receive_address_label, 0, 0)
        grid.addWidget(self.receive_address_e, 0, 1, 1, 4)

        self.receive_message_e = QLineEdit()
        grid.addWidget(QLabel(_('Description')), 1, 0)
        grid.addWidget(self.receive_message_e, 1, 1, 1, 4)
        self.receive_message_e.textChanged.connect(self.update_receive_qr)

        self.receive_amount_e = BTCAmountEdit(self.get_decimal_point)
        grid.addWidget(QLabel(_('Requested amount')), 2, 0)
        grid.addWidget(self.receive_amount_e, 2, 1, 1, 2)
        self.receive_amount_e.textChanged.connect(self.update_receive_qr)

        self.expires_combo = QComboBox()
        self.expires_combo.addItems(map(lambda x:x[0], expiration_values))
        self.expires_combo.setCurrentIndex(1)
        grid.addWidget(QLabel(_('Expires in')), 3, 0)
        grid.addWidget(self.expires_combo, 3, 1)
        self.expires_label = QLineEdit('')
        self.expires_label.setReadOnly(1)
        self.expires_label.setFocusPolicy(Qt.NoFocus)
        self.expires_label.hide()
        grid.addWidget(self.expires_label, 3, 1, 1, 2)

        self.save_request_button = QPushButton(_('Save'))
        self.save_request_button.clicked.connect(self.save_payment_request)

        self.new_request_button = QPushButton(_('New'))
        self.new_request_button.clicked.connect(self.new_payment_request)

        self.receive_qr = QRCodeWidget(fixedSize=200)
        self.receive_qr.mouseReleaseEvent = lambda x: self.toggle_qr_window()

        self.receive_buttons = buttons = QHBoxLayout()
        buttons.addStretch(1)
        buttons.addWidget(self.save_request_button)
        buttons.addWidget(self.new_request_button)

        self.receive_requests_label = QLabel(_('My Requests'))
        self.receive_list = MyTreeWidget(self, self.receive_list_menu, [_('Date'), _('Account'), _('Address'), _('Description'), _('Amount'), _('Status')], [])
        self.receive_list.currentItemChanged.connect(self.receive_item_changed)
        self.receive_list.itemClicked.connect(self.receive_item_changed)
        self.receive_list.setSortingEnabled(True)
        self.receive_list.setColumnWidth(0, 180)
        self.receive_list.hideColumn(1)     # the update will show it if necessary
        self.receive_list.hideColumn(2)     # don't show address
        self.receive_list.setColumnWidth(2, 340)
        h = self.receive_list.header()
        h.setStretchLastSection(False)
        h.setResizeMode(3, QHeaderView.Stretch)

        # layout
        vbox_g = QVBoxLayout()
        vbox_g.addLayout(grid)
        vbox_g.addLayout(buttons)

        hbox = QHBoxLayout()
        hbox.addLayout(vbox_g)
        hbox.addStretch()
        hbox.addWidget(self.receive_qr)

        w = QWidget()
        vbox = QVBoxLayout(w)
        vbox.addLayout(hbox)
        vbox.addStretch(1)
        vbox.addWidget(self.receive_requests_label)
        vbox.addWidget(self.receive_list)

        return w

    def receive_item_changed(self, item):
        if item is None:
            return
        addr = str(item.text(2))
        req = self.receive_requests[addr]
        expires = _('Never') if req.get('expiration') is None else format_time(req['time'] + req['expiration'])
        amount = req['amount']
        message = self.wallet.labels.get(addr, '')
        self.receive_address_e.setText(addr)
        self.receive_message_e.setText(message)
        self.receive_amount_e.setAmount(amount)
        self.expires_combo.hide()
        self.expires_label.show()
        self.expires_label.setText(expires)
        self.new_request_button.setEnabled(True)

    def delete_payment_request(self, item):
        addr = str(item.text(2))
        self.receive_requests.pop(addr)
        self.wallet.storage.put('receive_requests2', self.receive_requests)
        self.update_receive_tab()
        self.clear_receive_tab()

    def get_receive_URI(self):
        addr = str(self.receive_address_e.text())
        amount = self.receive_amount_e.get_amount()
        message = unicode(self.receive_message_e.text())
        URI = util.create_URI(addr, amount, message)
        return URI

    def receive_list_menu(self, position):
        item = self.receive_list.itemAt(position)
        addr = str(item.text(2))
        req = self.receive_requests[addr]
        time, amount = req['time'], req['amount']
        message = self.wallet.labels.get(addr, '')
        URI = util.create_URI(addr, amount, message)
        menu = QMenu()
        menu.addAction(_("Copy Address"), lambda: self.app.clipboard().setText(addr))
        menu.addAction(_("Copy URI"), lambda: self.app.clipboard().setText(str(URI)))
        menu.addAction(_("Save as BIP70 file"), lambda: self.export_payment_request(addr))
        menu.addAction(_("Delete"), lambda: self.delete_payment_request(item))
        menu.exec_(self.receive_list.viewport().mapToGlobal(position))

    def save_payment_request(self):
        now = int(time.time())
        addr = str(self.receive_address_e.text())
        amount = self.receive_amount_e.get_amount()
        message = unicode(self.receive_message_e.text())
        i = self.expires_combo.currentIndex()
        expiration = map(lambda x: x[1], expiration_values)[i]
        if not message and not amount:
            QMessageBox.warning(self, _('Error'), _('No message or amount'), _('OK'))
            return
        self.receive_requests = self.wallet.storage.get('receive_requests2',{})
        self.receive_requests[addr] = {'time':now, 'amount':amount, 'expiration':expiration}
        self.wallet.storage.put('receive_requests2', self.receive_requests)
        self.wallet.set_label(addr, message)
        self.update_receive_tab()
        self.update_address_tab()
        self.save_request_button.setEnabled(False)

    def make_payment_request(self, addr):
        req = self.receive_requests[addr]
        time = req['time']
        amount = req['amount']
        expiration = req['expiration']
        message = self.wallet.labels.get(addr, '')
        script = Transaction.pay_script('address', addr).decode('hex')
        outputs = [(script, amount)]
        cert_path = self.config.get('cert_path')
        chain_path = self.config.get('chain_path')
        return make_payment_request(outputs, message, time, time + expiration, cert_path, chain_path)

    def export_payment_request(self, addr):
        pr = self.make_payment_request(addr)
        name = 'request.bip70'
        fileName = self.getSaveFileName(_("Select where to save your payment request"), name, "*.bip70")
        if fileName:
            with open(fileName, "wb+") as f:
                f.write(str(pr))
            self.show_message(_("Request saved successfully"))
            self.saved = True

    def get_receive_address(self):
        domain = self.wallet.get_account_addresses(self.current_account, include_change=False)
        for addr in domain:
            if not self.wallet.history.get(addr) and addr not in self.receive_requests.keys():
                return addr

    def new_payment_request(self):
        addr = self.get_receive_address()
        if addr is None:
            if isinstance(self.wallet, Imported_Wallet):
                self.show_message(_('No more addresses in your wallet.'))
                return
            if not self.question(_("Warning: The next address will not be recovered automatically if you restore your wallet from seed; you may need to add it manually.\n\nThis occurs because you have too many unused addresses in your wallet. To avoid this situation, use the existing addresses first.\n\nCreate anyway?")):
                return
            addr = self.wallet.create_new_address(self.current_account, False)
        self.set_receive_address(addr)
        self.expires_label.hide()
        self.expires_combo.show()
        self.new_request_button.setEnabled(False)
        self.receive_message_e.setFocus(1)

    def set_receive_address(self, addr):
        self.receive_address_e.setText(addr)
        self.receive_message_e.setText('')
        self.receive_amount_e.setAmount(None)

    def clear_receive_tab(self):
        self.receive_requests = self.wallet.storage.get('receive_requests2',{})
        domain = self.wallet.get_account_addresses(self.current_account, include_change=False)
        for addr in domain:
            if not self.wallet.history.get(addr) and addr not in self.receive_requests.keys():
                break
        else:
            addr = ''
        self.receive_address_e.setText(addr)
        self.receive_message_e.setText('')
        self.receive_amount_e.setAmount(None)

    def toggle_qr_window(self):
        import qrwindow
        if not self.qr_window:
            self.qr_window = qrwindow.QR_Window(self)
            self.qr_window.setVisible(True)
            self.qr_window_geometry = self.qr_window.geometry()
        else:
            if not self.qr_window.isVisible():
                self.qr_window.setVisible(True)
                self.qr_window.setGeometry(self.qr_window_geometry)
            else:
                self.qr_window_geometry = self.qr_window.geometry()
                self.qr_window.setVisible(False)
        self.update_receive_qr()


    def receive_at(self, addr):
        if not bitcoin.is_address(addr):
            return
        self.tabs.setCurrentIndex(2)
        self.receive_address_e.setText(addr)
        self.new_request_button.setEnabled(True)

    def update_receive_tab(self):
        self.receive_requests = self.wallet.storage.get('receive_requests2',{})

        # hide receive tab if no receive requests available
        b = len(self.receive_requests) > 0
        self.receive_list.setVisible(b)
        self.receive_requests_label.setVisible(b)
        if not b:
            self.expires_label.hide()
            self.expires_combo.show()

        # check if it is necessary to show the account
        self.receive_list.setColumnHidden(1, len(self.wallet.get_accounts()) == 1)

        # update the receive address if necessary
        current_address = self.receive_address_e.text()
        domain = self.wallet.get_account_addresses(self.current_account, include_change=False)
        addr = self.get_receive_address()
        if not current_address in domain and addr:
            self.set_receive_address(addr)
        self.new_request_button.setEnabled(addr != current_address)

        # clear the list and fill it again
        self.receive_list.clear()
        for address, req in self.receive_requests.viewitems():
            timestamp, amount = req['time'], req['amount']
            expiration = req.get('expiration', None)
            message = self.wallet.labels.get(address, '')
            # only show requests for the current account
            if address not in domain:
                continue
            date = format_time(timestamp)
            account = self.wallet.get_account_name(self.wallet.get_account_from_address(address))
            amount_str = self.format_amount(amount) if amount else ""
            if amount:
                paid = amount <= self.wallet.get_addr_received(address)
                status = PR_PAID if paid else PR_UNPAID
                if status == PR_UNPAID and expiration is not None and time.time() > timestamp + expiration:
                    status = PR_EXPIRED
            else:
                status = ''
            item = QTreeWidgetItem([date, account, address, message, amount_str, pr_tooltips.get(status,'')])
            if status is not '':
                item.setIcon(5, QIcon(pr_icons.get(status)))
            self.receive_list.addTopLevelItem(item)


    def update_receive_qr(self):
        addr = str(self.receive_address_e.text())
        amount = self.receive_amount_e.get_amount()
        message = unicode(self.receive_message_e.text()).encode('utf8')
        self.save_request_button.setEnabled((amount is not None) or (message != ""))
        uri = util.create_URI(addr, amount, message)
        self.receive_qr.setData(uri)
        if self.qr_window and self.qr_window.isVisible():
            self.qr_window.set_content(addr, amount, message, uri)


    def create_send_tab(self):
        self.send_grid = grid = QGridLayout()
        grid.setSpacing(8)
        grid.setColumnMinimumWidth(3,300)
        grid.setColumnStretch(5,1)
        grid.setRowStretch(8, 1)

        from paytoedit import PayToEdit
        self.amount_e = BTCAmountEdit(self.get_decimal_point)
        self.payto_e = PayToEdit(self)
        msg = _('Recipient of the funds.') + '\n\n'\
              + _('You may enter a Litecoin address, a label from your list of contacts (a list of completions will be proposed), or an alias (email-like address that forwards to a Litecoin address)')
        payto_label = HelpLabel(_('Pay to'), msg)
        grid.addWidget(payto_label, 1, 0)
        grid.addWidget(self.payto_e, 1, 1, 1, 3)

        completer = QCompleter()
        completer.setCaseSensitivity(False)
        self.payto_e.setCompleter(completer)
        completer.setModel(self.completions)

        msg = _('Description of the transaction (not mandatory).') + '\n\n'\
              + _('The description is not sent to the recipient of the funds. It is stored in your wallet file, and displayed in the \'History\' tab.')
        description_label = HelpLabel(_('Description'), msg)
        grid.addWidget(description_label, 2, 0)
        self.message_e = MyLineEdit()
        grid.addWidget(self.message_e, 2, 1, 1, 3)

        self.from_label = QLabel(_('From'))
        grid.addWidget(self.from_label, 3, 0)
        self.from_list = MyTreeWidget(self, self.from_list_menu, ['',''], [350, 50])
        self.from_list.setHeaderHidden(True)
        self.from_list.setMaximumHeight(80)
        grid.addWidget(self.from_list, 3, 1, 1, 3)
        self.set_pay_from([])

        msg = _('Amount to be sent.') + '\n\n' \
              + _('The amount will be displayed in red if you do not have enough funds in your wallet.') + ' ' \
              + _('Note that if you have frozen some of your addresses, the available funds will be lower than your total balance.') + '\n\n' \
              + _('Keyboard shortcut: type "!" to send all your coins.')
        amount_label = HelpLabel(_('Amount'), msg)
        grid.addWidget(amount_label, 4, 0)
        grid.addWidget(self.amount_e, 4, 1, 1, 2)

        msg = _('Litecoin transactions are in general not free. A transaction fee is paid by the sender of the funds.') + '\n\n'\
              + _('The amount of fee can be decided freely by the sender. However, transactions with low fees take more time to be processed.') + '\n\n'\
              + _('A suggested fee is automatically added to this field. You may override it. The suggested fee increases with the size of the transaction.')
        self.fee_e_label = HelpLabel(_('Fee'), msg)
        self.fee_e = BTCAmountEdit(self.get_decimal_point)
        grid.addWidget(self.fee_e_label, 5, 0)
        grid.addWidget(self.fee_e, 5, 1, 1, 2)
        self.update_fee_edit()

        self.send_button = EnterButton(_("Send"), self.do_send)
        self.clear_button = EnterButton(_("Clear"), self.do_clear)
        buttons = QHBoxLayout()
        buttons.addStretch(1)
        buttons.addWidget(self.send_button)
        buttons.addWidget(self.clear_button)

        def on_shortcut():
            sendable = self.get_sendable_balance()
            inputs = self.get_coins()
            for i in inputs: self.wallet.add_input_info(i)
            addr = self.payto_e.payto_address if self.payto_e.payto_address else self.dummy_address
            output = ('address', addr, sendable)
            dummy_tx = Transaction.from_io(inputs, [output])
            fee = self.wallet.estimated_fee(dummy_tx)
            self.amount_e.setAmount(max(0,sendable-fee))
            self.amount_e.textEdited.emit("")
            self.fee_e.setAmount(fee)

        self.amount_e.shortcut.connect(on_shortcut)

        self.payto_e.textChanged.connect(lambda: self.update_fee(False))
        self.amount_e.textEdited.connect(lambda: self.update_fee(False))
        self.fee_e.textEdited.connect(lambda: self.update_fee(True))

        def entry_changed():
            if not self.not_enough_funds:
                palette = QPalette()
                palette.setColor(self.amount_e.foregroundRole(), QColor('black'))
                text = ""
            else:
                palette = QPalette()
                palette.setColor(self.amount_e.foregroundRole(), QColor('red'))
                text = _( "Not enough funds" )
                c, u = self.wallet.get_frozen_balance()
                if c+u: text += ' (' + self.format_amount(c+u).strip() + ' ' + self.base_unit() + ' ' +_("are frozen") + ')'
            self.statusBar().showMessage(text)
            self.amount_e.setPalette(palette)
            self.fee_e.setPalette(palette)

        self.amount_e.textChanged.connect(entry_changed)
        self.fee_e.textChanged.connect(entry_changed)

        self.invoices_label = QLabel(_('Invoices'))
        self.invoices_list = MyTreeWidget(self, self.create_invoice_menu, [_('Date'), _('Requestor'), _('Memo'), _('Amount'), _('Status')], [150, 150, None, 150, 100])

        vbox0 = QVBoxLayout()
        vbox0.addLayout(grid)
        vbox0.addLayout(buttons)
        vbox0.addStretch(1)
        hbox = QHBoxLayout()
        hbox.addLayout(vbox0)
        hbox.addStretch(1)
        w = QWidget()
        vbox = QVBoxLayout(w)
        vbox.addLayout(hbox)
        vbox.addStretch()
        vbox.addWidget(self.invoices_label)
        vbox.addWidget(self.invoices_list)

        run_hook('create_send_tab', grid)
        return w

    def update_fee(self, is_fee):
        outputs = self.payto_e.get_outputs()
        amount = self.amount_e.get_amount()
        fee = self.fee_e.get_amount() if is_fee else None
        if amount is None:
            self.fee_e.setAmount(None)
            self.not_enough_funds = False
        else:
            if not outputs:
                addr = self.payto_e.payto_address if self.payto_e.payto_address else self.dummy_address
                outputs = [('address', addr, amount)]
            try:
                tx = self.wallet.make_unsigned_transaction(outputs, fee, coins = self.get_coins())
                self.not_enough_funds = False
            except NotEnoughFunds:
                self.not_enough_funds = True
            if not is_fee:
                fee = None if self.not_enough_funds else self.wallet.get_tx_fee(tx)
                self.fee_e.setAmount(fee)

    def update_fee_edit(self):
        b = self.config.get('can_edit_fees', False)
        self.fee_e.setVisible(b)
        self.fee_e_label.setVisible(b)

    def from_list_delete(self, item):
        i = self.from_list.indexOfTopLevelItem(item)
        self.pay_from.pop(i)
        self.redraw_from_list()

    def from_list_menu(self, position):
        item = self.from_list.itemAt(position)
        menu = QMenu()
        menu.addAction(_("Remove"), lambda: self.from_list_delete(item))
        menu.exec_(self.from_list.viewport().mapToGlobal(position))

    def set_pay_from(self, domain = None):
        self.pay_from = [] if domain == [] else self.wallet.get_unspent_coins(domain)
        self.redraw_from_list()

    def redraw_from_list(self):
        self.from_list.clear()
        self.from_label.setHidden(len(self.pay_from) == 0)
        self.from_list.setHidden(len(self.pay_from) == 0)

        def format(x):
            h = x.get('prevout_hash')
            return h[0:8] + '...' + h[-8:] + ":%d"%x.get('prevout_n') + u'\t' + "%s"%x.get('address')

        for item in self.pay_from:
            self.from_list.addTopLevelItem(QTreeWidgetItem( [format(item), self.format_amount(item['value']) ]))

    def update_completions(self):
        l = self.wallet.get_completions()
        self.completions.setStringList(l)


    def protected(func):
        return lambda s, *args: s.do_protect(func, args)


    def read_send_tab(self):

        if self.payment_request and self.payment_request.has_expired():
            QMessageBox.warning(self, _('Error'), _('Payment request has expired'), _('OK'))
            return

        label = unicode( self.message_e.text() )

        if self.payment_request:
            outputs = self.payment_request.get_outputs()
        else:
            errors = self.payto_e.get_errors()
            if errors:
                self.show_warning(_("Invalid Lines found:") + "\n\n" + '\n'.join([ _("Line #") + str(x[0]+1) + ": " + x[1] for x in errors]))
                return
            outputs = self.payto_e.get_outputs()

        if not outputs:
            QMessageBox.warning(self, _('Error'), _('No outputs'), _('OK'))
            return

        for _type, addr, amount in outputs:
            if addr is None:
                QMessageBox.warning(self, _('Error'), _('Litecoin Address is None'), _('OK'))
                return
            if _type == 'address' and not bitcoin.is_address(addr):
                QMessageBox.warning(self, _('Error'), _('Invalid Litecoin Address'), _('OK'))
                return
            if amount is None:
                QMessageBox.warning(self, _('Error'), _('Invalid Amount'), _('OK'))
                return

        fee = self.fee_e.get_amount()
        if fee is None:
            QMessageBox.warning(self, _('Error'), _('Invalid Fee'), _('OK'))
            return

        amount = sum(map(lambda x:x[2], outputs))
        confirm_amount = self.config.get('confirm_amount', 1000000000)
        if amount >= confirm_amount:
            o = '\n'.join(map(lambda x:x[1], outputs))
            if not self.question(_("send %(amount)s to %(address)s?")%{ 'amount' : self.format_amount(amount) + ' '+ self.base_unit(), 'address' : o}):
                return

        coins = self.get_coins()
        return outputs, fee, label, coins


    def do_send(self):
        if run_hook('before_send'):
            return
        r = self.read_send_tab()
        if not r:
            return
        outputs, fee, label, coins = r
        try:
            tx = self.wallet.make_unsigned_transaction(outputs, fee, None, coins = coins)
            if not tx:
                raise BaseException(_("Insufficient funds"))
        except Exception as e:
            traceback.print_exc(file=sys.stdout)
            self.show_message(str(e))
            return

        if tx.get_fee() < tx.required_fee(self.wallet.verifier):
            QMessageBox.warning(self, _('Error'), _("This transaction requires a higher fee, or it will not be propagated by the network."), _('OK'))
            return

        if not self.config.get('can_edit_fees', False):
            if not self.question(_("A fee of %(fee)s will be added to this transaction.\nProceed?")%{ 'fee' : self.format_amount(fee) + ' '+ self.base_unit()}):
                return
        else:
            confirm_fee = self.config.get('confirm_fee', 1000000)
            if fee >= confirm_fee:
                if not self.question(_("The fee for this transaction seems unusually high.\nAre you really sure you want to pay %(fee)s in fees?")%{ 'fee' : self.format_amount(fee) + ' '+ self.base_unit()}):
                    return

        self.send_tx(tx, label)


    @protected
    def send_tx(self, tx, label, password):
        self.send_button.setDisabled(True)

        # call hook to see if plugin needs gui interaction
        run_hook('send_tx', tx)

        # sign the tx
        def sign_thread():
            if self.wallet.is_watching_only():
                return tx
            self.wallet.sign_transaction(tx, password)
            return tx

        def sign_done(tx):
            if label and tx.is_complete():
                self.wallet.set_label(tx.hash(), label)
            if not tx.is_complete() or self.config.get('show_before_broadcast'):
                self.show_transaction(tx)
                self.do_clear()
                return
            self.broadcast_transaction(tx)

        # keep a reference to WaitingDialog or the gui might crash
        self.waiting_dialog = WaitingDialog(self, 'Signing..', sign_thread, sign_done, lambda: self.send_button.setDisabled(False))
        self.waiting_dialog.start()



    def broadcast_transaction(self, tx):

        def broadcast_thread():
            # non-GUI thread
            pr = self.payment_request
            key = pr.get_id()
            if pr is None:
                return self.wallet.sendtx(tx)
            if pr.has_expired():
                self.payment_request = None
                return False, _("Payment request has expired")
            status, msg =  self.wallet.sendtx(tx)
            if not status:
                return False, msg
            self.invoices.set_paid(key, tx.hash())
            self.payment_request = None
            refund_address = self.wallet.addresses()[0]
            ack_status, ack_msg = pr.send_ack(str(tx), refund_address)
            if ack_status:
                msg = ack_msg
            return status, msg

        def broadcast_done(status, msg):
            # GUI thread
            if status:
                QMessageBox.information(self, '', _('Payment sent.') + '\n' + msg, _('OK'))
                self.update_invoices_list()
                self.do_clear()
            else:
                QMessageBox.warning(self, _('Error'), msg, _('OK'))
            self.send_button.setDisabled(False)

        self.waiting_dialog = WaitingDialog(self, 'Broadcasting..', broadcast_thread, broadcast_done)
        self.waiting_dialog.start()



    def prepare_for_payment_request(self):
        self.tabs.setCurrentIndex(1)
        self.payto_e.is_pr = True
        for e in [self.payto_e, self.amount_e, self.message_e]:
            e.setFrozen(True)
        self.payto_e.setText(_("please wait..."))
        return True

    def payment_request_ok(self):
        pr = self.payment_request
        key = self.invoices.add(pr)
        status = self.invoices.get_status(key)
        self.update_invoices_list()
        if status == PR_PAID:
            self.show_message("invoice already paid")
            self.do_clear()
            self.payment_request = None
            return

        if not pr.has_expired():
            self.payto_e.setGreen()
        else:
            self.payto_e.setExpired()

        self.payto_e.setText(pr.get_requestor())
        self.amount_e.setText(self.format_amount(pr.get_amount()))
        self.message_e.setText(pr.get_memo())
        # signal to set fee
        self.amount_e.textEdited.emit("")

    def payment_request_error(self):
        self.do_clear()
        self.show_message(self.payment_request.error)
        self.payment_request = None

    def pay_from_URI(self,URI):
        if not URI:
            return
        try:
            address, amount, label, message, request_url = util.parse_URI(URI)
        except Exception as e:
            QMessageBox.warning(self, _('Error'), _('Invalid litecoin URI:') + '\n' + str(e), _('OK'))
            return

        self.tabs.setCurrentIndex(1)

        if not request_url:
            if label:
                if self.wallet.labels.get(address) != label:
                    if self.question(_('Save label "%(label)s" for address %(address)s ?'%{'label':label,'address':address})):
                        if address not in self.wallet.addressbook and not self.wallet.is_mine(address):
                            self.wallet.addressbook.append(address)
                            self.wallet.set_label(address, label)
            else:
                label = self.wallet.labels.get(address)
            if address:
                self.payto_e.setText(label + '  <'+ address +'>' if label else address)
            if message:
                self.message_e.setText(message)
            if amount:
                self.amount_e.setAmount(amount)
                self.amount_e.textEdited.emit("")
            return

        def get_payment_request_thread():
            self.payment_request = get_payment_request(request_url)
            if self.payment_request.verify():
                self.emit(SIGNAL('payment_request_ok'))
            else:
                self.emit(SIGNAL('payment_request_error'))

        t = threading.Thread(target=get_payment_request_thread)
        t.setDaemon(True)
        t.start()
        self.prepare_for_payment_request()



    def do_clear(self):
        self.not_enough_funds = False
        self.payto_e.is_pr = False
        for e in [self.payto_e, self.message_e, self.amount_e, self.fee_e]:
            e.setText('')
            e.setFrozen(False)

        self.set_pay_from([])
        self.update_status()
        run_hook('do_clear')


    def set_addrs_frozen(self,addrs,freeze):
        for addr in addrs:
            if not addr: continue
            if addr in self.wallet.frozen_addresses and not freeze:
                self.wallet.unfreeze(addr)
            elif addr not in self.wallet.frozen_addresses and freeze:
                self.wallet.freeze(addr)
        self.update_address_tab()

    def create_list_tab(self, l):
        w = QWidget()
        vbox = QVBoxLayout()
        w.setLayout(vbox)
        vbox.setMargin(0)
        vbox.setSpacing(0)
        vbox.addWidget(l)
        buttons = QWidget()
        vbox.addWidget(buttons)
        return w

    def create_addresses_tab(self):
        l = MyTreeWidget(self, self.create_receive_menu, [ _('Address'), _('Label'), _('Balance'), _('Tx')], [370, None, 130])
        l.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.address_list = l
        return self.create_list_tab(l)

    def create_contacts_tab(self):
        l = MyTreeWidget(self, self.create_contact_menu, [_('Address'), _('Label'), _('Tx')], [350, None])
        self.contacts_list = l
        return self.create_list_tab(l)

    def update_invoices_list(self):
        inv_list = self.invoices.sorted_list()
        l = self.invoices_list
        l.clear()
        for pr in inv_list:
            key = pr.get_id()
            status = self.invoices.get_status(key)
            requestor = pr.get_requestor()
            date_str = format_time(pr.get_expiration_date())
            item = QTreeWidgetItem( [ date_str, requestor, pr.memo, self.format_amount(pr.get_amount(), whitespaces=True), pr_tooltips.get(status,'')] )
            item.setIcon(4, QIcon(pr_icons.get(status)))
            item.setData(0, Qt.UserRole, key)
            item.setFont(1, QFont(MONOSPACE_FONT))
            item.setFont(3, QFont(MONOSPACE_FONT))
            l.addTopLevelItem(item)
        l.setCurrentItem(l.topLevelItem(0))
        self.invoices_list.setVisible(len(inv_list))
        self.invoices_label.setVisible(len(inv_list))

    def delete_imported_key(self, addr):
        if self.question(_("Do you want to remove")+" %s "%addr +_("from your wallet?")):
            self.wallet.delete_imported_key(addr)
            self.update_address_tab()
            self.update_history_tab()

    def edit_account_label(self, k):
        text, ok = QInputDialog.getText(self, _('Rename account'), _('Name') + ':', text = self.wallet.labels.get(k,''))
        if ok:
            label = unicode(text)
            self.wallet.set_label(k,label)
            self.update_address_tab()

    def account_set_expanded(self, item, k, b):
        item.setExpanded(b)
        self.accounts_expanded[k] = b

    def create_account_menu(self, position, k, item):
        menu = QMenu()
        exp = item.isExpanded()
        menu.addAction(_("Minimize") if exp else _("Maximize"), lambda: self.account_set_expanded(item, k, not exp))
        menu.addAction(_("Rename"), lambda: self.edit_account_label(k))
        if self.wallet.seed_version > 4:
            menu.addAction(_("View details"), lambda: self.show_account_details(k))
        if self.wallet.account_is_pending(k):
            menu.addAction(_("Delete"), lambda: self.delete_pending_account(k))
        menu.exec_(self.address_list.viewport().mapToGlobal(position))

    def delete_pending_account(self, k):
        self.wallet.delete_pending_account(k)
        self.update_address_tab()
        self.update_account_selector()

    def create_receive_menu(self, position):
        # fixme: this function apparently has a side effect.
        # if it is not called the menu pops up several times
        #self.address_list.selectedIndexes()

        selected = self.address_list.selectedItems()
        multi_select = len(selected) > 1
        addrs = [unicode(item.text(0)) for item in selected]
        if not multi_select:
            item = self.address_list.itemAt(position)
            if not item:
                return
            addr = addrs[0]
            if not is_valid(addr):
                k = str(item.data(0,32).toString())
                if k:
                    self.create_account_menu(position, k, item)
                else:
                    item.setExpanded(not item.isExpanded())
                return

        menu = QMenu()
        if not multi_select:
            menu.addAction(_("Copy to clipboard"), lambda: self.app.clipboard().setText(addr))
            menu.addAction(_("Request payment"), lambda: self.receive_at(addr))
            menu.addAction(_("Edit label"), lambda: self.address_list.edit_label(item))
            menu.addAction(_('History'), lambda: self.show_address(addr))
            menu.addAction(_('Public Keys'), lambda: self.show_public_keys(addr))
            if self.wallet.can_export():
                menu.addAction(_("Private key"), lambda: self.show_private_key(addr))
            if not self.wallet.is_watching_only():
                menu.addAction(_("Sign/verify message"), lambda: self.sign_verify_message(addr))
                menu.addAction(_("Encrypt/decrypt message"), lambda: self.encrypt_message(addr))
            if self.wallet.is_imported(addr):
                menu.addAction(_("Remove from wallet"), lambda: self.delete_imported_key(addr))

        if any(addr not in self.wallet.frozen_addresses for addr in addrs):
            menu.addAction(_("Freeze"), lambda: self.set_addrs_frozen(addrs, True))
        if any(addr in self.wallet.frozen_addresses for addr in addrs):
            menu.addAction(_("Unfreeze"), lambda: self.set_addrs_frozen(addrs, False))

        def can_send(addr):
            return addr not in self.wallet.frozen_addresses and self.wallet.get_addr_balance(addr) != (0, 0)
        if any(can_send(addr) for addr in addrs):
            menu.addAction(_("Send From"), lambda: self.send_from_addresses(addrs))

        run_hook('receive_menu', menu, addrs)
        menu.exec_(self.address_list.viewport().mapToGlobal(position))


    def get_sendable_balance(self):
        return sum(map(lambda x:x['value'], self.get_coins()))


    def get_coins(self):
        if self.pay_from:
            return self.pay_from
        else:
            domain = self.wallet.get_account_addresses(self.current_account)
            for i in self.wallet.frozen_addresses:
                if i in domain: domain.remove(i)
            return self.wallet.get_unspent_coins(domain)


    def send_from_addresses(self, addrs):
        self.set_pay_from( addrs )
        self.tabs.setCurrentIndex(1)


    def payto(self, addr):
        if not addr: return
        label = self.wallet.labels.get(addr)
        m_addr = label + '  <' + addr + '>' if label else addr
        self.tabs.setCurrentIndex(1)
        self.payto_e.setText(m_addr)
        self.amount_e.setFocus()


    def delete_contact(self, x):
        if self.question(_("Do you want to remove")+" %s "%x +_("from your list of contacts?")):
            self.wallet.delete_contact(x)
            self.wallet.set_label(x, None)
            self.update_history_tab()
            self.update_contacts_tab()
            self.update_completions()


    def create_contact_menu(self, position):
        item = self.contacts_list.itemAt(position)
        menu = QMenu()
        if not item:
            menu.addAction(_("New contact"), lambda: self.new_contact_dialog())
        else:
            addr = unicode(item.text(0))
            label = unicode(item.text(1))
            is_editable = item.data(0,32).toBool()
            payto_addr = item.data(0,33).toString()
            menu.addAction(_("Copy to Clipboard"), lambda: self.app.clipboard().setText(addr))
            menu.addAction(_("Pay to"), lambda: self.payto(payto_addr))
            menu.addAction(_("QR code"), lambda: self.show_qrcode("litecoin:" + addr, _("Address")))
            if is_editable:
                menu.addAction(_("Edit label"), lambda: self.contacts_list.edit_label(item))
                menu.addAction(_("Delete"), lambda: self.delete_contact(addr))

        run_hook('create_contact_menu', menu, item)
        menu.exec_(self.contacts_list.viewport().mapToGlobal(position))


    def show_invoice(self, key):
        pr = self.invoices.get(key)
        pr.verify()
        self.show_pr_details(pr)

    def show_pr_details(self, pr):
        d = QDialog(self)
        d.setWindowTitle(_("Invoice"))
        vbox = QVBoxLayout(d)
        grid = QGridLayout()
        grid.addWidget(QLabel(_("Requestor") + ':'), 0, 0)
        grid.addWidget(QLabel(pr.get_requestor()), 0, 1)
        grid.addWidget(QLabel(_("Expires") + ':'), 1, 0)
        grid.addWidget(QLabel(format_time(pr.get_expiration_date())), 1, 1)
        grid.addWidget(QLabel(_("Memo") + ':'), 2, 0)
        grid.addWidget(QLabel(pr.get_memo()), 2, 1)
        grid.addWidget(QLabel(_("Signature") + ':'), 3, 0)
        grid.addWidget(QLabel(pr.get_verify_status()), 3, 1)
        grid.addWidget(QLabel(_("Payment URL") + ':'), 4, 0)
        grid.addWidget(QLabel(pr.payment_url), 4, 1)
        grid.addWidget(QLabel(_("Outputs") + ':'), 5, 0)
        outputs_str = '\n'.join(map(lambda x: x[1] + ' ' + self.format_amount(x[2])+ self.base_unit(), pr.get_outputs()))
        grid.addWidget(QLabel(outputs_str), 5, 1)
        if pr.tx:
            grid.addWidget(QLabel(_("Transaction ID") + ':'), 6, 0)
            l = QLineEdit(pr.tx)
            l.setReadOnly(True)
            grid.addWidget(l, 6, 1)
        vbox.addLayout(grid)
        vbox.addLayout(Buttons(CloseButton(d)))
        d.exec_()
        return


    def do_pay_invoice(self, key):
        pr = self.invoices.get(key)
        self.payment_request = pr
        self.prepare_for_payment_request()
        if pr.verify():
            self.payment_request_ok()
        else:
            self.payment_request_error()


    def create_invoice_menu(self, position):
        item = self.invoices_list.itemAt(position)
        if not item:
            return
        key = str(item.data(0, 32).toString())
        pr = self.invoices.get(key)
        status = self.invoices.get_status(key)
        menu = QMenu()
        menu.addAction(_("Details"), lambda: self.show_invoice(key))
        if status == PR_UNPAID:
            menu.addAction(_("Pay Now"), lambda: self.do_pay_invoice(key))
        def delete_invoice(key):
            self.invoices.remove(key)
            self.update_invoices_list()
        menu.addAction(_("Delete"), lambda: delete_invoice(key))
        menu.exec_(self.invoices_list.viewport().mapToGlobal(position))


    def update_address_tab(self):
        l = self.address_list
        item = l.currentItem()
        current_address = item.data(0, Qt.UserRole).toString() if item else None
        l.clear()
        accounts = self.wallet.get_accounts()
        if self.current_account is None:
            account_items = sorted(accounts.items())
        else:
            account_items = [(self.current_account, accounts.get(self.current_account))]
        for k, account in account_items:
            if len(accounts) > 1:
                name = self.wallet.get_account_name(k)
                c, u = self.wallet.get_account_balance(k)
                account_item = QTreeWidgetItem( [ name, '', self.format_amount(c+u), ''] )
                l.addTopLevelItem(account_item)
                account_item.setExpanded(self.accounts_expanded.get(k, True))
                account_item.setData(0, Qt.UserRole, k)
            else:
                account_item = l
            sequences = [0,1] if account.has_change() else [0]
            for is_change in sequences:
                if len(sequences) > 1:
                    name = _("Receiving") if not is_change else _("Change")
                    seq_item = QTreeWidgetItem( [ name, '', '', '', ''] )
                    account_item.addChild(seq_item)
                    if not is_change:
                        seq_item.setExpanded(True)
                else:
                    seq_item = account_item
                used_item = QTreeWidgetItem( [ _("Used"), '', '', '', ''] )
                used_flag = False
                addr_list = account.get_addresses(is_change)
                for address in addr_list:
                    num, is_used = self.wallet.is_used(address)
                    label = self.wallet.labels.get(address,'')
                    c, u = self.wallet.get_addr_balance(address)
                    balance = self.format_amount(c + u)
                    item = QTreeWidgetItem( [ address, label, balance, "%d"%num] )
                    item.setFont(0, QFont(MONOSPACE_FONT))
                    item.setData(0, Qt.UserRole, address)
                    item.setData(0, Qt.UserRole+1, True) # label can be edited
                    if address in self.wallet.frozen_addresses:
                        item.setBackgroundColor(0, QColor('lightblue'))
                    if self.wallet.is_beyond_limit(address, account, is_change):
                        item.setBackgroundColor(0, QColor('red'))
                    if is_used:
                        if not used_flag:
                            seq_item.insertChild(0, used_item)
                            used_flag = True
                        used_item.addChild(item)
                    else:
                        seq_item.addChild(item)
                    if address == current_address:
                        l.setCurrentItem(item)


    def update_contacts_tab(self):
        l = self.contacts_list
        item = l.currentItem()
        current_address = item.data(0, Qt.UserRole).toString() if item else None
        l.clear()
        for address in self.wallet.addressbook:
            label = self.wallet.labels.get(address,'')
            n = self.wallet.get_num_tx(address)
            item = QTreeWidgetItem( [ address, label, "%d"%n] )
            item.setFont(0, QFont(MONOSPACE_FONT))
            item.setData(0, Qt.UserRole, address)
            item.setData(0, Qt.UserRole+1, True)
            l.addTopLevelItem(item)
            if address == current_address:
                l.setCurrentItem(item)
        run_hook('update_contacts_tab', l)


    def create_console_tab(self):
        from console import Console
        self.console = console = Console()
        return console


    def update_console(self):
        console = self.console
        console.history = self.config.get("console-history",[])
        console.history_index = len(console.history)

        console.updateNamespace({'wallet' : self.wallet, 'network' : self.network, 'gui':self})
        console.updateNamespace({'util' : util, 'bitcoin':bitcoin})

        c = commands.Commands(self.wallet, self.network, lambda: self.console.set_json(True))
        methods = {}
        def mkfunc(f, method):
            return lambda *args: apply( f, (method, args, self.password_dialog ))
        for m in dir(c):
            if m[0]=='_' or m in ['network','wallet']: continue
            methods[m] = mkfunc(c._run, m)

        console.updateNamespace(methods)


    def change_account(self,s):
        if s == _("All accounts"):
            self.current_account = None
        else:
            accounts = self.wallet.get_account_names()
            for k, v in accounts.items():
                if v == s:
                    self.current_account = k
        self.update_history_tab()
        self.update_status()
        self.update_address_tab()
        self.update_receive_tab()

    def create_status_bar(self):

        sb = QStatusBar()
        sb.setFixedHeight(35)
        qtVersion = qVersion()

        self.balance_label = QLabel("")
        sb.addWidget(self.balance_label)

        from version_getter import UpdateLabel
        self.updatelabel = UpdateLabel(self.config, sb)

        self.account_selector = QComboBox()
        self.account_selector.setSizeAdjustPolicy(QComboBox.AdjustToContents)
        self.connect(self.account_selector,SIGNAL("activated(QString)"),self.change_account)
        sb.addPermanentWidget(self.account_selector)

        if (int(qtVersion[0]) >= 4 and int(qtVersion[2]) >= 7):
            sb.addPermanentWidget( StatusBarButton( QIcon(":icons/switchgui.png"), _("Switch to Lite Mode"), self.go_lite ) )

        self.lock_icon = QIcon()
        self.password_button = StatusBarButton( self.lock_icon, _("Password"), self.change_password_dialog )
        sb.addPermanentWidget( self.password_button )

        sb.addPermanentWidget( StatusBarButton( QIcon(":icons/preferences.png"), _("Preferences"), self.settings_dialog ) )
        self.seed_button = StatusBarButton( QIcon(":icons/seed.png"), _("Seed"), self.show_seed_dialog )
        sb.addPermanentWidget( self.seed_button )
        self.status_button = StatusBarButton( QIcon(":icons/status_disconnected.png"), _("Network"), self.run_network_dialog )
        sb.addPermanentWidget( self.status_button )

        run_hook('create_status_bar', sb)

        self.setStatusBar(sb)


    def update_lock_icon(self):
        icon = QIcon(":icons/lock.png") if self.wallet.use_encryption else QIcon(":icons/unlock.png")
        self.password_button.setIcon( icon )


    def update_buttons_on_seed(self):
        self.seed_button.setVisible(self.wallet.has_seed())
        self.password_button.setVisible(self.wallet.can_change_password())
        self.send_button.setText(_("Create unsigned transaction") if self.wallet.is_watching_only() else _("Send"))


    def change_password_dialog(self):
        from password_dialog import PasswordDialog
        d = PasswordDialog(self.wallet, self)
        d.run()
        self.update_lock_icon()


    def new_contact_dialog(self):

        d = QDialog(self)
        d.setWindowTitle(_("New Contact"))
        vbox = QVBoxLayout(d)
        vbox.addWidget(QLabel(_('New Contact')+':'))

        grid = QGridLayout()
        line1 = QLineEdit()
        line2 = QLineEdit()
        grid.addWidget(QLabel(_("Address")), 1, 0)
        grid.addWidget(line1, 1, 1)
        grid.addWidget(QLabel(_("Name")), 2, 0)
        grid.addWidget(line2, 2, 1)

        vbox.addLayout(grid)
        vbox.addLayout(Buttons(CancelButton(d), OkButton(d)))

        if not d.exec_():
            return

        address = str(line1.text())
        label = unicode(line2.text())

        if not is_valid(address):
            QMessageBox.warning(self, _('Error'), _('Invalid Address'), _('OK'))
            return

        self.wallet.add_contact(address)
        if label:
            self.wallet.set_label(address, label)

        self.update_contacts_tab()
        self.update_history_tab()
        self.update_completions()
        self.tabs.setCurrentIndex(3)


    @protected
    def new_account_dialog(self, password):
        dialog = QDialog(self)
        dialog.setModal(1)
        dialog.setWindowTitle(_("New Account"))
        vbox = QVBoxLayout()
        vbox.addWidget(QLabel(_('Account name')+':'))
        e = QLineEdit()
        vbox.addWidget(e)
        msg = _("Note: Newly created accounts are 'pending' until they receive litecoins.") + " " \
            + _("You will need to wait for 2 confirmations until the correct balance is displayed and more addresses are created for that account.")
        l = QLabel(msg)
        l.setWordWrap(True)
        vbox.addWidget(l)
        vbox.addLayout(Buttons(CancelButton(dialog), OkButton(dialog)))
        dialog.setLayout(vbox)
        r = dialog.exec_()
        if not r:
            return
        name = str(e.text())
        self.wallet.create_pending_account(name, password)
        self.update_address_tab()
        self.update_account_selector()
        self.tabs.setCurrentIndex(3)


    def show_master_public_keys(self):

        dialog = QDialog(self)
        dialog.setModal(1)
        dialog.setWindowTitle(_("Master Public Keys"))

        mpk_dict = self.wallet.get_master_public_keys()
        vbox = QVBoxLayout()
        # only show the combobox in case multiple accounts are available
        if len(mpk_dict) > 1:
            gb = QGroupBox(_("Master Public Keys"))
            vbox.addWidget(gb)
            group = QButtonGroup()
            first_button = None
            for key in sorted(mpk_dict.keys()):
                is_mine = self.wallet.master_private_keys.has_key(key)
                b = QRadioButton(gb)
                name = 'Self' if is_mine else 'Cosigner'
                b.setText(name + ' (%s)'%key)
                b.key = key
                group.addButton(b)
                vbox.addWidget(b)
                if not first_button:
                    first_button = b

            mpk_text = ShowQRTextEdit()
            mpk_text.setMaximumHeight(170)
            vbox.addWidget(mpk_text)

            def show_mpk(b):
                mpk = mpk_dict.get(b.key, "")
                mpk_text.setText(mpk)

            group.buttonReleased.connect(show_mpk)
            first_button.setChecked(True)
            show_mpk(first_button)
        elif len(mpk_dict) == 1:
            mpk = mpk_dict.values()[0]
            mpk_text = ShowQRTextEdit(text=mpk)
            mpk_text.setMaximumHeight(170)
            vbox.addWidget(mpk_text)

        mpk_text.addCopyButton(self.app)
        vbox.addLayout(Buttons(CloseButton(dialog)))
        dialog.setLayout(vbox)
        dialog.exec_()

    @protected
    def show_seed_dialog(self, password):
        if not self.wallet.has_seed():
            QMessageBox.information(self, _('Message'), _('This wallet has no seed'), _('OK'))
            return

        try:
            mnemonic = self.wallet.get_mnemonic(password)
        except BaseException as e:
            QMessageBox.warning(self, _('Error'), str(e), _('OK'))
            return
        from seed_dialog import SeedDialog
        d = SeedDialog(self, mnemonic, self.wallet.has_imported_keys())
        d.exec_()



    def show_qrcode(self, data, title = _("QR code")):
        if not data:
            return
        d = QRDialog(data, self, title)
        d.exec_()


    def do_protect(self, func, args):
        if self.wallet.use_encryption:
            while True:
                password = self.password_dialog()
                if not password:
                    return
                try:
                    self.wallet.check_password(password)
                    break
                except Exception as e:
                    QMessageBox.warning(self, _('Error'), str(e), _('OK'))
                    continue
        else:
            password = None

        if args != (False,):
            args = (self,) + args + (password,)
        else:
            args = (self, password)
        apply(func, args)


    def show_public_keys(self, address):
        if not address: return
        try:
            pubkey_list = self.wallet.get_public_keys(address)
        except Exception as e:
            traceback.print_exc(file=sys.stdout)
            self.show_message(str(e))
            return

        d = QDialog(self)
        d.setMinimumSize(600, 200)
        d.setModal(1)
        d.setWindowTitle(_("Public key"))
        vbox = QVBoxLayout()
        vbox.addWidget( QLabel(_("Address") + ': ' + address))
        vbox.addWidget( QLabel(_("Public key") + ':'))
        keys_e = ShowQRTextEdit(text='\n'.join(pubkey_list))
        keys_e.addCopyButton(self.app)
        vbox.addWidget(keys_e)
        vbox.addLayout(Buttons(CloseButton(d)))
        d.setLayout(vbox)
        d.exec_()

    @protected
    def show_private_key(self, address, password):
        if not address: return
        try:
            pk_list = self.wallet.get_private_key(address, password)
        except Exception as e:
            traceback.print_exc(file=sys.stdout)
            self.show_message(str(e))
            return

        d = QDialog(self)
        d.setMinimumSize(600, 200)
        d.setModal(1)
        d.setWindowTitle(_("Private key"))
        vbox = QVBoxLayout()
        vbox.addWidget( QLabel(_("Address") + ': ' + address))
        vbox.addWidget( QLabel(_("Private key") + ':'))
        keys_e = ShowQRTextEdit(text='\n'.join(pk_list))
        keys_e.addCopyButton(self.app)
        vbox.addWidget(keys_e)
        vbox.addLayout(Buttons(CloseButton(d)))
        d.setLayout(vbox)
        d.exec_()


    @protected
    def do_sign(self, address, message, signature, password):
        message = unicode(message.toPlainText())
        message = message.encode('utf-8')
        try:
            sig = self.wallet.sign_message(str(address.text()), message, password)
            signature.setText(sig)
        except Exception as e:
            self.show_message(str(e))

    def do_verify(self, address, message, signature):
        message = unicode(message.toPlainText())
        message = message.encode('utf-8')
        if bitcoin.verify_message(address.text(), str(signature.toPlainText()), message):
            self.show_message(_("Signature verified"))
        else:
            self.show_message(_("Error: wrong signature"))


    def sign_verify_message(self, address=''):
        d = QDialog(self)
        d.setModal(1)
        d.setWindowTitle(_('Sign/verify Message'))
        d.setMinimumSize(410, 290)

        layout = QGridLayout(d)

        message_e = QTextEdit()
        layout.addWidget(QLabel(_('Message')), 1, 0)
        layout.addWidget(message_e, 1, 1)
        layout.setRowStretch(2,3)

        address_e = QLineEdit()
        address_e.setText(address)
        layout.addWidget(QLabel(_('Address')), 2, 0)
        layout.addWidget(address_e, 2, 1)

        signature_e = QTextEdit()
        layout.addWidget(QLabel(_('Signature')), 3, 0)
        layout.addWidget(signature_e, 3, 1)
        layout.setRowStretch(3,1)

        hbox = QHBoxLayout()

        b = QPushButton(_("Sign"))
        b.clicked.connect(lambda: self.do_sign(address_e, message_e, signature_e))
        hbox.addWidget(b)

        b = QPushButton(_("Verify"))
        b.clicked.connect(lambda: self.do_verify(address_e, message_e, signature_e))
        hbox.addWidget(b)

        b = QPushButton(_("Close"))
        b.clicked.connect(d.accept)
        hbox.addWidget(b)
        layout.addLayout(hbox, 4, 1)
        d.exec_()


    @protected
    def do_decrypt(self, message_e, pubkey_e, encrypted_e, password):
        try:
            decrypted = self.wallet.decrypt_message(str(pubkey_e.text()), str(encrypted_e.toPlainText()), password)
            message_e.setText(decrypted)
        except BaseException as e:
            traceback.print_exc(file=sys.stdout)
            self.show_warning(str(e))


    def do_encrypt(self, message_e, pubkey_e, encrypted_e):
        message = unicode(message_e.toPlainText())
        message = message.encode('utf-8')
        try:
            encrypted = bitcoin.encrypt_message(message, str(pubkey_e.text()))
            encrypted_e.setText(encrypted)
        except BaseException as e:
            traceback.print_exc(file=sys.stdout)
            self.show_warning(str(e))


    def encrypt_message(self, address = ''):
        d = QDialog(self)
        d.setModal(1)
        d.setWindowTitle(_('Encrypt/decrypt Message'))
        d.setMinimumSize(610, 490)

        layout = QGridLayout(d)

        message_e = QTextEdit()
        layout.addWidget(QLabel(_('Message')), 1, 0)
        layout.addWidget(message_e, 1, 1)
        layout.setRowStretch(2,3)

        pubkey_e = QLineEdit()
        if address:
            pubkey = self.wallet.get_public_keys(address)[0]
            pubkey_e.setText(pubkey)
        layout.addWidget(QLabel(_('Public key')), 2, 0)
        layout.addWidget(pubkey_e, 2, 1)

        encrypted_e = QTextEdit()
        layout.addWidget(QLabel(_('Encrypted')), 3, 0)
        layout.addWidget(encrypted_e, 3, 1)
        layout.setRowStretch(3,1)

        hbox = QHBoxLayout()
        b = QPushButton(_("Encrypt"))
        b.clicked.connect(lambda: self.do_encrypt(message_e, pubkey_e, encrypted_e))
        hbox.addWidget(b)

        b = QPushButton(_("Decrypt"))
        b.clicked.connect(lambda: self.do_decrypt(message_e, pubkey_e, encrypted_e))
        hbox.addWidget(b)

        b = QPushButton(_("Close"))
        b.clicked.connect(d.accept)
        hbox.addWidget(b)

        layout.addLayout(hbox, 4, 1)
        d.exec_()


    def question(self, msg):
        return QMessageBox.question(self, _('Message'), msg, QMessageBox.Yes | QMessageBox.No, QMessageBox.No) == QMessageBox.Yes

    def show_message(self, msg):
        QMessageBox.information(self, _('Message'), msg, _('OK'))

    def show_warning(self, msg):
        QMessageBox.warning(self, _('Warning'), msg, _('OK'))

    def password_dialog(self, msg=None):
        d = QDialog(self)
        d.setModal(1)
        d.setWindowTitle(_("Enter Password"))

        pw = QLineEdit()
        pw.setEchoMode(2)

        vbox = QVBoxLayout()
        if not msg:
            msg = _('Please enter your password')
        vbox.addWidget(QLabel(msg))

        grid = QGridLayout()
        grid.setSpacing(8)
        grid.addWidget(QLabel(_('Password')), 1, 0)
        grid.addWidget(pw, 1, 1)
        vbox.addLayout(grid)

        vbox.addLayout(Buttons(CancelButton(d), OkButton(d)))
        d.setLayout(vbox)

        run_hook('password_dialog', pw, grid, 1)
        if not d.exec_(): return
        return unicode(pw.text())








    def tx_from_text(self, txt):
        "json or raw hexadecimal"
        try:
            txt.decode('hex')
            is_hex = True
        except:
            is_hex = False

        if is_hex:
            try:
                return Transaction(txt)
            except:
                traceback.print_exc(file=sys.stdout)
                QMessageBox.critical(None, _("Unable to parse transaction"), _("Electrum was unable to parse your transaction"))
                return

        try:
            tx_dict = json.loads(str(txt))
            assert "hex" in tx_dict.keys()
            tx = Transaction(tx_dict["hex"])
            #if tx_dict.has_key("input_info"):
            #    input_info = json.loads(tx_dict['input_info'])
            #    tx.add_input_info(input_info)
            return tx
        except Exception:
            traceback.print_exc(file=sys.stdout)
            QMessageBox.critical(None, _("Unable to parse transaction"), _("Electrum was unable to parse your transaction"))


    def read_tx_from_qrcode(self):
        from electrum_ltc import qrscanner
        try:
            data = qrscanner.scan_qr(self.config)
        except BaseException, e:
            QMessageBox.warning(self, _('Error'), _(e), _('OK'))
            return
        if not data:
            return
        # if the user scanned a bitcoin URI
        if data.startswith("litecoin:"):
            self.pay_from_URI(data)
            return
        # else if the user scanned an offline signed tx
        # transactions are binary, but qrcode seems to return utf8...
        data = data.decode('utf8')
        z = bitcoin.base_decode(data, length=None, base=43)
        data = ''.join(chr(ord(b)) for b in z).encode('hex')
        tx = self.tx_from_text(data)
        if not tx:
            return
        self.show_transaction(tx)


    def read_tx_from_file(self):
        fileName = self.getOpenFileName(_("Select your transaction file"), "*.txn")
        if not fileName:
            return
        try:
            with open(fileName, "r") as f:
                file_content = f.read()
        except (ValueError, IOError, os.error), reason:
            QMessageBox.critical(None, _("Unable to read file or no transaction found"), _("Electrum was unable to open your transaction file") + "\n" + str(reason))

        return self.tx_from_text(file_content)


    @protected
    def sign_raw_transaction(self, tx, password):
        try:
            self.wallet.sign_transaction(tx, password)
        except Exception as e:
            traceback.print_exc(file=sys.stdout)
            QMessageBox.warning(self, _("Error"), str(e))

    def do_process_from_text(self):
        text = text_dialog(self, _('Input raw transaction'), _("Transaction:"), _("Load transaction"))
        if not text:
            return
        tx = self.tx_from_text(text)
        if tx:
            self.show_transaction(tx)

    def do_process_from_file(self):
        tx = self.read_tx_from_file()
        if tx:
            self.show_transaction(tx)

    def do_process_from_txid(self):
        from electrum_ltc import transaction
        txid, ok = QInputDialog.getText(self, _('Lookup transaction'), _('Transaction ID') + ':')
        if ok and txid:
            r = self.network.synchronous_get([ ('blockchain.transaction.get',[str(txid)]) ])[0]
            if r:
                tx = transaction.Transaction(r)
                if tx:
                    self.show_transaction(tx)
                else:
                    self.show_message("unknown transaction")

    def do_process_from_csvReader(self, csvReader):
        outputs = []
        errors = []
        errtext = ""
        try:
            for position, row in enumerate(csvReader):
                address = row[0]
                if not bitcoin.is_address(address):
                    errors.append((position, address))
                    continue
                amount = Decimal(row[1])
                amount = int(100000000*amount)
                outputs.append(('address', address, amount))
        except (ValueError, IOError, os.error), reason:
            QMessageBox.critical(None, _("Unable to read file or no transaction found"), _("Electrum was unable to open your transaction file") + "\n" + str(reason))
            return
        if errors != []:
            for x in errors:
                errtext += "CSV Row " + str(x[0]+1) + ": " + x[1] + "\n"
            QMessageBox.critical(None, _("Invalid Addresses"), _("ABORTING! Invalid Addresses found:") + "\n\n" + errtext)
            return

        try:
            tx = self.wallet.make_unsigned_transaction(outputs, None, None)
        except Exception as e:
            self.show_message(str(e))
            return

        self.show_transaction(tx)

    def do_process_from_csv_file(self):
        fileName = self.getOpenFileName(_("Select your transaction CSV"), "*.csv")
        if not fileName:
            return
        try:
            with open(fileName, "r") as f:
                csvReader = csv.reader(f)
                self.do_process_from_csvReader(csvReader)
        except (ValueError, IOError, os.error), reason:
            QMessageBox.critical(None, _("Unable to read file or no transaction found"), _("Electrum was unable to open your transaction file") + "\n" + str(reason))
            return

    def do_process_from_csv_text(self):
        text = text_dialog(self, _('Input CSV'), _("Please enter a list of outputs.") + '\n' \
                               + _("Format: address, amount. One output per line"), _("Load CSV"))
        if not text:
            return
        f = StringIO.StringIO(text)
        csvReader = csv.reader(f)
        self.do_process_from_csvReader(csvReader)



    @protected
    def export_privkeys_dialog(self, password):
        if self.wallet.is_watching_only():
            self.show_message(_("This is a watching-only wallet"))
            return

        try:
            self.wallet.check_password(password)
        except Exception as e:
            QMessageBox.warning(self, _('Error'), str(e), _('OK'))
            return

        d = QDialog(self)
        d.setWindowTitle(_('Private keys'))
        d.setMinimumSize(850, 300)
        vbox = QVBoxLayout(d)

        msg = "%s\n%s\n%s" % (_("WARNING: ALL your private keys are secret."),
                              _("Exposing a single private key can compromise your entire wallet!"),
                              _("In particular, DO NOT use 'redeem private key' services proposed by third parties."))
        vbox.addWidget(QLabel(msg))

        e = QTextEdit()
        e.setReadOnly(True)
        vbox.addWidget(e)

        defaultname = 'electrum-ltc-private-keys.csv'
        select_msg = _('Select file to export your private keys to')
        hbox, filename_e, csv_button = filename_field(self, self.config, defaultname, select_msg)
        vbox.addLayout(hbox)

        b = OkButton(d, _('Export'))
        b.setEnabled(False)
        vbox.addLayout(Buttons(CancelButton(d), b))

        private_keys = {}
        addresses = self.wallet.addresses(True)
        done = False
        def privkeys_thread():
            for addr in addresses:
                time.sleep(0.1)
                if done:
                    break
                private_keys[addr] = "\n".join(self.wallet.get_private_key(addr, password))
                d.emit(SIGNAL('computing_privkeys'))
            d.emit(SIGNAL('show_privkeys'))

        def show_privkeys():
            s = "\n".join( map( lambda x: x[0] + "\t"+ x[1], private_keys.items()))
            e.setText(s)
            b.setEnabled(True)

        d.connect(d, QtCore.SIGNAL('computing_privkeys'), lambda: e.setText("Please wait... %d/%d"%(len(private_keys),len(addresses))))
        d.connect(d, QtCore.SIGNAL('show_privkeys'), show_privkeys)
        threading.Thread(target=privkeys_thread).start()

        if not d.exec_():
            done = True
            return

        filename = filename_e.text()
        if not filename:
            return

        try:
            self.do_export_privkeys(filename, private_keys, csv_button.isChecked())
        except (IOError, os.error), reason:
            export_error_label = _("Electrum was unable to produce a private key-export.")
            QMessageBox.critical(None, _("Unable to create csv"), export_error_label + "\n" + str(reason))

        except Exception as e:
            self.show_message(str(e))
            return

        self.show_message(_("Private keys exported."))


    def do_export_privkeys(self, fileName, pklist, is_csv):
        with open(fileName, "w+") as f:
            if is_csv:
                transaction = csv.writer(f)
                transaction.writerow(["address", "private_key"])
                for addr, pk in pklist.items():
                    transaction.writerow(["%34s"%addr,pk])
            else:
                import json
                f.write(json.dumps(pklist, indent = 4))


    def do_import_labels(self):
        labelsFile = self.getOpenFileName(_("Open labels file"), "*.dat")
        if not labelsFile: return
        try:
            f = open(labelsFile, 'r')
            data = f.read()
            f.close()
            for key, value in json.loads(data).items():
                self.wallet.set_label(key, value)
            QMessageBox.information(None, _("Labels imported"), _("Your labels were imported from")+" '%s'" % str(labelsFile))
        except (IOError, os.error), reason:
            QMessageBox.critical(None, _("Unable to import labels"), _("Electrum was unable to import your labels.")+"\n" + str(reason))


    def do_export_labels(self):
        labels = self.wallet.labels
        try:
            fileName = self.getSaveFileName(_("Select file to save your labels"), 'electrum-ltc_labels.dat', "*.dat")
            if fileName:
                with open(fileName, 'w+') as f:
                    json.dump(labels, f)
                QMessageBox.information(None, _("Labels exported"), _("Your labels where exported to")+" '%s'" % str(fileName))
        except (IOError, os.error), reason:
            QMessageBox.critical(None, _("Unable to export labels"), _("Electrum was unable to export your labels.")+"\n" + str(reason))


    def export_history_dialog(self):
        d = QDialog(self)
        d.setWindowTitle(_('Export History'))
        d.setMinimumSize(400, 200)
        vbox = QVBoxLayout(d)
        defaultname = os.path.expanduser('~/electrum-ltc-history.csv')
        select_msg = _('Select file to export your wallet transactions to')
        hbox, filename_e, csv_button = filename_field(self, self.config, defaultname, select_msg)
        vbox.addLayout(hbox)
        vbox.addStretch(1)
        hbox = Buttons(CancelButton(d), OkButton(d, _('Export')))
        vbox.addLayout(hbox)
        run_hook('export_history_dialog', self, hbox)
        self.update()
        if not d.exec_():
            return
        filename = filename_e.text()
        if not filename:
            return
        try:
            self.do_export_history(self.wallet, filename, csv_button.isChecked())
        except (IOError, os.error), reason:
            export_error_label = _("Electrum was unable to produce a transaction export.")
            QMessageBox.critical(self, _("Unable to export history"), export_error_label + "\n" + str(reason))
            return
        QMessageBox.information(self,_("History exported"), _("Your wallet history has been successfully exported."))


    def do_export_history(self, wallet, fileName, is_csv):
        history = wallet.get_history()
        lines = []
        for item in history:
            tx_hash, confirmations, value, timestamp, balance = item
            if confirmations:
                if timestamp is not None:
                    time_string = format_time(timestamp)
                else:
                    time_string = "unknown"
            else:
                time_string = "pending"

            if value is not None:
                value_string = format_satoshis(value, True)
            else:
                value_string = '--'

            if tx_hash:
                label, is_default_label = wallet.get_label(tx_hash)
                label = label.encode('utf-8')
            else:
                label = ""

            if is_csv:
                lines.append([tx_hash, label, confirmations, value_string, time_string])
            else:
                lines.append({'txid':tx_hash, 'date':"%16s"%time_string, 'label':label, 'value':value_string})

        with open(fileName, "w+") as f:
            if is_csv:
                transaction = csv.writer(f, lineterminator='\n')
                transaction.writerow(["transaction_hash","label", "confirmations", "value", "timestamp"])
                for line in lines:
                    transaction.writerow(line)
            else:
                import json
                f.write(json.dumps(lines, indent = 4))


    def sweep_key_dialog(self):
        d = QDialog(self)
        d.setWindowTitle(_('Sweep private keys'))
        d.setMinimumSize(600, 300)

        vbox = QVBoxLayout(d)
        vbox.addWidget(QLabel(_("Enter private keys")))

        keys_e = QTextEdit()
        keys_e.setTabChangesFocus(True)
        vbox.addWidget(keys_e)

        h, address_e = address_field(self.wallet.addresses(False))
        vbox.addLayout(h)

        vbox.addStretch(1)
        button = OkButton(d, _('Sweep'))
        vbox.addLayout(Buttons(CancelButton(d), button))
        button.setEnabled(False)

        def get_address():
            addr = str(address_e.text())
            if bitcoin.is_address(addr):
                return addr

        def get_pk():
            pk = str(keys_e.toPlainText()).strip()
            if Wallet.is_private_key(pk):
                return pk.split()

        f = lambda: button.setEnabled(get_address() is not None and get_pk() is not None)
        keys_e.textChanged.connect(f)
        address_e.textChanged.connect(f)
        if not d.exec_():
            return

        fee = self.wallet.fee_per_kb
        tx = Transaction.sweep(get_pk(), self.network, get_address(), fee)
        self.show_transaction(tx)


    @protected
    def do_import_privkey(self, password):
        if not self.wallet.has_imported_keys():
            r = QMessageBox.question(None, _('Warning'), '<b>'+_('Warning') +':\n</b><br/>'+ _('Imported keys are not recoverable from seed.') + ' ' \
                                         + _('If you ever need to restore your wallet from its seed, these keys will be lost.') + '<p>' \
                                         + _('Are you sure you understand what you are doing?'), 3, 4)
            if r == 4: return

        text = text_dialog(self, _('Import private keys'), _("Enter private keys")+':', _("Import"))
        if not text: return

        text = str(text).split()
        badkeys = []
        addrlist = []
        for key in text:
            try:
                addr = self.wallet.import_key(key, password)
            except Exception as e:
                badkeys.append(key)
                continue
            if not addr:
                badkeys.append(key)
            else:
                addrlist.append(addr)
        if addrlist:
            QMessageBox.information(self, _('Information'), _("The following addresses were added") + ':\n' + '\n'.join(addrlist))
        if badkeys:
            QMessageBox.critical(self, _('Error'), _("The following inputs could not be imported") + ':\n'+ '\n'.join(badkeys))
        self.update_address_tab()
        self.update_history_tab()


    def settings_dialog(self):
        self.need_restart = False
        d = QDialog(self)
        d.setWindowTitle(_('Electrum Settings'))
        d.setModal(1)
        vbox = QVBoxLayout()
        grid = QGridLayout()
        grid.setColumnStretch(0,1)
        widgets = []

        lang_label = QLabel(_('Language') + ':')
        lang_help = HelpButton(_('Select which language is used in the GUI (after restart).'))
        lang_combo = QComboBox()
        from electrum_ltc.i18n import languages
        lang_combo.addItems(languages.values())
        try:
            index = languages.keys().index(self.config.get("language",''))
        except Exception:
            index = 0
        lang_combo.setCurrentIndex(index)
        if not self.config.is_modifiable('language'):
            for w in [lang_combo, lang_label]: w.setEnabled(False)
        def on_lang(x):
            lang_request = languages.keys()[lang_combo.currentIndex()]
            if lang_request != self.config.get('language'):
                self.config.set_key("language", lang_request, True)
                self.need_restart = True
        lang_combo.currentIndexChanged.connect(on_lang)
        widgets.append((lang_label, lang_combo, lang_help))

        nz_label = QLabel(_('Zeros after decimal point') + ':')
        nz_help = HelpButton(_('Number of zeros displayed after the decimal point. For example, if this is set to 2, "1." will be displayed as "1.00"'))
        nz = QSpinBox()
        nz.setMinimum(0)
        nz.setMaximum(self.decimal_point)
        nz.setValue(self.num_zeros)
        if not self.config.is_modifiable('num_zeros'):
            for w in [nz, nz_label]: w.setEnabled(False)
        def on_nz():
            value = nz.value()
            if self.num_zeros != value:
                self.num_zeros = value
                self.config.set_key('num_zeros', value, True)
                self.update_history_tab()
                self.update_address_tab()
        nz.valueChanged.connect(on_nz)
        widgets.append((nz_label, nz, nz_help))

        fee_label = QLabel(_('Transaction fee per kb') + ':')
        fee_help = HelpButton(_('Fee per kilobyte of transaction.') + '\n' \
                              + _('Recommended value') + ': ' + self.format_amount(bitcoin.RECOMMENDED_FEE) + ' ' + self.base_unit())
        fee_e = BTCAmountEdit(self.get_decimal_point)
        fee_e.setAmount(self.wallet.fee_per_kb)
        if not self.config.is_modifiable('fee_per_kb'):
            for w in [fee_e, fee_label]: w.setEnabled(False)
        def on_fee():
            fee = fee_e.get_amount()
            self.wallet.set_fee(fee)
        fee_e.editingFinished.connect(on_fee)
        widgets.append((fee_label, fee_e, fee_help))

        units = ['LTC', 'mLTC', 'bits']
        unit_label = QLabel(_('Base unit') + ':')
        unit_combo = QComboBox()
        unit_combo.addItems(units)
        unit_combo.setCurrentIndex(units.index(self.base_unit()))
        msg = _('Base unit of your wallet.')\
              + '\n1BTC=1000mLTC.\n' \
              + _(' These settings affects the fields in the Send tab')+' '
        unit_help = HelpButton(msg)
        def on_unit(x):
            unit_result = units[unit_combo.currentIndex()]
            if self.base_unit() == unit_result:
                return
            if unit_result == 'LTC':
                self.decimal_point = 8
            elif unit_result == 'mLTC':
                self.decimal_point = 5
            elif unit_result == 'bits':
                self.decimal_point = 2
            else:
                raise Exception('Unknown base unit')
            self.config.set_key('decimal_point', self.decimal_point, True)
            self.update_history_tab()
            self.update_receive_tab()
            self.update_address_tab()
            fee_e.setAmount(self.wallet.fee_per_kb)
            self.update_status()
        unit_combo.currentIndexChanged.connect(on_unit)
        widgets.append((unit_label, unit_combo, unit_help))

        block_explorers = ['explorer.litecoin.net', 'block-explorer.com', 'Blockr.io', 'SoChain']
        block_ex_label = QLabel(_('Online Block Explorer') + ':')
        block_ex_combo = QComboBox()
        block_ex_combo.addItems(block_explorers)
        block_ex_combo.setCurrentIndex(block_explorers.index(self.config.get('block_explorer', 'explorer.litecoin.net')))
        block_ex_help = HelpButton(_('Choose which online block explorer to use for functions that open a web browser'))
        def on_be(x):
            be_result = block_explorers[block_ex_combo.currentIndex()]
            self.config.set_key('block_explorer', be_result, True)
        block_ex_combo.currentIndexChanged.connect(on_be)
        widgets.append((block_ex_label, block_ex_combo, block_ex_help))

        from electrum_ltc import qrscanner
        system_cameras = qrscanner._find_system_cameras()
        qr_combo = QComboBox()
        qr_combo.addItem("Default","default")
        for camera, device in system_cameras.items():
            qr_combo.addItem(camera, device)
        #combo.addItem("Manually specify a device", config.get("video_device"))
        index = qr_combo.findData(self.config.get("video_device"))
        qr_combo.setCurrentIndex(index)
        qr_label = QLabel(_('Video Device') + ':')
        qr_combo.setEnabled(qrscanner.zbar is not None)
        qr_help = HelpButton(_("Install the zbar package to enable this.\nOn linux, type: 'apt-get install python-zbar'"))
        on_video_device = lambda x: self.config.set_key("video_device", str(qr_combo.itemData(x).toString()), True)
        qr_combo.currentIndexChanged.connect(on_video_device)
        widgets.append((qr_label, qr_combo, qr_help))

        usechange_cb = QCheckBox(_('Use change addresses'))
        usechange_cb.setChecked(self.wallet.use_change)
        usechange_help = HelpButton(_('Using change addresses makes it more difficult for other people to track your transactions.'))
        if not self.config.is_modifiable('use_change'): usechange_cb.setEnabled(False)
        def on_usechange(x):
            usechange_result = x == Qt.Checked
            if self.wallet.use_change != usechange_result:
                self.wallet.use_change = usechange_result
                self.wallet.storage.put('use_change', self.wallet.use_change)
        usechange_cb.stateChanged.connect(on_usechange)
        widgets.append((usechange_cb, None, usechange_help))

        showtx_cb = QCheckBox(_('Show transaction before broadcast'))
        showtx_cb.setChecked(self.config.get('show_before_broadcast', False))
        showtx_cb.stateChanged.connect(lambda x: self.config.set_key('show_before_broadcast', showtx_cb.isChecked()))
        showtx_help = HelpButton(_('Display the details of your transactions before broadcasting it.'))
        widgets.append((showtx_cb, None, showtx_help))

        can_edit_fees_cb = QCheckBox(_('Set transaction fees manually'))
        can_edit_fees_cb.setChecked(self.config.get('can_edit_fees', False))
        def on_editfees(x):
            self.config.set_key('can_edit_fees', x == Qt.Checked)
            self.update_fee_edit()
        can_edit_fees_cb.stateChanged.connect(on_editfees)
        can_edit_fees_help = HelpButton(_('This option lets you edit fees in the send tab.'))
        widgets.append((can_edit_fees_cb, None, can_edit_fees_help))

        for a,b,c in widgets:
            i = grid.rowCount()
            if b:
                grid.addWidget(a, i, 0)
                grid.addWidget(b, i, 1)
            else:
                grid.addWidget(a, i, 0, 1, 2)
            grid.addWidget(c, i, 2)

        vbox.addLayout(grid)
        vbox.addStretch(1)
        vbox.addLayout(Buttons(CloseButton(d)))
        d.setLayout(vbox)

        # run the dialog
        d.exec_()

        run_hook('close_settings_dialog')
        if self.need_restart:
            QMessageBox.warning(self, _('Success'), _('Please restart Electrum to activate the new GUI settings'), _('OK'))



    def run_network_dialog(self):
        if not self.network:
            QMessageBox.warning(self, _('Offline'), _('You are using Electrum in offline mode.\nRestart Electrum if you want to get connected.'), _('OK'))
            return
        NetworkDialog(self.wallet.network, self.config, self).do_exec()

    def closeEvent(self, event):
        self.config.set_key("is_maximized", self.isMaximized())
        if not self.isMaximized():
            g = self.geometry()
            self.config.set_key("winpos-qt", [g.left(),g.top(),g.width(),g.height()])
        self.config.set_key("console-history", self.console.history[-50:], True)
        self.wallet.storage.put('accounts_expanded', self.accounts_expanded)
        event.accept()


    def plugins_dialog(self):
        from electrum_ltc.plugins import plugins

        self.pluginsdialog = d = QDialog(self)
        d.setWindowTitle(_('Electrum Plugins'))
        d.setModal(1)

        vbox = QVBoxLayout(d)

        # plugins
        scroll = QScrollArea()
        scroll.setEnabled(True)
        scroll.setWidgetResizable(True)
        scroll.setMinimumSize(400,250)
        vbox.addWidget(scroll)

        w = QWidget()
        scroll.setWidget(w)
        w.setMinimumHeight(len(plugins)*35)

        grid = QGridLayout()
        grid.setColumnStretch(0,1)
        w.setLayout(grid)

        def do_toggle(cb, p, w):
            if p.is_enabled():
                if p.disable():
                    p.close()
            else:
                if p.enable():
                    p.load_wallet(self.wallet)
                    p.init_qt(self.gui_object)
            r = p.is_enabled()
            cb.setChecked(r)
            if w: w.setEnabled(r)

        def mk_toggle(cb, p, w):
            return lambda: do_toggle(cb,p,w)

        for i, p in enumerate(plugins):
            try:
                cb = QCheckBox(p.fullname())
                cb.setDisabled(not p.is_available())
                cb.setChecked(p.is_enabled())
                grid.addWidget(cb, i, 0)
                if p.requires_settings():
                    w = p.settings_widget(self)
                    w.setEnabled( p.is_enabled() )
                    grid.addWidget(w, i, 1)
                else:
                    w = None
                cb.clicked.connect(mk_toggle(cb,p,w))
                grid.addWidget(HelpButton(p.description()), i, 2)
            except Exception:
                print_msg("Error: cannot display plugin", p)
                traceback.print_exc(file=sys.stdout)
        grid.setRowStretch(i+1,1)
        vbox.addLayout(Buttons(CloseButton(d)))
        d.exec_()

    def show_account_details(self, k):
        account = self.wallet.accounts[k]

        d = QDialog(self)
        d.setWindowTitle(_('Account Details'))
        d.setModal(1)

        vbox = QVBoxLayout(d)
        name = self.wallet.get_account_name(k)
        label = QLabel('Name: ' + name)
        vbox.addWidget(label)

        vbox.addWidget(QLabel(_('Address type') + ': ' + account.get_type()))

        vbox.addWidget(QLabel(_('Derivation') + ': ' + k))

        vbox.addWidget(QLabel(_('Master Public Key:')))

        text = QTextEdit()
        text.setReadOnly(True)
        text.setMaximumHeight(170)
        vbox.addWidget(text)
        mpk_text = '\n'.join( account.get_master_pubkeys() )
        text.setText(mpk_text)
        vbox.addLayout(Buttons(CloseButton(d)))
        d.exec_()
