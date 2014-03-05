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

import sys, time, datetime, re, threading
from electrum.i18n import _, set_language
from electrum.util import print_error, print_msg
import os.path, json, ast, traceback
import webbrowser
import shutil
import StringIO


import PyQt4
from PyQt4.QtGui import *
from PyQt4.QtCore import *
import PyQt4.QtCore as QtCore

from electrum.bitcoin import MIN_RELAY_TX_FEE, is_valid
from electrum.plugins import run_hook

import icons_rc

from electrum.wallet import format_satoshis
from electrum import Transaction
from electrum import mnemonic
from electrum import util, bitcoin, commands, Interface, Wallet
from electrum import SimpleConfig, Wallet, WalletStorage


from electrum import bmp, pyqrnative

from amountedit import AmountEdit
from network_dialog import NetworkDialog
from qrcodewidget import QRCodeWidget

from decimal import Decimal

import platform
import httplib
import socket
import webbrowser
import csv

if platform.system() == 'Windows':
    MONOSPACE_FONT = 'Lucida Console'
elif platform.system() == 'Darwin':
    MONOSPACE_FONT = 'Monaco'
else:
    MONOSPACE_FONT = 'monospace'

from electrum import ELECTRUM_VERSION
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










default_column_widths = { "history":[40,140,350,140], "contacts":[350,330], "receive": [370,200,130] }

class ElectrumWindow(QMainWindow):
    def build_menu(self):
        m = QMenu()
        m.addAction(_("Show/Hide"), self.show_or_hide)
        m.addSeparator()
        m.addAction(_("Exit Electrum"), self.close)
        self.tray.setContextMenu(m)

    def show_or_hide(self):
        self.tray_activated(QSystemTrayIcon.DoubleClick)

    def tray_activated(self, reason):
        if reason == QSystemTrayIcon.DoubleClick:
            if self.isMinimized() or self.isHidden():
                self.show()
            else:
                self.hide()

    def __init__(self, config, network):
        QMainWindow.__init__(self)

        self.config = config
        self.network = network

        self._close_electrum = False
        self.lite = None

        if sys.platform == 'darwin':
          self.icon = QIcon(":icons/electrum_dark_icon.png")
          #self.icon = QIcon(":icons/lock.png")
        else:
          self.icon = QIcon(':icons/electrum_light_icon.png')

        self.tray = QSystemTrayIcon(self.icon, self)
        self.tray.setToolTip('Electrum')
        self.tray.activated.connect(self.tray_activated)

        self.build_menu()
        self.tray.show()
        self.create_status_bar()

        self.need_update = threading.Event()

        self.decimal_point = config.get('decimal_point', 8)
        self.num_zeros     = int(config.get('num_zeros',0))

        set_language(config.get('language'))

        self.funds_error = False
        self.completions = QStringListModel()

        self.tabs = tabs = QTabWidget(self)
        self.column_widths = self.config.get("column_widths_2", default_column_widths )
        tabs.addTab(self.create_history_tab(), _('History') )
        tabs.addTab(self.create_send_tab(), _('Send') )
        tabs.addTab(self.create_receive_tab(), _('Receive') )
        tabs.addTab(self.create_contacts_tab(), _('Contacts') )
        tabs.addTab(self.create_console_tab(), _('Console') )
        tabs.setMinimumSize(600, 400)
        tabs.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.setCentralWidget(tabs)

        g = self.config.get("winpos-qt",[100, 100, 840, 400])
        self.setGeometry(g[0], g[1], g[2], g[3])

        self.setWindowIcon(QIcon(":icons/electrum.png"))
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

        self.history_list.setFocus(True)

        # network callbacks
        if self.network:
            self.network.register_callback('updated', lambda: self.need_update.set())
            self.network.register_callback('banner', lambda: self.emit(QtCore.SIGNAL('banner_signal')))
            self.network.register_callback('disconnected', lambda: self.emit(QtCore.SIGNAL('update_status')))
            self.network.register_callback('disconnecting', lambda: self.emit(QtCore.SIGNAL('update_status')))
            self.network.register_callback('new_transaction', lambda: self.emit(QtCore.SIGNAL('transaction_signal')))

            # set initial message
            self.console.showMessage(self.network.banner)

        self.wallet = None
        self.init_lite()


    def go_full(self):
        self.config.set_key('lite_mode', False, True)
        self.mini.hide()
        self.show()

    def go_lite(self):
        self.config.set_key('lite_mode', True, True)
        self.hide()
        self.mini.show()


    def init_lite(self):
        import lite_window
        if not self.check_qt_version():
            if self.config.get('lite_mode') is True:
                msg = "Electrum was unable to load the 'Lite GUI' because it needs Qt version >= 4.7.\nChanging your config to use the 'Classic' GUI"
                QMessageBox.warning(None, "Could not start Lite GUI.", msg)
                self.config.set_key('lite_mode', False, True)
                sys.exit(0)
            self.mini = None
            self.show()
            return

        actuator = lite_window.MiniActuator(self)

        # Should probably not modify the current path but instead
        # change the behaviour of rsrc(...)
        old_path = QDir.currentPath()
        actuator.load_theme()

        self.mini = lite_window.MiniWindow(actuator, self.go_full, self.config)

        driver = lite_window.MiniDriver(self, self.mini)

        # Reset path back to original value now that loading the GUI
        # is completed.
        QDir.setCurrent(old_path)

        if self.config.get('lite_mode') is True:
            self.go_lite()
        else:
            self.go_full()


    def check_qt_version(self):
        qtVersion = qVersion()
        return int(qtVersion[0]) >= 4 and int(qtVersion[2]) >= 7


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


    def load_wallet(self, wallet):
        import electrum
        self.wallet = wallet
        self.accounts_expanded = self.wallet.storage.get('accounts_expanded',{})
        self.current_account = self.wallet.storage.get("current_account", None)

        title = 'Electrum ' + self.wallet.electrum_version + '  -  ' + self.wallet.storage.path
        if self.wallet.is_watching_only(): title += ' [%s]' % (_('watching only'))
        self.setWindowTitle( title )
        self.update_wallet()
        # Once GUI has been initialized check if we want to announce something since the callback has been called before the GUI was initialized
        self.notify_transactions()
        self.update_account_selector()
        self.new_account.setEnabled(self.wallet.seed_version>4)
        self.update_lock_icon()
        self.update_buttons_on_seed()
        self.update_console()

        run_hook('load_wallet', wallet)


    def open_wallet(self):
        wallet_folder = self.wallet.storage.path
        filename = unicode( QFileDialog.getOpenFileName(self, "Select your wallet file", wallet_folder) )
        if not filename:
            return

        storage = WalletStorage({'wallet_path': filename})
        if not storage.file_exists:
            self.show_message("file not found "+ filename)
            return

        self.wallet.stop_threads()

        # create new wallet
        wallet = Wallet(storage)
        wallet.start_threads(self.network)

        self.load_wallet(wallet)



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

        wallet_folder = os.path.dirname(self.wallet.storage.path)
        filename = unicode( QFileDialog.getSaveFileName(self, _('Enter a new file name'), wallet_folder) )
        if not filename:
            return
        filename = os.path.join(wallet_folder, filename)

        storage = WalletStorage({'wallet_path': filename})
        if storage.file_exists:
            QMessageBox.critical(None, "Error", _("File exists"))
            return

        wizard = installwizard.InstallWizard(self.config, self.network, storage)
        wallet = wizard.run()
        if wallet:
            self.load_wallet(wallet)



    def init_menubar(self):
        menubar = QMenuBar()

        file_menu = menubar.addMenu(_("&File"))
        file_menu.addAction(_("&Open"), self.open_wallet).setShortcut(QKeySequence.Open)
        file_menu.addAction(_("&New/Restore"), self.new_wallet).setShortcut(QKeySequence.New)
        file_menu.addAction(_("&Save Copy"), self.backup_wallet).setShortcut(QKeySequence.SaveAs)
        file_menu.addAction(_("&Quit"), self.close)

        wallet_menu = menubar.addMenu(_("&Wallet"))
        wallet_menu.addAction(_("&New contact"), self.new_contact_dialog)
        self.new_account = wallet_menu.addAction(_("&New account"), self.new_account_dialog)

        wallet_menu.addSeparator()

        wallet_menu.addAction(_("&Password"), self.change_password_dialog)
        wallet_menu.addAction(_("&Seed"), self.show_seed_dialog)
        wallet_menu.addAction(_("&Master Public Key"), self.show_master_public_key)

        wallet_menu.addSeparator()
        labels_menu = wallet_menu.addMenu(_("&Labels"))
        labels_menu.addAction(_("&Import"), self.do_import_labels)
        labels_menu.addAction(_("&Export"), self.do_export_labels)

        keys_menu = wallet_menu.addMenu(_("&Private keys"))
        keys_menu.addAction(_("&Import"), self.do_import_privkey)
        keys_menu.addAction(_("&Export"), self.do_export_privkeys)

        wallet_menu.addAction(_("&Export History"), self.do_export_history)

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

        help_menu = menubar.addMenu(_("&Help"))
        help_menu.addAction(_("&About"), self.show_about)
        help_menu.addAction(_("&Official website"), lambda: webbrowser.open("http://electrum.org"))
        help_menu.addSeparator()
        help_menu.addAction(_("&Documentation"), lambda: webbrowser.open("http://electrum.org/documentation.html")).setShortcut(QKeySequence.HelpContents)
        help_menu.addAction(_("&Report Bug"), self.show_report_bug)

        self.setMenuBar(menubar)

    def show_about(self):
        QMessageBox.about(self, "Electrum",
            _("Version")+" %s" % (self.wallet.electrum_version) + "\n\n" + _("Electrum's focus is speed, with low resource usage and simplifying Bitcoin. You do not need to perform regular backups, because your wallet can be recovered from a secret phrase that you can memorize or write on paper. Startup times are instant because it operates in conjunction with high-performance servers that handle the most complicated parts of the Bitcoin system."))

    def show_report_bug(self):
        QMessageBox.information(self, "Electrum - " + _("Reporting Bugs"),
            _("Please report any bugs as issues on github:")+" <a href=\"https://github.com/spesmilo/electrum/issues\">https://github.com/spesmilo/electrum/issues</a>")


    def notify_transactions(self):
        if not self.network or not self.network.is_connected():
            return

        print_error("Notifying GUI")
        if len(self.network.interface.pending_transactions_for_notifications) > 0:
            # Combine the transactions if there are more then three
            tx_amount = len(self.network.interface.pending_transactions_for_notifications)
            if(tx_amount >= 3):
                total_amount = 0
                for tx in self.network.interface.pending_transactions_for_notifications:
                    is_relevant, is_mine, v, fee = self.wallet.get_tx_value(tx)
                    if(v > 0):
                        total_amount += v

                self.notify(_("%(txs)s new transactions received. Total amount received in the new transactions %(amount)s %(unit)s") \
                                % { 'txs' : tx_amount, 'amount' : self.format_amount(total_amount), 'unit' : self.base_unit()})

                self.network.interface.pending_transactions_for_notifications = []
            else:
              for tx in self.network.interface.pending_transactions_for_notifications:
                  if tx:
                      self.network.interface.pending_transactions_for_notifications.remove(tx)
                      is_relevant, is_mine, v, fee = self.wallet.get_tx_value(tx)
                      if(v > 0):
                          self.notify(_("New transaction received. %(amount)s %(unit)s") % { 'amount' : self.format_amount(v), 'unit' : self.base_unit()})

    def notify(self, message):
        self.tray.showMessage("Electrum", message, QSystemTrayIcon.Information, 20000)



    # custom wrappers for getOpenFileName and getSaveFileName, that remember the path selected by the user
    def getOpenFileName(self, title, filter = ""):
        directory = self.config.get('io_dir', os.path.expanduser('~'))
        fileName = unicode( QFileDialog.getOpenFileName(self, title, directory, filter) )
        if fileName and directory != os.path.dirname(fileName):
            self.config.set_key('io_dir', os.path.dirname(fileName), True)
        return fileName

    def getSaveFileName(self, title, filename, filter = ""):
        directory = self.config.get('io_dir', os.path.expanduser('~'))
        path = os.path.join( directory, filename )
        fileName = unicode( QFileDialog.getSaveFileName(self, title, path, filter) )
        if fileName and directory != os.path.dirname(fileName):
            self.config.set_key('io_dir', os.path.dirname(fileName), True)
        return fileName

    def close(self):
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

    def read_amount(self, x):
        if x in['.', '']: return None
        p = pow(10, self.decimal_point)
        return int( p * Decimal(x) )

    def base_unit(self):
        assert self.decimal_point in [5,8]
        return "BTC" if self.decimal_point == 8 else "mBTC"


    def update_status(self):
        if self.network is None or not self.network.is_running():
            text = _("Offline")
            icon = QIcon(":icons/status_disconnected.png")

        elif self.network.is_connected():
            if not self.wallet.up_to_date:
                text = _("Synchronizing...")
                icon = QIcon(":icons/status_waiting.png")
            elif self.network.server_lag > 1:
                text = _("Server is lagging (%d blocks)"%self.network.server_lag)
                icon = QIcon(":icons/status_lagging.png")
            else:
                c, u = self.wallet.get_account_balance(self.current_account)
                text =  _( "Balance" ) + ": %s "%( self.format_amount(c) ) + self.base_unit()
                if u: text +=  " [%s unconfirmed]"%( self.format_amount(u,True).strip() )

                r = {}
                run_hook('set_quote_text', c+u, r)
                quote = r.get(0)
                if quote:
                    text += "  (%s)"%quote

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
            self.update_history_tab()
            self.update_receive_tab()
            self.update_contacts_tab()
            self.update_completions()


    def create_history_tab(self):
        self.history_list = l = MyTreeWidget(self)
        l.setColumnCount(5)
        for i,width in enumerate(self.column_widths['history']):
            l.setColumnWidth(i, width)
        l.setHeaderLabels( [ '', _('Date'), _('Description') , _('Amount'), _('Balance')] )
        self.connect(l, SIGNAL('itemDoubleClicked(QTreeWidgetItem*, int)'), self.tx_label_clicked)
        self.connect(l, SIGNAL('itemChanged(QTreeWidgetItem*, int)'), self.tx_label_changed)

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
        menu.addAction(_("Details"), lambda: self.show_transaction(self.wallet.transactions.get(tx_hash)))
        menu.addAction(_("Edit description"), lambda: self.tx_label_clicked(item,2))
        menu.addAction(_("View on Blockchain.info"), lambda: webbrowser.open("https://blockchain.info/tx/" + tx_hash))
        menu.exec_(self.contacts_list.viewport().mapToGlobal(position))


    def show_transaction(self, tx):
        import transaction_dialog
        d = transaction_dialog.TxDialog(tx, self)
        d.exec_()

    def tx_label_clicked(self, item, column):
        if column==2 and item.isSelected():
            self.is_edit=True
            item.setFlags(Qt.ItemIsEditable|Qt.ItemIsSelectable | Qt.ItemIsUserCheckable | Qt.ItemIsEnabled | Qt.ItemIsDragEnabled)
            self.history_list.editItem( item, column )
            item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsUserCheckable | Qt.ItemIsEnabled | Qt.ItemIsDragEnabled)
            self.is_edit=False

    def tx_label_changed(self, item, column):
        if self.is_edit:
            return
        self.is_edit=True
        tx_hash = str(item.data(0, Qt.UserRole).toString())
        tx = self.wallet.transactions.get(tx_hash)
        text = unicode( item.text(2) )
        self.wallet.set_label(tx_hash, text)
        if text:
            item.setForeground(2, QBrush(QColor('black')))
        else:
            text = self.wallet.get_default_label(tx_hash)
            item.setText(2, text)
            item.setForeground(2, QBrush(QColor('gray')))
        self.is_edit=False


    def edit_label(self, is_recv):
        l = self.receive_list if is_recv else self.contacts_list
        item = l.currentItem()
        item.setFlags(Qt.ItemIsEditable|Qt.ItemIsSelectable | Qt.ItemIsUserCheckable | Qt.ItemIsEnabled | Qt.ItemIsDragEnabled)
        l.editItem( item, 1 )
        item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsUserCheckable | Qt.ItemIsEnabled | Qt.ItemIsDragEnabled)



    def address_label_clicked(self, item, column, l, column_addr, column_label):
        if column == column_label and item.isSelected():
            is_editable = item.data(0, 32).toBool()
            if not is_editable:
                return
            addr = unicode( item.text(column_addr) )
            label = unicode( item.text(column_label) )
            item.setFlags(Qt.ItemIsEditable|Qt.ItemIsSelectable | Qt.ItemIsUserCheckable | Qt.ItemIsEnabled | Qt.ItemIsDragEnabled)
            l.editItem( item, column )
            item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsUserCheckable | Qt.ItemIsEnabled | Qt.ItemIsDragEnabled)


    def address_label_changed(self, item, column, l, column_addr, column_label):
        if column == column_label:
            addr = unicode( item.text(column_addr) )
            text = unicode( item.text(column_label) )
            is_editable = item.data(0, 32).toBool()
            if not is_editable:
                return

            changed = self.wallet.set_label(addr, text)
            if changed:
                self.update_history_tab()
                self.update_completions()

            self.current_item_changed(item)

        run_hook('item_changed', item, column)


    def current_item_changed(self, a):
        run_hook('current_item_changed', a)



    def update_history_tab(self):

        self.history_list.clear()
        for item in self.wallet.get_tx_history(self.current_account):
            tx_hash, conf, is_mine, value, fee, balance, timestamp = item
            time_str = _("unknown")
            if conf > 0:
                try:
                    time_str = datetime.datetime.fromtimestamp( timestamp).isoformat(' ')[:-3]
                except Exception:
                    time_str = _("error")

            if conf == -1:
                time_str = 'unverified'
                icon = QIcon(":icons/unconfirmed.png")
            elif conf == 0:
                time_str = 'pending'
                icon = QIcon(":icons/unconfirmed.png")
            elif conf < 6:
                icon = QIcon(":icons/clock%d.png"%conf)
            else:
                icon = QIcon(":icons/confirmed.png")

            if value is not None:
                v_str = self.format_amount(value, True, whitespaces=True)
            else:
                v_str = '--'

            balance_str = self.format_amount(balance, whitespaces=True)

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
        run_hook('history_tab_update')


    def create_send_tab(self):
        w = QWidget()

        grid = QGridLayout()
        grid.setSpacing(8)
        grid.setColumnMinimumWidth(3,300)
        grid.setColumnStretch(5,1)


        self.payto_e = QLineEdit()
        grid.addWidget(QLabel(_('Pay to')), 1, 0)
        grid.addWidget(self.payto_e, 1, 1, 1, 3)

        grid.addWidget(HelpButton(_('Recipient of the funds.') + '\n\n' + _('You may enter a Bitcoin address, a label from your list of contacts (a list of completions will be proposed), or an alias (email-like address that forwards to a Bitcoin address)')), 1, 4)

        completer = QCompleter()
        completer.setCaseSensitivity(False)
        self.payto_e.setCompleter(completer)
        completer.setModel(self.completions)

        self.message_e = QLineEdit()
        grid.addWidget(QLabel(_('Description')), 2, 0)
        grid.addWidget(self.message_e, 2, 1, 1, 3)
        grid.addWidget(HelpButton(_('Description of the transaction (not mandatory).') + '\n\n' + _('The description is not sent to the recipient of the funds. It is stored in your wallet file, and displayed in the \'History\' tab.')), 2, 4)

        self.from_label = QLabel(_('From'))
        grid.addWidget(self.from_label, 3, 0)
        self.from_list = QTreeWidget(self)
        self.from_list.setColumnCount(2)
        self.from_list.setColumnWidth(0, 350)
        self.from_list.setColumnWidth(1, 50)
        self.from_list.setHeaderHidden (True)
        self.from_list.setMaximumHeight(80)
        grid.addWidget(self.from_list, 3, 1, 1, 3)
        self.set_pay_from([])

        self.amount_e = AmountEdit(self.base_unit)
        grid.addWidget(QLabel(_('Amount')), 4, 0)
        grid.addWidget(self.amount_e, 4, 1, 1, 2)
        grid.addWidget(HelpButton(
                _('Amount to be sent.') + '\n\n' \
                    + _('The amount will be displayed in red if you do not have enough funds in your wallet. Note that if you have frozen some of your addresses, the available funds will be lower than your total balance.') \
                    + '\n\n' + _('Keyboard shortcut: type "!" to send all your coins.')), 4, 3)

        self.fee_e = AmountEdit(self.base_unit)
        grid.addWidget(QLabel(_('Fee')), 5, 0)
        grid.addWidget(self.fee_e, 5, 1, 1, 2)
        grid.addWidget(HelpButton(
                _('Bitcoin transactions are in general not free. A transaction fee is paid by the sender of the funds.') + '\n\n'\
                    + _('The amount of fee can be decided freely by the sender. However, transactions with low fees take more time to be processed.') + '\n\n'\
                    + _('A suggested fee is automatically added to this field. You may override it. The suggested fee increases with the size of the transaction.')), 5, 3)


        self.send_button = EnterButton(_("Send"), self.do_send)
        grid.addWidget(self.send_button, 6, 1)

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

            if self.amount_e.is_shortcut:
                self.amount_e.is_shortcut = False
                sendable = self.get_sendable_balance()
                # there is only one output because we are completely spending inputs
                inputs, total, fee = self.wallet.choose_tx_inputs( sendable, 0, 1, self.get_payment_sources())
                fee = self.wallet.estimated_fee(inputs, 1)
                amount = total - fee
                self.amount_e.setText( self.format_amount(amount) )
                self.fee_e.setText( self.format_amount( fee ) )
                return

            amount = self.read_amount(str(self.amount_e.text()))
            fee = self.read_amount(str(self.fee_e.text()))

            if not is_fee: fee = None
            if amount is None:
                return
            # assume that there will be 2 outputs (one for change)
            inputs, total, fee = self.wallet.choose_tx_inputs(amount, fee, 2, self.get_payment_sources())
            if not is_fee:
                self.fee_e.setText( self.format_amount( fee ) )
            if inputs:
                palette = QPalette()
                palette.setColor(self.amount_e.foregroundRole(), QColor('black'))
                text = ""
            else:
                palette = QPalette()
                palette.setColor(self.amount_e.foregroundRole(), QColor('red'))
                self.funds_error = True
                text = _( "Not enough funds" )
                c, u = self.wallet.get_frozen_balance()
                if c+u: text += ' (' + self.format_amount(c+u).strip() + self.base_unit() + ' ' +_("are frozen") + ')'

            self.statusBar().showMessage(text)
            self.amount_e.setPalette(palette)
            self.fee_e.setPalette(palette)

        self.amount_e.textChanged.connect(lambda: entry_changed(False) )
        self.fee_e.textChanged.connect(lambda: entry_changed(True) )

        run_hook('create_send_tab', grid)
        return w2


    def set_pay_from(self, l):
        self.pay_from = l
        self.from_list.clear()
        self.from_label.setHidden(len(self.pay_from) == 0)
        self.from_list.setHidden(len(self.pay_from) == 0)
        for addr in self.pay_from:
            c, u = self.wallet.get_addr_balance(addr)
            balance = self.format_amount(c + u)
            self.from_list.addTopLevelItem(QTreeWidgetItem( [addr, balance] ))


    def update_completions(self):
        l = []
        for addr,label in self.wallet.labels.items():
            if addr in self.wallet.addressbook:
                l.append( label + '  <' + addr + '>')

        run_hook('update_completions', l)
        self.completions.setStringList(l)


    def protected(func):
        return lambda s, *args: s.do_protect(func, args)


    def do_send(self):

        label = unicode( self.message_e.text() )
        r = unicode( self.payto_e.text() )
        r = r.strip()

        # label or alias, with address in brackets
        m = re.match('(.*?)\s*\<([1-9A-HJ-NP-Za-km-z]{26,})\>', r)
        to_address = m.group(2) if m else r

        if not is_valid(to_address):
            QMessageBox.warning(self, _('Error'), _('Invalid Bitcoin Address') + ':\n' + to_address, _('OK'))
            return

        try:
            amount = self.read_amount(unicode( self.amount_e.text()))
        except Exception:
            QMessageBox.warning(self, _('Error'), _('Invalid Amount'), _('OK'))
            return
        try:
            fee = self.read_amount(unicode( self.fee_e.text()))
        except Exception:
            QMessageBox.warning(self, _('Error'), _('Invalid Fee'), _('OK'))
            return

        confirm_amount = self.config.get('confirm_amount', 100000000)
        if amount >= confirm_amount:
            if not self.question(_("send %(amount)s to %(address)s?")%{ 'amount' : self.format_amount(amount) + ' '+ self.base_unit(), 'address' : to_address}):
                return
            
        confirm_fee = self.config.get('confirm_fee', 100000)
        if fee >= confirm_fee:
            if not self.question(_("The fee for this transaction seems unusually high.\nAre you really sure you want to pay %(fee)s in fees?")%{ 'fee' : self.format_amount(fee) + ' '+ self.base_unit()}):
                return

        self.send_tx(to_address, amount, fee, label)


    @protected
    def send_tx(self, to_address, amount, fee, label, password):
        try:
            tx = self.wallet.mktx( [(to_address, amount)], password, fee,
                    domain=self.get_payment_sources())
        except Exception as e:
            traceback.print_exc(file=sys.stdout)
            self.show_message(str(e))
            return

        if tx.requires_fee(self.wallet.verifier) and fee < MIN_RELAY_TX_FEE:
            QMessageBox.warning(self, _('Error'), _("This transaction requires a higher fee, or it will not be propagated by the network."), _('OK'))
            return

        if label:
            self.wallet.set_label(tx.hash(), label)

        if tx.is_complete:
            h = self.wallet.send_tx(tx)
            waiting_dialog(lambda: False if self.wallet.tx_event.isSet() else _("Please wait..."))
            status, msg = self.wallet.receive_tx( h, tx )
            if status:
                QMessageBox.information(self, '', _('Payment sent.')+'\n'+msg, _('OK'))
                self.do_clear()
                self.update_contacts_tab()
            else:
                QMessageBox.warning(self, _('Error'), msg, _('OK'))
        else:

            self.show_transaction(tx)

        # add recipient to addressbook
        if to_address not in self.wallet.addressbook and not self.wallet.is_mine(to_address):
            self.wallet.addressbook.append(to_address)




    def set_url(self, url):
        address, amount, label, message, signature, identity, url = util.parse_url(url)

        try:
            if amount and self.base_unit() == 'mBTC': amount = str( 1000* Decimal(amount))
            elif amount: amount = str(Decimal(amount))
        except Exception:
            amount = "0.0"
            QMessageBox.warning(self, _('Error'), _('Invalid Amount'), _('OK'))

        if self.mini:
            self.mini.set_payment_fields(address, amount)

        if label and self.wallet.labels.get(address) != label:
            if self.question('Give label "%s" to address %s ?'%(label,address)):
                if address not in self.wallet.addressbook and not self.wallet.is_mine(address):
                    self.wallet.addressbook.append(address)
                self.wallet.set_label(address, label)

        run_hook('set_url', url, self.show_message, self.question)

        self.tabs.setCurrentIndex(1)
        label = self.wallet.labels.get(address)
        m_addr = label + '  <'+ address +'>' if label else address
        self.payto_e.setText(m_addr)

        self.message_e.setText(message)
        if amount:
            self.amount_e.setText(amount)

        if identity:
            self.set_frozen(self.payto_e,True)
            self.set_frozen(self.amount_e,True)
            self.set_frozen(self.message_e,True)
            self.payto_sig.setText( '      '+_('The bitcoin URI was signed by')+' ' + identity )
        else:
            self.payto_sig.setVisible(False)

    def do_clear(self):
        self.payto_sig.setVisible(False)
        for e in [self.payto_e, self.message_e, self.amount_e, self.fee_e]:
            e.setText('')
            self.set_frozen(e,False)

        self.set_pay_from([])
        self.update_status()

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


    def set_addrs_frozen(self,addrs,freeze):
        for addr in addrs:
            if not addr: continue
            if addr in self.wallet.frozen_addresses and not freeze:
                self.wallet.unfreeze(addr)
            elif addr not in self.wallet.frozen_addresses and freeze:
                self.wallet.freeze(addr)
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
        l,w,hbox = self.create_list_tab([ _('Address'), _('Label'), _('Balance'), _('Tx')])
        l.setContextMenuPolicy(Qt.CustomContextMenu)
        l.customContextMenuRequested.connect(self.create_receive_menu)
        l.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.connect(l, SIGNAL('itemDoubleClicked(QTreeWidgetItem*, int)'), lambda a, b: self.address_label_clicked(a,b,l,0,1))
        self.connect(l, SIGNAL('itemChanged(QTreeWidgetItem*, int)'), lambda a,b: self.address_label_changed(a,b,l,0,1))
        self.connect(l, SIGNAL('currentItemChanged(QTreeWidgetItem*, QTreeWidgetItem*)'), lambda a,b: self.current_item_changed(a))
        self.receive_list = l
        self.receive_buttons_hbox = hbox
        hbox.addStretch(1)
        return w




    def save_column_widths(self):
        self.column_widths["receive"] = []
        for i in range(self.receive_list.columnCount() -1):
            self.column_widths["receive"].append(self.receive_list.columnWidth(i))

        self.column_widths["history"] = []
        for i in range(self.history_list.columnCount() - 1):
            self.column_widths["history"].append(self.history_list.columnWidth(i))

        self.column_widths["contacts"] = []
        for i in range(self.contacts_list.columnCount() - 1):
            self.column_widths["contacts"].append(self.contacts_list.columnWidth(i))

        self.config.set_key("column_widths_2", self.column_widths, True)


    def create_contacts_tab(self):
        l,w,hbox = self.create_list_tab([_('Address'), _('Label'), _('Tx')])
        l.setContextMenuPolicy(Qt.CustomContextMenu)
        l.customContextMenuRequested.connect(self.create_contact_menu)
        for i,width in enumerate(self.column_widths['contacts']):
            l.setColumnWidth(i, width)

        self.connect(l, SIGNAL('itemDoubleClicked(QTreeWidgetItem*, int)'), lambda a, b: self.address_label_clicked(a,b,l,0,1))
        self.connect(l, SIGNAL('itemChanged(QTreeWidgetItem*, int)'), lambda a,b: self.address_label_changed(a,b,l,0,1))
        self.contacts_list = l
        self.contacts_buttons_hbox = hbox
        hbox.addStretch(1)
        return w


    def delete_imported_key(self, addr):
        if self.question(_("Do you want to remove")+" %s "%addr +_("from your wallet?")):
            self.wallet.delete_imported_key(addr)
            self.update_receive_tab()
            self.update_history_tab()

    def edit_account_label(self, k):
        text, ok = QInputDialog.getText(self, _('Rename account'), _('Name') + ':', text = self.wallet.labels.get(k,''))
        if ok:
            label = unicode(text)
            self.wallet.set_label(k,label)
            self.update_receive_tab()

    def account_set_expanded(self, item, k, b):
        item.setExpanded(b)
        self.accounts_expanded[k] = b

    def create_account_menu(self, position, k, item):
        menu = QMenu()
        if item.isExpanded():
            menu.addAction(_("Minimize"), lambda: self.account_set_expanded(item, k, False))
        else:
            menu.addAction(_("Maximize"), lambda: self.account_set_expanded(item, k, True))
        menu.addAction(_("Rename"), lambda: self.edit_account_label(k))
        menu.addAction(_("View details"), lambda: self.show_account_details(k))
        if self.wallet.account_is_pending(k):
            menu.addAction(_("Delete"), lambda: self.delete_pending_account(k))
        menu.exec_(self.receive_list.viewport().mapToGlobal(position))

    def delete_pending_account(self, k):
        self.wallet.delete_pending_account(k)
        self.update_receive_tab()

    def create_receive_menu(self, position):
        # fixme: this function apparently has a side effect.
        # if it is not called the menu pops up several times
        #self.receive_list.selectedIndexes()

        selected = self.receive_list.selectedItems()
        multi_select = len(selected) > 1
        addrs = [unicode(item.text(0)) for item in selected]
        if not multi_select:
            item = self.receive_list.itemAt(position)
            if not item: return

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
            menu.addAction(_("QR code"), lambda: self.show_qrcode("bitcoin:" + addr, _("Address")) )
            menu.addAction(_("Edit label"), lambda: self.edit_label(True))
            if self.wallet.seed:
                menu.addAction(_("Private key"), lambda: self.show_private_key(addr))
                menu.addAction(_("Sign/verify message"), lambda: self.sign_verify_message(addr))
                menu.addAction(_("Encrypt/decrypt message"), lambda: self.encrypt_message(addr))
            if addr in self.wallet.imported_keys:
                menu.addAction(_("Remove from wallet"), lambda: self.delete_imported_key(addr))

        if any(addr not in self.wallet.frozen_addresses for addr in addrs):
            menu.addAction(_("Freeze"), lambda: self.set_addrs_frozen(addrs, True))
        if any(addr in self.wallet.frozen_addresses for addr in addrs):
            menu.addAction(_("Unfreeze"), lambda: self.set_addrs_frozen(addrs, False))

        if any(addr not in self.wallet.frozen_addresses for addr in addrs):
            menu.addAction(_("Send From"), lambda: self.send_from_addresses(addrs))

        run_hook('receive_menu', menu, addrs)
        menu.exec_(self.receive_list.viewport().mapToGlobal(position))


    def get_sendable_balance(self):
        return sum(sum(self.wallet.get_addr_balance(a)) for a in self.get_payment_sources())


    def get_payment_sources(self):
        if self.pay_from:
            return self.pay_from
        else:
            return self.wallet.get_account_addresses(self.current_account)


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
            menu.addAction(_("QR code"), lambda: self.show_qrcode("bitcoin:" + addr, _("Address")))
            if is_editable:
                menu.addAction(_("Edit label"), lambda: self.edit_label(False))
                menu.addAction(_("Delete"), lambda: self.delete_contact(addr))

        run_hook('create_contact_menu', menu, item)
        menu.exec_(self.contacts_list.viewport().mapToGlobal(position))


    def update_receive_item(self, item):
        item.setFont(0, QFont(MONOSPACE_FONT))
        address = str(item.data(0,0).toString())
        label = self.wallet.labels.get(address,'')
        item.setData(1,0,label)
        item.setData(0,32, True) # is editable

        run_hook('update_receive_item', address, item)

        if not self.wallet.is_mine(address): return

        c, u = self.wallet.get_addr_balance(address)
        balance = self.format_amount(c + u)
        item.setData(2,0,balance)

        if address in self.wallet.frozen_addresses:
            item.setBackgroundColor(0, QColor('lightblue'))


    def update_receive_tab(self):
        l = self.receive_list

        l.clear()
        l.setColumnHidden(2, False)
        l.setColumnHidden(3, False)
        for i,width in enumerate(self.column_widths['receive']):
            l.setColumnWidth(i, width)

        if self.current_account is None:
            account_items = self.wallet.accounts.items()
        elif self.current_account != -1:
            account_items = [(self.current_account, self.wallet.accounts.get(self.current_account))]
        else:
            account_items = []

        for k, account in account_items:
            name = self.wallet.get_account_name(k)
            c,u = self.wallet.get_account_balance(k)
            account_item = QTreeWidgetItem( [ name, '', self.format_amount(c+u), ''] )
            l.addTopLevelItem(account_item)
            account_item.setExpanded(self.accounts_expanded.get(k, True))
            account_item.setData(0, 32, k)

            if not self.wallet.is_seeded(k):
                icon = QIcon(":icons/key.png")
                account_item.setIcon(0, icon)

            for is_change in ([0,1]):
                name = _("Receiving") if not is_change else _("Change")
                seq_item = QTreeWidgetItem( [ name, '', '', '', ''] )
                account_item.addChild(seq_item)
                used_item = QTreeWidgetItem( [ _("Used"), '', '', '', ''] )
                used_flag = False
                if not is_change: seq_item.setExpanded(True)

                is_red = False
                gap = 0

                for address in account.get_addresses(is_change):
                    h = self.wallet.history.get(address,[])

                    if h == []:
                        gap += 1
                        if gap > self.wallet.gap_limit:
                            is_red = True
                    else:
                        gap = 0

                    c, u = self.wallet.get_addr_balance(address)
                    num_tx = '*' if h == ['*'] else "%d"%len(h)
                    item = QTreeWidgetItem( [ address, '', '', num_tx] )
                    self.update_receive_item(item)
                    if is_red:
                        item.setBackgroundColor(1, QColor('red'))
                    if len(h) > 0 and c == -u:
                        if not used_flag:
                            seq_item.insertChild(0,used_item)
                            used_flag = True
                        used_item.addChild(item)
                    else:
                        seq_item.addChild(item)


        for k, addr in self.wallet.get_pending_accounts():
            name = self.wallet.labels.get(k,'')
            account_item = QTreeWidgetItem( [ name + "  [ "+_('pending account')+" ]", '', '', ''] )
            self.update_receive_item(item)
            l.addTopLevelItem(account_item)
            account_item.setExpanded(True)
            account_item.setData(0, 32, k)
            item = QTreeWidgetItem( [ addr, '', '', '', ''] )
            account_item.addChild(item)
            self.update_receive_item(item)


        if self.wallet.imported_keys and (self.current_account is None or self.current_account == -1):
            c,u = self.wallet.get_imported_balance()
            account_item = QTreeWidgetItem( [ _('Imported'), '', self.format_amount(c+u), ''] )
            l.addTopLevelItem(account_item)
            account_item.setExpanded(True)
            for address in self.wallet.imported_keys.keys():
                item = QTreeWidgetItem( [ address, '', '', ''] )
                self.update_receive_item(item)
                account_item.addChild(item)


        # we use column 1 because column 0 may be hidden
        l.setCurrentItem(l.topLevelItem(0),1)


    def update_contacts_tab(self):
        l = self.contacts_list
        l.clear()

        for address in self.wallet.addressbook:
            label = self.wallet.labels.get(address,'')
            n = self.wallet.get_num_tx(address)
            item = QTreeWidgetItem( [ address, label, "%d"%n] )
            item.setFont(0, QFont(MONOSPACE_FONT))
            # 32 = label can be edited (bool)
            item.setData(0,32, True)
            # 33 = payto string
            item.setData(0,33, address)
            l.addTopLevelItem(item)

        run_hook('update_contacts_tab', l)
        l.setCurrentItem(l.topLevelItem(0))



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

        run_hook('create_status_bar', (sb,))

        self.setStatusBar(sb)


    def update_lock_icon(self):
        icon = QIcon(":icons/lock.png") if self.wallet.use_encryption else QIcon(":icons/unlock.png")
        self.password_button.setIcon( icon )


    def update_buttons_on_seed(self):
        if not self.wallet.is_watching_only():
           self.seed_button.show()
           self.password_button.show()
           self.send_button.setText(_("Send"))
        else:
           self.password_button.hide()
           self.seed_button.hide()
           self.send_button.setText(_("Create unsigned transaction"))


    def change_password_dialog(self):
        from password_dialog import PasswordDialog
        d = PasswordDialog(self.wallet, self)
        d.run()
        self.update_lock_icon()


    def new_contact_dialog(self):

        d = QDialog(self)
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
        vbox.addLayout(ok_cancel_buttons(d))

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


    def new_account_dialog(self):

        dialog = QDialog(self)
        dialog.setModal(1)
        dialog.setWindowTitle(_("New Account"))

        vbox = QVBoxLayout()
        vbox.addWidget(QLabel(_('Account name')+':'))
        e = QLineEdit()
        vbox.addWidget(e)
        msg = _("Note: Newly created accounts are 'pending' until they receive bitcoins.") + " " \
            + _("You will need to wait for 2 confirmations until the correct balance is displayed and more addresses are created for that account.")
        l = QLabel(msg)
        l.setWordWrap(True)
        vbox.addWidget(l)

        vbox.addLayout(ok_cancel_buttons(dialog))
        dialog.setLayout(vbox)
        r = dialog.exec_()
        if not r: return

        name = str(e.text())
        if not name: return

        self.wallet.create_pending_account('1', name)
        self.update_receive_tab()
        self.tabs.setCurrentIndex(2)



    def show_master_public_key_old(self):
        dialog = QDialog(self)
        dialog.setModal(1)
        dialog.setWindowTitle(_("Master Public Key"))

        main_text = QTextEdit()
        main_text.setText(self.wallet.get_master_public_key())
        main_text.setReadOnly(True)
        main_text.setMaximumHeight(170)
        qrw = QRCodeWidget(self.wallet.get_master_public_key())

        ok_button = QPushButton(_("OK"))
        ok_button.setDefault(True)
        ok_button.clicked.connect(dialog.accept)

        main_layout = QGridLayout()
        main_layout.addWidget(QLabel(_('Your Master Public Key is:')), 0, 0, 1, 2)

        main_layout.addWidget(main_text, 1, 0)
        main_layout.addWidget(qrw, 1, 1 )

        vbox = QVBoxLayout()
        vbox.addLayout(main_layout)
        vbox.addLayout(close_button(dialog))
        dialog.setLayout(vbox)
        dialog.exec_()


    def show_master_public_key(self):

        if self.wallet.seed_version == 4:
            self.show_master_public_key_old()
            return

        dialog = QDialog(self)
        dialog.setModal(1)
        dialog.setWindowTitle(_("Master Public Keys"))

        chain_text = QTextEdit()
        chain_text.setReadOnly(True)
        chain_text.setMaximumHeight(170)
        chain_qrw = QRCodeWidget()

        mpk_text = QTextEdit()
        mpk_text.setReadOnly(True)
        mpk_text.setMaximumHeight(170)
        mpk_qrw = QRCodeWidget()

        main_layout = QGridLayout()

        main_layout.addWidget(QLabel(_('Key')), 1, 0)
        main_layout.addWidget(mpk_text, 1, 1)
        main_layout.addWidget(mpk_qrw, 1, 2)

        main_layout.addWidget(QLabel(_('Chain')), 2, 0)
        main_layout.addWidget(chain_text, 2, 1)
        main_layout.addWidget(chain_qrw, 2, 2)

        def update(key):
            c, K, cK = self.wallet.master_public_keys[str(key)]
            chain_text.setText(c)
            chain_qrw.set_addr(c)
            chain_qrw.update_qr()
            mpk_text.setText(K)
            mpk_qrw.set_addr(K)
            mpk_qrw.update_qr()

        key_selector = QComboBox()
        keys = sorted(self.wallet.master_public_keys.keys())
        key_selector.addItems(keys)

        main_layout.addWidget(QLabel(_('Derivation:')), 0, 0)
        main_layout.addWidget(key_selector, 0, 1)
        dialog.connect(key_selector,SIGNAL("activated(QString)"),update)

        update(keys[0])

        vbox = QVBoxLayout()
        vbox.addLayout(main_layout)
        vbox.addLayout(close_button(dialog))

        dialog.setLayout(vbox)
        dialog.exec_()


    @protected
    def show_seed_dialog(self, password):
        if self.wallet.is_watching_only():
            QMessageBox.information(self, _('Message'), _('This is a watching-only wallet'), _('OK'))
            return

        if self.wallet.seed:
            try:
                mnemonic = self.wallet.get_mnemonic(password)
            except Exception:
                QMessageBox.warning(self, _('Error'), _('Incorrect Password'), _('OK'))
                return
            from seed_dialog import SeedDialog
            d = SeedDialog(self, mnemonic, self.wallet.imported_keys)
            d.exec_()
        else:
            l = {}
            for k in self.wallet.master_private_keys.keys():
                pk = self.wallet.get_master_private_key(k, password)
                l[k] = pk
            from seed_dialog import PrivateKeysDialog
            d = PrivateKeysDialog(self,l)
            d.exec_()





    def show_qrcode(self, data, title = _("QR code")):
        if not data: return
        d = QDialog(self)
        d.setModal(1)
        d.setWindowTitle(title)
        d.setMinimumSize(270, 300)
        vbox = QVBoxLayout()
        qrw = QRCodeWidget(data)
        vbox.addWidget(qrw, 1)
        vbox.addWidget(QLabel(data), 0, Qt.AlignHCenter)
        hbox = QHBoxLayout()
        hbox.addStretch(1)

        filename = os.path.join(self.config.path, "qrcode.bmp")

        def print_qr():
            bmp.save_qrcode(qrw.qr, filename)
            QMessageBox.information(None, _('Message'), _("QR code saved to file") + " " + filename, _('OK'))

        def copy_to_clipboard():
            bmp.save_qrcode(qrw.qr, filename)
            self.app.clipboard().setImage(QImage(filename))
            QMessageBox.information(None, _('Message'), _("QR code saved to clipboard"), _('OK'))

        b = QPushButton(_("Copy"))
        hbox.addWidget(b)
        b.clicked.connect(copy_to_clipboard)

        b = QPushButton(_("Save"))
        hbox.addWidget(b)
        b.clicked.connect(print_qr)

        b = QPushButton(_("Close"))
        hbox.addWidget(b)
        b.clicked.connect(d.accept)
        b.setDefault(True)

        vbox.addLayout(hbox)
        d.setLayout(vbox)
        d.exec_()


    def do_protect(self, func, args):
        if self.wallet.use_encryption:
            password = self.password_dialog()
            if not password:
                return
        else:
            password = None

        if args != (False,):
            args = (self,) + args + (password,)
        else:
            args = (self,password)
        apply( func, args)


    @protected
    def show_private_key(self, address, password):
        if not address: return
        try:
            pk_list = self.wallet.get_private_key(address, password)
        except Exception as e:
            self.show_message(str(e))
            return

        d = QDialog(self)
        d.setMinimumSize(600, 200)
        d.setModal(1)
        vbox = QVBoxLayout()
        vbox.addWidget( QLabel(_("Address") + ': ' + address))
        vbox.addWidget( QLabel(_("Private key") + ':'))
        keys = QTextEdit()
        keys.setReadOnly(True)
        keys.setText('\n'.join(pk_list))
        vbox.addWidget(keys)
        vbox.addWidget( QRCodeWidget('\n'.join(pk_list)) )
        vbox.addLayout(close_button(d))
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
        except Exception as e:
            self.show_message(str(e))


    def do_encrypt(self, message_e, pubkey_e, encrypted_e):
        message = unicode(message_e.toPlainText())
        message = message.encode('utf-8')
        try:
            encrypted = bitcoin.encrypt_message(message, str(pubkey_e.text()))
            encrypted_e.setText(encrypted)
        except Exception as e:
            self.show_message(str(e))



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
            pubkey = self.wallet.getpubkeys(address)[0]
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

        run_hook('password_dialog', pw, grid, 1)
        if not d.exec_(): return
        return unicode(pw.text())








    def tx_from_text(self, txt):
        "json or raw hexadecimal"
        try:
            txt.decode('hex')
            tx = Transaction(txt)
            return tx
        except Exception:
            pass

        try:
            tx_dict = json.loads(str(txt))
            assert "hex" in tx_dict.keys()
            assert "complete" in tx_dict.keys()
            tx = Transaction(tx_dict["hex"], tx_dict["complete"])
            if not tx_dict["complete"]:
                assert "input_info" in tx_dict.keys()
                input_info = json.loads(tx_dict['input_info'])
                tx.add_input_info(input_info)
            return tx
        except Exception:
            pass

        QMessageBox.critical(None, _("Unable to parse transaction"), _("Electrum was unable to parse your transaction"))



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
    def sign_raw_transaction(self, tx, input_info, password):
        self.wallet.signrawtransaction(tx, input_info, [], password)

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
        from electrum import transaction
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
                if not is_valid(address):
                    errors.append((position, address))
                    continue
                amount = Decimal(row[1])
                amount = int(100000000*amount)
                outputs.append((address, amount))
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
    def do_export_privkeys(self, password):
        if not self.wallet.seed:
            self.show_message(_("This wallet has no seed"))
            return

        self.show_message("%s\n%s\n%s" % (_("WARNING: ALL your private keys are secret."),  _("Exposing a single private key can compromise your entire wallet!"), _("In particular, DO NOT use 'redeem private key' services proposed by third parties.")))

        try:
            select_export = _('Select file to export your private keys to')
            fileName = self.getSaveFileName(select_export, 'electrum-private-keys.csv', "*.csv")
            if fileName:
                with open(fileName, "w+") as csvfile:
                    transaction = csv.writer(csvfile)
                    transaction.writerow(["address", "private_key"])

                    addresses = self.wallet.addresses(True)

                    for addr in addresses:
                        pk = "".join(self.wallet.get_private_key(addr, password))
                        transaction.writerow(["%34s"%addr,pk])

                    self.show_message(_("Private keys exported."))

        except (IOError, os.error), reason:
            export_error_label = _("Electrum was unable to produce a private key-export.")
            QMessageBox.critical(None, _("Unable to create csv"), export_error_label + "\n" + str(reason))

        except Exception as e:
          self.show_message(str(e))
          return


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
            fileName = self.getSaveFileName(_("Select file to save your labels"), 'electrum_labels.dat', "*.dat")
            if fileName:
                with open(fileName, 'w+') as f:
                    json.dump(labels, f)
                QMessageBox.information(None, _("Labels exported"), _("Your labels where exported to")+" '%s'" % str(fileName))
        except (IOError, os.error), reason:
            QMessageBox.critical(None, _("Unable to export labels"), _("Electrum was unable to export your labels.")+"\n" + str(reason))


    def do_export_history(self):
        from lite_window import csv_transaction
        csv_transaction(self.wallet)


    @protected
    def do_import_privkey(self, password):
        if not self.wallet.imported_keys:
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
        self.update_receive_tab()
        self.update_history_tab()


    def settings_dialog(self):
        d = QDialog(self)
        d.setWindowTitle(_('Electrum Settings'))
        d.setModal(1)
        vbox = QVBoxLayout()
        grid = QGridLayout()
        grid.setColumnStretch(0,1)

        nz_label = QLabel(_('Display zeros') + ':')
        grid.addWidget(nz_label, 0, 0)
        nz_e = AmountEdit(None,True)
        nz_e.setText("%d"% self.num_zeros)
        grid.addWidget(nz_e, 0, 1)
        msg = _('Number of zeros displayed after the decimal point. For example, if this is set to 2, "1." will be displayed as "1.00"')
        grid.addWidget(HelpButton(msg), 0, 2)
        if not self.config.is_modifiable('num_zeros'):
            for w in [nz_e, nz_label]: w.setEnabled(False)

        lang_label=QLabel(_('Language') + ':')
        grid.addWidget(lang_label, 1, 0)
        lang_combo = QComboBox()
        from electrum.i18n import languages
        lang_combo.addItems(languages.values())
        try:
            index = languages.keys().index(self.config.get("language",''))
        except Exception:
            index = 0
        lang_combo.setCurrentIndex(index)
        grid.addWidget(lang_combo, 1, 1)
        grid.addWidget(HelpButton(_('Select which language is used in the GUI (after restart).')+' '), 1, 2)
        if not self.config.is_modifiable('language'):
            for w in [lang_combo, lang_label]: w.setEnabled(False)


        fee_label = QLabel(_('Transaction fee') + ':')
        grid.addWidget(fee_label, 2, 0)
        fee_e = AmountEdit(self.base_unit)
        fee_e.setText(self.format_amount(self.wallet.fee).strip())
        grid.addWidget(fee_e, 2, 1)
        msg = _('Fee per kilobyte of transaction.') + ' ' \
            + _('Recommended value') + ': ' + self.format_amount(20000)
        grid.addWidget(HelpButton(msg), 2, 2)
        if not self.config.is_modifiable('fee_per_kb'):
            for w in [fee_e, fee_label]: w.setEnabled(False)

        units = ['BTC', 'mBTC']
        unit_label = QLabel(_('Base unit') + ':')
        grid.addWidget(unit_label, 3, 0)
        unit_combo = QComboBox()
        unit_combo.addItems(units)
        unit_combo.setCurrentIndex(units.index(self.base_unit()))
        grid.addWidget(unit_combo, 3, 1)
        grid.addWidget(HelpButton(_('Base unit of your wallet.')\
                                             + '\n1BTC=1000mBTC.\n' \
                                             + _(' These settings affects the fields in the Send tab')+' '), 3, 2)

        usechange_cb = QCheckBox(_('Use change addresses'))
        usechange_cb.setChecked(self.wallet.use_change)
        grid.addWidget(usechange_cb, 4, 0)
        grid.addWidget(HelpButton(_('Using change addresses makes it more difficult for other people to track your transactions.')+' '), 4, 2)
        if not self.config.is_modifiable('use_change'): usechange_cb.setEnabled(False)

        grid.setRowStretch(5,1)

        vbox.addLayout(grid)
        vbox.addLayout(ok_cancel_buttons(d))
        d.setLayout(vbox)

        # run the dialog
        if not d.exec_(): return

        fee = unicode(fee_e.text())
        try:
            fee = self.read_amount(fee)
        except Exception:
            QMessageBox.warning(self, _('Error'), _('Invalid value') +': %s'%fee, _('OK'))
            return

        self.wallet.set_fee(fee)

        nz = unicode(nz_e.text())
        try:
            nz = int( nz )
            if nz>8: nz=8
        except Exception:
            QMessageBox.warning(self, _('Error'), _('Invalid value')+':%s'%nz, _('OK'))
            return

        if self.num_zeros != nz:
            self.num_zeros = nz
            self.config.set_key('num_zeros', nz, True)
            self.update_history_tab()
            self.update_receive_tab()

        usechange_result = usechange_cb.isChecked()
        if self.wallet.use_change != usechange_result:
            self.wallet.use_change = usechange_result
            self.wallet.storage.put('use_change', self.wallet.use_change)

        unit_result = units[unit_combo.currentIndex()]
        if self.base_unit() != unit_result:
            self.decimal_point = 8 if unit_result == 'BTC' else 5
            self.config.set_key('decimal_point', self.decimal_point, True)
            self.update_history_tab()
            self.update_status()

        need_restart = False

        lang_request = languages.keys()[lang_combo.currentIndex()]
        if lang_request != self.config.get('language'):
            self.config.set_key("language", lang_request, True)
            need_restart = True

        run_hook('close_settings_dialog')

        if need_restart:
            QMessageBox.warning(self, _('Success'), _('Please restart Electrum to activate the new GUI settings'), _('OK'))


    def run_network_dialog(self):
        if not self.network:
            return
        NetworkDialog(self.wallet.network, self.config, self).do_exec()

    def closeEvent(self, event):
        self.tray.hide()
        g = self.geometry()
        self.config.set_key("winpos-qt", [g.left(),g.top(),g.width(),g.height()], True)
        self.save_column_widths()
        self.config.set_key("console-history", self.console.history[-50:], True)
        self.wallet.storage.put('accounts_expanded', self.accounts_expanded)
        event.accept()


    def plugins_dialog(self):
        from electrum.plugins import plugins

        d = QDialog(self)
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
            r = p.toggle()
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
                print_msg(_("Error: cannot display plugin"), p)
                traceback.print_exc(file=sys.stdout)
        grid.setRowStretch(i+1,1)

        vbox.addLayout(close_button(d))

        d.exec_()


    def show_account_details(self, k):
        d = QDialog(self)
        d.setWindowTitle(_('Account Details'))
        d.setModal(1)

        vbox = QVBoxLayout(d)
        roots = self.wallet.get_roots(k)

        name = self.wallet.get_account_name(k)
        label = QLabel('Name: ' + name)
        vbox.addWidget(label)

        acctype = '2 of 2' if len(roots) == 2 else '2 of 3' if len(roots) == 3 else 'Single key'
        vbox.addWidget(QLabel('Type: ' + acctype))

        label = QLabel('Derivation: ' + k)
        vbox.addWidget(label)

        #for root in roots:
        #    mpk = self.wallet.master_public_keys[root]
        #    text = QTextEdit()
        #    text.setReadOnly(True)
        #    text.setMaximumHeight(120)
        #    text.setText(repr(mpk))
        #    vbox.addWidget(text)

        vbox.addLayout(close_button(d))
        d.exec_()
