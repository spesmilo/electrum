#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2012 thomasv@gitorious
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import sys, time, threading
import os, json, traceback
import shutil
import socket
import weakref
import webbrowser
import csv
from decimal import Decimal
import base64
from functools import partial

import PyQt4
from PyQt4.QtGui import *
from PyQt4.QtCore import *
import PyQt4.QtCore as QtCore

import icons_rc

from electrum.bitcoin import COIN, is_valid, TYPE_ADDRESS
from electrum.plugins import run_hook
from electrum.i18n import _
from electrum.util import (block_explorer, block_explorer_info, format_time,
                           block_explorer_URL, format_satoshis, PrintError,
                           format_satoshis_plain, NotEnoughFunds, StoreDict,
                           UserCancelled)
from electrum import Transaction, mnemonic
from electrum import util, bitcoin, commands, coinchooser
from electrum import SimpleConfig, paymentrequest
from electrum.wallet import Wallet, BIP32_RD_Wallet, Multisig_Wallet

from amountedit import BTCAmountEdit, MyLineEdit, BTCkBEdit
from network_dialog import NetworkDialog
from qrcodewidget import QRCodeWidget, QRDialog
from qrtextedit import ShowQRTextEdit
from transaction_dialog import show_transaction



from electrum import ELECTRUM_VERSION
import re

from util import *


class StatusBarButton(QPushButton):
    def __init__(self, icon, tooltip, func):
        QPushButton.__init__(self, icon, '')
        self.setToolTip(tooltip)
        self.setFlat(True)
        self.setMaximumWidth(25)
        self.clicked.connect(self.onPress)
        self.func = func
        self.setIconSize(QSize(25,25))

    def onPress(self, checked=False):
        '''Drops the unwanted PyQt4 "checked" argument'''
        self.func()

    def keyPressEvent(self, e):
        if e.key() == QtCore.Qt.Key_Return:
            self.func()


from electrum.paymentrequest import PR_UNPAID, PR_PAID, PR_UNKNOWN, PR_EXPIRED

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
    (_('1 day'), 24*60*60),
    (_('1 week'), 7*24*60*60),
    (_('Never'), None)
]



class ElectrumWindow(QMainWindow, MessageBoxMixin, PrintError):

    def __init__(self, gui_object, wallet):
        QMainWindow.__init__(self)

        self.gui_object = gui_object
        self.config = config = gui_object.config
        self.network = gui_object.daemon.network
        self.invoices = gui_object.invoices
        self.contacts = gui_object.contacts
        self.tray = gui_object.tray
        self.app = gui_object.app
        self.cleaned_up = False

        self.create_status_bar()
        self.need_update = threading.Event()

        self.decimal_point = config.get('decimal_point', 5)
        self.num_zeros     = int(config.get('num_zeros',0))

        self.completions = QStringListModel()

        self.tabs = tabs = QTabWidget(self)
        tabs.addTab(self.create_history_tab(), _('History') )
        tabs.addTab(self.create_send_tab(), _('Send') )
        tabs.addTab(self.create_receive_tab(), _('Receive') )
        tabs.addTab(self.create_addresses_tab(), _('Addresses') )
        tabs.addTab(self.create_contacts_tab(), _('Contacts') )
        tabs.addTab(self.create_console_tab(), _('Console') )
        tabs.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.setCentralWidget(tabs)

        if self.config.get("is_maximized"):
            self.showMaximized()

        self.setWindowIcon(QIcon(":icons/electrum.png"))
        self.init_menubar()

        wrtabs = weakref.proxy(tabs)
        QShortcut(QKeySequence("Ctrl+W"), self, self.close)
        QShortcut(QKeySequence("Ctrl+Q"), self, self.close)
        QShortcut(QKeySequence("Ctrl+R"), self, self.update_wallet)
        QShortcut(QKeySequence("Ctrl+PgUp"), self, lambda: wrtabs.setCurrentIndex((wrtabs.currentIndex() - 1)%wrtabs.count()))
        QShortcut(QKeySequence("Ctrl+PgDown"), self, lambda: wrtabs.setCurrentIndex((wrtabs.currentIndex() + 1)%wrtabs.count()))

        for i in range(wrtabs.count()):
            QShortcut(QKeySequence("Alt+" + str(i + 1)), self, lambda i=i: wrtabs.setCurrentIndex(i))

        self.connect(self, QtCore.SIGNAL('payment_request_ok'), self.payment_request_ok)
        self.connect(self, QtCore.SIGNAL('payment_request_error'), self.payment_request_error)
        self.history_list.setFocus(True)

        # network callbacks
        if self.network:
            self.connect(self, QtCore.SIGNAL('network'), self.on_network_qt)
            interests = ['updated', 'new_transaction', 'status',
                         'banner', 'verified']
            # To avoid leaking references to "self" that prevent the
            # window from being GC-ed when closed, callbacks should be
            # methods of this class only, and specifically not be
            # partials, lambdas or methods of subobjects.  Hence...
            self.network.register_callback(self.on_network, interests)
            # set initial message
            self.console.showMessage(self.network.banner)

        self.payment_request = None
        self.checking_accounts = False
        self.qr_window = None
        self.not_enough_funds = False
        self.pluginsdialog = None
        self.fetch_alias()
        self.require_fee_update = False
        self.tx_notifications = []
        self.tl_windows = []
        self.load_wallet(wallet)
        self.connect_slots(gui_object.timer)

    def push_top_level_window(self, window):
        '''Used for e.g. tx dialog box to ensure new dialogs are appropriately
        parented.  This used to be done by explicitly providing the parent
        window, but that isn't something hardware wallet prompts know.'''
        self.tl_windows.append(window)

    def pop_top_level_window(self, window):
        self.tl_windows.remove(window)

    def top_level_window(self):
        '''Do the right thing in the presence of tx dialog windows'''
        override = self.tl_windows[-1] if self.tl_windows else None
        return self.top_level_window_recurse(override)

    def diagnostic_name(self):
        return "%s/%s" % (PrintError.diagnostic_name(self),
                          self.wallet.basename() if self.wallet else "None")

    def is_hidden(self):
        return self.isMinimized() or self.isHidden()

    def show_or_hide(self):
        if self.is_hidden():
            self.bring_to_top()
        else:
            self.hide()

    def bring_to_top(self):
        self.show()
        self.raise_()

    def on_error(self, exc_info):
        if not isinstance(exc_info[1], UserCancelled):
            traceback.print_exception(*exc_info)
            self.show_error(str(exc_info[1]))

    def on_network(self, event, *args):
        if event == 'updated':
            self.need_update.set()
        elif event == 'new_transaction':
            self.tx_notifications.append(args[0])
        elif event in ['status', 'banner', 'verified']:
            # Handle in GUI thread
            self.emit(QtCore.SIGNAL('network'), event, *args)
        else:
            self.print_error("unexpected network message:", event, args)

    def on_network_qt(self, event, *args):
        # Handle a network message in the GUI thread
        if event == 'status':
            self.update_status()
        elif event == 'banner':
            self.console.showMessage(args[0])
        elif event == 'verified':
            self.history_list.update_item(*args)
        else:
            self.print_error("unexpected network_qt signal:", event, args)

    def fetch_alias(self):
        self.alias_info = None
        alias = self.config.get('alias')
        if alias:
            alias = str(alias)
            def f():
                self.alias_info = self.contacts.resolve_openalias(alias)
                self.emit(SIGNAL('alias_received'))
            t = threading.Thread(target=f)
            t.setDaemon(True)
            t.start()

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
        if self.wallet:
            self.print_error('close_wallet', self.wallet.storage.path)
            self.wallet.storage.put('accounts_expanded', self.accounts_expanded)
        run_hook('close_wallet', self.wallet)

    def load_wallet(self, wallet):
        wallet.thread = TaskThread(self, self.on_error)
        self.wallet = wallet
        self.update_recently_visited(wallet.storage.path)
        self.import_old_contacts()
        # address used to create a dummy transaction and estimate transaction fee
        self.accounts_expanded = self.wallet.storage.get('accounts_expanded',{})
        self.current_account = self.wallet.storage.get("current_account", None)
        self.history_list.update()
        self.need_update.set()
        # Once GUI has been initialized check if we want to announce something since the callback has been called before the GUI was initialized
        self.notify_transactions()
        # update menus
        self.update_new_account_menu()
        self.seed_menu.setEnabled(self.wallet.has_seed())
        self.mpk_menu.setEnabled(self.wallet.is_deterministic())
        self.update_lock_icon()
        self.update_buttons_on_seed()
        self.update_console()
        self.clear_receive_tab()
        self.receive_list.update()
        self.tabs.show()

        try:
            self.setGeometry(*self.wallet.storage.get("winpos-qt"))
        except:
            self.setGeometry(100, 100, 840, 400)

        if self.config.get('hide_gui') and self.gui_object.tray.isVisible():
            self.hide()
        else:
            self.show()
        self.watching_only_changed()
        run_hook('load_wallet', wallet, self)

    def watching_only_changed(self):
        title = 'Electrum %s  -  %s' % (self.wallet.electrum_version,
                                        self.wallet.basename())
        if self.wallet.is_watching_only():
            self.warn_if_watching_only()
            title += ' [%s]' % (_('watching only'))
        self.setWindowTitle(title)
        self.password_menu.setEnabled(self.wallet.can_change_password())
        self.import_menu.setVisible(self.wallet.can_import())
        self.export_menu.setEnabled(self.wallet.can_export())

    def warn_if_watching_only(self):
        if self.wallet.is_watching_only():
            msg = ' '.join([
                _("This wallet is watching-only."),
                _("This means you will not be able to spend Bitcoins with it."),
                _("Make sure you own the seed phrase or the private keys, before you request Bitcoins to be sent to this wallet.")
            ])
            self.show_warning(msg, title=_('Information'))

    def import_old_contacts(self):
        # backward compatibility: import contacts
        old_contacts = self.wallet.storage.get('contacts', [])
        if old_contacts:
            for k in set(old_contacts):
                l = self.wallet.labels.get(k)
                if bitcoin.is_address(k) and l:
                    self.contacts[l] = ('address', k)
            self.wallet.storage.put('contacts', None)

    def open_wallet(self):
        wallet_folder = self.get_wallet_folder()
        filename = unicode(QFileDialog.getOpenFileName(self, "Select your wallet file", wallet_folder))
        if not filename:
            return
        self.gui_object.new_window(filename)


    def backup_wallet(self):
        path = self.wallet.storage.path
        wallet_folder = os.path.dirname(path)
        filename = unicode( QFileDialog.getSaveFileName(self, _('Enter a filename for the copy of your wallet'), wallet_folder) )
        if not filename:
            return

        new_path = os.path.join(wallet_folder, filename)
        if new_path != path:
            try:
                shutil.copy2(path, new_path)
                self.show_message(_("A copy of your wallet file was created in")+" '%s'" % str(new_path), title=_("Wallet backup created"))
            except (IOError, os.error), reason:
                self.show_critical(_("Electrum was unable to copy your wallet file to the specified location.") + "\n" + str(reason), title=_("Unable to create backup"))

    def update_recently_visited(self, filename):
        recent = self.config.get('recently_open', [])
        if filename in recent:
            recent.remove(filename)
        recent.insert(0, filename)
        recent = recent[:5]
        self.config.set_key('recently_open', recent)
        self.recently_visited_menu.clear()
        for i, k in enumerate(sorted(recent)):
            b = os.path.basename(k)
            def loader(k):
                return lambda: self.gui_object.new_window(k)
            self.recently_visited_menu.addAction(b, loader(k)).setShortcut(QKeySequence("Ctrl+%d"%(i+1)))
        self.recently_visited_menu.setEnabled(len(recent))

    def get_wallet_folder(self):
        return os.path.dirname(os.path.abspath(self.config.get_wallet_path()))

    def new_wallet(self):
        wallet_folder = self.get_wallet_folder()
        i = 1
        while True:
            filename = "wallet_%d" % i
            if filename in os.listdir(wallet_folder):
                i += 1
            else:
                break
        filename = line_dialog(self, _('New Wallet'), _('Enter file name')
                               + ':', _('OK'), filename)
        if not filename:
            return
        full_path = os.path.join(wallet_folder, filename)
        if os.path.exists(full_path):
            self.show_critical(_("File exists"))
            return
        self.gui_object.start_new_window(full_path, None)

    def init_menubar(self):
        menubar = QMenuBar()

        file_menu = menubar.addMenu(_("&File"))
        self.recently_visited_menu = file_menu.addMenu(_("&Recently open"))
        file_menu.addAction(_("&Open"), self.open_wallet).setShortcut(QKeySequence.Open)
        file_menu.addAction(_("&New/Restore"), self.new_wallet).setShortcut(QKeySequence.New)
        file_menu.addAction(_("&Save Copy"), self.backup_wallet).setShortcut(QKeySequence.SaveAs)
        file_menu.addSeparator()
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
        wallet_menu.addAction(_("Search"), self.toggle_search).setShortcut(QKeySequence("Ctrl+S"))

        tools_menu = menubar.addMenu(_("&Tools"))

        # Settings / Preferences are all reserved keywords in OSX using this as work around
        tools_menu.addAction(_("Electrum preferences") if sys.platform == 'darwin' else _("Preferences"), self.settings_dialog)
        tools_menu.addAction(_("&Network"), self.run_network_dialog)
        tools_menu.addAction(_("&Plugins"), self.plugins_dialog)
        tools_menu.addSeparator()
        tools_menu.addAction(_("&Sign/verify message"), self.sign_verify_message)
        tools_menu.addAction(_("&Encrypt/decrypt message"), self.encrypt_message)
        tools_menu.addSeparator()

        paytomany_menu = tools_menu.addAction(_("&Pay to many"), self.paytomany)

        raw_transaction_menu = tools_menu.addMenu(_("&Load transaction"))
        raw_transaction_menu.addAction(_("&From file"), self.do_process_from_file)
        raw_transaction_menu.addAction(_("&From text"), self.do_process_from_text)
        raw_transaction_menu.addAction(_("&From the blockchain"), self.do_process_from_txid)
        raw_transaction_menu.addAction(_("&From QR code"), self.read_tx_from_qrcode)
        self.raw_transaction_menu = raw_transaction_menu

        help_menu = menubar.addMenu(_("&Help"))
        help_menu.addAction(_("&About"), self.show_about)
        help_menu.addAction(_("&Official website"), lambda: webbrowser.open("http://electrum.org"))
        help_menu.addSeparator()
        help_menu.addAction(_("&Documentation"), lambda: webbrowser.open("http://docs.electrum.org/")).setShortcut(QKeySequence.HelpContents)
        help_menu.addAction(_("&Report Bug"), self.show_report_bug)
        help_menu.addSeparator()
        help_menu.addAction(_("&Donate to server"), self.donate_to_server)

        self.setMenuBar(menubar)

    def donate_to_server(self):
        if self.network.is_connected():
            d = self.network.get_donation_address()
            host = self.network.get_parameters()[0]
            self.pay_to_URI('bitcoin:%s?message=donation for %s'%(d, host))

    def show_about(self):
        QMessageBox.about(self, "Electrum",
            _("Version")+" %s" % (self.wallet.electrum_version) + "\n\n" + _("Electrum's focus is speed, with low resource usage and simplifying Bitcoin. You do not need to perform regular backups, because your wallet can be recovered from a secret phrase that you can memorize or write on paper. Startup times are instant because it operates in conjunction with high-performance servers that handle the most complicated parts of the Bitcoin system."))

    def show_report_bug(self):
        msg = ' '.join([
            _("Please report any bugs as issues on github:<br/>"),
            "<a href=\"https://github.com/spesmilo/electrum/issues\">https://github.com/spesmilo/electrum/issues</a><br/><br/>",
            _("Before reporting a bug, upgrade to the most recent version of Electrum (latest release or git HEAD), and include the version number in your report."),
            _("Try to explain not only what the bug is, but how it occurs.")
         ])
        self.show_message(msg, title="Electrum - " + _("Reporting Bugs"))

    def notify_transactions(self):
        if not self.network or not self.network.is_connected():
            return
        self.print_error("Notifying GUI")
        if len(self.tx_notifications) > 0:
            # Combine the transactions if there are more then three
            tx_amount = len(self.tx_notifications)
            if(tx_amount >= 3):
                total_amount = 0
                for tx in self.tx_notifications:
                    is_relevant, is_mine, v, fee = self.wallet.get_wallet_delta(tx)
                    if(v > 0):
                        total_amount += v
                self.notify(_("%(txs)s new transactions received. Total amount received in the new transactions %(amount)s") \
                            % { 'txs' : tx_amount, 'amount' : self.format_amount_and_units(total_amount)})
                self.tx_notifications = []
            else:
              for tx in self.tx_notifications:
                  if tx:
                      self.tx_notifications.remove(tx)
                      is_relevant, is_mine, v, fee = self.wallet.get_wallet_delta(tx)
                      if(v > 0):
                          self.notify(_("New transaction received. %(amount)s") % { 'amount' : self.format_amount_and_units(v)})

    def notify(self, message):
        if self.tray:
            self.tray.showMessage("Electrum", message, QSystemTrayIcon.Information, 20000)



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

    def connect_slots(self, sender):
        self.connect(sender, QtCore.SIGNAL('timersignal'), self.timer_actions)

    def timer_actions(self):
        # Note this runs in the GUI thread
        if self.need_update.is_set():
            self.need_update.clear()
            self.update_wallet()
        # resolve aliases
        self.payto_e.resolve()
        # update fee
        if self.require_fee_update:
            self.do_update_fee()
            self.require_fee_update = False

    def format_amount(self, x, is_diff=False, whitespaces=False):
        return format_satoshis(x, is_diff, self.num_zeros, self.decimal_point, whitespaces)

    def format_amount_and_units(self, amount):
        text = self.format_amount(amount) + ' '+ self.base_unit()
        x = run_hook('format_amount_and_units', amount)
        if text and x:
            text += ' (%s)'%x
        return text

    def get_decimal_point(self):
        return self.decimal_point

    def base_unit(self):
        assert self.decimal_point in [2, 5, 8]
        if self.decimal_point == 2:
            return 'bits'
        if self.decimal_point == 5:
            return 'mBTC'
        if self.decimal_point == 8:
            return 'BTC'
        raise Exception('Unknown base unit')

    def update_status(self):
        if not self.wallet:
            return

        if self.network is None or not self.network.is_running():
            text = _("Offline")
            icon = QIcon(":icons/status_disconnected.png")

        elif self.network.is_connected():
            server_height = self.network.get_server_height()
            server_lag = self.network.get_local_height() - server_height
            # Server height can be 0 after switching to a new server
            # until we get a headers subscription request response.
            # Display the synchronizing message in that case.
            if not self.wallet.up_to_date or server_height == 0:
                text = _("Synchronizing...")
                icon = QIcon(":icons/status_waiting.png")
            elif server_lag > 1:
                text = _("Server is lagging (%d blocks)"%server_lag)
                icon = QIcon(":icons/status_lagging.png")
            else:
                c, u, x = self.wallet.get_account_balance(self.current_account)
                text =  _("Balance" ) + ": %s "%(self.format_amount_and_units(c))
                if u:
                    text +=  " [%s unconfirmed]"%(self.format_amount(u, True).strip())
                if x:
                    text +=  " [%s unmatured]"%(self.format_amount(x, True).strip())
                # append fiat balance and price from exchange rate plugin
                rate = run_hook('get_fiat_status_text', c + u + x)
                if rate:
                    text += rate
                icon = QIcon(":icons/status_connected.png")
        else:
            text = _("Not connected")
            icon = QIcon(":icons/status_disconnected.png")

        self.tray.setToolTip("%s (%s)" % (text, self.wallet.basename()))
        self.balance_label.setText(text)
        self.status_button.setIcon( icon )


    def update_wallet(self):
        self.update_status()
        if self.wallet.up_to_date or not self.network or not self.network.is_connected():
            self.update_tabs()
        if self.wallet.up_to_date:
            self.check_next_account()

    def update_tabs(self):
        self.history_list.update()
        self.receive_list.update()
        self.address_list.update()
        self.contacts_list.update()
        self.invoices_list.update()
        self.update_completions()

    def create_history_tab(self):
        from history_widget import HistoryWidget
        self.history_list = l = HistoryWidget(self)
        return l

    def show_address(self, addr):
        import address_dialog
        d = address_dialog.AddressDialog(self, addr)
        d.exec_()

    def show_transaction(self, tx, tx_desc = None):
        '''tx_desc is set only for txs created in the Send tab'''
        show_transaction(tx, self, tx_desc)

    def create_receive_tab(self):
        # A 4-column grid layout.  All the stretch is in the last column.
        # The exchange rate plugin adds a fiat widget in column 2
        self.receive_grid = grid = QGridLayout()
        grid.setSpacing(8)
        grid.setColumnStretch(3, 1)

        self.receive_address_e = ButtonsLineEdit()
        self.receive_address_e.addCopyButton(self.app)
        self.receive_address_e.setReadOnly(True)
        msg = _('Bitcoin address where the payment should be received. Note that each payment request uses a different Bitcoin address.')
        self.receive_address_label = HelpLabel(_('Receiving address'), msg)
        self.receive_address_e.textChanged.connect(self.update_receive_qr)
        self.receive_address_e.setFocusPolicy(Qt.NoFocus)
        grid.addWidget(self.receive_address_label, 0, 0)
        grid.addWidget(self.receive_address_e, 0, 1, 1, -1)

        self.receive_message_e = QLineEdit()
        grid.addWidget(QLabel(_('Description')), 1, 0)
        grid.addWidget(self.receive_message_e, 1, 1, 1, -1)
        self.receive_message_e.textChanged.connect(self.update_receive_qr)

        self.receive_amount_e = BTCAmountEdit(self.get_decimal_point)
        grid.addWidget(QLabel(_('Requested amount')), 2, 0)
        grid.addWidget(self.receive_amount_e, 2, 1)
        self.receive_amount_e.textChanged.connect(self.update_receive_qr)

        self.expires_combo = QComboBox()
        self.expires_combo.addItems(map(lambda x:x[0], expiration_values))
        self.expires_combo.setCurrentIndex(1)
        self.expires_combo.setFixedWidth(self.receive_amount_e.width())
        msg = ' '.join([
            _('Expiration date of your request.'),
            _('This information is seen by the recipient if you send them a signed payment request.'),
            _('Expired requests have to be deleted manually from your list, in order to free the corresponding Bitcoin addresses.'),
            _('The bitcoin address never expires and will always be part of this electrum wallet.'),
        ])
        grid.addWidget(HelpLabel(_('Request expires'), msg), 3, 0)
        grid.addWidget(self.expires_combo, 3, 1)
        self.expires_label = QLineEdit('')
        self.expires_label.setReadOnly(1)
        self.expires_label.setFocusPolicy(Qt.NoFocus)
        self.expires_label.hide()
        grid.addWidget(self.expires_label, 3, 1)

        self.save_request_button = QPushButton(_('Save'))
        self.save_request_button.clicked.connect(self.save_payment_request)

        self.new_request_button = QPushButton(_('New'))
        self.new_request_button.clicked.connect(self.new_payment_request)

        self.receive_qr = QRCodeWidget(fixedSize=200)
        self.receive_qr.mouseReleaseEvent = lambda x: self.toggle_qr_window()
        self.receive_qr.enterEvent = lambda x: self.app.setOverrideCursor(QCursor(Qt.PointingHandCursor))
        self.receive_qr.leaveEvent = lambda x: self.app.setOverrideCursor(QCursor(Qt.ArrowCursor))

        self.receive_buttons = buttons = QHBoxLayout()
        buttons.addStretch(1)
        buttons.addWidget(self.save_request_button)
        buttons.addWidget(self.new_request_button)
        grid.addLayout(buttons, 4, 1, 1, 2)

        self.receive_requests_label = QLabel(_('Requests'))
        self.receive_list = MyTreeWidget(self, self.receive_list_menu, [_('Date'), _('Account'), _('Address'), '', _('Description'), _('Amount'), _('Status')], 4)
        self.receive_list.currentItemChanged.connect(self.receive_item_changed)
        self.receive_list.itemClicked.connect(self.receive_item_changed)
        self.receive_list.setSortingEnabled(True)
        self.receive_list.setColumnWidth(0, 180)
        self.receive_list.hideColumn(1)
        self.receive_list.hideColumn(2)
        self.receive_list.on_update = self.update_receive_tab

        # layout
        vbox_g = QVBoxLayout()
        vbox_g.addLayout(grid)
        vbox_g.addStretch()

        hbox = QHBoxLayout()
        hbox.addLayout(vbox_g)
        hbox.addWidget(self.receive_qr)

        w = QWidget()
        vbox = QVBoxLayout(w)
        vbox.addLayout(hbox)
        vbox.addStretch(1)
        vbox.addWidget(self.receive_requests_label)
        vbox.addWidget(self.receive_list)
        vbox.setStretchFactor(self.receive_list, 1000)

        return w

    def receive_item_changed(self, item):
        if item is None:
            return
        if not self.receive_list.isItemSelected(item):
            return
        addr = str(item.text(2))
        req = self.wallet.receive_requests[addr]
        expires = util.age(req['time'] + req['exp']) if req.get('exp') else _('Never')
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
        self.wallet.remove_payment_request(addr, self.config)
        self.receive_list.update()
        self.clear_receive_tab()

    def get_request_URI(self, addr):
        req = self.wallet.receive_requests[addr]
        message = self.wallet.labels.get(addr, '')
        amount = req['amount']
        URI = util.create_URI(addr, amount, message)
        if req.get('time'):
            URI += "&time=%d"%req.get('time')
        if req.get('exp'):
            URI += "&exp=%d"%req.get('exp')
        if req.get('name') and req.get('sig'):
            sig = req.get('sig').decode('hex')
            sig = bitcoin.base_encode(sig, base=58)
            URI += "&name=" + req['name'] + "&sig="+sig
        return str(URI)

    def receive_list_menu(self, position):
        item = self.receive_list.itemAt(position)
        addr = str(item.text(2))
        req = self.wallet.receive_requests[addr]
        menu = QMenu(self)
        menu.addAction(_("Copy Address"), lambda: self.view_and_paste(_('Address'), '', addr))
        menu.addAction(_("Copy URI"), lambda: self.view_and_paste('URI', '', self.get_request_URI(addr)))
        menu.addAction(_("Save as BIP70 file"), lambda: self.export_payment_request(addr))
        menu.addAction(_("Delete"), lambda: self.delete_payment_request(item))
        run_hook('receive_list_menu', menu, addr)
        menu.exec_(self.receive_list.viewport().mapToGlobal(position))

    def sign_payment_request(self, addr):
        alias = self.config.get('alias')
        alias_privkey = None
        if alias and self.alias_info:
            alias_addr, alias_name, validated = self.alias_info
            if alias_addr:
                if self.wallet.is_mine(alias_addr):
                    msg = _('This payment request will be signed.') + '\n' + _('Please enter your password')
                    password = self.password_dialog(msg)
                    if password:
                        try:
                            self.wallet.sign_payment_request(addr, alias, alias_addr, password)
                        except Exception as e:
                            self.show_error(str(e))
                            return
                    else:
                        return
                else:
                    return


    def save_payment_request(self):
        addr = str(self.receive_address_e.text())
        amount = self.receive_amount_e.get_amount()
        message = unicode(self.receive_message_e.text())
        if not message and not amount:
            self.show_error(_('No message or amount'))
            return False
        i = self.expires_combo.currentIndex()
        expiration = map(lambda x: x[1], expiration_values)[i]
        req = self.wallet.make_payment_request(addr, amount, message, expiration)
        self.wallet.add_payment_request(req, self.config)
        self.sign_payment_request(addr)
        self.receive_list.update()
        self.address_list.update()
        self.save_request_button.setEnabled(False)

    def view_and_paste(self, title, msg, data):
        dialog = WindowModalDialog(self, title)
        vbox = QVBoxLayout()
        label = QLabel(msg)
        label.setWordWrap(True)
        vbox.addWidget(label)
        pr_e = ShowQRTextEdit(text=data)
        vbox.addWidget(pr_e)
        vbox.addLayout(Buttons(CopyCloseButton(pr_e.text, self.app, dialog)))
        dialog.setLayout(vbox)
        dialog.exec_()

    def export_payment_request(self, addr):
        r = self.wallet.receive_requests.get(addr)
        pr = paymentrequest.serialize_request(r).SerializeToString()
        name = r['id'] + '.bip70'
        fileName = self.getSaveFileName(_("Select where to save your payment request"), name, "*.bip70")
        if fileName:
            with open(fileName, "wb+") as f:
                f.write(str(pr))
            self.show_message(_("Request saved successfully"))
            self.saved = True

    def new_payment_request(self):
        addr = self.wallet.get_unused_address(self.current_account)
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
        addr = self.wallet.get_unused_address(self.current_account)
        self.receive_address_e.setText(addr if addr else '')
        self.receive_message_e.setText('')
        self.receive_amount_e.setAmount(None)
        self.expires_label.hide()
        self.expires_combo.show()

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

        # hide receive tab if no receive requests available
        b = len(self.wallet.receive_requests) > 0
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
        addr = self.wallet.get_unused_address(self.current_account)
        if not current_address in domain and addr:
            self.set_receive_address(addr)
        self.new_request_button.setEnabled(addr != current_address)

        # clear the list and fill it again
        self.receive_list.clear()
        for req in self.wallet.get_sorted_requests(self.config):
            address = req['address']
            if address not in domain:
                continue
            timestamp = req.get('time', 0)
            amount = req.get('amount')
            expiration = req.get('exp', None)
            message = req.get('memo', '')
            date = format_time(timestamp)
            status = req.get('status')
            signature = req.get('sig')
            requestor = req.get('name', '')
            amount_str = self.format_amount(amount) if amount else ""
            account = ''
            item = QTreeWidgetItem([date, account, address, '', message, amount_str, pr_tooltips.get(status,'')])
            if signature is not None:
                item.setIcon(3, QIcon(":icons/seal.png"))
                item.setToolTip(3, 'signed by '+ requestor)
            if status is not PR_UNKNOWN:
                item.setIcon(6, QIcon(pr_icons.get(status)))
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

    def show_before_broadcast(self):
        return self.config.get('show_before_broadcast', False)

    def set_show_before_broadcast(self, show):
        self.config.set_key('show_before_broadcast', bool(show))
        self.set_send_button_text()

    def set_send_button_text(self):
        if self.show_before_broadcast():
            text = _("Send...")
        elif self.wallet and self.wallet.is_watching_only():
            text = _("Send...")
        else:
            text = _("Send")
        self.send_button.setText(text)

    def create_send_tab(self):
        # A 4-column grid layout.  All the stretch is in the last column.
        # The exchange rate plugin adds a fiat widget in column 2
        self.send_grid = grid = QGridLayout()
        grid.setSpacing(8)
        grid.setColumnStretch(3, 1)

        from paytoedit import PayToEdit
        self.amount_e = BTCAmountEdit(self.get_decimal_point)
        self.payto_e = PayToEdit(self)
        msg = _('Recipient of the funds.') + '\n\n'\
              + _('You may enter a Bitcoin address, a label from your list of contacts (a list of completions will be proposed), or an alias (email-like address that forwards to a Bitcoin address)')
        payto_label = HelpLabel(_('Pay to'), msg)
        grid.addWidget(payto_label, 1, 0)
        grid.addWidget(self.payto_e, 1, 1, 1, -1)

        completer = QCompleter()
        completer.setCaseSensitivity(False)
        self.payto_e.setCompleter(completer)
        completer.setModel(self.completions)

        msg = _('Description of the transaction (not mandatory).') + '\n\n'\
              + _('The description is not sent to the recipient of the funds. It is stored in your wallet file, and displayed in the \'History\' tab.')
        description_label = HelpLabel(_('Description'), msg)
        grid.addWidget(description_label, 2, 0)
        self.message_e = MyLineEdit()
        grid.addWidget(self.message_e, 2, 1, 1, -1)

        self.from_label = QLabel(_('From'))
        grid.addWidget(self.from_label, 3, 0)
        self.from_list = MyTreeWidget(self, self.from_list_menu, ['',''])
        self.from_list.setHeaderHidden(True)
        self.from_list.setMaximumHeight(80)
        grid.addWidget(self.from_list, 3, 1, 1, -1)
        self.set_pay_from([])

        msg = _('Amount to be sent.') + '\n\n' \
              + _('The amount will be displayed in red if you do not have enough funds in your wallet.') + ' ' \
              + _('Note that if you have frozen some of your addresses, the available funds will be lower than your total balance.') + '\n\n' \
              + _('Keyboard shortcut: type "!" to send all your coins.')
        amount_label = HelpLabel(_('Amount'), msg)
        grid.addWidget(amount_label, 4, 0)
        grid.addWidget(self.amount_e, 4, 1)

        msg = _('Bitcoin transactions are in general not free. A transaction fee is paid by the sender of the funds.') + '\n\n'\
              + _('The amount of fee can be decided freely by the sender. However, transactions with low fees take more time to be processed.') + '\n\n'\
              + _('A suggested fee is automatically added to this field. You may override it. The suggested fee increases with the size of the transaction.')
        self.fee_e_label = HelpLabel(_('Fee'), msg)
        self.fee_e = BTCAmountEdit(self.get_decimal_point)
        grid.addWidget(self.fee_e_label, 5, 0)
        grid.addWidget(self.fee_e, 5, 1)

        self.send_button = EnterButton(_("Send"), self.do_send)
        self.clear_button = EnterButton(_("Clear"), self.do_clear)
        buttons = QHBoxLayout()
        buttons.addStretch(1)
        buttons.addWidget(self.send_button)
        buttons.addWidget(self.clear_button)
        grid.addLayout(buttons, 6, 1, 1, 2)

        def on_shortcut():
            inputs = self.get_coins()
            sendable = sum(map(lambda x:x['value'], inputs))
            fee = self.fee_e.get_amount() if self.fee_e.isModified() else None
            addr = self.get_payto_or_dummy()
            amount, fee = self.wallet.get_max_amount(self.config, inputs, addr, fee)
            if not self.fee_e.isModified():
                self.fee_e.setAmount(fee)
            self.amount_e.setAmount(amount)
            self.not_enough_funds = (fee + amount > sendable)
            # emit signal for fiat_amount update
            self.amount_e.textEdited.emit("")

        self.amount_e.shortcut.connect(on_shortcut)
        self.payto_e.textChanged.connect(self.update_fee)
        self.amount_e.textEdited.connect(self.update_fee)
        self.fee_e.textEdited.connect(self.update_fee)
        # This is so that when the user blanks the fee and moves on,
        # we go back to auto-calculate mode and put a fee back.
        self.fee_e.editingFinished.connect(self.update_fee)

        def entry_changed():
            text = ""
            if self.not_enough_funds:
                amt_color, fee_color = RED_FG, RED_FG
                text = _( "Not enough funds" )
                c, u, x = self.wallet.get_frozen_balance()
                if c+u+x:
                    text += ' (' + self.format_amount(c+u+x).strip() + ' ' + self.base_unit() + ' ' +_("are frozen") + ')'

            elif self.fee_e.isModified():
                amt_color, fee_color = BLACK_FG, BLACK_FG
            elif self.amount_e.isModified():
                amt_color, fee_color = BLACK_FG, BLUE_FG
            else:
                amt_color, fee_color = BLUE_FG, BLUE_FG

            self.statusBar().showMessage(text)
            self.amount_e.setStyleSheet(amt_color)
            self.fee_e.setStyleSheet(fee_color)

        self.amount_e.textChanged.connect(entry_changed)
        self.fee_e.textChanged.connect(entry_changed)

        self.invoices_label = QLabel(_('Invoices'))
        self.invoices_list = MyTreeWidget(self, self.invoices_list_menu,
                                          [_('Expires'), _('Requestor'), _('Description'), _('Amount'), _('Status')], 2)
        self.invoices_list.setSortingEnabled(True)
        self.invoices_list.header().setResizeMode(1, QHeaderView.Interactive)
        self.invoices_list.setColumnWidth(1, 200)
        self.invoices_list.on_update = self.update_invoices_list

        vbox0 = QVBoxLayout()
        vbox0.addLayout(grid)
        hbox = QHBoxLayout()
        hbox.addLayout(vbox0)
        w = QWidget()
        vbox = QVBoxLayout(w)
        vbox.addLayout(hbox)
        vbox.addStretch(1)
        vbox.addWidget(self.invoices_label)
        vbox.addWidget(self.invoices_list)
        vbox.setStretchFactor(self.invoices_list, 1000)

        # Defer this until grid is parented to avoid ugly flash during startup
        self.update_fee_edit()

        run_hook('create_send_tab', grid)
        return w

    def update_fee(self):
        self.require_fee_update = True

    def get_payto_or_dummy(self):
        return self.payto_e.payto_address if self.payto_e.payto_address else self.wallet.dummy_address()

    def do_update_fee(self):
        '''Recalculate the fee.  If the fee was manually input, retain it, but
        still build the TX to see if there are enough funds.
        '''
        freeze_fee = (self.fee_e.isModified()
                      and (self.fee_e.text() or self.fee_e.hasFocus()))
        amount = self.amount_e.get_amount()
        if amount is None:
            if not freeze_fee:
                self.fee_e.setAmount(None)
            self.not_enough_funds = False
        else:
            fee = self.fee_e.get_amount() if freeze_fee else None
            outputs = self.payto_e.get_outputs()
            if not outputs:
                addr = self.get_payto_or_dummy()
                outputs = [(TYPE_ADDRESS, addr, amount)]
            try:
                tx = self.wallet.make_unsigned_transaction(self.get_coins(), outputs, self.config, fee)
                self.not_enough_funds = False
            except NotEnoughFunds:
                self.not_enough_funds = True
            if not freeze_fee:
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
        self.update_fee()

    def from_list_menu(self, position):
        item = self.from_list.itemAt(position)
        menu = QMenu()
        menu.addAction(_("Remove"), lambda: self.from_list_delete(item))
        menu.exec_(self.from_list.viewport().mapToGlobal(position))

    def set_pay_from(self, domain = None):
        self.pay_from = [] if domain == [] else self.wallet.get_spendable_coins(domain)
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

    def get_contact_payto(self, key):
        _type, value = self.contacts.get(key)
        return key + '  <' + value + '>' if _type == 'address' else key

    def update_completions(self):
        l = [self.get_contact_payto(key) for key in self.contacts.keys()]
        self.completions.setStringList(l)

    def protected(func):
        '''Password request wrapper.  The password is passed to the function
        as the 'password' named argument.  "None" indicates either an
        unencrypted wallet, or the user cancelled the password request.
        An empty input is passed as the empty string.'''
        def request_password(self, *args, **kwargs):
            parent = self.top_level_window()
            password = None
            while self.wallet.use_encryption:
                password = self.password_dialog(parent=parent)
                try:
                    if password:
                        self.wallet.check_password(password)
                    break
                except Exception as e:
                    self.show_error(str(e), parent=parent)
                    continue

            kwargs['password'] = password
            return func(self, *args, **kwargs)
        return request_password

    def read_send_tab(self):
        if self.payment_request and self.payment_request.has_expired():
            self.show_error(_('Payment request has expired'))
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

            if self.payto_e.is_alias and self.payto_e.validated is False:
                alias = self.payto_e.toPlainText()
                msg = _('WARNING: the alias "%s" could not be validated via an additional security check, DNSSEC, and thus may not be correct.'%alias) + '\n'
                msg += _('Do you wish to continue?')
                if not self.question(msg):
                    return

        if not outputs:
            self.show_error(_('No outputs'))
            return

        for _type, addr, amount in outputs:
            if addr is None:
                self.show_error(_('Bitcoin Address is None'))
                return
            if _type == TYPE_ADDRESS and not bitcoin.is_address(addr):
                self.show_error(_('Invalid Bitcoin Address'))
                return
            if amount is None:
                self.show_error(_('Invalid Amount'))
                return

        fee = self.fee_e.get_amount()
        if fee is None:
            self.show_error(_('Invalid Fee'))
            return

        coins = self.get_coins()
        return outputs, fee, label, coins


    def do_send(self):
        if run_hook('abort_send', self):
            return
        r = self.read_send_tab()
        if not r:
            return
        outputs, fee, tx_desc, coins = r
        amount = sum(map(lambda x:x[2], outputs))
        try:
            tx = self.wallet.make_unsigned_transaction(coins, outputs, self.config, fee)
        except NotEnoughFunds:
            self.show_message(_("Insufficient funds"))
            return
        except BaseException as e:
            traceback.print_exc(file=sys.stdout)
            self.show_message(str(e))
            return

        if tx.get_fee() < self.wallet.relayfee() and tx.requires_fee(self.wallet):
            self.show_error(_("This transaction requires a higher fee, or it will not be propagated by the network"))
            return

        if self.show_before_broadcast():
            self.show_transaction(tx, tx_desc)
            return
        # confirmation dialog
        confirm_amount = self.config.get('confirm_amount', COIN)
        msg = [
            _("Amount to be sent") + ": " + self.format_amount_and_units(amount),
            _("Mining fee") + ": " + self.format_amount_and_units(fee),
        ]

        extra_fee = run_hook('get_additional_fee', self.wallet, tx)
        if extra_fee:
            msg.append( _("Additional fees") + ": " + self.format_amount_and_units(extra_fee) )

        if tx.get_fee() >= self.config.get('confirm_fee', 100000):
            msg.append(_('Warning')+ ': ' + _("The fee for this transaction seems unusually high."))

        if self.wallet.use_encryption:
            msg.append("")
            msg.append(_("Enter your password to proceed"))
            password = self.password_dialog('\n'.join(msg))
            if not password:
                return
        else:
            msg.append(_('Proceed?'))
            password = None
            if not self.question('\n'.join(msg)):
                return

        def sign_done(success):
            if success:
                if not tx.is_complete():
                    self.show_transaction(tx)
                    self.do_clear()
                else:
                    self.broadcast_transaction(tx, tx_desc)
        self.sign_tx_with_password(tx, sign_done, password)

    @protected
    def sign_tx(self, tx, callback, password):
        self.sign_tx_with_password(tx, callback, password)

    def sign_tx_with_password(self, tx, callback, password):
        '''Sign the transaction in a separate thread.  When done, calls
        the callback with a success code of True or False.
        '''
        if self.wallet.use_encryption and not password:
            callback(False) # User cancelled password input
            return

        # call hook to see if plugin needs gui interaction
        run_hook('sign_tx', self, tx)

        def on_signed(result):
            callback(True)
        def on_failed(exc_info):
            self.on_error(exc_info)
            callback(False)

        task = partial(self.wallet.sign_transaction, tx, password)
        WaitingDialog(self, _('Signing transaction...'), task,
                      on_signed, on_failed)

    def broadcast_transaction(self, tx, tx_desc):

        def broadcast_thread():
            # non-GUI thread
            pr = self.payment_request
            if pr and pr.has_expired():
                self.payment_request = None
                return False, _("Payment request has expired")
            status, msg =  self.network.broadcast(tx)
            if pr and status is True:
                pr.set_paid(tx.hash())
                self.invoices.save()
                self.payment_request = None
                refund_address = self.wallet.addresses()[0]
                ack_status, ack_msg = pr.send_ack(str(tx), refund_address)
                if ack_status:
                    msg = ack_msg
            return status, msg

        # Capture current TL window; override might be removed on return
        parent = self.top_level_window()

        def broadcast_done(result):
            # GUI thread
            if result:
                status, msg = result
                if status:
                    if tx_desc is not None and tx.is_complete():
                        self.wallet.set_label(tx.hash(), tx_desc)
                        parent.show_message(_('Payment sent.') + '\n' + msg)
                        self.invoices_list.update()
                        self.do_clear()
                else:
                    parent.show_error(msg)

        WaitingDialog(self, _('Broadcasting transaction...'),
                      broadcast_thread, broadcast_done, self.on_error)

    def query_choice(self, msg, choices):
        # Needed by QtHandler for hardware wallets
        dialog = WindowModalDialog(self.top_level_window())
        clayout = ChoicesLayout(msg, choices)
        vbox = QVBoxLayout(dialog)
        vbox.addLayout(clayout.layout())
        vbox.addLayout(Buttons(OkButton(dialog)))
        dialog.exec_()
        return clayout.selected_index()

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
        self.invoices_list.update()
        if status == PR_PAID:
            self.show_message("invoice already paid")
            self.do_clear()
            self.payment_request = None
            return

        self.payto_e.is_pr = True
        if not pr.has_expired():
            self.payto_e.setGreen()
        else:
            self.payto_e.setExpired()

        self.payto_e.setText(pr.get_requestor())
        self.amount_e.setText(format_satoshis_plain(pr.get_amount(), self.decimal_point))
        self.message_e.setText(pr.get_memo())
        # signal to set fee
        self.amount_e.textEdited.emit("")

    def payment_request_error(self):
        self.show_message(self.payment_request.error)
        self.payment_request = None
        self.do_clear()

    def on_pr(self, request):
        self.payment_request = request
        if self.payment_request.verify(self.contacts):
            self.emit(SIGNAL('payment_request_ok'))
        else:
            self.emit(SIGNAL('payment_request_error'))

    def pay_to_URI(self, URI):
        if not URI:
            return
        try:
            out = util.parse_URI(unicode(URI), self.on_pr)
        except BaseException as e:
            self.show_error(_('Invalid bitcoin URI:') + '\n' + str(e))
            return
        self.tabs.setCurrentIndex(1)
        r = out.get('r')
        sig = out.get('sig')
        name = out.get('name')
        if r or (name and sig):
            self.prepare_for_payment_request()
            return
        address = out.get('address')
        amount = out.get('amount')
        label = out.get('label')
        message = out.get('message')
        # use label as description (not BIP21 compliant)
        if label and not message:
            message = label
        if address:
            self.payto_e.setText(address)
        if message:
            self.message_e.setText(message)
        if amount:
            self.amount_e.setAmount(amount)
            self.amount_e.textEdited.emit("")


    def do_clear(self):
        self.not_enough_funds = False
        self.payment_request = None
        self.payto_e.is_pr = False
        for e in [self.payto_e, self.message_e, self.amount_e, self.fee_e]:
            e.setText('')
            e.setFrozen(False)
        self.set_pay_from([])
        self.update_status()
        run_hook('do_clear', self)

    def set_frozen_state(self, addrs, freeze):
        self.wallet.set_frozen_state(addrs, freeze)
        self.address_list.update()
        self.update_fee()

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
        l = MyTreeWidget(self, self.create_receive_menu, [ _('Address'), _('Label'), _('Balance'), _('Tx')], 1)
        l.setSelectionMode(QAbstractItemView.ExtendedSelection)
        l.on_update = self.update_address_tab
        self.address_list = l
        return self.create_list_tab(l)

    def create_contacts_tab(self):
        l = MyTreeWidget(self, self.create_contact_menu, [_('Name'), _('Value'), _('Type')], 1, [0, 1])
        l.setSelectionMode(QAbstractItemView.ExtendedSelection)
        l.setSortingEnabled(True)
        l.on_edited = self.on_contact_edited
        l.on_permit_edit = self.on_permit_contact_edit
        l.on_update = self.update_contacts_tab
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
            exp = pr.get_expiration_date()
            date_str = util.format_time(exp) if exp else _('Never')
            item = QTreeWidgetItem([date_str, requestor, pr.memo, self.format_amount(pr.get_amount(), whitespaces=True), pr_tooltips.get(status,'')])
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
            self.address_list.update()
            self.history_list.update()

    def edit_account_label(self, k):
        text, ok = QInputDialog.getText(self, _('Rename account'), _('Name') + ':', text = self.wallet.labels.get(k,''))
        if ok:
            label = unicode(text)
            self.wallet.set_label(k,label)
            self.address_list.update()

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
        menu.exec_(self.address_list.viewport().mapToGlobal(position))

    def create_receive_menu(self, position):
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
            menu.addAction(_("Edit label"), lambda: self.address_list.editItem(item, self.address_list.editable_columns[0]))
            menu.addAction(_('History'), lambda: self.show_address(addr))
            menu.addAction(_('Public Keys'), lambda: self.show_public_keys(addr))
            if self.wallet.can_export():
                menu.addAction(_("Private key"), lambda: self.show_private_key(addr))
            if not self.wallet.is_watching_only():
                menu.addAction(_("Sign/verify message"), lambda: self.sign_verify_message(addr))
                menu.addAction(_("Encrypt/decrypt message"), lambda: self.encrypt_message(addr))
            if self.wallet.is_imported(addr):
                menu.addAction(_("Remove from wallet"), lambda: self.delete_imported_key(addr))
            addr_URL = block_explorer_URL(self.config, 'addr', addr)
            if addr_URL:
                menu.addAction(_("View on block explorer"), lambda: webbrowser.open(addr_URL))

        if any(not self.wallet.is_frozen(addr) for addr in addrs):
            menu.addAction(_("Freeze"), lambda: self.set_frozen_state(addrs, True))
        if any(self.wallet.is_frozen(addr) for addr in addrs):
            menu.addAction(_("Unfreeze"), lambda: self.set_frozen_state(addrs, False))

        def can_send(addr):
            return not self.wallet.is_frozen(addr) and sum(self.wallet.get_addr_balance(addr)[:2])
        if any(can_send(addr) for addr in addrs):
            menu.addAction(_("Send From"), lambda: self.send_from_addresses(addrs))

        run_hook('receive_menu', menu, addrs, self.wallet)
        menu.exec_(self.address_list.viewport().mapToGlobal(position))


    def get_coins(self):
        if self.pay_from:
            return self.pay_from
        else:
            domain = self.wallet.get_account_addresses(self.current_account)
            return self.wallet.get_spendable_coins(domain)


    def send_from_addresses(self, addrs):
        self.set_pay_from(addrs)
        self.tabs.setCurrentIndex(1)
        self.update_fee()

    def paytomany(self):
        self.tabs.setCurrentIndex(1)
        self.payto_e.paytomany()
        msg = '\n'.join([
            _('Enter a list of outputs in the \'Pay to\' field.'),
            _('One output per line.'),
            _('Format: address, amount'),
            _('You may load a CSV file using the file icon.')
        ])
        self.show_message(msg, title=_('Pay to many'))

    def payto_contacts(self, labels):
        paytos = [self.get_contact_payto(label) for label in labels]
        self.tabs.setCurrentIndex(1)
        if len(paytos) == 1:
            self.payto_e.setText(paytos[0])
            self.amount_e.setFocus()
        else:
            text = "\n".join([payto + ", 0" for payto in paytos])
            self.payto_e.setText(text)
            self.payto_e.setFocus()

    def on_permit_contact_edit(self, item, column):
        # openalias items shouldn't be editable
        return item.text(2) != "openalias"

    def on_contact_edited(self, item, column, prior):
        if column == 0:  # Remove old contact if renamed
            self.contacts.pop(prior)
        self.set_contact(unicode(item.text(0)), unicode(item.text(1)))

    def set_contact(self, label, address):
        if not is_valid(address):
            self.show_error(_('Invalid Address'))
            self.contacts_list.update()  # Displays original unchanged value
            return False
        self.contacts[label] = ('address', address)
        self.contacts_list.update()
        self.history_list.update()
        self.update_completions()
        return True

    def delete_contacts(self, labels):
        if not self.question(_("Remove %s from your list of contacts?")
                             % " + ".join(labels)):
            return
        for label in labels:
            self.contacts.pop(label)
        self.history_list.update()
        self.contacts_list.update()
        self.update_completions()

    def create_contact_menu(self, position):
        menu = QMenu()
        selected = self.contacts_list.selectedItems()
        if not selected:
            menu.addAction(_("New contact"), lambda: self.new_contact_dialog())
        else:
            labels = [unicode(item.text(0)) for item in selected]
            addrs = [unicode(item.text(1)) for item in selected]
            types = [unicode(item.text(2)) for item in selected]
            menu.addAction(_("Copy to Clipboard"), lambda:
                           self.app.clipboard().setText('\n'.join(labels)))
            menu.addAction(_("Pay to"), lambda: self.payto_contacts(labels))
            menu.addAction(_("Delete"), lambda: self.delete_contacts(labels))
            URLs = []
            for (addr, _type) in zip(addrs, types):
                if _type == 'address':
                    URLs.append(block_explorer_URL(self.config, 'addr', addr))
            if URLs:
                menu.addAction(_("View on block explorer"),
                               lambda: map(webbrowser.open, URLs))

        run_hook('create_contact_menu', menu, selected)
        menu.exec_(self.contacts_list.viewport().mapToGlobal(position))


    def show_invoice(self, key):
        pr = self.invoices.get(key)
        pr.verify(self.contacts)
        self.show_pr_details(pr)

    def show_pr_details(self, pr):
        d = WindowModalDialog(self, _("Invoice"))
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
        if pr.verify(self.contacts):
            self.payment_request_ok()
        else:
            self.payment_request_error()


    def invoices_list_menu(self, position):
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
            self.invoices_list.update()
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
                c, u, x = self.wallet.get_account_balance(k)
                account_item = QTreeWidgetItem([ name, '', self.format_amount(c + u + x), ''])
                account_item.setExpanded(self.accounts_expanded.get(k, True))
                account_item.setData(0, Qt.UserRole, k)
                l.addTopLevelItem(account_item)
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
                    num = len(self.wallet.history.get(address,[]))
                    is_used = self.wallet.is_used(address)
                    label = self.wallet.labels.get(address,'')
                    c, u, x = self.wallet.get_addr_balance(address)
                    balance = self.format_amount(c + u + x)
                    item = QTreeWidgetItem([address, label, balance, "%d"%num])
                    item.setFont(0, QFont(MONOSPACE_FONT))
                    item.setData(0, Qt.UserRole, address)
                    item.setData(0, Qt.UserRole+1, True) # label can be edited
                    if self.wallet.is_frozen(address):
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
        current_key = item.data(0, Qt.UserRole).toString() if item else None
        l.clear()
        for key in sorted(self.contacts.keys()):
            _type, value = self.contacts[key]
            item = QTreeWidgetItem([key, value, _type])
            item.setData(0, Qt.UserRole, key)
            l.addTopLevelItem(item)
            if key == current_key:
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

        console.updateNamespace({'wallet' : self.wallet,
                                 'network' : self.network,
                                 'plugins' : self.gui_object.plugins,
                                 'window': self})
        console.updateNamespace({'util' : util, 'bitcoin':bitcoin})

        c = commands.Commands(self.config, self.wallet, self.network, lambda: self.console.set_json(True))
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
        self.history_list.update()
        self.update_status()
        self.address_list.update()
        self.receive_list.update()

    def create_status_bar(self):

        sb = QStatusBar()
        sb.setFixedHeight(35)
        qtVersion = qVersion()

        self.balance_label = QLabel("")
        sb.addWidget(self.balance_label)

        self.account_selector = QComboBox()
        self.account_selector.setSizeAdjustPolicy(QComboBox.AdjustToContents)
        self.connect(self.account_selector, SIGNAL("activated(QString)"), self.change_account)
        sb.addPermanentWidget(self.account_selector)

        self.search_box = QLineEdit()
        self.search_box.textChanged.connect(self.do_search)
        self.search_box.hide()
        sb.addPermanentWidget(self.search_box)

        self.lock_icon = QIcon()
        self.password_button = StatusBarButton(self.lock_icon, _("Password"), self.change_password_dialog )
        sb.addPermanentWidget(self.password_button)

        sb.addPermanentWidget(StatusBarButton(QIcon(":icons/preferences.png"), _("Preferences"), self.settings_dialog ) )
        self.seed_button = StatusBarButton(QIcon(":icons/seed.png"), _("Seed"), self.show_seed_dialog )
        sb.addPermanentWidget(self.seed_button)
        self.status_button = StatusBarButton(QIcon(":icons/status_disconnected.png"), _("Network"), self.run_network_dialog )
        sb.addPermanentWidget(self.status_button)
        run_hook('create_status_bar', sb)
        self.setStatusBar(sb)

    def update_lock_icon(self):
        icon = QIcon(":icons/lock.png") if self.wallet.use_encryption else QIcon(":icons/unlock.png")
        self.password_button.setIcon(icon)

    def update_buttons_on_seed(self):
        self.seed_button.setVisible(self.wallet.has_seed())
        self.password_button.setVisible(self.wallet.can_change_password())
        self.set_send_button_text()

    def change_password_dialog(self):
        from password_dialog import PasswordDialog, PW_CHANGE

        msg = (_('Your wallet is encrypted. Use this dialog to change your '
                 'password. To disable wallet encryption, enter an empty new '
                 'password.') if self.wallet.use_encryption
               else _('Your wallet keys are not encrypted'))
        d = PasswordDialog(self, self.wallet, msg, PW_CHANGE)
        ok, password, new_password = d.run()
        if not ok:
            return

        try:
            self.wallet.check_password(password)
        except BaseException as e:
            self.show_error(str(e))
            return

        try:
            self.wallet.update_password(password, new_password)
        except:
            traceback.print_exc(file=sys.stdout)
            self.show_error(_('Failed to update password'))
            return

        if new_password:
            msg = _('Password was updated successfully')
        else:
            msg = _('This wallet is not encrypted')
        self.show_message(msg, title=_("Success"))

        self.update_lock_icon()

    def toggle_search(self):
        self.search_box.setHidden(not self.search_box.isHidden())
        if not self.search_box.isHidden():
            self.search_box.setFocus(1)
        else:
            self.do_search('')

    def do_search(self, t):
        i = self.tabs.currentIndex()
        if i == 0:
            self.history_list.filter(t, [2, 3, 4])  # Date, Description, Amount
        elif i == 1:
            self.invoices_list.filter(t, [0, 1, 2, 3]) # Date, Requestor, Description, Amount
        elif i == 2:
            self.receive_list.filter(t, [0, 1, 2, 3, 4]) # Date, Account, Address, Description, Amount
        elif i == 3:
            self.address_list.filter(t, [0,1, 2])  # Address, Label, Balance
        elif i == 4:
            self.contacts_list.filter(t, [0, 1])  # Key, Value


    def new_contact_dialog(self):
        d = WindowModalDialog(self, _("New Contact"))
        vbox = QVBoxLayout(d)
        vbox.addWidget(QLabel(_('New Contact') + ':'))
        grid = QGridLayout()
        line1 = QLineEdit()
        line1.setFixedWidth(280)
        line2 = QLineEdit()
        line2.setFixedWidth(280)
        grid.addWidget(QLabel(_("Address")), 1, 0)
        grid.addWidget(line1, 1, 1)
        grid.addWidget(QLabel(_("Name")), 2, 0)
        grid.addWidget(line2, 2, 1)

        vbox.addLayout(grid)
        vbox.addLayout(Buttons(CancelButton(d), OkButton(d)))

        if not d.exec_():
            return

        if self.set_contact(unicode(line2.text()), str(line1.text())):
            self.tabs.setCurrentIndex(4)

    def update_new_account_menu(self):
        self.new_account_menu.setVisible(self.wallet.can_create_accounts())
        self.new_account_menu.setEnabled(self.wallet.permit_account_naming())
        self.update_account_selector()

    def new_account_dialog(self):
        dialog = WindowModalDialog(self, _("New Account Name"))
        vbox = QVBoxLayout()
        msg = _("Enter a name to give the account.  You will not be "
                "permitted to create further accounts until the new account "
                "receives at least one transaction.") + "\n"
        label = QLabel(msg)
        label.setWordWrap(True)
        vbox.addWidget(label)
        e = QLineEdit()
        vbox.addWidget(e)
        vbox.addLayout(Buttons(CancelButton(dialog), OkButton(dialog)))
        dialog.setLayout(vbox)
        if dialog.exec_():
            self.wallet.set_label(self.wallet.last_account_id(), str(e.text()))
            self.address_list.update()
            self.tabs.setCurrentIndex(3)
            self.update_new_account_menu()

    def check_next_account(self):
        if self.wallet.needs_next_account() and not self.checking_accounts:
            self.checking_accounts = True
            msg = _("All the accounts in your wallet have received "
                    "transactions.  Electrum must check whether more "
                    "accounts exist; one will only be shown if "
                    "it has been used or you give it a name.")
            self.show_message(msg, title=_("Check Accounts"))
            self.create_next_account()

    @protected
    def create_next_account(self, password):
        def on_done():
            self.checking_accounts = False
            self.update_new_account_menu()
        task = partial(self.wallet.create_next_account, password)
        self.wallet.thread.add(task, on_done=on_done)

    def show_master_public_keys(self):
        dialog = WindowModalDialog(self, "Master Public Keys")
        mpk_dict = self.wallet.get_master_public_keys()
        vbox = QVBoxLayout()
        mpk_text = ShowQRTextEdit()
        mpk_text.setMaximumHeight(100)
        mpk_text.addCopyButton(self.app)
        sorted_keys = sorted(mpk_dict.keys())
        def show_mpk(index):
            mpk_text.setText(mpk_dict[sorted_keys[index]])

        # only show the combobox in case multiple accounts are available
        if len(mpk_dict) > 1:
            def label(key):
                if isinstance(self.wallet, Multisig_Wallet):
                    is_mine = self.wallet.master_private_keys.has_key(key)
                    mine_text = [_("cosigner"), _("self")]
                    return "%s (%s)" % (key, mine_text[is_mine])
                return key
            labels = list(map(label, sorted_keys))
            on_click = lambda clayout: show_mpk(clayout.selected_index())
            labels_clayout = ChoicesLayout(_("Master Public Keys"), labels,
                                           on_click)
            vbox.addLayout(labels_clayout.layout())

        show_mpk(0)
        vbox.addWidget(mpk_text)
        vbox.addLayout(Buttons(CloseButton(dialog)))
        dialog.setLayout(vbox)
        dialog.exec_()

    @protected
    def show_seed_dialog(self, password):
        if self.wallet.use_encryption and password is None:
            return    # User cancelled password input
        if not self.wallet.has_seed():
            self.show_message(_('This wallet has no seed'))
            return

        try:
            mnemonic = self.wallet.get_mnemonic(password)
        except BaseException as e:
            self.show_error(str(e))
            return
        from seed_dialog import SeedDialog
        d = SeedDialog(self, mnemonic, self.wallet.has_imported_keys())
        d.exec_()



    def show_qrcode(self, data, title = _("QR code"), parent=None):
        if not data:
            return
        d = QRDialog(data, parent or self, title)
        d.exec_()

    def show_public_keys(self, address):
        if not address: return
        try:
            pubkey_list = self.wallet.get_public_keys(address)
        except Exception as e:
            traceback.print_exc(file=sys.stdout)
            self.show_message(str(e))
            return

        d = WindowModalDialog(self, _("Public key"))
        d.setMinimumSize(600, 200)
        vbox = QVBoxLayout()
        vbox.addWidget( QLabel(_("Address") + ': ' + address))
        if isinstance(self.wallet, BIP32_RD_Wallet):
            derivation = self.wallet.address_id(address)
            vbox.addWidget(QLabel(_("Derivation") + ': ' + derivation))
        vbox.addWidget(QLabel(_("Public key") + ':'))
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

        d = WindowModalDialog(self, _("Private key"))
        d.setMinimumSize(600, 200)
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
        message = unicode(message.toPlainText()).encode('utf-8')
        task = partial(self.wallet.sign_message, str(address.text()),
                       message, password)
        def show_signed_message(sig):
            signature.setText(base64.b64encode(sig))
        self.wallet.thread.add(task, on_success=show_signed_message)

    def do_verify(self, address, message, signature):
        message = unicode(message.toPlainText())
        message = message.encode('utf-8')
        try:
            # This can throw on invalid base64
            sig = base64.b64decode(str(signature.toPlainText()))
            verified = bitcoin.verify_message(address.text(), sig, message)
        except:
            verified = False
        if verified:
            self.show_message(_("Signature verified"))
        else:
            self.show_error(_("Wrong signature"))


    def sign_verify_message(self, address=''):
        d = WindowModalDialog(self, _('Sign/verify Message'))
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
        cyphertext = str(encrypted_e.toPlainText())
        task = partial(self.wallet.decrypt_message, str(pubkey_e.text()),
                       cyphertext, password)
        self.wallet.thread.add(task, on_success=message_e.setText)

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
        d = WindowModalDialog(self, _('Encrypt/decrypt Message'))
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

    def password_dialog(self, msg=None, parent=None):
        parent = parent or self
        d = WindowModalDialog(parent, _("Enter Password"))
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
        from electrum.transaction import tx_from_str, Transaction
        try:
            tx = tx_from_str(txt)
            return Transaction(tx)
        except:
            traceback.print_exc(file=sys.stdout)
            self.show_critical(_("Electrum was unable to parse your transaction"))
            return

    def read_tx_from_qrcode(self):
        from electrum import qrscanner
        try:
            data = qrscanner.scan_qr(self.config)
        except BaseException as e:
            self.show_error(str(e))
            return
        if not data:
            return
        # if the user scanned a bitcoin URI
        if data.startswith("bitcoin:"):
            self.pay_to_URI(data)
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
        except (ValueError, IOError, os.error) as reason:
            self.show_critical(_("Electrum was unable to open your transaction file") + "\n" + str(reason), title=_("Unable to read file or no transaction found"))
        return self.tx_from_text(file_content)

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
            txid = str(txid).strip()
            try:
                r = self.network.synchronous_get(('blockchain.transaction.get',[txid]))
            except BaseException as e:
                self.show_message(str(e))
                return
            tx = transaction.Transaction(r)
            self.show_transaction(tx)


    @protected
    def export_privkeys_dialog(self, password):
        if self.wallet.is_watching_only():
            self.show_message(_("This is a watching-only wallet"))
            return

        try:
            self.wallet.check_password(password)
        except Exception as e:
            self.show_error(str(e))
            return

        d = WindowModalDialog(self, _('Private keys'))
        d.setMinimumSize(850, 300)
        vbox = QVBoxLayout(d)

        msg = "%s\n%s\n%s" % (_("WARNING: ALL your private keys are secret."),
                              _("Exposing a single private key can compromise your entire wallet!"),
                              _("In particular, DO NOT use 'redeem private key' services proposed by third parties."))
        vbox.addWidget(QLabel(msg))

        e = QTextEdit()
        e.setReadOnly(True)
        vbox.addWidget(e)

        defaultname = 'electrum-private-keys.csv'
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
        except (IOError, os.error) as reason:
            txt = "\n".join([
                _("Electrum was unable to produce a private key-export."),
                str(reason)
            ])
            self.show_critical(txt, title=_("Unable to create csv"))

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
        labelsFile = self.getOpenFileName(_("Open labels file"), "*.json")
        if not labelsFile: return
        try:
            f = open(labelsFile, 'r')
            data = f.read()
            f.close()
            for key, value in json.loads(data).items():
                self.wallet.set_label(key, value)
            self.show_message(_("Your labels were imported from") + " '%s'" % str(labelsFile))
        except (IOError, os.error) as reason:
            self.show_critical(_("Electrum was unable to import your labels.") + "\n" + str(reason))


    def do_export_labels(self):
        labels = self.wallet.labels
        try:
            fileName = self.getSaveFileName(_("Select file to save your labels"), 'electrum_labels.json', "*.json")
            if fileName:
                with open(fileName, 'w+') as f:
                    json.dump(labels, f, indent=4, sort_keys=True)
                self.show_message(_("Your labels where exported to") + " '%s'" % str(fileName))
        except (IOError, os.error), reason:
            self.show_critical(_("Electrum was unable to export your labels.") + "\n" + str(reason))


    def export_history_dialog(self):
        d = WindowModalDialog(self, _('Export History'))
        d.setMinimumSize(400, 200)
        vbox = QVBoxLayout(d)
        defaultname = os.path.expanduser('~/electrum-history.csv')
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
            self.show_critical(export_error_label + "\n" + str(reason), title=_("Unable to export history"))
            return
        self.show_message(_("Your wallet history has been successfully exported."))


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
                time_string = "unconfirmed"

            if value is not None:
                value_string = format_satoshis(value, True)
            else:
                value_string = '--'

            if tx_hash:
                label = wallet.get_label(tx_hash)
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
        d = WindowModalDialog(self, title=_('Sweep private keys'))
        d.setMinimumSize(600, 300)

        vbox = QVBoxLayout(d)
        vbox.addWidget(QLabel(_("Enter private keys:")))

        keys_e = QTextEdit()
        keys_e.setTabChangesFocus(True)
        vbox.addWidget(keys_e)

        addresses = self.wallet.get_unused_addresses(self.current_account)
        h, address_e = address_field(addresses)
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

        fee = self.wallet.fee_per_kb(self.config)
        tx = Transaction.sweep(get_pk(), self.network, get_address(), fee)
        if not tx:
            self.show_message(_('No inputs found. (Note that inputs need to be confirmed)'))
            return
        self.warn_if_watching_only()
        self.show_transaction(tx)


    @protected
    def do_import_privkey(self, password):
        if not self.wallet.has_imported_keys():
            if not self.question('<b>'+_('Warning') +':\n</b><br/>'+ _('Imported keys are not recoverable from seed.') + ' ' \
                                 + _('If you ever need to restore your wallet from its seed, these keys will be lost.') + '<p>' \
                                 + _('Are you sure you understand what you are doing?'), title=_('Warning')):
                return

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
            self.show_message(_("The following addresses were added") + ':\n' + '\n'.join(addrlist))
        if badkeys:
            self.show_critical(_("The following inputs could not be imported") + ':\n'+ '\n'.join(badkeys))
        self.address_list.update()
        self.history_list.update()


    def settings_dialog(self):
        self.need_restart = False
        d = WindowModalDialog(self, _('Preferences'))
        vbox = QVBoxLayout()
        tabs = QTabWidget()
        gui_widgets = []
        tx_widgets = []
        id_widgets = []

        # language
        lang_help = _('Select which language is used in the GUI (after restart).')
        lang_label = HelpLabel(_('Language') + ':', lang_help)
        lang_combo = QComboBox()
        from electrum.i18n import languages
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
        gui_widgets.append((lang_label, lang_combo))

        nz_help = _('Number of zeros displayed after the decimal point. For example, if this is set to 2, "1." will be displayed as "1.00"')
        nz_label = HelpLabel(_('Zeros after decimal point') + ':', nz_help)
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
                self.history_list.update()
                self.address_list.update()
        nz.valueChanged.connect(on_nz)
        gui_widgets.append((nz_label, nz))

        msg = '\n'.join([
            _('Fee per kilobyte of transaction.')
        ])
        fee_label = HelpLabel(_('Transaction fee per kb') + ':', msg)
        fee_e = BTCkBEdit(self.get_decimal_point)
        def on_fee(is_done):
            if self.config.get('dynamic_fees'):
                return
            v = fee_e.get_amount() or 0
            self.config.set_key('fee_per_kb', v, is_done)
            self.update_fee()
        fee_e.editingFinished.connect(lambda: on_fee(True))
        fee_e.textEdited.connect(lambda: on_fee(False))
        tx_widgets.append((fee_label, fee_e))

        dynfee_cb = QCheckBox(_('Dynamic fees'))
        dynfee_cb.setChecked(self.config.get('dynamic_fees', False))
        dynfee_cb.setToolTip(_("Use a fee per kB value recommended by the server."))
        dynfee_sl = QSlider(Qt.Horizontal, self)
        # The pref is from 0 to 100; add 50 to get the factor from 50% to 150%
        dynfee_sl.setRange(0, 100)
        dynfee_sl.setTickInterval(10)
        dynfee_sl.setTickPosition(QSlider.TicksBelow)
        dynfee_sl.setValue(self.config.get('fee_factor', 50))
        dynfee_sl.setToolTip("Min = 50%, Max = 150%")
        multiplier_label = HelpLabel("", _("Multiply the recommended fee/kb value by a constant factor. Min = 50%, Max = 150%"))
        tx_widgets.append((dynfee_cb, dynfee_sl))
        tx_widgets.append((None, multiplier_label))

        def update_feeperkb():
            fee_e.setAmount(self.wallet.fee_per_kb(self.config))
            b = self.config.get('dynamic_fees', False)
            dynfee_sl.setEnabled(b)
            multiplier_label.setEnabled(b)
            fee_e.setEnabled(not b)
        def slider_moved():
            multiplier_label.setText(_('Fee multiplier: %3d%%')
                                     % (dynfee_sl.sliderPosition() + 50))
        def slider_released():
            self.config.set_key('fee_factor', dynfee_sl.sliderPosition(), False)
            update_feeperkb()
        def on_dynfee(x):
            dynfee = x == Qt.Checked
            self.config.set_key('dynamic_fees', dynfee)
            update_feeperkb()
        dynfee_cb.stateChanged.connect(on_dynfee)
        dynfee_sl.valueChanged.connect(slider_moved)
        dynfee_sl.sliderReleased.connect(slider_released)
        update_feeperkb()
        slider_moved()

        msg = _('OpenAlias record, used to receive coins and to sign payment requests.') + '\n\n'\
              + _('The following alias providers are available:') + '\n'\
              + '\n'.join(['https://cryptoname.co/', 'http://xmr.link']) + '\n\n'\
              + 'For more information, see http://openalias.org'
        alias_label = HelpLabel(_('OpenAlias') + ':', msg)
        alias = self.config.get('alias','')
        alias_e = QLineEdit(alias)
        def set_alias_color():
            if not self.config.get('alias'):
                alias_e.setStyleSheet("")
                return
            if self.alias_info:
                alias_addr, alias_name, validated = self.alias_info
                alias_e.setStyleSheet(GREEN_BG if validated else RED_BG)
            else:
                alias_e.setStyleSheet(RED_BG)
        def on_alias_edit():
            alias_e.setStyleSheet("")
            alias = str(alias_e.text())
            self.config.set_key('alias', alias, True)
            if alias:
                self.fetch_alias()
        set_alias_color()
        self.connect(self, SIGNAL('alias_received'), set_alias_color)
        alias_e.editingFinished.connect(on_alias_edit)
        id_widgets.append((alias_label, alias_e))

        # SSL certificate
        msg = ' '.join([
            _('SSL certificate used to sign payment requests.'),
            _('Use setconfig to set ssl_chain and ssl_privkey.'),
        ])
        if self.config.get('ssl_privkey') or self.config.get('ssl_chain'):
            try:
                SSL_identity = paymentrequest.check_ssl_config(self.config)
                SSL_error = None
            except BaseException as e:
                SSL_identity = "error"
                SSL_error = str(e)
        else:
            SSL_identity = ""
            SSL_error = None
        SSL_id_label = HelpLabel(_('SSL certificate') + ':', msg)
        SSL_id_e = QLineEdit(SSL_identity)
        SSL_id_e.setStyleSheet(RED_BG if SSL_error else GREEN_BG if SSL_identity else '')
        if SSL_error:
            SSL_id_e.setToolTip(SSL_error)
        SSL_id_e.setReadOnly(True)
        id_widgets.append((SSL_id_label, SSL_id_e))

        units = ['BTC', 'mBTC', 'bits']
        msg = _('Base unit of your wallet.')\
              + '\n1BTC=1000mBTC.\n' \
              + _(' These settings affects the fields in the Send tab')+' '
        unit_label = HelpLabel(_('Base unit') + ':', msg)
        unit_combo = QComboBox()
        unit_combo.addItems(units)
        unit_combo.setCurrentIndex(units.index(self.base_unit()))
        def on_unit(x):
            unit_result = units[unit_combo.currentIndex()]
            if self.base_unit() == unit_result:
                return
            edits = self.amount_e, self.fee_e, self.receive_amount_e, fee_e
            amounts = [edit.get_amount() for edit in edits]
            if unit_result == 'BTC':
                self.decimal_point = 8
            elif unit_result == 'mBTC':
                self.decimal_point = 5
            elif unit_result == 'bits':
                self.decimal_point = 2
            else:
                raise Exception('Unknown base unit')
            self.config.set_key('decimal_point', self.decimal_point, True)
            self.history_list.update()
            self.receive_list.update()
            self.address_list.update()
            for edit, amount in zip(edits, amounts):
                edit.setAmount(amount)
            self.update_status()
        unit_combo.currentIndexChanged.connect(on_unit)
        gui_widgets.append((unit_label, unit_combo))

        block_explorers = sorted(block_explorer_info.keys())
        msg = _('Choose which online block explorer to use for functions that open a web browser')
        block_ex_label = HelpLabel(_('Online Block Explorer') + ':', msg)
        block_ex_combo = QComboBox()
        block_ex_combo.addItems(block_explorers)
        block_ex_combo.setCurrentIndex(block_explorers.index(block_explorer(self.config)))
        def on_be(x):
            be_result = block_explorers[block_ex_combo.currentIndex()]
            self.config.set_key('block_explorer', be_result, True)
        block_ex_combo.currentIndexChanged.connect(on_be)
        gui_widgets.append((block_ex_label, block_ex_combo))

        from electrum import qrscanner
        system_cameras = qrscanner._find_system_cameras()
        qr_combo = QComboBox()
        qr_combo.addItem("Default","default")
        for camera, device in system_cameras.items():
            qr_combo.addItem(camera, device)
        #combo.addItem("Manually specify a device", config.get("video_device"))
        index = qr_combo.findData(self.config.get("video_device"))
        qr_combo.setCurrentIndex(index)
        msg = _("Install the zbar package to enable this.\nOn linux, type: 'apt-get install python-zbar'")
        qr_label = HelpLabel(_('Video Device') + ':', msg)
        qr_combo.setEnabled(qrscanner.zbar is not None)
        on_video_device = lambda x: self.config.set_key("video_device", str(qr_combo.itemData(x).toString()), True)
        qr_combo.currentIndexChanged.connect(on_video_device)
        gui_widgets.append((qr_label, qr_combo))

        usechange_cb = QCheckBox(_('Use change addresses'))
        usechange_cb.setChecked(self.wallet.use_change)
        if not self.config.is_modifiable('use_change'): usechange_cb.setEnabled(False)
        def on_usechange(x):
            usechange_result = x == Qt.Checked
            if self.wallet.use_change != usechange_result:
                self.wallet.use_change = usechange_result
                self.wallet.storage.put('use_change', self.wallet.use_change)
                multiple_cb.setEnabled(self.wallet.use_change)
        usechange_cb.stateChanged.connect(on_usechange)
        usechange_cb.setToolTip(_('Using change addresses makes it more difficult for other people to track your transactions.'))

        def on_multiple(x):
            multiple = x == Qt.Checked
            if self.wallet.multiple_change != multiple:
                self.wallet.multiple_change = multiple
                self.wallet.storage.put('multiple_change', multiple)
        multiple_change = self.wallet.multiple_change
        multiple_cb = QCheckBox(_('Use multiple change addresses'))
        multiple_cb.setEnabled(self.wallet.use_change)
        multiple_cb.setToolTip('\n'.join([
            _('In some cases, use up to 3 change addresses in order to break '
              'up large coin amounts and obfuscate the recipient address.'),
            _('This may result in higher transactions fees.')
        ]))
        multiple_cb.setChecked(multiple_change)
        multiple_cb.stateChanged.connect(on_multiple)
        tx_widgets.append((usechange_cb, None))
        tx_widgets.append((multiple_cb, None))

        showtx_cb = QCheckBox(_('View transaction before signing'))
        showtx_cb.setChecked(self.show_before_broadcast())
        showtx_cb.stateChanged.connect(lambda x: self.set_show_before_broadcast(showtx_cb.isChecked()))
        showtx_cb.setToolTip(_('Display the details of your transactions before signing it.'))
        tx_widgets.append((showtx_cb, None))

        can_edit_fees_cb = QCheckBox(_('Set transaction fees manually'))
        can_edit_fees_cb.setChecked(self.config.get('can_edit_fees', False))
        def on_editfees(x):
            self.config.set_key('can_edit_fees', x == Qt.Checked)
            self.update_fee_edit()
        can_edit_fees_cb.stateChanged.connect(on_editfees)
        can_edit_fees_cb.setToolTip(_('This option lets you edit fees in the send tab.'))
        tx_widgets.append((can_edit_fees_cb, None))

        def fmt_docs(key, klass):
            lines = [ln.lstrip(" ") for ln in klass.__doc__.split("\n")]
            return '\n'.join([key, "", " ".join(lines)])

        choosers = sorted(coinchooser.COIN_CHOOSERS.keys())
        chooser_name = coinchooser.get_name(self.config)
        msg = _('Choose coin (UTXO) selection method.  The following are available:\n\n')
        msg += '\n\n'.join(fmt_docs(*item) for item in coinchooser.COIN_CHOOSERS.items())
        chooser_label = HelpLabel(_('Coin selection') + ':', msg)
        chooser_combo = QComboBox()
        chooser_combo.addItems(choosers)
        i = choosers.index(chooser_name) if chooser_name in choosers else 0
        chooser_combo.setCurrentIndex(i)
        def on_chooser(x):
            chooser_name = choosers[chooser_combo.currentIndex()]
            self.config.set_key('coin_chooser', chooser_name)
        chooser_combo.currentIndexChanged.connect(on_chooser)
        tx_widgets.append((chooser_label, chooser_combo))

        tabs_info = [
            (tx_widgets, _('Transactions')),
            (gui_widgets, _('Appearance')),
            (id_widgets, _('Identity')),
        ]
        for widgets, name in tabs_info:
            tab = QWidget()
            grid = QGridLayout(tab)
            grid.setColumnStretch(0,1)
            for a,b in widgets:
                i = grid.rowCount()
                if b:
                    if a:
                        grid.addWidget(a, i, 0)
                    grid.addWidget(b, i, 1)
                else:
                    grid.addWidget(a, i, 0, 1, 2)
            tabs.addTab(tab, name)

        vbox.addWidget(tabs)
        vbox.addStretch(1)
        vbox.addLayout(Buttons(CloseButton(d)))
        d.setLayout(vbox)

        # run the dialog
        d.exec_()
        self.disconnect(self, SIGNAL('alias_received'), set_alias_color)

        run_hook('close_settings_dialog')
        if self.need_restart:
            self.show_warning(_('Please restart Electrum to activate the new GUI settings'), title=_('Success'))

    def run_network_dialog(self):
        if not self.network:
            self.show_warning(_('You are using Electrum in offline mode; restart Electrum if you want to get connected'), title=_('Offline'))
            return
        NetworkDialog(self.wallet.network, self.config, self).do_exec()

    def closeEvent(self, event):
        # It seems in some rare cases this closeEvent() is called twice
        if not self.cleaned_up:
            self.cleaned_up = True
            self.clean_up()
        event.accept()

    def clean_up(self):
        self.wallet.thread.stop()
        if self.network:
            self.network.unregister_callback(self.on_network)
        self.config.set_key("is_maximized", self.isMaximized())
        if not self.isMaximized():
            g = self.geometry()
            self.wallet.storage.put("winpos-qt", [g.left(),g.top(),
                                                  g.width(),g.height()])
        self.config.set_key("console-history", self.console.history[-50:],
                            True)
        if self.qr_window:
            self.qr_window.close()
        self.close_wallet()
        self.gui_object.close_window(self)

    def plugins_dialog(self):
        self.pluginsdialog = d = WindowModalDialog(self, _('Electrum Plugins'))

        plugins = self.gui_object.plugins

        vbox = QVBoxLayout(d)

        # plugins
        scroll = QScrollArea()
        scroll.setEnabled(True)
        scroll.setWidgetResizable(True)
        scroll.setMinimumSize(400,250)
        vbox.addWidget(scroll)

        w = QWidget()
        scroll.setWidget(w)
        w.setMinimumHeight(plugins.count() * 35)

        grid = QGridLayout()
        grid.setColumnStretch(0,1)
        w.setLayout(grid)

        settings_widgets = {}

        def enable_settings_widget(p, name, i):
            widget = settings_widgets.get(name)
            if not widget and p and p.requires_settings():
                widget = settings_widgets[name] = p.settings_widget(d)
                grid.addWidget(widget, i, 1)
            if widget:
                widget.setEnabled(bool(p and p.is_enabled()))

        def do_toggle(cb, name, i):
            p = plugins.toggle(name)
            cb.setChecked(bool(p))
            enable_settings_widget(p, name, i)
            run_hook('init_qt', self.gui_object)

        for i, descr in enumerate(plugins.descriptions.values()):
            name = descr['__name__']
            p = plugins.get(name)
            if descr.get('registers_wallet_type'):
                continue
            try:
                cb = QCheckBox(descr['fullname'])
                cb.setEnabled(plugins.is_available(name, self.wallet))
                cb.setChecked(p is not None and p.is_enabled())
                grid.addWidget(cb, i, 0)
                enable_settings_widget(p, name, i)
                cb.clicked.connect(partial(do_toggle, cb, name, i))
                msg = descr['description']
                if descr.get('requires'):
                    msg += '\n\n' + _('Requires') + ':\n' + '\n'.join(map(lambda x: x[1], descr.get('requires')))
                grid.addWidget(HelpButton(msg), i, 2)
            except Exception:
                self.print_msg("error: cannot display plugin", name)
                traceback.print_exc(file=sys.stdout)
        grid.setRowStretch(i+1,1)
        vbox.addLayout(Buttons(CloseButton(d)))
        d.exec_()

    def show_account_details(self, k):
        account = self.wallet.accounts[k]

        d = WindowModalDialog(self, _('Account Details'))

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
