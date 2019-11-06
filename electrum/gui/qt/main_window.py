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
import sys
import time
import threading
import os
import traceback
import json
import shutil
import weakref
import csv
from decimal import Decimal
import base64
from functools import partial
import queue
import asyncio
from typing import Optional

from PyQt5.QtGui import QPixmap, QKeySequence, QIcon, QCursor
from PyQt5.QtCore import Qt, QRect, QStringListModel, QSize, pyqtSignal
from PyQt5.QtWidgets import (QMessageBox, QComboBox, QSystemTrayIcon, QTabWidget,
                             QSpinBox, QMenuBar, QFileDialog, QCheckBox, QLabel,
                             QVBoxLayout, QGridLayout, QLineEdit, QTreeWidgetItem,
                             QHBoxLayout, QPushButton, QScrollArea, QTextEdit,
                             QShortcut, QMainWindow, QCompleter, QInputDialog,
                             QWidget, QMenu, QSizePolicy, QStatusBar)

import electrum
from electrum import (keystore, simple_config, ecc, constants, util, bitcoin, commands,
                      coinchooser, paymentrequest)
from electrum.bitcoin import COIN, is_address, TYPE_ADDRESS
from electrum.plugin import run_hook
from electrum.i18n import _
from electrum.util import (format_time, format_satoshis, format_fee_satoshis,
                           format_satoshis_plain, NotEnoughFunds,
                           UserCancelled, NoDynamicFeeEstimates, profiler,
                           export_meta, import_meta, bh2u, bfh, InvalidPassword,
                           base_units, base_units_list, base_unit_name_to_decimal_point,
                           decimal_point_to_base_unit_name, quantize_feerate,
                           UnknownBaseUnit, DECIMAL_POINT_DEFAULT, UserFacingException,
                           get_new_wallet_name, send_exception_to_crash_reporter,
                           InvalidBitcoinURI)
from electrum.transaction import Transaction, TxOutput
from electrum.address_synchronizer import AddTransactionException
from electrum.wallet import (Multisig_Wallet, CannotBumpFee, Abstract_Wallet,
                             sweep_preparations, InternalAddressCorruption)
from electrum.version import ELECTRUM_VERSION
from electrum.network import Network, TxBroadcastError, BestEffortRequestFailed
from electrum.exchange_rate import FxThread
from electrum.simple_config import SimpleConfig
from electrum.logging import Logger
from electrum.paymentrequest import PR_PAID

from .exception_window import Exception_Hook
from .amountedit import AmountEdit, BTCAmountEdit, MyLineEdit, FeerateEdit
from .qrcodewidget import QRCodeWidget, QRDialog
from .qrtextedit import ShowQRTextEdit, ScanQRTextEdit
from .transaction_dialog import show_transaction
from .fee_slider import FeeSlider
from .util import (read_QIcon, ColorScheme, text_dialog, icon_path, WaitingDialog,
                   WindowModalDialog, ChoicesLayout, HelpLabel, FromList, Buttons,
                   OkButton, InfoButton, WWLabel, TaskThread, CancelButton,
                   CloseButton, HelpButton, MessageBoxMixin, EnterButton, expiration_values,
                   ButtonsLineEdit, CopyCloseButton, import_meta_gui, export_meta_gui,
                   filename_field, address_field, char_width_in_lineedit, webopen)
from .installwizard import WIF_HELP_TEXT
from .history_list import HistoryList, HistoryModel
from .update_checker import UpdateCheck, UpdateCheckThread


class StatusBarButton(QPushButton):
    def __init__(self, icon, tooltip, func):
        QPushButton.__init__(self, icon, '')
        self.setToolTip(tooltip)
        self.setFlat(True)
        self.setMaximumWidth(25)
        self.clicked.connect(self.onPress)
        self.func = func
        self.setIconSize(QSize(25,25))
        self.setCursor(QCursor(Qt.PointingHandCursor))

    def onPress(self, checked=False):
        '''Drops the unwanted PyQt5 "checked" argument'''
        self.func()

    def keyPressEvent(self, e):
        if e.key() == Qt.Key_Return:
            self.func()


class ElectrumWindow(QMainWindow, MessageBoxMixin, Logger):

    payment_request_ok_signal = pyqtSignal()
    payment_request_error_signal = pyqtSignal()
    new_fx_quotes_signal = pyqtSignal()
    new_fx_history_signal = pyqtSignal()
    network_signal = pyqtSignal(str, object)
    alias_received_signal = pyqtSignal()
    computing_privkeys_signal = pyqtSignal()
    show_privkeys_signal = pyqtSignal()

    def __init__(self, gui_object, wallet: Abstract_Wallet):
        QMainWindow.__init__(self)

        self.gui_object = gui_object
        self.config = config = gui_object.config  # type: SimpleConfig
        self.gui_thread = gui_object.gui_thread

        self.setup_exception_hook()

        self.network = gui_object.daemon.network  # type: Network
        assert wallet, "no wallet"
        self.wallet = wallet
        self.fx = gui_object.daemon.fx  # type: FxThread
        self.invoices = wallet.invoices
        self.contacts = wallet.contacts
        self.tray = gui_object.tray
        self.app = gui_object.app
        self.cleaned_up = False
        self.payment_request = None  # type: Optional[paymentrequest.PaymentRequest]
        self.checking_accounts = False
        self.qr_window = None
        self.not_enough_funds = False
        self.pluginsdialog = None
        self.require_fee_update = False
        self.tl_windows = []
        self.tx_external_keypairs = {}
        Logger.__init__(self)

        self.tx_notification_queue = queue.Queue()
        self.tx_notification_last_time = 0

        self.create_status_bar()
        self.need_update = threading.Event()

        self.decimal_point = config.get('decimal_point', DECIMAL_POINT_DEFAULT)
        try:
            decimal_point_to_base_unit_name(self.decimal_point)
        except UnknownBaseUnit:
            self.decimal_point = DECIMAL_POINT_DEFAULT
        self.num_zeros = int(config.get('num_zeros', 0))

        self.completions = QStringListModel()

        self.tabs = tabs = QTabWidget(self)
        self.send_tab = self.create_send_tab()
        self.receive_tab = self.create_receive_tab()
        self.addresses_tab = self.create_addresses_tab()
        self.utxo_tab = self.create_utxo_tab()
        self.console_tab = self.create_console_tab()
        self.contacts_tab = self.create_contacts_tab()
        tabs.addTab(self.create_history_tab(), read_QIcon("tab_history.png"), _('History'))
        tabs.addTab(self.send_tab, read_QIcon("tab_send.png"), _('Send'))
        tabs.addTab(self.receive_tab, read_QIcon("tab_receive.png"), _('Receive'))

        def add_optional_tab(tabs, tab, icon, description, name):
            tab.tab_icon = icon
            tab.tab_description = description
            tab.tab_pos = len(tabs)
            tab.tab_name = name
            if self.config.get('show_{}_tab'.format(name), False):
                tabs.addTab(tab, icon, description.replace("&", ""))

        add_optional_tab(tabs, self.addresses_tab, read_QIcon("tab_addresses.png"), _("&Addresses"), "addresses")
        add_optional_tab(tabs, self.utxo_tab, read_QIcon("tab_coins.png"), _("Co&ins"), "utxo")
        add_optional_tab(tabs, self.contacts_tab, read_QIcon("tab_contacts.png"), _("Con&tacts"), "contacts")
        add_optional_tab(tabs, self.console_tab, read_QIcon("tab_console.png"), _("Con&sole"), "console")

        tabs.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.setCentralWidget(tabs)

        if self.config.get("is_maximized"):
            self.showMaximized()

        self.setWindowIcon(read_QIcon("electrum.png"))
        self.init_menubar()

        wrtabs = weakref.proxy(tabs)
        QShortcut(QKeySequence("Ctrl+W"), self, self.close)
        QShortcut(QKeySequence("Ctrl+Q"), self, self.close)
        QShortcut(QKeySequence("Ctrl+R"), self, self.update_wallet)
        QShortcut(QKeySequence("F5"), self, self.update_wallet)
        QShortcut(QKeySequence("Ctrl+PgUp"), self, lambda: wrtabs.setCurrentIndex((wrtabs.currentIndex() - 1)%wrtabs.count()))
        QShortcut(QKeySequence("Ctrl+PgDown"), self, lambda: wrtabs.setCurrentIndex((wrtabs.currentIndex() + 1)%wrtabs.count()))

        for i in range(wrtabs.count()):
            QShortcut(QKeySequence("Alt+" + str(i + 1)), self, lambda i=i: wrtabs.setCurrentIndex(i))

        self.payment_request_ok_signal.connect(self.payment_request_ok)
        self.payment_request_error_signal.connect(self.payment_request_error)
        self.history_list.setFocus(True)

        # network callbacks
        if self.network:
            self.network_signal.connect(self.on_network_qt)
            interests = ['wallet_updated', 'network_updated', 'blockchain_updated',
                         'new_transaction', 'status',
                         'banner', 'verified', 'fee', 'fee_histogram']
            # To avoid leaking references to "self" that prevent the
            # window from being GC-ed when closed, callbacks should be
            # methods of this class only, and specifically not be
            # partials, lambdas or methods of subobjects.  Hence...
            self.network.register_callback(self.on_network, interests)
            # set initial message
            self.console.showMessage(self.network.banner)
            self.network.register_callback(self.on_quotes, ['on_quotes'])
            self.network.register_callback(self.on_history, ['on_history'])
            self.new_fx_quotes_signal.connect(self.on_fx_quotes)
            self.new_fx_history_signal.connect(self.on_fx_history)

        # update fee slider in case we missed the callback
        self.fee_slider.update()
        self.load_wallet(wallet)
        gui_object.timer.timeout.connect(self.timer_actions)
        self.fetch_alias()

        # If the option hasn't been set yet
        if config.get('check_updates') is None:
            choice = self.question(title="Electrum - " + _("Enable update check"),
                                   msg=_("For security reasons we advise that you always use the latest version of Electrum.") + " " +
                                       _("Would you like to be notified when there is a newer version of Electrum available?"))
            config.set_key('check_updates', bool(choice), save=True)

        if config.get('check_updates', False):
            # The references to both the thread and the window need to be stored somewhere
            # to prevent GC from getting in our way.
            def on_version_received(v):
                if UpdateCheck.is_newer(v):
                    self.update_check_button.setText(_("Update to Electrum {} is available").format(v))
                    self.update_check_button.clicked.connect(lambda: self.show_update_check(v))
                    self.update_check_button.show()
            self._update_check_thread = UpdateCheckThread(self)
            self._update_check_thread.checked.connect(on_version_received)
            self._update_check_thread.start()

    def on_history(self, b):
        self.wallet.clear_coin_price_cache()
        self.new_fx_history_signal.emit()

    def setup_exception_hook(self):
        Exception_Hook(self)

    def on_fx_history(self):
        self.history_model.refresh('fx_history')
        self.address_list.update()

    def on_quotes(self, b):
        self.new_fx_quotes_signal.emit()

    def on_fx_quotes(self):
        self.update_status()
        # Refresh edits with the new rate
        edit = self.fiat_send_e if self.fiat_send_e.is_last_edited else self.amount_e
        edit.textEdited.emit(edit.text())
        edit = self.fiat_receive_e if self.fiat_receive_e.is_last_edited else self.receive_amount_e
        edit.textEdited.emit(edit.text())
        # History tab needs updating if it used spot
        if self.fx.history_used_spot:
            self.history_model.refresh('fx_quotes')
        self.address_list.update()

    def toggle_tab(self, tab):
        show = not self.config.get('show_{}_tab'.format(tab.tab_name), False)
        self.config.set_key('show_{}_tab'.format(tab.tab_name), show)
        item_text = (_("Hide {}") if show else _("Show {}")).format(tab.tab_description)
        tab.menu_action.setText(item_text)
        if show:
            # Find out where to place the tab
            index = len(self.tabs)
            for i in range(len(self.tabs)):
                try:
                    if tab.tab_pos < self.tabs.widget(i).tab_pos:
                        index = i
                        break
                except AttributeError:
                    pass
            self.tabs.insertTab(index, tab, tab.tab_icon, tab.tab_description.replace("&", ""))
        else:
            i = self.tabs.indexOf(tab)
            self.tabs.removeTab(i)

    def push_top_level_window(self, window):
        '''Used for e.g. tx dialog box to ensure new dialogs are appropriately
        parented.  This used to be done by explicitly providing the parent
        window, but that isn't something hardware wallet prompts know.'''
        self.tl_windows.append(window)

    def pop_top_level_window(self, window):
        self.tl_windows.remove(window)

    def top_level_window(self, test_func=None):
        '''Do the right thing in the presence of tx dialog windows'''
        override = self.tl_windows[-1] if self.tl_windows else None
        if override and test_func and not test_func(override):
            override = None  # only override if ok for test_func
        return self.top_level_window_recurse(override, test_func)

    def diagnostic_name(self):
        #return '{}:{}'.format(self.__class__.__name__, self.wallet.diagnostic_name())
        return self.wallet.diagnostic_name()

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
        e = exc_info[1]
        if isinstance(e, UserCancelled):
            pass
        elif isinstance(e, UserFacingException):
            self.show_error(str(e))
        else:
            try:
                self.logger.error("on_error", exc_info=exc_info)
            except OSError:
                pass  # see #4418
            self.show_error(str(e))

    def on_network(self, event, *args):
        if event == 'wallet_updated':
            wallet = args[0]
            if wallet == self.wallet:
                self.need_update.set()
        elif event == 'network_updated':
            self.gui_object.network_updated_signal_obj.network_updated_signal \
                .emit(event, args)
            self.network_signal.emit('status', None)
        elif event == 'blockchain_updated':
            # to update number of confirmations in history
            self.need_update.set()
        elif event == 'new_transaction':
            wallet, tx = args
            if wallet == self.wallet:
                self.tx_notification_queue.put(tx)
        elif event in ['status', 'banner', 'verified', 'fee', 'fee_histogram']:
            # Handle in GUI thread
            self.network_signal.emit(event, args)
        else:
            self.logger.info(f"unexpected network message: {event} {args}")

    def on_network_qt(self, event, args=None):
        # Handle a network message in the GUI thread
        if event == 'status':
            self.update_status()
        elif event == 'banner':
            self.console.showMessage(args[0])
        elif event == 'verified':
            wallet, tx_hash, tx_mined_status = args
            if wallet == self.wallet:
                self.history_model.update_tx_mined_status(tx_hash, tx_mined_status)
        elif event == 'fee':
            if self.config.is_dynfee():
                self.fee_slider.update()
                self.require_fee_update = True
        elif event == 'fee_histogram':
            if self.config.is_dynfee():
                self.fee_slider.update()
                self.require_fee_update = True
            self.history_model.on_fee_histogram()
        else:
            self.logger.info(f"unexpected network_qt signal: {event} {args}")

    def fetch_alias(self):
        self.alias_info = None
        alias = self.config.get('alias')
        if alias:
            alias = str(alias)
            def f():
                self.alias_info = self.contacts.resolve_openalias(alias)
                self.alias_received_signal.emit()
            t = threading.Thread(target=f)
            t.setDaemon(True)
            t.start()

    def close_wallet(self):
        if self.wallet:
            self.logger.info(f'close_wallet {self.wallet.storage.path}')
        run_hook('close_wallet', self.wallet)

    @profiler
    def load_wallet(self, wallet):
        wallet.thread = TaskThread(self, self.on_error)
        self.update_recently_visited(wallet.storage.path)
        self.need_update.set()
        # Once GUI has been initialized check if we want to announce something since the callback has been called before the GUI was initialized
        # update menus
        self.seed_menu.setEnabled(self.wallet.has_seed())
        self.update_lock_icon()
        self.update_buttons_on_seed()
        self.update_console()
        self.clear_receive_tab()
        self.request_list.update()
        self.tabs.show()
        self.init_geometry()
        if self.config.get('hide_gui') and self.gui_object.tray.isVisible():
            self.hide()
        else:
            self.show()
        self.watching_only_changed()
        run_hook('load_wallet', wallet, self)
        try:
            wallet.try_detecting_internal_addresses_corruption()
        except InternalAddressCorruption as e:
            self.show_error(str(e))
            send_exception_to_crash_reporter(e)

    def init_geometry(self):
        winpos = self.wallet.storage.get("winpos-qt")
        try:
            screen = self.app.desktop().screenGeometry()
            assert screen.contains(QRect(*winpos))
            self.setGeometry(*winpos)
        except:
            self.logger.info("using default geometry")
            self.setGeometry(100, 100, 840, 400)

    def watching_only_changed(self):
        name = "Electrum Testnet" if constants.net.TESTNET else "Electrum"
        title = '%s %s  -  %s' % (name, ELECTRUM_VERSION,
                                        self.wallet.basename())
        extra = [self.wallet.storage.get('wallet_type', '?')]
        if self.wallet.is_watching_only():
            extra.append(_('watching only'))
        title += '  [%s]'% ', '.join(extra)
        self.setWindowTitle(title)
        self.password_menu.setEnabled(self.wallet.may_have_password())
        self.import_privkey_menu.setVisible(self.wallet.can_import_privkey())
        self.import_address_menu.setVisible(self.wallet.can_import_address())
        self.export_menu.setEnabled(self.wallet.can_export())

    def warn_if_watching_only(self):
        if self.wallet.is_watching_only():
            msg = ' '.join([
                _("This wallet is watching-only."),
                _("This means you will not be able to spend Bitcoins with it."),
                _("Make sure you own the seed phrase or the private keys, before you request Bitcoins to be sent to this wallet.")
            ])
            self.show_warning(msg, title=_('Watch-only wallet'))

    def warn_if_testnet(self):
        if not constants.net.TESTNET:
            return
        # user might have opted out already
        if self.config.get('dont_show_testnet_warning', False):
            return
        # only show once per process lifecycle
        if getattr(self.gui_object, '_warned_testnet', False):
            return
        self.gui_object._warned_testnet = True
        msg = ''.join([
            _("You are in testnet mode."), ' ',
            _("Testnet coins are worthless."), '\n',
            _("Testnet is separate from the main Bitcoin network. It is used for testing.")
        ])
        cb = QCheckBox(_("Don't show this again."))
        cb_checked = False
        def on_cb(x):
            nonlocal cb_checked
            cb_checked = x == Qt.Checked
        cb.stateChanged.connect(on_cb)
        self.show_warning(msg, title=_('Testnet'), checkbox=cb)
        if cb_checked:
            self.config.set_key('dont_show_testnet_warning', True)

    def open_wallet(self):
        try:
            wallet_folder = self.get_wallet_folder()
        except FileNotFoundError as e:
            self.show_error(str(e))
            return
        filename, __ = QFileDialog.getOpenFileName(self, "Select your wallet file", wallet_folder)
        if not filename:
            return
        self.gui_object.new_window(filename)


    def backup_wallet(self):
        path = self.wallet.storage.path
        wallet_folder = os.path.dirname(path)
        filename, __ = QFileDialog.getSaveFileName(self, _('Enter a filename for the copy of your wallet'), wallet_folder)
        if not filename:
            return
        new_path = os.path.join(wallet_folder, filename)
        if new_path != path:
            try:
                shutil.copy2(path, new_path)
                self.show_message(_("A copy of your wallet file was created in")+" '%s'" % str(new_path), title=_("Wallet backup created"))
            except BaseException as reason:
                self.show_critical(_("Electrum was unable to copy your wallet file to the specified location.") + "\n" + str(reason), title=_("Unable to create backup"))

    def update_recently_visited(self, filename):
        recent = self.config.get('recently_open', [])
        try:
            sorted(recent)
        except:
            recent = []
        if filename in recent:
            recent.remove(filename)
        recent.insert(0, filename)
        recent = [path for path in recent if os.path.exists(path)]
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
        try:
            wallet_folder = self.get_wallet_folder()
        except FileNotFoundError as e:
            self.show_error(str(e))
            return
        filename = get_new_wallet_name(wallet_folder)
        full_path = os.path.join(wallet_folder, filename)
        self.gui_object.start_new_window(full_path, None)

    def init_menubar(self):
        menubar = QMenuBar()

        file_menu = menubar.addMenu(_("&File"))
        self.recently_visited_menu = file_menu.addMenu(_("&Recently open"))
        file_menu.addAction(_("&Open"), self.open_wallet).setShortcut(QKeySequence.Open)
        file_menu.addAction(_("&New/Restore"), self.new_wallet).setShortcut(QKeySequence.New)
        file_menu.addAction(_("&Save Copy"), self.backup_wallet).setShortcut(QKeySequence.SaveAs)
        file_menu.addAction(_("Delete"), self.remove_wallet)
        file_menu.addSeparator()
        file_menu.addAction(_("&Quit"), self.close)

        wallet_menu = menubar.addMenu(_("&Wallet"))
        wallet_menu.addAction(_("&Information"), self.show_master_public_keys)
        wallet_menu.addSeparator()
        self.password_menu = wallet_menu.addAction(_("&Password"), self.change_password_dialog)
        self.seed_menu = wallet_menu.addAction(_("&Seed"), self.show_seed_dialog)
        self.private_keys_menu = wallet_menu.addMenu(_("&Private keys"))
        self.private_keys_menu.addAction(_("&Sweep"), self.sweep_key_dialog)
        self.import_privkey_menu = self.private_keys_menu.addAction(_("&Import"), self.do_import_privkey)
        self.export_menu = self.private_keys_menu.addAction(_("&Export"), self.export_privkeys_dialog)
        self.import_address_menu = wallet_menu.addAction(_("Import addresses"), self.import_addresses)
        wallet_menu.addSeparator()

        addresses_menu = wallet_menu.addMenu(_("&Addresses"))
        addresses_menu.addAction(_("&Filter"), lambda: self.address_list.toggle_toolbar(self.config))
        labels_menu = wallet_menu.addMenu(_("&Labels"))
        labels_menu.addAction(_("&Import"), self.do_import_labels)
        labels_menu.addAction(_("&Export"), self.do_export_labels)
        history_menu = wallet_menu.addMenu(_("&History"))
        history_menu.addAction(_("&Filter"), lambda: self.history_list.toggle_toolbar(self.config))
        history_menu.addAction(_("&Summary"), self.history_list.show_summary)
        history_menu.addAction(_("&Plot"), self.history_list.plot_history_dialog)
        history_menu.addAction(_("&Export"), self.history_list.export_history_dialog)
        contacts_menu = wallet_menu.addMenu(_("Contacts"))
        contacts_menu.addAction(_("&New"), self.new_contact_dialog)
        contacts_menu.addAction(_("Import"), lambda: self.contact_list.import_contacts())
        contacts_menu.addAction(_("Export"), lambda: self.contact_list.export_contacts())
        invoices_menu = wallet_menu.addMenu(_("Invoices"))
        invoices_menu.addAction(_("Import"), lambda: self.invoice_list.import_invoices())
        invoices_menu.addAction(_("Export"), lambda: self.invoice_list.export_invoices())

        wallet_menu.addSeparator()
        wallet_menu.addAction(_("Find"), self.toggle_search).setShortcut(QKeySequence("Ctrl+F"))

        def add_toggle_action(view_menu, tab):
            is_shown = self.config.get('show_{}_tab'.format(tab.tab_name), False)
            item_name = (_("Hide") if is_shown else _("Show")) + " " + tab.tab_description
            tab.menu_action = view_menu.addAction(item_name, lambda: self.toggle_tab(tab))

        view_menu = menubar.addMenu(_("&View"))
        add_toggle_action(view_menu, self.addresses_tab)
        add_toggle_action(view_menu, self.utxo_tab)
        add_toggle_action(view_menu, self.contacts_tab)
        add_toggle_action(view_menu, self.console_tab)

        tools_menu = menubar.addMenu(_("&Tools"))

        # Settings / Preferences are all reserved keywords in macOS using this as work around
        tools_menu.addAction(_("Electrum preferences") if sys.platform == 'darwin' else _("Preferences"), self.settings_dialog)
        tools_menu.addAction(_("&Network"), lambda: self.gui_object.show_network_dialog(self))
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
        run_hook('init_menubar_tools', self, tools_menu)

        help_menu = menubar.addMenu(_("&Help"))
        help_menu.addAction(_("&About"), self.show_about)
        help_menu.addAction(_("&Check for updates"), self.show_update_check)
        help_menu.addAction(_("&Official website"), lambda: webopen("https://electrum.org"))
        help_menu.addSeparator()
        help_menu.addAction(_("&Documentation"), lambda: webopen("http://docs.electrum.org/")).setShortcut(QKeySequence.HelpContents)
        help_menu.addAction(_("&Report Bug"), self.show_report_bug)
        help_menu.addSeparator()
        help_menu.addAction(_("&Donate to server"), self.donate_to_server)

        self.setMenuBar(menubar)

    def donate_to_server(self):
        d = self.network.get_donation_address()
        if d:
            host = self.network.get_parameters().host
            self.pay_to_URI('bitcoin:%s?message=donation for %s'%(d, host))
        else:
            self.show_error(_('No donation address for this server'))

    def show_about(self):
        QMessageBox.about(self, "Electrum",
                          (_("Version")+" %s" % ELECTRUM_VERSION + "\n\n" +
                           _("Electrum's focus is speed, with low resource usage and simplifying Bitcoin.") + " " +
                           _("You do not need to perform regular backups, because your wallet can be "
                              "recovered from a secret phrase that you can memorize or write on paper.") + " " +
                           _("Startup times are instant because it operates in conjunction with high-performance "
                              "servers that handle the most complicated parts of the Bitcoin system.") + "\n\n" +
                           _("Uses icons from the Icons8 icon pack (icons8.com).")))

    def show_update_check(self, version=None):
        self.gui_object._update_check = UpdateCheck(self, version)

    def show_report_bug(self):
        msg = ' '.join([
            _("Please report any bugs as issues on github:<br/>"),
            f'''<a href="{constants.GIT_REPO_ISSUES_URL}">{constants.GIT_REPO_ISSUES_URL}</a><br/><br/>''',
            _("Before reporting a bug, upgrade to the most recent version of Electrum (latest release or git HEAD), and include the version number in your report."),
            _("Try to explain not only what the bug is, but how it occurs.")
         ])
        self.show_message(msg, title="Electrum - " + _("Reporting Bugs"), rich_text=True)

    def notify_transactions(self):
        if self.tx_notification_queue.qsize() == 0:
            return
        if not self.wallet.up_to_date:
            return  # no notifications while syncing
        now = time.time()
        rate_limit = 20  # seconds
        if self.tx_notification_last_time + rate_limit > now:
            return
        self.tx_notification_last_time = now
        self.logger.info("Notifying GUI about new transactions")
        txns = []
        while True:
            try:
                txns.append(self.tx_notification_queue.get_nowait())
            except queue.Empty:
                break
        # Combine the transactions if there are at least three
        if len(txns) >= 3:
            total_amount = 0
            for tx in txns:
                is_relevant, is_mine, v, fee = self.wallet.get_wallet_delta(tx)
                if not is_relevant:
                    continue
                total_amount += v
            self.notify(_("{} new transactions: Total amount received in the new transactions {}")
                        .format(len(txns), self.format_amount_and_units(total_amount)))
        else:
            for tx in txns:
                is_relevant, is_mine, v, fee = self.wallet.get_wallet_delta(tx)
                if not is_relevant:
                    continue
                self.notify(_("New transaction: {}").format(self.format_amount_and_units(v)))

    def notify(self, message):
        if self.tray:
            try:
                # this requires Qt 5.9
                self.tray.showMessage("Electrum", message, read_QIcon("electrum_dark_icon"), 20000)
            except TypeError:
                self.tray.showMessage("Electrum", message, QSystemTrayIcon.Information, 20000)



    # custom wrappers for getOpenFileName and getSaveFileName, that remember the path selected by the user
    def getOpenFileName(self, title, filter = ""):
        directory = self.config.get('io_dir', os.path.expanduser('~'))
        fileName, __ = QFileDialog.getOpenFileName(self, title, directory, filter)
        if fileName and directory != os.path.dirname(fileName):
            self.config.set_key('io_dir', os.path.dirname(fileName), True)
        return fileName

    def getSaveFileName(self, title, filename, filter = ""):
        directory = self.config.get('io_dir', os.path.expanduser('~'))
        path = os.path.join( directory, filename )
        fileName, __ = QFileDialog.getSaveFileName(self, title, path, filter)
        if fileName and directory != os.path.dirname(fileName):
            self.config.set_key('io_dir', os.path.dirname(fileName), True)
        return fileName

    def timer_actions(self):
        # Note this runs in the GUI thread
        if self.need_update.is_set():
            self.need_update.clear()
            self.update_wallet()
        elif not self.wallet.up_to_date:
            # this updates "synchronizing" progress
            self.update_status()
        # resolve aliases
        # FIXME this is a blocking network call that has a timeout of 5 sec
        self.payto_e.resolve()
        # update fee
        if self.require_fee_update:
            self.do_update_fee()
            self.require_fee_update = False
        self.notify_transactions()

    def format_amount(self, x, is_diff=False, whitespaces=False):
        return format_satoshis(x, self.num_zeros, self.decimal_point, is_diff=is_diff, whitespaces=whitespaces)

    def format_amount_and_units(self, amount):
        text = self.format_amount(amount) + ' '+ self.base_unit()
        x = self.fx.format_amount_and_units(amount) if self.fx else None
        if text and x:
            text += ' (%s)'%x
        return text

    def format_fee_rate(self, fee_rate):
        # fee_rate is in sat/kB
        return format_fee_satoshis(fee_rate/1000, num_zeros=self.num_zeros) + ' sat/byte'

    def get_decimal_point(self):
        return self.decimal_point

    def base_unit(self):
        return decimal_point_to_base_unit_name(self.decimal_point)

    def connect_fields(self, window, btc_e, fiat_e, fee_e):

        def edit_changed(edit):
            if edit.follows:
                return
            edit.setStyleSheet(ColorScheme.DEFAULT.as_stylesheet())
            fiat_e.is_last_edited = (edit == fiat_e)
            amount = edit.get_amount()
            rate = self.fx.exchange_rate() if self.fx else Decimal('NaN')
            if rate.is_nan() or amount is None:
                if edit is fiat_e:
                    btc_e.setText("")
                    if fee_e:
                        fee_e.setText("")
                else:
                    fiat_e.setText("")
            else:
                if edit is fiat_e:
                    btc_e.follows = True
                    btc_e.setAmount(int(amount / Decimal(rate) * COIN))
                    btc_e.setStyleSheet(ColorScheme.BLUE.as_stylesheet())
                    btc_e.follows = False
                    if fee_e:
                        window.update_fee()
                else:
                    fiat_e.follows = True
                    fiat_e.setText(self.fx.ccy_amount_str(
                        amount * Decimal(rate) / COIN, False))
                    fiat_e.setStyleSheet(ColorScheme.BLUE.as_stylesheet())
                    fiat_e.follows = False

        btc_e.follows = False
        fiat_e.follows = False
        fiat_e.textChanged.connect(partial(edit_changed, fiat_e))
        btc_e.textChanged.connect(partial(edit_changed, btc_e))
        fiat_e.is_last_edited = False

    def update_status(self):
        if not self.wallet:
            return

        if self.network is None:
            text = _("Offline")
            icon = read_QIcon("status_disconnected.png")

        elif self.network.is_connected():
            server_height = self.network.get_server_height()
            server_lag = self.network.get_local_height() - server_height
            fork_str = "_fork" if len(self.network.get_blockchains())>1 else ""
            # Server height can be 0 after switching to a new server
            # until we get a headers subscription request response.
            # Display the synchronizing message in that case.
            if not self.wallet.up_to_date or server_height == 0:
                num_sent, num_answered = self.wallet.get_history_sync_state_details()
                text = ("{} ({}/{})"
                        .format(_("Synchronizing..."), num_answered, num_sent))
                icon = read_QIcon("status_waiting.png")
            elif server_lag > 1:
                text = _("Server is lagging ({} blocks)").format(server_lag)
                icon = read_QIcon("status_lagging%s.png"%fork_str)
            else:
                c, u, x = self.wallet.get_balance()
                text =  _("Balance" ) + ": %s "%(self.format_amount_and_units(c))
                if u:
                    text +=  " [%s unconfirmed]"%(self.format_amount(u, is_diff=True).strip())
                if x:
                    text +=  " [%s unmatured]"%(self.format_amount(x, is_diff=True).strip())

                # append fiat balance and price
                if self.fx.is_enabled():
                    text += self.fx.get_fiat_status_text(c + u + x,
                        self.base_unit(), self.get_decimal_point()) or ''
                if not self.network.proxy:
                    icon = read_QIcon("status_connected%s.png"%fork_str)
                else:
                    icon = read_QIcon("status_connected_proxy%s.png"%fork_str)
        else:
            if self.network.proxy:
                text = "{} ({})".format(_("Not connected"), _("proxy enabled"))
            else:
                text = _("Not connected")
            icon = read_QIcon("status_disconnected.png")

        self.tray.setToolTip("%s (%s)" % (text, self.wallet.basename()))
        self.balance_label.setText(text)
        self.status_button.setIcon( icon )

    def update_wallet(self):
        self.update_status()
        if self.wallet.up_to_date or not self.network or not self.network.is_connected():
            self.update_tabs()

    def update_tabs(self, wallet=None):
        if wallet is None:
            wallet = self.wallet
        if wallet != self.wallet:
            return
        self.history_model.refresh('update_tabs')
        self.request_list.update()
        self.address_list.update()
        self.utxo_list.update()
        self.contact_list.update()
        self.invoice_list.update()
        self.update_completions()

    def create_history_tab(self):
        self.history_model = HistoryModel(self)
        self.history_list = l = HistoryList(self, self.history_model)
        self.history_model.set_view(self.history_list)
        l.searchable_list = l
        toolbar = l.create_toolbar(self.config)
        toolbar_shown = self.config.get('show_toolbar_history', False)
        l.show_toolbar(toolbar_shown)
        return self.create_list_tab(l, toolbar)

    def show_address(self, addr):
        from . import address_dialog
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
        self.receive_address_e.textChanged.connect(self.update_receive_address_styling)
        self.receive_address_e.setFocusPolicy(Qt.ClickFocus)
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

        self.fiat_receive_e = AmountEdit(self.fx.get_currency if self.fx else '')
        if not self.fx or not self.fx.is_enabled():
            self.fiat_receive_e.setVisible(False)
        grid.addWidget(self.fiat_receive_e, 2, 2, Qt.AlignLeft)
        self.connect_fields(self, self.receive_amount_e, self.fiat_receive_e, None)

        self.expires_combo = QComboBox()
        self.expires_combo.addItems([i[0] for i in expiration_values])
        self.expires_combo.setCurrentIndex(3)
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

        from .request_list import RequestList
        self.request_list = RequestList(self)

        # layout
        vbox_g = QVBoxLayout()
        vbox_g.addLayout(grid)
        vbox_g.addStretch()

        hbox = QHBoxLayout()
        hbox.addLayout(vbox_g)
        hbox.addWidget(self.receive_qr)

        w = QWidget()
        w.searchable_list = self.request_list
        vbox = QVBoxLayout(w)
        vbox.addLayout(hbox)
        vbox.addStretch(1)
        vbox.addWidget(self.receive_requests_label)
        vbox.addWidget(self.request_list)
        vbox.setStretchFactor(self.request_list, 1000)

        return w


    def delete_payment_request(self, addr):
        self.wallet.remove_payment_request(addr, self.config)
        self.request_list.update()
        self.clear_receive_tab()

    def get_request_URI(self, addr):
        req = self.wallet.receive_requests[addr]
        message = self.wallet.labels.get(addr, '')
        amount = req['amount']
        extra_query_params = {}
        if req.get('time'):
            extra_query_params['time'] = str(int(req.get('time')))
        if req.get('exp'):
            extra_query_params['exp'] = str(int(req.get('exp')))
        if req.get('name') and req.get('sig'):
            sig = bfh(req.get('sig'))
            sig = bitcoin.base_encode(sig, base=58)
            extra_query_params['name'] = req['name']
            extra_query_params['sig'] = sig
        uri = util.create_bip21_uri(addr, amount, message, extra_query_params=extra_query_params)
        return str(uri)


    def sign_payment_request(self, addr):
        alias = self.config.get('alias')
        alias_privkey = None
        if alias and self.alias_info:
            alias_addr, alias_name, validated = self.alias_info
            if alias_addr:
                if self.wallet.is_mine(alias_addr):
                    msg = _('This payment request will be signed.') + '\n' + _('Please enter your password')
                    password = None
                    if self.wallet.has_keystore_encryption():
                        password = self.password_dialog(msg)
                        if not password:
                            return
                    try:
                        self.wallet.sign_payment_request(addr, alias, alias_addr, password)
                    except Exception as e:
                        self.show_error(str(e))
                        return
                else:
                    return

    def save_payment_request(self):
        addr = str(self.receive_address_e.text())
        amount = self.receive_amount_e.get_amount()
        message = self.receive_message_e.text()
        if not message and not amount:
            self.show_error(_('No message or amount'))
            return False
        i = self.expires_combo.currentIndex()
        expiration = list(map(lambda x: x[1], expiration_values))[i]
        req = self.wallet.make_payment_request(addr, amount, message, expiration)
        try:
            self.wallet.add_payment_request(req, self.config)
        except Exception as e:
            self.logger.exception('Error adding payment request')
            self.show_error(_('Error adding payment request') + ':\n' + str(e))
        else:
            self.sign_payment_request(addr)
            self.save_request_button.setEnabled(False)
        finally:
            self.request_list.update()
            self.address_list.update()

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
                f.write(util.to_bytes(pr))
            self.show_message(_("Request saved successfully"))
            self.saved = True

    def new_payment_request(self):
        addr = self.wallet.get_unused_address()
        if addr is None:
            if not self.wallet.is_deterministic():
                msg = [
                    _('No more addresses in your wallet.'),
                    _('You are using a non-deterministic wallet, which cannot create new addresses.'),
                    _('If you want to create new addresses, use a deterministic wallet instead.')
                   ]
                self.show_message(' '.join(msg))
                return
            if not self.question(_("Warning: The next address will not be recovered automatically if you restore your wallet from seed; you may need to add it manually.\n\nThis occurs because you have too many unused addresses in your wallet. To avoid this situation, use the existing addresses first.\n\nCreate anyway?")):
                return
            addr = self.wallet.create_new_address(False)
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
        try:
            addr = self.wallet.get_receiving_address() or ''
        except InternalAddressCorruption as e:
            self.show_error(str(e))
            addr = ''
        self.receive_address_e.setText(addr)
        self.receive_message_e.setText('')
        self.receive_amount_e.setAmount(None)
        self.expires_label.hide()
        self.expires_combo.show()

    def toggle_qr_window(self):
        from . import qrwindow
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

    def show_send_tab(self):
        self.tabs.setCurrentIndex(self.tabs.indexOf(self.send_tab))

    def show_receive_tab(self):
        self.tabs.setCurrentIndex(self.tabs.indexOf(self.receive_tab))

    def receive_at(self, addr):
        if not bitcoin.is_address(addr):
            return
        self.show_receive_tab()
        self.receive_address_e.setText(addr)
        self.new_request_button.setEnabled(True)

    def update_receive_qr(self):
        addr = str(self.receive_address_e.text())
        amount = self.receive_amount_e.get_amount()
        message = self.receive_message_e.text()
        self.save_request_button.setEnabled((amount is not None) or (message != ""))
        uri = util.create_bip21_uri(addr, amount, message)
        self.receive_qr.setData(uri)
        if self.qr_window and self.qr_window.isVisible():
            self.qr_window.qrw.setData(uri)

    def update_receive_address_styling(self):
        addr = str(self.receive_address_e.text())
        if self.wallet.is_used(addr):
            self.receive_address_e.setStyleSheet(ColorScheme.RED.as_stylesheet(True))
            self.receive_address_e.setToolTip(_("This address has already been used. "
                                                "For better privacy, do not reuse it for new payments."))
        else:
            self.receive_address_e.setStyleSheet("")
            self.receive_address_e.setToolTip("")

    def set_feerounding_text(self, num_satoshis_added):
        self.feerounding_text = (_('Additional {} satoshis are going to be added.')
                                 .format(num_satoshis_added))

    def create_send_tab(self):
        # A 4-column grid layout.  All the stretch is in the last column.
        # The exchange rate plugin adds a fiat widget in column 2
        self.send_grid = grid = QGridLayout()
        grid.setSpacing(8)
        grid.setColumnStretch(3, 1)

        from .paytoedit import PayToEdit
        self.amount_e = BTCAmountEdit(self.get_decimal_point)
        self.payto_e = PayToEdit(self)
        msg = _('Recipient of the funds.') + '\n\n'\
              + _('You may enter a Bitcoin address, a label from your list of contacts (a list of completions will be proposed), or an alias (email-like address that forwards to a Bitcoin address)')
        payto_label = HelpLabel(_('Pay to'), msg)
        grid.addWidget(payto_label, 1, 0)
        grid.addWidget(self.payto_e, 1, 1, 1, -1)

        completer = QCompleter()
        completer.setCaseSensitivity(False)
        self.payto_e.set_completer(completer)
        completer.setModel(self.completions)

        msg = _('Description of the transaction (not mandatory).') + '\n\n'\
              + _('The description is not sent to the recipient of the funds. It is stored in your wallet file, and displayed in the \'History\' tab.')
        description_label = HelpLabel(_('Description'), msg)
        grid.addWidget(description_label, 2, 0)
        self.message_e = MyLineEdit()
        grid.addWidget(self.message_e, 2, 1, 1, -1)

        self.from_label = QLabel(_('From'))
        grid.addWidget(self.from_label, 3, 0)
        self.from_list = FromList(self, self.from_list_menu)
        grid.addWidget(self.from_list, 3, 1, 1, -1)
        self.set_pay_from([])

        msg = _('Amount to be sent.') + '\n\n' \
              + _('The amount will be displayed in red if you do not have enough funds in your wallet.') + ' ' \
              + _('Note that if you have frozen some of your addresses, the available funds will be lower than your total balance.') + '\n\n' \
              + _('Keyboard shortcut: type "!" to send all your coins.')
        amount_label = HelpLabel(_('Amount'), msg)
        grid.addWidget(amount_label, 4, 0)
        grid.addWidget(self.amount_e, 4, 1)

        self.fiat_send_e = AmountEdit(self.fx.get_currency if self.fx else '')
        if not self.fx or not self.fx.is_enabled():
            self.fiat_send_e.setVisible(False)
        grid.addWidget(self.fiat_send_e, 4, 2)
        self.amount_e.frozen.connect(
            lambda: self.fiat_send_e.setFrozen(self.amount_e.isReadOnly()))

        self.max_button = EnterButton(_("Max"), self.spend_max)
        self.max_button.setFixedWidth(self.amount_e.width())
        self.max_button.setCheckable(True)
        grid.addWidget(self.max_button, 4, 3)
        hbox = QHBoxLayout()
        hbox.addStretch(1)
        grid.addLayout(hbox, 4, 4)

        msg = _('Bitcoin transactions are in general not free. A transaction fee is paid by the sender of the funds.') + '\n\n'\
              + _('The amount of fee can be decided freely by the sender. However, transactions with low fees take more time to be processed.') + '\n\n'\
              + _('A suggested fee is automatically added to this field. You may override it. The suggested fee increases with the size of the transaction.')
        self.fee_e_label = HelpLabel(_('Fee'), msg)

        def fee_cb(dyn, pos, fee_rate):
            if dyn:
                if self.config.use_mempool_fees():
                    self.config.set_key('depth_level', pos, False)
                else:
                    self.config.set_key('fee_level', pos, False)
            else:
                self.config.set_key('fee_per_kb', fee_rate, False)

            if fee_rate:
                fee_rate = Decimal(fee_rate)
                self.feerate_e.setAmount(quantize_feerate(fee_rate / 1000))
            else:
                self.feerate_e.setAmount(None)
            self.fee_e.setModified(False)

            self.fee_slider.activate()
            self.spend_max() if self.max_button.isChecked() else self.update_fee()

        self.fee_slider = FeeSlider(self, self.config, fee_cb)
        self.fee_slider.setFixedWidth(self.amount_e.width())

        def on_fee_or_feerate(edit_changed, editing_finished):
            edit_other = self.feerate_e if edit_changed == self.fee_e else self.fee_e
            if editing_finished:
                if edit_changed.get_amount() is None:
                    # This is so that when the user blanks the fee and moves on,
                    # we go back to auto-calculate mode and put a fee back.
                    edit_changed.setModified(False)
            else:
                # edit_changed was edited just now, so make sure we will
                # freeze the correct fee setting (this)
                edit_other.setModified(False)
            self.fee_slider.deactivate()
            self.update_fee()

        class TxSizeLabel(QLabel):
            def setAmount(self, byte_size):
                self.setText(('x   %s bytes   =' % byte_size) if byte_size else '')

        self.size_e = TxSizeLabel()
        self.size_e.setAlignment(Qt.AlignCenter)
        self.size_e.setAmount(0)
        self.size_e.setFixedWidth(self.amount_e.width())
        self.size_e.setStyleSheet(ColorScheme.DEFAULT.as_stylesheet())

        self.feerate_e = FeerateEdit(lambda: 0)
        self.feerate_e.setAmount(self.config.fee_per_byte())
        self.feerate_e.textEdited.connect(partial(on_fee_or_feerate, self.feerate_e, False))
        self.feerate_e.editingFinished.connect(partial(on_fee_or_feerate, self.feerate_e, True))

        self.fee_e = BTCAmountEdit(self.get_decimal_point)
        self.fee_e.textEdited.connect(partial(on_fee_or_feerate, self.fee_e, False))
        self.fee_e.editingFinished.connect(partial(on_fee_or_feerate, self.fee_e, True))

        def feerounding_onclick():
            text = (self.feerounding_text + '\n\n' +
                    _('To somewhat protect your privacy, Electrum tries to create change with similar precision to other outputs.') + ' ' +
                    _('At most 100 satoshis might be lost due to this rounding.') + ' ' +
                    _("You can disable this setting in '{}'.").format(_('Preferences')) + '\n' +
                    _('Also, dust is not kept as change, but added to the fee.')  + '\n' +
                    _('Also, when batching RBF transactions, BIP 125 imposes a lower bound on the fee.'))
            self.show_message(title=_('Fee rounding'), msg=text)

        self.feerounding_icon = QPushButton(read_QIcon('info.png'), '')
        self.feerounding_icon.setFixedWidth(round(2.2 * char_width_in_lineedit()))
        self.feerounding_icon.setFlat(True)
        self.feerounding_icon.clicked.connect(feerounding_onclick)
        self.feerounding_icon.setVisible(False)

        self.connect_fields(self, self.amount_e, self.fiat_send_e, self.fee_e)

        vbox_feelabel = QVBoxLayout()
        vbox_feelabel.addWidget(self.fee_e_label)
        vbox_feelabel.addStretch(1)
        grid.addLayout(vbox_feelabel, 5, 0)

        self.fee_adv_controls = QWidget()
        hbox = QHBoxLayout(self.fee_adv_controls)
        hbox.setContentsMargins(0, 0, 0, 0)
        hbox.addWidget(self.feerate_e)
        hbox.addWidget(self.size_e)
        hbox.addWidget(self.fee_e)
        hbox.addWidget(self.feerounding_icon, Qt.AlignLeft)
        hbox.addStretch(1)

        vbox_feecontrol = QVBoxLayout()
        vbox_feecontrol.addWidget(self.fee_adv_controls)
        vbox_feecontrol.addWidget(self.fee_slider)

        grid.addLayout(vbox_feecontrol, 5, 1, 1, -1)

        if not self.config.get('show_fee', False):
            self.fee_adv_controls.setVisible(False)

        self.preview_button = EnterButton(_("Preview"), self.do_preview)
        self.preview_button.setToolTip(_('Display the details of your transaction before signing it.'))
        self.send_button = EnterButton(_("Send"), self.do_send)
        self.clear_button = EnterButton(_("Clear"), self.do_clear)
        buttons = QHBoxLayout()
        buttons.addStretch(1)
        buttons.addWidget(self.clear_button)
        buttons.addWidget(self.preview_button)
        buttons.addWidget(self.send_button)
        grid.addLayout(buttons, 6, 1, 1, 3)

        self.amount_e.shortcut.connect(self.spend_max)
        self.payto_e.textChanged.connect(self.update_fee)
        self.amount_e.textEdited.connect(self.update_fee)

        def reset_max(text):
            self.max_button.setChecked(False)
            enable = not bool(text) and not self.amount_e.isReadOnly()
            self.max_button.setEnabled(enable)
        self.amount_e.textEdited.connect(reset_max)
        self.fiat_send_e.textEdited.connect(reset_max)

        def entry_changed():
            text = ""

            amt_color = ColorScheme.DEFAULT
            fee_color = ColorScheme.DEFAULT
            feerate_color = ColorScheme.DEFAULT

            if self.not_enough_funds:
                amt_color, fee_color = ColorScheme.RED, ColorScheme.RED
                feerate_color = ColorScheme.RED
                text = _("Not enough funds")
                c, u, x = self.wallet.get_frozen_balance()
                if c+u+x:
                    text += " ({} {} {})".format(
                        self.format_amount(c + u + x).strip(), self.base_unit(), _("are frozen")
                    )

            # blue color denotes auto-filled values
            elif self.fee_e.isModified():
                feerate_color = ColorScheme.BLUE
            elif self.feerate_e.isModified():
                fee_color = ColorScheme.BLUE
            elif self.amount_e.isModified():
                fee_color = ColorScheme.BLUE
                feerate_color = ColorScheme.BLUE
            else:
                amt_color = ColorScheme.BLUE
                fee_color = ColorScheme.BLUE
                feerate_color = ColorScheme.BLUE

            self.statusBar().showMessage(text)
            self.amount_e.setStyleSheet(amt_color.as_stylesheet())
            self.fee_e.setStyleSheet(fee_color.as_stylesheet())
            self.feerate_e.setStyleSheet(feerate_color.as_stylesheet())

        self.amount_e.textChanged.connect(entry_changed)
        self.fee_e.textChanged.connect(entry_changed)
        self.feerate_e.textChanged.connect(entry_changed)

        self.invoices_label = QLabel(_('Invoices'))
        from .invoice_list import InvoiceList
        self.invoice_list = InvoiceList(self)

        vbox0 = QVBoxLayout()
        vbox0.addLayout(grid)
        hbox = QHBoxLayout()
        hbox.addLayout(vbox0)
        w = QWidget()
        vbox = QVBoxLayout(w)
        vbox.addLayout(hbox)
        vbox.addStretch(1)
        vbox.addWidget(self.invoices_label)
        vbox.addWidget(self.invoice_list)
        vbox.setStretchFactor(self.invoice_list, 1000)
        w.searchable_list = self.invoice_list
        run_hook('create_send_tab', grid)
        return w

    def spend_max(self):
        if run_hook('abort_send', self):
            return
        self.max_button.setChecked(True)
        self.do_update_fee()

    def update_fee(self):
        self.require_fee_update = True

    def get_payto_or_dummy(self):
        r = self.payto_e.get_recipient()
        if r:
            return r
        return (TYPE_ADDRESS, self.wallet.dummy_address())

    def do_update_fee(self):
        '''Recalculate the fee.  If the fee was manually input, retain it, but
        still build the TX to see if there are enough funds.
        '''
        freeze_fee = self.is_send_fee_frozen()
        freeze_feerate = self.is_send_feerate_frozen()
        amount = '!' if self.max_button.isChecked() else self.amount_e.get_amount()
        if amount is None:
            if not freeze_fee:
                self.fee_e.setAmount(None)
            self.not_enough_funds = False
            self.statusBar().showMessage('')
            return

        outputs, fee_estimator, tx_desc, coins = self.read_send_tab()
        if not outputs:
            _type, addr = self.get_payto_or_dummy()
            outputs = [TxOutput(_type, addr, amount)]
        is_sweep = bool(self.tx_external_keypairs)
        make_tx = lambda fee_est: \
            self.wallet.make_unsigned_transaction(
                coins, outputs, self.config,
                fixed_fee=fee_est, is_sweep=is_sweep)
        try:
            tx = make_tx(fee_estimator)
            self.not_enough_funds = False
        except (NotEnoughFunds, NoDynamicFeeEstimates) as e:
            if not freeze_fee:
                self.fee_e.setAmount(None)
            if not freeze_feerate:
                self.feerate_e.setAmount(None)
            self.feerounding_icon.setVisible(False)

            if isinstance(e, NotEnoughFunds):
                self.not_enough_funds = True
            elif isinstance(e, NoDynamicFeeEstimates):
                try:
                    tx = make_tx(0)
                    size = tx.estimated_size()
                    self.size_e.setAmount(size)
                except BaseException:
                    pass
            return
        except BaseException:
            self.logger.exception('')
            return

        size = tx.estimated_size()
        self.size_e.setAmount(size)

        fee = tx.get_fee()
        fee = None if self.not_enough_funds else fee

        # Displayed fee/fee_rate values are set according to user input.
        # Due to rounding or dropping dust in CoinChooser,
        # actual fees often differ somewhat.
        if freeze_feerate or self.fee_slider.is_active():
            displayed_feerate = self.feerate_e.get_amount()
            if displayed_feerate is not None:
                displayed_feerate = quantize_feerate(displayed_feerate)
            else:
                # fallback to actual fee
                displayed_feerate = quantize_feerate(fee / size) if fee is not None else None
                self.feerate_e.setAmount(displayed_feerate)
            displayed_fee = round(displayed_feerate * size) if displayed_feerate is not None else None
            self.fee_e.setAmount(displayed_fee)
        else:
            if freeze_fee:
                displayed_fee = self.fee_e.get_amount()
            else:
                # fallback to actual fee if nothing is frozen
                displayed_fee = fee
                self.fee_e.setAmount(displayed_fee)
            displayed_fee = displayed_fee if displayed_fee else 0
            displayed_feerate = quantize_feerate(displayed_fee / size) if displayed_fee is not None else None
            self.feerate_e.setAmount(displayed_feerate)

        # show/hide fee rounding icon
        feerounding = (fee - displayed_fee) if fee else 0
        self.set_feerounding_text(int(feerounding))
        self.feerounding_icon.setToolTip(self.feerounding_text)
        self.feerounding_icon.setVisible(abs(feerounding) >= 1)

        if self.max_button.isChecked():
            amount = tx.output_value()
            __, x_fee_amount = run_hook('get_tx_extra_fee', self.wallet, tx) or (None, 0)
            amount_after_all_fees = amount - x_fee_amount
            self.amount_e.setAmount(amount_after_all_fees)

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

    def set_pay_from(self, coins):
        self.pay_from = list(coins)
        self.redraw_from_list()

    def redraw_from_list(self):
        self.from_list.clear()
        self.from_label.setHidden(len(self.pay_from) == 0)
        self.from_list.setHidden(len(self.pay_from) == 0)

        def format(x):
            h = x.get('prevout_hash')
            return h[0:10] + '...' + h[-10:] + ":%d"%x.get('prevout_n') + u'\t' + "%s"%x.get('address')

        for item in self.pay_from:
            self.from_list.addTopLevelItem(QTreeWidgetItem( [format(item), self.format_amount(item['value']) ]))

    def get_contact_payto(self, key):
        _type, label = self.contacts.get(key)
        return label + '  <' + key + '>' if _type == 'address' else key

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
            while self.wallet.has_keystore_encryption():
                password = self.password_dialog(parent=parent)
                if password is None:
                    # User cancelled password input
                    return
                try:
                    self.wallet.check_password(password)
                    break
                except Exception as e:
                    self.show_error(str(e), parent=parent)
                    continue

            kwargs['password'] = password
            return func(self, *args, **kwargs)
        return request_password

    def is_send_fee_frozen(self):
        return self.fee_e.isVisible() and self.fee_e.isModified() \
               and (self.fee_e.text() or self.fee_e.hasFocus())

    def is_send_feerate_frozen(self):
        return self.feerate_e.isVisible() and self.feerate_e.isModified() \
               and (self.feerate_e.text() or self.feerate_e.hasFocus())

    def get_send_fee_estimator(self):
        if self.is_send_fee_frozen():
            fee_estimator = self.fee_e.get_amount()
        elif self.is_send_feerate_frozen():
            amount = self.feerate_e.get_amount()  # sat/byte feerate
            amount = 0 if amount is None else amount * 1000  # sat/kilobyte feerate
            fee_estimator = partial(
                simple_config.SimpleConfig.estimate_fee_for_feerate, amount)
        else:
            fee_estimator = None
        return fee_estimator

    def read_send_tab(self):
        label = self.message_e.text()
        if self.payment_request:
            outputs = self.payment_request.get_outputs()
        else:
            outputs = self.payto_e.get_outputs(self.max_button.isChecked())
        fee_estimator = self.get_send_fee_estimator()
        coins = self.get_coins()
        return outputs, fee_estimator, label, coins

    def check_send_tab_outputs_and_show_errors(self, outputs) -> bool:
        """Returns whether there are errors with outputs.
        Also shows error dialog to user if so.
        """
        pr = self.payment_request
        if pr:
            if pr.has_expired():
                self.show_error(_('Payment request has expired'))
                return True

        if not pr:
            errors = self.payto_e.get_errors()
            if errors:
                self.show_warning(_("Invalid Lines found:") + "\n\n" + '\n'.join([ _("Line #") + str(x[0]+1) + ": " + x[1] for x in errors]))
                return True

            if self.payto_e.is_alias and self.payto_e.validated is False:
                alias = self.payto_e.toPlainText()
                msg = _('WARNING: the alias "{}" could not be validated via an additional '
                        'security check, DNSSEC, and thus may not be correct.').format(alias) + '\n'
                msg += _('Do you wish to continue?')
                if not self.question(msg):
                    return True

        if not outputs:
            self.show_error(_('No outputs'))
            return True

        for o in outputs:
            if o.address is None:
                self.show_error(_('Bitcoin Address is None'))
                return True
            if o.type == TYPE_ADDRESS and not bitcoin.is_address(o.address):
                self.show_error(_('Invalid Bitcoin Address'))
                return True
            if o.value is None:
                self.show_error(_('Invalid Amount'))
                return True

        return False  # no errors

    def do_preview(self):
        self.do_send(preview = True)

    def do_send(self, preview = False):
        if run_hook('abort_send', self):
            return
        outputs, fee_estimator, tx_desc, coins = self.read_send_tab()
        if self.check_send_tab_outputs_and_show_errors(outputs):
            return
        try:
            is_sweep = bool(self.tx_external_keypairs)
            tx = self.wallet.make_unsigned_transaction(
                coins, outputs, self.config, fixed_fee=fee_estimator,
                is_sweep=is_sweep)
        except (NotEnoughFunds, NoDynamicFeeEstimates) as e:
            self.show_message(str(e))
            return
        except InternalAddressCorruption as e:
            self.show_error(str(e))
            raise
        except BaseException as e:
            self.logger.exception('')
            self.show_message(str(e))
            return

        amount = tx.output_value() if self.max_button.isChecked() else sum(map(lambda x:x[2], outputs))
        fee = tx.get_fee()

        use_rbf = self.config.get('use_rbf', True)
        if use_rbf:
            tx.set_rbf(True)

        if fee < self.wallet.relayfee() * tx.estimated_size() / 1000:
            self.show_error('\n'.join([
                _("This transaction requires a higher fee, or it will not be propagated by your current server"),
                _("Try to raise your transaction fee, or use a server with a lower relay fee.")
            ]))
            return

        if preview:
            self.show_transaction(tx, tx_desc)
            return

        if not self.network:
            self.show_error(_("You can't broadcast a transaction without a live network connection."))
            return

        # confirmation dialog
        msg = [
            _("Amount to be sent") + ": " + self.format_amount_and_units(amount),
            _("Mining fee") + ": " + self.format_amount_and_units(fee),
        ]

        x_fee = run_hook('get_tx_extra_fee', self.wallet, tx)
        if x_fee:
            x_fee_address, x_fee_amount = x_fee
            msg.append( _("Additional fees") + ": " + self.format_amount_and_units(x_fee_amount) )

        feerate_warning = simple_config.FEERATE_WARNING_HIGH_FEE
        if fee > feerate_warning * tx.estimated_size() / 1000:
            msg.append(_('Warning') + ': ' + _("The fee for this transaction seems unusually high."))

        if self.wallet.has_keystore_encryption():
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
        def on_success(result):
            callback(True)
        def on_failure(exc_info):
            self.on_error(exc_info)
            callback(False)
        on_success = run_hook('tc_sign_wrapper', self.wallet, tx, on_success, on_failure) or on_success
        if self.tx_external_keypairs:
            # can sign directly
            task = partial(Transaction.sign, tx, self.tx_external_keypairs)
        else:
            task = partial(self.wallet.sign_transaction, tx, password)
        msg = _('Signing transaction...')
        WaitingDialog(self, msg, task, on_success, on_failure)

    def broadcast_transaction(self, tx, tx_desc):

        def broadcast_thread():
            # non-GUI thread
            pr = self.payment_request
            if pr and pr.has_expired():
                self.payment_request = None
                return False, _("Payment request has expired")
            status = False
            try:
                self.network.run_from_another_thread(self.network.broadcast_transaction(tx))
            except TxBroadcastError as e:
                msg = e.get_message_for_gui()
            except BestEffortRequestFailed as e:
                msg = repr(e)
            else:
                status, msg = True, tx.txid()
            if pr and status is True:
                self.invoices.set_paid(pr, tx.txid())
                self.invoices.save()
                self.payment_request = None
                refund_address = self.wallet.get_receiving_address()
                coro = pr.send_payment_and_receive_paymentack(str(tx), refund_address)
                fut = asyncio.run_coroutine_threadsafe(coro, self.network.asyncio_loop)
                ack_status, ack_msg = fut.result(timeout=20)
                self.logger.info(f"Payment ACK: {ack_status}. Ack message: {ack_msg}")
            return status, msg

        # Capture current TL window; override might be removed on return
        parent = self.top_level_window(lambda win: isinstance(win, MessageBoxMixin))

        def broadcast_done(result):
            # GUI thread
            if result:
                status, msg = result
                if status:
                    if tx_desc is not None and tx.is_complete():
                        self.wallet.set_label(tx.txid(), tx_desc)
                    parent.show_message(_('Payment sent.') + '\n' + msg)
                    self.invoice_list.update()
                    self.do_clear()
                else:
                    msg = msg or ''
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
        if not dialog.exec_():
            return None
        return clayout.selected_index()

    def lock_amount(self, b):
        self.amount_e.setFrozen(b)
        self.max_button.setEnabled(not b)

    def prepare_for_payment_request(self):
        self.show_send_tab()
        self.payto_e.is_pr = True
        for e in [self.payto_e, self.message_e]:
            e.setFrozen(True)
        self.lock_amount(True)
        self.payto_e.setText(_("please wait..."))
        return True

    def delete_invoice(self, key):
        self.invoices.remove(key)
        self.invoice_list.update()

    def payment_request_ok(self):
        pr = self.payment_request
        if not pr:
            return
        key = self.invoices.add(pr)
        status = self.invoices.get_status(key)
        self.invoice_list.update()
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
        pr = self.payment_request
        if not pr:
            return
        self.show_message(pr.error)
        self.payment_request = None
        self.do_clear()

    def on_pr(self, request):
        self.payment_request = request
        if self.payment_request.verify(self.contacts):
            self.payment_request_ok_signal.emit()
        else:
            self.payment_request_error_signal.emit()

    def pay_to_URI(self, URI):
        if not URI:
            return
        try:
            out = util.parse_URI(URI, self.on_pr)
        except InvalidBitcoinURI as e:
            self.show_error(_("Error parsing URI") + f":\n{e}")
            return
        self.show_send_tab()
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
        self.max_button.setChecked(False)
        self.not_enough_funds = False
        self.payment_request = None
        self.payto_e.is_pr = False
        for e in [self.payto_e, self.message_e, self.amount_e, self.fiat_send_e,
                  self.fee_e, self.feerate_e]:
            e.setText('')
            e.setFrozen(False)
        self.fee_slider.activate()
        self.feerate_e.setAmount(self.config.fee_per_byte())
        self.size_e.setAmount(0)
        self.feerounding_icon.setVisible(False)
        self.set_pay_from([])
        self.tx_external_keypairs = {}
        self.update_status()
        run_hook('do_clear', self)

    def set_frozen_state_of_addresses(self, addrs, freeze: bool):
        self.wallet.set_frozen_state_of_addresses(addrs, freeze)
        self.address_list.update()
        self.utxo_list.update()
        self.update_fee()

    def set_frozen_state_of_coins(self, utxos, freeze: bool):
        self.wallet.set_frozen_state_of_coins(utxos, freeze)
        self.utxo_list.update()
        self.update_fee()

    def create_list_tab(self, l, toolbar=None):
        w = QWidget()
        w.searchable_list = l
        vbox = QVBoxLayout()
        w.setLayout(vbox)
        vbox.setContentsMargins(0, 0, 0, 0)
        vbox.setSpacing(0)
        if toolbar:
            vbox.addLayout(toolbar)
        vbox.addWidget(l)
        return w

    def create_addresses_tab(self):
        from .address_list import AddressList
        self.address_list = l = AddressList(self)
        toolbar = l.create_toolbar(self.config)
        toolbar_shown = self.config.get('show_toolbar_addresses', False)
        l.show_toolbar(toolbar_shown)
        return self.create_list_tab(l, toolbar)

    def create_utxo_tab(self):
        from .utxo_list import UTXOList
        self.utxo_list = l = UTXOList(self)
        return self.create_list_tab(l)

    def create_contacts_tab(self):
        from .contact_list import ContactList
        self.contact_list = l = ContactList(self)
        return self.create_list_tab(l)

    def remove_address(self, addr):
        if self.question(_("Do you want to remove {} from your wallet?").format(addr)):
            self.wallet.delete_address(addr)
            self.need_update.set()  # history, addresses, coins
            self.clear_receive_tab()

    def get_coins(self):
        if self.pay_from:
            return self.pay_from
        else:
            return self.wallet.get_spendable_coins(None, self.config)

    def spend_coins(self, coins):
        self.set_pay_from(coins)
        self.show_send_tab()
        self.update_fee()

    def paytomany(self):
        self.show_send_tab()
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
        self.show_send_tab()
        if len(paytos) == 1:
            self.payto_e.setText(paytos[0])
            self.amount_e.setFocus()
        else:
            text = "\n".join([payto + ", 0" for payto in paytos])
            self.payto_e.setText(text)
            self.payto_e.setFocus()

    def set_contact(self, label, address):
        if not is_address(address):
            self.show_error(_('Invalid Address'))
            self.contact_list.update()  # Displays original unchanged value
            return False
        self.contacts[address] = ('address', label)
        self.contact_list.update()
        self.history_list.update()
        self.update_completions()
        return True

    def delete_contacts(self, labels):
        if not self.question(_("Remove {} from your list of contacts?")
                             .format(" + ".join(labels))):
            return
        for label in labels:
            self.contacts.pop(label)
        self.history_list.update()
        self.contact_list.update()
        self.update_completions()

    def show_invoice(self, key):
        pr = self.invoices.get(key)
        if pr is None:
            self.show_error('Cannot find payment request in wallet.')
            return
        pr.verify(self.contacts)
        self.show_pr_details(pr)

    def show_pr_details(self, pr):
        key = pr.get_id()
        d = WindowModalDialog(self, _("Invoice"))
        vbox = QVBoxLayout(d)
        grid = QGridLayout()
        grid.addWidget(QLabel(_("Requestor") + ':'), 0, 0)
        grid.addWidget(QLabel(pr.get_requestor()), 0, 1)
        grid.addWidget(QLabel(_("Amount") + ':'), 1, 0)
        outputs_str = '\n'.join(map(lambda x: self.format_amount(x[2])+ self.base_unit() + ' @ ' + x[1], pr.get_outputs()))
        grid.addWidget(QLabel(outputs_str), 1, 1)
        expires = pr.get_expiration_date()
        grid.addWidget(QLabel(_("Memo") + ':'), 2, 0)
        grid.addWidget(QLabel(pr.get_memo()), 2, 1)
        grid.addWidget(QLabel(_("Signature") + ':'), 3, 0)
        grid.addWidget(QLabel(pr.get_verify_status()), 3, 1)
        if expires:
            grid.addWidget(QLabel(_("Expires") + ':'), 4, 0)
            grid.addWidget(QLabel(format_time(expires)), 4, 1)
        vbox.addLayout(grid)
        def do_export():
            name = str(key) + '.bip70'
            fn = self.getSaveFileName(_("Save invoice to file"), name, filter="*.bip70")
            if not fn:
                return
            with open(fn, 'wb') as f:
                data = f.write(pr.raw)
            self.show_message(_('Invoice saved as' + ' ' + fn))
        exportButton = EnterButton(_('Save'), do_export)
        def do_delete():
            if self.question(_('Delete invoice?')):
                self.invoices.remove(key)
                self.history_list.update()
                self.invoice_list.update()
                d.close()
        deleteButton = EnterButton(_('Delete'), do_delete)
        vbox.addLayout(Buttons(exportButton, deleteButton, CloseButton(d)))
        d.exec_()

    def do_pay_invoice(self, key):
        pr = self.invoices.get(key)
        self.payment_request = pr
        self.prepare_for_payment_request()
        pr.error = None  # this forces verify() to re-run
        if pr.verify(self.contacts):
            self.payment_request_ok()
        else:
            self.payment_request_error()

    def create_console_tab(self):
        from .console import Console
        self.console = console = Console()
        return console

    def update_console(self):
        console = self.console
        console.history = self.config.get("console-history",[])
        console.history_index = len(console.history)

        console.updateNamespace({
            'wallet': self.wallet,
            'network': self.network,
            'plugins': self.gui_object.plugins,
            'window': self,
            'config': self.config,
            'electrum': electrum,
            'daemon': self.gui_object.daemon,
            'util': util,
            'bitcoin': bitcoin,
        })

        c = commands.Commands(self.config, self.wallet, self.network, lambda: self.console.set_json(True))
        methods = {}
        def mkfunc(f, method):
            return lambda *args: f(method, args, self.password_dialog)
        for m in dir(c):
            if m[0]=='_' or m in ['network','wallet','config']: continue
            methods[m] = mkfunc(c._run, m)

        console.updateNamespace(methods)

    def create_status_bar(self):

        sb = QStatusBar()
        sb.setFixedHeight(35)

        self.balance_label = QLabel("Loading wallet...")
        self.balance_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.balance_label.setStyleSheet("""QLabel { padding: 0 }""")
        sb.addWidget(self.balance_label)

        self.search_box = QLineEdit()
        self.search_box.textChanged.connect(self.do_search)
        self.search_box.hide()
        sb.addPermanentWidget(self.search_box)

        self.update_check_button = QPushButton("")
        self.update_check_button.setFlat(True)
        self.update_check_button.setCursor(QCursor(Qt.PointingHandCursor))
        self.update_check_button.setIcon(read_QIcon("update.png"))
        self.update_check_button.hide()
        sb.addPermanentWidget(self.update_check_button)

        self.password_button = StatusBarButton(QIcon(), _("Password"), self.change_password_dialog )
        sb.addPermanentWidget(self.password_button)

        sb.addPermanentWidget(StatusBarButton(read_QIcon("preferences.png"), _("Preferences"), self.settings_dialog ) )
        self.seed_button = StatusBarButton(read_QIcon("seed.png"), _("Seed"), self.show_seed_dialog )
        sb.addPermanentWidget(self.seed_button)
        self.status_button = StatusBarButton(read_QIcon("status_disconnected.png"), _("Network"), lambda: self.gui_object.show_network_dialog(self))
        sb.addPermanentWidget(self.status_button)
        run_hook('create_status_bar', sb)
        self.setStatusBar(sb)

    def update_lock_icon(self):
        icon = read_QIcon("lock.png") if self.wallet.has_password() else read_QIcon("unlock.png")
        self.password_button.setIcon(icon)

    def update_buttons_on_seed(self):
        self.seed_button.setVisible(self.wallet.has_seed())
        self.password_button.setVisible(self.wallet.may_have_password())
        self.send_button.setVisible(not self.wallet.is_watching_only())

    def change_password_dialog(self):
        from electrum.storage import STO_EV_XPUB_PW
        if self.wallet.get_available_storage_encryption_version() == STO_EV_XPUB_PW:
            from .password_dialog import ChangePasswordDialogForHW
            d = ChangePasswordDialogForHW(self, self.wallet)
            ok, encrypt_file = d.run()
            if not ok:
                return

            try:
                hw_dev_pw = self.wallet.keystore.get_password_for_storage_encryption()
            except UserCancelled:
                return
            except BaseException as e:
                self.logger.exception('')
                self.show_error(str(e))
                return
            old_password = hw_dev_pw if self.wallet.has_password() else None
            new_password = hw_dev_pw if encrypt_file else None
        else:
            from .password_dialog import ChangePasswordDialogForSW
            d = ChangePasswordDialogForSW(self, self.wallet)
            ok, old_password, new_password, encrypt_file = d.run()

        if not ok:
            return
        try:
            self.wallet.update_password(old_password, new_password, encrypt_file)
        except InvalidPassword as e:
            self.show_error(str(e))
            return
        except BaseException:
            self.logger.exception('Failed to update password')
            self.show_error(_('Failed to update password'))
            return
        msg = _('Password was updated successfully') if self.wallet.has_password() else _('Password is disabled, this wallet is not protected')
        self.show_message(msg, title=_("Success"))
        self.update_lock_icon()

    def toggle_search(self):
        tab = self.tabs.currentWidget()
        #if hasattr(tab, 'searchable_list'):
        #    tab.searchable_list.toggle_toolbar()
        #return
        self.search_box.setHidden(not self.search_box.isHidden())
        if not self.search_box.isHidden():
            self.search_box.setFocus(1)
        else:
            self.do_search('')

    def do_search(self, t):
        tab = self.tabs.currentWidget()
        if hasattr(tab, 'searchable_list'):
            tab.searchable_list.filter(t)

    def new_contact_dialog(self):
        d = WindowModalDialog(self, _("New Contact"))
        vbox = QVBoxLayout(d)
        vbox.addWidget(QLabel(_('New Contact') + ':'))
        grid = QGridLayout()
        line1 = QLineEdit()
        line1.setFixedWidth(32 * char_width_in_lineedit())
        line2 = QLineEdit()
        line2.setFixedWidth(32 * char_width_in_lineedit())
        grid.addWidget(QLabel(_("Address")), 1, 0)
        grid.addWidget(line1, 1, 1)
        grid.addWidget(QLabel(_("Name")), 2, 0)
        grid.addWidget(line2, 2, 1)
        vbox.addLayout(grid)
        vbox.addLayout(Buttons(CancelButton(d), OkButton(d)))
        if d.exec_():
            self.set_contact(line2.text(), line1.text())

    def show_master_public_keys(self):
        dialog = WindowModalDialog(self, _("Wallet Information"))
        dialog.setMinimumSize(500, 100)
        mpk_list = self.wallet.get_master_public_keys()
        vbox = QVBoxLayout()
        wallet_type = self.wallet.storage.get('wallet_type', '')
        if self.wallet.is_watching_only():
            wallet_type += ' [{}]'.format(_('watching-only'))
        seed_available = _('True') if self.wallet.has_seed() else _('False')
        keystore_types = [k.get_type_text() for k in self.wallet.get_keystores()]
        grid = QGridLayout()
        basename = os.path.basename(self.wallet.storage.path)
        grid.addWidget(QLabel(_("Wallet name")+ ':'), 0, 0)
        grid.addWidget(QLabel(basename), 0, 1)
        grid.addWidget(QLabel(_("Wallet type")+ ':'), 1, 0)
        grid.addWidget(QLabel(wallet_type), 1, 1)
        grid.addWidget(QLabel(_("Script type")+ ':'), 2, 0)
        grid.addWidget(QLabel(self.wallet.txin_type), 2, 1)
        grid.addWidget(QLabel(_("Seed available") + ':'), 3, 0)
        grid.addWidget(QLabel(str(seed_available)), 3, 1)
        if len(keystore_types) <= 1:
            grid.addWidget(QLabel(_("Keystore type") + ':'), 4, 0)
            ks_type = str(keystore_types[0]) if keystore_types else _('No keystore')
            grid.addWidget(QLabel(ks_type), 4, 1)
        vbox.addLayout(grid)
        if self.wallet.is_deterministic():
            mpk_text = ShowQRTextEdit()
            mpk_text.setMaximumHeight(150)
            mpk_text.addCopyButton(self.app)
            def show_mpk(index):
                mpk_text.setText(mpk_list[index])
                mpk_text.repaint()  # macOS hack for #4777
            # only show the combobox in case multiple accounts are available
            if len(mpk_list) > 1:
                def label(key):
                    if isinstance(self.wallet, Multisig_Wallet):
                        return _("cosigner") + f' {key+1} ( keystore: {keystore_types[key]} )'
                    return ''
                labels = [label(i) for i in range(len(mpk_list))]
                on_click = lambda clayout: show_mpk(clayout.selected_index())
                labels_clayout = ChoicesLayout(_("Master Public Keys"), labels, on_click)
                vbox.addLayout(labels_clayout.layout())
            else:
                vbox.addWidget(QLabel(_("Master Public Key")))
            show_mpk(0)
            vbox.addWidget(mpk_text)
        vbox.addStretch(1)
        vbox.addLayout(Buttons(CloseButton(dialog)))
        dialog.setLayout(vbox)
        dialog.exec_()

    def remove_wallet(self):
        if self.question('\n'.join([
                _('Delete wallet file?'),
                "%s"%self.wallet.storage.path,
                _('If your wallet contains funds, make sure you have saved its seed.')])):
            self._delete_wallet()

    @protected
    def _delete_wallet(self, password):
        wallet_path = self.wallet.storage.path
        basename = os.path.basename(wallet_path)
        r = self.gui_object.daemon.delete_wallet(wallet_path)
        self.close()
        if r:
            self.show_error(_("Wallet removed: {}").format(basename))
        else:
            self.show_error(_("Wallet file not found: {}").format(basename))

    @protected
    def show_seed_dialog(self, password):
        if not self.wallet.has_seed():
            self.show_message(_('This wallet has no seed'))
            return
        keystore = self.wallet.get_keystore()
        try:
            seed = keystore.get_seed(password)
            passphrase = keystore.get_passphrase(password)
        except BaseException as e:
            self.show_error(str(e))
            return
        from .seed_dialog import SeedDialog
        d = SeedDialog(self, seed, passphrase)
        d.exec_()

    def show_qrcode(self, data, title = _("QR code"), parent=None):
        if not data:
            return
        d = QRDialog(data, parent or self, title)
        d.exec_()

    @protected
    def show_private_key(self, address, password):
        if not address:
            return
        try:
            pk, redeem_script = self.wallet.export_private_key(address, password)
        except Exception as e:
            self.logger.exception('')
            self.show_message(str(e))
            return
        xtype = bitcoin.deserialize_privkey(pk)[0]
        d = WindowModalDialog(self, _("Private key"))
        d.setMinimumSize(600, 150)
        vbox = QVBoxLayout()
        vbox.addWidget(QLabel(_("Address") + ': ' + address))
        vbox.addWidget(QLabel(_("Script type") + ': ' + xtype))
        vbox.addWidget(QLabel(_("Private key") + ':'))
        keys_e = ShowQRTextEdit(text=pk)
        keys_e.addCopyButton(self.app)
        vbox.addWidget(keys_e)
        if redeem_script:
            vbox.addWidget(QLabel(_("Redeem Script") + ':'))
            rds_e = ShowQRTextEdit(text=redeem_script)
            rds_e.addCopyButton(self.app)
            vbox.addWidget(rds_e)
        vbox.addLayout(Buttons(CloseButton(d)))
        d.setLayout(vbox)
        d.exec_()

    msg_sign = _("Signing with an address actually means signing with the corresponding "
                "private key, and verifying with the corresponding public key. The "
                "address you have entered does not have a unique public key, so these "
                "operations cannot be performed.") + '\n\n' + \
               _('The operation is undefined. Not just in Electrum, but in general.')

    @protected
    def do_sign(self, address, message, signature, password):
        address  = address.text().strip()
        message = message.toPlainText().strip()
        if not bitcoin.is_address(address):
            self.show_message(_('Invalid Bitcoin address.'))
            return
        if self.wallet.is_watching_only():
            self.show_message(_('This is a watching-only wallet.'))
            return
        if not self.wallet.is_mine(address):
            self.show_message(_('Address not in wallet.'))
            return
        txin_type = self.wallet.get_txin_type(address)
        if txin_type not in ['p2pkh', 'p2wpkh', 'p2wpkh-p2sh']:
            self.show_message(_('Cannot sign messages with this type of address:') + \
                              ' ' + txin_type + '\n\n' + self.msg_sign)
            return
        task = partial(self.wallet.sign_message, address, message, password)

        def show_signed_message(sig):
            try:
                signature.setText(base64.b64encode(sig).decode('ascii'))
            except RuntimeError:
                # (signature) wrapped C/C++ object has been deleted
                pass

        self.wallet.thread.add(task, on_success=show_signed_message)

    def do_verify(self, address, message, signature):
        address  = address.text().strip()
        message = message.toPlainText().strip().encode('utf-8')
        if not bitcoin.is_address(address):
            self.show_message(_('Invalid Bitcoin address.'))
            return
        try:
            # This can throw on invalid base64
            sig = base64.b64decode(str(signature.toPlainText()))
            verified = ecc.verify_message_with_address(address, sig, message)
        except Exception as e:
            verified = False
        if verified:
            self.show_message(_("Signature verified"))
        else:
            self.show_error(_("Wrong signature"))

    def sign_verify_message(self, address=''):
        d = WindowModalDialog(self, _('Sign/verify Message'))
        d.setMinimumSize(610, 290)

        layout = QGridLayout(d)

        message_e = QTextEdit()
        message_e.setAcceptRichText(False)
        layout.addWidget(QLabel(_('Message')), 1, 0)
        layout.addWidget(message_e, 1, 1)
        layout.setRowStretch(2,3)

        address_e = QLineEdit()
        address_e.setText(address)
        layout.addWidget(QLabel(_('Address')), 2, 0)
        layout.addWidget(address_e, 2, 1)

        signature_e = QTextEdit()
        signature_e.setAcceptRichText(False)
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
        if self.wallet.is_watching_only():
            self.show_message(_('This is a watching-only wallet.'))
            return
        cyphertext = encrypted_e.toPlainText()
        task = partial(self.wallet.decrypt_message, pubkey_e.text(), cyphertext, password)

        def setText(text):
            try:
                message_e.setText(text.decode('utf-8'))
            except RuntimeError:
                # (message_e) wrapped C/C++ object has been deleted
                pass

        self.wallet.thread.add(task, on_success=setText)

    def do_encrypt(self, message_e, pubkey_e, encrypted_e):
        message = message_e.toPlainText()
        message = message.encode('utf-8')
        try:
            public_key = ecc.ECPubkey(bfh(pubkey_e.text()))
        except BaseException as e:
            self.logger.exception('Invalid Public key')
            self.show_warning(_('Invalid Public key'))
            return
        encrypted = public_key.encrypt_message(message)
        encrypted_e.setText(encrypted.decode('ascii'))

    def encrypt_message(self, address=''):
        d = WindowModalDialog(self, _('Encrypt/decrypt Message'))
        d.setMinimumSize(610, 490)

        layout = QGridLayout(d)

        message_e = QTextEdit()
        message_e.setAcceptRichText(False)
        layout.addWidget(QLabel(_('Message')), 1, 0)
        layout.addWidget(message_e, 1, 1)
        layout.setRowStretch(2,3)

        pubkey_e = QLineEdit()
        if address:
            pubkey = self.wallet.get_public_key(address)
            pubkey_e.setText(pubkey)
        layout.addWidget(QLabel(_('Public key')), 2, 0)
        layout.addWidget(pubkey_e, 2, 1)

        encrypted_e = QTextEdit()
        encrypted_e.setAcceptRichText(False)
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
        from .password_dialog import PasswordDialog
        parent = parent or self
        d = PasswordDialog(parent, msg)
        return d.run()

    def tx_from_text(self, txt):
        from electrum.transaction import tx_from_str
        try:
            tx = tx_from_str(txt)
            return Transaction(tx)
        except BaseException as e:
            self.show_critical(_("Electrum was unable to parse your transaction") + ":\n" + str(e))
            return

    def read_tx_from_qrcode(self):
        from electrum import qrscanner
        try:
            data = qrscanner.scan_barcode(self.config.get_video_device())
        except BaseException as e:
            self.show_error(str(e))
            return
        if not data:
            return
        # if the user scanned a bitcoin URI
        if str(data).startswith("bitcoin:"):
            self.pay_to_URI(data)
            return
        # else if the user scanned an offline signed tx
        try:
            data = bh2u(bitcoin.base_decode(data, length=None, base=43))
        except BaseException as e:
            self.show_error((_('Could not decode QR code')+':\n{}').format(repr(e)))
            return
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
            return
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
                raw_tx = self.network.run_from_another_thread(
                    self.network.get_transaction(txid, timeout=10))
            except Exception as e:
                self.show_message(_("Error getting transaction from network") + ":\n" + str(e))
                return
            tx = transaction.Transaction(raw_tx)
            self.show_transaction(tx)

    @protected
    def export_privkeys_dialog(self, password):
        if self.wallet.is_watching_only():
            self.show_message(_("This is a watching-only wallet"))
            return

        if isinstance(self.wallet, Multisig_Wallet):
            self.show_message(_('WARNING: This is a multi-signature wallet.') + '\n' +
                              _('It cannot be "backed up" by simply exporting these private keys.'))

        d = WindowModalDialog(self, _('Private keys'))
        d.setMinimumSize(980, 300)
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
        addresses = self.wallet.get_addresses()
        done = False
        cancelled = False
        def privkeys_thread():
            for addr in addresses:
                time.sleep(0.1)
                if done or cancelled:
                    break
                privkey = self.wallet.export_private_key(addr, password)[0]
                private_keys[addr] = privkey
                self.computing_privkeys_signal.emit()
            if not cancelled:
                self.computing_privkeys_signal.disconnect()
                self.show_privkeys_signal.emit()

        def show_privkeys():
            s = "\n".join( map( lambda x: x[0] + "\t"+ x[1], private_keys.items()))
            e.setText(s)
            b.setEnabled(True)
            self.show_privkeys_signal.disconnect()
            nonlocal done
            done = True

        def on_dialog_closed(*args):
            nonlocal done
            nonlocal cancelled
            if not done:
                cancelled = True
                self.computing_privkeys_signal.disconnect()
                self.show_privkeys_signal.disconnect()

        self.computing_privkeys_signal.connect(lambda: e.setText("Please wait... %d/%d"%(len(private_keys),len(addresses))))
        self.show_privkeys_signal.connect(show_privkeys)
        d.finished.connect(on_dialog_closed)
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
                f.write(json.dumps(pklist, indent = 4))

    def do_import_labels(self):
        def import_labels(path):
            def _validate(data):
                return data  # TODO

            def import_labels_assign(data):
                for key, value in data.items():
                    self.wallet.set_label(key, value)
            import_meta(path, _validate, import_labels_assign)

        def on_import():
            self.need_update.set()
        import_meta_gui(self, _('labels'), import_labels, on_import)

    def do_export_labels(self):
        def export_labels(filename):
            export_meta(self.wallet.labels, filename)
        export_meta_gui(self, _('labels'), export_labels)

    def sweep_key_dialog(self):
        d = WindowModalDialog(self, title=_('Sweep private keys'))
        d.setMinimumSize(600, 300)

        vbox = QVBoxLayout(d)

        hbox_top = QHBoxLayout()
        hbox_top.addWidget(QLabel(_("Enter private keys:")))
        hbox_top.addWidget(InfoButton(WIF_HELP_TEXT), alignment=Qt.AlignRight)
        vbox.addLayout(hbox_top)

        keys_e = ScanQRTextEdit(allow_multi=True)
        keys_e.setTabChangesFocus(True)
        vbox.addWidget(keys_e)

        addresses = self.wallet.get_unused_addresses()
        if not addresses:
            try:
                addresses = self.wallet.get_receiving_addresses()
            except AttributeError:
                addresses = self.wallet.get_addresses()
        h, address_e = address_field(addresses)
        vbox.addLayout(h)

        vbox.addStretch(1)
        button = OkButton(d, _('Sweep'))
        vbox.addLayout(Buttons(CancelButton(d), button))
        button.setEnabled(False)

        def get_address():
            addr = str(address_e.text()).strip()
            if bitcoin.is_address(addr):
                return addr

        def get_pk(*, raise_on_error=False):
            text = str(keys_e.toPlainText())
            return keystore.get_private_keys(text, raise_on_error=raise_on_error)

        def on_edit():
            valid_privkeys = False
            try:
                valid_privkeys = get_pk(raise_on_error=True) is not None
            except Exception as e:
                button.setToolTip(f'{_("Error")}: {str(e)}')
            else:
                button.setToolTip('')
            button.setEnabled(get_address() is not None and valid_privkeys)
        on_address = lambda text: address_e.setStyleSheet((ColorScheme.DEFAULT if get_address() else ColorScheme.RED).as_stylesheet())
        keys_e.textChanged.connect(on_edit)
        address_e.textChanged.connect(on_edit)
        address_e.textChanged.connect(on_address)
        on_address(str(address_e.text()))
        if not d.exec_():
            return
        # user pressed "sweep"
        addr = get_address()
        try:
            self.wallet.check_address(addr)
        except InternalAddressCorruption as e:
            self.show_error(str(e))
            raise
        try:
            coins, keypairs = sweep_preparations(get_pk(), self.network)
        except Exception as e:  # FIXME too broad...
            self.show_message(str(e))
            return
        self.do_clear()
        self.tx_external_keypairs = keypairs
        self.spend_coins(coins)
        self.payto_e.setText(addr)
        self.spend_max()
        self.payto_e.setFrozen(True)
        self.amount_e.setFrozen(True)
        self.warn_if_watching_only()

    def _do_import(self, title, header_layout, func):
        text = text_dialog(self, title, header_layout, _('Import'), allow_multi=True)
        if not text:
            return
        keys = str(text).split()
        good_inputs, bad_inputs = func(keys)
        if good_inputs:
            msg = '\n'.join(good_inputs[:10])
            if len(good_inputs) > 10: msg += '\n...'
            self.show_message(_("The following addresses were added")
                              + f' ({len(good_inputs)}):\n' + msg)
        if bad_inputs:
            msg = "\n".join(f"{key[:10]}... ({msg})" for key, msg in bad_inputs[:10])
            if len(bad_inputs) > 10: msg += '\n...'
            self.show_error(_("The following inputs could not be imported")
                            + f' ({len(bad_inputs)}):\n' + msg)
        self.address_list.update()
        self.history_list.update()

    def import_addresses(self):
        if not self.wallet.can_import_address():
            return
        title, msg = _('Import addresses'), _("Enter addresses")+':'
        self._do_import(title, msg, self.wallet.import_addresses)

    @protected
    def do_import_privkey(self, password):
        if not self.wallet.can_import_privkey():
            return
        title = _('Import private keys')
        header_layout = QHBoxLayout()
        header_layout.addWidget(QLabel(_("Enter private keys")+':'))
        header_layout.addWidget(InfoButton(WIF_HELP_TEXT), alignment=Qt.AlignRight)
        self._do_import(title, header_layout, lambda x: self.wallet.import_private_keys(x, password))

    def update_fiat(self):
        b = self.fx and self.fx.is_enabled()
        self.fiat_send_e.setVisible(b)
        self.fiat_receive_e.setVisible(b)
        self.history_list.update()
        self.address_list.refresh_headers()
        self.address_list.update()
        self.update_status()

    def settings_dialog(self):
        self.need_restart = False
        d = WindowModalDialog(self, _('Preferences'))
        vbox = QVBoxLayout()
        tabs = QTabWidget()
        gui_widgets = []
        fee_widgets = []
        tx_widgets = []
        id_widgets = []

        # language
        lang_help = _('Select which language is used in the GUI (after restart).')
        lang_label = HelpLabel(_('Language') + ':', lang_help)
        lang_combo = QComboBox()
        from electrum.i18n import languages
        lang_combo.addItems(list(languages.values()))
        lang_keys = list(languages.keys())
        lang_cur_setting = self.config.get("language", '')
        try:
            index = lang_keys.index(lang_cur_setting)
        except ValueError:  # not in list
            index = 0
        lang_combo.setCurrentIndex(index)
        if not self.config.is_modifiable('language'):
            for w in [lang_combo, lang_label]: w.setEnabled(False)
        def on_lang(x):
            lang_request = list(languages.keys())[lang_combo.currentIndex()]
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
            _('Time based: fee rate is based on average confirmation time estimates'),
            _('Mempool based: fee rate is targeting a depth in the memory pool')
            ]
        )
        fee_type_label = HelpLabel(_('Fee estimation') + ':', msg)
        fee_type_combo = QComboBox()
        fee_type_combo.addItems([_('Static'), _('ETA'), _('Mempool')])
        fee_type_combo.setCurrentIndex((2 if self.config.use_mempool_fees() else 1) if self.config.is_dynfee() else 0)
        def on_fee_type(x):
            self.config.set_key('mempool_fees', x==2)
            self.config.set_key('dynamic_fees', x>0)
            self.fee_slider.update()
        fee_type_combo.currentIndexChanged.connect(on_fee_type)
        fee_widgets.append((fee_type_label, fee_type_combo))

        feebox_cb = QCheckBox(_('Edit fees manually'))
        feebox_cb.setChecked(self.config.get('show_fee', False))
        feebox_cb.setToolTip(_("Show fee edit box in send tab."))
        def on_feebox(x):
            self.config.set_key('show_fee', x == Qt.Checked)
            self.fee_adv_controls.setVisible(bool(x))
        feebox_cb.stateChanged.connect(on_feebox)
        fee_widgets.append((feebox_cb, None))

        use_rbf = self.config.get('use_rbf', True)
        use_rbf_cb = QCheckBox(_('Use Replace-By-Fee'))
        use_rbf_cb.setChecked(use_rbf)
        use_rbf_cb.setToolTip(
            _('If you check this box, your transactions will be marked as non-final,') + '\n' + \
            _('and you will have the possibility, while they are unconfirmed, to replace them with transactions that pay higher fees.') + '\n' + \
            _('Note that some merchants do not accept non-final transactions until they are confirmed.'))
        def on_use_rbf(x):
            self.config.set_key('use_rbf', bool(x))
            batch_rbf_cb.setEnabled(bool(x))
        use_rbf_cb.stateChanged.connect(on_use_rbf)
        fee_widgets.append((use_rbf_cb, None))

        batch_rbf_cb = QCheckBox(_('Batch RBF transactions'))
        batch_rbf_cb.setChecked(self.config.get('batch_rbf', False))
        batch_rbf_cb.setEnabled(use_rbf)
        batch_rbf_cb.setToolTip(
            _('If you check this box, your unconfirmed transactions will be consolidated into a single transaction.') + '\n' + \
            _('This will save fees.'))
        def on_batch_rbf(x):
            self.config.set_key('batch_rbf', bool(x))
        batch_rbf_cb.stateChanged.connect(on_batch_rbf)
        fee_widgets.append((batch_rbf_cb, None))

        msg = _('OpenAlias record, used to receive coins and to sign payment requests.') + '\n\n'\
              + _('The following alias providers are available:') + '\n'\
              + '\n'.join(['https://cryptoname.co/', 'http://xmr.link']) + '\n\n'\
              + 'For more information, see https://openalias.org'
        alias_label = HelpLabel(_('OpenAlias') + ':', msg)
        alias = self.config.get('alias','')
        alias_e = QLineEdit(alias)
        def set_alias_color():
            if not self.config.get('alias'):
                alias_e.setStyleSheet("")
                return
            if self.alias_info:
                alias_addr, alias_name, validated = self.alias_info
                alias_e.setStyleSheet((ColorScheme.GREEN if validated else ColorScheme.RED).as_stylesheet(True))
            else:
                alias_e.setStyleSheet(ColorScheme.RED.as_stylesheet(True))
        def on_alias_edit():
            alias_e.setStyleSheet("")
            alias = str(alias_e.text())
            self.config.set_key('alias', alias, True)
            if alias:
                self.fetch_alias()
        set_alias_color()
        self.alias_received_signal.connect(set_alias_color)
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
        SSL_id_e.setStyleSheet((ColorScheme.RED if SSL_error else ColorScheme.GREEN).as_stylesheet(True) if SSL_identity else '')
        if SSL_error:
            SSL_id_e.setToolTip(SSL_error)
        SSL_id_e.setReadOnly(True)
        id_widgets.append((SSL_id_label, SSL_id_e))

        units = base_units_list
        msg = (_('Base unit of your wallet.')
               + '\n1 BTC = 1000 mBTC. 1 mBTC = 1000 bits. 1 bit = 100 sat.\n'
               + _('This setting affects the Send tab, and all balance related fields.'))
        unit_label = HelpLabel(_('Base unit') + ':', msg)
        unit_combo = QComboBox()
        unit_combo.addItems(units)
        unit_combo.setCurrentIndex(units.index(self.base_unit()))
        def on_unit(x, nz):
            unit_result = units[unit_combo.currentIndex()]
            if self.base_unit() == unit_result:
                return
            edits = self.amount_e, self.fee_e, self.receive_amount_e
            amounts = [edit.get_amount() for edit in edits]
            self.decimal_point = base_unit_name_to_decimal_point(unit_result)
            self.config.set_key('decimal_point', self.decimal_point, True)
            nz.setMaximum(self.decimal_point)
            self.history_list.update()
            self.request_list.update()
            self.address_list.update()
            for edit, amount in zip(edits, amounts):
                edit.setAmount(amount)
            self.update_status()
        unit_combo.currentIndexChanged.connect(lambda x: on_unit(x, nz))
        gui_widgets.append((unit_label, unit_combo))

        block_explorers = sorted(util.block_explorer_info().keys())
        msg = _('Choose which online block explorer to use for functions that open a web browser')
        block_ex_label = HelpLabel(_('Online Block Explorer') + ':', msg)
        block_ex_combo = QComboBox()
        block_ex_combo.addItems(block_explorers)
        block_ex_combo.setCurrentIndex(block_ex_combo.findText(util.block_explorer(self.config)))
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
        msg = _("Install the zbar package to enable this.")
        qr_label = HelpLabel(_('Video Device') + ':', msg)
        qr_combo.setEnabled(qrscanner.libzbar is not None)
        on_video_device = lambda x: self.config.set_key("video_device", qr_combo.itemData(x), True)
        qr_combo.currentIndexChanged.connect(on_video_device)
        gui_widgets.append((qr_label, qr_combo))

        colortheme_combo = QComboBox()
        colortheme_combo.addItem(_('Light'), 'default')
        colortheme_combo.addItem(_('Dark'), 'dark')
        index = colortheme_combo.findData(self.config.get('qt_gui_color_theme', 'default'))
        colortheme_combo.setCurrentIndex(index)
        colortheme_label = QLabel(_('Color theme') + ':')
        def on_colortheme(x):
            self.config.set_key('qt_gui_color_theme', colortheme_combo.itemData(x), True)
            self.need_restart = True
        colortheme_combo.currentIndexChanged.connect(on_colortheme)
        gui_widgets.append((colortheme_label, colortheme_combo))

        updatecheck_cb = QCheckBox(_("Automatically check for software updates"))
        updatecheck_cb.setChecked(self.config.get('check_updates', False))
        def on_set_updatecheck(v):
            self.config.set_key('check_updates', v == Qt.Checked, save=True)
        updatecheck_cb.stateChanged.connect(on_set_updatecheck)
        gui_widgets.append((updatecheck_cb, None))

        filelogging_cb = QCheckBox(_("Write logs to file"))
        filelogging_cb.setChecked(bool(self.config.get('log_to_file', False)))
        def on_set_filelogging(v):
            self.config.set_key('log_to_file', v == Qt.Checked, save=True)
            self.need_restart = True
        filelogging_cb.stateChanged.connect(on_set_filelogging)
        filelogging_cb.setToolTip(_('Debug logs can be persisted to disk. These are useful for troubleshooting.'))
        gui_widgets.append((filelogging_cb, None))

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
        tx_widgets.append((usechange_cb, None))

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
        tx_widgets.append((multiple_cb, None))

        def fmt_docs(key, klass):
            lines = [ln.lstrip(" ") for ln in klass.__doc__.split("\n")]
            return '\n'.join([key, "", " ".join(lines)])

        choosers = sorted(coinchooser.COIN_CHOOSERS.keys())
        if len(choosers) > 1:
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

        def on_unconf(x):
            self.config.set_key('confirmed_only', bool(x))
        conf_only = self.config.get('confirmed_only', False)
        unconf_cb = QCheckBox(_('Spend only confirmed coins'))
        unconf_cb.setToolTip(_('Spend only confirmed inputs.'))
        unconf_cb.setChecked(conf_only)
        unconf_cb.stateChanged.connect(on_unconf)
        tx_widgets.append((unconf_cb, None))

        def on_outrounding(x):
            self.config.set_key('coin_chooser_output_rounding', bool(x))
        enable_outrounding = self.config.get('coin_chooser_output_rounding', False)
        outrounding_cb = QCheckBox(_('Enable output value rounding'))
        outrounding_cb.setToolTip(
            _('Set the value of the change output so that it has similar precision to the other outputs.') + '\n' +
            _('This might improve your privacy somewhat.') + '\n' +
            _('If enabled, at most 100 satoshis might be lost due to this, per transaction.'))
        outrounding_cb.setChecked(enable_outrounding)
        outrounding_cb.stateChanged.connect(on_outrounding)
        tx_widgets.append((outrounding_cb, None))

        # Fiat Currency
        hist_checkbox = QCheckBox()
        hist_capgains_checkbox = QCheckBox()
        fiat_address_checkbox = QCheckBox()
        ccy_combo = QComboBox()
        ex_combo = QComboBox()

        def update_currencies():
            if not self.fx: return
            currencies = sorted(self.fx.get_currencies(self.fx.get_history_config()))
            ccy_combo.clear()
            ccy_combo.addItems([_('None')] + currencies)
            if self.fx.is_enabled():
                ccy_combo.setCurrentIndex(ccy_combo.findText(self.fx.get_currency()))

        def update_history_cb():
            if not self.fx: return
            hist_checkbox.setChecked(self.fx.get_history_config())
            hist_checkbox.setEnabled(self.fx.is_enabled())

        def update_fiat_address_cb():
            if not self.fx: return
            fiat_address_checkbox.setChecked(self.fx.get_fiat_address_config())

        def update_history_capgains_cb():
            if not self.fx: return
            hist_capgains_checkbox.setChecked(self.fx.get_history_capital_gains_config())
            hist_capgains_checkbox.setEnabled(hist_checkbox.isChecked())

        def update_exchanges():
            if not self.fx: return
            b = self.fx.is_enabled()
            ex_combo.setEnabled(b)
            if b:
                h = self.fx.get_history_config()
                c = self.fx.get_currency()
                exchanges = self.fx.get_exchanges_by_ccy(c, h)
            else:
                exchanges = self.fx.get_exchanges_by_ccy('USD', False)
            ex_combo.blockSignals(True)
            ex_combo.clear()
            ex_combo.addItems(sorted(exchanges))
            ex_combo.setCurrentIndex(ex_combo.findText(self.fx.config_exchange()))
            ex_combo.blockSignals(False)

        def on_currency(hh):
            if not self.fx: return
            b = bool(ccy_combo.currentIndex())
            ccy = str(ccy_combo.currentText()) if b else None
            self.fx.set_enabled(b)
            if b and ccy != self.fx.ccy:
                self.fx.set_currency(ccy)
            update_history_cb()
            update_exchanges()
            self.update_fiat()

        def on_exchange(idx):
            exchange = str(ex_combo.currentText())
            if self.fx and self.fx.is_enabled() and exchange and exchange != self.fx.exchange.name():
                self.fx.set_exchange(exchange)

        def on_history(checked):
            if not self.fx: return
            self.fx.set_history_config(checked)
            update_exchanges()
            self.history_model.refresh('on_history')
            if self.fx.is_enabled() and checked:
                self.fx.trigger_update()
            update_history_capgains_cb()

        def on_history_capgains(checked):
            if not self.fx: return
            self.fx.set_history_capital_gains_config(checked)
            self.history_model.refresh('on_history_capgains')

        def on_fiat_address(checked):
            if not self.fx: return
            self.fx.set_fiat_address_config(checked)
            self.address_list.refresh_headers()
            self.address_list.update()

        update_currencies()
        update_history_cb()
        update_history_capgains_cb()
        update_fiat_address_cb()
        update_exchanges()
        ccy_combo.currentIndexChanged.connect(on_currency)
        hist_checkbox.stateChanged.connect(on_history)
        hist_capgains_checkbox.stateChanged.connect(on_history_capgains)
        fiat_address_checkbox.stateChanged.connect(on_fiat_address)
        ex_combo.currentIndexChanged.connect(on_exchange)

        fiat_widgets = []
        fiat_widgets.append((QLabel(_('Fiat currency')), ccy_combo))
        fiat_widgets.append((QLabel(_('Show history rates')), hist_checkbox))
        fiat_widgets.append((QLabel(_('Show capital gains in history')), hist_capgains_checkbox))
        fiat_widgets.append((QLabel(_('Show Fiat balance for addresses')), fiat_address_checkbox))
        fiat_widgets.append((QLabel(_('Source')), ex_combo))

        tabs_info = [
            (fee_widgets, _('Fees')),
            (tx_widgets, _('Transactions')),
            (gui_widgets, _('General')),
            (fiat_widgets, _('Fiat')),
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

        if self.fx:
            self.fx.trigger_update()

        self.alias_received_signal.disconnect(set_alias_color)

        run_hook('close_settings_dialog')
        if self.need_restart:
            self.show_warning(_('Please restart Electrum to activate the new GUI settings'), title=_('Success'))


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
            self.network.unregister_callback(self.on_quotes)
            self.network.unregister_callback(self.on_history)
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

        self.gui_object.timer.timeout.disconnect(self.timer_actions)
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
            full_name = descr['__name__']
            prefix, _separator, name = full_name.rpartition('.')
            p = plugins.get(name)
            if descr.get('registers_keystore'):
                continue
            try:
                cb = QCheckBox(descr['fullname'])
                plugin_is_loaded = p is not None
                cb_enabled = (not plugin_is_loaded and plugins.is_available(name, self.wallet)
                              or plugin_is_loaded and p.can_user_disable())
                cb.setEnabled(cb_enabled)
                cb.setChecked(plugin_is_loaded and p.is_enabled())
                grid.addWidget(cb, i, 0)
                enable_settings_widget(p, name, i)
                cb.clicked.connect(partial(do_toggle, cb, name, i))
                msg = descr['description']
                if descr.get('requires'):
                    msg += '\n\n' + _('Requires') + ':\n' + '\n'.join(map(lambda x: x[1], descr.get('requires')))
                grid.addWidget(HelpButton(msg), i, 2)
            except Exception:
                self.logger.exception(f"cannot display plugin {name}")
        grid.setRowStretch(len(plugins.descriptions.values()), 1)
        vbox.addLayout(Buttons(CloseButton(d)))
        d.exec_()

    def cpfp(self, parent_tx, new_tx):
        total_size = parent_tx.estimated_size() + new_tx.estimated_size()
        parent_fee = self.wallet.get_tx_fee(parent_tx)
        if parent_fee is None:
            self.show_error(_("Can't CPFP: unknown fee for parent transaction."))
            return
        d = WindowModalDialog(self, _('Child Pays for Parent'))
        vbox = QVBoxLayout(d)
        msg = (
            "A CPFP is a transaction that sends an unconfirmed output back to "
            "yourself, with a high fee. The goal is to have miners confirm "
            "the parent transaction in order to get the fee attached to the "
            "child transaction.")
        vbox.addWidget(WWLabel(_(msg)))
        msg2 = ("The proposed fee is computed using your "
            "fee/kB settings, applied to the total size of both child and "
            "parent transactions. After you broadcast a CPFP transaction, "
            "it is normal to see a new unconfirmed transaction in your history.")
        vbox.addWidget(WWLabel(_(msg2)))
        grid = QGridLayout()
        grid.addWidget(QLabel(_('Total size') + ':'), 0, 0)
        grid.addWidget(QLabel('%d bytes'% total_size), 0, 1)
        max_fee = new_tx.output_value()
        grid.addWidget(QLabel(_('Input amount') + ':'), 1, 0)
        grid.addWidget(QLabel(self.format_amount(max_fee) + ' ' + self.base_unit()), 1, 1)
        output_amount = QLabel('')
        grid.addWidget(QLabel(_('Output amount') + ':'), 2, 0)
        grid.addWidget(output_amount, 2, 1)
        fee_e = BTCAmountEdit(self.get_decimal_point)
        # FIXME with dyn fees, without estimates, there are all kinds of crashes here
        combined_fee = QLabel('')
        combined_feerate = QLabel('')
        def on_fee_edit(x):
            out_amt = max_fee - fee_e.get_amount()
            out_amt_str = (self.format_amount(out_amt) + ' ' + self.base_unit()) if out_amt else ''
            output_amount.setText(out_amt_str)
            comb_fee = parent_fee + fee_e.get_amount()
            comb_fee_str = (self.format_amount(comb_fee) + ' ' + self.base_unit()) if comb_fee else ''
            combined_fee.setText(comb_fee_str)
            comb_feerate = comb_fee / total_size * 1000
            comb_feerate_str = self.format_fee_rate(comb_feerate) if comb_feerate else ''
            combined_feerate.setText(comb_feerate_str)
        fee_e.textChanged.connect(on_fee_edit)
        def get_child_fee_from_total_feerate(fee_per_kb):
            fee = fee_per_kb * total_size / 1000 - parent_fee
            fee = min(max_fee, fee)
            fee = max(total_size, fee)  # pay at least 1 sat/byte for combined size
            return fee
        suggested_feerate = self.config.fee_per_kb()
        if suggested_feerate is None:
            self.show_error(f'''{_("Can't CPFP'")}: {_('Dynamic fee estimates not available')}''')
            return
        fee = get_child_fee_from_total_feerate(suggested_feerate)
        fee_e.setAmount(fee)
        grid.addWidget(QLabel(_('Fee for child') + ':'), 3, 0)
        grid.addWidget(fee_e, 3, 1)
        def on_rate(dyn, pos, fee_rate):
            fee = get_child_fee_from_total_feerate(fee_rate)
            fee_e.setAmount(fee)
        fee_slider = FeeSlider(self, self.config, on_rate)
        fee_slider.update()
        grid.addWidget(fee_slider, 4, 1)
        grid.addWidget(QLabel(_('Total fee') + ':'), 5, 0)
        grid.addWidget(combined_fee, 5, 1)
        grid.addWidget(QLabel(_('Total feerate') + ':'), 6, 0)
        grid.addWidget(combined_feerate, 6, 1)
        vbox.addLayout(grid)
        vbox.addLayout(Buttons(CancelButton(d), OkButton(d)))
        if not d.exec_():
            return
        fee = fee_e.get_amount()
        if fee > max_fee:
            self.show_error(_('Max fee exceeded'))
            return
        new_tx = self.wallet.cpfp(parent_tx, fee)
        new_tx.set_rbf(True)
        self.show_transaction(new_tx)

    def bump_fee_dialog(self, tx):
        fee = self.wallet.get_tx_fee(tx)
        if fee is None:
            self.show_error(_("Can't bump fee: unknown fee for original transaction."))
            return
        tx_label = self.wallet.get_label(tx.txid())
        tx_size = tx.estimated_size()
        old_fee_rate = fee / tx_size  # sat/vbyte
        d = WindowModalDialog(self, _('Bump Fee'))
        vbox = QVBoxLayout(d)
        vbox.addWidget(WWLabel(_("Increase your transaction's fee to improve its position in mempool.")))
        vbox.addWidget(QLabel(_('Current Fee') + ': %s'% self.format_amount(fee) + ' ' + self.base_unit()))
        vbox.addWidget(QLabel(_('Current Fee rate') + ': %s' % self.format_fee_rate(1000 * old_fee_rate)))
        vbox.addWidget(QLabel(_('New Fee rate') + ':'))

        def on_textedit_rate():
            fee_slider.deactivate()
        feerate_e = FeerateEdit(lambda: 0)
        feerate_e.setAmount(max(old_fee_rate * 1.5, old_fee_rate + 1))
        feerate_e.textEdited.connect(on_textedit_rate)
        vbox.addWidget(feerate_e)

        def on_slider_rate(dyn, pos, fee_rate):
            fee_slider.activate()
            if fee_rate is not None:
                feerate_e.setAmount(fee_rate / 1000)
        fee_slider = FeeSlider(self, self.config, on_slider_rate)
        fee_slider.deactivate()
        vbox.addWidget(fee_slider)
        cb = QCheckBox(_('Final'))
        vbox.addWidget(cb)
        vbox.addLayout(Buttons(CancelButton(d), OkButton(d)))
        if not d.exec_():
            return
        is_final = cb.isChecked()
        new_fee_rate = feerate_e.get_amount()
        try:
            new_tx = self.wallet.bump_fee(tx=tx, new_fee_rate=new_fee_rate, config=self.config)
        except CannotBumpFee as e:
            self.show_error(str(e))
            return
        if is_final:
            new_tx.set_rbf(False)
        self.show_transaction(new_tx, tx_label)

    def save_transaction_into_wallet(self, tx):
        win = self.top_level_window()
        try:
            if not self.wallet.add_transaction(tx.txid(), tx):
                win.show_error(_("Transaction could not be saved.") + "\n" +
                               _("It conflicts with current history."))
                return False
        except AddTransactionException as e:
            win.show_error(e)
            return False
        else:
            self.wallet.storage.write()
            # need to update at least: history_list, utxo_list, address_list
            self.need_update.set()
            msg = (_("Transaction added to wallet history.") + '\n\n' +
                   _("Note: this is an offline transaction, if you want the network "
                     "to see it, you need to broadcast it."))
            win.msg_box(QPixmap(icon_path("offline_tx.png")), None, _('Success'), msg)
            return True
