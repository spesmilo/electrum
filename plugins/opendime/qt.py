#!/usr/bin/env python
#
# Opendime Plugin for
# Electrum - lightweight Bitcoin client
# Copyright (C) 2016 Coinkite Inc.
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

import os, sys, copy, time, traceback
import sip
import threading

import webbrowser

from PyQt4.QtGui import QApplication, QPushButton

from electrum.plugins import BasePlugin, hook
from electrum.i18n import _

from electrum_gui.qt.util import EnterButton, WindowModalDialog, Buttons, MONOSPACE_FONT
from electrum_gui.qt.util import OkButton, CloseButton, MyTreeWidget, ThreadedButton
from electrum_gui.qt.util import WaitingDialog
from electrum_gui.qt.qrcodewidget import QRCodeWidget
from electrum_gui.qt.address_dialog import AddressDialog
from electrum_gui.qt.main_window import ElectrumWindow
from PyQt4.Qt import QVBoxLayout, QHBoxLayout, QWidget, QPixmap, QTreeWidgetItem, QIcon
from PyQt4.Qt import QGridLayout, QPushButton, QCheckBox, QLabel, QMenu, QFont, QSize
from PyQt4.Qt import QDesktopServices, QUrl, QHeaderView, QFrame, QFontMetrics, QSpacerItem
from PyQt4.Qt import Qt, QBrush
from PyQt4.QtCore import pyqtSignal
from functools import partial
from collections import OrderedDict

from electrum.wallet import Imported_Wallet, IMPORTED_ACCOUNT
from electrum.paymentrequest import PR_UNKNOWN

from .shared import AttachedOpendime, has_libusb, has_psutil
from . import  assets_rc

from electrum.util import block_explorer_URL, PrintError
from electrum.rsakey import getRandomBytes

BACKGROUND_TXT = _('''\
<img src=":od-plugin/od-logo.png"></img>
<h3>Opendime&trade; Helper Plugin</h3>
<p>
Makes setup, loading and spending from
Opendime disposable hardware bitcoins even easier.
</p><p>
Once this plugin is enabled:
</p>
<ul>
<li> If you connect a sealed Opendime, the balance will be shown
     and you can send funds to it directly.
<li> Funds from <b>unsealed</b> devices will be automatically sent to your wallet.
<li> Fresh devices will be setup with good quality entropy.
<li> Use the <b>Opendime</b> tab to do all this!
</ul>
<p>
Learn more about Opendime and get some for yourself
at <a href="https://opendime.com/electrum">Opendime.com</a>
</p>
<hr>
''')


class OpendimeItem(QTreeWidgetItem):
    def __init__(self, unit):
        '''
            QTreeWidgetItem() for a single OD unit.
        '''
        self.unit = unit

        #print "New OD: %r" % unit

        icon_name, status_text = self.display_status()

        addr = unit.address if not unit.is_new else '-'
        super(OpendimeItem, self).__init__([status_text, addr, '' if unit.is_new else '?'])

        self.setChildIndicatorPolicy(QTreeWidgetItem.DontShowIndicator)

        # status column
        self.setIcon(0, QIcon(icon_name))

        # address column
        self.setFont(1, QFont(MONOSPACE_FONT))

        # balance
        self.setFont(2, QFont(MONOSPACE_FONT))

        # key value used for UID
        self.serial = unit.serial

        if not unit.is_new and not unit.is_sealed:
            # Show "unsealed" state with special background, since kinda important to
            # sweep as soon as possible... and not deposit more, etc.
            pass

        if unit.problem:
            hilite = QBrush(Qt.red, Qt.FDiagPattern)
            for col in range(self.columnCount()):
                self.setBackground(col, hilite)

    def display_status(self):
        '''
            Return an icon filename and a short string status for a unit.
        '''
        unit = self.unit

        if not unit.is_sealed:
            return ":icons/unlock.png", "Unsealed"

        if not unit.verify_level:
            return ":icons/expired.png", "INVALID"

        if unit.is_new:
            return ":icons/key.png", "Fresh"

        return ":icons/seal.png", "Ready"

    def update_balance(self, confirmed, unconf, immature, formatter):
        '''
            Update our display of balance. Try not to mislead.

            Really don't like "0." for empty ... but oh well.
        '''
        unconf += immature
        txt = formatter(confirmed + unconf, whitespaces=True)

        if unconf:
            icon = QIcon(":icons/unconfirmed.png")
        elif confirmed:
            icon = QIcon(":icons/confirmed.png")
        else:
            icon = QIcon(":od-plugin/placeholder.png")

        self.setIcon(2, icon)
        self.setText(2, txt)


        unit = self.unit
        assert not unit.is_new


class InMemoryStorage(PrintError):
    '''
        Replacement for lib/wallet.Storage object which will only
        store things in memory during operation. We don't need/want to
        remember anything about Opendimes we have seen in the past.
    '''

    def __init__(self, path=None):
        self.lock = threading.RLock()
        self.data = {}

    def read(self, path):
        raise NotImplementedError
    def write(self):
        pass

    def get(self, key, default=None):
        with self.lock:
            v = self.data.get(key)
            return default if v is None else copy.deepcopy(v)

    def put(self, key, value):
        with self.lock:
            if value is not None:
                if self.data.get(key) != value:
                    self.data[key] = copy.deepcopy(value)
            elif key in self.data:
                self.data.pop(key)

class OpendimeTransientWallet(Imported_Wallet):
    '''
        Fake wallet used to monitor balances of Opendimes that are presently connected.
    '''
    def __init__(self, *a, **kws):
        self.od_tab = kws.pop('od_tab')
        super(OpendimeTransientWallet, self).__init__(*a, **kws)

    @property
    def path(self):
        # some code paths assume we have a disk location
        raise NotImplementedError

    def is_watching_only(self):
        return True

    def check_password(self, password):
        # not encrypted
        pass

    def import_address(self, address):
        # abstract wallet doesn't have this, but there is a constructor
        self.accounts[IMPORTED_ACCOUNT].add(address, None, None, None)
        self.save_accounts()

        # force resynchronization, because we need to re-run add_transaction
        if address in self.history:
            self.history.pop(address)

        assert self.synchronizer
        self.synchronizer.add(address)

    def save_transactions(self, write=False):
        # need an event to know when changes/results are known
        super(OpendimeTransientWallet, self).save_transactions(write)

        #print "updates: %s" % self.history

        self.od_tab.more_txn_data_sig.emit()

    def basename(self):
        return 'in-memory'

    def get_payment_request(self, addr, config):
        raise NotImplementedError

    def get_request_status(self, key):
        return PR_UNKNOWN


class OpendimeTab(QWidget):

    # signals for slotting
    new_unit_sig = pyqtSignal(AttachedOpendime)
    unit_updated_sig = pyqtSignal(AttachedOpendime)
    scan_done_sig = pyqtSignal(list)

    more_txn_data_sig = pyqtSignal()

    # calculated a little later.
    ADDR_TEXT_WIDTH = None

    def __init__(self, wallet, main_window):
        '''
            Each open wallet may have an Opendime tab.
        '''
        QWidget.__init__(self)

        # P2PKH addresses will always be no wider than this size on screen.
        if not self.ADDR_TEXT_WIDTH:
            met = QFontMetrics(QFont(MONOSPACE_FONT))
            OpendimeTab.ADDR_TEXT_WIDTH = met.width("M") * 35

        # capture these
        self.real_wallet = wallet
        while not isinstance(main_window, ElectrumWindow):
            main_window = main_window.parent()
            assert main_window
        self.main_window = main_window

        # for balance tracking we need a wallet which will be an
        # 'imported' watch-only type wallet, and uses fake storage
        self.od_wallet = OpendimeTransientWallet(InMemoryStorage(), od_tab=self)
        self.od_wallet.start_threads(self.main_window.network)

        self.wallet = self.od_wallet        # other code compat.

        # Make a new tab, and insert as second-last. Keeping 'console'
        # as last tab, since that's more important than us.
        tab_bar = main_window.tabs
        idx = tab_bar.count() - 1

        # these will be OpendimeItem instances, in display order, key is serial number
        self.attached = OrderedDict()

        # connect slots
        self.new_unit_sig.connect(self.on_new_unit)
        self.unit_updated_sig.connect(self.on_unit_updated)
        self.scan_done_sig.connect(self.on_scan_done)
        self.more_txn_data_sig.connect(self.on_more_txn_data)

        self.build_gui()

        tab_bar.insertTab(idx, self, _('Opendime') )

    def setup_unit(self, unit):
        # setup entropy
        SZ = 256*1024

        if not unit.is_new: return

        def doit():
            rnd = getRandomBytes(SZ)
            try:
                unit.initalize(rnd)
            except:
                # I expect errors here depending on OS and timing and such... ignore
                traceback.print_exc(file=sys.stdout)

            # wait a touch and do a re-scan. imperfect.
            time.sleep(15)
            self.rescan_button.clicked.emit(True)

        # start the write in a thread (very slow) and show delay
        WaitingDialog(self, _("Writing large quantity of random numbers to this Opendime. Please wait."), doit)

    def import_privkey(self, unit):
        # Adds private key from opendime into current wallet, but does not sweep funds!
        # Since most wallets are deterministic, this won't work for most, and is not
        # offered in the menu unless it might work.
        try:
            assert not unit.is_sealed
            assert not unit.is_new
            assert not unit.privkey
            assert self.real_wallet.can_import()

            chk_addr = self.real_wallet.import_key(unit.privkey, None)
        except:
            traceback.print_exc(file=sys.stdout)
            self.show_critical(_("Could not be import key!"))
            return

        assert chk_addr == unit.address

        self.show_message(_("Opendime was added to your wallet: ") + chk_addr)

        self.main_window.address_list.update()
        self.main_window.history_list.update()

    def sweep_value(self, unit):
        # use existing interaction
        self.main_window.sweep_key_dialog(prefilled_privkey = unit.privkey)

    def table_item_menu(self, position):
        item = self.table.itemAt(position)

        if not item:
            # item can be None if they click on a blank (unused) row.
            return

        menu = QMenu()

        # read what unit is associated w/ row
        unit = item.unit
        assert unit

        # reality check
        sn = unit.serial
        chk = self.attached[sn]
        assert chk == item

        if unit.problem:
            a = menu.addAction("- DO NOT USE -", lambda: None)
            a.setEnabled(False)
            a = menu.addAction(unit.problem, lambda: None)
            a.setEnabled(False)
            menu.addSeparator()

            # Do not allow them to do anything foolish with a bogus unit...
            # Disable entire menu! Problem: hard to clear popup but can by
            # switching windows.
            menu.setEnabled(False)


        needs_wall = set()

        if unit.is_new:
            menu.addAction(_("Initalize with random key"), lambda: self.setup_unit(unit))

        else:
            addr = unit.address

            # Show address as a kinda header on menu
            if unit.verify_level:
                a = menu.addAction(u"\u2713 Verified (level %d)" % unit.verify_level, lambda: None)
                a.setEnabled(False)

            a = menu.addAction(unit.address, lambda: None)
            a.setEnabled(False)

            menu.addSeparator()

            app = QApplication.instance()

            if not unit.is_sealed:
                # Most people should use this....
                a = menu.addAction(_("Sweep funds (one time)"), lambda: self.sweep_value(unit))
                needs_wall.add(a)

                if self.real_wallet.can_import():
                    # BIP32 wallets cannot import, so most will never see this option.
                    a = menu.addAction(_("Import private key into Electrum (advanced)"),
                                            lambda: self.import_privkey(unit))
                    needs_wall.add(a)

                menu.addAction(_("Copy private key to clipboard"),
                                lambda: app.clipboard().setText(unit.privkey))

                menu.addSeparator()
            else:
                a = menu.addAction(_("Pay to this Opendime..."),
                                        lambda: self.main_window.pay_to_URI('bitcoin:'+addr))
                needs_wall.add(a)

                # TODO: allow watch of sealed opendime
                #   if self.real_wallet.can_import():
                #       menu.addAction(_("Import address into Electrum (watch only)"),
                #                            lambda: self.import_for_watch(unit))

                menu.addSeparator()

            # Maybe todo: could open as a new wallet; either watch-only or if unsealed,
            # as a full wallet, see Wallet.from_address() and Wallet.from_private_key()
            # Probably a bad idea and too obscure otherwise.

            menu.addAction(_("Copy address to clipboard"),
                                lambda: app.clipboard().setText(unit.address))

            menu.addAction(_("Show as QR code"),
                lambda: self.main_window.show_qrcode(addr, 'Opendime', parent=self))


            # kinda words, but if they hit "next" goes to their wallet, etc.
            #menu.addAction(_("Request payment"), lambda: self.main_window.receive_at(addr))
            menu.addAction(_('History'), lambda: self.show_history(addr))

            url = block_explorer_URL(self.main_window.config, 'addr', addr)
            if url:
                menu.addAction(_("View on block explorer"), lambda: webbrowser.open(url))


            # disable items not possible w/ watchonly wallet
            if self.real_wallet.is_watching_only():
                for a in needs_wall:
                    a.setEnabled(False)

        menu.addSeparator()
        menu.addAction(_("View Opendime page (local HTML)"),
            lambda: webbrowser.open('file:'+os.path.join(unit.root_path, 'index.htm')))
        menu.addAction(_("Open Opendime folder (local)"),
            lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(unit.root_path)))

        menu.exec_(self.table.viewport().mapToGlobal(position))


    def rescan_now(self):
        '''
            Slow task: look for units, update table and our state when found.
            Runs in a non-GUI thread.
        '''
        try:
            self.status_label.text = "Scanning now..."
            self.status_label.update()

            # search for any and all units presently connected.
            paths = AttachedOpendime.find()

            new = []
            found = []

            for pn in paths:
                unit = AttachedOpendime(pn)
                found.append(unit)

                if unit.serial not in self.attached:
                    new.append(unit)
                    unit.verify_wrapped()

                    self.new_unit_sig.emit(unit)
                else:
                    ex = self.attached[unit.serial].unit

                    if unit.is_new != ex.is_new or unit.is_sealed != ex.is_sealed:
                        unit.verify_wrapped()
                        self.unit_updated_sig.emit(unit)

            msg = None
            if new:
                msg = "%d new units found." % len(new)
            elif not self.attached:
                msg = "No units found. Wait and try again."
            else:
                msg = "No change: %d units." % len(self.attached)

            self.status_label.setText(msg)

            self.scan_done_sig.emit([u.serial for u in found])


        except Exception, e:
            traceback.print_exc(file=sys.stdout)


    def build_gui(self):
        '''
            Build the GUI elements for the Opendime tab.
        '''

        grid = QGridLayout(self)
        grid.setHorizontalSpacing(10)
        grid.setVerticalSpacing(0)
        #grid.setColumnStretch(3, 1)

        prod = QLabel()
        prod.setPixmap(QPixmap(':od-plugin/prod-shot.png').scaledToWidth(300))
        grid.addWidget(prod, 0, 0)

        hp_link = QLabel('<center><a href="https://opendime.com/electrum">opendime.com</a>')
        hp_link.openExternalLinks = True
        hp_link.setTextInteractionFlags(Qt.TextBrowserInteraction)
        hp_link.linkActivated.connect(lambda link: webbrowser.open(link))
        grid.addWidget(hp_link, 1, 0)

        grid.setColumnStretch(1, 100)
        #grid.setColumnStretch(1, 10)
        #grid.setColumnStretch(2, 10)

        # addItem(QLayoutItem *item, row, column, rowSpan=1, columnSpan = 1, alignment = 0)

        # second column: button
        self.rescan_button = ThreadedButton(_('Find Opendime(s)'), self.rescan_now)
        self.rescan_button.setMinimumHeight(50)
        self.rescan_button.setMinimumWidth(200)
        grid.addWidget(self.rescan_button, 0, 1, alignment=Qt.AlignCenter)

        # Note: these column headers have already been translated elsewhere in project.
        self.table = MyTreeWidget(self, self.table_item_menu,
                            [ _('Status'), _('Address'), _('Balance')],
                            editable_columns=[])

        self.table.header().setResizeMode(QHeaderView.Stretch)

        # some forced space between header stuff and table
        grid.addItem(QSpacerItem(0, 20), 2, 0, 1, 4)

        grid.addWidget(self.table, 3, 0, 1, -1)

        # space between table and status line under it.
        grid.addItem(QSpacerItem(0, 10), 4, 0, 1, 4)
        self.status_label = QLabel("Click to start scan.")

        grid.addWidget(self.status_label, 5, 0, 1, 3, alignment=Qt.AlignLeft)

        self.rescan_button.clicked.emit(True)

    def on_more_txn_data(self):
        '''
            A payment was received, or something confirmed, and so on... some
            kind of event for our units... so redisplay all balances.
        '''
        for item in self.attached.values():
            if item.unit.is_new:
                continue

            # get current balance data
            bal = self.od_wallet.get_addr_balance(item.unit.address)

            item.update_balance(*bal, formatter=self.main_window.format_amount)


    def on_unit_updated(self, unit):
        '''
            Exisiting opendime changed; probably a sealed=>unsealed transition.

            (Plan is future units will have a defined serial number from new->ready
            transition, but for now, they do not have same serial, so this code
            only used during unseal.)
        '''
        sn = unit.serial
        assert sn in self.attached

        item = OpendimeItem(unit)
        existing = self.attached.pop(sn)

        sip.delete(existing)
        self.table.addChild(item)
        self.attached[sn] = item

        if not unit.is_new:
            self.od_wallet.import_address(unit.address)

    def on_new_unit(self, unit):
        '''
            New opendime found, and was added to Q.
        '''
        # add to gui and list
        item = OpendimeItem(unit)
        sn = unit.serial
        self.attached[sn] = item

        self.table.addChild(item)

        # start watching the payment address
        if not unit.is_new:
            self.od_wallet.import_address(unit.address)

    def on_scan_done(self, found_serials):
        '''
            Scan of drives is complete, and we found those serial number.
            Anything else in our list, is now disconnected.

            I was tempted to keep previously-attached units in the list,
            since for most operations we already know all we need to, but
            it's a privacy problem, and could lead to confusion. So our policy
            will be the Opendime has to be connected to interact with it.
            Add the address to your wallet (somehow?) if you want to watch it.
        '''
        missing = set(self.attached.keys()) - set(found_serials)

        # remove associated GUI objects
        for sn in missing:
            item = self.attached[sn]
            sip.delete(item)
            del self.attached[sn]

            # stop caring about it's balance.
            if not item.unit.is_new:
                self.od_wallet.delete_imported_key(item.unit.address)

    def show_history(self, addr):

		# PROBLEM: AddressDialog uses self.parent and assumes it's a main_window
		# window.  Mostly that's fine, except I want to use our od_wallet.
		# No clean way to fix this because AddressDialog then calls calls
		# HistoryWidget which makes the same assumptions and so on.

        # This list was created by exploring the UI... imperfect.
        flds = ['show_transaction', 'app', 'config', 'format_amount', 'show_qrcode']

        for fn in flds:
            setattr(self, fn, getattr(self.main_window, fn))

        d = AddressDialog(self, addr)
        d.exec_()

    def remove_gui(self):
        '''
            User has disabled the plugin, so remove the "Opendime" tab we added.
        '''
        tab_bar = self.main_window.tabs

        for idx in range(tab_bar.count()):
            if tab_bar.widget(idx) is not self:
                continue
            tab_bar.removeTab(idx)

class Plugin(BasePlugin):

    button_label = _("Send to Opendime")

    def __init__(self, parent, config, name):
        BasePlugin.__init__(self, parent, config, name)
        self.instances = set()

        # if we are enabled after the system has a wallet
        # open, then our "load_wallet" hook will not have
        # been called, and typically there is at least one
        # wallet already open. Find it, and add our tab.
        qa = QApplication.instance()
        if not qa:
            # During startup case (iff enabled during previous run)
            # we are called before Qt is started; which is fine. Don't
            # need to do anything, since load_wallet will happen
            pass
        else:
            # Look for open wallet windows. Ignore others.
            for win in qa.topLevelWidgets():
                wallet = getattr(win, 'wallet', None)
                if wallet:
                    self.load_wallet(wallet, win)

    @hook
    def load_wallet(self, wallet, main_window):
        '''
            After a new wallet is loaded, we are called here.

            Add an Opendime tab to the wallet window.
        '''

        instance = OpendimeTab(wallet, main_window)

        self.instances.add(instance)

    @hook
    def close_wallet(self, wallet):
        '''
            A wallet was closed, remove from our list of instances.
            Other cleanup will be based on Qt.
        '''
        delme = set()
        for t in self.instances:
            if t.wallet is wallet:
                delme.add(t)
        self.instances.difference_update(delme)

    def on_close(self):
        '''
            This plugin has been disabled. Remove the Opendime tab on all wallets.
        '''

        for t in self.instances:
            t.remove_gui()

        self.instances.clear()

    def requires_settings(self):
        '''
            Do we want a settings button (on plugins menu)? Yes.
        '''
        return True

    def settings_widget(self, window):
        '''
            Provide a widget to be shown inline on the plugin list/menu.
        '''
        return EnterButton(_('Settings'), partial(self.settings_dialog, window))

    def settings_dialog(self, window):
        '''
            Our settings dialog, which is mostly background info at this point.
        '''
        d = WindowModalDialog(window, _("Opendime Settings"))

        vbox = QVBoxLayout(d)
        blurb = QLabel(BACKGROUND_TXT)
        blurb.openExternalLinks = True
        blurb.setTextInteractionFlags(Qt.TextBrowserInteraction)
        blurb.linkActivated.connect(lambda link: webbrowser.open(link))
        vbox.addWidget(blurb)

        grid = QGridLayout()
        vbox.addLayout(grid)
        y = 0

        # MEH: not so interesting.
        if 0:
            # checkbox: always grab everything
            def on_change_grab(checked):
                self.config.set_key('od_grab', bool(checked))

            grab_checkbox = QCheckBox()
            grab_checkbox.setChecked(self.config.get("od_grab", False))
            grab_checkbox.stateChanged.connect(on_change_grab)

            grid.addWidget(QLabel(_('Always grab unsealed funds (no confirm)? ')), y, 0)
            grid.addWidget(grab_checkbox, y,1)
            y += 1

        # checkboxes ... readouts not controls, sigh.
        def on_change_check(chkbox, forced_state):
            chkbox.setChecked(forced_state)

            if forced_state:
                msg = '''This feature is enabled if suitable python modules are '''+\
                            '''installed and there is no reason to disable it.'''
            else:
                msg = '''Please try: "sudo pip install psutil pyusb" '''+\
                            '''... and then restart Electrum'''

            window.show_message(msg)

        verify_checkbox = QCheckBox()
        verify_checkbox.setChecked(has_libusb)
        verify_checkbox.stateChanged.connect(lambda x: on_change_check(verify_checkbox, has_libusb))

        grid.addWidget(QLabel(_(
            'Perform maximum device authenticity checks (for the paranoid)? ')), y, 0)
        grid.addWidget(verify_checkbox, y,1)
        y += 1

        psut_checkbox = QCheckBox()
        psut_checkbox.setChecked(has_psutil)
        psut_checkbox.stateChanged.connect(lambda x: on_change_check(psut_checkbox, has_psutil))

        grid.addWidget(QLabel(_(
            'Use faster method to find devices (psutil)? ')), y, 0)
        grid.addWidget(psut_checkbox, y,1)
        y += 1

        vbox.addStretch()
        vbox.addLayout(Buttons(CloseButton(d), OkButton(d)))

        return d.exec_()

