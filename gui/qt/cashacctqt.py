##!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Electron Cash - A Bitcoin Cash SPV Wallet
# This file Copyright (c) 2019 Calin Culianu <calin.culianu@gmail.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

'''
Cash Accounts related classes and functions - Qt UI related.
'''

# TODO: whittle these * imports down to what we actually use
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *
from .util import *

import queue
from typing import Tuple, List, Callable
from enum import IntEnum
from electroncash import cashacct
from electroncash import util
from electroncash.address import Address, UnknownAddress
from electroncash.i18n import _, ngettext
from electroncash.wallet import Abstract_Wallet


class VerifyingDialog(WaitingDialog):

    def __init__(self, parent, message, task, on_success=None, on_error=None, auto_cleanup=True,
                 *, auto_show=True, auto_exec=False, title=None, disable_escape_key=False):
        super().__init__(parent, message, task, on_success=on_success,
                         on_error=on_error, auto_cleanup=auto_cleanup,
                         auto_show=False, auto_exec=False,
                         title=title or _('Verifying Cash Account'),
                         disable_escape_key=disable_escape_key)
        hbox = QHBoxLayout()
        self._vbox.removeWidget(self._label)
        icon_lbl = QLabel()
        icon_lbl.setPixmap(QIcon(":icons/cashacct-logo.png").pixmap(50))
        hbox.addWidget(icon_lbl)
        hbox.addWidget(self._label)
        self._vbox.addLayout(hbox)
        prog = QProgressBar()
        prog.setRange(0,0)
        self._vbox.addWidget(prog)
        if auto_show and not auto_exec:
            self.open()
        elif auto_exec:
            self.exec_()


def verify_multiple_blocks(blocks : List[int], parent : MessageBoxMixin, wallet : Abstract_Wallet, timeout=10.0) -> int:
    ''' Pass a list of blocks and will attempt to verify them all in 1 pass.
    This is used by the Contacts tab to verify unverified Cash Accounts that
    may have been imported. Returns the number of successfully verified blocks
    or None on user cancel. '''
    if not len(blocks):
        return 0
    blocks = set(blocks)
    nblocks = len(blocks)
    q = queue.Queue()
    def done_cb(thing):
        if isinstance(thing, cashacct.ProcessedBlock) and thing.reg_txs:
            q.put(thing)
        else:
            q.put(None)
    ctr = 0
    def thread_func():
        nonlocal ctr
        for number in blocks:
            wallet.cashacct.verify_block_asynch(number, success_cb=done_cb, error_cb=done_cb, timeout=timeout)
        errs = 0
        while ctr + errs < nblocks:
            try:
                thing = q.get(timeout=timeout)
                if thing is None:
                    errs += 1
                else:
                    ctr += 1
            except queue.Empty:
                return
    code = VerifyingDialog(parent.top_level_window(),
                           ngettext("Verifying {count} block please wait ...",
                                    "Verifying {count} blocks please wait ...", nblocks).format(count=nblocks),
                                    thread_func, auto_show=False, on_error=lambda e: parent.show_error(str(e))).exec_()
    if code != QDialog.Accepted:
        return None
    return ctr


def resolve_cashacct(parent : MessageBoxMixin, name : str, wallet : Abstract_Wallet = None) -> Tuple[cashacct.Info, str]:
    ''' Throws up a WaitingDialog while it resolves a Cash Account.

    Goes out to network, verifies all tx's.

    Returns: a tuple of: (Info, Minimally_Encoded_Formatted_AccountName)

    Argument `name` should be a Cash Account name string of the form:

      name#number.123
      name#number
      name#number.;  etc

    If the result would be ambigious, that is considered an error, so enough
    of the account name#number.collision_hash needs to be specified to
    unambiguously resolve the Cash Account.

    On failure throws up an error window and returns None.'''
    from .main_window import ElectrumWindow
    if isinstance(parent, ElectrumWindow) and not wallet:
        wallet = parent.wallet
    assert isinstance(wallet, Abstract_Wallet)
    class Bad(Exception): pass
    try:
        if not wallet.network or not wallet.network.interface:
            raise Bad(_("Cannot verify Cash Account as the network appears to be offline."))
        ca_tup = wallet.cashacct.parse_string(name)
        if not ca_tup:
            raise Bad(_("Invalid Cash Account name specified: {name}").format(name=name))
        results = None
        def resolve_verify():
            nonlocal results
            results = wallet.cashacct.resolve_verify(name)
        code = VerifyingDialog(parent.top_level_window(),
                               _("Verifying Cash Account {name} please wait ...").format(name=name),
                               resolve_verify, on_error=lambda e: parent.show_error(str(e)), auto_show=False).exec_()
        if code == QDialog.Rejected:
            # user cancel operation
            return
        if not results:
            raise Bad(_("Cash Account not found: {name}").format(name=name) + "\n\n"
                      + _("Could not find the Cash Account name specified. "
                          "It either does not exist or there may have been a network connectivity error. "
                          "Please double-check it and try again."))
        if len(results) > 1:
            tup = multiple_result_picker(parent=parent, wallet=wallet, results=results)
            if not tup:
                # user cancel
                return
            results = [tup]
        info, mch = results[0]
        name = wallet.cashacct.fmt_info(info, mch)
        if not isinstance(info.address, Address):
            raise Bad(_("Unsupported payment data type.") + "\n\n"
                      + _("The Cash Account {name} uses an account type that "
                          "is not supported by Electron Cash.").format(name=name))
        return info, name
    except Bad as e:
        parent.show_error(str(e))
    return None


class ButtonAssociatedLabel(QLabel):
    ''' A QLabel, that if clicked on, sends a 'click()' call to an associated
    QAbstractButton. '''

    def __init__(self, *args, **kwargs):
        but = kwargs.pop('button', None)
        super().__init__(*args, **kwargs)
        self.but = but
        self.setTextInteractionFlags(self.textInteractionFlags() | Qt.TextSelectableByMouse)

    def setButton(self, b : QAbstractButton): self.but = b
    def button(self) -> QAbstractButton: return self.but

    def mouseReleaseEvent(self, e):
        super().mouseReleaseEvent(e)
        if self.but:
            if self.but.isEnabled():
                self.but.click()
            elif self.but.toolTip() and not self.hasSelectedText():
                QToolTip.showText(QCursor.pos(), self.but.toolTip(), self)


class InfoGroupBox(PrintError, QGroupBox):

    class ButtonType(IntEnum):
        NoButton = 0  # If this is specified to button_type, then the buttons will be hidden. selectedItem and selectedItems will have undefined results.
        Radio    = 1  # If specified, the on-screen buttons will be QRadioButtons and selectedItems() will always have 0 or 1 item.
        CheckBox = 2  # If specified, the on-screen buttons will be QCheckBox and selectedItems() may be a list of more than 1 result

    def __init__(self,
                 parent : QWidget,  # widget parent for layout/embedding/etc
                 main_window : MessageBoxMixin,  # may be same as 'parent'; will raise if not an ElectrumWindow instance
                 items: List[Tuple[cashacct.Info, str, str]] = [], # list of 2 or 3 tuple : Info, minimal_chash[, formatted_string]
                 title : str = None,
                 button_type : ButtonType = ButtonType.Radio,  # Note that if CheckBox, the buttonGroup will be made non-exclusive and selectedItems() may return more than 1 item.
                 extra_buttons : List[Callable[[Tuple[cashacct.Info, str, str]], QAbstractButton]] = [],  # pass a list of callables that take a 3-tuple for each item and return a button
                 show_addresses : bool = True,  # if False, the address label remains hidden
                 custom_contents_margins : Tuple[int] = None,  # if specified, use this as the contents margins for the internal layout widget
                 ):
        from .main_window import ElectrumWindow
        assert isinstance(main_window, ElectrumWindow)
        super().__init__(parent)
        self.main_window = main_window
        self.wallet = self.main_window.wallet
        self.extra_buttons = extra_buttons or []
        self.show_addresses = bool(show_addresses)
        if isinstance(custom_contents_margins, (tuple, list)) and len(custom_contents_margins) == 4 and all(isinstance(x, (int, float)) for x in custom_contents_margins):
            self.custom_contents_margins = custom_contents_margins
        else:
            self.custom_contents_margins = None
        assert isinstance(self.wallet, Abstract_Wallet)
        self._setup()
        self.setItems(items=items, title=title, auto_resize_parent=False, button_type=button_type)

    def _setup(self):
        self.w = QWidget(self)
        self.vbox = QVBoxLayout(self)
        self.vbox.setContentsMargins(0,0,0,0)
        self.vbox.addWidget(self.w)
        self._but_grp = QButtonGroup(self)  # client code shouldn't use this but instead use selectedItems(), etc
        self.no_items_text = _('No Cash Accounts')  # client code may set this directly

    def setItems(self,
                 items : List[Tuple[cashacct.Info, str, str]],  # list of 2 or 3 tuple : Info, minimal_chash[, formatted_string]
                 title = None, auto_resize_parent = True, sort=True,
                 button_type : ButtonType = ButtonType.Radio):
        items = items or []
        nitems = len(items)
        title = ngettext("{number} Cash Account", "{number} Cash Accounts", nitems).format(number=nitems) if title is None else title
        wallet = self.wallet
        if items and (sort or len(items[0]) != 3):
            # sort items by formatted cash account string, also adding the string to
            # the items tuples; tuples now are modified to 3 elements:
            # (info, min_chash, formatted_ca_string)
            formatter = lambda x: (x[0], x[1], wallet.cashacct.fmt_info(x[0], x[1]))
            if sort:
                items = sorted((formatter(x) for x in items), key=lambda tup:tup[2])
            else:
                items = [formatter(x) for x in items]
        self._items = items
        self.button_type = button_type
        self.setTitle(title)
        self.refresh()
        if auto_resize_parent and self.parent():
            weakParent = util.Weak.ref(self.parent())
            QTimer.singleShot(0, lambda: weakParent() and weakParent().resize(weakParent().sizeHint()))

    def buttonGroup(self) -> QButtonGroup:
        ''' The button group id's will point to indices in self.items() '''
        return self._but_grp

    def checkItemWithInfo(self, info : cashacct.Info):
        ''' Pass an info object and the item that corresponds to that
        Info object will be checked. Pass None to uncheck all items. '''
        for i, item in enumerate(self._items):
            if info is None:
                self._but_grp.button(i).setChecked(False)
            elif item[0] == info:
                self._but_grp.button(i).setChecked(True)

    def items(self) -> List[Tuple[cashacct.Info, str, str]]:
        ''' The list of items on-screen. self.buttonGroup()'s ids will point
        to indices in this list.

        Returned list items are 3-tuples of:
           (Info, min_chash: str, fmtd_acct_name: str) '''
        return self._items

    def selectedItem(self) -> Tuple[cashacct.Info, str, str]:
        ''' Returns the currently selected item tuple or None if none is selected '''
        items = self.selectedItems()
        if items:
            return items[0]

    def selectedItems(self) -> List[Tuple[cashacct.Info, str, str]]:
        ''' In multi-select mode (CheckBox mode), returns the currently selected
        items as a list of 3-tuple. '''
        ret = []
        buts = self._but_grp.buttons()
        for but in buts:
            if but.isChecked():
                which = self._but_grp.id(but)
                if which > -1 and which < len(self._items):
                    ret.append(self._items[which])
        return ret

    def refresh(self):
        from .main_window import ElectrumWindow
        parent = self.main_window
        wallet = self.wallet
        items = self._items
        button_type = self.button_type
        assert all(len(x) == 3 for x in items)
        but_grp = self._but_grp
        cols, col, row = 2, 0, -1

        if self.w:
            # save selection
            saved_selection = [tup[0] for tup in self.selectedItems()]
            # tear down the dummy container widget from before and everything
            # in it
            for c in self.findChildren(QAbstractButton, "InfoGroupBoxButton"):
                if isinstance(c, QAbstractButton):
                    but_grp.removeButton(c)
            self.w.hide()
            self.vbox.removeWidget(self.w)
            self.w.setParent(None)
            self.w.deleteLater()
            self.w = None
        self.w = w = QWidget(self)
        self.vbox.addWidget(w)

        grid = QGridLayout(w)

        if self.custom_contents_margins:
            grid.setContentsMargins(*self.custom_contents_margins)

        def view_tx_link_activated(txid):
            if isinstance(parent, ElectrumWindow):
                parent.do_process_from_txid(txid=txid, tx_desc=wallet.get_label(txid))

        def view_addr_link_activated(addr):
            if isinstance(parent, ElectrumWindow):
                try:
                    address = Address.from_string(addr)
                    parent.show_address(address, parent=parent.top_level_window())
                except Exception as e:
                    parent.print_error(repr(e))



        if button_type == __class__.ButtonType.CheckBox:
            BUTTON_CLASS = QCheckBox
            but_grp.setExclusive(False)
        else:
            BUTTON_CLASS = QRadioButton
            but_grp.setExclusive(True)
        hide_but = button_type == __class__.ButtonType.NoButton

        grid.setVerticalSpacing(4)

        if not items:
            label = WWLabel("<i>" + self.no_items_text + "</i>")
            label.setAlignment(Qt.AlignCenter)
            grid.addWidget(label, 0, 0, -1, -1)


        for i, item in enumerate(items):
            col = col % cols
            if not col:
                row += 1
            info, min_chash, ca_string = item
            # Radio button (by itself in colum 0)
            rb = BUTTON_CLASS()
            rb.setObjectName("InfoGroupBoxButton")
            rb.setHidden(hide_but)
            rb.setDisabled(hide_but)  # hidden buttons also disabled to prevent user clicking their labels to select them
            is_valid = True
            is_mine = False
            is_change = False
            if not isinstance(info.address, Address):
                rb.setDisabled(True)
                is_valid = False
                rb.setToolTip(_('Electron Cash currently only supports Cash Account types 1 & 2'))
            elif wallet.is_mine(info.address):
                is_mine = True
                is_change = wallet.is_change(info.address)
            but_grp.addButton(rb, i)
            grid.addWidget(rb, row*3, col*5, 1, 1)
            pretty_string = info.emoji + " " + ca_string[:-1]
            chash_extra = info.collision_hash[len(min_chash):]
            if not min_chash:
                chash_extra = "." + chash_extra

            # Cash Account name
            ca_lbl = ButtonAssociatedLabel(f'<b>{pretty_string}</b><font size=-1><i>{chash_extra}</i></font><b>;</b>', button=rb)
            grid.addWidget(ca_lbl, row*3, col*5+1, 1, 1)

            # View tx ...
            viewtx = _("View tx")
            view_tx_lbl = WWLabel(f'<font size=-1><a href="{info.txid}">{viewtx}...</a></font>')
            grid.addWidget(view_tx_lbl, row*3, col*5+2, 1, 1)
            view_tx_lbl.setToolTip(_("View Registration Transaction"))

            # misc buttons
            but_style_sheet = 'QPushButton { border-width: 1px; padding: 0px; margin: 0px; }'
            if not ColorScheme.dark_scheme:
                but_style_sheet += ''' QPushButton { border: 1px solid transparent; }
                QPushButton:hover { border: 1px solid #3daee9; }'''
            hbox = QHBoxLayout()
            hbox.setContentsMargins(0,0,0,0)
            hbox.setSpacing(4)
            for func in self.extra_buttons:
                if callable(func):
                    ab = func(item)
                    if isinstance(ab, QAbstractButton):
                        ab.setStyleSheet(but_style_sheet)
                        ab.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
                        hbox.addWidget(ab)
            # copy button
            copy_but = QPushButton(QIcon(":icons/copy.png"), "")
            copy_but.setStyleSheet(but_style_sheet)
            copy_but.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
            hbox.addWidget(copy_but)
            grid.addLayout(hbox, row*3, col*5+3, 1, 1)
            # end button bar

            if isinstance(parent, ElectrumWindow):
                view_tx_lbl.linkActivated.connect(view_tx_link_activated)
                copy_but.clicked.connect(lambda ignored=None, ca_string=ca_string, copy_but=copy_but:
                                             parent.copy_to_clipboard(text=ca_string, tooltip=_('Cash Account copied to clipboard'), widget=copy_but) )
                copy_but.setToolTip(_("Copy <b>{cash_account_name}</b>").format(cash_account_name=ca_string))
            else:
                view_tx_lbl.setHidden(True)
                copy_but.setHidden(True)

            if self.show_addresses:
                addr_lbl = ButtonAssociatedLabel('', button=rb)
                if is_valid:
                    if is_mine:
                        addr_lbl.setText(f'<a href="{info.address.to_ui_string()}"><pre>{info.address.to_ui_string()}</pre></a>')
                        addr_lbl.linkActivated.connect(view_addr_link_activated)
                        addr_lbl.setToolTip(_('Wallet') + ' - ' + (_('Change Address') if is_change else _('Receiving Address')))
                        addr_lbl.setButton(None)  # disable click to select
                    else:
                        addr_lbl.setText(f'<pre>{info.address.to_ui_string()}</pre>')
                else:
                    addr_lbl.setText('<i>' + _('Unsupported Account Type') + '</i>')
                    addr_lbl.setToolTip(rb.toolTip())
                grid.addWidget(addr_lbl, row*3+1, col*5+1, 1, 3)

            if (col % cols) == 0:
                # insert stretch in between the two columns
                spacer = QSpacerItem(1,0)
                grid.addItem(spacer, row, col*5+4, 1, 1)
                grid.setColumnStretch(col*5+4, 10)

            if self.show_addresses:
                # in-between row spaer. Only added if showing addresses
                # to make the address line visually closer to the line above it
                spacer = QSpacerItem(1, 8)
                grid.addItem(spacer, row*3+2, col*5, 1, 4)

            col += 1


        if len(items) == 1:
            # just 1 item, put it on the left
            grid.addItem(QSpacerItem(2,1), 0, 5)
            grid.setColumnStretch(5, 100)
        if len(items) <= 2:
            # just 1 row, push it up to the top
            grid.addItem(QSpacerItem(1,2), 3, 0, -1, -1)
            grid.setRowStretch(3, 100)


        if saved_selection and self.button_type != self.ButtonType.NoButton:
            for info in saved_selection:
                self.checkItemWithInfo(info)
        else:
            self.checkItemWithInfo(None)

def multiple_result_picker(parent, results, wallet=None, msg=None, title=None, gbtext=None):
    ''' Pops up a modal dialog telling you to pick a results. Used by the
    Contacts tab edit function, etc. '''
    assert parent
    from .main_window import ElectrumWindow
    if isinstance(parent, ElectrumWindow) and not wallet:
        wallet = parent.wallet
    assert isinstance(wallet, Abstract_Wallet)

    msg = msg or _('Multiple results were found, please select an option from the items below:')
    title = title or _("Select Cash Account")

    d = WindowModalDialog(parent, title)
    util.finalization_print_error(d)  # track object lifecycle
    destroyed_print_error(d)

    vbox = QVBoxLayout(d)
    lbl = WWLabel(msg)
    vbox.addWidget(lbl)

    gb = InfoGroupBox(d, parent, results)
    vbox.addWidget(gb)

    ok_but = OkButton(d)
    buts = Buttons(CancelButton(d), ok_but)
    vbox.addLayout(buts)
    ok_but.setEnabled(False)

    but_grp = gb.buttonGroup()
    but_grp.buttonClicked.connect(lambda x=None: ok_but.setEnabled(gb.selectedItem() is not None))

    code = d.exec_()

    if code == QDialog.Accepted:
        item = gb.selectedItem()
        if item:
            return item[:-1]

def lookup_cash_account_dialog(
    parent, wallet, *,  # parent and wallet are required and parent must be an ElectrumWindow instance.
        title: str = None,  # the title to use, defaults to "Lookup Cash Account" (translated) and is bold and larger. Can be rich text.
        blurb: str = None,  # will appear in the same label, can be rich text, will get concatenated to title.
        title_label_link_activated_slot: Callable[[str], None] = None,  # if you embed links in the blub, pass a callback to handle them
        button_type: InfoGroupBox.ButtonType = InfoGroupBox.ButtonType.NoButton,  #  see InfoGroupBox
        add_to_contacts_button: bool = False  # if true, the button bar will include an add to contacts button
) -> List[Tuple[cashacct.Info, str, str]]:  # Returns a list of tuples
    ''' Shows the generic Cash Account lookup interface. '''
    from .main_window import ElectrumWindow
    ok_disables = button_type != InfoGroupBox.ButtonType.NoButton
    title = title or _("Lookup Cash Account")
    blurb = blurb or ''
    assert isinstance(parent, ElectrumWindow) and isinstance(wallet, Abstract_Wallet)
    if parent.gui_object.warn_if_no_network(parent):
        return None
    d = WindowModalDialog(parent.top_level_window(), title)
    d.setObjectName("WindowModalDialog - " + title)
    finalization_print_error(d)
    destroyed_print_error(d)
    all_cashacct_contacts = set(contact.name for contact in wallet.contacts.get_all(nocopy=True) if contact.type == 'cashacct')

    vbox = QVBoxLayout(d)
    hbox = QHBoxLayout()
    label = QLabel()
    label.setPixmap(QIcon(":icons/cashacct-logo.png").pixmap(50))
    hbox.addWidget(label)
    hbox.addItem(QSpacerItem(10, 1))
    label = QLabel("<font size=+1><b>" + title + "</b></font>" + blurb)
    if callable(title_label_link_activated_slot):
        label.linkActivated.connect(title_label_link_activated_slot)
    label.setAlignment(Qt.AlignVCenter|Qt.AlignLeft)
    hbox.addWidget(label)
    hbox.addStretch(2)
    vbox.addLayout(hbox)
    grid = QGridLayout()
    grid.setContentsMargins(62, 32, 12, 12)
    acct = QLineEdit()
    acct.setPlaceholderText(_("Cash Account e.g. satoshi#123.45"))
    acct.setMinimumWidth(280)
    label2 = WWLabel('<a href="https://www.cashaccount.info/#lookup">' + _("Search online...") + "</a>")
    label2.linkActivated.connect(webopen)


    #acct.setFixedWidth(280)
    label = HelpLabel(_("&Cash Account Name"), _("Enter a Cash Account name of the form Name#123.45, and Electron Cash will search for the contact and present you with its resolved address."))
    label.setBuddy(acct)
    search = QPushButton(_("Lookup"))
    search.setEnabled(False)
    grid.addWidget(label, 0, 0, 1, 1, Qt.AlignRight)
    grid.addWidget(acct, 0, 1, 1, 1, Qt.AlignLeft)
    grid.addWidget(search, 0, 2, 1, 1, Qt.AlignLeft)
    grid.addWidget(label2, 0, 3, 1, 1, Qt.AlignLeft)
    grid.setColumnStretch(3, 5)
    vbox.addLayout(grid)
    vbox.addItem(QSpacerItem(20,10))
    frame = QScrollArea()
    tit_lbl = QLabel()
    vbox.addWidget(tit_lbl)
    extra_buttons = []
    if add_to_contacts_button:
        def create_add_to_contacts_button_callback(item: tuple) -> QPushButton:
            but = QPushButton()
            but.setIcon(QIcon(":icons/tab_contacts.png"))
            if isinstance(item[0].address, Address):
                if item[2] in all_cashacct_contacts or wallet.is_mine(item[0].address):
                    but.setDisabled(True)
                    but.setToolTip(_("<b>{cash_account}</b> already in Contacts").format(cash_account=item[2]))
                else:
                    but.setToolTip(_("Add <b>{cash_account}</b> to Contacts").format(cash_account=item[2]))
                    def add_contact_slot(ign=None, but=but, item=item):
                        # label, address, typ='address') -> str:
                        if parent.set_contact(label=item[2], address=item[0].address, typ='cashacct'):
                            msg = _("<b>{cash_account}</b> added to Contacts").format(cash_account=item[2])
                            but.setDisabled(True)
                            but.setToolTip(msg)
                        else:
                            msg = _("Error occurred adding to Contacts")
                        QToolTip.showText(QCursor.pos(), msg, frame, QRect(), 5000)
                    # /add_contact
                    but.clicked.connect(add_contact_slot)
            else:
                but.setDisabled(True)
                but.setToolTip("<i>" + _("Unsupported Account Type") + "</i>")
            return but
        extra_buttons.append(create_add_to_contacts_button_callback)
    ca = InfoGroupBox(frame, parent, button_type = button_type, title = '', extra_buttons=extra_buttons)
    ca.refresh()
    frame.setMinimumWidth(765)
    frame.setMinimumHeight(250)
    frame.setWidget(ca)
    frame.setWidgetResizable(True)
    vbox.addWidget(frame)
    search.setDefault(True)
    if ok_disables:
        need_to_fwd_return = True
        ok = OkButton(d)
        ok.setDisabled(ok_disables)
        vbox.addLayout(Buttons(CancelButton(d), ok))
    else:
        need_to_fwd_return = False
        ok = CloseButton(d)
        ok.setDefault(False)
        vbox.addLayout(Buttons(ok))

    def ca_msg(m, clear=False):
        ca.no_items_text = m
        if clear:
            ca.setItems([], auto_resize_parent=False, title = '')
        else:
            ca.refresh()
        tit_lbl.setText('')

    def on_return_pressed():
        if need_to_fwd_return and search.isEnabled():
            search.click()

    def on_text_changed(txt):
        txt = txt.strip() if txt else ''
        search.setEnabled(bool(wallet.cashacct.parse_string(txt)))
        if not txt and not ca.items():
            ca_msg(" ")

    def on_search():
        ok.setDisabled(ok_disables)
        name = acct.text().strip()
        tup = wallet.cashacct.parse_string(name)
        if tup:
            ca_msg(_("Searching for <b>{cash_account_name}</b> please wait ...").format(cash_account_name=name), True)
            results = None
            def resolve_verify():
                nonlocal results
                results = wallet.cashacct.resolve_verify(name)
            code = VerifyingDialog(parent.top_level_window(),
                                   _("Verifying Cash Account {name} please wait ...").format(name=name),
                                   resolve_verify, auto_show=False).exec_()
            if code == QDialog.Rejected:
                # user cancel -- the waiting dialog thread will continue to run in the background but that's ok.. it will be a no-op
                d.reject()
                return
            if results:
                ca.setItems(results, auto_resize_parent=False, title='', button_type = button_type)  # suppress groupbox title
            else:
                ca_msg(_("The specified Cash Account does not appear to be associated with any address"), True)
            nres = len(results or [])
            title =  "<b>" + name + "</b> - " + ngettext("{number} Cash Account", "{number} Cash Accounts", nres).format(number=nres)
            tit_lbl.setText(title)
        else:
            ca_msg(_("Invalid Cash Account name, please try again"), True)

    acct.textChanged.connect(on_text_changed)
    search.clicked.connect(on_search)
    acct.returnPressed.connect(on_return_pressed)
    ca.buttonGroup().buttonClicked.connect(lambda x=None: ok.setEnabled(ok_disables and ca.selectedItem() is not None))

    ca_msg(" ")

    if d.exec_() == QDialog.Accepted:
        return ca.selectedItems()
    return None
