# Copyright (C) 2022 The Electrum developers
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://www.opensource.org/licenses/mit-license.php

from typing import Optional, TYPE_CHECKING

from PyQt5.QtGui import QFont
from PyQt5.QtCore import Qt, QSize
from PyQt5.QtWidgets import (QComboBox, QLabel, QVBoxLayout, QGridLayout, QLineEdit,
                             QHBoxLayout, QPushButton, QWidget, QSizePolicy)

from electrum.bitcoin import is_address
from electrum.i18n import _
from electrum.util import InvoiceError
from electrum.invoices import PR_DEFAULT_EXPIRATION_WHEN_CREATING
from electrum.invoices import PR_EXPIRED, pr_expiration_values
from electrum.logging import Logger

from .amountedit import AmountEdit, BTCAmountEdit, SizedFreezableLineEdit
from .qrcodewidget import QRCodeWidget
from .util import read_QIcon, ColorScheme, HelpLabel, WWLabel, MessageBoxMixin, MONOSPACE_FONT
from .util import ButtonsTextEdit

if TYPE_CHECKING:
    from . import ElectrumGui
    from .main_window import ElectrumWindow


class ReceiveTab(QWidget, MessageBoxMixin, Logger):

    def __init__(self, window: 'ElectrumWindow'):
        QWidget.__init__(self, window)
        Logger.__init__(self)

        self.window = window
        self.wallet = window.wallet
        self.fx = window.fx
        self.config = window.config

        # A 4-column grid layout.  All the stretch is in the last column.
        # The exchange rate plugin adds a fiat widget in column 2
        self.receive_grid = grid = QGridLayout()
        grid.setSpacing(8)
        grid.setColumnStretch(3, 1)

        self.receive_message_e = SizedFreezableLineEdit(width=400)
        grid.addWidget(QLabel(_('Description')), 0, 0)
        grid.addWidget(self.receive_message_e, 0, 1, 1, 4)

        self.receive_amount_e = BTCAmountEdit(self.window.get_decimal_point)
        grid.addWidget(QLabel(_('Requested amount')), 1, 0)
        grid.addWidget(self.receive_amount_e, 1, 1)

        self.fiat_receive_e = AmountEdit(self.fx.get_currency if self.fx else '')
        if not self.fx or not self.fx.is_enabled():
            self.fiat_receive_e.setVisible(False)
        grid.addWidget(self.fiat_receive_e, 1, 2, Qt.AlignLeft)

        self.window.connect_fields(self.receive_amount_e, self.fiat_receive_e)

        self.expires_combo = QComboBox()
        evl = sorted(pr_expiration_values.items())
        evl_keys = [i[0] for i in evl]
        evl_values = [i[1] for i in evl]
        default_expiry = self.config.get('request_expiry', PR_DEFAULT_EXPIRATION_WHEN_CREATING)
        try:
            i = evl_keys.index(default_expiry)
        except ValueError:
            i = 0
        self.expires_combo.addItems(evl_values)
        self.expires_combo.setCurrentIndex(i)
        def on_expiry(i):
            self.config.set_key('request_expiry', evl_keys[i])
        self.expires_combo.currentIndexChanged.connect(on_expiry)
        msg = ''.join([
            _('Expiration date of your request.'), ' ',
            _('This information is seen by the recipient if you send them a signed payment request.'),
            '\n\n',
            _('For on-chain requests, the address gets reserved until expiration. After that, it might get reused.'), ' ',
            _('The bitcoin address never expires and will always be part of this electrum wallet.'), ' ',
            _('You can reuse a bitcoin address any number of times but it is not good for your privacy.'),
            '\n\n',
            _('For Lightning requests, payments will not be accepted after the expiration.'),
        ])
        grid.addWidget(HelpLabel(_('Expires after') + ' (?)', msg), 2, 0)
        grid.addWidget(self.expires_combo, 2, 1)
        self.expires_label = QLineEdit('')
        self.expires_label.setReadOnly(1)
        self.expires_label.setFocusPolicy(Qt.NoFocus)
        self.expires_label.hide()
        grid.addWidget(self.expires_label, 2, 1)

        self.clear_invoice_button = QPushButton(_('Clear'))
        self.clear_invoice_button.clicked.connect(self.do_clear)
        self.create_invoice_button = QPushButton(_('Create Request'))
        self.create_invoice_button.clicked.connect(lambda: self.create_invoice())
        self.receive_buttons = buttons = QHBoxLayout()
        buttons.addStretch(1)
        buttons.addWidget(self.clear_invoice_button)
        buttons.addWidget(self.create_invoice_button)
        grid.addLayout(buttons, 4, 0, 1, -1)

        self.receive_address_e = ButtonsTextEdit()
        self.receive_address_help_text = WWLabel('')
        vbox = QVBoxLayout()
        vbox.addWidget(self.receive_address_help_text)
        self.receive_address_help = QWidget()
        self.receive_address_help.setVisible(False)
        self.receive_address_help.setLayout(vbox)

        self.receive_URI_e = ButtonsTextEdit()
        self.receive_URI_help = WWLabel('')
        self.receive_lightning_e = ButtonsTextEdit()
        self.receive_lightning_help_text = WWLabel('')
        self.receive_rebalance_button = QPushButton('Rebalance')
        self.receive_rebalance_button.suggestion = None
        def on_receive_rebalance():
            if self.receive_rebalance_button.suggestion:
                chan1, chan2, delta = self.receive_rebalance_button.suggestion
                self.window.rebalance_dialog(chan1, chan2, amount_sat=delta)
        self.receive_rebalance_button.clicked.connect(on_receive_rebalance)
        self.receive_swap_button = QPushButton('Swap')
        self.receive_swap_button.suggestion = None
        def on_receive_swap():
            if self.receive_swap_button.suggestion:
                chan, swap_recv_amount_sat = self.receive_swap_button.suggestion
                self.window.run_swap_dialog(is_reverse=True, recv_amount_sat=swap_recv_amount_sat, channels=[chan])
        self.receive_swap_button.clicked.connect(on_receive_swap)
        buttons = QHBoxLayout()
        buttons.addWidget(self.receive_rebalance_button)
        buttons.addWidget(self.receive_swap_button)
        vbox = QVBoxLayout()
        vbox.addWidget(self.receive_lightning_help_text)
        vbox.addLayout(buttons)
        self.receive_lightning_help = QWidget()
        self.receive_lightning_help.setVisible(False)
        self.receive_lightning_help.setLayout(vbox)
        self.receive_address_qr = QRCodeWidget()
        self.receive_URI_qr = QRCodeWidget()
        self.receive_lightning_qr = QRCodeWidget()

        for e in [self.receive_address_e, self.receive_URI_e, self.receive_lightning_e]:
            e.setFont(QFont(MONOSPACE_FONT))
            e.addCopyButton()
            e.setReadOnly(True)

        self.receive_lightning_e.textChanged.connect(self.update_receive_widgets)

        self.receive_address_widget = ReceiveTabWidget(self,
            self.receive_address_e, self.receive_address_qr, self.receive_address_help)
        self.receive_URI_widget = ReceiveTabWidget(self,
            self.receive_URI_e, self.receive_URI_qr, self.receive_URI_help)
        self.receive_lightning_widget = ReceiveTabWidget(self,
            self.receive_lightning_e, self.receive_lightning_qr, self.receive_lightning_help)

        from .util import VTabWidget
        self.receive_tabs = VTabWidget()
        self.receive_tabs.setMinimumHeight(ReceiveTabWidget.min_size.height() + 4) # for margins
        self.receive_tabs.addTab(self.receive_URI_widget, read_QIcon("link.png"), _('URI'))
        self.receive_tabs.addTab(self.receive_address_widget, read_QIcon("bitcoin.png"), _('Address'))
        self.receive_tabs.addTab(self.receive_lightning_widget, read_QIcon("lightning.png"), _('Lightning'))
        self.receive_tabs.currentChanged.connect(self.update_receive_qr_window)
        self.receive_tabs.setCurrentIndex(self.config.get('receive_tabs_index', 0))
        self.receive_tabs.currentChanged.connect(lambda i: self.config.set_key('receive_tabs_index', i))
        receive_tabs_sp = QSizePolicy(QSizePolicy.MinimumExpanding, QSizePolicy.MinimumExpanding)
        receive_tabs_sp.setRetainSizeWhenHidden(True)
        self.receive_tabs.setSizePolicy(receive_tabs_sp)
        self.receive_tabs.setVisible(False)

        self.receive_requests_label = QLabel(_('Receive queue'))
        from .request_list import RequestList
        self.request_list = RequestList(self)

        # layout
        vbox_g = QVBoxLayout()
        vbox_g.addLayout(grid)
        vbox_g.addStretch()
        hbox = QHBoxLayout()
        hbox.addLayout(vbox_g)
        hbox.addStretch()
        hbox.addWidget(self.receive_tabs)

        self.searchable_list = self.request_list
        vbox = QVBoxLayout(self)
        vbox.addLayout(hbox)
        vbox.addStretch()
        vbox.addWidget(self.receive_requests_label)
        vbox.addWidget(self.request_list)
        vbox.setStretchFactor(hbox, 40)
        vbox.setStretchFactor(self.request_list, 60)
        self.request_list.update()  # after parented and put into a layout, can update without flickering

    def toggle_receive_qr(self, e):
        if e.button() != Qt.LeftButton:
            return
        b = not self.config.get('receive_qr_visible', False)
        self.config.set_key('receive_qr_visible', b)
        self.update_receive_widgets()

    def update_receive_widgets(self):
        b = self.config.get('receive_qr_visible', False)
        self.receive_URI_widget.update_visibility(b)
        self.receive_address_widget.update_visibility(b)
        self.receive_lightning_widget.update_visibility(b)

    def update_current_request(self):
        key = self.request_list.get_current_key()
        req = self.wallet.get_request(key) if key else None
        if req is None:
            self.receive_URI_e.setText('')
            self.receive_lightning_e.setText('')
            self.receive_address_e.setText('')
            return
        addr = req.get_address() or ''
        amount_sat = req.get_amount_sat() or 0
        address_help = '' if addr else _('Amount too small to be received onchain')
        URI_help = ''
        lnaddr = req.lightning_invoice
        bip21_lightning = lnaddr if self.config.get('bip21_lightning', False) else None
        URI = req.get_bip21_URI(lightning=bip21_lightning)
        lightning_online = self.wallet.lnworker and self.wallet.lnworker.num_peers() > 0
        can_receive_lightning = self.wallet.lnworker and amount_sat <= self.wallet.lnworker.num_sats_can_receive()
        has_expired = self.wallet.get_request_status(key) == PR_EXPIRED
        if has_expired:
            URI_help = ln_help = address_help = _('This request has expired')
            URI = lnaddr = address = ''
            can_rebalance = False
            can_swap = False
        elif lnaddr is None:
            ln_help = _('This request does not have a Lightning invoice.')
            lnaddr = ''
            can_rebalance = False
            can_swap = False
        elif not lightning_online:
            ln_help = _('You must be online to receive Lightning payments.')
            lnaddr = ''
            can_rebalance = False
            can_swap = False
        elif not can_receive_lightning:
            self.receive_rebalance_button.suggestion = self.wallet.lnworker.suggest_rebalance_to_receive(amount_sat)
            self.receive_swap_button.suggestion = self.wallet.lnworker.suggest_swap_to_receive(amount_sat)
            can_rebalance = bool(self.receive_rebalance_button.suggestion)
            can_swap = bool(self.receive_swap_button.suggestion)
            lnaddr = ''
            ln_help = _('You do not have the capacity to receive that amount with Lightning.')
            if can_rebalance:
                ln_help += '\n\n' + _('You may have that capacity if you rebalance your channels.')
            elif can_swap:
                ln_help += '\n\n' + _('You may have that capacity if you swap some of your funds.')
        else:
            ln_help = ''
            can_rebalance = False
            can_swap = False
        self.receive_rebalance_button.setVisible(can_rebalance)
        self.receive_swap_button.setVisible(can_swap)
        self.receive_rebalance_button.setEnabled(can_rebalance and self.window.num_tasks() == 0)
        self.receive_swap_button.setEnabled(can_swap and self.window.num_tasks() == 0)
        icon_name = "lightning.png" if lnaddr else "lightning_disconnected.png"
        self.receive_tabs.setTabIcon(2, read_QIcon(icon_name))
        # encode lightning invoices as uppercase so QR encoding can use
        # alphanumeric mode; resulting in smaller QR codes
        lnaddr_qr = lnaddr.upper()
        self.receive_address_e.setText(addr)
        self.update_receive_address_styling()
        self.receive_address_qr.setData(addr)
        self.receive_address_help_text.setText(address_help)
        self.receive_URI_e.setText(URI)
        self.receive_URI_qr.setData(URI)
        self.receive_URI_help.setText(URI_help)
        self.receive_lightning_e.setText(lnaddr)  # TODO maybe prepend "lightning:" ??
        self.receive_lightning_help_text.setText(ln_help)
        self.receive_lightning_qr.setData(lnaddr_qr)
        # macOS hack (similar to #4777)
        self.receive_lightning_e.repaint()
        self.receive_URI_e.repaint()
        self.receive_address_e.repaint()
        # always show
        self.receive_tabs.setVisible(True)
        self.update_receive_qr_window()

    def update_receive_qr_window(self):
        if self.window.qr_window and self.window.qr_window.isVisible():
            i = self.receive_tabs.currentIndex()
            if i == 0:
                data = self.receive_URI_qr.data
            elif i == 1:
                data = self.receive_address_qr.data
            else:
                data = self.receive_lightning_qr.data
            self.window.qr_window.qrw.setData(data)

    def sign_payment_request(self, addr):
        alias = self.config.get('alias')
        if alias and self.wallet.contacts.alias_info:
            alias_addr, alias_name, validated = self.wallet.contacts.alias_info
            if alias_addr:
                if self.wallet.is_mine(alias_addr):
                    msg = _('This payment request will be signed.') + '\n' + _('Please enter your password')
                    password = None
                    if self.wallet.has_keystore_encryption():
                        password = self.window.password_dialog(msg)
                        if not password:
                            return
                    try:
                        self.wallet.sign_payment_request(addr, alias, alias_addr, password)
                    except Exception as e:
                        self.show_error(repr(e))
                        return
                else:
                    return

    def create_invoice(self):
        amount_sat = self.receive_amount_e.get_amount()
        message = self.receive_message_e.text()
        expiry = self.config.get('request_expiry', PR_DEFAULT_EXPIRATION_WHEN_CREATING)

        if amount_sat and amount_sat < self.wallet.dust_threshold():
            address = None
            if not self.wallet.has_lightning():
                return
        else:
            address = self.get_bitcoin_address_for_request(amount_sat)
            if not address:
                return
            self.window.address_list.update()

        # generate even if we cannot receive
        lightning = self.wallet.has_lightning()
        try:
            key = self.wallet.create_request(amount_sat, message, expiry, address, lightning=lightning)
        except InvoiceError as e:
            self.show_error(_('Error creating payment request') + ':\n' + str(e))
            return
        except Exception as e:
            self.logger.exception('Error adding payment request')
            self.show_error(_('Error adding payment request') + ':\n' + repr(e))
            return
        self.sign_payment_request(address)
        assert key is not None
        self.window.address_list.refresh_all()
        self.request_list.update()
        self.request_list.set_current_key(key)
        # clear request fields
        self.receive_amount_e.setText('')
        self.receive_message_e.setText('')
        # copy to clipboard
        r = self.wallet.get_request(key)
        content = r.lightning_invoice if r.is_lightning() else r.get_address()
        title = _('Invoice') if r.is_lightning() else _('Address')
        self.window.do_copy(content, title=title)

    def get_bitcoin_address_for_request(self, amount) -> Optional[str]:
        addr = self.wallet.get_unused_address()
        if addr is None:
            if not self.wallet.is_deterministic():  # imported wallet
                msg = [
                    _('No more addresses in your wallet.'), ' ',
                    _('You are using a non-deterministic wallet, which cannot create new addresses.'), ' ',
                    _('If you want to create new addresses, use a deterministic wallet instead.'), '\n\n',
                    _('Creating a new payment request will reuse one of your addresses and overwrite an existing request. Continue anyway?'),
                   ]
                if not self.question(''.join(msg)):
                    return
                addr = self.wallet.get_receiving_address()
            else:  # deterministic wallet
                if not self.question(_("Warning: The next address will not be recovered automatically if you restore your wallet from seed; you may need to add it manually.\n\nThis occurs because you have too many unused addresses in your wallet. To avoid this situation, use the existing addresses first.\n\nCreate anyway?")):
                    return
                addr = self.wallet.create_new_address(False)
        return addr

    def do_clear(self):
        self.receive_address_e.setText('')
        self.receive_URI_e.setText('')
        self.receive_lightning_e.setText('')
        self.receive_tabs.setVisible(False)
        self.receive_message_e.setText('')
        self.receive_amount_e.setAmount(None)
        self.expires_label.hide()
        self.expires_combo.show()
        self.request_list.clearSelection()

    def update_receive_address_styling(self):
        addr = str(self.receive_address_e.text())
        if is_address(addr) and self.wallet.adb.is_used(addr):
            self.receive_address_e.setStyleSheet(ColorScheme.RED.as_stylesheet(True))
            self.receive_address_e.setToolTip(_("This address has already been used. "
                                                "For better privacy, do not reuse it for new payments."))
        else:
            self.receive_address_e.setStyleSheet("")
            self.receive_address_e.setToolTip("")


class ReceiveTabWidget(QWidget):
    min_size = QSize(200, 200)

    def __init__(self, receive_tab: 'ReceiveTab', textedit, qr, help_widget):
        self.textedit = textedit
        self.qr = qr
        self.help_widget = help_widget
        QWidget.__init__(self)
        for w in [textedit, qr, help_widget]:
            w.setMinimumSize(self.min_size)
        for w in [textedit, qr]:
            w.mousePressEvent = receive_tab.toggle_receive_qr
            tooltip = _('Click to switch between text and QR code view')
            w.setToolTip(tooltip)
        textedit.setFocusPolicy(Qt.NoFocus)
        hbox = QHBoxLayout()
        hbox.setContentsMargins(0, 0, 0, 0)
        hbox.addWidget(textedit)
        hbox.addWidget(help_widget)
        hbox.addWidget(qr)
        self.setLayout(hbox)

    def update_visibility(self, is_qr):
        if str(self.textedit.text()):
            self.help_widget.setVisible(False)
            self.textedit.setVisible(not is_qr)
            self.qr.setVisible(is_qr)
        else:
            self.help_widget.setVisible(True)
            self.textedit.setVisible(False)
            self.qr.setVisible(False)

