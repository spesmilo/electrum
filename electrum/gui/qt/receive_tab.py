# Copyright (C) 2022 The Electrum developers
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://www.opensource.org/licenses/mit-license.php

from typing import Optional, TYPE_CHECKING

from PyQt6.QtGui import QFont, QCursor, QMouseEvent
from PyQt6.QtCore import Qt, QSize
from PyQt6.QtWidgets import (QComboBox, QLabel, QVBoxLayout, QGridLayout, QLineEdit, QTextEdit,
                             QHBoxLayout, QPushButton, QWidget, QSizePolicy, QFrame)

from electrum.bitcoin import is_address
from electrum.i18n import _
from electrum.util import InvoiceError
from electrum.invoices import pr_expiration_values
from electrum.logging import Logger

from .amountedit import AmountEdit, BTCAmountEdit, SizedFreezableLineEdit
from .qrcodewidget import QRCodeWidget
from .util import read_QIcon, ColorScheme, HelpLabel, WWLabel, MessageBoxMixin, MONOSPACE_FONT
from .util import ButtonsTextEdit, get_iconname_qrcode

if TYPE_CHECKING:
    from . import ElectrumGui
    from .main_window import ElectrumWindow


class ReceiveTab(QWidget, MessageBoxMixin, Logger):

    # strings updated by update_current_request
    addr = ''
    lnaddr = ''
    URI = ''
    address_help = ''
    URI_help = ''
    ln_help = ''

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
        grid.addWidget(self.fiat_receive_e, 1, 2, Qt.AlignmentFlag.AlignLeft)

        self.window.connect_fields(self.receive_amount_e, self.fiat_receive_e)

        self.expiry_button = QPushButton('')
        self.expiry_button.clicked.connect(self.expiry_dialog)
        grid.addWidget(QLabel(_('Expiry')), 2, 0)
        grid.addWidget(self.expiry_button, 2, 1)

        self.clear_invoice_button = QPushButton(_('Clear'))
        self.clear_invoice_button.clicked.connect(self.do_clear)
        self.create_invoice_button = QPushButton(_('Create Request'))
        self.create_invoice_button.clicked.connect(lambda: self.create_invoice())
        self.receive_buttons = buttons = QHBoxLayout()
        buttons.addStretch(1)
        buttons.addWidget(self.clear_invoice_button)
        buttons.addWidget(self.create_invoice_button)
        grid.addLayout(buttons, 4, 0, 1, -1)

        self.receive_e = QTextEdit()
        self.receive_e.setFont(QFont(MONOSPACE_FONT))
        self.receive_e.setReadOnly(True)
        self.receive_e.setContextMenuPolicy(Qt.ContextMenuPolicy.NoContextMenu)
        self.receive_e.setTextInteractionFlags(Qt.TextInteractionFlag.NoTextInteraction)
        self.receive_e.textChanged.connect(self.update_receive_widgets)

        self.receive_qr = QRCodeWidget(manual_size=True)

        self.receive_help_text = WWLabel('')
        self.receive_help_text.setLayout(QHBoxLayout())
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
        vbox.addWidget(self.receive_help_text)
        vbox.addLayout(buttons)
        self.receive_help_widget = FramedWidget()
        self.receive_help_widget.setVisible(False)
        self.receive_help_widget.setLayout(vbox)

        self.receive_widget = ReceiveWidget(
            self, self.receive_e, self.receive_qr, self.receive_help_widget)

        receive_widget_sp = QSizePolicy(QSizePolicy.Policy.MinimumExpanding, QSizePolicy.Policy.MinimumExpanding)
        receive_widget_sp.setRetainSizeWhenHidden(True)
        self.receive_widget.setSizePolicy(receive_widget_sp)
        self.receive_widget.setVisible(False)

        self.receive_requests_label = QLabel(_('Requests'))
        # with QDarkStyle, this label may partially cover the qrcode widget.
        # setMaximumWidth prevents that
        self.receive_requests_label.setMaximumWidth(400)
        from .request_list import RequestList
        self.request_list = RequestList(self)
        # toolbar
        self.toolbar, menu = self.request_list.create_toolbar_with_menu('')

        self.toggle_qr_button = QPushButton('')
        self.toggle_qr_button.setIcon(read_QIcon(get_iconname_qrcode()))
        self.toggle_qr_button.setToolTip(_('Switch between text and QR code view'))
        self.toggle_qr_button.clicked.connect(self.toggle_receive_qr)
        self.toggle_qr_button.setEnabled(False)
        self.toolbar.insertWidget(2, self.toggle_qr_button)

        self.toggle_view_button = QPushButton('')
        self.toggle_view_button.setToolTip(_('switch between view'))
        self.toggle_view_button.clicked.connect(self.toggle_view)
        self.toggle_view_button.setEnabled(False)
        self.update_view_button()
        self.toolbar.insertWidget(2, self.toggle_view_button)
        # menu
        menu.addConfig(self.config.cv.WALLET_BOLT11_FALLBACK, callback=self.on_toggle_bolt11_fallback)
        menu.addConfig(self.config.cv.WALLET_BIP21_LIGHTNING, callback=self.update_current_request)
        self.qr_menu_action = menu.addToggle(_("Show detached QR code window"), self.window.toggle_qr_window)
        menu.addAction(_("Import requests"), self.window.import_requests)
        menu.addAction(_("Export requests"), self.window.export_requests)
        menu.addAction(_("Delete expired requests"), self.request_list.delete_expired_requests)
        self.toolbar_menu = menu

        # layout
        vbox_g = QVBoxLayout()
        vbox_g.addLayout(grid)
        vbox_g.addStretch()
        hbox = QHBoxLayout()
        hbox.addLayout(vbox_g)
        hbox.addStretch()
        hbox.addWidget(self.receive_widget, 1)

        self.searchable_list = self.request_list
        vbox = QVBoxLayout(self)
        vbox.addLayout(self.toolbar)
        vbox.addLayout(hbox)
        vbox.addStretch()
        vbox.addWidget(self.receive_requests_label)
        vbox.addWidget(self.request_list)
        vbox.setStretchFactor(hbox, 40)
        vbox.setStretchFactor(self.request_list, 60)
        self.request_list.update()  # after parented and put into a layout, can update without flickering
        self.update_expiry_text()

    def update_expiry_text(self):
        expiry = self.config.WALLET_PAYREQ_EXPIRY_SECONDS
        text = pr_expiration_values()[expiry]
        self.expiry_button.setText(text)

    def expiry_dialog(self):
        msg = ''.join([
            _('Expiration period of your request.'), ' ',
            _('This information is seen by the recipient if you send them a signed payment request.'),
            '\n\n',
            _('For on-chain requests, the address gets reserved until expiration. After that, it might get reused.'), ' ',
            _('The bitcoin address never expires and will always be part of this electrum wallet.'), ' ',
            _('You can reuse a bitcoin address any number of times but it is not good for your privacy.'),
            '\n\n',
            _('For Lightning requests, payments will not be accepted after the expiration.'),
        ])
        expiry = self.config.WALLET_PAYREQ_EXPIRY_SECONDS
        choices = list(pr_expiration_values().items())
        v = self.window.query_choice(msg, choices, title=_('Expiry'), default_choice=expiry)
        if v is None:
            return
        self.config.WALLET_PAYREQ_EXPIRY_SECONDS = v
        self.update_expiry_text()

    def on_toggle_bolt11_fallback(self):
        if not self.wallet.lnworker:
            return
        self.wallet.lnworker.clear_invoices_cache()
        self.update_current_request()

    def update_view_button(self):
        i = self.config.GUI_QT_RECEIVE_TABS_INDEX
        if i == 0:
            icon, text = read_QIcon("link.png"), _('Bitcoin URI')
        elif i == 1:
            icon, text = read_QIcon("bitcoin.png"), _('Address')
        elif i == 2:
            icon, text = read_QIcon("lightning.png"), _('Lightning')
        self.toggle_view_button.setText(text)
        self.toggle_view_button.setIcon(icon)

    def toggle_view(self):
        i = self.config.GUI_QT_RECEIVE_TABS_INDEX
        i = (i + 1) % (3 if self.wallet.has_lightning() else 2)
        self.config.GUI_QT_RECEIVE_TABS_INDEX = i
        self.update_current_request()
        self.update_view_button()

    def on_tab_changed(self):
        text, data, help_text, title = self.get_tab_data()
        self.window.do_copy(text, title=title)
        self.update_receive_qr_window()

    def do_copy(self, e: 'QMouseEvent'):
        if e.button() != Qt.MouseButton.LeftButton:
            return
        text, data, help_text, title = self.get_tab_data()
        self.window.do_copy(text, title=title)

    def toggle_receive_qr(self):
        b = not self.config.GUI_QT_RECEIVE_TAB_QR_VISIBLE
        self.config.GUI_QT_RECEIVE_TAB_QR_VISIBLE = b
        self.update_receive_widgets()

    def update_receive_widgets(self):
        b = self.config.GUI_QT_RECEIVE_TAB_QR_VISIBLE
        self.receive_widget.update_visibility(b)

    def update_current_request(self):
        key = self.request_list.get_current_key()
        req = self.wallet.get_request(key) if key else None
        if req is None:
            self.receive_e.setText('')
            self.addr = self.URI = self.lnaddr = ''
            self.address_help = self.URI_help = self.ln_help = ''
            return
        help_texts = self.wallet.get_help_texts_for_receive_request(req)
        self.addr = (req.get_address() or '') if not help_texts.address_is_error else ''
        self.URI = (self.wallet.get_request_URI(req) or '') if not help_texts.URI_is_error else ''
        self.lnaddr = self.wallet.get_bolt11_invoice(req) if not help_texts.ln_is_error else ''
        self.address_help = help_texts.address_help
        self.URI_help = help_texts.URI_help
        self.ln_help = help_texts.ln_help
        can_rebalance = help_texts.can_rebalance()
        can_swap = help_texts.can_swap()
        self.receive_rebalance_button.suggestion = help_texts.ln_rebalance_suggestion
        self.receive_swap_button.suggestion = help_texts.ln_swap_suggestion
        self.receive_rebalance_button.setVisible(can_rebalance)
        self.receive_swap_button.setVisible(can_swap)
        self.receive_rebalance_button.setEnabled(can_rebalance and self.window.num_tasks() == 0)
        self.receive_swap_button.setEnabled(can_swap and self.window.num_tasks() == 0)
        text, data, help_text, title = self.get_tab_data()
        self.receive_e.setText(text)
        self.receive_qr.setData(data)
        self.receive_help_text.setText(help_text)
        for w in [self.receive_e, self.receive_qr]:
            w.setEnabled(bool(text) and not help_text)
            w.setToolTip(help_text)
        # macOS hack (similar to #4777)
        self.receive_e.repaint()
        # always show
        self.receive_widget.setVisible(True)
        self.toggle_qr_button.setEnabled(True)
        self.toggle_view_button.setEnabled(True)
        self.update_receive_qr_window()

    def get_tab_data(self):
        i = self.config.GUI_QT_RECEIVE_TABS_INDEX
        if i == 0:
            out = self.URI, self.URI, self.URI_help, _('Bitcoin URI')
        elif i == 1:
            out = self.addr, self.addr, self.address_help, _('Address')
        elif i == 2:
            # encode lightning invoices as uppercase so QR encoding can use
            # alphanumeric mode; resulting in smaller QR codes
            out = self.lnaddr, self.lnaddr.upper(), self.ln_help, _('Lightning Request')
        return out

    def update_receive_qr_window(self):
        if self.window.qr_window and self.window.qr_window.isVisible():
            text, data, help_text, title = self.get_tab_data()
            self.window.qr_window.qrw.setData(data)

    def create_invoice(self):
        amount_sat = self.receive_amount_e.get_amount()
        message = self.receive_message_e.text()
        expiry = self.config.WALLET_PAYREQ_EXPIRY_SECONDS

        if amount_sat and amount_sat < self.wallet.dust_threshold():
            address = None
            if not self.wallet.has_lightning():
                self.show_error(_('Amount too small to be received onchain'))
                return
        else:
            address = self.get_bitcoin_address_for_request(amount_sat)
            if not address:
                return
            self.window.address_list.update()

        # generate even if we cannot receive
        try:
            key = self.wallet.create_request(amount_sat, message, expiry, address)
        except InvoiceError as e:
            self.show_error(_('Error creating payment request') + ':\n' + str(e))
            return
        except Exception as e:
            self.logger.exception('Error adding payment request')
            self.show_error(_('Error adding payment request') + ':\n' + repr(e))
            return
        assert key is not None
        self.window.address_list.refresh_all()
        self.request_list.update()
        self.request_list.set_current_key(key)
        # clear request fields
        self.receive_amount_e.setText('')
        self.receive_message_e.setText('')
        # copy current tab to clipboard
        self.on_tab_changed()

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
        self.receive_e.setText('')
        self.addr = self.URI = self.lnaddr = ''
        self.address_help = self.URI_help = self.ln_help = ''
        self.receive_widget.setVisible(False)
        self.toggle_qr_button.setEnabled(False)
        self.toggle_view_button.setEnabled(False)
        self.receive_message_e.setText('')
        self.receive_amount_e.setAmount(None)
        self.request_list.clearSelection()


class ReceiveWidget(QWidget):
    min_size = QSize(200, 200)

    def __init__(self, receive_tab: 'ReceiveTab', textedit: QWidget, qr: QWidget, help_widget: QWidget):
        QWidget.__init__(self)
        self.textedit = textedit
        self.qr = qr
        self.help_widget = help_widget
        self.setMinimumSize(self.min_size)

        for w in [textedit, qr]:
            w.mousePressEvent = receive_tab.do_copy
            w.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))

        textedit.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        if isinstance(help_widget, QLabel):
            help_widget.setFrameStyle(QFrame.Shape.StyledPanel)
            help_widget.setStyleSheet("QLabel {border:1px solid gray; border-radius:2px; }")

        hbox = QHBoxLayout()
        hbox.addStretch()
        hbox.addWidget(textedit)
        hbox.addWidget(help_widget)
        hbox.addWidget(qr)

        vbox = QVBoxLayout()
        vbox.addLayout(hbox)
        vbox.addStretch()

        self.setLayout(vbox)

    def update_visibility(self, is_qr):
        if str(self.textedit.toPlainText()):
            self.help_widget.setVisible(False)
            self.textedit.setVisible(not is_qr)
            self.qr.setVisible(is_qr)
        else:
            self.help_widget.setVisible(True)
            self.textedit.setVisible(False)
            self.qr.setVisible(False)

    def resizeEvent(self, e):
        # keep square aspect ratio when resized
        size = e.size()
        margin = 10
        x = min(size.height(), size.width()) - margin
        for w in [self.textedit, self.qr, self.help_widget]:
            w.setFixedWidth(x)
            w.setFixedHeight(x)
        return super().resizeEvent(e)


class FramedWidget(QFrame):
    def __init__(self):
        QFrame.__init__(self)
        self.setFrameStyle(QFrame.Shape.StyledPanel)
        self.setStyleSheet("FramedWidget {border:1px solid gray; border-radius:2px; }")
