import enum

from PyQt5.QtCore import Qt, QRect
from PyQt5.QtGui import QStandardItem
from PyQt5.QtWidgets import QVBoxLayout, QLabel, QWidget, QHBoxLayout, QHeaderView, QStyleOptionButton, QStyle, \
    QGridLayout, QCompleter, QComboBox, \
    QStyledItemDelegate

from electrum.i18n import _
from .amountedit import BTCAmountEdit, MyLineEdit, AmountEdit
from .completion_text_edit import CompletionTextEdit
from .main_window import ElectrumWindow
from .recovery_list import RecoveryTabARStandalone, RecoveryTabAIRStandalone
from .util import read_QIcon, HelpLabel, EnterButton
from ...mnemonic import load_wordlist
from ...plugin import run_hook
from ...three_keys import short_mnemonic


class CheckableHeader(QHeaderView):
    def __init__(self, orientation, parent=None):
        super().__init__(orientation, parent)
        self.parent = parent
        self.is_on = False

    def paintSection(self, painter: 'QPainter', rect: 'QRect', logical_index: int):
        painter.save()
        super().paintSection(painter, rect, logical_index)
        painter.restore()

        # assure set only in first column
        if logical_index == 0:
            option = QStyleOptionButton()
            option.rect = QRect(
                23, 3,
                14, 14
            )
            if self.is_on:
                option.state = QStyle.State_On
            else:
                option.state = QStyle.State_Off
            self.style().drawPrimitive(QStyle.PE_IndicatorCheckBox, option, painter)

    def mousePressEvent(self, event):
        if self.is_on:
            self.is_on = False
        else:
            self.is_on = True
        super().updateSection(0)
        super().mousePressEvent(event)


class TableItem(QStandardItem):
    def __init__(self, text, if_checkable=False):
        super().__init__(text)
        self.setCheckable(if_checkable)
        self.setTextAlignment(Qt.AlignRight)


class ElectrumMultikeyWalletWindow(ElectrumWindow):
    LABELS = ['Date', 'Confirmation', 'Balance']

    def __init__(self, gui_object: 'ElectrumGui', wallet: 'Abstract_Wallet'):
        super().__init__(gui_object=gui_object, wallet=wallet)
        self.alert_transactions = []
        self.recovery_tab = self.create_recovery_tab(wallet, self.config)
        # todo add proper icon
        self.tabs.addTab(self.recovery_tab, read_QIcon('recovery.png'), _('Recovery'))

    def create_recovery_tab(self, wallet: 'Abstract_Wallet', config):
        raise NotImplementedError()

    def sweep_key_dialog(self):
        self.wallet.set_alert()
        super().sweep_key_dialog()

    def show_recovery_tab(self):
        self.tabs.setCurrentIndex(self.tabs.indexOf(self.recovery_tab))


class ElectrumARWindow(ElectrumMultikeyWalletWindow):

    def __init__(self, gui_object: 'ElectrumGui', wallet: 'Abstract_Wallet'):
        super().__init__(gui_object=gui_object, wallet=wallet)

    def create_recovery_tab(self, wallet: 'Abstract_Wallet', config):
        return RecoveryTabARStandalone(self, wallet, config)

    def do_pay(self):
        invoice = self.read_invoice()
        if not invoice:
            return
        self.wallet.save_invoice(invoice)
        self.invoice_list.update()
        self.do_clear()
        self.wallet.set_alert()
        self.do_pay_invoice(invoice)


class ElectrumAIRWindow(ElectrumMultikeyWalletWindow):
    class TX_TYPES(enum.IntEnum):
        alert = 0
        instant = 1

    def __init__(self, gui_object: 'ElectrumGui', wallet: 'Abstract_Wallet'):
        self.wordlist = load_wordlist("english.txt")
        super().__init__(gui_object=gui_object, wallet=wallet)

    def create_recovery_tab(self, wallet: 'Abstract_Wallet', config):
        return RecoveryTabAIRStandalone(self, wallet, config)

    def create_send_tab(self):
        # A 4-column grid layout.  All the stretch is in the last column.
        # The exchange rate plugin adds a fiat widget in column 2
        self.send_grid = grid = QGridLayout()
        grid.setSpacing(8)
        grid.setColumnStretch(3, 1)

        from .paytoedit import PayToEdit
        self.amount_e = BTCAmountEdit(self.get_decimal_point)
        self.payto_e = PayToEdit(self)
        msg = _('Recipient of the funds.') + '\n\n' \
              + _(
            'You may enter a Bitcoin address, a label from your list of contacts (a list of completions will be proposed), or an alias (email-like address that forwards to a Bitcoin address)')
        payto_label = HelpLabel(_('Pay to'), msg)
        grid.addWidget(payto_label, 1, 0)
        grid.addWidget(self.payto_e, 1, 1, 1, -1)

        completer = QCompleter()
        completer.setCaseSensitivity(False)
        self.payto_e.set_completer(completer)
        completer.setModel(self.completions)

        msg = _('Description of the transaction (not mandatory).') + '\n\n' \
              + _(
            'The description is not sent to the recipient of the funds. It is stored in your wallet file, and displayed in the \'History\' tab.')
        description_label = HelpLabel(_('Description'), msg)
        grid.addWidget(description_label, 2, 0)
        self.message_e = MyLineEdit()
        self.message_e.setMinimumWidth(700)
        grid.addWidget(self.message_e, 2, 1, 1, -1)

        msg = _('Amount to be sent.') + '\n\n' \
              + _('The amount will be displayed in red if you do not have enough funds in your wallet.') + ' ' \
              + _(
            'Note that if you have frozen some of your addresses, the available funds will be lower than your total balance.') + '\n\n' \
              + _('Keyboard shortcut: type "!" to send all your coins.')
        amount_label = HelpLabel(_('Amount'), msg)
        grid.addWidget(amount_label, 3, 0)
        grid.addWidget(self.amount_e, 3, 1)

        self.fiat_send_e = AmountEdit(self.fx.get_currency if self.fx else '')
        if not self.fx or not self.fx.is_enabled():
            self.fiat_send_e.setVisible(False)
        grid.addWidget(self.fiat_send_e, 3, 2)
        self.amount_e.frozen.connect(
            lambda: self.fiat_send_e.setFrozen(self.amount_e.isReadOnly()))

        self.max_button = EnterButton(_("Max"), self.spend_max)
        self.max_button.setFixedWidth(100)
        self.max_button.setCheckable(True)
        grid.addWidget(self.max_button, 3, 3)

        def on_tx_type(index):
            if self.tx_type_combo.currentIndex() == self.TX_TYPES['alert']:
                self.instant_privkey_line.setEnabled(False)
                self.instant_privkey_line.clear()
            elif self.tx_type_combo.currentIndex() == self.TX_TYPES['instant']:
                self.instant_privkey_line.setEnabled(True)

        msg = _('Choose transaction type.') + '\n\n' + \
              _('Alert - confirmed after 24h, reversible.') + '\n' + \
              _('Instant - confirmed immediately, non-reversible. Needs an additional signature.')
        tx_type_label = HelpLabel(_('Transaction type'), msg)
        self.tx_type_combo = QComboBox()
        self.tx_type_combo.addItems([_(tx_type.name) for tx_type in self.TX_TYPES])
        self.tx_type_combo.setCurrentIndex(self.TX_TYPES['alert'])
        self.tx_type_combo.currentIndexChanged.connect(on_tx_type)
        grid.addWidget(tx_type_label, 4, 0)
        grid.addWidget(self.tx_type_combo, 4, 1, 1, -1)

        instant_privkey_label = HelpLabel(_('Instant TX seed'), msg)
        self.instant_privkey_line = CompletionTextEdit()
        self.instant_privkey_line.setTabChangesFocus(False)
        self.instant_privkey_line.setEnabled(False)
        self.instant_privkey_line.textChanged.connect(self.on_instant_priv_key_line_edit)

        # complete line edit with suggestions
        class CompleterDelegate(QStyledItemDelegate):
            def initStyleOption(self, option, index):
                super().initStyleOption(option, index)

        delegate = CompleterDelegate(self.instant_privkey_line)
        self.completer = QCompleter(self.wordlist)
        self.completer.popup().setItemDelegate(delegate)
        self.instant_privkey_line.set_completer(self.completer)

        height = self.payto_e.height()
        self.instant_privkey_line.setMaximumHeight(2 * height)
        grid.addWidget(instant_privkey_label, 5, 0)
        grid.addWidget(self.instant_privkey_line, 5, 1, 1, -1)

        self.save_button = EnterButton(_("Save"), self.do_save_invoice)
        self.send_button = EnterButton(_("Pay"), self.do_pay)
        self.clear_button = EnterButton(_("Clear"), self.do_clear)

        buttons = QHBoxLayout()
        buttons.addStretch(1)
        buttons.addWidget(self.clear_button)
        buttons.addWidget(self.save_button)
        buttons.addWidget(self.send_button)
        grid.addLayout(buttons, 6, 1, 1, 4)

        self.amount_e.shortcut.connect(self.spend_max)

        def reset_max(text):
            self.max_button.setChecked(False)
            enable = not bool(text) and not self.amount_e.isReadOnly()
            # self.max_button.setEnabled(enable)

        self.amount_e.textEdited.connect(reset_max)
        self.fiat_send_e.textEdited.connect(reset_max)

        self.set_onchain(False)

        self.invoices_label = QLabel(_('Outgoing payments'))
        from .invoice_list import InvoiceList
        self.invoice_list = InvoiceList(self)

        vbox0 = QVBoxLayout()
        vbox0.addLayout(grid)
        hbox = QHBoxLayout()
        hbox.addLayout(vbox0)
        hbox.addStretch(1)
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

    def on_instant_priv_key_line_edit(self):
        for word in self.get_instant_seed()[:-1]:
            if word not in self.wordlist:
                self.instant_privkey_line.disable_suggestions()
                return
        self.instant_privkey_line.enable_suggestions()

    def get_instant_seed(self):
        text = self.instant_privkey_line.text()
        return text.split()

    def get_instant_keypair(self):
        stored_instant_pubkey = self.wallet.storage.get('instant_pubkey')
        seed = self.get_instant_seed()
        if not short_mnemonic.is_valid(seed):
            raise ValueError(_("Invalid instant TX seed"))
        privkey, pubkey = short_mnemonic.seed_to_keypair(seed)
        if pubkey != stored_instant_pubkey:
            raise Exception(_("Instant TX seed not matching any key in this wallet"))
        return {pubkey: (privkey, True)}

    def do_pay(self):
        invoice = self.read_invoice()
        if not invoice:
            return
        if self.tx_type_combo.currentIndex() == self.TX_TYPES['instant']:
            try:
                keypair = self.get_instant_keypair()
                self.wallet.set_instant()
            except Exception as e:
                self.on_error([0, str(e)])
                return
        else:
            keypair = None
            self.wallet.set_alert()
        self.wallet.save_invoice(invoice)
        self.invoice_list.update()
        self.do_clear()
        self.do_pay_invoice(invoice, external_keypairs=keypair)

    def do_clear(self):
        self.max_button.setChecked(False)
        self.payment_request = None
        self.payto_URI = None
        self.payto_e.is_pr = False
        self.is_onchain = False
        self.set_onchain(False)
        for e in [self.payto_e, self.message_e, self.amount_e]:
            e.setText('')
            e.setFrozen(False)
        self.instant_privkey_line.clear()
        self.tx_type_combo.setCurrentIndex(self.TX_TYPES['alert'])
        self.update_status()
        run_hook('do_clear', self)
