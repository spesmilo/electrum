from enum import IntEnum
from datetime import datetime, timedelta
from functools import partial
import re

from typing import Union, List, Dict

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QStandardItemModel, QStandardItem, QMouseEvent, QValidator, QKeySequence
from PyQt5.QtWidgets import QPushButton, QLabel, QWidget, QComboBox,\
    QTreeView, QHeaderView, QStyledItemDelegate,\
    QVBoxLayout, QGridLayout,\
    QCompleter, QShortcut

from electrum.i18n import _
from electrum.logging import get_logger
from electrum.wallet import Abstract_Wallet
from electrum.util import get_request_status, PR_TYPE_ONCHAIN, PR_TYPE_LN
from electrum import bitcoin

from .util import read_QIcon, pr_icons, WaitingDialog, filter_non_printable, ColorScheme
from .confirm_tx_dialog import ConfirmTxDialog
from .completion_text_edit import CompletionTextEdit
from ...mnemonic import load_wordlist
from ...plugin import run_hook
from ...transaction import PartialTransaction
from ...util import PR_UNPAID, PR_UNKNOWN
from ...three_keys import short_mnemonic

_logger = get_logger(__name__)

ROLE_REQUEST_TYPE = Qt.UserRole
ROLE_REQUEST_ID = Qt.UserRole + 1


class RecoveryView(QTreeView):

    class Columns(IntEnum):
        DATE = 0
        DESCRIPTION = 1
        AMOUNT = 2
        STATUS = 3

    headers = {
        Columns.DATE: _('Date'),
        Columns.DESCRIPTION: _('Description'),
        Columns.AMOUNT: _('Amount'),
        Columns.STATUS: _('Status'),
    }
    filter_columns = [Columns.DATE, Columns.DESCRIPTION, Columns.AMOUNT]

    def __init__(self, parent):
        super().__init__(parent)

        self.wallet = parent.wallet
        self.main_window = parent

        self.required_confirmations = 144
        self.stretch_column = self.Columns.DESCRIPTION

        self.setSortingEnabled(True)
        self.setAlternatingRowColors(True)
        self.setModel(QStandardItemModel(self))
        self.setSelectionMode(QTreeView.NoSelection)

        shortcut = QShortcut(QKeySequence(QKeySequence.SelectAll), self, self.onSelectAll)
        self.selected_all = False

        now = datetime.now()
        self.to_timestamp = datetime.timestamp(now)
        self.from_timestamp = datetime.timestamp(now + timedelta(days=-2))

        self.update_data()

    def mouseDoubleClickEvent(self, event: QMouseEvent):
        super().mouseDoubleClickEvent(event)
        self.update_data()

    def onSelectAll(self):
        model = self.model()
        state = Qt.Checked
        if self.selected_all:
            self.selected_all = False
            state = Qt.Unchecked
        else:
            self.selected_all = True

        for i in range(model.rowCount()):
            m_index = model.index(i, 0)
            item = model.itemFromIndex(m_index)
            item.setCheckState(state)

    def update_data(self):
        self.model().clear()
        self.update_headers(self.__class__.headers)

        for index, txid in enumerate(self.wallet.get_atxs_to_recovery()):
            invoice_type = PR_TYPE_ONCHAIN
            if invoice_type == PR_TYPE_LN:
                #key = item['rhash']
                icon_name = 'lightning.png'
            elif invoice_type == PR_TYPE_ONCHAIN:
                icon_name = 'bitcoin.png'
                #if item.get('bip70'):
                #   icon_name = 'seal.png'
            else:
                raise Exception('Unsupported type')

            txinfo = self.wallet.get_tx_info(txid)
            if txinfo.tx_mined_status.txtype == 'ALERT_PENDING':
                status, status_str = get_request_status({'status': PR_UNPAID})
            else:
                status, status_str = get_request_status({'status': PR_UNKNOWN})

            status_str = '{} {}/{}'.format(status_str, txinfo.tx_mined_status.conf, self.required_confirmations)
            num_status, date_str = self.wallet.get_tx_status(txid.txid(), txinfo.tx_mined_status)
            amount_str = self.main_window.format_amount(txinfo.amount - txinfo.fee, whitespaces=True)
            labels = [date_str, txinfo.label, amount_str, status_str]

            def set_editable(item: QStandardItem) -> QStandardItem:
                item.setEditable(False)
                return item

            items = [set_editable(QStandardItem(e)) for e in labels]
            items[self.Columns.DATE].setIcon(read_QIcon(icon_name))
            items[self.Columns.STATUS].setIcon(read_QIcon(pr_icons.get(status)))
            items[self.Columns.DATE].setData(invoice_type, role=ROLE_REQUEST_TYPE)
            items[self.Columns.DATE].setData(txid, role=ROLE_REQUEST_ID)
            items[self.Columns.DATE].setCheckable(True)

            self.model().insertRow(index, items)

        # sort requests by date
        self.model().sort(self.Columns.DATE)

    def update_headers(self, headers: Union[List[str], Dict[int, str]]):
        # headers is either a list of column names, or a dict: (col_idx->col_name)
        if not isinstance(headers, dict):  # convert to dict
            headers = dict(enumerate(headers))
        col_names = [headers[col_idx] for col_idx in sorted(headers.keys())]
        self.model().setHorizontalHeaderLabels(col_names)
        self.header().setStretchLastSection(False)
        for col_idx in headers:
            sm = QHeaderView.Stretch if col_idx == self.stretch_column else QHeaderView.ResizeToContents
            self.header().setSectionResizeMode(col_idx, sm)

    def selected(self):
        out = []
        model = self.model()
        for i in range(model.rowCount()):
            m_index = model.index(i, 0)
            item = model.itemFromIndex(m_index)
            if item.checkState() == Qt.Checked:
                out.append(item.data())
        return out


def is_address_valid(address):
    tmp = re.match('([0-9A-Za-z]{1,})', address)
    if not tmp or tmp.group() != address:
        return False
    else:
        if not bitcoin.is_address(address):
            return False
    return True


class RecoveryTab(QWidget):
    def __init__(self, parent, wallet: Abstract_Wallet, config):
        self.electrum_main_window = parent
        self.config = config
        self.wallet = wallet
        QWidget.__init__(self)

        self.invoice_list = RecoveryView(self.electrum_main_window)

        # wordlist
        self.wordlist = load_wordlist("english.txt")
        ###

    def _create_recovery_address(self):
        class Validator(QValidator):
            ADDRESS_LENGTH = 35

            def validate(self, input: str, index: int):
                input = filter_non_printable(input)
                i_len = len(input)
                state = QValidator.Acceptable

                if i_len < self.ADDRESS_LENGTH:
                    state = QValidator.Intermediate
                else:
                    if not is_address_valid(input):
                        state = QValidator.Invalid

                return state, input, index

        addr_list = self.wallet.get_receiving_addresses()

        obj = QComboBox(self)
        obj.setDuplicatesEnabled(False)
        obj.setEditable(True)
        obj.setInsertPolicy(QComboBox.InsertAtTop)

        for addr in addr_list:
            obj.addItem(addr)

        # must be after item add
        obj.setValidator(Validator(obj))
        obj.editTextChanged.connect(self.onEditTextChanged)

        return obj

    def onEditTextChanged(self, input: str):
        if not is_address_valid(input):
            self.recovery_address_line.setStyleSheet(ColorScheme.RED.as_stylesheet(True))
        else:
            self.recovery_address_line.setStyleSheet(ColorScheme.DEFAULT.as_stylesheet(True))

    def on_priv_key_line_edit(self):
        for word in self.get_recovery_seed()[:-1]:
            if word not in self.wordlist:
                self.recovery_privkey_line.disable_suggestions()
                return
        self.recovery_privkey_line.enable_suggestions()

    def get_recovery_seed(self):
        text = self.recovery_privkey_line.text()
        return text.split()

    def _get_recovery_keypair(self):
        stored_recovery_pubkey = self.wallet.storage.get('recovery_pubkey')
        seed = self.get_recovery_seed()
        if not short_mnemonic.is_valid(seed):
            raise ValueError(_("Invalid recovery TX seed"))
        privkey, pubkey = short_mnemonic.seed_to_keypair(seed)
        if pubkey != stored_recovery_pubkey:
            raise Exception(_("Recovery TX seed not matching any key in this wallet"))
        return {pubkey: (privkey, True)}

    def recovery_onchain_dialog(self, inputs, outputs, recovery_keypairs):
        """Code copied from pay_onchain_dialog"""
        external_keypairs = None
        invoice = None
        # trusted coin requires this
        if run_hook('abort_send', self):
            return
        is_sweep = bool(external_keypairs)
        make_tx = lambda fee_est: self.wallet.make_unsigned_transaction(
            coins=inputs,
            outputs=outputs,
            fee=fee_est,
            is_sweep=is_sweep)
        if self.config.get('advanced_preview'):
            self.electrum_main_window.preview_tx_dialog(make_tx, outputs, external_keypairs=external_keypairs, invoice=invoice)
            return

        output_values = [x.value for x in outputs]
        output_value = '!' if '!' in output_values else sum(output_values)
        d = ConfirmTxDialog(self.electrum_main_window, make_tx, output_value, is_sweep)
        d.update_tx()
        if d.not_enough_funds:
            self.electrum_main_window.show_message(_('Not Enough Funds'))
            return
        cancelled, is_send, password, tx = d.run()
        if cancelled:
            return
        if is_send:
            def sign_done(success):
                if success:
                    self.electrum_main_window.broadcast_or_show(tx, invoice=invoice)
            self.sign_tx_with_password(tx, sign_done, password, recovery_keypairs)
        else:
            self.electrum_main_window.preview_tx_dialog(make_tx, outputs, external_keypairs=external_keypairs, invoice=invoice)

    def sign_tx_with_password(self, tx: PartialTransaction, callback, password, external_keypairs=None):
        def on_success(result):
            callback(True)

        def on_failure(exc_info):
            self.electrum_main_window.on_error(exc_info)
            callback(False)

        on_success = run_hook('tc_sign_wrapper', self.wallet, tx, on_success, on_failure) or on_success

        if external_keypairs and self.wallet.is_recovery_mode():
            task = partial(self.wallet.sign_recovery_transaction, tx, password, external_keypairs)
        else:
            task = partial(self.wallet.sign_transaction, tx, password, external_keypairs)
        msg = _('Signing transaction...')
        WaitingDialog(self, msg, task, on_success, on_failure)

    def recover_action(self):
        try:
            atxs = self.invoice_list.selected()
            address = self.recovery_address_line.currentText()
            recovery_keypair = self._get_recovery_keypair()

            if not is_address_valid(address):
                raise Exception(_('Invalid recovery address'))

            inputs, output = self.wallet.get_inputs_and_output_for_recovery(atxs, address)
            inputs = self.wallet.prepare_inputs_for_recovery(inputs)
        except Exception as e:
            self.electrum_main_window.on_error([0, e])
            return

        self.wallet.set_recovery()
        self.recovery_onchain_dialog(
            inputs=inputs,
            outputs=[output],
            recovery_keypairs=recovery_keypair,
        )

        self.recovery_privkey_line.setText('')

    def _create_privkey_line(self):
        class CompleterDelegate(QStyledItemDelegate):
            def initStyleOption(self, option, index):
                super().initStyleOption(option, index)

        recovery_privkey_line = CompletionTextEdit()
        recovery_privkey_line.setTabChangesFocus(False)
        recovery_privkey_line.textChanged.connect(self.on_priv_key_line_edit)

        delegate = CompleterDelegate(recovery_privkey_line)
        completer = QCompleter(self.wordlist)
        completer.popup().setItemDelegate(delegate)
        recovery_privkey_line.set_completer(completer)
        # size hint other
        height = self.recovery_address_line.sizeHint().height()
        recovery_privkey_line.setMaximumHeight(height)
        return recovery_privkey_line


class RecoveryTabARStandalone(RecoveryTab):

    def __init__(self, parent, wallet: Abstract_Wallet, config):
        super().__init__(parent, wallet, config)
        self.main_layout = QVBoxLayout()
        label = QLabel(_('Alert transaction to recover'))
        self.main_layout.addWidget(label)
        self.main_layout.addWidget(self.invoice_list)

        grid_layout = QGridLayout()
        # Row 1
        grid_layout.addWidget(QLabel(_('Recovery address')), 0, 0)
        self.recovery_address_line = self._create_recovery_address()
        grid_layout.addWidget(self.recovery_address_line, 0, 1)
        # Row 2
        grid_layout.addWidget(QLabel(_('Recovery tx seed')), 1, 0)

        # complete line edit with suggestions
        self.recovery_privkey_line = self._create_privkey_line()
        grid_layout.addWidget(self.recovery_privkey_line, 1, 1)
        # Row 3
        button = QPushButton(_('Recover'))
        button.clicked.connect(self.recover_action)
        # if line edit with suggestions size change 3rd argument needs to be adjusted
        grid_layout.addWidget(button, 2, 0, 1, 3)
        ###

        self.main_layout.addLayout(grid_layout)
        self.setLayout(self.main_layout)


class RecoveryTabAIRStandalone(RecoveryTab):

    def __init__(self, parent, wallet: Abstract_Wallet, config):
        super().__init__(parent, wallet, config)
        self.main_layout = QVBoxLayout()
        label = QLabel(_('Alert transaction to recover'))
        self.main_layout.addWidget(label)
        self.main_layout.addWidget(self.invoice_list)

        grid_layout = QGridLayout()
        # Row 1
        grid_layout.addWidget(QLabel(_('Recovery address')), 0, 0)
        self.recovery_address_line = self._create_recovery_address()
        grid_layout.addWidget(self.recovery_address_line, 0, 1)

        # Row 2
        grid_layout.addWidget(QLabel(_('Instant tx seed')), 1, 0)
        # complete line edit with suggestions
        self.instant_privkey_line = self._create_privkey_line()
        grid_layout.addWidget(self.instant_privkey_line, 1, 1)

        # Row 3
        grid_layout.addWidget(QLabel(_('Recovery tx seed')), 2, 0)
        # complete line edit with suggestions
        self.recovery_privkey_line = self._create_privkey_line()
        grid_layout.addWidget(self.recovery_privkey_line, 2, 1)

        # Row 4
        button = QPushButton(_('Recover'))
        button.clicked.connect(self.recover_action)
        # if line edit with suggestions size change 3rd argument needs to be adjusted
        grid_layout.addWidget(button, 3, 0, 1, 3)
        ###

        self.main_layout.addLayout(grid_layout)
        self.setLayout(self.main_layout)

    def get_instant_seed(self):
        text = self.instant_privkey_line.text()
        return text.split()

    def _get_instant_keypair(self):
        stored_instant_pubkey = self.wallet.storage.get('instant_pubkey')
        seed = self.get_instant_seed()
        if not short_mnemonic.is_valid(seed):
            raise ValueError(_("Invalid instant TX seed"))
        privkey, pubkey = short_mnemonic.seed_to_keypair(seed)
        if pubkey != stored_instant_pubkey:
            raise Exception(_("Instant TX seed not matching any key in this wallet"))
        return {pubkey: (privkey, True)}

    def recover_action(self):
        try:
            address = self.recovery_address_line.currentText()
            instant_keypair = self._get_instant_keypair()
            recovery_keypair = self._get_recovery_keypair()
            atxs = self.invoice_list.selected()

            if not is_address_valid(address):
                raise Exception(_('Invalid recovery address'))

            inputs, output = self.wallet.get_inputs_and_output_for_recovery(atxs, address)
            inputs = self.wallet.prepare_inputs_for_recovery(inputs)
        except Exception as e:
            self.electrum_main_window.on_error([0, e])
            return

        self.wallet.set_recovery()
        recovery_keypair.update(instant_keypair)
        self.recovery_onchain_dialog(
            inputs=inputs,
            outputs=[output],
            recovery_keypairs=recovery_keypair,
        )
        self.instant_privkey_line.setText('')
        self.recovery_privkey_line.setText('')
