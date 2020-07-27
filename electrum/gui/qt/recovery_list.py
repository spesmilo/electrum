from enum import IntEnum
from datetime import datetime, timedelta
from functools import partial
from hashlib import sha256
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes


from PyQt5.QtCore import Qt, QItemSelectionModel
from PyQt5.QtGui import QStandardItemModel, QStandardItem, QMouseEvent, QFocusEvent
from PyQt5.QtWidgets import QPushButton, QLabel, QLineEdit, QWidget,\
    QCompleter, QAbstractItemView, QStyledItemDelegate,\
    QVBoxLayout, QGridLayout

from electrum.i18n import _
from electrum.logging import get_logger
from electrum.wallet import Abstract_Wallet
from electrum.util import get_request_status, PR_TYPE_ONCHAIN, PR_TYPE_LN

from .util import MyTreeView, read_QIcon, pr_icons, WaitingDialog
from .confirm_tx_dialog import ConfirmTxDialog
from .completion_text_edit import CompletionTextEdit
from ...mnemonic import load_wordlist
from ...plugin import run_hook
from ...transaction import PartialTransaction
from ...util import PR_UNPAID, PR_UNKNOWN

_logger = get_logger(__name__)

ROLE_REQUEST_TYPE = Qt.UserRole
ROLE_REQUEST_ID = Qt.UserRole + 1


class RecoveryColumns(IntEnum):
    DATE = 0
    DESCRIPTION = 1
    AMOUNT = 2


class RecoveryView(MyTreeView):

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
        super().__init__(parent, self.create_menu,
                         stretch_column=self.Columns.DESCRIPTION,
                         editable_columns=[])

        self.required_confirmations = 144

        self.parent = parent
        self.setSortingEnabled(True)
        self.setModel(QStandardItemModel(self))
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        now = datetime.now()
        self.to_timestamp = datetime.timestamp(now)
        self.from_timestamp = datetime.timestamp(now + timedelta(days=-2))
        self.update_data()

    def create_menu(self, position):
        pass

    def focusInEvent(self, event: QFocusEvent):
        super().focusInEvent(event)
        self.update_data()

    def focusOutEvent(self, event: QFocusEvent):
        super().focusOutEvent(event)
        self.update_data()

    def mouseDoubleClickEvent(self, event: QMouseEvent):
        super().mouseDoubleClickEvent(event)
        self.update_data()

    def update_data(self):
        self.model().clear()
        self.update_headers(self.__class__.headers)

        for index, txid in enumerate(self.parent.wallet.get_atxs_to_recovery()):
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

            txinfo = self.parent.wallet.get_tx_info(txid)
            if txinfo.tx_mined_status.txtype == 'ALERT_PENDING':
                status, status_str = get_request_status({'status': PR_UNPAID})
            else:
                status, status_str = get_request_status({'status': PR_UNKNOWN})

            status_str = '{} {}/{}'.format(status_str, txinfo.tx_mined_status.conf, self.required_confirmations)
            num_status, date_str = self.parent.wallet.get_tx_status(txid.txid(), txinfo.tx_mined_status)
            amount_str = self.parent.format_amount(txinfo.amount - txinfo.fee, whitespaces=True)
            labels = [date_str, txinfo.label, amount_str, status_str]

            items = [QStandardItem(e) for e in labels]
            self.set_editability(items)
            items[self.Columns.DATE].setIcon(read_QIcon(icon_name))
            items[self.Columns.STATUS].setIcon(read_QIcon(pr_icons.get(status)))
            items[self.Columns.DATE].setData(invoice_type, role=ROLE_REQUEST_TYPE)
            items[self.Columns.DATE].setData(txid, role=ROLE_REQUEST_ID)
            self.model().insertRow(index, items)

        self.selectionModel().select(self.model().index(0, 0), QItemSelectionModel.SelectCurrent)
        # sort requests by date
        self.model().sort(self.Columns.DATE)


class RecoveryTab(QWidget):
    def __init__(self, parent, wallet: Abstract_Wallet, config):
        self.electrum_main_window = parent
        self.config = config
        self.wallet = wallet
        QWidget.__init__(self)

        self.invoice_list = RecoveryView(self.electrum_main_window)

        self.main_layout = QVBoxLayout()

        label = QLabel(_('Alert transaction to recovery'))
        self.main_layout.addWidget(label)

        self.main_layout.addWidget(self.invoice_list)

        grid_layout = QGridLayout()
        # Row 1
        grid_layout.addWidget(QLabel(_('Recovery address')), 0, 0)
        self.recovery_address_line = QLineEdit()
        addr_list = self.wallet.get_receiving_addresses()
        self.recovery_address_line.setText(addr_list[0])
        grid_layout.addWidget(self.recovery_address_line, 0, 1)
        # Row 2
        grid_layout.addWidget(QLabel(_('Private key Phrase')), 1, 0)

        # wordlist
        self.wordlist = load_wordlist("english.txt")
        ###

        # complete line edit with suggestions
        class CompleterDelegate(QStyledItemDelegate):
            def initStyleOption(self, option, index):
                super().initStyleOption(option, index)

        self.recovery_privkey_line = CompletionTextEdit()
        self.recovery_privkey_line.setTabChangesFocus(False)
        self.recovery_privkey_line.textChanged.connect(self.on_priv_key_line_edit)

        delegate = CompleterDelegate(self.recovery_privkey_line)
        self.completer = QCompleter(self.wordlist)
        self.completer.popup().setItemDelegate(delegate)
        self.recovery_privkey_line.set_completer(self.completer)
        # size hint other
        height = self.recovery_address_line.sizeHint().height()
        self.recovery_privkey_line.setMaximumHeight(height)
        ###

        grid_layout.addWidget(self.recovery_privkey_line, 1, 1)
        # Row 3
        button = QPushButton(_('Recover'))
        button.clicked.connect(self.recover_action)
        # if line edit with suggestions size change 3rd argument needs to be adjusted
        grid_layout.addWidget(button, 2, 0, 1, 3)
        ###

        self.main_layout.addLayout(grid_layout)
        self.setLayout(self.main_layout)

    def on_priv_key_line_edit(self):
        for word in self.get_seed()[:-1]:
            if word not in self.wordlist:
                self.recovery_privkey_line.disable_suggestions()
                return
        self.recovery_privkey_line.enable_suggestions()

    def get_seed(self):
        text = self.recovery_privkey_line.text()
        return text.split()

    @staticmethod
    def generate_encryption_key(salt: bytes, password: bytes) -> [bytes, int]:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password)
        return key

    def _get_recovery_keypair(self):
        recovery_pubkey = self.wallet.storage.get('recovery_pubkey')

        seed = self.get_seed()
        index_cache = [self.wordlist.index(word) for word in seed]

        payload = 0
        for i, b in enumerate(reversed(index_cache)):
            payload = payload | (b << (i * 11))

        payload = payload.to_bytes(17, 'big')
        checksum = payload[:1]
        entropy = payload[1:]

        sha256sum = sha256(entropy).digest()
        if sha256sum.hex()[0] != checksum.hex()[1]:
            raise ValueError(_('Checksum miss matched'))

        private_key = self.generate_encryption_key(entropy, entropy)

        return {recovery_pubkey: (private_key, True)}

    def _get_checked_atxs(self):
        return [row.data(ROLE_REQUEST_ID) for row in self.invoice_list.selectedIndexes() if row.data(ROLE_REQUEST_ID)]

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
            self.preview_tx_dialog(make_tx, outputs, external_keypairs=external_keypairs, invoice=invoice)
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
            self.preview_tx_dialog(make_tx, outputs, external_keypairs=external_keypairs, invoice=invoice)

    def sign_tx_with_password(self, tx: PartialTransaction, callback, password, external_keypairs=None):
        def on_success(result):
            callback(True)

        def on_failure(exc_info):
            self.electrum_main_window.on_error(exc_info)
            callback(False)

        on_success = run_hook('tc_sign_wrapper', self.wallet, tx, on_success, on_failure) or on_success

        if external_keypairs and self.wallet.multisig_script_generator.is_recovery_mode():
            task = partial(self.wallet.sign_recovery_transaction, tx, password, external_keypairs)
        else:
            task = partial(self.wallet.sign_transaction, tx, password)
        msg = _('Signing transaction...')
        WaitingDialog(self, msg, task, on_success, on_failure)

    def recover_action(self):
        try:
            address = self.recovery_address_line.text()
            recovery_keypair = self._get_recovery_keypair()
            atxs = self._get_checked_atxs()

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
