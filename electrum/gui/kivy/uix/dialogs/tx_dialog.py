import copy
from datetime import datetime
from typing import NamedTuple, Callable, TYPE_CHECKING
from functools import partial

from kivy.app import App
from kivy.factory import Factory
from kivy.properties import ObjectProperty
from kivy.lang import Builder
from kivy.clock import Clock
from kivy.uix.label import Label
from kivy.uix.dropdown import DropDown
from kivy.uix.button import Button

from electrum.util import InvalidPassword
from electrum.address_synchronizer import TX_HEIGHT_LOCAL
from electrum.wallet import CannotBumpFee, CannotCPFP, CannotDoubleSpendTx
from electrum.transaction import Transaction, PartialTransaction
from electrum.network import NetworkException

from electrum.gui.kivy.i18n import _
from electrum.gui.kivy.util import address_colors
from ..actiondropdown import ActionDropdown, ActionButtonOption
from .question import Question

if TYPE_CHECKING:
    from ...main_window import ElectrumWindow


Builder.load_string('''
#:import KIVY_GUI_PATH electrum.gui.kivy.KIVY_GUI_PATH

<TxDialog>
    id: popup
    title: _('Transaction')
    is_mine: True
    can_sign: False
    can_broadcast: False
    can_rbf: False
    can_cpfp: False
    fee_str: ''
    feerate_str: ''
    date_str: ''
    date_label:''
    amount_str: ''
    tx_hash: ''
    status_str: ''
    description: ''
    outputs_str: ''
    BoxLayout:
        orientation: 'vertical'
        ScrollView:
            scroll_type: ['bars', 'content']
            bar_width: '25dp'
            GridLayout:
                height: self.minimum_height
                size_hint_y: None
                cols: 1
                spacing: '10dp'
                padding: '10dp'
                GridLayout:
                    height: self.minimum_height
                    size_hint_y: None
                    cols: 1
                    spacing: '10dp'
                    BoxLabel:
                        text: _('Status')
                        value: root.status_str
                    BoxLabel:
                        text: _('Description') if root.description else ''
                        value: root.description
                    BoxLabel:
                        text: root.date_label
                        value: root.date_str
                    BoxLabel:
                        text: _('Amount sent') if root.is_mine else _('Amount received')
                        value: root.amount_str
                    BoxLabel:
                        text: _('Transaction fee') if root.fee_str else ''
                        value: root.fee_str
                    BoxLabel:
                        text: _('Transaction fee rate') if root.feerate_str else ''
                        value: root.feerate_str
                TopLabel:
                    text: _('Transaction ID') + ':' if root.tx_hash else ''
                TxHashLabel:
                    data: root.tx_hash
                    name: _('Transaction ID')
                TopLabel:
                    text: _('Outputs') + ':'
                OutputList:
                    id: output_list
        Widget:
            size_hint: 1, 0.1

        BoxLayout:
            size_hint: 1, None
            height: '48dp'
            ActionDropdown:
                id: action_dropdown
                size_hint: 0.5, None
                height: '48dp'
            IconButton:
                size_hint: 0.5, None
                height: '48dp'
                icon: f'atlas://{KIVY_GUI_PATH}/theming/atlas/light/qrcode'
                on_release: root.show_qr()
            Button:
                size_hint: 0.5, None
                height: '48dp'
                text: _('Label')
                on_release: root.label_dialog()
            Button:
                size_hint: 0.5, None
                height: '48dp'
                text: _('Close')
                on_release: root.dismiss()
''')


class TxDialog(Factory.Popup):

    def __init__(self, app, tx):
        Factory.Popup.__init__(self)
        self.app = app  # type: ElectrumWindow
        self.wallet = self.app.wallet
        self.tx = tx  # type: Transaction
        self.config = self.app.electrum_config

        # If the wallet can populate the inputs with more info, do it now.
        # As a result, e.g. we might learn an imported address tx is segwit,
        # or that a beyond-gap-limit address is is_mine.
        # note: this might fetch prev txs over the network.
        # note: this is a no-op for complete txs
        tx.add_info_from_wallet(self.wallet)

    def on_open(self):
        self.update()

    def update(self):
        format_amount = self.app.format_amount_and_units
        tx_details = self.wallet.get_tx_info(self.tx)
        tx_mined_status = tx_details.tx_mined_status
        exp_n = tx_details.mempool_depth_bytes
        amount, fee = tx_details.amount, tx_details.fee
        self.status_str = tx_details.status
        self.description = tx_details.label
        self.can_broadcast = tx_details.can_broadcast
        self.can_rbf = tx_details.can_bump
        self.can_cpfp = tx_details.can_cpfp
        self.can_dscancel = tx_details.can_dscancel
        self.tx_hash = tx_details.txid or ''
        if tx_mined_status.timestamp:
            self.date_label = _('Date')
            self.date_str = datetime.fromtimestamp(tx_mined_status.timestamp).isoformat(' ')[:-3]
        elif exp_n is not None:
            self.date_label = _('Mempool depth')
            self.date_str = self.config.depth_tooltip(exp_n)
        else:
            self.date_label = ''
            self.date_str = ''

        self.can_sign = self.wallet.can_sign(self.tx)
        if amount is None:
            self.amount_str = _("Transaction unrelated to your wallet")
        elif amount > 0:
            self.is_mine = False
            self.amount_str = format_amount(amount)
        else:
            self.is_mine = True
            self.amount_str = format_amount(-amount)
        risk_of_burning_coins = (isinstance(self.tx, PartialTransaction)
                                 and self.can_sign
                                 and fee is not None
                                 and bool(self.wallet.get_warning_for_risk_of_burning_coins_as_fees(self.tx)))
        if fee is not None and not risk_of_burning_coins:
            self.fee_str = format_amount(fee)
            fee_per_kb = fee / self.tx.estimated_size() * 1000
            self.feerate_str = self.app.format_fee_rate(fee_per_kb)
        else:
            self.fee_str = _('unknown')
            self.feerate_str = _('unknown')
        self.ids.output_list.update(self.tx.outputs())

        for dict_entry in self.ids.output_list.data:
            dict_entry['color'], dict_entry['background_color'] = address_colors(self.wallet, dict_entry['address'])

        self.can_remove_tx = tx_details.can_remove
        self.update_action_dropdown()

    def update_action_dropdown(self):
        action_dropdown = self.ids.action_dropdown  # type: ActionDropdown
        # note: button texts need to be short; there is only horizontal space for ~13 chars
        options = (
            ActionButtonOption(text=_('Sign'), func=lambda btn: self.do_sign(), enabled=self.can_sign),
            ActionButtonOption(text=_('Broadcast'), func=lambda btn: self.do_broadcast(), enabled=self.can_broadcast),
            ActionButtonOption(text=_('Bump fee'), func=lambda btn: self.do_rbf(), enabled=self.can_rbf),
            ActionButtonOption(text=_('Child pays\nfor parent'), func=lambda btn: self.do_cpfp(), enabled=(not self.can_rbf and self.can_cpfp)),
            ActionButtonOption(text=_('Cancel') + '\n(double-spend)', func=lambda btn: self.do_dscancel(), enabled=self.can_dscancel),
            ActionButtonOption(text=_('Remove'), func=lambda btn: self.remove_local_tx(), enabled=self.can_remove_tx),
        )
        action_dropdown.update(options=options)

    def _add_info_to_tx_from_wallet_and_network(self, tx: PartialTransaction) -> bool:
        """Returns whether successful."""
        # note side-effect: tx is being mutated
        assert isinstance(tx, PartialTransaction)
        try:
            # note: this might download input utxos over network
            # FIXME network code in gui thread...
            tx.add_info_from_wallet(self.wallet, ignore_network_issues=False)
        except NetworkException as e:
            self.app.show_error(repr(e))
            return False
        return True

    def do_rbf(self):
        from .bump_fee_dialog import BumpFeeDialog
        tx = self.tx
        txid = tx.txid()
        assert txid
        if not isinstance(tx, PartialTransaction):
            tx = PartialTransaction.from_tx(tx)
        if not self._add_info_to_tx_from_wallet_and_network(tx):
            return
        fee = tx.get_fee()
        assert fee is not None
        size = tx.estimated_size()
        cb = partial(self._do_rbf, tx=tx, txid=txid)
        d = BumpFeeDialog(self.app, fee, size, cb)
        d.open()

    def _do_rbf(
            self,
            new_fee_rate,
            is_final,
            *,
            tx: PartialTransaction,
            txid: str,
    ):
        if new_fee_rate is None:
            return
        try:
            new_tx = self.wallet.bump_fee(
                tx=tx,
                txid=txid,
                new_fee_rate=new_fee_rate,
            )
        except CannotBumpFee as e:
            self.app.show_error(str(e))
            return
        new_tx.set_rbf(not is_final)
        self.tx = new_tx
        self.update()
        self.do_sign()

    def do_cpfp(self):
        from .cpfp_dialog import CPFPDialog
        parent_tx = self.tx
        new_tx = self.wallet.cpfp(parent_tx, 0)
        total_size = parent_tx.estimated_size() + new_tx.estimated_size()
        parent_txid = parent_tx.txid()
        assert parent_txid
        parent_fee = self.wallet.adb.get_tx_fee(parent_txid)
        if parent_fee is None:
            self.app.show_error(_("Can't CPFP: unknown fee for parent transaction."))
            return
        cb = partial(self._do_cpfp, parent_tx=parent_tx)
        d = CPFPDialog(self.app, parent_fee, total_size, new_tx=new_tx, callback=cb)
        d.open()

    def _do_cpfp(
            self,
            fee,
            max_fee,
            *,
            parent_tx: Transaction,
    ):
        if fee is None:
            return  # fee left empty, treat is as "cancel"
        if fee > max_fee:
            self.app.show_error(_('Max fee exceeded'))
            return
        try:
            new_tx = self.wallet.cpfp(parent_tx, fee)
        except CannotCPFP as e:
            self.app.show_error(str(e))
            return
        self.app.tx_dialog(new_tx)

    def do_dscancel(self):
        from .dscancel_dialog import DSCancelDialog
        tx = self.tx
        txid = tx.txid()
        assert txid
        if not isinstance(tx, PartialTransaction):
            tx = PartialTransaction.from_tx(tx)
        if not self._add_info_to_tx_from_wallet_and_network(tx):
            return
        fee = tx.get_fee()
        assert fee is not None
        size = tx.estimated_size()
        cb = partial(self._do_dscancel, tx=tx)
        d = DSCancelDialog(self.app, fee, size, cb)
        d.open()

    def _do_dscancel(
            self,
            new_fee_rate,
            *,
            tx: PartialTransaction,
    ):
        if new_fee_rate is None:
            return
        try:
            new_tx = self.wallet.dscancel(
                tx=tx,
                new_fee_rate=new_fee_rate,
            )
        except CannotDoubleSpendTx as e:
            self.app.show_error(str(e))
            return
        self.tx = new_tx
        self.update()
        self.do_sign()

    def do_sign(self):
        self.app.protected(_("Sign this transaction?"), self._do_sign, ())

    def _do_sign(self, password):
        self.status_str = _('Signing') + '...'
        Clock.schedule_once(lambda dt: self.__do_sign(password), 0.1)

    def __do_sign(self, password):
        try:
            self.app.wallet.sign_transaction(self.tx, password)
        except InvalidPassword:
            self.app.show_error(_("Invalid PIN"))
        self.update()

    def do_broadcast(self):
        self.app.broadcast(self.tx)

    def show_qr(self):
        original_raw_tx = str(self.tx)
        qr_data = self.tx.to_qr_data()
        self.app.qr_dialog(_("Raw Transaction"), qr_data, text_for_clipboard=original_raw_tx)

    def remove_local_tx(self):
        txid = self.tx.txid()
        num_child_txs = len(self.wallet.adb.get_depending_transactions(txid))
        question = _("Are you sure you want to remove this transaction?")
        if num_child_txs > 0:
            question = (
                _("Are you sure you want to remove this transaction and {} child transactions?")
                .format(num_child_txs))
        def on_prompt(b):
            if b:
                self.wallet.adb.remove_transaction(txid)
                self.wallet.save_db()
                self.app._trigger_update_wallet()  # FIXME private...
                self.dismiss()
        d = Question(question, on_prompt)
        d.open()

    def label_dialog(self):
        from .label_dialog import LabelDialog
        key = self.tx.txid()
        text = self.app.wallet.get_label_for_txid(key)
        def callback(text):
            self.app.wallet.set_label(key, text)
            self.update()
            self.app.history_screen.update()
        d = LabelDialog(_('Enter Transaction Label'), text, callback)
        d.open()
