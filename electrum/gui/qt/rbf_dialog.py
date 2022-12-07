# Copyright (C) 2021 The Electrum developers
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://www.opensource.org/licenses/mit-license.php

from typing import TYPE_CHECKING

from PyQt5.QtWidgets import (QCheckBox, QLabel, QVBoxLayout, QGridLayout, QWidget,
                             QPushButton, QHBoxLayout, QComboBox)

from .amountedit import FeerateEdit
from .fee_slider import FeeSlider, FeeComboBox
from .util import (ColorScheme, WindowModalDialog, Buttons,
                   OkButton, WWLabel, CancelButton)

from electrum.i18n import _
from electrum.transaction import PartialTransaction
from electrum.wallet import BumpFeeStrategy

if TYPE_CHECKING:
    from .main_window import ElectrumWindow


class _BaseRBFDialog(WindowModalDialog):

    def __init__(
            self,
            *,
            main_window: 'ElectrumWindow',
            tx: PartialTransaction,
            txid: str,
            title: str,
            help_text: str,
    ):
        WindowModalDialog.__init__(self, main_window, title=title)
        self.window = main_window
        self.wallet = main_window.wallet
        self.tx = tx
        assert txid
        self.txid = txid

        fee = tx.get_fee()
        assert fee is not None
        tx_size = tx.estimated_size()
        old_fee_rate = fee / tx_size  # sat/vbyte
        vbox = QVBoxLayout(self)
        vbox.addWidget(WWLabel(help_text))

        ok_button = OkButton(self)
        self.adv_button = QPushButton(_("Show advanced settings"))
        self.adv_button.setEnabled(False)
        self.adv_button.setVisible(False)
        warning_label = WWLabel('\n')
        warning_label.setStyleSheet(ColorScheme.RED.as_stylesheet())
        self.feerate_e = FeerateEdit(lambda: 0)
        self.feerate_e.setAmount(max(old_fee_rate * 1.5, old_fee_rate + 1))

        def on_feerate():
            fee_rate = self.feerate_e.get_amount()
            warning_text = '\n'
            if fee_rate is not None:
                try:
                    new_tx = self.rbf_func(fee_rate)
                except Exception as e:
                    new_tx = None
                    warning_text = str(e).replace('\n', ' ')
            else:
                new_tx = None
            ok_button.setEnabled(new_tx is not None)
            warning_label.setText(warning_text)

        self.feerate_e.textChanged.connect(on_feerate)

        def on_slider(dyn, pos, fee_rate):
            fee_slider.activate()
            if fee_rate is not None:
                self.feerate_e.setAmount(fee_rate / 1000)

        fee_slider = FeeSlider(self.window, self.window.config, on_slider)
        fee_combo = FeeComboBox(fee_slider)
        fee_slider.deactivate()
        self.feerate_e.textEdited.connect(fee_slider.deactivate)

        grid = QGridLayout()
        grid.addWidget(QLabel(_('Current Fee') + ':'), 0, 0)
        grid.addWidget(QLabel(self.window.format_amount(fee) + ' ' + self.window.base_unit()), 0, 1)
        grid.addWidget(QLabel(_('Current Fee rate') + ':'), 1, 0)
        grid.addWidget(QLabel(self.window.format_fee_rate(1000 * old_fee_rate)), 1, 1)
        grid.addWidget(QLabel(_('New Fee rate') + ':'), 2, 0)
        grid.addWidget(self.feerate_e, 2, 1)
        grid.addWidget(fee_slider, 3, 1)
        grid.addWidget(fee_combo, 3, 2)
        vbox.addLayout(grid)
        self._add_advanced_options_cont(vbox)
        vbox.addWidget(warning_label)

        btns_hbox = QHBoxLayout()
        btns_hbox.addWidget(self.adv_button)
        btns_hbox.addStretch(1)
        btns_hbox.addWidget(CancelButton(self))
        btns_hbox.addWidget(ok_button)
        vbox.addLayout(btns_hbox)

    def rbf_func(self, fee_rate) -> PartialTransaction:
        raise NotImplementedError()  # implemented by subclasses

    def _add_advanced_options_cont(self, vbox: QVBoxLayout) -> None:
        adv_vbox = QVBoxLayout()
        adv_vbox.setContentsMargins(0, 0, 0, 0)
        adv_widget = QWidget()
        adv_widget.setLayout(adv_vbox)
        adv_widget.setVisible(False)
        def show_adv_settings():
            self.adv_button.setEnabled(False)
            adv_widget.setVisible(True)
        self.adv_button.clicked.connect(show_adv_settings)
        self._add_advanced_options(adv_vbox)
        vbox.addWidget(adv_widget)

    def _add_advanced_options(self, adv_vbox: QVBoxLayout) -> None:
        pass

    def run(self) -> None:
        if not self.exec_():
            return
        new_fee_rate = self.feerate_e.get_amount()
        try:
            new_tx = self.rbf_func(new_fee_rate)
        except Exception as e:
            self.window.show_error(str(e))
            return
        new_tx.set_rbf(True)
        tx_label = self.wallet.get_label_for_txid(self.txid)
        self.window.show_transaction(new_tx, tx_desc=tx_label)
        # TODO maybe save tx_label as label for new tx??


class BumpFeeDialog(_BaseRBFDialog):

    def __init__(
            self,
            *,
            main_window: 'ElectrumWindow',
            tx: PartialTransaction,
            txid: str,
    ):
        help_text = _("Increase your transaction's fee to improve its position in mempool.")
        _BaseRBFDialog.__init__(
            self,
            main_window=main_window,
            tx=tx,
            txid=txid,
            title=_('Bump Fee'),
            help_text=help_text,
        )

    def rbf_func(self, fee_rate):
        return self.wallet.bump_fee(
            tx=self.tx,
            txid=self.txid,
            new_fee_rate=fee_rate,
            coins=self.window.get_coins(),
            strategies=self.option_index_to_strats[self.strat_combo.currentIndex()],
        )

    def _add_advanced_options(self, adv_vbox: QVBoxLayout) -> None:
        self.adv_button.setVisible(True)
        self.adv_button.setEnabled(True)
        self.strat_combo = QComboBox()
        options = [
            _("decrease change, or add new inputs, or decrease any outputs"),
            _("decrease change, or decrease any outputs"),
            _("decrease payment"),
        ]
        self.option_index_to_strats = {
            0: [BumpFeeStrategy.COINCHOOSER, BumpFeeStrategy.DECREASE_CHANGE],
            1: [BumpFeeStrategy.DECREASE_CHANGE],
            2: [BumpFeeStrategy.DECREASE_PAYMENT],
        }
        self.strat_combo.addItems(options)
        self.strat_combo.setCurrentIndex(0)
        strat_hbox = QHBoxLayout()
        strat_hbox.addWidget(QLabel(_("Strategy") + ":"))
        strat_hbox.addWidget(self.strat_combo)
        strat_hbox.addStretch(1)
        adv_vbox.addLayout(strat_hbox)


class DSCancelDialog(_BaseRBFDialog):

    def __init__(
            self,
            *,
            main_window: 'ElectrumWindow',
            tx: PartialTransaction,
            txid: str,
    ):
        help_text = _(
            "Cancel an unconfirmed RBF transaction by double-spending "
            "its inputs back to your wallet with a higher fee.")
        _BaseRBFDialog.__init__(
            self,
            main_window=main_window,
            tx=tx,
            txid=txid,
            title=_('Cancel transaction'),
            help_text=help_text,
        )

    def rbf_func(self, fee_rate):
        return self.wallet.dscancel(tx=self.tx, new_fee_rate=fee_rate)
