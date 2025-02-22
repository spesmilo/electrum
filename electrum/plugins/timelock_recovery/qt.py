'''

Timelock Recovery

Copyright:
    2025 Oren <orenz0@protonmail.com>

Distributed under the MIT software license, see the accompanying
file LICENCE or http://www.opensource.org/licenses/mit-license.php

'''

import os
import uuid
import json
import hashlib
from datetime import datetime
from functools import partial
from typing import TYPE_CHECKING
from decimal import Decimal

import qrcode
from PyQt6.QtPrintSupport import QPrinter
from PyQt6.QtCore import Qt, QRectF, QMarginsF
from PyQt6.QtGui import (QImage, QPainter, QFontDatabase, QFont, QIntValidator,
                         QPageSize, QPageLayout, QFontMetrics)
from PyQt6.QtWidgets import (QVBoxLayout, QHBoxLayout, QLabel,
                             QPushButton, QLineEdit, QScrollArea, QGridLayout, QFileDialog)

from electrum import constants, version
from electrum.gui.qt.paytoedit import PayToEdit
from electrum.bitcoin import COIN, address_to_script, DummyAddress
from electrum.payment_identifier import PaymentIdentifierType
from electrum.plugin import hook
from electrum.i18n import _
from electrum.transaction import PartialTxInput, PartialTxOutput, TxOutpoint
from electrum.util import make_dir, bfh
from electrum.gui.qt.util import (ColorScheme, WindowModalDialog, Buttons, HelpLabel)
from electrum.gui.qt.main_window import StatusBarButton
from electrum.gui.qt.util import read_QIcon_from_bytes, read_QPixmap_from_bytes

from .timelock_recovery import TimelockRecoveryPlugin


if TYPE_CHECKING:
    from electrum.gui.qt import ElectrumGui

agreement_text = "I understand that using this wallet after generating a Timelock Recovery plan might break the plan"
alert_address_label = "Timelock Recovery Alert Address"
cancellation_address_label = "Timelock Recovery Cancellation Address"
anchor_output_amount_sats = 600
min_locktime_days = 2
# 0xFFFF * 512 seconds = 388.36 days.
max_locktime_days = 388

def selectable_label(text):
    label = QLabel(text)
    label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    return label

def format_sats_as_btc(value):
    return f"{(Decimal(value) / Decimal(COIN)):.8f}"


class PartialTxInputWithFixedNsequence(PartialTxInput):
    def __init__(self, *args, nsequence=0xffffffff - 1, **kwargs):
        self._fixed_nsequence = nsequence
        super().__init__(*args, **kwargs)

    @property
    def nsequence(self):
        return self._fixed_nsequence

    @nsequence.setter
    def nsequence(self, value):
        pass # ignore override attempts


class Plugin(TimelockRecoveryPlugin):
    def __init__(self, parent, config, name):
        TimelockRecoveryPlugin.__init__(self, parent, config, name)
        self.base_dir = os.path.join(config.electrum_path(), 'timelock_recovery')
        make_dir(self.base_dir)

        self._init_qt_received = False
        self.small_logo_bytes = self.read_file("timelock_recovery_60.png")
        self.large_logo_bytes = self.read_file("timelock_recovery_820.png")
        self.intro_text = self.read_file("intro.txt").decode('utf-8')

    @hook
    def init_qt(self, gui: 'ElectrumGui'):
        if self._init_qt_received:  # only need/want the first signal
            return
        self._init_qt_received = True
        # load custom fonts (note: here, and not in __init__, as it needs the QApplication to be created)
        QFontDatabase.addApplicationFont(os.path.join(os.path.dirname(__file__), 'PTMono-Regular.ttf'))
        QFontDatabase.addApplicationFont(os.path.join(os.path.dirname(__file__), 'PTMono-Bold.ttf'))

    @hook
    def create_status_bar(self, sb):
        b = StatusBarButton(
            read_QIcon_from_bytes(self.small_logo_bytes),
            "Timelock Recovery "+_("Plugin"),
            partial(self.start, sb), sb.height())
        sb.addPermanentWidget(b)

    def requires_settings(self):
        return False

    def start(self, window):
        self.wallet = window.parent().wallet
        self.wallet_name = str(self.wallet)

        if constants.net.NET_NAME == 'regtest':
            return self.create_step1_dialog(window)
        return self.create_intro_dialog(window)

    def create_intro_dialog(self, window):
        intro_dialog = WindowModalDialog(window, "Timelock Recovery")
        intro_dialog.setContentsMargins(11,11,1,1)

        # Create an HBox layout.  The logo will be on the left and the rest of the dialog on the right.
        hbox_layout = QHBoxLayout(intro_dialog)

        # Create the logo label.
        logo_label = QLabel()

        # Set the logo label pixmap.
        logo_label.setPixmap(read_QPixmap_from_bytes(self.small_logo_bytes))

        # Align the logo label to the top left.
        logo_label.setAlignment(Qt.AlignmentFlag.AlignLeft)

        # Create a VBox layout for the main contents of the dialog.
        vbox_layout = QVBoxLayout()

        # Populate the HBox layout with spacing between the two columns.
        hbox_layout.addWidget(logo_label)
        hbox_layout.addSpacing(16)
        hbox_layout.addLayout(vbox_layout)

        title_label = QLabel(_("What Is Timelock Recovery?"))
        vbox_layout.addWidget(title_label)

        intro_label = QLabel(self.intro_text)
        intro_label.setWordWrap(True)
        intro_label.setTextFormat(Qt.TextFormat.RichText)
        intro_label.setOpenExternalLinks(True)
        intro_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextBrowserInteraction)

        intro_wrapper = QScrollArea()
        intro_wrapper.setWidget(intro_label)
        intro_wrapper.setWidgetResizable(True)
        intro_wrapper.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOn)
        intro_wrapper.setFrameStyle(0)
        intro_wrapper.setMinimumHeight(200)

        vbox_layout.addWidget(intro_wrapper)

        # Create the labels.
        instructions_label = selectable_label(_(f'Please type in the textbox below:\n"{agreement_text}"'))

        # Create the noise scan QR text edit.
        self.intro_agreement_textedit = QLineEdit()

        # Update the UI when the text changes.
        self.intro_agreement_textedit.textChanged.connect(self.on_agreement_edit)

        # Create the buttons.
        self.intro_next_button = QPushButton(_("Next"), intro_dialog)

        # Initially disable the next button.
        self.intro_next_button.setEnabled(False)

        # Handle clicks on the buttons.
        self.intro_next_button.clicked.connect(intro_dialog.close)
        self.intro_next_button.clicked.connect(partial(self.create_step1_dialog, window))

        # Populate the VBox layout.
        vbox_layout.addWidget(instructions_label)
        vbox_layout.addWidget(self.intro_agreement_textedit)
        vbox_layout.addLayout(Buttons(self.intro_next_button))

        # Add stretches to the end of the layouts to prevent the contents from spreading when the dialog is enlarged.
        hbox_layout.addStretch(1)
        vbox_layout.addStretch(1)

        return bool(intro_dialog.exec())

    def on_agreement_edit(self):
        text = self.intro_agreement_textedit.text()
        self.intro_next_button.setEnabled(constants.net.NET_NAME == 'regtest' or text.lower() == agreement_text.lower())

    def get_address_by_label(self, label):
        for addr in self.wallet.get_unused_addresses():
            if self.wallet.get_label_for_address(addr) ==label:
                return addr
        for addr in self.wallet.get_unused_addresses():
            if self.wallet.get_label_for_address(addr) == '':
                self.wallet.set_label(addr, label)
                return addr
        if self.wallet.is_deterministic():
            addr = self.wallet.create_new_address(False)
            self.wallet.set_label(addr, label)
        return None

    def create_step1_dialog(self, window):
        step1_dialog = WindowModalDialog(window, "Timelock Recovery - Step 1")
        step1_dialog.setContentsMargins(11, 11, 1, 1)
        step1_dialog.resize(800, step1_dialog.height())

        self.alert_address = self.get_address_by_label(alert_address_label)
        if not self.alert_address:
            step1_dialog.show_error(''.join([
                _('No more addresses in your wallet.'), ' ',
                _('You are using a non-deterministic wallet, which cannot create new addresses.'), ' ',
                _('If you want to create new addresses, use a deterministic wallet instead.'),
            ]))
            step1_dialog.close()
            return

        step1_grid = QGridLayout()
        step1_grid.setSpacing(8)
        step1_grid.setColumnStretch(3, 1)
        step1_grid.setRowStretch(2, 1)

        step1_grid.addWidget(HelpLabel(
            _("Alert Address"),
            _("This address in your wallet will receive the funds when the Alert Transaction is broadcasted."),
        ), 0, 0)
        step1_grid.addWidget(selectable_label(self.alert_address), 0, 1, 1, 4)

        self.payto_e = PayToEdit(window.parent().send_tab) # Reuse configuration from send tab
        self.payto_e.toggle_paytomany()
        self.payto_e.paymentIdentifierChanged.connect(self._verify_step1_details)
        self.timelock_days = 90
        self.timelock_days_widget = QLineEdit()
        self.timelock_days_widget.setValidator(QIntValidator(2, 388))
        self.timelock_days_widget.setText(str(self.timelock_days))
        self.timelock_days_widget.textChanged.connect(self._verify_step1_details)

        step1_grid.addWidget(HelpLabel(
            _("Pay to"),
            (
                _("Final recipient(s) of the funds.")
                + "\n\n"
                + _("This field must contain a single Bitcoin address, or multiple lines in the format: 'address, amount'.") + "\n"
                + "\n"
                + _("If multiple lines are used, at least one line must be set to 'max', using the '!' special character.") + "\n"
                + _("Integers weights can also be used in conjunction with '!', "
                    "e.g. set one amount to '2!' and another to '3!' to split your coins 40-60.")
            ),
        ), 1, 0)
        step1_grid.addWidget(self.payto_e, 1, 1, 1, 4)
        step1_grid.addWidget(HelpLabel(
            _("Cancellation time-window (days)"),
            (
                _("After broadcasting the Alert Transaction, you have a limited time to cancel the transaction.") + "\n"
                + _("Value must be between {} and {} days.").format(min_locktime_days, max_locktime_days)
            )
        ), 2, 0)
        step1_grid.addWidget(self.timelock_days_widget, 2, 1, 1, 4)

        # Create an HBox layout.  The logo will be on the left and the rest of the dialog on the right.
        hbox_layout = QHBoxLayout(step1_dialog)

        # Create the logo label.
        logo_label = QLabel()

        # Set the logo label pixmap.
        logo_label.setPixmap(read_QPixmap_from_bytes(self.small_logo_bytes))

        # Align the logo label to the top left.
        logo_label.setAlignment(Qt.AlignmentFlag.AlignLeft)

        # Create a VBox layout for the main contents of the dialog.
        vbox_layout = QVBoxLayout()

        vbox_layout.addLayout(step1_grid, stretch=1)

        self.step1_next_button = QPushButton(_("Next"), step1_dialog)
        self.step1_next_button.clicked.connect(step1_dialog.close)
        self.step1_next_button.clicked.connect(partial(self.create_alert_fee_dialog, window))
        self.step1_next_button.setEnabled(False)

        vbox_layout.addLayout(Buttons(self.step1_next_button))

        # Populate the HBox layout.
        hbox_layout.addWidget(logo_label)
        hbox_layout.addSpacing(16)
        hbox_layout.addLayout(vbox_layout, stretch=1)

        return bool(step1_dialog.exec())

    def _verify_step1_details(self):
        self.timelock_days = None
        try:
            timelock_days_str = self.timelock_days_widget.text()
            timelock_days = int(timelock_days_str)
            if str(timelock_days) != timelock_days_str or timelock_days < min_locktime_days or timelock_days > max_locktime_days:
                raise ValueError("Value not in range.")
            self.timelock_days = timelock_days
            self.timelock_days_widget.setStyleSheet(None)
            self.timelock_days_widget.setToolTip("")
        except ValueError:
            self.timelock_days_widget.setStyleSheet(ColorScheme.RED.as_stylesheet(True))
            self.timelock_days_widget.setToolTip("Value must be between {} and {} days.".format(min_locktime_days, max_locktime_days))
            self.step1_next_button.setEnabled(False)
            return
        pi = self.payto_e.payment_identifier
        if not pi:
            self.step1_next_button.setEnabled(False)
            return
        if not pi.is_valid():
            # Don't make background red - maybe the user did not complete typing yet.
            self.payto_e.setStyleSheet(ColorScheme.RED.as_stylesheet(True) if '\n' in pi.text.strip() else '')
            self.payto_e.setToolTip((pi.get_error() or "Invalid address.") if pi.text else "")
            self.step1_next_button.setEnabled(False)
            return
        elif pi.is_multiline():
            if not pi.is_multiline_max():
                self.payto_e.setStyleSheet(ColorScheme.RED.as_stylesheet(True))
                self.payto_e.setToolTip("At least one line must be set to max spend ('!' in the amount column).")
                self.step1_next_button.setEnabled(False)
                return
            self.outputs = pi.multiline_outputs
        else:
            if not pi.is_available() or pi.type != PaymentIdentifierType.SPK or not pi.spk_is_address:
                self.payto_e.setStyleSheet(ColorScheme.RED.as_stylesheet(True))
                self.payto_e.setToolTip("Invalid address type - must be a Bitcoin address.")
                self.step1_next_button.setEnabled(False)
                return
            scriptpubkey, is_address = pi.parse_output(pi.text.strip())
            if not is_address:
                self.payto_e.setStyleSheet(ColorScheme.RED.as_stylesheet(True))
                self.payto_e.setToolTip("Must be a valid address, not a script.")
                self.step1_next_button.setEnabled(False)
                return
            self.outputs = [PartialTxOutput(scriptpubkey=scriptpubkey, value='!')]
        self.payto_e.setStyleSheet(ColorScheme.GREEN.as_stylesheet(True))
        self.payto_e.setToolTip("")
        self.step1_next_button.setEnabled(True)

    def create_alert_fee_dialog(self, window):
        alert_transaction_outputs = [
            PartialTxOutput(scriptpubkey=address_to_script(self.alert_address), value='!'),
        ] + [
            PartialTxOutput(scriptpubkey=output.scriptpubkey, value=anchor_output_amount_sats)
            for output in self.outputs
        ]
        make_tx = lambda fee_est, *, confirmed_only=False: self.wallet.make_unsigned_transaction(
            coins=window.parent().get_coins(nonlocal_only=False, confirmed_only=confirmed_only),
            outputs=alert_transaction_outputs,
            fee=fee_est,
            is_sweep=False,
        )
        tx, is_preview = window.parent().confirm_tx_dialog(make_tx, '!', allow_preview=False)
        if tx is None or is_preview or tx.has_dummy_output(DummyAddress.SWAP):
            return
        if not tx.is_segwit():
            window.parent().show_error(_("Alert transaction is not segwit. This extension only works with segwit addresses."))
            return
        if not all(tx_input.is_segwit() for tx_input in tx.inputs()):
            window.parent().show_error(_("All of the Alert transaction inputs must be segwit."))
            return
        txid = tx.txid()
        def sign_done(success):
            if not success:
                return
            if tx.txid() != txid:
                window.parent().show_error(_("Alert transaction has been modified."))
                return
            if not tx.is_complete():
                window.parent().show_error(_("Alert transaction is not complete."))
                return
            self.alert_tx = tx
            self.create_recovery_fee_dialog(window)
        window.parent().sign_tx(
            tx,
            callback=sign_done,
            external_keypairs=None)

    def create_recovery_fee_dialog(self, window):
        prevouts = [
            (index, tx_output) for index, tx_output in enumerate(self.alert_tx.outputs())
            if tx_output.address == self.alert_address and tx_output.value != anchor_output_amount_sats
        ]
        if len(prevouts) != 1:
            window.parent().show_error(_("Expected 1 output from the Alert transaction to the Alert Address, but got %d." % len(prevouts)))
            return
        (prevout_index, prevout) = prevouts[0]

        nsequence = round(self.timelock_days * 24 * 60 * 60 / 512)
        if nsequence > 0xFFFF:
            # Safety check - not expected to happen
            raise ValueError("Sequence number is too large")
        nsequence += 0x00400000 # time based lock instead of block-height based lock

        tx_input = PartialTxInputWithFixedNsequence(
            prevout=TxOutpoint(txid=bfh(self.alert_tx.txid()), out_idx=prevout_index),
            nsequence=nsequence,
        )
        tx_input.witness_utxo = prevout

        make_tx = lambda fee_est, *, confirmed_only=False: self.wallet.make_unsigned_transaction(
            coins=[tx_input],
            outputs=[output for output in self.outputs if output.value != 0],
            fee=fee_est,
            is_sweep=False,
        )

        tx, is_preview = window.parent().confirm_tx_dialog(make_tx, '!', allow_preview=False)
        if tx is None or is_preview or tx.has_dummy_output(DummyAddress.SWAP):
            return
        if not tx.is_segwit():
            window.parent().show_error(_("Recovery transaction is not segwit. This extension only works with segwit addresses."))
            return
        if not all(tx_input.is_segwit() for tx_input in tx.inputs()):
            window.parent().show_error(_("All of the transaction inputs must be segwit."))
            return
        txid = tx.txid()
        def sign_done(success):
            if not success:
                return
            if tx.txid() != txid:
                window.parent().show_error(_("Recovery transaction has been modified."))
                return
            if not tx.is_complete():
                window.parent().show_error(_("Recovery transaction is not complete."))
                return
            self.recovery_tx = tx
            self.create_cancellation_dialog(window)
        window.parent().sign_tx(
            tx,
            callback=sign_done,
            external_keypairs=None)

    def create_cancellation_dialog(self, window):
        answer = window.parent().question('\n'.join([
            _("Do you want to also create a Cancellation transaction?"),
            _(
                "If the Alert transaction is has been broadcasted against your intention," +
                " you will be able to broadcast the Cancellation transaction within {} days," +
                " to invalidate the Recovery transaction and keep the funds in this wallet" +
                " - without the need to restore the seed of this wallet (i.e. in case you have split or hidden it)."
            ).format(self.timelock_days),
            _(
                "However, if the seed of this wallet is lost, broadcasting the Cancellation transaction" +
                " might lock the funds on this wallet forever."
            )
        ]))
        if not answer:
            self.cancellation_tx = None
            return self.create_download_dialog(window)
        cancellation_address = self.get_address_by_label(cancellation_address_label)
        if not cancellation_address:
            window.parent().show_error(''.join([
                _("No more addresses in your wallet."), " ",
                _("You are using a non-deterministic wallet, which cannot create new addresses."), " ",
                _("If you want to create new addresses, use a deterministic wallet instead."),
            ]))
            self.cancellation_tx = None
            return self.create_download_dialog(window)

        prevouts = [
            (index, tx_output) for index, tx_output in enumerate(self.alert_tx.outputs())
            if tx_output.address == self.alert_address and tx_output.value != anchor_output_amount_sats
        ]
        if len(prevouts) != 1:
            window.parent().show_error(_("Expected 1 output from the Alert transaction to the Alert Address, but got %d." % len(prevouts)))
            return
        (prevout_index, prevout) = prevouts[0]

        tx_input = PartialTxInput(
            prevout=TxOutpoint(txid=bfh(self.alert_tx.txid()), out_idx=prevout_index),
        )
        tx_input.witness_utxo = prevout

        make_tx = lambda fee_est, *, confirmed_only=False: self.wallet.make_unsigned_transaction(
            coins=[tx_input],
            outputs=[
                PartialTxOutput(scriptpubkey=address_to_script(cancellation_address), value='!'),
            ],
            fee=fee_est,
            is_sweep=False,
        )

        tx, is_preview = window.parent().confirm_tx_dialog(make_tx, '!', allow_preview=False)
        if tx is None or is_preview or tx.has_dummy_output(DummyAddress.SWAP):
            return
        if not tx.is_segwit():
            window.parent().show_error(_("Recovery transaction is not segwit. This extension only works with segwit addresses."))
            return
        if not all(tx_input.is_segwit() for tx_input in tx.inputs()):
            window.parent().show_error(_("All of the transaction inputs must be segwit."))
            return
        txid = tx.txid()
        def sign_done(success):
            if not success:
                return
            if tx.txid() != txid:
                window.parent().show_error(_("Recovery transaction has been modified."))
                return
            if not tx.is_complete():
                window.parent().show_error(_("Recovery transaction is not complete."))
                return
            self.cancellation_tx = tx
            self.create_download_dialog(window)
        window.parent().sign_tx(
            tx,
            callback=sign_done,
            external_keypairs=None,
        )

    def create_download_dialog(self, window):
        self.recovery_plan_id = str(uuid.uuid4())
        self.recovery_plan_created_at = datetime.now().astimezone()
        self.download_dialog = WindowModalDialog(window, "Timelock Recovery - Download")
        self.download_dialog.setContentsMargins(11, 11, 1, 1)
        self.download_dialog.resize(800, self.download_dialog.height())

        # Create an HBox layout. The logo will be on the left and the rest of the dialog on the right.
        hbox_layout = QHBoxLayout(self.download_dialog)

        # Create the logo label
        logo_label = QLabel()
        logo_label.setPixmap(read_QPixmap_from_bytes(self.small_logo_bytes))
        logo_label.setAlignment(Qt.AlignmentFlag.AlignLeft)

        # Create a VBox layout for the main contents
        vbox_layout = QVBoxLayout()

        # Create and populate the grid
        grid = QGridLayout()
        grid.setSpacing(8)
        grid.setColumnStretch(3, 1)

        line_number = 0

        # Add Recovery Plan ID row
        grid.addWidget(HelpLabel(
            _("Recovery Plan ID"),
            _("Unique identifier for this recovery plan"),
        ), 0, 0)
        grid.addWidget(selectable_label(self.recovery_plan_id), line_number, 1, 1, 4)
        line_number += 1
        # Add Creation Date row
        grid.addWidget(HelpLabel(
            _("Created At"),
            _("Date and time when this recovery plan was created"),
        ), 1, 0)
        grid.addWidget(selectable_label(self.recovery_plan_created_at.strftime("%Y-%m-%d %H:%M:%S %Z (%z)")), line_number, 1, 1, 4)
        line_number += 1

        grid.addWidget(HelpLabel(
            _("Alert Transaction ID"),
            _("ID of the Alert transaction"),
        ), 2, 0)
        grid.addWidget(selectable_label(self.alert_tx.txid()), line_number, 1, 1, 4)
        line_number += 1

        grid.addWidget(HelpLabel(
            _("Recovery Transaction ID"),
            _("ID of the Recovery transaction"),
        ), 3, 0)
        grid.addWidget(selectable_label(self.recovery_tx.txid()), line_number, 1, 1, 4)
        line_number += 1

        if self.cancellation_tx is not None:
            grid.addWidget(HelpLabel(
                _("Cancellation Transaction ID"),
                _("ID of the Cancellation transaction"),
            ), 4, 0)
            grid.addWidget(selectable_label(self.cancellation_tx.txid()), line_number, 1, 1, 4)
            line_number += 1

        # Create buttons
        # Save Recovery Plan button row
        save_recovery_hbox = QHBoxLayout()
        save_recovery_pdf_button = QPushButton(_("Save Recovery Plan PDF..."), self.download_dialog)
        save_recovery_pdf_button.clicked.connect(self._save_recovery_plan_pdf)
        save_recovery_hbox.addWidget(save_recovery_pdf_button)
        save_recovery_json_button = QPushButton(_("Save Recovery Plan JSON..."), self.download_dialog)
        save_recovery_json_button.clicked.connect(self._save_recovery_plan_json)
        save_recovery_hbox.addWidget(save_recovery_json_button)
        save_recovery_hbox.addStretch(1)
        grid.addLayout(save_recovery_hbox, line_number, 0, 1, 5)
        line_number += 1

        # Save Cancellation Plan button row (if applicable)
        if self.cancellation_tx is not None:
            save_cancel_hbox = QHBoxLayout()
            save_cancel_button = QPushButton(_("Save Cancellation Plan PDF..."), self.download_dialog)
            save_cancel_button.clicked.connect(self._save_cancellation_plan_pdf)
            save_cancellation_json_button = QPushButton(_("Save Cancellation Plan JSON..."), self.download_dialog)
            save_cancellation_json_button.clicked.connect(self._save_cancellation_plan_json)
            save_cancel_hbox.addWidget(save_cancel_button)
            save_cancel_hbox.addWidget(save_cancellation_json_button)
            save_cancel_hbox.addStretch(1)
            grid.addLayout(save_cancel_hbox, line_number, 0, 1, 5)
            line_number += 1

        # Add layouts to main vbox
        vbox_layout.addLayout(grid)

        close_button = QPushButton(_("Close"), self.download_dialog)
        close_button.clicked.connect(self.download_dialog.close)

        vbox_layout.addLayout(Buttons(close_button))

        # Populate the HBox layout.
        hbox_layout.addWidget(logo_label)
        hbox_layout.addSpacing(16)
        hbox_layout.addLayout(vbox_layout, stretch=1)

        return bool(self.download_dialog.exec())

    def _save_recovery_plan_json(self):
        try:
            # Open a Save As dialog to get the file path
            file_path, _selected_filter = QFileDialog.getSaveFileName(
                self.download_dialog,
                _("Save Recovery Plan JSON..."),
                os.path.join(self.base_dir, "timelock-recovery-plan-{}.json".format(self.recovery_plan_id)),
                _("JSON files (*.json)")
            )
            if not file_path:
                return
            with open(file_path, "w") as f:
                json_data = {
                    "kind": "timelock-recovery-plan",
                    "id": self.recovery_plan_id,
                    "created_at": self.recovery_plan_created_at.isoformat(),
                    "plugin_version": self.VERSION,
                    "wallet_kind": "electrum",
                    "wallet_version": version.ELECTRUM_VERSION,
                    "wallet_name": self.wallet_name,
                    "timelock_days": self.timelock_days,
                    "alert_address": self.alert_address,
                    "alert_tx": self.alert_tx.serialize().upper(),
                    "alert_txid": self.alert_tx.txid(),
                    "recovery_tx": self.recovery_tx.serialize().upper(),
                    "recovery_txid": self.recovery_tx.txid(),
                }
                # Simple checksum to ensure the file is not corrupted by foolish users
                json_data["checksum"] = hashlib.sha256(json.dumps(sorted(json_data.items()), separators=(',', ':')).encode()).hexdigest()
                json.dump(json_data, f, indent=2)
            self.download_dialog.show_message(_("File saved successfully"))
        except Exception as e:
            self.logger.exception(repr(e))
            self.download_dialog.show_error(_("Error saving file"))

    def _save_cancellation_plan_json(self):
        try:
            # Open a Save As dialog to get the file path
            file_path, _selected_filter = QFileDialog.getSaveFileName(
                self.download_dialog,
                _("Save Cancellation Plan JSON..."),
                os.path.join(self.base_dir, "timelock-cancellation-plan-{}.json".format(self.recovery_plan_id)),
                _("JSON files (*.json)")
            )
            if not file_path:
                return
            with open(file_path, "w") as f:
                json_data = {
                    "kind": "timelock-cancellation-plan",
                    "id": self.recovery_plan_id,
                    "created_at": self.recovery_plan_created_at.isoformat(),
                    "plugin_version": self.VERSION,
                    "wallet_kind": "electrum",
                    "wallet_version": version.ELECTRUM_VERSION,
                    "wallet_name": self.wallet_name,
                    "timelock_days": self.timelock_days,
                    "alert_address": self.alert_address,
                    "alert_txid": self.alert_tx.txid(),
                    "cancellation_tx": self.cancellation_tx.serialize().upper(),
                    "cancellation_txid": self.cancellation_tx.txid(),
                }
                # Simple checksum to ensure the file is not corrupted by foolish users
                json_data["checksum"] = hashlib.sha256(json.dumps(sorted(json_data.items()), separators=(',', ':')).encode()).hexdigest()
                json.dump(json_data, f, indent=2)
            self.download_dialog.show_message(_("File saved successfully"))
        except Exception as e:
            self.logger.exception(repr(e))
            self.download_dialog.show_error(_("Error saving file"))

    def _save_recovery_plan_pdf(self):
        try:
            # Open a Save As dialog to get the file path
            file_path, _selected_filter = QFileDialog.getSaveFileName(
                self.download_dialog,
                _("Save Recovery Plan PDF..."),
                os.path.join(self.base_dir, "timelock-recovery-plan-{}.pdf".format(self.recovery_plan_id)),
                _("PDF files (*.pdf)")
            )
            if not file_path:
                return
            # Create PDF printer
            printer = QPrinter()
            printer.setResolution(600)
            printer.setPageSize(QPageSize(QPageSize.PageSizeId.A4))
            printer.setOutputFormat(QPrinter.OutputFormat.PdfFormat)
            printer.setOutputFileName(file_path)
            printer.setPageMargins(QMarginsF(20, 20, 20, 20), QPageLayout.Unit.Point)

            # Create painter
            painter = QPainter()
            if not painter.begin(printer):
                return

            pixels_per_point = printer.resolution() / 72.0

            # Set up fonts
            header_font = QFont("PT Mono", 8)
            header_line_spacing = QFontMetrics(header_font).lineSpacing() * pixels_per_point
            title_font = QFont("PT Mono", 18, QFont.Weight.Bold)
            title_line_spacing = QFontMetrics(title_font).height() * pixels_per_point
            subtitle_font = QFont("PT Mono", 10)
            subtitle_line_spacing = QFontMetrics(subtitle_font).height() * pixels_per_point
            title_small_font = QFont("PT Mono", 16, QFont.Weight.Bold)
            title_small_line_spacing = QFontMetrics(title_small_font).height() * pixels_per_point
            body_font = QFont("PT Mono", 9)
            body_small_font = QFont("PT Mono", 8)
            body_small_line_spacing = QFontMetrics(body_small_font).lineSpacing() * pixels_per_point

            # Get page dimensions
            page_rect = printer.pageRect(QPrinter.Unit.DevicePixel)
            page_width = page_rect.width()
            page_height = page_rect.height()

            current_height = 0
            page_number = 1

            # Header
            painter.setFont(header_font)
            painter.drawText(
                QRectF(0, 0, page_width, header_line_spacing + 20),
                Qt.AlignmentFlag.AlignHCenter,
                f"Recovery-Guide  Date: {self.recovery_plan_created_at.strftime('%Y-%m-%d %H:%M:%S %Z (%z)')}  ID: {self.recovery_plan_id}  Page: {page_number}",
            )
            current_height += header_line_spacing + 40

            # Add logo image
            logo_pixmap = read_QPixmap_from_bytes(self.large_logo_bytes)
            logo_size = int(page_width / 10)
            scaled_logo = logo_pixmap.scaled(
                logo_size,
                logo_size,
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation
            )

            # Center the logo horizontally and draw at current_height
            logo_x = (page_width - scaled_logo.width()) / 2
            painter.drawPixmap(int(logo_x), int(current_height), scaled_logo)
            current_height += scaled_logo.height() + 40  # Add padding below logo

            # Title
            painter.setFont(title_font)
            painter.drawText(QRectF(0, current_height, page_width, title_line_spacing + 20), Qt.AlignmentFlag.AlignHCenter, "Timelock-Recovery Guide")
            current_height += title_line_spacing + 20

            # Subtitle
            painter.setFont(subtitle_font)
            painter.drawText(
                QRectF(0, current_height, page_width, subtitle_line_spacing + 20), Qt.AlignmentFlag.AlignCenter,
                f"Electrum Version: {version.ELECTRUM_VERSION} - Plugin Version: {self.VERSION}"
            )
            current_height += subtitle_line_spacing + 60

            # Main content
            recovery_tx_outputs = self.recovery_tx.outputs()
            painter.setFont(body_font)
            intro_text = (
                f"This document will guide you through the process of recovering the funds on wallet: {self.wallet_name}. "
                f"The process will take at least {self.timelock_days} days, and will eventually send the following amount "
                f"to the following {"address" if len(recovery_tx_outputs) == 1 else "addresses"}:\n\n"
                f"{', '.join([
                    f'• {output.address}: {format_sats_as_btc(output.value)} BTC'
                    for output in recovery_tx_outputs
                ])}\n\n"
                f"Before proceeding, MAKE SURE THAT YOU HAVE ACCESS TO THE {"WALLET OF THIS ADDRESS" if len(recovery_tx_outputs) == 1 else "WALLETS OF THESE ADDRESSES"}, "
                f"OR TRUST THE {"OWNER OF THIS ADDRESS" if len(recovery_tx_outputs) == 1 else "OWNERS OF THESE ADDRESSES"}. "
                "The simplest way to do so is to send a small amount to the address, and then trying "
                "to send all funds from that wallet to a different wallet. Also important: make sure that the "
                "seed-phrase of this wallet has not been compromised, or else a malicious actor could steal "
                "the funds the moment they reach their destination.\n\n"
                "For more information, visit: https://timelockrecovery.com\n"
            )

            drawn_rect = painter.drawText(
                QRectF(0, current_height, page_width, page_height - current_height),
                Qt.TextFlag.TextWordWrap,
                intro_text,
            )
            current_height += drawn_rect.height() + 20

            # Step 1
            painter.setFont(title_small_font)
            painter.drawText(
                QRectF(0, current_height, page_width, title_small_line_spacing + 20),Qt.AlignmentFlag.AlignLeft,
                "Step 1 - Broadcasting the Alert transaction",
            )
            current_height += title_small_line_spacing + 20

            painter.setFont(body_font)
            # Calculate number of anchors
            num_anchors = len(self.alert_tx.outputs()) - 1

            # Split alert tx into parts if needed
            alert_raw = self.alert_tx.serialize().upper()
            if len(alert_raw) < 2300:
                alert_raw_parts = [alert_raw]
            else:
                alert_raw_parts = []
                for i in range(0, len(alert_raw), 2100):
                    alert_raw_parts.append(alert_raw[i:i+2100])

            # Step 1 explanation text
            step1_text = (
                f"The first step is to broadcast the Alert transaction. "
                f"This transaction will keep most funds in the same wallet {self.wallet_name}, "
            )

            if num_anchors > 0:
                step1_text += (
                    f"except for 600 sats that will be sent to "
                    f"{'each of the following addresses' if num_anchors > 1 else 'the following address'} "
                    f"(and can be used in case you need to accelerate the transaction via Child-Pay-For-Parent, "
                    f"as we'll explain later):\n"
                )
                for output in self.alert_tx.outputs():
                    if output.address != self.alert_address and output.value == anchor_output_amount_sats:
                        step1_text += f"• {output.address}\n"
            else:
                step1_text += "except for a small fee.\n"

            step1_text += (
                f"\nTo broadcast the Alert transaction, "
                f"{'scan the QR code on the next page' if len(alert_raw_parts) <= 1 else f'scan the QR codes on the next {len(alert_raw_parts)} pages, concatenate the contents of the QR codes (without spaces),'} "
                f"and paste the content in one of the following Bitcoin block-explorer websites:\n"
                "• https://mempool.space/tx/push\n"
                "• https://blockstream.info/tx/push\n"
                "• https://coinb.in/#broadcast\n\n"
                f"You should then see a success message for broadcasting transaction-id: {self.alert_tx.txid()}"
            )

            drawn_rect = painter.drawText(
                QRectF(0, current_height, page_width, page_height - current_height),
                Qt.TextFlag.TextWordWrap,
                step1_text
            )
            current_height += drawn_rect.height() + 20

            # Generate QR pages for alert tx parts
            for i, alert_part in enumerate(alert_raw_parts):
                # Add new page
                printer.newPage()
                page_number += 1
                current_height = 20

                # Header
                painter.setFont(header_font)
                painter.drawText(
                    QRectF(0, current_height, page_width, header_line_spacing),
                    Qt.AlignmentFlag.AlignCenter,
                    f"Recovery-Guide  Date: {self.recovery_plan_created_at.strftime('%Y-%m-%d %H:%M:%S %Z (%z)')}  ID: {self.recovery_plan_id}  Page: {page_number}"
                )
                current_height += header_line_spacing + 20

                # Title
                painter.setFont(title_font)
                painter.drawText(
                    QRectF(0, current_height, page_width, title_line_spacing),
                    Qt.AlignmentFlag.AlignCenter,
                    "Alert Transaction"
                )
                current_height += title_line_spacing + 20

                # Transaction ID
                painter.setFont(subtitle_font)
                painter.drawText(
                    QRectF(0, current_height, page_width, subtitle_line_spacing),
                    Qt.AlignmentFlag.AlignCenter,
                    f"Transaction Id: {self.alert_tx.txid()}"
                )
                current_height += subtitle_line_spacing + 20

                # Part number if multiple parts
                if len(alert_raw_parts) > 1:
                    painter.setFont(subtitle_font)
                    painter.drawText(
                        QRectF(0, current_height, page_width, subtitle_line_spacing),
                        Qt.AlignmentFlag.AlignCenter,
                        f"Part {i+1} of {len(alert_raw_parts)}"
                    )
                    current_height += subtitle_line_spacing + 20

                # QR Code
                qr = qrcode.QRCode(
                    error_correction=qrcode.constants.ERROR_CORRECT_Q,
                )
                qr.add_data(alert_part)
                qr.make()
                qr_image = self._paint_qr(qr)

                # Calculate QR position to center it
                qr_width = int(page_width * 0.6)
                qr_x = (page_width - qr_width) / 2
                painter.drawImage(QRectF(qr_x, current_height, qr_width, qr_width), qr_image)
                current_height += qr_width + 40

                # Raw text below QR
                painter.setFont(body_font)
                painter.drawText(
                    QRectF(20, current_height, page_width, page_height - current_height),
                    Qt.TextFlag.TextWrapAnywhere,
                    alert_part
                )

            printer.newPage()
            page_number += 1
            current_height = 20
            # Header
            painter.setFont(header_font)
            painter.drawText(
                QRectF(0, current_height, page_width, header_line_spacing),
                Qt.AlignmentFlag.AlignCenter,
                f"Recovery-Guide  Date: {self.recovery_plan_created_at.strftime('%Y-%m-%d %H:%M:%S %Z (%z)')}  ID: {self.recovery_plan_id}  Page: {page_number}"
            )
            current_height += header_line_spacing + 20

            # Step 2 page
            painter.setFont(title_small_font)
            painter.drawText(QRectF(20, current_height, page_width, title_small_line_spacing), Qt.AlignmentFlag.AlignLeft, "Step 2 - Waiting for the Alert transaction confirmation")
            current_height += title_small_line_spacing + 20

            painter.setFont(body_font)
            painter.drawText(QRectF(20, current_height, page_width, subtitle_line_spacing), Qt.AlignmentFlag.AlignLeft, "You can follow the Alert transaction via any of the following links:")
            current_height += subtitle_line_spacing + 20

            # QR codes and links for transaction tracking
            for link in [f"https://mempool.space/tx/{self.alert_tx.txid()}", f"https://blockstream.info/tx/{self.alert_tx.txid()}"]:
                qr = qrcode.QRCode(
                    error_correction=qrcode.constants.ERROR_CORRECT_H,
                )
                qr.add_data(link)
                qr.make()
                qr_image = self._paint_qr(qr)

                qr_width = int(page_width * 0.2)
                qr_x = (page_width - qr_width) / 2
                painter.drawImage(QRectF(qr_x, current_height, qr_width, qr_width), qr_image)
                current_height += qr_width + 20

                painter.setFont(body_small_font)
                painter.drawText(QRectF(0, current_height, page_width, body_small_line_spacing), Qt.AlignmentFlag.AlignCenter, link)
                current_height += body_small_line_spacing + 20

            # Explanation text
            painter.setFont(body_font)
            explanation_text = (
                "Please wait for a while until the transaction is marked as \"confirmed\" (number of confirmations greater than 0). "
                "The time that takes a transaction to confirm depends on the fee that it pays, compared to the fee that other "
                "pending transactions are willing to pay. At the time this document was created, it was hard to predict what a "
                "reasonable fee would be today. If the transaction is not confirmed after 24 hours, you may try paying to a "
                "Transaction Acceleration service, such as the one offered by: https://mempool.space.com ."
            )
            if len(self.outputs) > 0:
                explanation_text += (
                    f" Another solution, which may be cheaper but requires more technical skill, would be to use"
                    f"{' one of the wallets that receive 600 sats (addresses mentioned in Step 1),' if len(self.outputs) > 1 else ' the wallet that receive 600 sats (address mentioned in Step 1),'}"
                    " and send a high-fee transaction that includes that 600 sats UTXO (this transaction could also be from the"
                    " wallet to itself). For more information, visit: https://timelockrecovery.com ."
                )

            drawn_rect = painter.drawText(QRectF(20, current_height, page_width, page_height - current_height), Qt.TextFlag.TextWordWrap, explanation_text)
            current_height += drawn_rect.height() + 40

            # Step 3 header
            painter.setFont(title_small_font)
            painter.drawText(QRectF(20, current_height, page_width, title_small_line_spacing), Qt.AlignmentFlag.AlignLeft, "Step 3 - Broadcasting the Recovery transaction")
            current_height += title_small_line_spacing + 20

            # Split recovery transaction if needed
            recovery_raw = self.recovery_tx.serialize().upper()
            recovery_raw_parts = [recovery_raw[i:i+2100] for i in range(0, len(recovery_raw), 2100)] if len(recovery_raw) > 2300 else [recovery_raw]

            # Step 3 explanation
            painter.setFont(body_font)
            step3_text = (
                f"Approximately {self.timelock_days} days after the Alert transaction has been confirmed, you "
                "will be able to broadcast the second Recovery transaction that will send the funds to the final"
                f"{' destinations,' if len(recovery_tx_outputs) > 1 else ' destination,'} mentioned on the first page. This can be done using the same websites mentioned in Step 1, but "
                f"this time you will need to {'scan the QR code on page ' + str(page_number + 1) if len(recovery_raw_parts) <= 1 else 'scan the QR codes on pages ' + str(page_number + 1) + '-' + str(page_number + len(recovery_raw_parts)) + ' and concatenate their content (without spaces)'}. If this transaction remains unconfirmed for a "
                "long time, you should use the Transaction Acceleration service mentioned on Step 2, or use the "
                "Child-Pay-For-Parent technique."
            )
            painter.drawText(QRectF(20, current_height, page_width, page_height - current_height), Qt.TextFlag.TextWordWrap, step3_text)

            # Recovery transaction pages
            for i, recovery_part in enumerate(recovery_raw_parts):
                printer.newPage()
                page_number += 1
                current_height = 20

                # Header
                painter.setFont(header_font)
                painter.drawText(
                    QRectF(0, current_height, page_width, header_line_spacing),
                    Qt.AlignmentFlag.AlignCenter,
                    f"Recovery-Guide  Date: {self.recovery_plan_created_at.strftime('%Y-%m-%d %H:%M:%S %Z (%z)')}  ID: {self.recovery_plan_id}  Page: {page_number}"
                )
                current_height += header_line_spacing + 20

                # Title
                painter.setFont(title_font)
                painter.drawText(
                    QRectF(0, current_height, page_width, title_line_spacing),
                    Qt.AlignmentFlag.AlignCenter,
                    "Recovery Transaction"
                )
                current_height += title_line_spacing + 20

                # Transaction ID
                painter.setFont(subtitle_font)
                painter.drawText(
                    QRectF(0, current_height, page_width, subtitle_line_spacing),
                    Qt.AlignmentFlag.AlignCenter,
                    f"Transaction Id: {self.recovery_tx.txid()}"
                )
                current_height += subtitle_line_spacing + 20

                # Part number if multiple parts
                if len(recovery_raw_parts) > 1:
                    painter.setFont(subtitle_font)
                    painter.drawText(
                        QRectF(0, current_height, page_width, subtitle_line_spacing),
                        Qt.AlignmentFlag.AlignCenter,
                        f"Part {i+1} of {len(recovery_raw_parts)}"
                    )
                    current_height += subtitle_line_spacing + 20

                # QR Code
                qr = qrcode.QRCode(
                    error_correction=qrcode.constants.ERROR_CORRECT_Q,
                )
                qr.add_data(recovery_part)
                qr.make()
                qr_image = self._paint_qr(qr)

                # Calculate QR position to center it
                qr_width = int(page_width * 0.6)
                qr_x = (page_width - qr_width) / 2
                painter.drawImage(QRectF(qr_x, current_height, qr_width, qr_width), qr_image)
                current_height += qr_width + 40

                # Raw text below QR
                painter.setFont(body_font)
                painter.drawText(
                    QRectF(20, current_height, page_width, page_height - current_height),
                    Qt.TextFlag.TextWrapAnywhere,
                    recovery_part
                )

            painter.end()

            self.download_dialog.show_message(_("File saved successfully"))
        except Exception as e:
            self.logger.exception(repr(e))
            self.download_dialog.show_error(_("Error saving file"))


    def _save_cancellation_plan_pdf(self):
        try:
            cancellation_raw = self.cancellation_tx.serialize().upper()
            if len(cancellation_raw) > 2300:
                # Splitting the cancellation transaction into multiple QR codes is not implemented
                # because it is unexpected to happen anyways.
                raise Exception("Cancellation transaction is too large to be saved as a single QR code")

            # Open a Save As dialog to get the file path
            file_path, _selected_filter = QFileDialog.getSaveFileName(
                self.download_dialog,
                _("Save Cancellation Plan PDF..."),
                os.path.join(self.base_dir, "timelock-cancellation-plan-{}.pdf".format(self.recovery_plan_id)),
                _("PDF files (*.pdf)")
            )
            if not file_path:
                return

            printer = QPrinter()
            printer.setResolution(600)
            printer.setPageSize(QPageSize(QPageSize.PageSizeId.A4))
            printer.setOutputFormat(QPrinter.OutputFormat.PdfFormat)
            printer.setOutputFileName(file_path)
            printer.setPageMargins(QMarginsF(20, 20, 20, 20), QPageLayout.Unit.Point)

            # Create painter
            painter = QPainter()
            if not painter.begin(printer):
                return

            pixels_per_point = printer.resolution() / 72.0

            # Setup fonts
            header_font = QFont("PT Mono", 8)
            header_line_spacing = QFontMetrics(header_font).lineSpacing() * pixels_per_point
            title_font = QFont("PT Mono", 18, QFont.Weight.Bold)
            title_line_spacing = QFontMetrics(title_font).height() * pixels_per_point
            subtitle_font = QFont("PT Mono", 10)
            subtitle_line_spacing = QFontMetrics(subtitle_font).height() * pixels_per_point
            body_font = QFont("PT Mono", 9)
            body_small_font = QFont("PT Mono", 8)
            body_small_line_spacing = QFontMetrics(body_small_font).lineSpacing() * pixels_per_point

            # Start painting
            painter = QPainter()
            painter.begin(printer)

            # Get page dimensions
            page_rect = printer.pageRect(QPrinter.Unit.DevicePixel)
            page_width = page_rect.width()
            page_height = page_rect.height()

            current_height = 0
            page_number = 1

            # Header
            painter.setFont(header_font)
            painter.drawText(
                QRectF(0, current_height, page_width, header_line_spacing),
                Qt.AlignmentFlag.AlignCenter,
                f"Cancellation-Guide  Date: {self.recovery_plan_created_at.strftime('%Y-%m-%d %H:%M:%S %Z (%z)')}  ID: {self.recovery_plan_id}  Page: {page_number}"
            )
            current_height += header_line_spacing + 40

            # Add logo image
            logo_pixmap = read_QPixmap_from_bytes(self.large_logo_bytes)
            logo_size = int(page_width / 10)
            scaled_logo = logo_pixmap.scaled(
                logo_size,
                logo_size,
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation
            )

            # Center the logo horizontally and draw at current_height
            logo_x = (page_width - scaled_logo.width()) / 2
            painter.drawPixmap(int(logo_x), int(current_height), scaled_logo)
            current_height += scaled_logo.height() + 40  # Add padding below logo


            # Title
            painter.setFont(title_font)
            painter.drawText(
                QRectF(0, current_height, page_width, title_line_spacing),
                Qt.AlignmentFlag.AlignCenter,
                "Timelock-Recovery Cancellation Guide"
            )
            current_height += title_line_spacing + 20

            # Subtitle
            painter.setFont(subtitle_font)
            painter.drawText(
                QRectF(0, current_height, page_width, subtitle_line_spacing + 20), Qt.AlignmentFlag.AlignCenter,
                f"Electrum Version: {version.ELECTRUM_VERSION} - Plugin Version: {self.VERSION}"
            )
            current_height += subtitle_line_spacing + 60

            # Main text
            painter.setFont(body_font)
            explanation_text = (
                f"This document is intended solely for the eyes of the owner of wallet: {self.wallet_name}. "
                f"The Recovery Guide (the other document) will allow to transfer the funds from this wallet to "
                f"a different wallet within {self.timelock_days} days. To prevent this from happening accidentally "
                f"or maliciously by someone who found that document, you should periodically check if the Alert "
                f"transaction has been broadcasted, using a Bitcoin block-explorer website such as:"
            )
            drawn_rect = painter.drawText(
                QRectF(20, current_height, page_width - 40, page_height),
                Qt.TextFlag.TextWordWrap,
                explanation_text
            )
            current_height += drawn_rect.height() + 40

            # QR codes and links for transaction tracking
            for link in [f"https://mempool.space/tx/{self.alert_tx.txid()}", f"https://blockstream.info/tx/{self.alert_tx.txid()}"]:
                qr = qrcode.QRCode(
                    error_correction=qrcode.constants.ERROR_CORRECT_H,
                )
                qr.add_data(link)
                qr.make()
                qr_image = self._paint_qr(qr)

                qr_width = int(page_width * 0.2)
                qr_x = (page_width - qr_width) / 2
                painter.drawImage(QRectF(qr_x, current_height, qr_width, qr_width), qr_image)
                current_height += qr_width + 20

                painter.setFont(body_small_font)
                painter.drawText(
                    QRectF(0, current_height, page_width, body_small_line_spacing),
                    Qt.AlignmentFlag.AlignCenter,
                    link
                )
                current_height += body_small_line_spacing + 20

            # Watch tower text
            painter.setFont(body_font)
            drawn_rect = painter.drawText(
                QRectF(20, current_height, page_width - 40, page_height - current_height),
                Qt.TextFlag.TextWordWrap,
                "It is also recommended to use a Watch-Tower service that will notify you immediately if the"
                " Alert transaction has been broadcasted. For more details, visit: https://timelockrecovery.com ."
            )
            current_height += drawn_rect.height() + 40

            # Cancellation transaction section
            cancellation_text = (
                "In case the Alert transaction has been broadcasted, and you want to stop the funds from "
                "leaving this wallet, you can scan the QR code on page 2, and broadcast "
                "the content using one of the following Bitcoin block-explorer websites:\n\n"
                "• https://mempool.space/tx/push\n"
                "• https://blockstream.info/tx/push\n"
                "• https://coinb.in/#broadcast\n\n"
                "If the transaction is not confirmed within reasonable time due to a low fee, you will have "
                "to access the wallet and use Replace-By-Fee/Child-Pay-For-Parent to move the funds to a new "
                "address on your wallet. (you can also pay to an Acceleration Service such as the one offered "
                "by https://mempool.space)\n\n"
                f"IMPORTANT NOTICE: If you lost the keys to access wallet {self.wallet_name} - do not broadcast the "
                "transaction on page 2! In this case it is recommended to destroy all copies of this document."
            )
            painter.drawText(
                QRectF(20, current_height, page_width - 40, page_height),
                Qt.TextFlag.TextWordWrap,
                cancellation_text
            )

            # New page for cancellation transaction
            printer.newPage()
            page_number += 1
            current_height = 20

            # Header
            painter.setFont(header_font)
            painter.drawText(
                QRectF(0, current_height, page_width, header_line_spacing),
                Qt.AlignmentFlag.AlignCenter,
                f"Cancellation-Guide  Date: {self.recovery_plan_created_at.strftime('%Y-%m-%d %H:%M:%S %Z (%z)')}  ID: {self.recovery_plan_id}  Page: {page_number}"
            )
            current_height += header_line_spacing + 20

            # Cancellation transaction title
            painter.setFont(title_font)
            painter.drawText(
                QRectF(0, current_height, page_width, title_line_spacing),
                Qt.AlignmentFlag.AlignCenter,
                "Cancellation Transaction"
            )
            current_height += title_line_spacing + 20

            # Transaction ID
            painter.setFont(subtitle_font)
            painter.drawText(
                QRectF(0, current_height, page_width, subtitle_line_spacing),
                Qt.AlignmentFlag.AlignCenter,
                f"Transaction Id: {self.cancellation_tx.txid()}"
            )
            current_height += subtitle_line_spacing + 20

            # QR Code for cancellation transaction
            qr = qrcode.QRCode(
                error_correction=qrcode.constants.ERROR_CORRECT_Q,
            )
            qr.add_data(cancellation_raw)
            qr.make()
            qr_image = self._paint_qr(qr)

            qr_width = int(page_width * 0.6)
            qr_x = (page_width - qr_width) / 2
            painter.drawImage(QRectF(qr_x, current_height, qr_width, qr_width), qr_image)
            current_height += qr_width + 40

            # Raw transaction text
            painter.setFont(body_font)
            painter.drawText(
                QRectF(20, current_height, page_width - 40, page_height),
                Qt.TextFlag.TextWrapAnywhere,
                cancellation_raw
            )

            painter.end()

            self.download_dialog.show_message(_("File saved successfully"))
        except Exception as e:
            self.logger.exception(repr(e))
            self.download_dialog.show_error(_("Error saving file"))

    def _paint_qr(self, qr):
        matrix = qr.get_matrix()
        k = len(matrix)
        border_color = Qt.GlobalColor.white
        base_img = QImage(k * 5, k * 5, QImage.Format.Format_ARGB32)
        base_img.fill(border_color)
        qrpainter = QPainter()
        qrpainter.begin(base_img)
        boxsize = 5
        size = k * boxsize
        left = (base_img.width() - size)//2
        top = (base_img.height() - size)//2
        qrpainter.setBrush(Qt.GlobalColor.black)
        qrpainter.setPen(Qt.GlobalColor.black)

        for r in range(k):
            for c in range(k):
                if matrix[r][c]:
                    qrpainter.drawRect(left+c*boxsize, top+r*boxsize, boxsize - 1, boxsize - 1)
        qrpainter.end()
        return base_img

