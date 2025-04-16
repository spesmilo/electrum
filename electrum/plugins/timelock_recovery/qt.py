'''

Timelock Recovery

Copyright:
    2025 Oren <orenz0@protonmail.com>

Distributed under the MIT software license, see the accompanying
file LICENCE or http://www.opensource.org/licenses/mit-license.php

'''

import os
import shutil
import tempfile
import uuid
import json
import hashlib
from datetime import datetime
from functools import partial
from typing import TYPE_CHECKING, Any, List, Optional, Tuple
from decimal import Decimal

import qrcode
from PyQt6.QtPrintSupport import QPrinter
from PyQt6.QtCore import Qt, QRectF, QMarginsF
from PyQt6.QtGui import (QImage, QPainter, QFont, QIntValidator, QAction,
                         QPageSize, QPageLayout, QFontMetrics)
from PyQt6.QtWidgets import (QVBoxLayout, QHBoxLayout, QLabel, QMenu, QCheckBox, QToolButton,
                             QPushButton, QLineEdit, QScrollArea, QGridLayout, QFileDialog)

from electrum import constants, version
from electrum.gui.common_qt.util import draw_qr, get_font_id
from electrum.gui.qt.paytoedit import PayToEdit
from electrum.payment_identifier import PaymentIdentifierType
from electrum.plugin import hook
from electrum.i18n import _
from electrum.transaction import PartialTxOutput
from electrum.util import make_dir
from electrum.gui.qt.util import ColorScheme, WindowModalDialog, Buttons, HelpLabel
from electrum.gui.qt.util import read_QIcon_from_bytes, read_QPixmap_from_bytes, WaitingDialog
from electrum.fee_policy import FeePolicy
from electrum.gui.qt.fee_slider import FeeSlider, FeeComboBox

from .timelock_recovery import TimelockRecoveryPlugin, TimelockRecoveryContext


if TYPE_CHECKING:
    from electrum.gui.qt import ElectrumGui
    from electrum.gui.qt.main_window import ElectrumWindow


AGREEMENT_TEXT = "I understand that using this wallet after generating a Timelock Recovery plan might break the plan"
MIN_LOCKTIME_DAYS = 2
# 0xFFFF * 512 seconds = 388.36 days.
MAX_LOCKTIME_DAYS = 388


def selectable_label(text: str) -> QLabel:
    label = QLabel(text)
    label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    return label


class FontManager:
    def __init__(self, font_name: str, resolution: int):
        pixels_per_point = resolution / 72.0
        self.header_font = QFont(font_name, 8)
        self.header_line_spacing = QFontMetrics(self.header_font).lineSpacing() * pixels_per_point
        self.title_font = QFont(font_name, 18, QFont.Weight.Bold)
        self.title_line_spacing = QFontMetrics(self.title_font).height() * pixels_per_point
        self.subtitle_font = QFont(font_name, 10)
        self.subtitle_line_spacing = QFontMetrics(self.subtitle_font).height() * pixels_per_point
        self.title_small_font = QFont(font_name, 16, QFont.Weight.Bold)
        self.title_small_line_spacing = QFontMetrics(self.title_small_font).height() * pixels_per_point
        self.body_font = QFont(font_name, 9)
        self.body_small_font = QFont(font_name, 8)
        self.body_small_line_spacing = QFontMetrics(self.body_small_font).lineSpacing() * pixels_per_point


class Plugin(TimelockRecoveryPlugin):
    base_dir: str
    _init_qt_received: bool
    font_name: str
    small_logo_bytes: bytes
    large_logo_bytes: bytes
    intro_text: str

    def __init__(self, parent, config, name: str):
        TimelockRecoveryPlugin.__init__(self, parent, config, name)
        self.base_dir = os.path.join(config.electrum_path(), 'timelock_recovery')
        make_dir(self.base_dir)

        self._init_qt_received = False
        self.font_name = 'Monospace'
        self.small_logo_bytes = self.read_file("timelock_recovery_60.png")
        self.large_logo_bytes = self.read_file("timelock_recovery_820.png")
        self.intro_text = self.read_file("intro.txt").decode('utf-8')
        plugin_metadata: Optional[dict] = parent.get_metadata('timelock_recovery')
        self.plugin_version: str = plugin_metadata['version'] if plugin_metadata else 'unknown'

    @hook
    def init_qt(self, gui: 'ElectrumGui'):
        if self._init_qt_received:  # only need/want the first signal
            return
        self._init_qt_received = True
        # load custom fonts (note: here, and not in __init__, as it needs the QApplication to be created)
        if get_font_id('PTMono-Regular.ttf') >= 0 and get_font_id('PTMono-Bold.ttf') >= 0:
            self.font_name = 'PT Mono'

    @hook
    def init_menubar(self, window):
        m = window.wallet_menu.addAction('Timelock Recovery', lambda: self.setup_dialog(window))
        icon = read_QIcon_from_bytes(self.read_file('timelock_recovery_60.png'))
        m.setIcon(icon)

    def setup_dialog(self, main_window: 'ElectrumWindow') -> bool:
        context = TimelockRecoveryContext(main_window.wallet)
        context.main_window = main_window
        if constants.net.NET_NAME == 'regtest':
            return self.create_plan_dialog(context)
        return self.create_intro_dialog(context)

    def create_intro_dialog(self, context: TimelockRecoveryContext) -> bool:
        intro_dialog = WindowModalDialog(context.main_window, "Timelock Recovery")
        intro_dialog.setContentsMargins(11, 11, 1, 1)

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
        instructions_label = selectable_label(_(f'Please type in the textbox below:\n"{AGREEMENT_TEXT}"'))

        # Create the noise scan QR text edit.
        intro_agreement_textedit = QLineEdit()

        # Create the buttons.
        intro_next_button = QPushButton(_("Next"), intro_dialog)

        # Update the UI when the text changes.
        intro_agreement_textedit.textChanged.connect(partial(self.on_agreement_edit, intro_agreement_textedit, intro_next_button))

        # Initially disable the next button.
        intro_next_button.setEnabled(False)

        # Handle clicks on the buttons.
        intro_next_button.clicked.connect(intro_dialog.close)
        intro_next_button.clicked.connect(partial(self.create_plan_dialog, context))

        # Populate the VBox layout.
        vbox_layout.addWidget(instructions_label)
        vbox_layout.addWidget(intro_agreement_textedit)
        vbox_layout.addLayout(Buttons(intro_next_button))

        # Add stretches to the end of the layouts to prevent the contents from spreading when the dialog is enlarged.
        hbox_layout.addStretch(1)
        vbox_layout.addStretch(1)

        return bool(intro_dialog.exec())

    def on_agreement_edit(self, intro_agreement_textedit: QLineEdit, intro_next_button: QPushButton):
        text = intro_agreement_textedit.text()
        intro_next_button.setEnabled(constants.net.NET_NAME == 'regtest' or text.lower() == AGREEMENT_TEXT.lower())

    def create_plan_dialog(self, context: TimelockRecoveryContext) -> bool:
        plan_dialog = WindowModalDialog(context.main_window, "Timelock Recovery")
        plan_dialog.setContentsMargins(11, 11, 1, 1)
        plan_dialog.resize(800, plan_dialog.height())

        fee_policy = FeePolicy(context.main_window.config.FEE_POLICY)
        create_cancel_cb = QCheckBox('', checked=False)
        alert_tx_label = QLabel('')
        recovery_tx_label = QLabel('')
        cancellation_tx_label = QLabel('')

        if not context.get_alert_address():
            plan_dialog.show_error(''.join([
                _("No more addresses in your wallet."), " ",
                _("You are using a non-deterministic wallet, which cannot create new addresses."), " ",
                _("If you want to create new addresses, use a deterministic wallet instead."),
            ]))
            plan_dialog.close()
            return

        plan_grid = QGridLayout()
        plan_grid.setSpacing(8)
        grid_row = 0

        next_button = QPushButton(_("Next"), plan_dialog)
        next_button.clicked.connect(plan_dialog.close)
        next_button.clicked.connect(lambda: self.start_plan(context))
        next_button.setEnabled(False)

        payto_e = PayToEdit(context.main_window.send_tab) # Reuse configuration from send tab
        payto_e.toggle_paytomany()

        context.timelock_days = 90
        timelock_days_widget = QLineEdit()
        timelock_days_widget.setValidator(QIntValidator(2, 388))
        timelock_days_widget.setText(str(context.timelock_days))

        def update_transactions():
            x = self._verify_step1_details(
                    context=context,
                    next_button=next_button,
                    payto_e=payto_e,
                    timelock_days_widget=timelock_days_widget,
            )
            view_alert_tx_button.setEnabled(x)
            view_recovery_tx_button.setEnabled(x)
            view_cancellation_tx_button.setEnabled(x)
            if not x:
                return
            context.alert_tx = tx = context.make_unsigned_alert_tx(fee_policy)
            assert all(tx_input.is_segwit() for tx_input in tx.inputs())
            alert_tx_label.setText(_("Fee: {}").format(self.config.format_amount_and_units(context.alert_tx.get_fee())))
            context.recovery_tx = context.make_unsigned_recovery_tx(fee_policy)
            assert all(tx_input.is_segwit() for tx_input in tx.inputs())
            recovery_tx_label.setText(_("Fee: {}").format(self.config.format_amount_and_units(context.recovery_tx.get_fee())))
            if not create_cancel_cb.isChecked():
                context.cancellation_tx = None
                return
            context.cancellation_tx = context.make_unsigned_cancellation_tx(fee_policy)
            assert all(tx_input.is_segwit() for tx_input in tx.inputs())
            cancellation_tx_label.setText(_("Fee: {}").format(self.config.format_amount_and_units(context.cancellation_tx.get_fee())))

        payto_e.paymentIdentifierChanged.connect(update_transactions)
        timelock_days_widget.textChanged.connect(update_transactions)

        plan_grid.addWidget(HelpLabel(
            _("Recipient of the funds"),
            (
                _("Recipient of the funds, after the cancellation time window has expired")
                + "\n\n"
                + _("This field must contain a single Bitcoin address, or multiple lines in the format: 'address, amount'.") + "\n"
                + "\n"
                + _("If multiple lines are used, at least one line must be set to 'max', using the '!' special character.") + "\n"
                + _("Integers weights can also be used in conjunction with '!', "
                    "e.g. set one amount to '2!' and another to '3!' to split your coins 40-60.")
            ),
        ), grid_row, 0)
        plan_grid.addWidget(payto_e, grid_row, 1, 1, 4)
        grid_row += 1

        plan_grid.addWidget(HelpLabel(
            _("Cancellation time-window (days)"),
            (
                _("After broadcasting the Alert Transaction, you have a limited time to cancel the transaction.") + "\n"
                + _("Value must be between {} and {} days.").format(MIN_LOCKTIME_DAYS, MAX_LOCKTIME_DAYS)
            )
        ), grid_row, 0)
        plan_grid.addWidget(timelock_days_widget, grid_row, 1)
        grid_row += 1
        plan_grid.addWidget(HelpLabel(
            _('Create a cancellation transaction'),
            '\n'.join([
                _(
                    "If the Alert transaction is has been broadcast against your intention," +
                    " you will be able to broadcast the Cancellation transaction within {} days," +
                    " to invalidate the Recovery transaction and keep the funds in this wallet" +
                    " - without the need to restore the seed of this wallet (i.e. in case you have split or hidden it)."
                ).format(context.timelock_days),
                _(
                    "However, if the seed of this wallet is lost, broadcasting the Cancellation transaction" +
                    " might lock the funds on this wallet forever."
                )
            ])
        ), grid_row, 0)
        plan_grid.addWidget(create_cancel_cb, grid_row, 1, 1, 4)
        grid_row += 1

        fee_slider = FeeSlider(
            parent=plan_dialog, network=context.main_window.network,
            fee_policy=fee_policy,
            callback=lambda x: update_transactions()
        )

        fee_combo = FeeComboBox(fee_slider)
        plan_grid.addWidget(QLabel('Fee policy'), grid_row, 0)
        plan_grid.addWidget(fee_slider, grid_row, 1)
        plan_grid.addWidget(fee_combo, grid_row, 2)
        grid_row += 1

        plan_grid.addWidget(QLabel('Alert transaction'), grid_row, 0)
        plan_grid.addWidget(alert_tx_label, grid_row, 1, 1, 3)
        view_alert_tx_button = QPushButton(_('View'))
        view_alert_tx_button.clicked.connect(lambda: context.main_window.show_transaction(context.alert_tx, show_sign_button=False, show_broadcast_button=False))
        plan_grid.addWidget(view_alert_tx_button, grid_row, 4)
        grid_row += 1

        plan_grid.addWidget(QLabel('Recovery transaction'), grid_row, 0)
        plan_grid.addWidget(recovery_tx_label, grid_row, 1, 1, 3)
        view_recovery_tx_button = QPushButton(_('View'))
        view_recovery_tx_button.clicked.connect(lambda: context.main_window.show_transaction(context.recovery_tx, show_sign_button=False, show_broadcast_button=False))
        plan_grid.addWidget(view_recovery_tx_button, grid_row, 4)
        grid_row += 1

        cancellation_label = QLabel('Cancellation transaction')
        plan_grid.addWidget(cancellation_label, grid_row, 0)
        plan_grid.addWidget(cancellation_tx_label, grid_row, 1, 1, 3)
        view_cancellation_tx_button = QPushButton(_('View'))
        view_cancellation_tx_button.clicked.connect(lambda: context.main_window.show_transaction(context.cancellation_tx, show_sign_button=False, show_broadcast_button=False))
        plan_grid.addWidget(view_cancellation_tx_button, grid_row, 4)
        grid_row += 1

        plan_grid.setRowStretch(grid_row, 1)  # Make sure the grid does not stretch
        # Create an HBox layout.  The logo will be on the left and the rest of the dialog on the right.
        hbox_layout = QHBoxLayout(plan_dialog)

        def on_cb_change(x):
            cancellation_label.setVisible(x)
            cancellation_tx_label.setVisible(x)
            view_cancellation_tx_button.setVisible(x)
            update_transactions()
        create_cancel_cb.stateChanged.connect(on_cb_change)
        # Create the logo label.
        logo_label = QLabel()

        # Set the logo label pixmap.
        logo_label.setPixmap(read_QPixmap_from_bytes(self.small_logo_bytes))

        # Align the logo label to the top left.
        logo_label.setAlignment(Qt.AlignmentFlag.AlignLeft)

        # Create a VBox layout for the main contents of the dialog.
        vbox_layout = QVBoxLayout()

        vbox_layout.addLayout(plan_grid, stretch=1)

        vbox_layout.addLayout(Buttons(next_button))

        # Populate the HBox layout.
        hbox_layout.addWidget(logo_label)
        hbox_layout.addSpacing(16)
        hbox_layout.addLayout(vbox_layout, stretch=1)

        # initialize
        on_cb_change(False)

        return bool(plan_dialog.exec())

    def _verify_step1_details(
            self,
            context: TimelockRecoveryContext, next_button: QPushButton, payto_e: PayToEdit,
            timelock_days_widget: QLineEdit) -> bool:
        context.timelock_days = None
        try:
            timelock_days_str = timelock_days_widget.text()
            timelock_days = int(timelock_days_str)
            if str(timelock_days) != timelock_days_str or timelock_days < MIN_LOCKTIME_DAYS or timelock_days > MAX_LOCKTIME_DAYS:
                raise ValueError("Timelock Days value not in range.")
            context.timelock_days = timelock_days
            timelock_days_widget.setStyleSheet(None)
            timelock_days_widget.setToolTip("")
        except ValueError:
            timelock_days_widget.setStyleSheet(ColorScheme.RED.as_stylesheet(True))
            timelock_days_widget.setToolTip("Value must be between {} and {} days.".format(MIN_LOCKTIME_DAYS, MAX_LOCKTIME_DAYS))
            next_button.setEnabled(False)
            return False
        pi = payto_e.payment_identifier
        if not pi:
            next_button.setEnabled(False)
            return False
        if not pi.is_valid():
            # Don't make background red - maybe the user did not complete typing yet.
            payto_e.setStyleSheet(ColorScheme.RED.as_stylesheet(True) if '\n' in pi.text.strip() else '')
            payto_e.setToolTip((pi.get_error() or "Invalid address.") if pi.text else "")
            next_button.setEnabled(False)
            return False
        elif pi.is_multiline():
            if not pi.is_multiline_max():
                payto_e.setStyleSheet(ColorScheme.RED.as_stylesheet(True))
                payto_e.setToolTip("At least one line must be set to max spend ('!' in the amount column).")
                next_button.setEnabled(False)
                return False
            context.outputs = pi.multiline_outputs
        else:
            if not pi.is_available() or pi.type != PaymentIdentifierType.SPK or not pi.spk_is_address:
                payto_e.setStyleSheet(ColorScheme.RED.as_stylesheet(True))
                payto_e.setToolTip("Invalid address type - must be a Bitcoin address.")
                next_button.setEnabled(False)
                return False
            scriptpubkey, is_address = pi.parse_output(pi.text.strip())
            if not is_address:
                payto_e.setStyleSheet(ColorScheme.RED.as_stylesheet(True))
                payto_e.setToolTip("Must be a valid address, not a script.")
                next_button.setEnabled(False)
                return False
            context.outputs = [PartialTxOutput(scriptpubkey=scriptpubkey, value='!')]
        payto_e.setStyleSheet(ColorScheme.GREEN.as_stylesheet(True))
        payto_e.setToolTip("")
        next_button.setEnabled(True)
        return True

    def start_plan(self, context: TimelockRecoveryContext):
        main_window = context.main_window
        wallet = main_window.wallet
        password = main_window.get_password()

        def task():
            wallet.sign_transaction(context.alert_tx, password, ignore_warnings=True)
            wallet.sign_transaction(context.recovery_tx, password, ignore_warnings=True)
            if context.cancellation_tx is not None:
                wallet.sign_transaction(context.cancellation_tx, password, ignore_warnings=True)

        def on_success(result):
            self.create_download_dialog(context)
        def on_failure(exc_info):
            main_window.on_error(exc_info)
        msg = _('Signing transaction...')
        WaitingDialog(main_window, msg, task, on_success, on_failure)


    def create_download_dialog(self, context: TimelockRecoveryContext) -> bool:
        context.recovery_plan_id = str(uuid.uuid4())
        context.recovery_plan_created_at = datetime.now().astimezone()
        download_dialog = WindowModalDialog(context.main_window, "Timelock Recovery - Download")
        download_dialog.setContentsMargins(11, 11, 1, 1)
        download_dialog.resize(800, download_dialog.height())

        # Create an HBox layout. The logo will be on the left and the rest of the dialog on the right.
        hbox_layout = QHBoxLayout(download_dialog)

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
        grid.addWidget(selectable_label(context.recovery_plan_id), line_number, 1, 1, 4)
        line_number += 1
        # Add Creation Date row
        grid.addWidget(HelpLabel(
            _("Created At"),
            _("Date and time when this recovery plan was created"),
        ), 1, 0)
        grid.addWidget(selectable_label(context.recovery_plan_created_at.strftime("%Y-%m-%d %H:%M:%S %Z (%z)")), line_number, 1, 1, 4)
        line_number += 1

        grid.addWidget(HelpLabel(
            _("Alert Address"),
            _("This address in your wallet will receive the funds when the Alert Transaction is broadcast."),
        ), line_number, 0)
        alert_address = context.get_alert_address()
        grid.addWidget(selectable_label(alert_address), line_number, 1, 1, 3)
        copy_button = QPushButton(_("Copy"))
        copy_button.clicked.connect(lambda: context.main_window.do_copy(alert_address))
        grid.addWidget(copy_button, line_number, 4)
        line_number += 1

        if context.cancellation_tx is not None:
            cancellation_address = context.get_cancellation_address()
            grid.addWidget(HelpLabel(
                _("Cancellation Address"),
                _("This address in your wallet will receive the funds when the Cancellation transaction is broadcast."),
            ), line_number, 0)
            grid.addWidget(selectable_label(cancellation_address), line_number, 1, 1, 3)
            copy_button2 = QPushButton(_("Copy"))
            copy_button2.clicked.connect(lambda: context.main_window.do_copy(cancellation_address))
            grid.addWidget(copy_button2, line_number, 4)
            line_number += 1

        grid.addWidget(HelpLabel(
            _("Alert Transaction ID"),
            _("ID of the Alert transaction"),
        ), line_number, 0)
        grid.addWidget(selectable_label(context.alert_tx.txid()), line_number, 1, 1, 3)
        line_number += 1

        grid.addWidget(HelpLabel(
            _("Recovery Transaction ID"),
            _("ID of the Recovery transaction"),
        ), line_number, 0)
        grid.addWidget(selectable_label(context.recovery_tx.txid()), line_number, 1, 1, 4)
        line_number += 1

        if context.cancellation_tx is not None:
            grid.addWidget(HelpLabel(
                _("Cancellation Transaction ID"),
                _("ID of the Cancellation transaction"),
            ), line_number, 0)
            grid.addWidget(selectable_label(context.cancellation_tx.txid()), line_number, 1, 1, 4)
            line_number += 1

        grid.setRowStretch(line_number, 1)
        # Create butttons
        recovery_menu = QMenu()
        action = QAction('Save as PDF', recovery_menu)
        action.triggered.connect(partial(self._save_recovery_plan_pdf, context, download_dialog))
        recovery_menu.addAction(action)
        action = QAction('Save as JSON', recovery_menu)
        action.triggered.connect(partial(self._save_recovery_plan_json, context, download_dialog))
        recovery_menu.addAction(action)
        recovery_button = QToolButton()
        recovery_button.setText(_("Save Recovery Plan"))
        recovery_button.setMenu(recovery_menu)
        recovery_button.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        # Save Cancellation Plan button row (if applicable)
        cancellation_menu = QMenu()
        action = QAction('Save as PDF', cancellation_menu)
        action.triggered.connect(partial(self._save_cancellation_plan_pdf, context, download_dialog))
        cancellation_menu.addAction(action)
        action = QAction('Save as JSON', cancellation_menu)
        action.triggered.connect(partial(self._save_cancellation_plan_json, context, download_dialog))
        cancellation_menu.addAction(action)
        cancellation_button = QToolButton()
        cancellation_button.setText(_("Save Cancellation Plan"))
        cancellation_button.setMenu(cancellation_menu)
        cancellation_button.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        # Add layouts to main vbox
        vbox_layout.addLayout(grid)
        vbox_layout.addStretch()
        close_button = QPushButton(_("Close"), download_dialog)
        close_button.clicked.connect(download_dialog.close)
        buttons = [recovery_button, close_button]
        if context.cancellation_tx is not None:
            buttons.insert(1, cancellation_button)
        vbox_layout.addLayout(Buttons(*buttons))
        # Populate the HBox layout.
        hbox_layout.addWidget(logo_label)
        hbox_layout.addSpacing(16)
        hbox_layout.addLayout(vbox_layout, stretch=1)

        return bool(download_dialog.exec())

    @classmethod
    def _checksum(cls, json_data: dict[str, Any]) -> str:
        # Assumes the values have a consistent json representation (not a key-value
        # object whose fields can be ordered in multiple ways).
        return hashlib.sha256(json.dumps(
            sorted(json_data.items()),
            skipkeys=False, ensure_ascii=True, check_circular=True,
            allow_nan=True, cls=None, indent=None, separators=(',', ':'),
            default=None, sort_keys=False,
        ).encode()).hexdigest()

    def _save_recovery_plan_json(self, context: TimelockRecoveryContext, download_dialog: WindowModalDialog):
        try:
            # Open a Save As dialog to get the file path
            file_path, _selected_filter = QFileDialog.getSaveFileName(
                download_dialog,
                _("Save Recovery Plan JSON..."),
                os.path.join(self.base_dir, "timelock-recovery-plan-{}.json".format(context.recovery_plan_id)),
                _("JSON files (*.json)")
            )
            if not file_path:
                return
            with open(file_path, "w") as json_file:
                json_data = {
                    "kind": "timelock-recovery-plan",
                    "id": context.recovery_plan_id,
                    "created_at": context.recovery_plan_created_at.isoformat(),
                    "plugin_version": self.plugin_version,
                    "wallet_kind": "Electrum",
                    "wallet_version": version.ELECTRUM_VERSION,
                    "wallet_name": context.wallet_name,
                    "timelock_days": context.timelock_days,
                    "anchor_amount_sats": context.ANCHOR_OUTPUT_AMOUNT_SATS,
                    "anchor_addresses": [output.address for output in context.outputs],
                    "alert_address": context.get_alert_address(),
                    "alert_inputs": [tx_input.prevout.to_str() for tx_input in context.alert_tx.inputs()],
                    "alert_tx": context.alert_tx.serialize().upper(),
                    "alert_txid": context.alert_tx.txid(),
                    "alert_fee": context.alert_tx.get_fee(),
                    "alert_weight": context.alert_tx.estimated_weight(),
                    "recovery_tx": context.recovery_tx.serialize().upper(),
                    "recovery_txid": context.recovery_tx.txid(),
                    "recovery_fee": context.recovery_tx.get_fee(),
                    "recovery_weight": context.recovery_tx.estimated_weight(),
                    "recovery_outputs": [[tx_output.address, tx_output.value] for tx_output in context.recovery_tx.outputs()],
                }
                # Simple checksum to ensure the file is not corrupted by foolish users
                json_data["checksum"] = self._checksum(json_data)
                json.dump(json_data, json_file, indent=2)
            download_dialog.show_message(_("File saved successfully"))
        except Exception as e:
            self.logger.exception(repr(e))
            download_dialog.show_error(_("Error saving file"))

    def _save_cancellation_plan_json(self, context: TimelockRecoveryContext, download_dialog: WindowModalDialog):
        try:
            # Open a Save As dialog to get the file path
            file_path, _selected_filter = QFileDialog.getSaveFileName(
                download_dialog,
                _("Save Cancellation Plan JSON..."),
                os.path.join(self.base_dir, "timelock-cancellation-plan-{}.json".format(context.recovery_plan_id)),
                _("JSON files (*.json)")
            )
            if not file_path:
                return
            with open(file_path, "w") as f:
                json_data = {
                    "kind": "timelock-cancellation-plan",
                    "id": context.recovery_plan_id,
                    "created_at": context.recovery_plan_created_at.isoformat(),
                    "plugin_version": self.plugin_version,
                    "wallet_kind": "Electrum",
                    "wallet_version": version.ELECTRUM_VERSION,
                    "wallet_name": context.wallet_name,
                    "timelock_days": context.timelock_days,
                    "alert_txid": context.alert_tx.txid(),
                    "cancellation_address": context.get_cancellation_address(),
                    "cancellation_tx": context.cancellation_tx.serialize().upper(),
                    "cancellation_txid": context.cancellation_tx.txid(),
                    "cancellation_fee": context.cancellation_tx.get_fee(),
                    "cancellation_weight": context.cancellation_tx.estimated_weight(),
                    "cancellation_amount": context.cancellation_tx.output_value(),
                }
                # Simple checksum to ensure the file is not corrupted by foolish users
                json_data["checksum"] = self._checksum(json_data)
                json.dump(json_data, f, indent=2)
            download_dialog.show_message(_("File saved successfully"))
        except Exception as e:
            self.logger.exception(repr(e))
            download_dialog.show_error(_("Error saving file"))

    def _create_pdf_printer(self, file_path: str) -> QPrinter:
        printer = QPrinter()
        printer.setResolution(600)
        printer.setPageSize(QPageSize(QPageSize.PageSizeId.A4))
        printer.setOutputFormat(QPrinter.OutputFormat.PdfFormat)
        printer.setOutputFileName(file_path)
        printer.setPageMargins(QMarginsF(20, 20, 20, 20), QPageLayout.Unit.Point)
        return printer

    def _paint_scaled_logo(self, painter: QPainter, page_width: int, current_height: float) -> int:
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
        return scaled_logo.height()

    def _save_recovery_plan_pdf(self, context: TimelockRecoveryContext, download_dialog: WindowModalDialog):
        # Open a Save As dialog to get the file path
        file_path, _selected_filter = QFileDialog.getSaveFileName(
            download_dialog,
            _("Save Recovery Plan PDF..."),
            os.path.join(self.base_dir, "timelock-recovery-plan-{}.pdf".format(context.recovery_plan_id)),
            _("PDF files (*.pdf)")
        )
        if not file_path:
            return

        painter = QPainter()
        temp_file_path: Optional[str] = None

        try:
            with tempfile.NamedTemporaryFile(dir=os.path.dirname(file_path), prefix=f"{os.path.basename(file_path)}-", delete=False) as temp_file:
                temp_file_path = temp_file.name
            printer = self._create_pdf_printer(temp_file_path)
            if not painter.begin(printer):
                return
            self._paint_recovery_plan_pdf(context, painter, printer)
            painter.end()
            shutil.move(temp_file_path, file_path)
            download_dialog.show_message(_("File saved successfully"))
        except (IOError, MemoryError) as e:
            self.logger.exception(repr(e))
            download_dialog.show_error(_("Error saving file"))
            if temp_file_path is not None and os.path.exists(temp_file_path):
                os.remove(temp_file_path)
        finally:
            if painter.isActive():
                painter.end()

    def _paint_recovery_plan_pdf(self, context: TimelockRecoveryContext, painter: QPainter, printer: QPrinter):
        font_manager = FontManager(self.font_name, printer.resolution())

        # Get page dimensions
        page_rect = printer.pageRect(QPrinter.Unit.DevicePixel)
        page_width = page_rect.width()
        page_height = page_rect.height()

        current_height = 0
        page_number = 1

        # Header
        painter.setFont(font_manager.header_font)
        painter.drawText(
            QRectF(0, 0, page_width, font_manager.header_line_spacing + 20),
            Qt.AlignmentFlag.AlignHCenter,
            f"Recovery-Guide  Date: {context.recovery_plan_created_at.strftime('%Y-%m-%d %H:%M:%S %Z (%z)')}  ID: {context.recovery_plan_id}  Page: {page_number}",
        )
        current_height += font_manager.header_line_spacing + 40

        current_height += self._paint_scaled_logo(painter, page_width, current_height) + 40

        # Title
        painter.setFont(font_manager.title_font)
        painter.drawText(QRectF(0, current_height, page_width, font_manager.title_line_spacing + 20), Qt.AlignmentFlag.AlignHCenter, "Timelock-Recovery Guide")
        current_height += font_manager.title_line_spacing + 20

        # Subtitle
        painter.setFont(font_manager.subtitle_font)
        painter.drawText(
            QRectF(0, current_height, page_width, font_manager.subtitle_line_spacing + 20), Qt.AlignmentFlag.AlignCenter,
            f"Electrum Version: {version.ELECTRUM_VERSION} - Plugin Version: {self.plugin_version}"
        )
        current_height += font_manager.subtitle_line_spacing + 60

        # Main content
        recovery_tx_outputs = context.recovery_tx.outputs()
        painter.setFont(font_manager.body_font)
        intro_text = (
            f"This document will guide you through the process of recovering the funds on wallet: {context.wallet_name}. "
            f"The process will take at least {context.timelock_days} days, and will eventually send the following amount "
            f"to the following {'address' if len(recovery_tx_outputs) == 1 else 'addresses'}:\n\n"
            + '\n'.join(f'• {output.address}: {context.main_window.config.format_amount_and_units(output.value)}' for output in recovery_tx_outputs) + "\n\n"
            f"Before proceeding, MAKE SURE THAT YOU HAVE ACCESS TO THE {'WALLET OF THIS ADDRESS' if len(recovery_tx_outputs) == 1 else 'WALLETS OF THESE ADDRESSES'}, "
            f"OR TRUST THE {'OWNER OF THIS ADDRESS' if len(recovery_tx_outputs) == 1 else 'OWNERS OF THESE ADDRESSES'}. "
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
        painter.setFont(font_manager.title_small_font)
        painter.drawText(
            QRectF(0, current_height, page_width, font_manager.title_small_line_spacing + 20),Qt.AlignmentFlag.AlignLeft,
            "Step 1 - Broadcasting the Alert transaction",
        )
        current_height += font_manager.title_small_line_spacing + 20

        painter.setFont(font_manager.body_font)
        # Calculate number of anchors
        num_anchors = len(context.alert_tx.outputs()) - 1

        # Split alert tx into parts if needed
        alert_raw = context.alert_tx.serialize().upper()
        if len(alert_raw) < 2300:
            alert_raw_parts = [alert_raw]
        else:
            alert_raw_parts = []
            for i in range(0, len(alert_raw), 2100):
                alert_raw_parts.append(alert_raw[i:i+2100])

        # Step 1 explanation text
        step1_text = (
            f"The first step is to broadcast the Alert transaction. "
            f"This transaction will keep most funds in the same wallet {context.wallet_name}, "
        )

        if num_anchors > 0:
            step1_text += (
                f"except for 600 sats that will be sent to "
                f"{'each of the following addresses' if num_anchors > 1 else 'the following address'} "
                f"(and can be used in case you need to accelerate the transaction via Child-Pay-For-Parent, "
                f"as we'll explain later):\n"
            )
            for output in context.alert_tx.outputs():
                if output.address != context.get_alert_address() and output.value == context.ANCHOR_OUTPUT_AMOUNT_SATS:
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
            f"You should then see a success message for broadcasting transaction-id: {context.alert_tx.txid()}"
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
            painter.setFont(font_manager.header_font)
            painter.drawText(
                QRectF(0, current_height, page_width, font_manager.header_line_spacing),
                Qt.AlignmentFlag.AlignCenter,
                f"Recovery-Guide  Date: {context.recovery_plan_created_at.strftime('%Y-%m-%d %H:%M:%S %Z (%z)')}  ID: {context.recovery_plan_id}  Page: {page_number}"
            )
            current_height += font_manager.header_line_spacing + 20

            # Title
            painter.setFont(font_manager.title_font)
            painter.drawText(
                QRectF(0, current_height, page_width, font_manager.title_line_spacing),
                Qt.AlignmentFlag.AlignCenter,
                "Alert Transaction"
            )
            current_height += font_manager.title_line_spacing + 20

            # Transaction ID
            painter.setFont(font_manager.subtitle_font)
            painter.drawText(
                QRectF(0, current_height, page_width, font_manager.subtitle_line_spacing),
                Qt.AlignmentFlag.AlignCenter,
                f"Transaction Id: {context.alert_tx.txid()}"
            )
            current_height += font_manager.subtitle_line_spacing + 20

            # Part number if multiple parts
            if len(alert_raw_parts) > 1:
                painter.setFont(font_manager.subtitle_font)
                painter.drawText(
                    QRectF(0, current_height, page_width, font_manager.subtitle_line_spacing),
                    Qt.AlignmentFlag.AlignCenter,
                    f"Part {i+1} of {len(alert_raw_parts)}"
                )
                current_height += font_manager.subtitle_line_spacing + 20

            # QR Code
            qr = qrcode.main.QRCode(
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
            painter.setFont(font_manager.body_font)
            painter.drawText(
                QRectF(20, current_height, page_width, page_height - current_height),
                Qt.TextFlag.TextWrapAnywhere,
                alert_part
            )

        printer.newPage()
        page_number += 1
        current_height = 20
        # Header
        painter.setFont(font_manager.header_font)
        painter.drawText(
            QRectF(0, current_height, page_width, font_manager.header_line_spacing),
            Qt.AlignmentFlag.AlignCenter,
            f"Recovery-Guide  Date: {context.recovery_plan_created_at.strftime('%Y-%m-%d %H:%M:%S %Z (%z)')}  ID: {context.recovery_plan_id}  Page: {page_number}"
        )
        current_height += font_manager.header_line_spacing + 20

        # Step 2 page
        painter.setFont(font_manager.title_small_font)
        painter.drawText(QRectF(20, current_height, page_width, font_manager.title_small_line_spacing), Qt.AlignmentFlag.AlignLeft, "Step 2 - Waiting for the Alert transaction confirmation")
        current_height += font_manager.title_small_line_spacing + 20

        painter.setFont(font_manager.body_font)
        painter.drawText(QRectF(20, current_height, page_width, font_manager.subtitle_line_spacing), Qt.AlignmentFlag.AlignLeft, "You can follow the Alert transaction via any of the following links:")
        current_height += font_manager.subtitle_line_spacing + 20

        # QR codes and links for transaction tracking
        for link in [f"https://mempool.space/tx/{context.alert_tx.txid()}", f"https://blockstream.info/tx/{context.alert_tx.txid()}"]:
            qr = qrcode.main.QRCode(
                error_correction=qrcode.constants.ERROR_CORRECT_H,
            )
            qr.add_data(link)
            qr.make()
            qr_image = self._paint_qr(qr)

            qr_width = int(page_width * 0.2)
            qr_x = (page_width - qr_width) / 2
            painter.drawImage(QRectF(qr_x, current_height, qr_width, qr_width), qr_image)
            current_height += qr_width + 20

            painter.setFont(font_manager.body_small_font)
            painter.drawText(QRectF(0, current_height, page_width, font_manager.body_small_line_spacing), Qt.AlignmentFlag.AlignCenter, link)
            current_height += font_manager.body_small_line_spacing + 20

        # Explanation text
        painter.setFont(font_manager.body_font)
        explanation_text = (
            "Please wait for a while until the transaction is marked as \"confirmed\" (number of confirmations greater than 0). "
            "The time that takes a transaction to confirm depends on the fee that it pays, compared to the fee that other "
            "pending transactions are willing to pay. At the time this document was created, it was hard to predict what a "
            "reasonable fee would be today. If the transaction is not confirmed after 24 hours, you may try paying to a "
            "Transaction Acceleration service, such as the one offered by: https://mempool.space.com ."
        )
        if len(context.outputs) > 0:
            explanation_text += (
                f" Another solution, which may be cheaper but requires more technical skill, would be to use"
                f"{' one of the wallets that receive 600 sats (addresses mentioned in Step 1),' if len(context.outputs) > 1 else ' the wallet that receive 600 sats (address mentioned in Step 1),'}"
                " and send a high-fee transaction that includes that 600 sats UTXO (this transaction could also be from the"
                " wallet to itself). For more information, visit: https://timelockrecovery.com ."
            )

        drawn_rect = painter.drawText(QRectF(20, current_height, page_width, page_height - current_height), Qt.TextFlag.TextWordWrap, explanation_text)
        current_height += drawn_rect.height() + 40

        # Step 3 header
        painter.setFont(font_manager.title_small_font)
        painter.drawText(QRectF(20, current_height, page_width, font_manager.title_small_line_spacing), Qt.AlignmentFlag.AlignLeft, "Step 3 - Broadcasting the Recovery transaction")
        current_height += font_manager.title_small_line_spacing + 20

        # Split recovery transaction if needed
        recovery_raw = context.recovery_tx.serialize().upper()
        recovery_raw_parts = [recovery_raw[i:i+2100] for i in range(0, len(recovery_raw), 2100)] if len(recovery_raw) > 2300 else [recovery_raw]

        # Step 3 explanation
        painter.setFont(font_manager.body_font)
        step3_text = (
            f"Approximately {context.timelock_days} days after the Alert transaction has been confirmed, you "
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
            painter.setFont(font_manager.header_font)
            painter.drawText(
                QRectF(0, current_height, page_width, font_manager.header_line_spacing),
                Qt.AlignmentFlag.AlignCenter,
                f"Recovery-Guide  Date: {context.recovery_plan_created_at.strftime('%Y-%m-%d %H:%M:%S %Z (%z)')}  ID: {context.recovery_plan_id}  Page: {page_number}"
            )
            current_height += font_manager.header_line_spacing + 20

            # Title
            painter.setFont(font_manager.title_font)
            painter.drawText(
                QRectF(0, current_height, page_width, font_manager.title_line_spacing),
                Qt.AlignmentFlag.AlignCenter,
                "Recovery Transaction"
            )
            current_height += font_manager.title_line_spacing + 20

            # Transaction ID
            painter.setFont(font_manager.subtitle_font)
            painter.drawText(
                QRectF(0, current_height, page_width, font_manager.subtitle_line_spacing),
                Qt.AlignmentFlag.AlignCenter,
                f"Transaction Id: {context.recovery_tx.txid()}"
            )
            current_height += font_manager.subtitle_line_spacing + 20

            # Part number if multiple parts
            if len(recovery_raw_parts) > 1:
                painter.setFont(font_manager.subtitle_font)
                painter.drawText(
                    QRectF(0, current_height, page_width, font_manager.subtitle_line_spacing),
                    Qt.AlignmentFlag.AlignCenter,
                    f"Part {i+1} of {len(recovery_raw_parts)}"
                )
                current_height += font_manager.subtitle_line_spacing + 20

            # QR Code
            qr = qrcode.main.QRCode(
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
            painter.setFont(font_manager.body_font)
            painter.drawText(
                QRectF(20, current_height, page_width, page_height - current_height),
                Qt.TextFlag.TextWrapAnywhere,
                recovery_part
            )

    def _save_cancellation_plan_pdf(self, context: TimelockRecoveryContext, download_dialog: WindowModalDialog):
        # Open a Save As dialog to get the file path
        file_path, _selected_filter = QFileDialog.getSaveFileName(
            download_dialog,
            _("Save Cancellation Plan PDF..."),
            os.path.join(self.base_dir, "timelock-cancellation-plan-{}.pdf".format(context.recovery_plan_id)),
            _("PDF files (*.pdf)")
        )
        if not file_path:
            return

        painter = QPainter()
        temp_file_path: Optional[str] = None

        try:
            with tempfile.NamedTemporaryFile(dir=os.path.dirname(file_path), prefix=f"{os.path.basename(file_path)}-", delete=False) as temp_file:
                temp_file_path = temp_file.name
            printer = self._create_pdf_printer(temp_file_path)
            if not painter.begin(printer):
                return
            self._paint_cancellation_plan_pdf(context, painter, printer)
            painter.end()
            shutil.move(temp_file_path, file_path)
            download_dialog.show_message(_("File saved successfully"))
        except (IOError, MemoryError) as e:
            self.logger.exception(repr(e))
            download_dialog.show_error(_("Error saving file"))
            if temp_file_path is not None and os.path.exists(temp_file_path):
                os.remove(temp_file_path)
        finally:
            if painter.isActive():
                painter.end()

    def _paint_cancellation_plan_pdf(self, context: TimelockRecoveryContext, painter: QPainter, printer: QPrinter):
        cancellation_raw = context.cancellation_tx.serialize().upper()
        if len(cancellation_raw) > 2300:
            # Splitting the cancellation transaction into multiple QR codes is not implemented
            # because it is unexpected to happen anyways.
            raise Exception("Cancellation transaction is too large to be saved as a single QR code")

        font_manager = FontManager(self.font_name, printer.resolution())

        # Get page dimensions
        page_rect = printer.pageRect(QPrinter.Unit.DevicePixel)
        page_width = page_rect.width()
        page_height = page_rect.height()

        current_height = 0
        page_number = 1

        # Header
        painter.setFont(font_manager.header_font)
        painter.drawText(
            QRectF(0, current_height, page_width, font_manager.header_line_spacing),
            Qt.AlignmentFlag.AlignCenter,
            f"Cancellation-Guide  Date: {context.recovery_plan_created_at.strftime('%Y-%m-%d %H:%M:%S %Z (%z)')}  ID: {context.recovery_plan_id}  Page: {page_number}"
        )
        current_height += font_manager.header_line_spacing + 40

        current_height += self._paint_scaled_logo(painter, page_width, current_height) + 40

        # Title
        painter.setFont(font_manager.title_font)
        painter.drawText(
            QRectF(0, current_height, page_width, font_manager.title_line_spacing),
            Qt.AlignmentFlag.AlignCenter,
            "Timelock-Recovery Cancellation Guide"
        )
        current_height += font_manager.title_line_spacing + 20

        # Subtitle
        painter.setFont(font_manager.subtitle_font)
        painter.drawText(
            QRectF(0, current_height, page_width, font_manager.subtitle_line_spacing + 20), Qt.AlignmentFlag.AlignCenter,
            f"Electrum Version: {version.ELECTRUM_VERSION} - Plugin Version: {self.plugin_version}"
        )
        current_height += font_manager.subtitle_line_spacing + 60

        # Main text
        painter.setFont(font_manager.body_font)
        explanation_text = (
            f"This document is intended solely for the eyes of the owner of wallet: {context.wallet_name}. "
            f"The Recovery Guide (the other document) will allow to transfer the funds from this wallet to "
            f"a different wallet within {context.timelock_days} days. To prevent this from happening accidentally "
            f"or maliciously by someone who found that document, you should periodically check if the Alert "
            f"transaction has been broadcast, using a Bitcoin block-explorer website such as:"
        )
        drawn_rect = painter.drawText(
            QRectF(20, current_height, page_width - 40, page_height),
            Qt.TextFlag.TextWordWrap,
            explanation_text
        )
        current_height += drawn_rect.height() + 40

        # QR codes and links for transaction tracking
        for link in [f"https://mempool.space/tx/{context.alert_tx.txid()}", f"https://blockstream.info/tx/{context.alert_tx.txid()}"]:
            qr = qrcode.main.QRCode(
                error_correction=qrcode.constants.ERROR_CORRECT_H,
            )
            qr.add_data(link)
            qr.make()
            qr_image = self._paint_qr(qr)

            qr_width = int(page_width * 0.2)
            qr_x = (page_width - qr_width) / 2
            painter.drawImage(QRectF(qr_x, current_height, qr_width, qr_width), qr_image)
            current_height += qr_width + 20

            painter.setFont(font_manager.body_small_font)
            painter.drawText(
                QRectF(0, current_height, page_width, font_manager.body_small_line_spacing),
                Qt.AlignmentFlag.AlignCenter,
                link
            )
            current_height += font_manager.body_small_line_spacing + 20

        # Watch tower text
        painter.setFont(font_manager.body_font)
        drawn_rect = painter.drawText(
            QRectF(20, current_height, page_width - 40, page_height - current_height),
            Qt.TextFlag.TextWordWrap,
            "It is also recommended to use a Watch-Tower service that will notify you immediately if the"
            " Alert transaction has been broadcast. For more details, visit: https://timelockrecovery.com ."
        )
        current_height += drawn_rect.height() + 40

        # Cancellation transaction section
        cancellation_text = (
            "In case the Alert transaction has been broadcast, and you want to stop the funds from "
            "leaving this wallet, you can scan the QR code on page 2, and broadcast "
            "the content using one of the following Bitcoin block-explorer websites:\n\n"
            "• https://mempool.space/tx/push\n"
            "• https://blockstream.info/tx/push\n"
            "• https://coinb.in/#broadcast\n\n"
            "If the transaction is not confirmed within reasonable time due to a low fee, you will have "
            "to access the wallet and use Replace-By-Fee/Child-Pay-For-Parent to move the funds to a new "
            "address on your wallet. (you can also pay to an Acceleration Service such as the one offered "
            "by https://mempool.space)\n\n"
            f"IMPORTANT NOTICE: If you lost the keys to access wallet {context.wallet_name} - do not broadcast the "
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
        painter.setFont(font_manager.header_font)
        painter.drawText(
            QRectF(0, current_height, page_width, font_manager.header_line_spacing),
            Qt.AlignmentFlag.AlignCenter,
            f"Cancellation-Guide  Date: {context.recovery_plan_created_at.strftime('%Y-%m-%d %H:%M:%S %Z (%z)')}  ID: {context.recovery_plan_id}  Page: {page_number}"
        )
        current_height += font_manager.header_line_spacing + 20

        # Cancellation transaction title
        painter.setFont(font_manager.title_font)
        painter.drawText(
            QRectF(0, current_height, page_width, font_manager.title_line_spacing),
            Qt.AlignmentFlag.AlignCenter,
            "Cancellation Transaction"
        )
        current_height += font_manager.title_line_spacing + 20

        # Transaction ID
        painter.setFont(font_manager.subtitle_font)
        painter.drawText(
            QRectF(0, current_height, page_width, font_manager.subtitle_line_spacing),
            Qt.AlignmentFlag.AlignCenter,
            f"Transaction Id: {context.cancellation_tx.txid()}"
        )
        current_height += font_manager.subtitle_line_spacing + 20

        # QR Code for cancellation transaction
        qr = qrcode.main.QRCode(
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
        painter.setFont(font_manager.body_font)
        painter.drawText(
            QRectF(20, current_height, page_width - 40, page_height),
            Qt.TextFlag.TextWrapAnywhere,
            cancellation_raw
        )

    @classmethod
    def _paint_qr(cls, qr: qrcode.main.QRCode) -> QImage:
        k = len(qr.get_matrix())
        base_img = QImage(k * 5, k * 5, QImage.Format.Format_ARGB32)
        draw_qr(qr=qr, paint_device=base_img)
        return base_img
