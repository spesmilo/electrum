'''

Timelock Recovery

Copyright:
    2025 Oren <orenz0@protonmail.com>

Distributed under the MIT software license, see the accompanying
file LICENCE or http://www.opensource.org/licenses/mit-license.php

'''

import os
from functools import partial
from typing import TYPE_CHECKING

from PyQt6.QtCore import Qt
from PyQt6.QtGui import (QFontDatabase, QFont)
from PyQt6.QtWidgets import (QVBoxLayout, QHBoxLayout, QLabel,
                             QPushButton, QLineEdit, QScrollArea, QGridLayout)

from electrum import constants
from electrum.gui.qt.paytoedit import PayToEdit
from electrum.payment_identifier import PaymentIdentifierType
from electrum.plugin import hook
from electrum.i18n import _
from electrum.transaction import PartialTxOutput
from electrum.util import make_dir
from electrum.gui.qt.util import (ColorScheme, WindowModalDialog, Buttons, CloseButton, HelpLabel)
from electrum.gui.qt.main_window import StatusBarButton
from electrum.gui.qt.util import read_QIcon_from_bytes, read_QPixmap_from_bytes

from .timelock_recovery import TimelockRecoveryPlugin


if TYPE_CHECKING:
    from electrum.gui.qt import ElectrumGui

agreement_text = "I understand that using this wallet after generating a Timelock Recovery plan might break the plan"
alert_address_label = "Timelock Recovery Alert Address"

def selectable_label(text):
    label = QLabel(text)
    label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    return label

class Plugin(TimelockRecoveryPlugin):
    def __init__(self, parent, config, name):
        TimelockRecoveryPlugin.__init__(self, parent, config, name)
        self.base_dir = os.path.join(config.electrum_path(), 'timelock_recovery')
        make_dir(self.base_dir)

        self.extension = False
        self._init_qt_received = False
        self.icon_bytes = self.read_file("timelock_recovery.png")
        self.intro_text = self.read_file("intro.txt").decode('utf-8')
        self.destinations = None

    @hook
    def init_qt(self, gui: 'ElectrumGui'):
        if self._init_qt_received:  # only need/want the first signal
            return
        self._init_qt_received = True
        # load custom fonts (note: here, and not in __init__, as it needs the QApplication to be created)
        QFontDatabase.addApplicationFont(os.path.join(os.path.dirname(__file__), 'DejaVuSansMono-Bold.ttf'))

    @hook
    def create_status_bar(self, sb):
        b = StatusBarButton(
            read_QIcon_from_bytes(self.icon_bytes),
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
        self.intro_dialog = WindowModalDialog(window, "Timelock Recovery")
        self.intro_dialog.setContentsMargins(11,11,1,1)

        # Create an HBox layout.  The logo will be on the left and the rest of the dialog on the right.
        hbox_layout = QHBoxLayout(self.intro_dialog)

        # Create the logo label.
        logo_label = QLabel()

        # Set the logo label pixmap.
        logo_label.setPixmap(read_QPixmap_from_bytes(self.icon_bytes))

        # Align the logo label to the top left.
        logo_label.setAlignment(Qt.AlignmentFlag.AlignLeft)

        # Create a VBox layout for the main contents of the dialog.
        vbox_layout = QVBoxLayout()

        # Populate the HBox layout with spacing between the two columns.
        hbox_layout.addWidget(logo_label)
        hbox_layout.addSpacing(16)
        hbox_layout.addLayout(vbox_layout)

        title_label = QLabel(_("What Is Timelock Recovery?"))
        title_label.setFont(QFont('DejaVu Sans Mono', 20, QFont.Weight.Bold))
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
        self.intro_next_button = QPushButton(_("Next"), self.intro_dialog)

        # Initially disable the next button.
        self.intro_next_button.setEnabled(False)

        # Handle clicks on the buttons.
        self.intro_next_button.clicked.connect(self.intro_dialog.close)
        self.intro_next_button.clicked.connect(partial(self.create_step1_dialog, window))

        # Populate the VBox layout.
        vbox_layout.addWidget(instructions_label)
        vbox_layout.addWidget(self.intro_agreement_textedit)
        vbox_layout.addLayout(Buttons(self.intro_next_button))

        # Add stretches to the end of the layouts to prevent the contents from spreading when the dialog is enlarged.
        hbox_layout.addStretch(1)
        vbox_layout.addStretch(1)

        return bool(self.intro_dialog.exec())

    def on_agreement_edit(self):
        text = self.intro_agreement_textedit.text()
        self.intro_next_button.setEnabled(constants.net.NET_NAME == 'regtest' or text.lower() == agreement_text.lower())

    def get_alert_address(self):
        for addr in self.wallet.get_unused_addresses():
            label = self.wallet.get_label_for_address(addr)
            if label == alert_address_label:
                return addr
        for addr in self.wallet.get_unused_addresses():
            label = self.wallet.get_label_for_address(addr)
            if label == '':
                self.wallet.set_label(addr, alert_address_label)
                return addr
        if self.wallet.is_deterministic():
            addr = self.wallet.create_new_address(False)
            self.wallet.set_label(addr, alert_address_label)
        return None


    def create_step1_dialog(self, window):
        self.step1_dialog = WindowModalDialog(window, "Timelock Recovery - Step 1")
        self.step1_dialog.setContentsMargins(11, 11, 1, 1)
        self.step1_dialog.resize(800, self.step1_dialog.height())

        self.alert_address = self.get_alert_address()
        if not self.alert_address:
            self.step1_dialog.show_error(''.join([
                _('No more addresses in your wallet.'), ' ',
                _('You are using a non-deterministic wallet, which cannot create new addresses.'), ' ',
                _('If you want to create new addresses, use a deterministic wallet instead.'),
            ]))
            self.step1_dialog.close()
            return

        self.step1_grid = QGridLayout()
        self.step1_grid.setSpacing(8)
        self.step1_grid.setColumnStretch(3, 1)
        self.step1_grid.setRowStretch(2, 1)

        self.step1_grid.addWidget(HelpLabel(
            _("Alert Address"),
            _("This address in your wallet will receive the funds when the Alert Transaction is broadcasted."),
        ), 0, 0)
        self.step1_grid.addWidget(selectable_label(self.alert_address), 0, 1, 1, 4)

        self.payto_e = PayToEdit(window.parent().send_tab) # Reuse configuration from send tab
        self.payto_e.toggle_paytomany()
        self.payto_e.paymentIdentifierChanged.connect(self._handle_payment_identifier)
        self.step1_grid.addWidget(HelpLabel(
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
        self.step1_grid.addWidget(self.payto_e, 1, 1, 1, 4)

        # Create an HBox layout.  The logo will be on the left and the rest of the dialog on the right.
        hbox_layout = QHBoxLayout(self.step1_dialog)

        # Create the logo label.
        logo_label = QLabel()

        # Set the logo label pixmap.
        logo_label.setPixmap(read_QPixmap_from_bytes(self.icon_bytes))

        # Align the logo label to the top left.
        logo_label.setAlignment(Qt.AlignmentFlag.AlignLeft)

        # Create a VBox layout for the main contents of the dialog.
        vbox_layout = QVBoxLayout()

        vbox_layout.addLayout(self.step1_grid, stretch=1)

        self.step1_next_button = QPushButton(_("Next"), self.step1_dialog)
        self.step1_next_button.clicked.connect(self.step1_dialog.close)
        self.step1_next_button.setEnabled(False)
        # self.step1_next_button.clicked.connect(partial(self.create_step2_dialog, window))

        vbox_layout.addLayout(Buttons(self.step1_next_button))

        # Populate the HBox layout.
        hbox_layout.addWidget(logo_label)
        hbox_layout.addSpacing(16)
        hbox_layout.addLayout(vbox_layout, stretch=1)

        return bool(self.step1_dialog.exec())

    def _handle_payment_identifier(self):
        self.destinations = None
        pi = self.payto_e.payment_identifier
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
            self.destinations = pi.multiline_outputs
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
            self.destinations = [PartialTxOutput(scriptpubkey=scriptpubkey, value='!')]
        self.payto_e.setStyleSheet(ColorScheme.GREEN.as_stylesheet(True))
        self.payto_e.setToolTip("")
        self.step1_next_button.setEnabled(True)

