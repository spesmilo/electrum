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
                             QPushButton, QLineEdit, QScrollArea)

from electrum.plugin import hook
from electrum.i18n import _
from electrum.util import make_dir
from electrum.gui.qt.util import (WindowModalDialog, Buttons, CloseButton)
from electrum.gui.qt.main_window import StatusBarButton
from electrum.gui.qt.util import read_QIcon_from_bytes, read_QPixmap_from_bytes

from .timelock_recovery import TimelockRecoveryPlugin


if TYPE_CHECKING:
    from electrum.gui.qt import ElectrumGui

agreement_text = "I understand that using this wallet after generating a Timelock Recovery plan might break the plan"

class Plugin(TimelockRecoveryPlugin):
    def __init__(self, parent, config, name):
        TimelockRecoveryPlugin.__init__(self, parent, config, name)
        self.base_dir = os.path.join(config.electrum_path(), 'timelock_recovery')
        make_dir(self.base_dir)

        self.extension = False
        self._init_qt_received = False
        self.icon_bytes = self.read_file("timelock_recovery.png")
        self.intro_text = self.read_file("intro.txt").decode('utf-8')

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
            partial(self.create_setup_dialog, sb), sb.height())
        sb.addPermanentWidget(b)

    def requires_settings(self):
        return False

    def create_setup_dialog(self, window):
        self.wallet = window.parent().wallet
        self.update_wallet_name(self.wallet)

        self.setup_dialog = WindowModalDialog(window, "Timelock Recovery")
        self.setup_dialog.setContentsMargins(11,11,1,1)

        # Create an HBox layout.  The logo will be on the left and the rest of the dialog on the right.
        hbox_layout = QHBoxLayout(self.setup_dialog)

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
        instructions_label = QLabel(_(f'Please type in the textbox below:\n"{agreement_text}"'))

        # Create the noise scan QR text edit.
        self.agreement_textedit = QLineEdit()

        # Update the UI when the text changes.
        self.agreement_textedit.textChanged.connect(self.on_agreement_edit)

        # Allow users to select text in the labels.
        instructions_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)

        # Create the buttons.
        self.next_button = QPushButton(_("Next"), self.setup_dialog)

        # Initially disable the next button.
        self.next_button.setEnabled(False)

        # Handle clicks on the buttons.
        self.next_button.clicked.connect(self.setup_dialog.close)
        self.next_button.clicked.connect(partial(self.create_step1_dialog, window))

        # Populate the VBox layout.
        vbox_layout.addWidget(instructions_label)
        vbox_layout.addWidget(self.agreement_textedit)
        vbox_layout.addLayout(Buttons(self.next_button))

        # Add stretches to the end of the layouts to prevent the contents from spreading when the dialog is enlarged.
        hbox_layout.addStretch(1)
        vbox_layout.addStretch(1)

        return bool(self.setup_dialog.exec())

    def on_agreement_edit(self):
        text = self.agreement_textedit.text()
        self.next_button.setEnabled(bool(text.lower() == agreement_text.lower()))

    def create_step1_dialog(self, window):
        self.step1_dialog = WindowModalDialog(window, "Timelock Recovery - Step 1")
        self.step1_dialog.setContentsMargins(11, 11, 1, 1)

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

        # Populate the HBox layout.
        hbox_layout.addWidget(logo_label)
        hbox_layout.addSpacing(16)
        hbox_layout.addLayout(vbox_layout)

        vbox_layout.addLayout(Buttons(CloseButton(self.step1_dialog)))

        # Add stretches to the end of the layouts to prevent the contents from spreading when the dialog is enlarged.
        hbox_layout.addStretch(1)
        vbox_layout.addStretch(1)

        return bool(self.step1_dialog.exec())

    def update_wallet_name(self, name):
        self.wallet_name = str(name)

