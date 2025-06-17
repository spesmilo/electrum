#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2025 The Electrum Developers
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
from typing import TYPE_CHECKING, Optional
from functools import partial
from datetime import datetime

from PyQt6.QtWidgets import (
    QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QTreeWidget, QTreeWidgetItem,
    QTextEdit, QApplication, QSpinBox, QSizePolicy, QComboBox, QLineEdit,
)
from PyQt6.QtGui import QPixmap, QImage
from PyQt6.QtCore import Qt

from electrum.i18n import _
from electrum.plugin import hook
from electrum.gui.qt.util import (
    WindowModalDialog, Buttons, OkButton, CancelButton, CloseButton,
    read_QIcon_from_bytes, read_QPixmap_from_bytes,
)
from electrum.gui.common_qt.util import paintQR

from .nwcserver import NWCServerPlugin

if TYPE_CHECKING:
    from electrum.wallet import Abstract_Wallet
    from electrum.gui.qt.main_window import ElectrumWindow


class Plugin(NWCServerPlugin):
    def __init__(self, *args):
        NWCServerPlugin.__init__(self, *args)
        self._init_qt_received = False

    @hook
    def load_wallet(self, wallet: 'Abstract_Wallet', window: 'ElectrumWindow'):
        if not wallet.has_lightning():
            return
        self.start_plugin(wallet)

    @hook
    def init_menubar(self, window):
        ma = window.wallet_menu.addAction('Nostr Wallet Connect', partial(self.settings_dialog, window))
        icon = read_QIcon_from_bytes(self.read_file('nwc.png'))
        ma.setIcon(icon)

    def settings_dialog(self, window: WindowModalDialog):
        if not self.initialized:
            window.show_error(
                _("{} plugin requires a lightning enabled wallet. Open a lightning-enabled wallet first.")
                .format("NWC"))
            return
        if window.wallet != self.nwc_server.wallet:
            window.show_error('not using this wallet')
            return

        d = WindowModalDialog(window, _("Nostr Wallet Connect"))
        main_layout = QHBoxLayout(d)

        # Create the logo label.
        logo_label = QLabel()
        pixmap = read_QPixmap_from_bytes(self.read_file('nwc.png'))
        logo_label.setPixmap(pixmap.scaled(50, 50))
        logo_label.setAlignment(Qt.AlignmentFlag.AlignLeft)

        vbox = QVBoxLayout()
        main_layout.addWidget(logo_label)
        main_layout.addSpacing(16)
        main_layout.addLayout(vbox)

        # Connections list
        connections_list = QTreeWidget()
        connections_list.setHeaderLabels([_("Name"), _("Budget [{}]").format(self.config.get_base_unit()), _("Expiry")])
        # Set the resize mode for all columns to adjust to content
        header = connections_list.header()
        header.setSectionResizeMode(0, header.ResizeMode.Stretch)
        header.setSectionResizeMode(1, header.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, header.ResizeMode.ResizeToContents)
        header.setStretchLastSection(False)
        # Set size policy to expand horizontally
        connections_list.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)
        # Make the widget update its size when data changes
        connections_list.setAutoExpandDelay(0)

        def update_connections_list():
            # Clear the list and repopulate it
            connections_list.clear()
            connections = self.list_connections()
            for name, conn in connections.items():
                if conn['valid_until'] == 'unset':
                    expiry = _("never")
                else:
                    expiry = datetime.fromtimestamp(conn['valid_until']).isoformat(' ')[:-3]
                if conn['daily_limit_sat'] == 'unset':
                    limit = _('unlimited')
                else:
                    budget = self.config.format_amount(conn['daily_limit_sat'])
                    used = self.config.format_amount(
                        self.nwc_server.get_used_budget(conn['client_pub']))
                    limit = f"{used}/{budget}"
                item = QTreeWidgetItem(
                    [
                        name,
                        limit,
                        expiry
                    ]
                )
                connections_list.addTopLevelItem(item)

        update_connections_list()
        connections_list.setMinimumHeight(min(connections_list.sizeHint().height(), 400))

        # Delete button - initially disabled
        delete_btn = QPushButton(_("Delete"))
        delete_btn.setEnabled(False)

        # Function to delete the selected connection
        def delete_selected_connection():
            selected_items = connections_list.selectedItems()
            if not selected_items:
                return
            for item in selected_items:
                try:
                    self.remove_connection(item.text(0))
                except ValueError:
                    self.logger.error(f"Failed to remove connection: {item.text(0)}")
                    return
                update_connections_list()
            if self.nwc_server:
                self.nwc_server.restart_event_handler()
            delete_btn.setEnabled(False)

        # Enable delete button when an item is selected
        def on_item_selected():
            delete_btn.setEnabled(bool(connections_list.selectedItems()))

        connections_list.itemSelectionChanged.connect(on_item_selected)
        delete_btn.clicked.connect(delete_selected_connection)

        # Create Connection button
        create_btn = QPushButton(_("Create"))

        def create_connection():
            # Show a dialog to create a new connection
            connection_string = self.connection_info_input_dialog(window)
            if connection_string:
                update_connections_list()
                self.show_new_connection_dialog(window, connection_string)
        create_btn.clicked.connect(create_connection)

        # Add the info and close button to the footer
        close_button = OkButton(d, label=_("Close"))
        info_button = QPushButton(_("Help"))
        info = _("This plugin allows you to create Nostr Wallet Connect connections and "
                 "remote control your wallet using Nostr NIP-47.")
        warning = _("Most NWC clients only use a single of your relays, so ensure the relays accept your events.")
        supported_methods = _("Supported NIP-47 methods: {}").format(", ".join(self.nwc_server.SUPPORTED_METHODS))
        info_msg = f"{info}\n\n{warning}\n\n{supported_methods}"
        info_button.clicked.connect(lambda: window.show_message(info_msg))

        title_hbox = QHBoxLayout()
        title_hbox.addStretch(1)
        title_hbox.addWidget(info_button)

        footer_buttons = Buttons(
            create_btn,
            delete_btn,
            close_button,
        )

        vbox.addLayout(title_hbox)
        vbox.addWidget(QLabel(_('Existing Connections:')))
        vbox.addWidget(connections_list)
        vbox.addLayout(footer_buttons)
        d.setLayout(main_layout)

        return bool(d.exec())

    def connection_info_input_dialog(self, window) -> Optional[str]:
        # Create input dialog for connection parameters
        input_dialog = WindowModalDialog(window, _("Enter NWC connection parameters"))
        layout = QVBoxLayout(input_dialog)

        # Name field (mandatory)
        layout.addWidget(QLabel(_("Connection Name (required):")))
        name_edit = QLineEdit()
        name_edit.setMaximumHeight(30)
        layout.addWidget(name_edit)

        # Daily limit field (optional)
        layout.addWidget(QLabel(_("Daily Satoshi Budget (optional):")))
        limit_edit = OptionalSpinBox()
        limit_edit.setRange(-1, 100_000_000)
        limit_edit.setMaximumHeight(30)
        layout.addWidget(limit_edit)

        # Validity period field (optional)
        layout.addWidget(QLabel(_("Valid for seconds (optional):")))
        validity_edit = OptionalSpinBox()
        validity_edit.setRange(-1, 63072000)
        validity_edit.setMaximumHeight(30)
        layout.addWidget(validity_edit)

        def change_nwc_relay(url):
            self.config.NWC_RELAY = url

        # dropdown menu to select prioritized nwc relay from self.config.NOSTR_RELAYS
        main_relay_label = QLabel(_("Main NWC Relay:"))
        relay_tooltip = (
            _("Most clients only use the first relay url encoded in the connection string.")
            + "\n" + _("The selected relay will be put first in the connection string."))
        main_relay_label.setToolTip(relay_tooltip)
        layout.addWidget(main_relay_label)
        relay_combo = QComboBox()
        relay_combo.setMaximumHeight(30)
        relay_combo.addItems(self.config.NOSTR_RELAYS.split(","))
        relay_combo.setCurrentText(self.config.NWC_RELAY)  # type: ignore
        relay_combo.currentTextChanged.connect(lambda: change_nwc_relay(relay_combo.currentText()))
        layout.addWidget(relay_combo)

        # Buttons
        buttons = Buttons(OkButton(input_dialog), CancelButton(input_dialog))
        layout.addLayout(buttons)

        if not input_dialog.exec():
            return None

        # Validate inputs
        name = name_edit.text().strip()
        if not name or len(name) < 1:
            window.show_error(_("Connection name is required"))
            return None
        duration_limit = validity_edit.value() if validity_edit.value() else None

        # Call create_connection function with user-provided parameters
        try:
            connection_string = self.create_connection(
                name=name,
                daily_limit_sat=limit_edit.value(),
                valid_for_sec=duration_limit
            )
        except ValueError as e:
            window.show_error(str(e))
            return None

        if not connection_string:
            window.show_error(_("Failed to create connection"))
            return None

        return connection_string

    @staticmethod
    def show_new_connection_dialog(window, connection_string: str):
        # Create popup with QR code
        popup = WindowModalDialog(window, _("New NWC Connection"))
        vbox = QVBoxLayout(popup)

        qr: Optional[QImage] = paintQR(connection_string)
        if not qr:
            return
        qr_pixmap = QPixmap.fromImage(qr)
        qr_label = QLabel()
        qr_label.setPixmap(qr_pixmap)
        qr_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        vbox.addWidget(QLabel(_("Scan this QR code with your nwc client:")))
        vbox.addWidget(qr_label)

        # Add connection string text that can be copied
        vbox.addWidget(QLabel(_("Or copy this connection string:")))
        text_edit = QTextEdit()
        text_edit.setText(connection_string)
        text_edit.setReadOnly(True)
        text_edit.setMaximumHeight(80)
        vbox.addWidget(text_edit)

        warning_label = QLabel(_("After closing this window you won't be able to "
                                 "access the connection string again!"))
        warning_label.setStyleSheet("color: red;")
        warning_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        vbox.addWidget(warning_label)

        # Button to copy to clipboard
        copy_btn = QPushButton(_("Copy to clipboard"))
        copy_btn.clicked.connect(lambda: QApplication.clipboard().setText(connection_string))

        vbox.addLayout(Buttons(copy_btn, CloseButton(popup)))

        popup.setLayout(vbox)
        popup.exec()


class OptionalSpinBox(QSpinBox):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setSpecialValueText(" ")
        self.setMinimum(-1)
        self.setValue(-1)

    def value(self):
        # Return None if at special value, otherwise return the actual value
        val = super().value()
        return None if val == -1 else val

    def setValue(self, value):
        # Accept None to set to the special empty value
        super().setValue(-1 if value is None else value)
