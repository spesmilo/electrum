from electrum.i18n import _
from .nwcserver import NWCServerPlugin
from electrum.gui.qt.util import WindowModalDialog, Buttons, EnterButton, OkButton, CancelButton, \
    CloseButton
from electrum.gui.common_qt.util import paintQR
from electrum.plugin import hook
from functools import partial
from datetime import datetime

from PyQt6.QtWidgets import QVBoxLayout, QPushButton, QLabel, QTreeWidget, QTreeWidgetItem, \
    QTextEdit, QApplication, QSpinBox, QSizePolicy, QComboBox, QLineEdit
from PyQt6.QtGui import QPixmap, QImage
from PyQt6.QtCore import Qt

from typing import TYPE_CHECKING, Optional
if TYPE_CHECKING:
    from electrum.wallet import Abstract_Wallet
    from electrum.gui.qt.main_window import ElectrumWindow
    from electrum.gui.qt import ElectrumGui

class Plugin(NWCServerPlugin):
    def __init__(self, *args):
        NWCServerPlugin.__init__(self, *args)
        self._init_qt_received = False

    @hook
    def load_wallet(self, wallet: 'Abstract_Wallet', window: 'ElectrumWindow'):
        self.start_plugin(wallet)

    @hook
    def init_qt(self, gui: 'ElectrumGui'):
        if self._init_qt_received:
            return
        self._init_qt_received = True
        for w in gui.windows:
            self.start_plugin(w.wallet)

    def requires_settings(self):
        return True

    def settings_dialog(self, window: WindowModalDialog, wallet: 'Abstract_Wallet'):
        if not wallet.has_lightning():
            window.show_error(_("{} plugin requires a lightning enabled wallet. Setup lightning first.")
                           .format("NWC"))
            return

        d = WindowModalDialog(window, _("Nostr Wallet Connect"))
        main_layout = QVBoxLayout(d)

        # Connections list
        main_layout.addWidget(QLabel(_("Existing Connections:")))
        connections_list = QTreeWidget()
        connections_list.setHeaderLabels([_("Name"), _("Budget [{}]").format(self.config.get_base_unit()), _("Expiry")])
        # Set the resize mode for all columns to adjust to content
        header = connections_list.header()
        header.setSectionResizeMode(0, header.ResizeMode.ResizeToContents)
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
        main_layout.addWidget(connections_list)

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
        main_layout.addWidget(delete_btn)

        # Create Connection button
        create_btn = QPushButton(_("Create Connection"))
        def create_connection():
            # Show a dialog to create a new connection
            connection_string = self.connection_info_input_dialog(window)
            if connection_string:
                update_connections_list()
                self.show_new_connection_dialog(window, connection_string)
        create_btn.clicked.connect(create_connection)
        main_layout.addWidget(create_btn)

        # Add the info and close button to the footer
        close_button = OkButton(d, label=_("Close"))
        info_button = QPushButton(_("Info"))
        info = _("This plugin allows you to create Nostr Wallet Connect connections and "
                 "remote control your wallet using Nostr NIP-47.")
        warning = _("Most NWC clients only use a single of your relays, so ensure the relays accept your events.")
        supported_methods = _("Supported NIP-47 methods: {}").format(", ".join(self.nwc_server.SUPPORTED_METHODS))
        info_msg = f"{info}\n\n{warning}\n\n{supported_methods}"
        info_button.clicked.connect(lambda: window.show_message(info_msg))
        footer_buttons = Buttons(
            info_button,
            close_button,
        )
        main_layout.addLayout(footer_buttons)

        d.setLayout(main_layout)

        # Resize the dialog to show the connections list properly
        conn_list_width = sum(header.sectionSize(i) for i in range(header.count()))
        d.resize(min(conn_list_width + 40, 600), d.height())
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
        value_limit = limit_edit.value() if limit_edit.value() else None
        duration_limit = validity_edit.value() if validity_edit.value() else None

        # Call create_connection function with user-provided parameters
        try:
            connection_string = self.create_connection(
                name=name,
                daily_limit_sat=value_limit,
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
