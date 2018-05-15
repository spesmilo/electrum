#!/usr/bin/env python
#
# Electron Cash - lightweight Bitcoin client
# Copyright (C) 2018 Electron Cash developers
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

import hashlib

from PyQt5.QtGui import *
from PyQt5.QtCore import *
from PyQt5.QtWidgets import *

from electroncash.i18n import _
from electroncash.plugins import ExternalPluginCodes, run_hook
from .util import MyTreeWidget, MessageBoxMixin, WindowModalDialog, Buttons, CloseButton


INSTALL_ERROR_MESSAGES = {
    ExternalPluginCodes.MISSING_MANIFEST: _("The plugin archive you selected is missing a manifest. It was therefore not possible to install it."),
    ExternalPluginCodes.NAME_ALREADY_IN_USE: _("There is already a plugin installed using the internal package name of the plugin you selected. It was therefore not possible to install it."),
    ExternalPluginCodes.UNABLE_TO_COPY_FILE: _("It was not possible to copy the plugin archive into Electron Cash's plugin storage location. It was therefore not possible to install it."),
    ExternalPluginCodes.INSTALLED_BUT_FAILED_LOAD: _("The plugin is installed, but in the process of enabling and loading it, an error occurred. Restart Electron Cash and try again, or uninstall it and report it to it's developers."),
    ExternalPluginCodes.INCOMPATIBLE_VERSION: _("The plugin is targeted at a later version of Electron Cash."),
}

use_tree_widget = True

class FixedCheckBox(QCheckBox):
    def mousePressEvent(self, event):
        event.ignore()
        
    def mouseReleaseEvent(self, event):
        event.ignore()


class ExternalPluginsPreviewDialog(WindowModalDialog):
    def __init__(self, plugin_dialog, main_window, title, plugin_path):
        WindowModalDialog.__init__(self, main_window, title)

        self.main_window = main_window
        self.plugin_dialog = plugin_dialog

        self.setMinimumWidth(600)
        self.setMaximumWidth(600)

        vbox = QVBoxLayout()
        self.setLayout(vbox)

        self.metadataFormLayout = QFormLayout()
        self.pluginNameLabel = QLabel()
        self.metadataFormLayout.addRow(_("Name"), self.pluginNameLabel)
        self.versionLabel = QLabel()
        self.metadataFormLayout.addRow(_("Version"), self.versionLabel)
        self.descriptionLabel = QLabel()
        self.descriptionLabel.setWordWrap(True)
        self.metadataFormLayout.addRow(_("Description"), self.descriptionLabel)
        self.supportedInterfacesLayout = QVBoxLayout()
        self.supportedInterfacesLabel = QLabel(_("Integration"))
        self.supportedInterfacesLabel.setAlignment(Qt.AlignLeft | Qt.AlignTop)
        self.metadataFormLayout.addRow(self.supportedInterfacesLabel, self.supportedInterfacesLayout)
        
        self.qtInterfaceCheckBox = FixedCheckBox("User interface.")
        self.supportedInterfacesLayout.addWidget(self.qtInterfaceCheckBox)
        self.cmdLineInterfaceCheckBox = FixedCheckBox("Command-line.")
        self.supportedInterfacesLayout.addWidget(self.cmdLineInterfaceCheckBox)

        groupBox = QGroupBox(_("Plugin Metadata"))
        groupBox.setLayout(self.metadataFormLayout)
        vbox.addWidget(groupBox)

        securityFormLayout = QFormLayout()
        self.checksumLabel = QLabel()
        self.checksumLabel.setAlignment(Qt.AlignRight)
        self.checksumLabel.setToolTip(_("If the official source for this plugin has a checksum for this plugin, ensure that the value shown here is the same."))
        securityFormLayout.addRow(_("Archive MD5 Checksum"), self.checksumLabel)

        groupBox = QGroupBox(_("Security"))
        groupBox.setLayout(securityFormLayout)
        vbox.addWidget(groupBox)

        confirmLayout = QVBoxLayout()
        confirmLayout.setAlignment(Qt.AlignHCenter)
        confirmGroupBox = QGroupBox()
        self.liabilityCheckbox = QCheckBox(_("I understand and accept the risk involved in installing this plugin."))
        confirmLayout.addWidget(self.liabilityCheckbox)
        confirmGroupBox.setLayout(confirmLayout)
        vbox.addWidget(confirmGroupBox)

        hbox = QHBoxLayout()
        vbox.addLayout(hbox)
        self.installButton = QPushButton("Install")
        hbox.addWidget(self.installButton)
        hbox.addStretch(1)
        self.cancelButton = QPushButton("Close")
        self.cancelButton.setDefault(True)
        hbox.addWidget(self.cancelButton)

        self.installButton.clicked.connect(self.on_install)
        self.cancelButton.clicked.connect(self.close)
        self.liabilityCheckbox.clicked.connect(self.on_liability_toggled)

        self.pluginNameLabel.setText(_("Unavailable."))
        self.versionLabel.setText(_("Unavailable."))
        self.descriptionLabel.setText(_("Unavailable."))
        self.checksumLabel.setText(_("Unavailable."))
            
        self.refresh_plugin(plugin_path)
        self.refresh_ui()

    def refresh_plugin(self, plugin_path):
        self.plugin_path = plugin_path
        
        plugin_manager = self.main_window.gui_object.plugins
        self.plugin_metadata = plugin_manager.get_metadata_from_external_plugin_zip_file(plugin_path)

        hash_md5 = hashlib.md5()
        with open(plugin_path, "rb") as f:
            hash_md5.update(f.read())
        self.checksumLabel.setText(hash_md5.hexdigest())
        
        self.pluginNameLabel.setText(self.plugin_metadata["display_name"])
        if "version" in self.plugin_metadata:
            self.versionLabel.setText(str(self.plugin_metadata["version"]))
        self.descriptionLabel.setText(self.plugin_metadata["description"])
        
        available_for = self.plugin_metadata.get("available_for", [])
        self.qtInterfaceCheckBox.setChecked("qt" in available_for)
        self.cmdLineInterfaceCheckBox.setChecked("cmdline" in available_for)

    def refresh_ui(self):
        are_widgets_enabled = self.is_plugin_valid()
        was_liability_accepted = self.liabilityCheckbox.checkState() == Qt.Checked

        self.pluginNameLabel.setEnabled(are_widgets_enabled)
        self.versionLabel.setEnabled(are_widgets_enabled)
        self.descriptionLabel.setEnabled(are_widgets_enabled)
        self.checksumLabel.setEnabled(are_widgets_enabled)
        self.installButton.setEnabled(was_liability_accepted and are_widgets_enabled)
        self.qtInterfaceCheckBox.setEnabled(are_widgets_enabled)
        self.cmdLineInterfaceCheckBox.setEnabled(are_widgets_enabled)
        self.liabilityCheckbox.setEnabled(are_widgets_enabled)

    def is_plugin_valid(self):
        return self.plugin_metadata is not None
        
    def on_liability_toggled(self):
        self.refresh_ui()

    def on_install(self):
        self.close()

        self.plugin_dialog.install_plugin_confirmed(self.plugin_path)


class ExternalPluginsDialog(WindowModalDialog, MessageBoxMixin):
    def __init__(self, parent, title):
        WindowModalDialog.__init__(self, parent, title)

        self.main_window = parent
        self.config = parent.config
        self.setMinimumWidth(600)
        self.setMaximumWidth(600)

        vbox = QVBoxLayout(self)

        # The warning message box at the top of the dialog window about dangers of installing plugins.
        self.descriptionGroupBox = QGroupBox()
        self.descriptionGroupBox.setTitle(_("Security Warning"))
        self.descriptionGroupBox.setAlignment(Qt.AlignHCenter)
        descriptionGroupLayout = QVBoxLayout()
        self.descriptionGroupBox.setLayout(descriptionGroupLayout)
        self.descriptionLabel = QLabel(_("Install plugins at your own risk.\nThey have almost complete access to Electron Cash's internals."))
        self.descriptionLabel.setAlignment(Qt.AlignCenter)
        descriptionGroupLayout.addWidget(self.descriptionLabel)
        vbox.addWidget(self.descriptionGroupBox)

        # The list of installed plugins and their state..
        self.pluginsList = ExternalPluginTable(self, self.main_window)
        vbox.addWidget(self.pluginsList)

        # The row of buttons under the plugin list for actions related to the plugins within it.
        hbox = QHBoxLayout()
        self.installButton = QPushButton("Add Plugin")
        hbox.addWidget(self.installButton)
        hbox.addStretch(1)
        self.settingsButton = QPushButton("Settings")
        self.toggleButton = QPushButton("")
        self.uninstallButton = QPushButton("Uninstall")
        hbox.addWidget(self.settingsButton)
        hbox.addWidget(self.toggleButton)
        hbox.addWidget(self.uninstallButton)
        vbox.addLayout(hbox)

        vbox.addLayout(Buttons(CloseButton(self)))

        self.installButton.clicked.connect(self.on_install_plugin)
        self.uninstallButton.clicked.connect(self.on_uninstall_plugin)
        self.toggleButton.clicked.connect(self.on_toggle_plugin)
        self.settingsButton.clicked.connect(self.on_settings)

        # Do an initial prime of the UI based on current state. We share the same
        # logic as updates following changes in state, in order to be consistent.
        self.refresh_ui()
        
    def refresh_ui(self):
        self.pluginsList.refresh_ui()
        selected_id = self.pluginsList.get_selected_key()
        self.on_item_selected(selected_id)

    def on_settings(self):
        package_name = self.pluginsList.get_selected_key()
        plugin_manager = self.main_window.gui_object.plugins
        plugin = plugin_manager.external_plugins.get(package_name, None)
        if plugin is not None:
            plugin.settings_dialog(self)

    def on_toggle_plugin(self):
        selected_key = self.pluginsList.get_selected_key()
        if selected_key is not None:
            package_name = selected_key
            plugin_manager = self.main_window.gui_object.plugins
            plugin = plugin_manager.external_plugins.get(package_name, None)
            if plugin is not None and plugin.is_enabled():
                plugin_manager.disable_external_plugin(package_name)
            else:
                plugin_manager.enable_external_plugin(package_name)
                run_hook('init_qt', self.main_window.gui_object)
            self.refresh_ui()

    def on_install_plugin(self):
        self.installFileDialog = d = QFileDialog(self, _("Select Plugin"))
        d.setNameFilter(_("Zip Archives (*.zip)"))
        if d.exec_():
            selected_file_paths = d.selectedFiles()
            if len(selected_file_paths):
                self.show_install_plugin_preview_dialog(selected_file_paths[0])
            
    def show_install_plugin_preview_dialog(self, file_path):
        self.installWarningDialog = d = ExternalPluginsPreviewDialog(self, self.main_window, _("Plugin Preview"), file_path)
        d.exec_()

    def install_plugin_confirmed(self, plugin_archive_path):
        plugin_manager = self.main_window.gui_object.plugins
        result_code = plugin_manager.install_external_plugin(plugin_archive_path)
        if result_code != ExternalPluginCodes.SUCCESS:
            self.show_error(INSTALL_ERROR_MESSAGES[result_code])
        else:
            run_hook('init_qt', self.main_window.gui_object)
        self.refresh_ui()

    def on_uninstall_plugin(self):
        package_name = self.pluginsList.get_selected_key()
        if self.show_warning(_("Are you sure you want to uninstall the selected plugin?")):
            plugin_manager = self.main_window.gui_object.plugins
            plugin_manager.uninstall_external_plugin(package_name)
            self.refresh_ui()

    def on_item_selected(self, package_name=None):
        if package_name is not None:
            plugin_manager = self.main_window.gui_object.plugins
            plugin_description = str(plugin_manager.external_plugin_metadata.get("description", "")).strip()
            if not len(plugin_description):
                plugin_description = _("No description provided.")

            plugin = plugin_manager.external_plugins.get(package_name, None)
            if plugin is not None and plugin.is_enabled():
                self.toggleButton.setText(_('Disable'))
            else:
                self.toggleButton.setText(_('Enable'))
            if plugin is not None and plugin.has_settings_dialog():
                self.settingsButton.setEnabled(True)
            else:
                self.settingsButton.setEnabled(False)
            self.toggleButton.setEnabled(True)
            self.uninstallButton.setEnabled(True)
        else:
            self.settingsButton.setEnabled(False)
            self.toggleButton.setText(_('Enable'))
            self.toggleButton.setEnabled(False)
            self.uninstallButton.setEnabled(False)


class ExternalPluginTable(QTableWidget):
    def __init__(self, parent, main_window):
        self.parent_widget = parent
        self.main_window = main_window

        QTableWidget.__init__(self)

        self.setAcceptDrops(True)
        
        self.setSelectionMode(QAbstractItemView.SingleSelection)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setSortingEnabled(False)

        self.horizontalHeader().setStretchLastSection(True)
        verticalHeader = self.verticalHeader()
        verticalHeader.setVisible(False)
        verticalHeader.setSectionResizeMode(QHeaderView.Fixed)
        verticalHeader.setDefaultSectionSize(80)
        self.setStyleSheet("QTableWidget::item { padding: 10px; }")

        self.itemSelectionChanged.connect(self.on_item_selection_changed)

        self.row_keys = []
        
    def get_file_path_from_dragdrop_event(self, event):
        mimeData = event.mimeData()
        if mimeData.hasUrls():
            for url in mimeData.urls():
                if url.isLocalFile():
                    file_path = url.toLocalFile()
                    if file_path.lower().endswith(".zip"):
                        return file_path

    def dragEnterEvent(self, event):
        file_path = self.get_file_path_from_dragdrop_event(event)
        if file_path is not None:
            event.accept()
        else:
            event.ignore()

    def dragMoveEvent(self, event):
        file_path = self.get_file_path_from_dragdrop_event(event)
        if file_path is not None:
            event.setDropAction(Qt.CopyAction)
            event.accept()
        else:
            event.ignore()

    def dropEvent(self, event):
        file_path = self.get_file_path_from_dragdrop_event(event)
        self.parent_widget.show_install_plugin_preview_dialog(file_path)

    def get_selected_key(self):
        selectedIndexes = self.selectedIndexes()
        if len(selectedIndexes):
            return self.row_keys[selectedIndexes[0].row()]

    def on_item_selection_changed(self):
        selection_key = self.get_selected_key()
        self.parent_widget.on_item_selected(selection_key)

    def refresh_ui(self):
        self.clear()

        plugin_manager = self.main_window.gui_object.plugins

        self.setRowCount(len(plugin_manager.external_plugin_metadata))
        self.setColumnCount(4)
        self.setColumnWidth(0, 150)
        self.setColumnWidth(1, 300)
        self.setColumnWidth(2, 60)
        self.setColumnWidth(3, 60)
        self.setHorizontalHeaderLabels([ "Name", "Description", "Version", "Enabled" ])

        self.row_keys = []
        for row_index, (package_name, metadata) in enumerate(plugin_manager.external_plugin_metadata.items()):
            self.row_keys.append(package_name)

            plugin = plugin_manager.get_external_plugin(package_name)
            fullname = metadata.get('display_name', package_name)
            description = metadata.get('description', "")
            version = metadata.get('version', 0)

            displayNameLabel = QLabel(fullname)
            displayNameLabel.setWordWrap(True)
            displayNameLabel.setAlignment(Qt.AlignLeft | Qt.AlignTop)
            self.setCellWidget(row_index, 0, displayNameLabel)
            descriptionLabel = QLabel(description)
            descriptionLabel.setWordWrap(True)
            descriptionLabel.setAlignment(Qt.AlignLeft | Qt.AlignTop)
            self.setCellWidget(row_index, 1, descriptionLabel)
            versionLabel = QLabel(str(version))
            versionLabel.setAlignment(Qt.AlignRight | Qt.AlignTop)
            self.setCellWidget(row_index, 2, versionLabel)
            enabledLabel = QLabel("Yes" if plugin is not None and plugin.is_enabled() else "No")
            enabledLabel.setAlignment(Qt.AlignHCenter | Qt.AlignTop)
            self.setCellWidget(row_index, 3, enabledLabel)


class ExternalPluginList(MyTreeWidget):
    def __init__(self, parent, main_window):
        self.main_window = main_window

        MyTreeWidget.__init__(self, parent, self.create_menu, [
            _('Name'),
            _('Description'),
            _('Version'),
            _('Enabled'),
        ], 0, [])
        self.setSelectionMode(QAbstractItemView.SingleSelection)
        self.setSortingEnabled(False)

        self.itemSelectionChanged.connect(self.on_item_selection_changed)

    def create_menu(self, position):
        pass

    def get_selected_keys(self):
        selected_items = self.selectedItems()
        selected_ids = [ item.data(0, Qt.UserRole) for item in self.selectedItems() ]
        return selected_ids

    def on_item_selection_changed(self):
        selection_keys = self.get_selected_keys()
        self.parent.on_items_selected(selection_keys)

    def on_update(self):
        self.clear()

        plugin_manager = self.main_window.gui_object.plugins
        for package_name, metadata in plugin_manager.external_plugin_metadata.items():
            row_key = package_name
            plugin = plugin_manager.get_external_plugin(package_name)
            fullname = metadata.get('display_name', package_name)
            description = metadata.get('description', "")
            version = metadata.get('version', 0)
            values = [
                fullname,
                description + " Now is the time for all good men to come to the aid of the party.",
                str(version),
                "Yes" if plugin is not None and plugin.is_enabled() else "No",
            ]
            item = QTreeWidgetItem(values)
            item.setSizeHint(1, QSize(200, 150))
            # item.setToolTip(0, _("This scheduled payment is up-to-date."))
            item.setData(0, Qt.UserRole, row_key)
            item.setData(1, Qt.TextAlignmentRole, Qt.AlignRight | Qt.AlignVCenter) # Align amount to the right.
            self.addTopLevelItem(item)


