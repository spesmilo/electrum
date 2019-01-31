#!/usr/bin/env python3
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

"""
This script automates all the work involved in packaging an external Electron Cash plugin.

Future work:
* Make this work on the command-line.
  * Take a manifest path, and output the package, or print errors.
"""

import compileall
import hashlib
import json
import os
import shutil
import sys
import tempfile
import traceback
import urllib.parse

from PyQt5.QtGui import *
from PyQt5.QtCore import *
from PyQt5.QtWidgets import *

## Start copied from .util
def versiontuple(v):
    return tuple(map(int, (v.split("."))))
## End copied from .util

def write_plugin_archive(metadata, source_package_path, archive_file_path):
    suffixless_path = archive_file_path.strip()
    # Ensure we don't end up with .zip.zip, as `make_archive` adds the suffix as well.
    if suffixless_path[-4:].lower() == ".zip":
        suffixless_path = suffixless_path[:-4]

    package_directory_name = os.path.basename(source_package_path)
    with tempfile.TemporaryDirectory() as temp_path:
        # Export the generated 'manifest.json' file into place.
        manifest_file_path = os.path.join(temp_path, "manifest.json")
        write_manifest(metadata, manifest_file_path)

        # Copy the selected Python package into place.
        dest_package_path = os.path.join(temp_path, package_directory_name)
        shutil.copytree(source_package_path,  dest_package_path)
        # Python bytecode cannot be written into the zip archive as Electron Cash runs it.
        # So we precompile it before creating the archived form.
        compileall.compile_dir(dest_package_path)
        shutil.make_archive(suffixless_path, 'zip', temp_path)

    plugin_path = suffixless_path +".zip"
    hasher = hashlib.sha256()
    with open(plugin_path, "rb") as f:
        hasher.update(f.read())

    base_name = os.path.basename(plugin_path)
    with open(plugin_path +".sha256", "w") as f:
        f.write("{0} *{1}".format(hasher.hexdigest(), base_name))

    return hasher.hexdigest()

def write_manifest(metadata, manifest_file_path):
    with open(manifest_file_path, "w") as f:
        json.dump(metadata, f, indent=4)

def build_manifest(display_name, version, project_url, description, minimum_ec_version, package_name, available_for_qt, available_for_cmdline, available_for_kivy):
    metadata = {}
    metadata["display_name"] = display_name
    version_value = version.strip()
    try:
        versiontuple(version_value)
    except ValueError:
        version_value = "0.0"
    metadata["version"] = version_value
    metadata["description"] = description
    version_value = minimum_ec_version.strip()
    try:
        versiontuple(version_value)
    except ValueError:
        version_value = "0.0"
    metadata["project_url"] = project_url
    metadata["minimum_ec_version"] = version_value
    if package_name is not None:
        metadata["package_name"] = package_name
    available_for = []
    if available_for_qt:
        available_for.append("qt")
    if available_for_cmdline:
        available_for.append("cmdline")
    if available_for_kivy:
        available_for.append("kivy")
    metadata["available_for"] = available_for

    return metadata

class App(QWidget):
    def __init__(self):
        super().__init__()

        self.directory_path = None

        self.setWindowTitle('Electron Cash Plugin Packager')
        self.setMinimumWidth(500)
        self.setMaximumWidth(500)

        outerVLayout = QVBoxLayout()
        self.setLayout(outerVLayout)

        self.importButton = QPushButton("Import Existing 'manifest.json'")
        outerVLayout.addWidget(self.importButton)

        groupBox = QGroupBox("Metadata")
        groupLayout = QFormLayout()
        outerVLayout.addWidget(groupBox)
        label = QLabel("This is a test")
        groupBox.setLayout(groupLayout)
        self.displayNameEdit = QLineEdit()
        self.displayNameEdit.setPlaceholderText("Scheduled Payments")
        groupLayout.addRow('Display Name', self.displayNameEdit)
        self.versionEdit = QLineEdit()
        self.versionEdit.setMaximumWidth(50)
        self.versionEdit.setPlaceholderText("1.0")
        groupLayout.addRow('Version', self.versionEdit)
        self.projectUrlEdit = QLineEdit()
        self.projectUrlEdit.setPlaceholderText("https://github.com/rt121212121/electron_cash_scheduled_payments_plugin")
        groupLayout.addRow('Project Url', self.projectUrlEdit)
        self.descriptionEdit = QTextEdit()
        self.descriptionEdit.setPlaceholderText("Add scheduled payments at a fixed time either on a given day every week, or a specific day every month.")
        self.descriptionEdit.setAcceptRichText(False)
        groupLayout.addRow('Description', self.descriptionEdit)
        self.minimumElectronCashVersionEdit = QLineEdit()
        self.minimumElectronCashVersionEdit.setPlaceholderText("3.2")
        self.minimumElectronCashVersionEdit.setMaximumWidth(50)
        self.minimumElectronCashVersionEdit.setToolTip("This is the lowest version of Electron Cash which this plugin can be installed with.")
        groupLayout.addRow('Minimum Electron Cash Version', self.minimumElectronCashVersionEdit)

        availableVLayout = QVBoxLayout()
        self.qtAvailableCheckBox = QCheckBox("Supports the QT user interface.")
        self.cmdlineAvailableCheckBox = QCheckBox("Supports the command line.")
        self.kivyAvailableCheckBox = QCheckBox("Supports the Kivy user interface.")
        availableVLayout.addWidget(self.qtAvailableCheckBox)
        availableVLayout.addWidget(self.cmdlineAvailableCheckBox)
        availableVLayout.addWidget(self.kivyAvailableCheckBox)
        groupLayout.addRow("Available For", availableVLayout)

        self.packageNameEdit = QLineEdit()
        self.packageNameEdit.setEnabled(False)
        self.packageNameEdit.setToolTip("This is the name of the folder in the zip archve that contains the Python plugin package.\nIt is necessary in the case that there are other folders containing Python code, or other supporting data like images.")
        self.selectDirectoryButton = QPushButton("Select Package Directory")
        contentsVLayout = QVBoxLayout()
        contentsVLayout.addWidget(self.packageNameEdit)
        contentsVLayout.addWidget(self.selectDirectoryButton)
        groupLayout.addRow('Package Name', contentsVLayout)

        self.packageButton = QPushButton("Make Plugin Archive")
        self.exportManifestButton = QPushButton("Export Manifest")
        buttonsHLayout = QHBoxLayout()
        buttonsHLayout.addWidget(self.packageButton)
        buttonsHLayout.addWidget(self.exportManifestButton)
        buttonsHLayout.addStretch(1)
        outerVLayout.addLayout(buttonsHLayout)

        self.closeButton = QPushButton("Close")
        self.checksumLabel = QLabel("Computed SHA256 checksum of plugin archive..")
        self.checksumLabel.setMinimumWidth(350)
        buttonsHLayout = QHBoxLayout()
        buttonsHLayout.addWidget(self.checksumLabel)
        buttonsHLayout.addStretch(1)
        buttonsHLayout.addWidget(self.closeButton)
        outerVLayout.addLayout(buttonsHLayout)

        self.selectDirectoryButton.clicked.connect(self.on_read_directory)
        self.importButton.clicked.connect(self.on_import_clicked)
        self.packageButton.clicked.connect(self.on_package_plugin)
        self.exportManifestButton.clicked.connect(self.on_export_manifest_clicked)
        self.closeButton.clicked.connect(self.close)
        self.displayNameEdit.textEdited.connect(self.on_required_text_change)
        self.versionEdit.textEdited.connect(self.on_required_text_change)
        self.projectUrlEdit.textEdited.connect(self.on_required_text_change)
        self.descriptionEdit.textChanged.connect(self.on_required_text_change)
        self.minimumElectronCashVersionEdit.textEdited.connect(self.on_required_text_change)

        self.refresh_ui()
        self.show()

    def refresh_ui(self):
        versionText = self.versionEdit.text().strip()
        try:
            versiontuple(versionText)
        except ValueError:
            versionText = ""

        minimumElectronCashVersionText = self.minimumElectronCashVersionEdit.text().strip()
        try:
            versiontuple(minimumElectronCashVersionText)
        except ValueError:
            minimumElectronCashVersionText = ""

        projectUrlText = self.projectUrlEdit.text().strip()
        url_components = urllib.parse.urlparse(projectUrlText)
        projectUrlText = projectUrlText if len(url_components.scheme) and len(url_components.netloc) else projectUrlText

        have_basics = True
        have_basics = have_basics and len(self.displayNameEdit.text().strip()) > 3
        have_basics = have_basics and len(versionText) > 0
        have_basics = have_basics and len(projectUrlText) > 0
        have_basics = have_basics and len(self.descriptionEdit.toPlainText().strip()) > 3
        have_basics = have_basics and len(minimumElectronCashVersionText) > 0
        have_basics = have_basics and (self.qtAvailableCheckBox.checkState() == Qt.Checked or self.cmdlineAvailableCheckBox.checkState() == Qt.Checked or self.kivyAvailableCheckBox.checkState() == Qt.Checked)

        can_export = have_basics
        can_package = have_basics and self.have_valid_directory(self.directory_path)

        self.packageButton.setEnabled(can_package)
        self.exportManifestButton.setEnabled(can_export)

    def have_valid_directory(self, directory_path):
        if directory_path is not None:
            init_path = os.path.join(directory_path, "__init__.py")
            if os.path.isfile(init_path):
                return True
        return False

    def on_required_text_change(self, *args):
        self.refresh_ui()

    def on_read_directory(self):
        directory_path = QFileDialog.getExistingDirectory(self, "Select Package Parent Directory", None, QFileDialog.ShowDirsOnly | QFileDialog.DontResolveSymlinks)
        if len(directory_path):
            if self.have_valid_directory(directory_path):
                self.directory_path = directory_path
                directory_name = os.path.basename(directory_path)
                self.packageNameEdit.setText(directory_name)
                self.refresh_ui()
            else:
                QMessageBox.information(self, 'Invalid Directory', 'The directory needs to be a Python package.')

    def on_package_plugin(self):
        self.archive_file_path, used_filter = QFileDialog.getSaveFileName(self, "Save Plugin Archive", None, "Plugin archive (*.zip)")
        if not len(self.archive_file_path):
            return

        metadata = self.build_manifest()
        checksumText = write_plugin_archive(metadata, self.directory_path, self.archive_file_path)
        self.checksumLabel.setText(checksumText)
        self.checksumLabel.setTextInteractionFlags(Qt.TextSelectableByMouse)

        file_name = os.path.basename(self.archive_file_path)
        QMessageBox.information(self, 'Success!', 'Created plugin archive '+ file_name +'.')

    def build_manifest(self):
        display_name = self.displayNameEdit.text().strip()
        version = self.versionEdit.text().strip()
        project_url = self.projectUrlEdit.text().strip()
        description = self.descriptionEdit.toPlainText().strip()
        minimum_ec_version = self.minimumElectronCashVersionEdit.text().strip()
        package_name = None
        if self.directory_path is not None:
            package_name = os.path.basename(self.directory_path)
        available_for_qt = self.qtAvailableCheckBox.checkState() == Qt.Checked
        available_for_cmdline = self.cmdlineAvailableCheckBox.checkState() == Qt.Checked
        available_for_kivy = self.kivyAvailableCheckBox.checkState() == Qt.Checked

        return build_manifest(display_name, version, project_url, description, minimum_ec_version, package_name, available_for_qt, available_for_cmdline, available_for_kivy)

    def write_manifest(self, manifest_file_path):
        metadata = self.build_manifest()
        write_manifest(metadata, manifest_file_path)

    def on_export_manifest_clicked(self):
        self.manifest_file_path, used_filter = QFileDialog.getSaveFileName(self, "Save Plugin Manifest", None, "Plugin manifest (manifest.json)")
        if not len(self.manifest_file_path):
            return

        try:
            self.write_manifest(self.manifest_file_path)
        except OSError:
            QMessageBox.critical(self, 'File Error', 'Unable to write to selected file.')
            return
        except:
            QMessageBox.critical(self, 'Encoding Error', 'Problem serialising json data.')
            traceback.print_exc()
            return

    def on_import_clicked(self):
        self.manifest_file_path, used_filter = QFileDialog.getOpenFileName(self, "Select Existing Plugin Manifest", None, "Plugin manifest (manifest.json)")
        if not len(self.manifest_file_path):
            return

        with open(self.manifest_file_path, "rb") as f:
            try:
                metadata = json.load(f)
            except json.JSONDecodeError:
                QMessageBox.critical(self, 'Invalid JSON File', 'Unable to load the file as valid JSON.')
                return

        self.displayNameEdit.setText(str(metadata.get("display_name", "")))
        self.versionEdit.setText(str(metadata.get("version", "")))
        self.projectUrlEdit.setText(str(metadata.get("project_url", "")))
        self.descriptionEdit.setText(str(metadata.get("description", "")))
        self.minimumElectronCashVersionEdit.setText(str(metadata.get("minimum_ec_version", "")))
        package_name = str(metadata.get("package_name", "")).strip()
        if len(package_name):
            manifest_path, manifest_filename = os.path.split(self.manifest_file_path)
            directory_path = os.path.join(manifest_path, package_name)
            if self.have_valid_directory(directory_path):
                self.directory_path = directory_path
                self.packageNameEdit.setText(package_name)

        available_for = metadata.get("available_for", [])
        self.qtAvailableCheckBox.setChecked("qt" in available_for)
        self.cmdlineAvailableCheckBox.setChecked("cmdline" in available_for)
        self.kivyAvailableCheckBox.setChecked("kivy" in available_for)

        self.refresh_ui()


if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = App()
    sys.exit(app.exec_())
