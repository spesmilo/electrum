# Electron Cash - lightweight Bitcoin client
# Copyright (C) 2019 Axel Gembe <derago@gmail.com>
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

import os
import tempfile

from PyQt5.QtCore import Qt, QObject
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import QDialog, QVBoxLayout, QLabel, QHBoxLayout, QPushButton, QMessageBox, QFrame

from electroncash.util import _, print_error
from electroncash.plugins import Plugins

class InstallHardwareWalletSupportDialog(QDialog):
    UDEV_RULES_FILE='/etc/udev/rules.d/20-electron-cash-hw-wallets.rules'
    GRAPHICAL_SUDOS=['pkexec','gksudo','kdesudo']

    ADDITIONAL_HARDWARE_IDS={
        (0x534c, 0x0001), # TREZOR
        (0x1209, 0x53c0), # TREZOR V2
        (0x1209, 0x53c1), # TREZOR V2
    }

    def __init__(self, parent: QObject = None, plugins: Plugins = None):
        super().__init__(parent)

        assert plugins

        # Make sure that all plugins are loaded so we have all hardware ids
        plugins.get_hardware_support()
        self.device_manager = plugins.device_manager

        self.setWindowTitle(_('Hardware wallet support'))

        layout = QVBoxLayout()
        self.setLayout(layout)

        info_label = QLabel()
        info_label.setText(
            _('This installs udev rules for your hardware wallet.') + '\n' +
            _('Udev rules allow a hardware wallet to be accessed by non-root users.')
            )
        layout.addWidget(info_label)

        self.status_label = QLabel()
        self.status_label.setAlignment(Qt.AlignCenter | Qt.AlignVCenter)
        font = QFont()
        font.setBold(True)
        font.setPointSize(15)
        self.status_label.setFont(font)
        self.status_label.setFrameStyle(QFrame.Panel)
        self.status_label.setMargin(5)
        layout.addWidget(self.status_label)

        button_layout = QHBoxLayout()
        layout.addLayout(button_layout)

        self.install_button = QPushButton()
        self.install_button.setText(_('&Install'))
        self.install_button.clicked.connect(self.installClicked)
        button_layout.addWidget(self.install_button)

        self.uninstall_button = QPushButton()
        self.uninstall_button.setText(_('&Uninstall'))
        self.uninstall_button.clicked.connect(self.uninstallClicked)
        button_layout.addWidget(self.uninstall_button)

        self.updateStatus()

    def setStatus(self, text: str):
        self.status_label.setText(_('Status: {}').format(text))

    def updateStatus(self):
        if not os.path.isfile(self.UDEV_RULES_FILE):
            self.install_button.setEnabled(True)
            self.uninstall_button.setEnabled(False)
            self.setStatus(_('Not installed'))
            return

        with open(self.UDEV_RULES_FILE, 'r') as rules_file:
            rules_installed = rules_file.read()

        rules = self.generateRulesFile()

        if rules_installed != rules:
            self.install_button.setEnabled(True)
            self.uninstall_button.setEnabled(True)
            self.setStatus(_('Needs update'))
            return

        self.install_button.setEnabled(False)
        self.uninstall_button.setEnabled(True)
        self.setStatus(_('Installed'))

    def generateRulesFile(self) -> str:
        line_format='SUBSYSTEMS=="usb", ATTRS{{idVendor}}=="{:04x}", ATTRS{{idProduct}}=="{:04x}", TAG+="uaccess"'
        ids_set = self.device_manager.recognised_hardware.union(self.ADDITIONAL_HARDWARE_IDS)
        lines = [line_format.format(ids[0], ids[1]) for ids in ids_set]
        return '# Electron Cash hardware wallet rules file\n' + '\n'.join(lines) + '\n'

    def _runScriptAsRoot(self, script: str) -> bool:
        assert script

        with tempfile.NamedTemporaryFile(mode='w', prefix='electroncash') as tf:
            tf.write(script)
            tf.flush()

            if os.getuid() == 0:
                if os.spawnvp(os.P_WAIT, 'sh', ['sh', tf.name]) == 0:
                    return True
                return False

            for sudo in self.GRAPHICAL_SUDOS:
                if os.spawnvp(os.P_WAIT, sudo, [sudo, 'sh', tf.name]) == 0:
                    return True

        return False

    def _addUdevAdmCommands(self, script: str) -> str:
        script = script + 'udevadm trigger\n'
        script = script + 'udevadm control --reload-rules\n'
        return script

    def installClicked(self):
        script = 'cat << EOF > "{}"\n'.format(self.UDEV_RULES_FILE)
        script = script + self.generateRulesFile()
        script = script + 'EOF\n'
        script = self._addUdevAdmCommands(script)
        print_error(script)
        self._runScriptAsRoot(script)
        self.updateStatus()
        msg = _('You need to replug your hardware wallet for the changes to take effect')
        QMessageBox.information(self, self.windowTitle(), msg)


    def uninstallClicked(self):
        script = 'rm -f "{}"\n'.format(self.UDEV_RULES_FILE)
        script = self._addUdevAdmCommands(script)
        print_error(script)
        self._runScriptAsRoot(script)
        self.updateStatus()
