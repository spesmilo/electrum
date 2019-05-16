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

"""
Only import this on linux platforms, the module imports linux specific modules
"""

import os
import tempfile
import grp

from PyQt5.QtCore import Qt, QObject
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import QDialog, QVBoxLayout, QLabel, QHBoxLayout, QPushButton, QMessageBox, QFrame, QWidget

from electroncash.util import _, PrintError
from electroncash.plugins import Plugins
from electroncash_gui.qt import WindowModalDialog

class InstallHardwareWalletSupportDialog(PrintError, WindowModalDialog):
    UDEV_RULES_FILE='/etc/udev/rules.d/20-electron-cash-hw-wallets.rules'
    GRAPHICAL_SUDOS=['pkexec','gksudo','kdesudo']

    ADDITIONAL_HARDWARE_IDS = {
        (0x534c, 0x0001), # TREZOR
        (0x1209, 0x53c0), # TREZOR V2
        (0x1209, 0x53c1), # TREZOR V2
    }

    def __init__(self, parent: QWidget, plugins: Plugins):
        assert parent and plugins
        super().__init__(parent)

        # Make sure that all plugins are loaded so we have all hardware ids
        plugins.get_hardware_support()
        self.device_manager = plugins.device_manager

        self.setWindowTitle(_('Hardware Wallet Support'))

        layout = QVBoxLayout()
        self.setLayout(layout)
        layout.setContentsMargins(20,20,20,20)

        info_label = QLabel()
        info_label.setText(
            _('This tool installs hardware wallet "udev rules" on your system.') + ' ' +
            _('Correct udev rules are required in order for a hardware wallet to be accessed by Electron Cash.') + '\n\n' +
            _('Note: Installing udev rules requires root access via "sudo", so make sure you are in the sudoers file and/or have Administrator rights on this system!')
            )
        info_label.setWordWrap(True)

        layout.addWidget(info_label)

        hbox = QHBoxLayout()
        hbox.addStretch(2)
        status_title = QLabel()
        status_title.setText(_('udev Rules Status:'))
        status_title.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        hbox.addWidget(status_title)
        hbox.addStretch(1)
        self.status_label = QLabel()
        self.status_label.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        font = self.status_label.font()
        font.setPointSize(15)
        self.status_label.setFont(font)
        hbox.addWidget(self.status_label)
        hbox.addStretch(2)
        layout.addLayout(hbox)

        button_layout = QHBoxLayout()
        layout.addLayout(button_layout)

        close_button = QPushButton(_('&Close'))
        close_button.clicked.connect(self.reject)
        button_layout.addWidget(close_button)
        button_layout.addStretch(1)
        self.uninstall_button = QPushButton()
        self.uninstall_button.setText(_('&Uninstall'))
        self.uninstall_button.clicked.connect(self.uninstallClicked)
        button_layout.addWidget(self.uninstall_button)

        self.install_button = QPushButton()
        self.install_button.setText(_('&Install'))
        self.install_button.clicked.connect(self.installClicked)
        button_layout.addWidget(self.install_button)

        self.install_button.setMinimumWidth(100)
        self.uninstall_button.setMinimumWidth(100)


        self.updateStatus()

        self.resize(400,300)

    def setStatus(self, text: str, bold: bool = False):
        self.status_label.setText(text if not bold else ('<b>{}</b>'.format(text)))
        self.status_label.setTextFormat(Qt.RichText)

    def updateStatus(self):
        if not os.path.isfile(self.UDEV_RULES_FILE):
            self.install_button.setEnabled(True)
            self.uninstall_button.setEnabled(False)
            self.setStatus(_('Not installed'), True)
            return

        with open(self.UDEV_RULES_FILE, 'r') as rules_file:
            rules_installed = rules_file.read()

        rules = self.generateRulesFile()

        if rules_installed != rules:
            self.install_button.setEnabled(True)
            self.uninstall_button.setEnabled(True)
            self.setStatus(_('Needs update'), True)
            return

        self.install_button.setEnabled(False)
        self.uninstall_button.setEnabled(True)
        self.setStatus(_('Installed'), False)

    def generateRulesFile(self) -> str:
        line_format='SUBSYSTEMS=="usb", ATTRS{{idVendor}}=="{:04x}", ATTRS{{idProduct}}=="{:04x}"'

        try:
            # Add the plugdev group if it exists
            grp.getgrnam('plugdev')
            line_format += ', GROUP="plugdev"'
        except KeyError:
            pass

        # Add the uaccess tag. On most distros this is all that is needed for users to access USB devices
        line_format += ', TAG+="uaccess"'

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
        # The below udevadm trigger line is here in case we decide we need it.
        # It appears unnecessary on most distros, according to @EchtarAgo (Axel Gembe)
        # If you find it is necessary, comment it back in.
        # Also note: on Tails Linux it did cause a system shutdown as well.
        #script = script + 'udevadm trigger\n'
        script = script + 'udevadm control --reload-rules\n'
        return script

    def installClicked(self):
        script = 'set -e\n'
        script += 'umask 022\n'
        script += 'cat << EOF > "{}"\n'.format(self.UDEV_RULES_FILE)
        script += self.generateRulesFile()
        script += 'EOF\n'
        script = self._addUdevAdmCommands(script)
        self.print_error(script)
        success = self._runScriptAsRoot(script)
        self.updateStatus()
        if success:
            msg = _('HW wallet udev rules have been successfully installed!')
            info = (
                _('Note: You may now need to disconnect & reconnect your HW wallet.')
                # Commented the below out as it's no longer relevant after our
                # removal of `udevadm trigger` above.
                #+ "\n\n" + _('(Your display resolution may also have changed as a result of this process. This is harmless; simply set it back.)')
            )
            self.show_message(msg, informative_text=info, rich_text=True)
        else:
            msg = _('Error installing udev rules and/or user canceled.')
            self.show_warning(msg)


    def uninstallClicked(self):
        script = 'rm -f "{}"\n'.format(self.UDEV_RULES_FILE)
        script = self._addUdevAdmCommands(script)
        self.print_error(script)
        success = self._runScriptAsRoot(script)
        self.updateStatus()
        if success:
            msg = _('HW wallet udev rules have been successfully uninstalled!')
            self.show_message(msg)
        else:
            msg = _('Error uninstalling udev rules and/or user canceled.')
            self.show_warning(msg)
