#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2013 ecdsa@github
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

import re
import math
from functools import partial

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QPixmap
from PyQt6.QtWidgets import QLineEdit, QLabel, QGridLayout, QVBoxLayout, QCheckBox

from electrum.i18n import _
from electrum.plugin import run_hook

from .util import (icon_path, WindowModalDialog, OkButton, CancelButton, Buttons,
                   PasswordLineEdit)


def check_password_strength(password):

    '''
    Check the strength of the password entered by the user and return back the same
    :param password: password entered by user in New Password
    :return: password strength Weak or Medium or Strong
    '''
    password = password
    n = math.log(len(set(password)))
    num = re.search("[0-9]", password) is not None and re.match("^[0-9]*$", password) is None
    caps = password != password.upper() and password != password.lower()
    extra = re.match("^[a-zA-Z0-9]*$", password) is None
    score = len(password)*(n + caps + num + extra)/20
    password_strength = {0:"Weak",1:"Medium",2:"Strong",3:"Very Strong"}
    return password_strength[min(3, int(score))]


PW_NEW, PW_CHANGE, PW_PASSPHRASE = range(0, 3)

MSG_ENTER_PASSWORD = _("Choose a password to encrypt your wallet keys.") + '\n'\
                     + _("Leave this field empty if you want to disable encryption.")

class PasswordLayout(object):

    titles = [_("Enter Password"), _("Change Password"), _("Enter Passphrase")]

    def __init__(self, msg, kind, OK_button, wallet=None):
        self.wallet = wallet

        self.pw = PasswordLineEdit()
        self.new_pw = PasswordLineEdit()
        self.conf_pw = PasswordLineEdit()
        self.kind = kind
        self.OK_button = OK_button

        vbox = QVBoxLayout()
        label = QLabel(msg + "\n")
        label.setWordWrap(True)

        grid = QGridLayout()
        grid.setSpacing(8)
        grid.setColumnMinimumWidth(0, 150)
        grid.setColumnMinimumWidth(1, 100)
        grid.setColumnStretch(1,1)

        if kind == PW_PASSPHRASE:
            vbox.addWidget(label)
            msgs = [_('Passphrase:'), _('Confirm Passphrase:')]
        else:
            logo_grid = QGridLayout()
            logo_grid.setSpacing(8)
            logo_grid.setColumnMinimumWidth(0, 70)
            logo_grid.setColumnStretch(1,1)

            logo = QLabel()
            logo.setAlignment(Qt.AlignmentFlag.AlignCenter)

            logo_grid.addWidget(logo,  0, 0)
            logo_grid.addWidget(label, 0, 1, 1, 2)
            vbox.addLayout(logo_grid)

            m1 = _('New Password:') if kind == PW_CHANGE else _('Password:')
            msgs = [m1, _('Confirm Password:')]
            if wallet and wallet.has_password():
                grid.addWidget(QLabel(_('Current Password:')), 0, 0)
                grid.addWidget(self.pw, 0, 1)
                lockfile = "lock.png"
            else:
                lockfile = "unlock.png"
            logo.setPixmap(QPixmap(icon_path(lockfile))
                           .scaledToWidth(36, mode=Qt.TransformationMode.SmoothTransformation))

        grid.addWidget(QLabel(msgs[0]), 1, 0)
        grid.addWidget(self.new_pw, 1, 1)

        grid.addWidget(QLabel(msgs[1]), 2, 0)
        grid.addWidget(self.conf_pw, 2, 1)
        vbox.addLayout(grid)

        # Password Strength Label
        if kind != PW_PASSPHRASE:
            self.pw_strength = QLabel()
            grid.addWidget(self.pw_strength, 3, 0, 1, 2)
            self.new_pw.textChanged.connect(self.pw_changed)

        def enable_OK():
            ok = self.new_pw.text() == self.conf_pw.text()
            OK_button.setEnabled(ok)
        self.new_pw.textChanged.connect(enable_OK)
        self.conf_pw.textChanged.connect(enable_OK)
        enable_OK()

        self.vbox = vbox

    def title(self):
        return self.titles[self.kind]

    def layout(self):
        return self.vbox

    def pw_changed(self):
        password = self.new_pw.text()
        if password:
            colors = {"Weak":"Red", "Medium":"Blue", "Strong":"Green",
                      "Very Strong":"Green"}
            strength = check_password_strength(password)
            label = (_("Password Strength") + ": " + "<font color="
                     + colors[strength] + ">" + strength + "</font>")
        else:
            label = ""
        self.pw_strength.setText(label)

    def old_password(self):
        if self.kind == PW_CHANGE:
            return self.pw.text() or None
        return None

    def new_password(self):
        pw = self.new_pw.text()
        # Empty passphrases are fine and returned empty.
        if pw == "" and self.kind != PW_PASSPHRASE:
            pw = None
        return pw

    def clear_password_fields(self):
        for field in [self.pw, self.new_pw, self.conf_pw]:
            field.clear()


class PasswordLayoutForHW(object):

    def __init__(self, msg, wallet=None):
        self.wallet = wallet

        vbox = QVBoxLayout()
        label = QLabel(msg + "\n")
        label.setWordWrap(True)

        grid = QGridLayout()
        grid.setSpacing(8)
        grid.setColumnMinimumWidth(0, 150)
        grid.setColumnMinimumWidth(1, 100)
        grid.setColumnStretch(1,1)

        logo_grid = QGridLayout()
        logo_grid.setSpacing(8)
        logo_grid.setColumnMinimumWidth(0, 70)
        logo_grid.setColumnStretch(1,1)

        logo = QLabel()
        logo.setAlignment(Qt.AlignmentFlag.AlignCenter)

        logo_grid.addWidget(logo,  0, 0)
        logo_grid.addWidget(label, 0, 1, 1, 2)
        vbox.addLayout(logo_grid)

        if wallet and wallet.has_storage_encryption():
            lockfile = "lock.png"
        else:
            lockfile = "unlock.png"
        logo.setPixmap(QPixmap(icon_path(lockfile))
                       .scaledToWidth(36, mode=Qt.TransformationMode.SmoothTransformation))

        vbox.addLayout(grid)

        self.vbox = vbox

    def title(self):
        return _("Toggle Encryption")

    def layout(self):
        return self.vbox


class ChangePasswordDialogBase(WindowModalDialog):

    def __init__(self, parent, wallet):
        WindowModalDialog.__init__(self, parent)
        is_encrypted = wallet.has_storage_encryption()
        OK_button = OkButton(self)

        self.create_password_layout(wallet, is_encrypted, OK_button)

        self.setWindowTitle(self.playout.title())
        vbox = QVBoxLayout(self)
        vbox.addLayout(self.playout.layout())
        vbox.addStretch(1)
        vbox.addLayout(Buttons(CancelButton(self), OK_button))

    def create_password_layout(self, wallet, is_encrypted, OK_button):
        raise NotImplementedError()


class ChangePasswordDialogForSW(ChangePasswordDialogBase):

    def create_password_layout(self, wallet, is_encrypted, OK_button):
        if not wallet.has_password():
            msg = _('Your wallet is not protected.')
            msg += ' ' + _('Use this dialog to add a password to your wallet.')
        else:
            if not is_encrypted:
                msg = _('Your bitcoins are password protected. However, your wallet file is not encrypted.')
            else:
                msg = _('Your wallet is password protected and encrypted.')
            msg += ' ' + _('Use this dialog to change your password.')
        self.playout = PasswordLayout(
            msg=msg,
            kind=PW_CHANGE,
            OK_button=OK_button,
            wallet=wallet)

    def run(self):
        try:
            if not self.exec():
                return False, None, None, None
            return True, self.playout.old_password(), self.playout.new_password(), True
        finally:
            self.playout.clear_password_fields()


class ChangePasswordDialogForHW(ChangePasswordDialogBase):

    def __init__(self, parent, wallet):
        ChangePasswordDialogBase.__init__(self, parent, wallet)

    def create_password_layout(self, wallet, is_encrypted, OK_button):
        if not is_encrypted:
            msg = _('Your wallet file is NOT encrypted.')
        else:
            msg = _('Your wallet file is encrypted.')
        msg += '\n' + _('Note: If you enable this setting, you will need your hardware device to open your wallet.')
        msg += '\n' + _('Use this dialog to toggle encryption.')
        self.playout = PasswordLayoutForHW(msg)

    def run(self):
        if not self.exec():
            return False, None
        return True, True


class PasswordDialog(WindowModalDialog):

    def __init__(self, parent=None, msg=None):
        msg = msg or _('Please enter your password')
        WindowModalDialog.__init__(self, parent, _("Enter Password"))
        self.pw = pw = PasswordLineEdit()
        label = QLabel(msg)
        label.setWordWrap(True)
        vbox = QVBoxLayout()
        vbox.addWidget(label)
        grid = QGridLayout()
        grid.setSpacing(8)
        grid.addWidget(QLabel(_('Password')), 1, 0)
        grid.addWidget(pw, 1, 1)
        vbox.addLayout(grid)
        vbox.addLayout(Buttons(CancelButton(self), OkButton(self)))
        self.setLayout(vbox)
        run_hook('password_dialog', pw, grid, 1)

    def run(self):
        try:
            if not self.exec():
                return
            return self.pw.text()
        finally:
            self.pw.clear()
