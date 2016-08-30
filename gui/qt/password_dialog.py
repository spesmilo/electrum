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

from PyQt4.QtGui import *
from PyQt4.QtCore import *
from electrum.i18n import _
from util import *
import re
import math

def check_password_strength(password):

    '''
    Check the strength of the password entered by the user and return back the same
    :param password: password entered by user in New Password
    :return: password strength Weak or Medium or Strong
    '''
    password = unicode(password)
    n = math.log(len(set(password)))
    num = re.search("[0-9]", password) is not None and re.match("^[0-9]*$", password) is None
    caps = password != password.upper() and password != password.lower()
    extra = re.match("^[a-zA-Z0-9]*$", password) is None
    score = len(password)*( n + caps + num + extra)/20
    password_strength = {0:"Weak",1:"Medium",2:"Strong",3:"Very Strong"}
    return password_strength[min(3, int(score))]


PW_NEW, PW_CHANGE, PW_PASSPHRASE = range(0, 3)


class PasswordLayout(object):

    titles = [_("Enter Password"), _("Change Password"), _("Enter Passphrase")]

    def __init__(self, wallet, msg, kind, OK_button):
        self.wallet = wallet

        self.pw = QLineEdit()
        self.pw.setEchoMode(2)
        self.new_pw = QLineEdit()
        self.new_pw.setEchoMode(2)
        self.conf_pw = QLineEdit()
        self.conf_pw.setEchoMode(2)
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
            logo.setAlignment(Qt.AlignCenter)

            logo_grid.addWidget(logo,  0, 0)
            logo_grid.addWidget(label, 0, 1, 1, 2)
            vbox.addLayout(logo_grid)

            m1 = _('New Password:') if kind == PW_NEW else _('Password:')
            msgs = [m1, _('Confirm Password:')]
            if wallet and wallet.has_password():
                grid.addWidget(QLabel(_('Current Password:')), 0, 0)
                grid.addWidget(self.pw, 0, 1)
                lockfile = ":icons/lock.png"
            else:
                lockfile = ":icons/unlock.png"
            logo.setPixmap(QPixmap(lockfile).scaledToWidth(36))

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
            OK_button.setEnabled(self.new_pw.text() == self.conf_pw.text())
        self.new_pw.textChanged.connect(enable_OK)
        self.conf_pw.textChanged.connect(enable_OK)

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
            return unicode(self.pw.text()) or None
        return None

    def new_password(self):
        pw = unicode(self.new_pw.text())
        # Empty passphrases are fine and returned empty.
        if pw == "" and self.kind != PW_PASSPHRASE:
            pw = None
        return pw


class PasswordDialog(WindowModalDialog):

    def __init__(self, parent, wallet, msg, kind):
        WindowModalDialog.__init__(self, parent)
        OK_button = OkButton(self)
        self.playout = PasswordLayout(wallet, msg, kind, OK_button)
        self.setWindowTitle(self.playout.title())
        vbox = QVBoxLayout(self)
        vbox.addLayout(self.playout.layout())
        vbox.addStretch(1)
        vbox.addLayout(Buttons(CancelButton(self), OK_button))

    def run(self):
        if not self.exec_():
            return False, None, None

        return True, self.playout.old_password(), self.playout.new_password()
