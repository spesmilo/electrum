#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2014 Thomas Voegtlin
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

import urllib
import httplib
import json
import sys

from PyQt4.QtGui import QMessageBox, QApplication, QPushButton

from electrum_grs.account import BIP32_Account
from electrum_grs import bitcoin, util
from electrum_grs import transaction
from electrum_grs.plugins import BasePlugin, hook
from electrum_grs.i18n import _
from electrum_grs.bitcoin import regenerate_key


description = _("Allows validating if your transactions have instant confirmations by GreenAddress")


class Plugin(BasePlugin):

    button_label = _("Verify GA instant")

    def fullname(self):
        return 'GreenAddress instant'

    def description(self):
        return description

    def is_available(self):
        return False

    @hook 
    def init_qt(self, gui):
        self.win = gui.main_window

    @hook
    def transaction_dialog(self, d):
        self.wallet = d.wallet
        self.verify_button = b = QPushButton(self.button_label)
        b.clicked.connect(lambda: self.do_verify(d.tx))
        d.buttons.insertWidget(2, b)
        self.transaction_dialog_update(d)

    def get_my_addr(self, tx):
        """Returns the address for given tx which can be used to request
        instant confirmation verification from GreenAddress"""

        for addr, _ in tx.get_outputs():
            if self.wallet.is_mine(addr):
                return addr
        return None

    @hook
    def transaction_dialog_update(self, d):
        if d.tx.is_complete() and self.get_my_addr(d.tx):
            self.verify_button.show()
        else:
            self.verify_button.hide()

    def do_verify(self, tx):
        # 1. get the password and sign the verification request
        password = None
        if self.wallet.use_encryption:
            msg = _('GreenAddress requires your signature to verify that transaction is instant.\n'
                    'Please enter your password to sign a verification request.')
            password = self.win.password_dialog(msg)
            if not password:
                return
        try:
            self.verify_button.setText(_('Verifying...'))
            QApplication.processEvents()  # update the button label

            addr = self.get_my_addr(tx)
            message = "Please verify if %s is GreenAddress instant confirmed" % tx.hash()
            sig = self.wallet.sign_message(addr, message, password)

            # 2. send the request
            connection = httplib.HTTPSConnection('greenaddress.it')
            connection.request("GET", ("/verify/?signature=%s&txhash=%s" % (urllib.quote(sig), tx.hash())),
                None, {'User-Agent': 'Electrum'})
            response = connection.getresponse()
            response = json.loads(response.read())

            # 3. display the result
            if response.get('verified'):
                QMessageBox.information(None, _('Verification successful!'),
                    _('%s is covered by GreenAddress instant confirmation') % (tx.hash()), _('OK'))
            else:
                QMessageBox.critical(None, _('Verification failed!'),
                    _('%s is not covered by GreenAddress instant confirmation') % (tx.hash()), _('OK'))
        except BaseException as e:
            import traceback
            traceback.print_exc(file=sys.stdout)
            QMessageBox.information(None, _('Error'), str(e), _('OK'))
        finally:
            self.verify_button.setText(self.button_label)
