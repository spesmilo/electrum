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

import base64
import urllib
import sys
import requests

from PyQt4.QtGui import QMessageBox, QApplication, QPushButton

from electrum.plugins import BasePlugin, hook
from electrum.i18n import _



class Plugin(BasePlugin):

    button_label = _("Verify GA instant")

    @hook
    def transaction_dialog(self, d):
        d.verify_button = QPushButton(self.button_label)
        d.verify_button.clicked.connect(lambda: self.do_verify(d))
        d.buttons.insert(0, d.verify_button)
        self.transaction_dialog_update(d)

    def get_my_addr(self, d):
        """Returns the address for given tx which can be used to request
        instant confirmation verification from GreenAddress"""
        for addr, _ in d.tx.get_outputs():
            if d.wallet.is_mine(addr):
                return addr
        return None

    @hook
    def transaction_dialog_update(self, d):
        if d.tx.is_complete() and self.get_my_addr(d):
            d.verify_button.show()
        else:
            d.verify_button.hide()

    def do_verify(self, d):
        tx = d.tx
        wallet = d.wallet
        window = d.parent
        # 1. get the password and sign the verification request
        password = None
        if wallet.use_encryption:
            msg = _('GreenAddress requires your signature \n'
                    'to verify that transaction is instant.\n'
                    'Please enter your password to sign a\n'
                    'verification request.')
            password = window.password_dialog(msg)
            if not password:
                return
        try:
            d.verify_button.setText(_('Verifying...'))
            QApplication.processEvents()  # update the button label

            addr = self.get_my_addr(d)
            message = "Please verify if %s is GreenAddress instant confirmed" % tx.hash()
            sig = wallet.sign_message(addr, message, password)
            sig = base64.b64encode(sig)

            # 2. send the request
            response = requests.request("GET", ("https://greenaddress.it/verify/?signature=%s&txhash=%s" % (urllib.quote(sig), tx.hash())),
                                        headers = {'User-Agent': 'Electrum'})
            response = response.json()

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
            d.verify_button.setText(self.button_label)
