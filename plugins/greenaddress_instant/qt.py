#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2014 Thomas Voegtlin
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

import base64
import urllib
import sys
import requests

from PyQt4.QtGui import QApplication, QPushButton

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
            password = window.password_dialog(msg, parent=d)
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
                d.show_message(_('%s is covered by GreenAddress instant confirmation') % (tx.hash()), title=_('Verification successful!'))
            else:
                d.show_critical(_('%s is not covered by GreenAddress instant confirmation') % (tx.hash()), title=_('Verification failed!'))
        except BaseException as e:
            import traceback
            traceback.print_exc(file=sys.stdout)
            d.show_error(str(e))
        finally:
            d.verify_button.setText(self.button_label)
