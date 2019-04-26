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
import urllib.parse
import sys
from typing import TYPE_CHECKING

from PyQt5.QtWidgets import QApplication, QPushButton

from electrum.plugin import BasePlugin, hook
from electrum.i18n import _
from electrum.network import Network

if TYPE_CHECKING:
    from aiohttp import ClientResponse


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
        for o in d.tx.outputs():
            if d.wallet.is_mine(o.address):
                return o.address
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
        window = d.main_window

        if wallet.is_watching_only():
            d.show_critical(_('This feature is not available for watch-only wallets.'))
            return

        # 1. get the password and sign the verification request
        password = None
        if wallet.has_keystore_encryption():
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
            message = "Please verify if %s is GreenAddress instant confirmed" % tx.txid()
            sig = wallet.sign_message(addr, message, password)
            sig = base64.b64encode(sig).decode('ascii')

            # 2. send the request
            async def handle_request(resp: 'ClientResponse'):
                resp.raise_for_status()
                return await resp.json()
            url = "https://greenaddress.it/verify/?signature=%s&txhash=%s" % (urllib.parse.quote(sig), tx.txid())
            response = Network.send_http_on_proxy('get', url, headers = {'User-Agent': 'Electrum'}, on_finish=handle_request)

            # 3. display the result
            if response.get('verified'):
                d.show_message(_('{} is covered by GreenAddress instant confirmation').format(tx.txid()), title=_('Verification successful!'))
            else:
                d.show_warning(_('{} is not covered by GreenAddress instant confirmation').format(tx.txid()), title=_('Verification failed!'))
        except BaseException as e:
            self.logger.exception('')
            d.show_error(str(e))
        finally:
            d.verify_button.setText(self.button_label)
