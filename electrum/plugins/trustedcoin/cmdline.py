#!/usr/bin/env python
#
# Electrum - Lightweight Bitcoin Client
# Copyright (C) 2015 Thomas Voegtlin
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

from electrum.i18n import _
from electrum.plugin import hook
from .trustedcoin import TrustedCoinPlugin


class Plugin(TrustedCoinPlugin):

    def prompt_user_for_otp(self, wallet, tx):
        if not isinstance(wallet, self.wallet_class):
            return
        if not wallet.can_sign_without_server():
            self.logger.info("twofactor:sign_tx")
            auth_code = None
            if wallet.keystores['x3/'].get_tx_derivations(tx):
                msg = _('Please enter your Google Authenticator code:')
                auth_code = int(input(msg))
            else:
                self.logger.info("twofactor: xpub3 not needed")
            wallet.auth_code = auth_code

