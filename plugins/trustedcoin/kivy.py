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

from functools import partial
from threading import Thread
import re
from decimal import Decimal

from kivy.clock import Clock

from electrum.i18n import _
from electrum.plugins import hook
from .trustedcoin import TrustedCoinPlugin, server, KIVY_DISCLAIMER



class Plugin(TrustedCoinPlugin):

    disclaimer_msg = KIVY_DISCLAIMER

    def __init__(self, parent, config, name):
        super().__init__(parent, config, name)

    @hook
    def load_wallet(self, wallet, window):
        if not isinstance(wallet, self.wallet_class):
            return
        self.start_request_thread(wallet)

    def go_online_dialog(self, wizard):
        # we skip this step on android
        wizard.run('accept_terms_of_use')

    def prompt_user_for_otp(self, wallet, tx, on_success, on_failure):
        from electrum_gui.kivy.uix.dialogs.label_dialog import LabelDialog
        msg = _('Please enter your Google Authenticator code')
        d = LabelDialog(msg, '', lambda otp: self.on_otp(wallet, tx, otp, on_success, on_failure))
        d.open()

    def on_otp(self, wallet, tx, otp, on_success, on_failure):
        try:
            wallet.on_otp(tx, otp)
        except:
            Clock.schedule_once(lambda dt: on_failure(_("Invalid OTP")))
            return
        on_success(tx)

    def accept_terms_of_use(self, wizard):
        tos = server.get_terms_of_service()
        f = lambda x: self.read_email(wizard)
        wizard.tos_dialog(tos=tos, run_next = f)

    def read_email(self, wizard):
        f = lambda x: self.create_remote_key(x, wizard)
        wizard.email_dialog(run_next = f)

    def request_otp_dialog(self, wizard, short_id, otp_secret, xpub3):
        f = lambda otp, reset: self.check_otp(wizard, short_id, otp_secret, xpub3, otp, reset)
        wizard.otp_dialog(otp_secret=otp_secret, run_next = f)
