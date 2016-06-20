#!/usr/bin/env python2
# -*- mode: python -*-
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2016  The Electrum developers
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

from electrum.plugins import BasePlugin, hook
from electrum.i18n import _


class HW_PluginBase(BasePlugin):
    # Derived classes provide:
    #
    #  class-static variables: client_class, firmware_URL, handler_class,
    #     libraries_available, libraries_URL, minimum_firmware,
    #     wallet_class, ckd_public, types, HidTransport

    def __init__(self, parent, config, name):
        BasePlugin.__init__(self, parent, config, name)
        self.device = self.wallet_class.device
        self.wallet_class.plugin = self

    def is_enabled(self):
        return self.libraries_available

    def device_manager(self):
        return self.parent.device_manager

    @hook
    def close_wallet(self, wallet):
        if isinstance(wallet, self.wallet_class):
            self.device_manager().unpair_wallet(wallet)

    def on_restore_wallet(self, wallet, wizard):
        assert isinstance(wallet, self.wallet_class)
        msg = _("Enter the seed for your %s wallet:" % self.device)
        f = lambda x: wizard.run('on_restore_seed', x)
        wizard.enter_seed_dialog(run_next=f, title=_('Restore hardware wallet'), message=msg, is_valid=self.is_valid_seed)

    def on_restore_seed(self, wallet, wizard, seed):
        f = lambda x: wizard.run('on_restore_passphrase', seed, x)
        wizard.request_passphrase(self.device, run_next=f)

    def on_restore_passphrase(self, wallet, wizard, seed, passphrase):
        f = lambda x: wizard.run('on_restore_password', seed, passphrase, x)
        wizard.request_password(run_next=f)

    def on_restore_password(self, wallet, wizard, seed, passphrase, password):
        # Restored wallets are not hardware wallets
        wallet_class = self.wallet_class.restore_wallet_class
        wallet.storage.put('wallet_type', wallet_class.wallet_type)
        wallet = wallet_class(wallet.storage)
        wallet.add_seed(seed, password)
        wallet.add_xprv_from_seed(seed, 'x/', password, passphrase)
        wallet.create_hd_account(password)
        wizard.create_addresses()

    @staticmethod
    def is_valid_seed(seed):
        return True
