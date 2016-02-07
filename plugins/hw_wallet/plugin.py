#!/usr/bin/env python2
# -*- mode: python -*-
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2016  The Electrum developers
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

import time

from electrum_ltc.util import ThreadJob
from electrum_ltc.plugins import BasePlugin, hook
from electrum_ltc.i18n import _


class HW_PluginBase(BasePlugin, ThreadJob):
    # Derived classes provide:
    #
    #  class-static variables: client_class, firmware_URL, handler_class,
    #     libraries_available, libraries_URL, minimum_firmware,
    #     wallet_class, ckd_public, types, HidTransport

    def __init__(self, parent, config, name):
        BasePlugin.__init__(self, parent, config, name)
        self.device = self.wallet_class.device
        self.wallet_class.plugin = self
        self.prevent_timeout = time.time() + 3600 * 24 * 365

    def is_enabled(self):
        return self.libraries_available

    def device_manager(self):
        return self.parent.device_manager

    def thread_jobs(self):
        # Thread job to handle device timeouts
        return [self] if self.libraries_available else []

    def run(self):
        '''Handle device timeouts.  Runs in the context of the Plugins
        thread.'''
        now = time.time()
        for wallet in self.device_manager().paired_wallets():
            if (isinstance(wallet, self.wallet_class)
                    and hasattr(wallet, 'last_operation')
                    and now > wallet.last_operation + wallet.session_timeout):
                wallet.timeout()
                wallet.last_operation = self.prevent_timeout

    @hook
    def close_wallet(self, wallet):
        if isinstance(wallet, self.wallet_class):
            self.device_manager().unpair_wallet(wallet)

    def on_restore_wallet(self, wallet, wizard):
        assert isinstance(wallet, self.wallet_class)

        msg = _("Enter the seed for your %s wallet:" % self.device)
        seed = wizard.request_seed(msg, is_valid = self.is_valid_seed)

        # Restored wallets are not hardware wallets
        wallet_class = self.wallet_class.restore_wallet_class
        wallet.storage.put('wallet_type', wallet_class.wallet_type)
        wallet = wallet_class(wallet.storage)

        passphrase = wizard.request_passphrase(self.device, restore=True)
        password = wizard.request_password()
        wallet.add_seed(seed, password)
        wallet.add_xprv_from_seed(seed, 'x/', password, passphrase)
        wallet.create_hd_account(password)
        return wallet

    @staticmethod
    def is_valid_seed(seed):
        return True
