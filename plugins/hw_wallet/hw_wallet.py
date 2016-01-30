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

from struct import pack

from electrum_ltc.wallet import BIP44_Wallet

class BIP44_HW_Wallet(BIP44_Wallet):
    '''A BIP44 hardware wallet base class.'''
    # Derived classes must set:
    #   - device
    #   - DEVICE_IDS
    #   - wallet_type

    restore_wallet_class = BIP44_Wallet
    max_change_outputs = 1

    def __init__(self, storage):
        BIP44_Wallet.__init__(self, storage)
        # After timeout seconds we clear the device session
        self.session_timeout = storage.get('session_timeout', 180)
        # Errors and other user interaction is done through the wallet's
        # handler.  The handler is per-window and preserved across
        # device reconnects
        self.handler = None
        self.force_watching_only = True

    def set_session_timeout(self, seconds):
        self.print_error("setting session timeout to %d seconds" % seconds)
        self.session_timeout = seconds
        self.storage.put('session_timeout', seconds)

    def unpaired(self):
        '''A device paired with the wallet was diconnected.  This can be
        called in any thread context.'''
        self.print_error("unpaired")
        self.force_watching_only = True
        self.handler.watching_only_changed()

    def paired(self):
        '''A device paired with the wallet was (re-)connected.  This can be
        called in any thread context.'''
        self.print_error("paired")
        self.force_watching_only = False
        self.handler.watching_only_changed()

    def timeout(self):
        '''Called when the wallet session times out.  Note this is called from
        the Plugins thread.'''
        client = self.get_client(force_pair=False)
        if client:
            client.clear_session()
        self.print_error("timed out")

    def get_action(self):
        pass

    def can_create_accounts(self):
        return True

    def can_export(self):
        return False

    def is_watching_only(self):
        '''The wallet is watching-only if its trezor device is unpaired.'''
        assert not self.has_seed()
        return self.force_watching_only

    def can_change_password(self):
        return False

    def get_client(self, force_pair=True):
        return self.plugin.get_client(self, force_pair)

    def first_address(self):
        '''Used to check a hardware wallet matches a software wallet'''
        account = self.accounts.get('0')
        derivation = self.address_derivation('0', 0, 0)
        return (account.first_address()[0] if account else None, derivation)

    def derive_xkeys(self, root, derivation, password):
        if self.master_public_keys.get(self.root_name):
            return BIP44_wallet.derive_xkeys(self, root, derivation, password)

        # When creating a wallet we need to ask the device for the
        # master public key
        xpub = self.get_public_key(derivation)
        return xpub, None

    def i4b(self, x):
        return pack('>I', x)
