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

from struct import pack

from electrum.wallet import BIP44_Wallet

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
        # Errors and other user interaction is done through the wallet's
        # handler.  The handler is per-window and preserved across
        # device reconnects
        self.handler = None

    def unpaired(self):
        '''A device paired with the wallet was diconnected.  This can be
        called in any thread context.'''
        self.print_error("unpaired")

    def paired(self):
        '''A device paired with the wallet was (re-)connected.  This can be
        called in any thread context.'''
        self.print_error("paired")

    def get_action(self):
        pass

    def can_create_accounts(self):
        return True

    def can_export(self):
        return False

    def is_watching_only(self):
        '''The wallet is not watching-only; the user will be prompted for
        pin and passphrase as appropriate when needed.'''
        assert not self.has_seed()
        return False

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
