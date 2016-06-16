#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2016 Thomas Voegtlin
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

import os
from electrum.wallet import Wallet, Multisig_Wallet
from electrum_gui.kivy.i18n import _


class BaseWizard(object):

    def __init__(self, config, network, storage):
        super(BaseWizard, self).__init__()
        self.config  = config
        self.network = network
        self.storage = storage
        self.wallet = None

    def run(self, action, *args):
        '''Entry point of our Installation wizard'''
        if not action:
            return
        if hasattr(self, action):
            f = getattr(self, action)
            apply(f, *args)
        else:
            raise BaseException("unknown action", action)

    def new(self):
        name = os.path.basename(self.storage.path)
        msg = "\n".join([
            _("Welcome to the Electrum installation wizard."),
            _("The wallet '%s' does not exist.") % name,
            _("What kind of wallet do you want to create?")
        ])
        choices = [
            (_('Standard wallet'), 'create_standard'),
            (_('Multi-signature wallet'), 'create_multisig'),
        ]
        self.choice_dialog(msg=msg, choices=choices, run_prev=self.cancel, run_next=self.run)

    def choose_seed(self):
        msg = ' '.join([
            _("Do you want to create a new seed, or to restore a wallet using an existing seed?")
        ])
        choices = [
            (_('Create a new seed'), 'create_seed'),
            (_('I already have a seed'), 'restore_seed'),
            (_('Watching-only wallet'), 'restore_xpub')
        ]
        self.choice_dialog(msg=msg, choices=choices, run_prev=self.new, run_next=self.run)

    def create_multisig(self):
        def f(m, n):
            self.wallet_type = "%dof%d"%(m, n)
            self.run('choose_seed')
        name = os.path.basename(self.storage.path)
        self.multisig_dialog(run_prev=self.new, run_next=f)

    def restore_seed(self):
        msg = _('Please type your seed phrase using the virtual keyboard.')
        self.restore_seed_dialog(run_prev=self.new, run_next=self.enter_pin, test=Wallet.is_seed, message=msg)

    def restore_xpub(self):
        title = "MASTER PUBLIC KEY"
        message =  _('To create a watching-only wallet, paste your master public key, or scan it using the camera button.')
        self.add_xpub_dialog(run_prev=self.new, run_next=lambda xpub: self.create_wallet(xpub, None), title=title, message=message, test=Wallet.is_mpk)

    def create_standard(self):
        self.wallet_type = 'standard'
        self.run('choose_seed')

    def create_wallet(self, text, password):
        if self.wallet_type == 'standard':
            self.wallet = Wallet.from_text(text, password, self.storage)
            self.run('create_addresses')
        else:
            self.storage.put('wallet_type', self.wallet_type)
            self.wallet = Multisig_Wallet(self.storage)
            self.wallet.add_seed(text, password)
            self.wallet.create_master_keys(password)
            action = self.wallet.get_action()
            self.run(action)

    def add_cosigners(self):
        xpub = self.wallet.master_public_keys.get('x1/')
        self.show_xpub_dialog(run_prev=self.create_multisig, run_next=self.add_cosigner, xpub=xpub, test=Wallet.is_xpub)

    def add_cosigner(self):
        def on_xpub(xpub):
            self.wallet.add_cosigner(xpub)
            i = self.wallet.get_missing_cosigner()
            action = 'add_cosigner' if i else 'create_main_account'
            self.run(action)
        title = "ADD COSIGNER"
        message = _('Please paste your cosigners master public key, or scan it using the camera button.')
        self.add_xpub_dialog(run_prev=self.add_cosigners, run_next=on_xpub, title=title, message=message, test=Wallet.is_xpub)

    def create_main_account(self):
        self.wallet.create_main_account()
        self.run('create_addresses')

    def create_addresses(self):
        def task():
            self.wallet.create_main_account()
            self.wallet.synchronize()
        msg= _("Electrum is generating your addresses, please wait.")
        self.waiting_dialog(task, msg, on_complete=self.terminate)

    def create_seed(self):
        from electrum.wallet import BIP32_Wallet
        seed = BIP32_Wallet.make_seed()
        msg = _("If you forget your PIN or lose your device, your seed phrase will be the "
                "only way to recover your funds.")
        self.show_seed_dialog(run_prev=self.new, run_next=self.confirm_seed, message=msg, seed_text=seed)

    def confirm_seed(self, seed):
        assert Wallet.is_seed(seed)
        msg = _('Please retype your seed phrase, to confirm that you properly saved it')
        self.restore_seed_dialog(run_prev=self.create_seed, run_next=self.enter_pin, test=lambda x: x==seed, message=msg)

    def enter_pin(self, seed):
        def callback(pin):
            action = 'confirm_pin' if pin else 'create_wallet'
            self.run(action, (seed, pin))
        self.password_dialog('Choose a PIN code', callback)

    def confirm_pin(self, seed, pin):
        def callback(conf):
            if conf == pin:
                self.run('create_wallet', (seed, pin))
            else:
                self.show_error(_('PIN mismatch'))
                self.run('enter_pin', (seed,))
        self.password_dialog('Confirm your PIN code', callback)

    def terminate(self):
        self.wallet.start_threads(self.network)
        self.dispatch('on_wizard_complete', self.wallet)

    def cancel(self):
        self.dispatch('on_wizard_complete', None)
        return True



