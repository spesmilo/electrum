import os
from electrum_ltc.wallet import Wallet, Multisig_Wallet
from electrum_ltc_gui.kivy.i18n import _

from kivy.app import App
from kivy.uix.widget import Widget
from kivy.core.window import Window
from kivy.clock import Clock
from kivy.factory import Factory

import sys
import threading
from functools import partial
import weakref

from create_restore import WizardChoiceDialog, ShowSeedDialog, RestoreSeedDialog, AddXpubDialog, WizardMultisigDialog
from password_dialog import PasswordDialog


# global Variables
app = App.get_running_app()


class InstallWizard(Widget):
    '''Installation Wizard. Responsible for instantiating the
    creation/restoration of wallets.

    events::
        `on_wizard_complete` Fired when the wizard is done creating/ restoring
        wallet/s.
    '''

    __events__ = ('on_wizard_complete', )

    def __init__(self, config, network, storage):
        super(InstallWizard, self).__init__()
        self.config  = config
        self.network = network
        self.storage = storage
        self.wallet = None

    def waiting_dialog(self, task, msg, on_complete=None):
        '''Perform a blocking task in the background by running the passed
        method in a thread.
        '''
        def target():
            # run your threaded function
            try:
                task()
            except Exception as err:
                Clock.schedule_once(lambda dt: app.show_error(str(err)))
            # on  completion hide message
            Clock.schedule_once(lambda dt: app.info_bubble.hide(now=True), -1)
            if on_complete:
                on_complete()

        app.show_info_bubble(
            text=msg, icon='atlas://gui/kivy/theming/light/important',
            pos=Window.center, width='200sp', arrow_pos=None, modal=True)
        t = threading.Thread(target = target)
        t.start()

    def run(self, action, *args):
        '''Entry point of our Installation wizard'''
        if not action:
            return
        if hasattr(self, action):
            f = getattr(self, action)
            apply(f, *args)
        else:
            raise BaseException("unknown action", action)

    def on_release(self, dialog, button):
        if not button or button.action == 'cancel':
            # soft back or escape button pressed
            return self.dispatch('on_wizard_complete', None)
        action = button.action if self.wallet is None else self.wallet.get_action()
        print "action", action
        dialog.close()
        self.run(action)

    def add_seed_or_xpub(self):
        msg = ' '.join([
            _("Do you want to create a new seed, or to restore a wallet using an existing seed?")
        ])
        choices = [
            (_('Create a new seed'), 'create_seed'),
            (_('I already have a seed'), 'restore_seed'),
            (_('Watching-only wallet'), 'restore_xpub')
        ]
        WizardChoiceDialog(msg=msg, choices=choices, on_release=self.on_release).open()

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
        WizardChoiceDialog(msg=msg, choices=choices, on_release=self.on_release).open()

    def choose_cosigners(self):
        def on_release(dialog, button):
            if not button:
                # soft back or escape button pressed
                return self.dispatch('on_wizard_complete', None)
            m = dialog.ids.m.value
            n = dialog.ids.n.value
            dialog.close()
            self.wallet_type = "%dof%d"%(m, n)
            self.run('add_seed_or_xpub')
        name = os.path.basename(self.storage.path)
        WizardMultisigDialog(on_release=on_release).open()

    def restore_seed(self):
        def on_seed(_dlg, btn):
            _dlg.close()
            if btn is _dlg.ids.back:
                self.run('new')
                return
            text = _dlg.get_text()
            self.run('enter_pin', (text,))
        msg = _('Please type your seed phrase using the virtual keyboard.')
        RestoreSeedDialog(test=Wallet.is_seed, message=msg, on_release=on_seed).open()

    def restore_xpub(self):
        def on_xpub(_dlg, btn):
            _dlg.close()
            if btn is _dlg.ids.back:
                self.run('new')
                return
            text = _dlg.get_text()
            self.run('create_wallet', (text, None))
        msg = _('To create a watching-only wallet, paste your master public key, or scan it using the camera button.')
        AddXpubDialog(test=Wallet.is_mpk, message=msg, on_release=on_xpub).open()

    def create_standard(self):
        self.wallet_type = 'standard'
        self.run('add_seed_or_xpub')

    def create_multisig(self):
        self.wallet_type = 'multisig'
        self.run('choose_cosigners')

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
        def on_xpub(_dlg, btn):
            xpub = _dlg.get_text()
            _dlg.close()
            self.wallet.add_master_public_key("x%d/" % 2, xpub)
            action = self.wallet.get_action()
            self.run(action)
        msg = _('Paste your cosigner xpub, or scan it using the camera button.')
        AddXpubDialog(test=Wallet.is_xpub, message=msg, on_release=on_xpub).open()

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
        from electrum_ltc.wallet import BIP32_Wallet
        seed = BIP32_Wallet.make_seed()
        msg = _("If you forget your PIN or lose your device, your seed phrase will be the "
                "only way to recover your funds.")
        def on_ok(_dlg, _btn):
            _dlg.close()
            if _btn == _dlg.ids.next:
                self.run('confirm_seed', (seed,))
            else:
                self.run('new')
        ShowSeedDialog(message=msg, seed_text=seed, on_release=on_ok).open()

    def confirm_seed(self, seed):
        assert Wallet.is_seed(seed)
        def on_seed(_dlg, btn):
            if btn is _dlg.ids.back:
                _dlg.close()
                self.run('create_seed')
                return
            _dlg.close()
            self.run('enter_pin', (seed,))
        msg = _('Please retype your seed phrase, to confirm that you properly saved it')
        RestoreSeedDialog(test=lambda x: x==seed, message=msg, on_release=on_seed).open()

    def enter_pin(self, seed):
        def callback(pin):
            action = 'confirm_pin' if pin else 'create_wallet'
            self.run(action, (seed, pin))
        popup = PasswordDialog()
        popup.init('Choose a PIN code', callback)
        popup.open()

    def confirm_pin(self, seed, pin):
        def callback(conf):
            if conf == pin:
                self.run('create_wallet', (seed, pin))
            else:
                app.show_error(_('PIN mismatch'), duration=.5)
                self.run('enter_pin', (seed,))
        popup = PasswordDialog()
        popup.init('Confirm your PIN code', callback)
        popup.open()

    def terminate(self):
        self.wallet.start_threads(self.network)
        self.dispatch('on_wizard_complete', self.wallet)

    def on_wizard_complete(self, wallet):
        """overriden by main_window"""
        pass
