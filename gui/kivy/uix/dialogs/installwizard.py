from electrum import Wallet
from electrum.i18n import _

from kivy.app import App
from kivy.uix.widget import Widget
from kivy.core.window import Window
from kivy.clock import Clock
from kivy.factory import Factory

Factory.register('CreateRestoreDialog',
                 module='electrum_gui.kivy.uix.dialogs.create_restore')

import sys
import threading
from functools import partial
import weakref

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
        self.wallet = Wallet(self.storage)
        self.is_restore = False

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

    def is_any(self, seed_e):
        text = self.get_seed_text(seed_e)
        return Wallet.is_any(text)

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
        def on_release(dialog, button):
            if not button:
                # soft back or escape button pressed
                return self.dispatch('on_wizard_complete', None)
            dialog.close()
            action = dialog.action
            if button == dialog.ids.create:
                self.run('create')
            elif button == dialog.ids.restore:
                self.run('restore')
            else:
                self.dispatch('on_wizard_complete', None)
        Factory.CreateRestoreDialog(on_release=on_release).open()

    def restore(self):
        from create_restore import RestoreSeedDialog
        self.is_restore = True
        def on_seed(_dlg, btn):
            if btn is _dlg.ids.back:
                _dlg.close()
                self.run('new')
                return
            text = _dlg.get_seed_text()
            need_password = Wallet.should_encrypt(text)
            _dlg.close()
            if need_password:
                self.run('enter_pin', (text,))
            else:
                self.wallet = Wallet.from_text(text)
                # fixme: sync
        msg = _('You may also enter an extended public key, to create a watching-only wallet')
        RestoreSeedDialog(test=Wallet.is_any, message=msg, on_release=partial(on_seed)).open()

    def add_seed(self, seed, password):
        def task():
            self.wallet.add_seed(seed, password)
            self.wallet.create_master_keys(password)
            self.wallet.create_main_account()
            self.wallet.synchronize()
        msg= _("Electrum is generating your addresses, please wait.")
        self.waiting_dialog(task, msg, self.terminate)

    def create(self):
        from create_restore import ShowSeedDialog
        self.is_restore = False
        seed = self.wallet.make_seed()
        msg = _("If you forget your PIN or lose your device, your seed phrase will be the "
                "only way to recover your funds.")
        def on_ok(_dlg, _btn):
            _dlg.close()
            if _btn == _dlg.ids.confirm:
                self.run('confirm_seed', (seed,))
            else:
                self.run('new')
        ShowSeedDialog(message=msg, seed_text=seed, on_release=on_ok).open()

    def confirm_seed(self, seed):
        from create_restore import RestoreSeedDialog
        def on_seed(_dlg, btn):
            if btn is _dlg.ids.back:
                _dlg.close()
                self.run('create')
                return
            _dlg.close()
            if Wallet.should_encrypt(seed):
                self.run('enter_pin', (seed,))
            else:
                self.wallet = Wallet.from_text(seed)
                # fixme: sync
        msg = _('Please retype your seed phrase, to confirm that you properly saved it')
        RestoreSeedDialog(test=lambda x: x==seed, message=msg, on_release=partial(on_seed)).open()

    def enter_pin(self, seed):
        from password_dialog import PasswordDialog
        def callback(pin):
            self.run('confirm_pin', (seed, pin))
        popup = PasswordDialog('Choose a PIN code', callback)
        popup.open()

    def confirm_pin(self, seed, pin):
        from password_dialog import PasswordDialog
        def callback(conf):
            if conf == pin:
                self.run('add_seed', (seed, pin))
            else:
                app.show_error(_('PIN mismatch'), duration=.5)
                self.run('enter_pin', (seed,))
        popup = PasswordDialog('Confirm your PIN code', callback)
        popup.open()

    def terminate(self):
        self.wallet.start_threads(self.network)
        #if self.is_restore:
        #    if self.wallet.is_found():
        #        app.show_info(_("Recovery successful"), duration=.5)
        #    else:
        #        app.show_info(_("No transactions found for this seed"), duration=.5)
        self.dispatch('on_wizard_complete', self.wallet)

    def on_wizard_complete(self, wallet):
        """overriden by main_window"""
        pass
