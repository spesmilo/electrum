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

    def waiting_dialog(self, task, msg):
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
        app.show_info_bubble(
            text=msg, icon='atlas://gui/kivy/theming/light/important',
            pos=Window.center, width='200sp', arrow_pos=None, modal=True)
        t = threading.Thread(target = target)
        t.start()

    def get_seed_text(self, ti_seed):
        text = unicode(ti_seed.text.lower()).strip()
        text = ' '.join(text.split())
        return text

    def is_any(self, seed_e):
        text = self.get_seed_text(seed_e)
        return Wallet.is_any(text)

    def run(self, action, *args):
        '''Entry point of our Installation wizard'''
        if not action:
            return
        if action == 'new':
            self.new()
        elif action == 'create':
            self.create()
        elif action == 'restore':
            self.restore()
        elif action == 'enter_pin':
            self.enter_pin(*args)
        elif action == 'confirm_pin':
            self.confirm_pin(*args)
        elif action == 'add_seed':
            self.add_seed(*args)
        elif action == 'terminate':
            self.terminate()
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
        def on_seed(_dlg, btn):
            if btn is _dlg.ids.back:
                _dlg.close()
                self.run('new')
                return
            text = self.get_seed_text(_dlg.ids.text_input_seed)
            need_password = Wallet.should_encrypt(text)
            _dlg.close()
            if need_password:
                self.run('enter_pin', text)
            else:
                self.wallet = Wallet.from_text(text)
                # fixme: sync
        RestoreSeedDialog(
            on_release=partial(on_seed),
            wizard=weakref.proxy(self)).open()

    def add_seed(self, seed, password):
        def task():
            self.wallet.add_seed(seed, password)
            self.wallet.create_master_keys(password)
            self.wallet.create_main_account()
            self.wallet.synchronize()
            self.run('terminate')
        msg= _("Electrum is generating your addresses, please wait.")
        self.waiting_dialog(task, msg)

    def create(self):
        from create_restore import InitSeedDialog
        seed = self.wallet.make_seed()
        msg = _("[color=#414141]"+\
                "[b]PLEASE WRITE DOWN YOUR SEED PASS[/b][/color]"+\
                "[size=9]\n\n[/size]" +\
                "[color=#929292]If you ever forget your pincode, your seed" +\
                " phrase will be the [color=#EB984E]"+\
                "[b]only way to recover[/b][/color] your wallet. Your " +\
                " [color=#EB984E][b]Bitcoins[/b][/color] will otherwise be" +\
                " [color=#EB984E][b]lost forever![/b][/color]")
        def on_ok(_dlg, _btn):
            _dlg.close()
            if _btn == _dlg.ids.confirm:
                self.run('enter_pin', seed)
            else:
                self.run('new')
        InitSeedDialog(message=msg, seed_msg=seed, on_release=on_ok, mode='create').open()

    def enter_pin(self, seed):
        from password_dialog import PasswordDialog
        def callback(pin):
            self.run('confirm_pin', seed, pin)
        popup = PasswordDialog('Enter PIN', callback)
        popup.open()

    def confirm_pin(self, seed, pin):
        from password_dialog import PasswordDialog
        def callback(conf):
            if conf == pin:
                self.run('add_seed', seed, pin)
            else:
                app = App.get_running_app()
                app.show_error(_('Passwords do not match'), duration=.5)
        popup = PasswordDialog('Confirm PIN', callback)
        popup.open()

    def terminate(self):
        self.wallet.start_threads(self.network)
        app.load_wallet(self.wallet)
        self.dispatch('on_wizard_complete', wallet)

    def on_wizard_complete(self, wallet):
        if wallet.is_found():
            app.show_info(_("Recovery successful"), duration=.5)
        else:
            app.show_info(_("No transactions found for this seed"),
                          duration=.5)
