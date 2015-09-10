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

    def waiting_dialog(self, task,
                       msg= _("Electrum is generating your addresses,"
                              " please wait."),
                       on_complete=None):
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

            # call completion routine
            if on_complete:
                Clock.schedule_once(lambda dt: on_complete())

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
        return (Wallet.is_seed(text) or
                Wallet.is_mpk(text) or
                Wallet.is_address(text) or
                Wallet.is_private_key(text))

    def run(self, action):
        '''Entry point of our Installation wizard
        '''
        if not action:
            return

        Factory.CreateRestoreDialog(
            on_release=self.on_creatrestore_complete,
            action=action).open()

    def on_creatrestore_complete(self, dialog, button):
        if not button:
            # soft back or escape button pressed
            return self.dispatch('on_wizard_complete', None)
        dialog.close()

        action = dialog.action
        if button == dialog.ids.create:
            wallet = Wallet(self.storage)
            self.password_dialog(wallet=wallet, mode='create')

        elif button == dialog.ids.restore:
            wallet = None
            self.restore_seed_dialog(wallet)

        else:
            self.dispatch('on_wizard_complete', None)

    def restore_seed_dialog(self, wallet):
        from electrum_gui.kivy.uix.dialogs.create_restore import\
            RestoreSeedDialog
        RestoreSeedDialog(
            on_release=partial(self.on_verify_restore_ok, wallet),
            wizard=weakref.proxy(self)).open()


    def on_verify_restore_ok(self, wallet, _dlg, btn, restore=False):
        if btn in (_dlg.ids.back, _dlg.ids.but_close) :
            _dlg.close()
            Factory.CreateRestoreDialog(
                on_release=self.on_creatrestore_complete).open()
            return

        seed = self.get_seed_text(_dlg.ids.text_input_seed)
        if not seed:
            return app.show_error(_("No seed!"), duration=.5)

        _dlg.close()

        if Wallet.is_seed(seed):
            return self.password_dialog(wallet=wallet, mode='restore',
                                        seed=seed)
        elif Wallet.is_mpk(seed):
            wallet = Wallet.from_mpk(seed, self.storage)
        elif Wallet.is_address(seed):
            wallet = Wallet.from_address(seed, self.storage)
        elif Wallet.is_private_key(seed):
            wallet = Wallet.from_private_key(seed, self.storage)
        else:
            return app.show_error(_('Not a valid seed. App will now exit'),
                                  exit=True, modal=True, duration=.5)
        return


    def show_seed(self, wallet=None, instance=None, password=None,
                         wallet_name=None, mode='create', seed=''):
        if instance and (not wallet or not wallet.seed):
            return app.show_error(_('No seed'))

        if not seed:
            try:
                seed = self.wallet.get_seed(password)
            except Exception:
                return app.show_error(_('Incorrect Password'))

        brainwallet = seed

        msg2 = _("[color=#414141]"+\
                "[b]PLEASE WRITE DOWN YOUR SEED PASS[/b][/color]"+\
                "[size=9]\n\n[/size]" +\
                "[color=#929292]If you ever forget your pincode, your seed" +\
                " phrase will be the [color=#EB984E]"+\
                "[b]only way to recover[/b][/color] your wallet. Your " +\
                " [color=#EB984E][b]Bitcoins[/b][/color] will otherwise be" +\
                " [color=#EB984E][b]lost forever![/b][/color]")

        if wallet.imported_keys:
            msg2 += "[b][color=#ff0000ff]" + _("WARNING") + "[/color]:[/b] " +\
                    _("Your wallet contains imported keys. These keys cannot" +\
                    " be recovered from seed.")

        def on_ok_press(_dlg, _btn):
            _dlg.close()
            mode = _dlg.mode
            if _btn != _dlg.ids.confirm:
                if not instance:
                    self.password_dialog(wallet, mode=mode)
                return
            # confirm
            if instance is None:
                # in initial phase create mode
                # save seed with password

                def create(password):
                    wallet.add_seed(seed, password)
                    wallet.create_master_keys(password)
                    wallet.create_main_account(password)
                    wallet.synchronize()  # generate first addresses offline

                self.waiting_dialog(partial(create, password),
                                    on_complete=partial(self.load_network,
                                                        wallet, mode=mode))


        from electrum_gui.kivy.uix.dialogs.create_restore import InitSeedDialog
        InitSeedDialog(message=msg2,
            seed_msg=brainwallet, on_release=on_ok_press, mode=mode).open()

    def password_dialog(self, wallet=None, instance=None, mode='create',
                        seed=''):
        """Can be called directly (instance is None)
        or from a callback (instance is not None)"""
        app = App.get_running_app()

        if mode != 'create' and wallet and wallet.is_watching_only():
            return app.show_error('This is a watching only wallet')

        if instance and not wallet.seed:
            return app.show_error('No seed !!', exit=True, modal=True)

        if instance is not None:
            if wallet.use_encryption:
                msg = (
                    _('Your wallet is encrypted. Use this dialog to change" + \
                    " your password.') + '\n' + _('To disable wallet" + \
                    " encryption, enter an empty new password.'))
                mode = 'confirm'
            else:
               msg = _('Your wallet keys are not encrypted')
            mode = 'new'
        else:
            msg = _("Please choose a password to encrypt your wallet keys.") +\
                '\n' + _("Leave these fields empty if you want to disable" + \
                         " encryption.")

        def on_release(wallet, seed, _dlg, _btn):
            ti_password = _dlg.ids.ti_password
            ti_new_password = _dlg.ids.ti_new_password
            ti_confirm_password = _dlg.ids.ti_confirm_password
            if _btn != _dlg.ids.next:
                if mode == 'restore':
                    # back is disabled cause seed is already set
                    return
                _dlg.close()
                if not instance:
                    # back on create
                    Factory.CreateRestoreDialog(
                        on_release=self.on_creatrestore_complete).open()
                return

            # Confirm
            wallet_name = _dlg.ids.ti_wallet_name.text
            new_password = unicode(ti_new_password.text)
            new_password2 = unicode(ti_confirm_password.text)

            if new_password != new_password2:
                # passwords don't match
                ti_password.text = ""
                ti_new_password.text = ""
                ti_confirm_password.text = ""
                if ti_password.disabled:
                    ti_new_password.focus = True
                else:
                    ti_password.focus = True
                return app.show_error(_('Passwords do not match'), duration=.5)

            if not new_password:
                new_password = None

            if mode == 'restore':
                wallet = Wallet.from_seed(seed, self.storage)
                password = (unicode(ti_password.text)
                            if wallet and wallet.use_encryption else
                            None)

                def on_complete(*l):
                    wallet.create_accounts(new_password)
                    self.load_network(wallet, mode='restore')
                    _dlg.close()

                self.waiting_dialog(lambda: wallet.add_seed(seed, new_password),
                                    msg=_("saving seed"),
                                    on_complete=on_complete)
                return

            if not instance:
                # create mode
                _dlg.close()
                seed = wallet.make_seed()

                return self.show_seed(password=new_password, wallet=wallet,
                                      wallet_name=wallet_name, mode=mode,
                                      seed=seed)

            # change password mode
            try:
                seed = wallet.decode_seed(password)
            except BaseException:
                return app.show_error(_('Incorrect Password'), duration=.5)

            # test carefully
            try:
                wallet.update_password(seed, password, new_password)
            except BaseException:
                return app.show_error(_('Failed to update password'), exit=True)
            else:
                app.show_info_bubble(
                    text=_('Password successfully updated'), duration=1,
                    pos=_btn.pos)
            _dlg.close()

            if instance is None:  # in initial phase
                self.load_wallet()
            self.app.update_wallet()

        from electrum_gui.kivy.uix.dialogs.create_restore import ChangePasswordDialog
        cpd = ChangePasswordDialog(
                             message=msg,
                             mode=mode,
                             on_release=partial(on_release,
                                                wallet, seed)).open()

    def load_network(self, wallet, mode='create'):
        #if not self.config.get('server'):
        if self.network:
            if self.network.interfaces:
                if mode not in ('restore', 'create'):
                    self.network_dialog()
            else:
                app.show_error(_('You are offline'))
                self.network.stop()
                self.network = None

        if mode in ('restore', 'create'):
            # auto cycle
            self.config.set_key('auto_cycle', True, True)

        # start wallet threads
        wallet.start_threads(self.network)

        if not mode == 'restore':
            return self.dispatch('on_wizard_complete', wallet)

        def get_text(text):
            def set_text(*l): app.info_bubble.ids.lbl.text=text
            Clock.schedule_once(set_text)

        def on_complete(*l):
            if not self.network:
                app.show_info(
                    _("This wallet was restored offline. It may contain more"
                      " addresses than displayed."), duration=.5)
                return self.dispatch('on_wizard_complete', wallet)

            if wallet.is_found():
                app.show_info(_("Recovery successful"), duration=.5)
            else:
                app.show_info(_("No transactions found for this seed"),
                              duration=.5)
            return self.dispatch('on_wizard_complete', wallet)

        self.waiting_dialog(lambda: wallet.restore(get_text),
                            on_complete=on_complete)

    def on_wizard_complete(self, wallet):
        pass
