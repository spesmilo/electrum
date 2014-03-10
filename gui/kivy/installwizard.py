from electrum import Wallet
from electrum.i18n import _

from kivy.app import App
from kivy.uix.widget import Widget
from kivy.core.window import Window
from kivy.clock import Clock

from electrum_gui.kivy.dialog import CreateRestoreDialog
#from network_dialog import NetworkDialog
#from util import *
#from amountedit import AmountEdit

import sys
import threading
from functools import partial

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

    def run(self):
        '''Entry point of our Installation wizard
        '''
        CreateRestoreDialog(on_release=self.on_creatrestore_complete).open()

    def on_creatrestore_complete(self, dialog, button):
        if not button:
            return self.dispatch('on_wizard_complete', None)

        #gap = self.config.get('gap_limit', 5)
        #if gap !=5:
        #    wallet.gap_limit = gap_limit
        #    wallet.storage.put('gap_limit', gap, True)

        dialog.close()
        if button == dialog.ids.create:
            # create
            wallet = Wallet(self.storage)
            self.change_password_dialog(wallet=wallet)
        elif button == dialog.ids.restore:
            # restore
            wallet = None
            self.restore_seed_dialog(wallet)
        #if button == dialog.ids.watching:
        #TODO: not available in the new design
        #    self.action = 'watching'
        else:
            self.dispatch('on_wizard_complete', None)

    def restore_seed_dialog(self, wallet):
        from electrum_gui.kivy.dialog import RestoreSeedDialog
        RestoreSeedDialog(
            on_release=partial(self.on_verify_restore_ok, wallet)).open()

    def on_verify_restore_ok(self, wallet, _dlg, btn, restore=False):

        if _dlg.ids.back == btn:
            _dlg.close()
            CreateRestoreDialog(
                on_release=self.on_creatrestore_complete).open()
            return

        seed = unicode(_dlg.ids.text_input_seed.text)
        if not seed:
            app.show_error(_("No seed!"), duration=.5)
            return

        try:
            wallet = Wallet.from_seed(seed, self.storage)
        except Exception as err:
            _dlg.close()
            return app.show_error(str(err) + '\n App will now exit',
                           exit=True, modal=True, duration=.5)
        _dlg.close()
        return self.change_password_dialog(wallet=wallet, mode='restore')


    def init_seed_dialog(self, wallet=None, instance=None, password=None,
                         wallet_name=None, mode='create'):
        # renamed from show_seed()
        '''Can be called directly (password is None)
        or from a password-protected callback (password is not None)'''

        if not wallet or not wallet.seed:
            if instance == None:
                wallet.init_seed(None)
            else:
                return app.show_error(_('No seed'))

        if password is None or not instance:
            seed = wallet.get_mnemonic(None)
        else:
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
            if _btn != _dlg.ids.confirm:
                if not instance:
                    self.change_password_dialog(wallet)
                return
            # confirm
            if instance is None:
                # in initial phase
                def create(password):
                    try:
                        password = None if not password else password
                        wallet.save_seed(password)
                    except Exception as err:
                        Logger.Info('Wallet: {}'.format(err))
                        Clock.schedule_once(lambda dt:
                            app.show_error(err))
                    wallet.synchronize()  # generate first addresses offline
                self.waiting_dialog(
                    partial(create, password),
                    on_complete=partial(self.load_network, wallet, mode=mode))

        from electrum_gui.kivy.dialog import InitSeedDialog
        InitSeedDialog(message=msg2,
            seed_msg=brainwallet, seed=seed, on_release=on_ok_press).open()

    def change_password_dialog(self, wallet=None, instance=None, mode='create'):
        """Can be called directly (instance is None)
        or from a callback (instance is not None)"""

        if instance and not wallet.seed:
            return ShowError(_('No seed !!'), exit=True, modal=True)

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

        def on_release(_dlg, _btn):
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
                    CreateRestoreDialog(
                        on_release=self.on_creatrestore_complete).open()
                return

            # Confirm
            wallet_name = _dlg.ids.ti_wallet_name.text
            password = (unicode(ti_password.text)
                        if wallet.use_encryption else
                        None)
            new_password = unicode(ti_new_password.text)
            new_password2 = unicode(ti_confirm_password.text)

            if new_password != new_password2:
                ti_password.text = ""
                ti_new_password.text = ""
                ti_confirm_password.text = ""
                if ti_password.disabled:
                    ti_new_password.focus = True
                else:
                    ti_password.focus = True
                return app.show_error(_('Passwords do not match'), duration=.5)

            if mode == 'restore':
                def on_complete(*l):
                    _dlg.close()
                    self.load_network(wallet, mode='restore')

                self.waiting_dialog(lambda: wallet.save_seed(new_password),
                                    msg=_("saving seed"),
                                    on_complete=on_complete)
                return
            if not instance:
                # create
                _dlg.close()
                #self.load_network(wallet, mode='create')
                return self.init_seed_dialog(password=new_password,
                    wallet=wallet, wallet_name=wallet_name, mode=mode)

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

        from electrum_gui.kivy.dialog import ChangePasswordDialog
        cpd = ChangePasswordDialog(
                             message=msg,
                             mode=mode,
                             on_release=on_release).open()

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
