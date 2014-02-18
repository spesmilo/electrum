from electrum import Wallet
from electrum.i18n import _
from electrum_gui.kivy.dialog import (CreateRestoreDialog, InitSeedDialog,
    ChangePasswordDialog)

from kivy.app import App
from kivy.uix.widget import Widget
from kivy.core.window import Window
from kivy.clock import Clock

#from seed_dialog import SeedDialog
#from network_dialog import NetworkDialog
#from util import *
#from amountedit import AmountEdit

import sys
import threading
from functools import partial

# global Variables
app = App.get_running_app()


class InstallWizard(Widget):

    __events__ = ('on_wizard_complete', )

    def __init__(self, config, network, storage):
        super(InstallWizard, self).__init__()
        self.config  = config
        self.network = network
        self.storage = storage

    def waiting_dialog(self, task,
                       msg= _("Electrum is generating your addresses,"
                              " please wait.")):
        def target():
            task()
            Clock.schedule_once(lambda dt:
                app.show_info_bubble(text="Complete", duration=.5,
                    icon='atlas://gui/kivy/theming/light/important',
                    pos=Window.center, width='200dp', arrow_pos=None))

        app.show_info_bubble(
            text=msg, icon='atlas://gui/kivy/theming/light/important',
            pos=Window.center, width='200sp', arrow_pos=None, modal=True)
        t = threading.Thread(target = target)
        t.start()

    def run(self):
        CreateRestoreDialog(on_release=self.on_creatrestore_complete).open()

    def on_creatrestore_complete(self, dialog, button):
        if not button:
            self.dispatch('on_wizard_complete', None)
            return
        wallet = Wallet(self.storage)
        gap = self.config.get('gap_limit', 5)
        if gap !=5:
            wallet.gap_limit = gap_limit
            wallet.storage.put('gap_limit', gap, True)

        dialog.close()
        if button == dialog.ids.create:
            # create
            self.change_password_dialog(wallet=wallet)
        elif button == dialog.ids.restore:
            # restore
            wallet.init_seed(None)
            self.restore_seed_dialog()
        #elif button == dialog.ids.watching:
        #    self.action = 'watching'
        else:
            self.dispatch('on_wizard_complete', None)

    def init_seed_dialog(self, wallet=None, instance=None, password=None,
                         wallet_name=None):
        # renamed from show_seed()
        '''Can be called directly (password is None)
        or from a password-protected callback (password is not None)'''

        if not wallet or not wallet.seed:
            if instance == None:
                wallet.init_seed(None)
            else:
                return MessageBoxError(message=_('No seed')).open()

        if password is None or not instance:
            seed = wallet.get_mnemonic(None)
        else:
            try:
                seed = self.wallet.get_seed(password)
            except Exception:
                return MessageBoxError(message=_('Incorrect Password'))

        brainwallet = seed

        msg2 = _("[color=#414141][b]"+\
                "[b]PLEASE WRITE DOWN YOUR SEED PASS[/b][/color]"+\
                "[size=9]\n\n[/size]" +\
                "[color=#929292]If you ever forget your pincode, your seed" +\
                " phrase will be the [color=#EB984E]"+\
                "[b]only way to recover[/b][/color] your wallet. Your " +\
                " [color=#EB984E][b]Bitcoins[/b][/color] will otherwise be" +\
                " [color=#EB984E]lost forever![/color]")

        if wallet.imported_keys:
            msg2 += "[b][color=#ff0000ff]" + _("WARNING") + "[/color]:[/b] " +\
                    _("Your wallet contains imported keys. These keys cannot" +\
                    " be recovered from seed.")

        def on_ok_press(_dlg, _btn):
            _dlg.close()
            if _btn != _dlg.ids.confirm:
                self.change_password_dialog(wallet)
                return
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
                self.waiting_dialog(partial(create, password))


        InitSeedDialog(message=msg2,
                        seed_msg=brainwallet,
                        seed=seed,
                        on_release=on_ok_press).open()

    def change_password_dialog(self, wallet=None, instance=None):
        """Can be called directly (instance is None)
        or from a callback (instance is not None)"""

        if instance and not wallet.seed:
            return MessageBoxExit(message=_('No seed !!')).open()

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
            mode = 'create'

        def on_release(_dlg, _btn):
            ti_password = _dlg.ids.ti_password
            ti_new_password = _dlg.ids.ti_new_password
            ti_confirm_password = _dlg.ids.ti_confirm_password
            if _btn != _dlg.ids.next:
                _dlg.close()
                if not instance:
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
                return app.show_error(_('Passwords do not match'))

            if not instance:
                _dlg.close()
                self.init_seed_dialog(password=new_password,
                                      wallet=wallet,
                                      wallet_name=wallet_name)
                return

            try:
                seed = wallet.decode_seed(password)
            except BaseException:
                return MessageBoxError(
                    message=_('Incorrect Password')).open()

            # test carefully
            try:
                wallet.update_password(seed, password, new_password)
            except BaseException:
                return MessageBoxExit(
                    message=_('Failed to update password')).open()
            else:
                app.show_info_bubble(
                    text=_('Password successfully updated'), duration=1,
                    pos=_btn.pos)
            _dlg.close()


            if instance is None:  # in initial phase
                self.load_wallet()
            self.app.gui.main_gui.update_wallet()

        cpd = ChangePasswordDialog(
                             message=msg,
                             mode=mode,
                             on_release=on_release).open()

    def on_wizard_complete(self, instance, wallet):
        pass
