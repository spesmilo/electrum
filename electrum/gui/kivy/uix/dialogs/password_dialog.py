from typing import Callable, TYPE_CHECKING, Optional, Union
import os

from kivy.app import App
from kivy.factory import Factory
from kivy.properties import ObjectProperty
from kivy.lang import Builder
from decimal import Decimal
from kivy.clock import Clock

from electrum.util import InvalidPassword
from electrum.wallet import WalletStorage, Wallet
from electrum.gui.kivy.i18n import _
from electrum.wallet_db import WalletDB

from .wallets import WalletDialog

if TYPE_CHECKING:
    from ...main_window import ElectrumWindow
    from electrum.wallet import Abstract_Wallet
    from electrum.storage import WalletStorage

Builder.load_string('''
#:import KIVY_GUI_PATH electrum.gui.kivy.KIVY_GUI_PATH

<PasswordDialog@Popup>
    id: popup
    title: 'Electrum'
    message: ''
    basename:''
    is_change: False
    hide_wallet_label: False
    require_password: True
    BoxLayout:
        size_hint: 1, 1
        orientation: 'vertical'
        spacing: '12dp'
        padding: '12dp'
        BoxLayout:
            size_hint: 1, None
            orientation: 'horizontal'
            height: '40dp'
            Label:
                size_hint: 0.85, None
                height: '40dp'
                font_size: '20dp'
                text: _('Wallet') + ': ' + root.basename
                text_size: self.width, None
                disabled: root.hide_wallet_label
                opacity: 0 if root.hide_wallet_label else 1
            IconButton:
                size_hint: 0.15, None
                height: '40dp'
                icon: f'atlas://{KIVY_GUI_PATH}/theming/light/btn_create_account'
                on_release: root.select_file()
                disabled: root.hide_wallet_label or root.is_change
                opacity: 0 if root.hide_wallet_label or root.is_change else 1
        Widget:
            size_hint: 1, 0.05
        Label:
            size_hint: 0.70, None
            font_size: '20dp'
            text: root.message
            text_size: self.width, None
        Widget:
            size_hint: 1, 0.05
        BoxLayout:
            orientation: 'horizontal'
            id: box_generic_password
            disabled: not root.require_password
            opacity: int(root.require_password)
            size_hint_y: 0.05
            height: '40dp'
            TextInput:
                height: '40dp'
                id: textinput_generic_password
                valign: 'center'
                multiline: False
                on_text_validate:
                    popup.on_password(self.text)
                password: True
                size_hint: 0.85, None
                unfocus_on_touch: False
                focus: True
            IconButton:
                height: '40dp'
                size_hint: 0.15, None
                icon: f'atlas://{KIVY_GUI_PATH}/theming/light/eye1'
                icon_size: '40dp'
                on_release:
                    textinput_generic_password.password = False if textinput_generic_password.password else True
        Widget:
            size_hint: 1, 1
        BoxLayout:
            orientation: 'horizontal'
            size_hint: 1, 0.5
            Button:
                text: 'Cancel'
                size_hint: 0.5, None
                height: '48dp'
                on_release: popup.dismiss()
            Button:
                text: 'Next'
                size_hint: 0.5, None
                height: '48dp'
                on_release:
                    popup.on_password(textinput_generic_password.text)


<PincodeDialog@Popup>
    id: popup
    title: 'Electrum'
    message: ''
    basename:''
    BoxLayout:
        size_hint: 1, 1
        orientation: 'vertical'
        Widget:
            size_hint: 1, 0.05
        Label:
            size_hint: 0.70, None
            font_size: '20dp'
            text: root.message
            text_size: self.width, None
        Widget:
            size_hint: 1, 0.05
        Label:
            id: label_pin
            size_hint_y: 0.05
            font_size: '50dp'
            text: '*'*len(kb.password) + '-'*(6-len(kb.password))
            size: self.texture_size
        Widget:
            size_hint: 1, 0.05
        GridLayout:
            id: kb
            size_hint: 1, None
            height: self.minimum_height
            update_amount: popup.update_password
            password: ''
            on_password: popup.on_password(self.password)
            spacing: '2dp'
            cols: 3
            KButton:
                text: '1'
            KButton:
                text: '2'
            KButton:
                text: '3'
            KButton:
                text: '4'
            KButton:
                text: '5'
            KButton:
                text: '6'
            KButton:
                text: '7'
            KButton:
                text: '8'
            KButton:
                text: '9'
            KButton:
                text: 'Clear'
            KButton:
                text: '0'
            KButton:
                text: '<'
''')


class AbstractPasswordDialog(Factory.Popup):

    def __init__(self, app: 'ElectrumWindow', *,
             check_password = None,
             on_success: Callable = None, on_failure: Callable = None,
             is_change: bool = False,
             is_password: bool = True,  # whether this is for a generic password or for a numeric PIN
             has_password: bool = False,
             message: str = '',
             basename:str=''):
        Factory.Popup.__init__(self)
        self.app = app
        self.pw_check = check_password
        self.message = message
        self.on_success = on_success
        self.on_failure = on_failure
        self.success = False
        self.is_change = is_change
        self.pw = None
        self.new_password = None
        self.title = 'Electrum'
        self.level = 1 if is_change and not has_password else 0
        self.basename = basename
        self.update_screen()

    def update_screen(self):
        self.clear_password()
        if self.level == 0 and self.message == '':
            self.message = self.enter_pw_message
        elif self.level == 1:
            self.message = self.enter_new_pw_message
        elif self.level == 2:
            self.message = self.confirm_new_pw_message

    def check_password(self, password):
        if self.level > 0:
            return True
        try:
            self.pw_check(password)
            return True
        except InvalidPassword as e:
            return False

    def on_dismiss(self):
        if self.level == 1 and self.allow_disable and self.on_success:
            self.on_success(self.pw, None)
            return False
        if not self.success:
            if self.on_failure:
                self.on_failure()
            else:
                # keep dialog open
                return True
        else:
            if self.on_success:
                args = (self.pw, self.new_password) if self.is_change else (self.pw,)
                Clock.schedule_once(lambda dt: self.on_success(*args), 0.1)

    def update_password(self, c):
        kb = self.ids.kb
        text = kb.password
        if c == '<':
            text = text[:-1]
        elif c == 'Clear':
            text = ''
        else:
            text += c
        kb.password = text


    def do_check(self, pw):
        if self.check_password(pw):
            if self.is_change is False:
                self.success = True
                self.pw = pw
                self.message = _('Please wait...')
                self.dismiss()
            elif self.level == 0:
                self.level = 1
                self.pw = pw
                self.update_screen()
            elif self.level == 1:
                self.level = 2
                self.new_password = pw
                self.update_screen()
            elif self.level == 2:
                self.success = pw == self.new_password
                self.dismiss()
        else:
            self.app.show_error(self.wrong_password_message)
            self.clear_password()


class PasswordDialog(AbstractPasswordDialog):
    enter_pw_message = _('Enter your password')
    enter_new_pw_message = _('Enter new password')
    confirm_new_pw_message = _('Confirm new password')
    wrong_password_message = _('Wrong password')
    allow_disable = False

    def __init__(self, app, **kwargs):
        AbstractPasswordDialog.__init__(self, app, **kwargs)
        self.hide_wallet_label = app._use_single_password

    def clear_password(self):
        self.ids.textinput_generic_password.text = ''

    def on_password(self, pw: str):
        #
        if not self.require_password:
            self.success = True
            self.message = _('Please wait...')
            self.dismiss()
            return
        # if setting new generic password, enforce min length
        if self.level > 0:
            if len(pw) < 6:
                self.app.show_error(_('Password is too short (min {} characters)').format(6))
                return
        # don't enforce minimum length on existing
        self.do_check(pw)



class PincodeDialog(AbstractPasswordDialog):
    enter_pw_message = _('Enter your PIN')
    enter_new_pw_message = _('Enter new PIN')
    confirm_new_pw_message = _('Confirm new PIN')
    wrong_password_message = _('Wrong PIN')
    allow_disable = True

    def __init__(self, app, **kwargs):
        AbstractPasswordDialog.__init__(self, app, **kwargs)

    def clear_password(self):
        self.ids.kb.password = ''

    def on_password(self, pw: str):
        # PIN codes are exactly 6 chars
        if len(pw) >= 6:
            self.do_check(pw)


class ChangePasswordDialog(PasswordDialog):

    def __init__(self, app, wallet, on_success, on_failure):
        PasswordDialog.__init__(self, app,
            basename = wallet.basename(),
            check_password = wallet.check_password,
            on_success=on_success,
            on_failure=on_failure,
            is_change=True,
            has_password=wallet.has_password())


class OpenWalletDialog(PasswordDialog):
    """This dialog will let the user choose another wallet file if they don't remember their the password"""

    def __init__(self, app, path, callback):
        self.app = app
        self.callback = callback
        PasswordDialog.__init__(self, app,
            on_success=lambda pw: self.callback(pw, self.storage),
            on_failure=self.app.stop)
        self.init_storage_from_path(path)

    def select_file(self):
        dirname = os.path.dirname(self.app.electrum_config.get_wallet_path())
        d = WalletDialog(dirname, self.init_storage_from_path, self.app.is_wallet_creation_disabled())
        d.open()

    def init_storage_from_path(self, path):
        self.storage = WalletStorage(path)
        self.basename = self.storage.basename()
        if not self.storage.file_exists():
            self.require_password = False
            self.message = _('Press Next to create')
        elif self.storage.is_encrypted():
            if not self.storage.is_encrypted_with_user_pw():
                raise Exception("Kivy GUI does not support this type of encrypted wallet files.")
            self.pw_check = self.storage.check_password
            if self.app.password and self.check_password(self.app.password):
                self.pw = self.app.password # must be set so that it is returned in callback
                self.require_password = False
                self.message = _('Press Next to open')
            else:
                self.require_password = True
                self.message = self.enter_pw_message
        else:
            # it is a bit wasteful load the wallet here and load it again in main_window,
            # but that is fine, because we are progressively enforcing storage encryption.
            db = WalletDB(self.storage.read(), manual_upgrades=False)
            wallet = Wallet(db, self.storage, config=self.app.electrum_config)
            self.require_password = wallet.has_password()
            self.pw_check = wallet.check_password
            self.message = self.enter_pw_message if self.require_password else _('Wallet not encrypted')
