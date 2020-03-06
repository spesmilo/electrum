from typing import Callable, TYPE_CHECKING, Optional, Union

from kivy.app import App
from kivy.factory import Factory
from kivy.properties import ObjectProperty
from kivy.lang import Builder
from decimal import Decimal
from kivy.clock import Clock

from electrum.util import InvalidPassword
from electrum.gui.kivy.i18n import _

if TYPE_CHECKING:
    from ...main_window import ElectrumWindow
    from electrum.wallet import Abstract_Wallet
    from electrum.storage import WalletStorage

Builder.load_string('''

<PasswordDialog@Popup>
    id: popup
    is_generic: False
    title: 'Electrum'
    message: ''
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
        BoxLayout:
            orientation: 'horizontal'
            id: box_generic_password
            visible: root.is_generic
            size_hint_y: 0.05
            opacity: 1 if self.visible else 0
            disabled: not self.visible
            WizardTextInput:
                id: textinput_generic_password
                valign: 'center'
                multiline: False
                on_text_validate:
                    popup.on_password(self.text)
                password: True
                size_hint: 0.9, None
                unfocus_on_touch: False
                focus: root.is_generic
            Button:
                size_hint: 0.1, None
                valign: 'center'
                background_normal: 'atlas://electrum/gui/kivy/theming/light/eye1'
                background_down: self.background_normal
                height: '50dp'
                width: '50dp'
                padding: '5dp', '5dp'
                on_release:
                    textinput_generic_password.password = False if textinput_generic_password.password else True
        Label:
            id: label_pin
            visible: not root.is_generic
            size_hint_y: 0.05
            opacity: 1 if self.visible else 0
            disabled: not self.visible
            font_size: '50dp'
            text: '*'*len(kb.password) + '-'*(6-len(kb.password))
            size: self.texture_size
        Widget:
            size_hint: 1, 0.05
        GridLayout:
            id: kb
            disabled: root.is_generic
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


class PasswordDialog(Factory.Popup):

    def init(self, app: 'ElectrumWindow', *,
             check_password = None,
             on_success: Callable = None, on_failure: Callable = None,
             is_change: bool = False,
             is_password: bool = True,  # whether this is for a generic password or for a numeric PIN
             has_password: bool = False,
             message: str = ''):
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
        self.is_generic = is_password
        self.update_screen()

    def update_screen(self):
        self.ids.kb.password = ''
        self.ids.textinput_generic_password.text = ''
        if self.level == 0 and self.message == '':
            self.message = _('Enter your password') if self.is_generic else _('Enter your PIN')
        elif self.level == 1:
            self.message = _('Enter new password') if self.is_generic else _('Enter new PIN')
        elif self.level == 2:
            self.message = _('Confirm new password') if self.is_generic else _('Confirm new PIN')

    def check_password(self, password):
        if self.level > 0:
            return True
        try:
            self.pw_check(password)
            return True
        except InvalidPassword as e:
            return False

    def on_dismiss(self):
        if self.level == 1 and not self.is_generic and self.on_success:
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


    def on_password(self, pw: str):
        # if setting new generic password, enforce min length
        if self.is_generic and self.level > 0:
            if len(pw) < 6:
                self.app.show_error(_('Password is too short (min {} characters)').format(6))
                return
        # PIN codes are exactly 6 chars; generic pw can be any (don't enforce minimum on existing)
        if len(pw) >= 6 or self.is_generic:
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
                self.app.show_error(_('Wrong PIN'))
                self.ids.kb.password = ''
