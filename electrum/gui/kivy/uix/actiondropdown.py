from typing import NamedTuple, Callable, Sequence

from kivy.uix.dropdown import DropDown
from kivy.uix.button import Button

from electrum.gui.kivy.i18n import _


class ActionButtonOption(NamedTuple):
    text: str
    func: Callable[['Button'], None]
    enabled: bool = True


class ActionDropdown(Button):
    """A button that offers a list of actions and can expand into a dropdown.

    If the list of available actions:
    - is empty, the button will be hidden,
    - consists of a single option, the button will correspond to that,
    - consists of multiple options, the button opens a dropdown which has one sub-button for each.
    """

    def __init__(self, **kwargs):
        Button.__init__(
            self,
            text='',
            disabled=True,
            opacity=0,
            **kwargs,
        )
        self.dropdown_text = _('Options')
        self._on_release = None

    def update(self, *, options: Sequence[ActionButtonOption] = ()):
        num_options = sum(map(lambda o: bool(o.enabled), options))
        # if no options available, hide button
        if num_options == 0:
            self.disabled = True
            self.opacity = 0
            return
        self.disabled = False
        self.opacity = 1

        if num_options == 1:
            # only one option, button will correspond to that
            for option in options:
                if option.enabled:
                    self.text = option.text
                    self._on_release = option.func
        else:
            # multiple options. button opens dropdown which has one sub-button for each
            dropdown = DropDown()
            self.text = self.dropdown_text
            self._on_release = dropdown.open
            def on_btn(option_func):
                def _on_btn(btn):
                    dropdown.dismiss()
                    option_func(btn)
                return _on_btn
            for option in options:
                if option.enabled:
                    btn = Button(
                        text=option.text,
                        size_hint_y=None,
                        height=self.height,
                        halign='center',
                        valign='center',
                    )
                    btn.bind(on_release=on_btn(option.func))
                    dropdown.add_widget(btn)

    def on_release(self):
        if self._on_release:
            self._on_release(self)
