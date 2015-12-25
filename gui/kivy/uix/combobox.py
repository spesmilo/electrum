'''
ComboBox
=======

Based on Spinner
'''

__all__ = ('ComboBox', 'ComboBoxOption')

from kivy.properties import ListProperty, ObjectProperty, BooleanProperty
from kivy.uix.button import Button
from kivy.uix.dropdown import DropDown
from kivy.lang import Builder


Builder.load_string('''
<ComboBoxOption>:
    size_hint_y: None
    height: 44

<ComboBox>:
    background_normal: 'atlas://data/images/defaulttheme/spinner'
    background_down: 'atlas://data/images/defaulttheme/spinner_pressed'
    on_key:
        if self.items: x, y = zip(*self.items); self.text = y[x.index(args[1])]
''')


class ComboBoxOption(Button):
    pass


class ComboBox(Button):
    items = ListProperty()
    key = ObjectProperty()

    option_cls = ObjectProperty(ComboBoxOption)

    dropdown_cls = ObjectProperty(DropDown)

    is_open = BooleanProperty(False)

    def __init__(self, **kwargs):
        self._dropdown = None
        super(ComboBox, self).__init__(**kwargs)
        self.items_dict = dict(self.items)
        self.bind(
            on_release=self._toggle_dropdown,
            dropdown_cls=self._build_dropdown,
            option_cls=self._build_dropdown,
            items=self._update_dropdown,
            key=self._update_text)
        self._build_dropdown()
        self._update_text()

    def _update_text(self, *largs):
        try:
            self.text = self.items_dict[self.key]
        except KeyError:
            pass

    def _build_dropdown(self, *largs):
        if self._dropdown:
            self._dropdown.unbind(on_select=self._on_dropdown_select)
            self._dropdown.dismiss()
            self._dropdown = None
        self._dropdown = self.dropdown_cls()
        self._dropdown.bind(on_select=self._on_dropdown_select)
        self._update_dropdown()

    def _update_dropdown(self, *largs):
        dp = self._dropdown
        cls = self.option_cls
        dp.clear_widgets()
        for key, value in self.items:
            item = cls(text=value)
            # extra attribute
            item.key = key
            item.bind(on_release=lambda option: dp.select(option.key))
            dp.add_widget(item)

    def _toggle_dropdown(self, *largs):
        self.is_open = not self.is_open

    def _on_dropdown_select(self, instance, data, *largs):
        self.key = data
        self.is_open = False

    def on_is_open(self, instance, value):
        if value:
            self._dropdown.open(self)
        else:
            self._dropdown.dismiss()
