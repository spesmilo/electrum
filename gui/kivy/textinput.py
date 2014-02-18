from kivy.uix.textinput import TextInput
from kivy.properties import OptionProperty

class ELTextInput(TextInput):

    def insert_text(self, substring, from_undo=False):
        if not from_undo:
            if self.input_type == 'numbers':
                numeric_list = map(str, range(10))
                if '.' not in self.text:
                    numeric_list.append('.')
                if substring not in numeric_list:
                    return
        super(ELTextInput, self).insert_text(substring, from_undo=from_undo)
