'''
'''
from kivy.core import core_select_lib
from kivy.uix.widget import Widget
from kivy.properties import ObjectProperty
from kivy.factory import Factory

__all__ = ('NFCBase', 'NFCScanner')

class NFCBase(Widget):

    payload = ObjectProperty(None)

    def nfc_init(self):
        ''' Initialize the adapter
        '''
        pass

    def nfc_disable(self):
        ''' Disable scanning
        '''
        pass

    def nfc_enable(self):
        ''' Enable Scanning
        '''
        pass

    def nfc_enable_exchange(self, data):
        ''' Start sending data
        '''
        pass

    def nfc_disable_exchange(self):
        ''' Disable/Stop ndef exchange
        '''
        pass

# load NFCScanner implementation

NFCScanner = core_select_lib('nfc_scanner', (
    ('android', 'scanner_android', 'ScannerAndroid'),
    ('dummy', 'scanner_dummy', 'ScannerDummy')), True, 'electrum_gui.kivy')
