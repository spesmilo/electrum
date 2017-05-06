__all__ = ('NFCBase', 'NFCScanner')

class NFCBase(Widget):
    ''' This is the base Abstract definition class that the actual hardware dependent
    implementations would be based on. If you want to define a feature that is
    accissible and implemented by every platform implementation then define that
    method in this class.
    '''

    payload = ObjectProperty(None)
    '''This is the data gotten from the tag. 
    '''

    def nfc_init(self):
        ''' Initialize the adapter.
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
        ''' Enable P2P Ndef exchange
        '''
        pass

    def nfc_disable_exchange(self):
        ''' Disable/Stop P2P Ndef exchange
        '''
        pass

# load NFCScanner implementation

NFCScanner = core_select_lib('nfc_manager', (
    # keep the dummy implementtation as the last one to make it the fallback provider.NFCScanner = core_select_lib('nfc_scanner', (
    ('android', 'scanner_android', 'ScannerAndroid'),
    ('dummy', 'scanner_dummy', 'ScannerDummy')), True, 'electrum_gui.kivy')
