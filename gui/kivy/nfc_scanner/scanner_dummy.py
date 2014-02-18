''' Dummy NFC Provider to be used on desktops in case no other provider is found
'''
from electrum_gui.kivy.nfc_scanner import NFCBase
from kivy.clock import Clock
from kivy.logger import Logger

class ScannerDummy(NFCBase):

    _initialised = False

    def nfc_init(self):
        # print 'nfc_init()'

        Logger.debug('NFC: configure nfc')
        self._initialised = True

    def on_new_intent(self, dt):
        Logger.debug('NFC: got new dummy tag')

    def nfc_enable(self):
        Logger.debug('NFC: enable')
        if self._initialised:
            Clock.schedule_interval(self.on_new_intent, 22)

    def nfc_disable(self):
        # print 'nfc_enable()'
        Clock.unschedule(self.on_new_intent)

    def nfc_enable_exchange(self, data):
        ''' Start sending data
        '''
        Logger.debug('NFC: sending data {}'.format(data))

    def nfc_disable_exchange(self):
        ''' Disable/Stop ndef exchange
        '''
        Logger.debug('NFC: disable nfc exchange')
