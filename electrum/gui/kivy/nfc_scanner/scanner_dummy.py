''' Dummy NFC Provider to be used on desktops in case no other provider is found
'''
from . import NFCBase
from kivy.clock import Clock
from kivy.logger import Logger
from kivy.app import App

class ScannerDummy(NFCBase):
    '''This is the dummy interface that gets selected in case any other
    hardware interface to NFC is not available.
    '''

    _initialised = False

    name = 'NFCDummy'

    def nfc_init(self):
        # print 'nfc_init()'

        Logger.debug('NFC: configure nfc')
        self._initialised = True
        self.nfc_enable()
        return True

    def on_new_intent(self, dt):
        tag_info = {'type': 'dymmy',
                    'message': 'dummy',
                    'extra details': None}

        # let Main app know that a tag has been detected
        app = App.get_running_app()
        app.tag_discovered(tag_info)
        app.show_info('New tag detected.', duration=2)
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
