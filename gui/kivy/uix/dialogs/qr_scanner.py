from kivy.app import App
from kivy.factory import Factory
from kivy.lang import Builder

Factory.register('QRScanner', module='electrum_gui.kivy.qr_scanner')

class QrScannerDialog(Factory.AnimatedPopup):

    __events__ = ('on_complete', )

    def on_symbols(self, instance, value):
        instance.stop()
        self.dismiss()
        data = value[0].data
        self.dispatch('on_complete', data)

    def on_complete(self, x):
        ''' Default Handler for on_complete event.
        '''
        print x


Builder.load_string('''
<QrScannerDialog>
    title:
        _(\
        '[size=18dp]Hold your QRCode up to the camera[/size][size=7dp]\\n[/size]')
    title_size: '24sp'
    border: 7, 7, 7, 7
    size_hint: None, None
    size: '340dp', '290dp'
    pos_hint: {'center_y': .53}
    #separator_color: .89, .89, .89, 1
    #separator_height: '1.2dp'
    #title_color: .437, .437, .437, 1
    #background: 'atlas://gui/kivy/theming/light/dialog'
    on_activate:
        qrscr.start()
        qrscr.size = self.size
    on_deactivate: qrscr.stop()
    QRScanner:
        id: qrscr
        on_symbols: root.on_symbols(*args)
''')
