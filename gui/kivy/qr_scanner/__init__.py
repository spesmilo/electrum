'''QrScanner Base Abstract implementation
'''

__all__ = ('ScannerBase', 'QRScanner')

from collections import namedtuple

from kivy.uix.anchorlayout import AnchorLayout
from kivy.core import core_select_lib
from kivy.metrics import dp
from kivy.properties import ListProperty, BooleanProperty
from kivy.factory import Factory


class ScannerBase(AnchorLayout):
    ''' Base implementation for camera based scanner
    '''
    camera_size = ListProperty([320, 240] if dp(1) < 2 else [640, 480])

    symbols = ListProperty([])

    # XXX can't work now, due to overlay.
    show_bounds = BooleanProperty(False)

    running = BooleanProperty(False)

    Qrcode = namedtuple('Qrcode',
            ['type', 'data', 'bounds', 'quality', 'count'])

    def start(self):
        pass

    def stop(self):
        pass

    def on_symbols(self, instance, value):
        #if self.show_bounds:
        #    self.update_bounds()
        pass

    def update_bounds(self):
        self.canvas.after.remove_group('bounds')
        if not self.symbols:
            return
        with self.canvas.after:
            Color(1, 0, 0, group='bounds')
            for symbol in self.symbols:
                x, y, w, h = symbol.bounds
                x = self._camera.right - x - w
                y = self._camera.top - y - h
                Line(rectangle=[x, y, w, h], group='bounds')


# load QRCodeDetector implementation

QRScanner = core_select_lib('qr_scanner', (
    ('android', 'scanner_android', 'ScannerAndroid'),
    ('camera', 'scanner_camera', 'ScannerCamera')), False, 'electrum_gui.kivy')

Factory.register('QRScanner', cls=QRScanner)
