'''QrScanner Base Abstract implementation
'''

__all__ = ('ScannerBase', 'QRScanner')

from collections import namedtuple

from kivy.uix.anchorlayout import AnchorLayout
from kivy.core import core_select_lib
from kivy.properties import ListProperty, BooleanProperty
from kivy.factory import Factory


def encode_uri(addr, amount=0, label='', message='', size='',
            currency='btc'):
    ''' Convert to BIP0021 compatible URI
    '''
    uri = 'bitcoin:{}'.format(addr)
    first = True
    if amount:
        uri += '{}amount={}'.format('?' if first else '&', amount)
        first = False
    if label:
        uri += '{}label={}'.format('?' if first else '&', label)
        first = False
    if message:
        uri += '{}?message={}'.format('?' if first else '&', message)
        first = False
    if size:
        uri += '{}size={}'.format('?' if not first else '&', size)
    return uri

def decode_uri(uri):
    if ':' not in uri:
        # It's just an address (not BIP21)
        return {'address': uri}

    if '//' not in uri:
        # Workaround for urlparse, it don't handle bitcoin: URI properly
        uri = uri.replace(':', '://')

    try:
        uri = urlparse(uri)
    except NameError:
        # delayed import
        from urlparse import urlparse, parse_qs
        uri = urlparse(uri)

    result = {'address': uri.netloc} 

    if uri.path.startswith('?'):
        params = parse_qs(uri.path[1:])
    else:
        params = parse_qs(uri.path)

    for k,v in params.items():
        if k in ('amount', 'label', 'message', 'size'):
            result[k] = v[0]

    return result


class ScannerBase(AnchorLayout):
    ''' Base implementation for camera based scanner
    '''
    camera_size = ListProperty([320, 240])

    symbols = ListProperty([])

    # XXX can't work now, due to overlay.
    show_bounds = BooleanProperty(False)

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
