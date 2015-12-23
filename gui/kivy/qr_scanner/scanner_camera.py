from kivy.uix.camera import Camera
from kivy.clock import Clock
from kivy.utils import platform

from electrum_gui.kivy.qr_scanner import ScannerBase

import iconv 

try:
    from zbar import ImageScanner, Config, Image, Symbol
except ImportError:
    raise SystemError('unable to import zbar please make sure you have'
        ' it installed.\nFor mac osx: `brew install zbar then\n`'
        '`pip install https://github.com/npinchot/zbar/archive/d3c1611ad2411fbdc3e79eb96ca704a63d30ae69.zip`')
try:
    from PIL import Image as PILImage
except ImportError:
    raise SystemError('unable to import Pil/pillow'
                      ' please install one of the two.')

__all__ = ('ScannerCamera', )

class ScannerCamera(ScannerBase):
    '''Widget that use the kivy.uix.camera.Camera and zbar to detect
    qrcode. When found, the `symbols` will be updated
    '''

    def __init__(self, **kwargs):
        super(ScannerCamera, self).__init__(**kwargs)
        self._camera = None
        # create a scanner used for detecting qrcode
        self._scanner = ImageScanner()
        self._scanner.parse_config('enable')
        #self._scanner.setConfig(Symbol.QRCODE, Config.ENABLE, 1)
        #self._scanner.setConfig(0, Config.X_DENSITY, 3)
        #self._scanner.setConfig(0, Config.Y_DENSITY, 3)

    def start(self):
        if not self._camera:
            self._camera = Camera(
                    resolution=self.camera_size,
                    size_hint=(None, None))
            self.add_widget(self._camera)
            self.bind(size=self._camera.setter('size'))
            self.bind(pos=self._camera.setter('pos'))
        else:
            self._camera._camera.init_camera()
        self._camera.play = True
        Clock.schedule_interval(self._detect_qrcode_frame, 1/15)

    def stop(self):
        if not self._camera:
            return
        self._camera.play = False
        Clock.unschedule(self._detect_qrcode_frame)
        # TODO: testing for various platforms(windows, mac)
        if platform == 'linux':
            self._camera._camera._pipeline.set_state(1)
        #self._camera = None

    def _detect_qrcode_frame(self, *args):
        # the image we got by default from a camera is using the rgba format
        # zbar only allow Y800/GREY image, so we first need to convert,
        # then start the detection on the image
        if not self.get_root_window():
            self.stop()
            return
        cam = self._camera
        tex = cam.texture
        if not tex:
            return
        im = PILImage.fromstring('RGBA', tex.size, tex.pixels)
        im = im.convert('L')
        barcode = Image(tex.size[0],
                        tex.size[1], 'Y800', im.tostring())

        result = self._scanner.scan(barcode)

        if result == 0:
            self.symbols = []
            del(barcode)
            return

        # we detected qrcode! extract and dispatch them
        symbols = []
        for symbol in barcode.symbols:
            qrcode = ScannerCamera.Qrcode(
                type=symbol.type,
                data=symbol.data,
                quality=symbol.quality,
                count=symbol.count,
                bounds=symbol.location)
            symbols.append(qrcode)

        self.symbols = symbols
        del(barcode)
