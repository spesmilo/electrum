''' Kivy Widget that accepts data and displays qrcode
'''

from threading import Thread
from functools import partial

import qrcode

from kivy.uix.floatlayout import FloatLayout
from kivy.graphics.texture import Texture
from kivy.properties import StringProperty
from kivy.properties import ObjectProperty, StringProperty, ListProperty,\
    BooleanProperty
from kivy.lang import Builder
from kivy.clock import Clock



Builder.load_string('''
<QRCodeWidget>
    canvas.before:
        # Draw white Rectangle
        Color:
            rgba: root.background_color
        Rectangle:
            size: self.size
            pos: self.pos
    canvas.after:
        Color:
            rgba: root.foreground_color
        Rectangle:
            size: self.size
            pos: self.pos
    Image
        id: qrimage
        pos_hint: {'center_x': .5, 'center_y': .5}
        allow_stretch: True
        size_hint: None, None
        size: root.width * .9, root.height * .9
''')

class QRCodeWidget(FloatLayout):

    data = StringProperty(None, allow_none=True)

    background_color = ListProperty((1, 1, 1, 1))

    foreground_color = ListProperty((0, 0, 0, 0))


    #loading_image = StringProperty('gui/kivy/theming/loading.gif')

    def __init__(self, **kwargs):
        super(QRCodeWidget, self).__init__(**kwargs)
        self.data = None
        self.qr = None
        self._qrtexture = None

    def on_data(self, instance, value):
        print "on data", value
        if not (self.canvas or value):
            return
        img = self.ids.get('qrimage', None)

        if not img:
            # if texture hasn't yet been created delay the texture updation
            Clock.schedule_once(lambda dt: self.on_data(instance, value))
            return

        #Thread(target=partial(self.update_qr, )).start()
        self.update_qr()

    def set_data(self, data):
        print "set data", data
        if self.data == data:
            return
        MinSize = 210 if len(data) < 128 else 500
        self.setMinimumSize((MinSize, MinSize))
        self.data = data
        self.qr = None

    def update_qr(self):
        if not self.data and self.qr:
            return
        L = qrcode.constants.ERROR_CORRECT_L
        data = self.data
        self.qr = qr = qrcode.QRCode(
            version=None,
            error_correction=L,
            box_size=10,
            border=0,
        )
        qr.add_data(data)
        qr.make(fit=True)
        self.update_texture()

    def setMinimumSize(self, size):
        # currently unused, do we need this?
        self._texture_size = size

    def _create_texture(self, k, dt):
        self._qrtexture = texture = Texture.create(size=(k,k), colorfmt='rgb')
        # don't interpolate texture
        texture.min_filter = 'nearest'
        texture.mag_filter = 'nearest'

    def update_texture(self):
        if not self.qr:
            return

        matrix = self.qr.get_matrix()
        k = len(matrix)
        # create the texture in main UI thread otherwise
        # this will lead to memory corruption
        Clock.schedule_once(partial(self._create_texture, k), -1)
        buff = []
        bext = buff.extend
        cr, cg, cb, ca = self.background_color[:]
        cr, cg, cb = cr*255, cg*255, cb*255

        for r in range(k):
            for c in range(k):
                bext([0, 0, 0] if matrix[r][c] else [cr, cg, cb])

        # then blit the buffer
        buff = ''.join(map(chr, buff))
        # update texture in UI thread.
        Clock.schedule_once(lambda dt: self._upd_texture(buff), .1)

    def _upd_texture(self, buff):
        texture = self._qrtexture
        if not texture:
            # if texture hasn't yet been created delay the texture updation
            Clock.schedule_once(lambda dt: self._upd_texture(buff), .1)
            return
        texture.blit_buffer(buff, colorfmt='rgb', bufferfmt='ubyte')
        img =self.ids.qrimage
        img.anim_delay = -1
        img.texture = texture
        img.canvas.ask_update()

if __name__ == '__main__':
    from kivy.app import runTouchApp
    import sys
    data = str(sys.argv[1:])
    runTouchApp(QRCodeWidget(data=data))


