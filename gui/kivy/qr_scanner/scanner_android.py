'''
Qrcode example application
==========================

Author: Mathieu Virbel <mat@meltingrocks.com>

License:
Copyright (c) 2013 Mathieu Virbel <mat@meltingrocks.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

Featuring:

- Android camera initialization
- Show the android camera into a Android surface that act as an overlay
- New AndroidWidgetHolder that control any android view as an overlay
- New ZbarQrcodeDetector that use AndroidCamera / PreviewFrame + zbar to
  detect Qrcode.

'''

__all__ = ('ScannerAndroid', )

from kivy.utils import platform
if platform != 'android':
    raise ImportError

from electrum_gui.kivy.qr_scanner import ScannerBase
from kivy.properties import ObjectProperty, NumericProperty
from kivy.uix.widget import Widget
from kivy.uix.anchorlayout import AnchorLayout
from kivy.graphics import Color, Line
from jnius import autoclass, PythonJavaClass, java_method, cast
from android.runnable import run_on_ui_thread

# preload java classes
System = autoclass('java.lang.System')
System.loadLibrary('iconv')
PythonActivity = autoclass('org.renpy.android.PythonActivity')
Camera = autoclass('android.hardware.Camera')
ImageScanner = autoclass('net.sourceforge.zbar.ImageScanner')
Image = autoclass('net.sourceforge.zbar.Image')
Symbol = autoclass('net.sourceforge.zbar.Symbol')
Config = autoclass('net.sourceforge.zbar.Config')
SurfaceView = autoclass('android.view.SurfaceView')
LayoutParams = autoclass('android.view.ViewGroup$LayoutParams')
ImageFormat = autoclass('android.graphics.ImageFormat')
LinearLayout = autoclass('android.widget.LinearLayout')


class PreviewCallback(PythonJavaClass):
    '''Interface used to get back the preview frame of the Android Camera
    '''
    __javainterfaces__ = ('android.hardware.Camera$PreviewCallback', )

    def __init__(self, callback):
        super(PreviewCallback, self).__init__()
        self.callback = callback

    @java_method('([BLandroid/hardware/Camera;)V')
    def onPreviewFrame(self, data, camera):
        self.callback(camera, data)


class SurfaceHolderCallback(PythonJavaClass):
    '''Interface used to know exactly when the Surface used for the Android
    Camera will be created and changed.
    '''

    __javainterfaces__ = ('android.view.SurfaceHolder$Callback', )

    def __init__(self, callback):
        super(SurfaceHolderCallback, self).__init__()
        self.callback = callback

    @java_method('(Landroid/view/SurfaceHolder;III)V')
    def surfaceChanged(self, surface, fmt, width, height):
        self.callback(fmt, width, height)

    @java_method('(Landroid/view/SurfaceHolder;)V')
    def surfaceCreated(self, surface):
        pass

    @java_method('(Landroid/view/SurfaceHolder;)V')
    def surfaceDestroyed(self, surface):
        pass


class AndroidWidgetHolder(Widget):
    '''Act as a placeholder for an Android widget.
    It will automatically add / remove the android view depending if the widget
    view is set or not. The android view will act as an overlay, so any graphics
    instruction in this area will be covered by the overlay.
    '''

    view = ObjectProperty(allownone=True)
    '''Must be an Android View
    '''

    def __init__(self, **kwargs):
        self._old_view = None
        from kivy.core.window import Window
        self._window = Window
        kwargs['size_hint'] = (None, None)
        super(AndroidWidgetHolder, self).__init__(**kwargs)

    def on_view(self, instance, view):
        if self._old_view is not None:
            layout = cast(LinearLayout, self._old_view.getParent())
            layout.removeView(self._old_view)
            self._old_view = None

        if view is None:
            return

        activity = PythonActivity.mActivity
        activity.addContentView(view, LayoutParams(*self.size))
        view.setZOrderOnTop(True)
        view.setX(self.x)
        view.setY(self._window.height - self.y - self.height)
        self._old_view = view

    def on_size(self, instance, size):
        if self.view:
            params = self.view.getLayoutParams()
            params.width = self.width
            params.height = self.height
            self.view.setLayoutParams(params)
            self.view.setY(self._window.height - self.y - self.height)

    def on_x(self, instance, x):
        if self.view:
            self.view.setX(x)

    def on_y(self, instance, y):
        if self.view:
            self.view.setY(self._window.height - self.y - self.height)


class AndroidCamera(Widget):
    '''Widget for controling an Android Camera.
    '''

    index = NumericProperty(0)

    __events__ = ('on_preview_frame', )

    def __init__(self, **kwargs):
        self._holder = None
        self._android_camera = None
        super(AndroidCamera, self).__init__(**kwargs)
        self._holder = AndroidWidgetHolder(size=self.size, pos=self.pos)
        self.add_widget(self._holder)

    @run_on_ui_thread
    def stop(self):
        self.running = False
        if self._android_camera is None:
            return
        self._android_camera.setPreviewCallback(None)
        self._android_camera.release()
        self._android_camera = None
        self._holder.view = None

    @run_on_ui_thread
    def start(self):
        self.running = True
        if self._android_camera is not None:
            return

        self._android_camera = Camera.open(self.index)

        # create a fake surfaceview to get the previewCallback working.
        self._android_surface = SurfaceView(PythonActivity.mActivity)
        surface_holder = self._android_surface.getHolder()

        # create our own surface holder to correctly call the next method when
        # the surface is ready
        self._android_surface_cb = SurfaceHolderCallback(self._on_surface_changed)
        surface_holder.addCallback(self._android_surface_cb)

        # attach the android surfaceview to our android widget holder
        self._holder.view = self._android_surface

        # set orientation
        self._android_camera.setDisplayOrientation(90)

    def _on_surface_changed(self, fmt, width, height):
        # internal, called when the android SurfaceView is ready
        # FIXME if the size is not handled by the camera, it will failed.
        params = self._android_camera.getParameters()
        params.setPreviewSize(width, height)
        self._android_camera.setParameters(params)

        # now that we know the camera size, we'll create 2 buffers for faster
        # result (using Callback buffer approach, as described in Camera android
        # documentation)
        # it also reduce the GC collection
        bpp = ImageFormat.getBitsPerPixel(params.getPreviewFormat()) / 8.
        buf = '\x00' * int(width * height * bpp)
        self._android_camera.addCallbackBuffer(buf)
        self._android_camera.addCallbackBuffer(buf)

        # create a PreviewCallback to get back the onPreviewFrame into python
        self._previewCallback = PreviewCallback(self._on_preview_frame)

        # connect everything and start the preview
        self._android_camera.setPreviewCallbackWithBuffer(self._previewCallback);
        self._android_camera.setPreviewDisplay(self._android_surface.getHolder())
        self._android_camera.startPreview();

    def _on_preview_frame(self, camera, data):
        # internal, called by the PreviewCallback when onPreviewFrame is
        # received
        self.dispatch('on_preview_frame', camera, data)
        # reintroduce the data buffer into the queue
        self._android_camera.addCallbackBuffer(data)

    def on_preview_frame(self, camera, data):
        pass

    def on_size(self, instance, size):
        if self._holder:
            self._holder.size = size

    def on_pos(self, instance, pos):
        if self._holder:
            self._holder.pos = pos


class ScannerAndroid(ScannerBase):
    '''Widget that use the AndroidCamera and zbar to detect qrcode.
    When found, the `symbols` will be updated
    '''

    def __init__(self, **kwargs):
        super(ScannerAndroid, self).__init__(**kwargs)
        self._camera = AndroidCamera(
                size=self.camera_size,
                size_hint=(None, None))
        self._camera.bind(on_preview_frame=self._detect_qrcode_frame)
        self.add_widget(self._camera)

        # create a scanner used for detecting qrcode
        self._scanner = ImageScanner()
        self._scanner.setConfig(0, Config.ENABLE, 0)
        self._scanner.setConfig(Symbol.QRCODE, Config.ENABLE, 1)
        self._scanner.setConfig(0, Config.X_DENSITY, 3)
        self._scanner.setConfig(0, Config.Y_DENSITY, 3)

    def start(self):
        self._camera.start()

    def stop(self):
        self._camera.stop()

    def _detect_qrcode_frame(self, instance, camera, data):
        # the image we got by default from a camera is using the NV21 format
        # zbar only allow Y800/GREY image, so we first need to convert,
        # then start the detection on the image
        if not self.get_root_window():
            self.stop()
            return
        parameters = camera.getParameters()
        size = parameters.getPreviewSize()
        barcode = Image(size.width, size.height, 'NV21')
        barcode.setData(data)
        barcode = barcode.convert('Y800')

        result = self._scanner.scanImage(barcode)

        if result == 0:
            self.symbols = []
            return

        # we detected qrcode! extract and dispatch them
        symbols = []
        it = barcode.getSymbols().iterator()
        while it.hasNext():
            symbol = it.next()
            qrcode = ScannerAndroid.Qrcode(
                type=symbol.getType(),
                data=symbol.getData(),
                quality=symbol.getQuality(),
                count=symbol.getCount(),
                bounds=symbol.getBounds())
            symbols.append(qrcode)

        self.symbols = symbols

    '''
    # can't work, due to the overlay.
    def on_symbols(self, instance, value):
        if self.show_bounds:
            self.update_bounds()

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
    '''


if __name__ == '__main__':
    from kivy.lang import Builder
    from kivy.app import App

    qrcode_kv = '''
BoxLayout:
    orientation: 'vertical'

    ZbarQrcodeDetector:
        id: detector

    Label:
        text: '\\n'.join(map(repr, detector.symbols))
        size_hint_y: None
        height: '100dp'

    BoxLayout:
        size_hint_y: None
        height: '48dp'

        Button:
            text: 'Scan a qrcode'
            on_release: detector.start()
        Button:
            text: 'Stop detection'
            on_release: detector.stop()
'''

    class QrcodeExample(App):
        def build(self):
            return Builder.load_string(qrcode_kv)

    QrcodeExample().run()
