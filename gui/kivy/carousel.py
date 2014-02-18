from kivy.uix.carousel import Carousel
from kivy.clock import Clock

class CCarousel(Carousel):

    def on_touch_move(self, touch):
        if self._get_uid('cavoid') in touch.ud:
            return
        if self._touch is not touch:
            super(Carousel, self).on_touch_move(touch)
            return self._get_uid() in touch.ud
        if touch.grab_current is not self:
            return True
        ud = touch.ud[self._get_uid()]
        direction = self.direction
        if ud['mode'] == 'unknown':
            if direction[0] in ('r', 'l'):
                distance = abs(touch.ox - touch.x)
            else:
                distance = abs(touch.oy - touch.y)
            if distance > self.scroll_distance:
                Clock.unschedule(self._change_touch_mode)
                ud['mode'] = 'scroll'
        else:
            diff = 0
            if direction[0] in ('r', 'l'):
                diff = touch.dx
            if direction[0] in ('t', 'b'):
                diff = touch.dy

            self._offset += diff * 1.27
        return True

if __name__ == "__main__":
    from kivy.app import runTouchApp
    from kivy.uix.button import Button
    cc = CCarousel()
    for i in range(10):
        cc.add_widget(Button(text=str(i)))
    runTouchApp(cc)