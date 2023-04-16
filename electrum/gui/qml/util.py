from functools import wraps
from time import time

from PyQt5.QtCore import pyqtSignal

from electrum.util import EventListener, event_listener

class QtEventListener(EventListener):

    qt_callback_signal = pyqtSignal(tuple)

    def register_callbacks(self):
        self.qt_callback_signal.connect(self.on_qt_callback_signal)
        EventListener.register_callbacks(self)

    def unregister_callbacks(self):
        #self.qt_callback_signal.disconnect()
        EventListener.unregister_callbacks(self)

    def on_qt_callback_signal(self, args):
        func = args[0]
        return func(self, *args[1:])

# decorator for members of the QtEventListener class
def qt_event_listener(func):
    func = event_listener(func)
    @wraps(func)
    def decorator(self, *args):
        self.qt_callback_signal.emit( (func,) + args)
    return decorator

# return delay in msec when expiry time string should be updated
# returns 0 when expired or expires > 1 day away (no updates needed)
def status_update_timer_interval(exp):
    # very roughly according to util.age
    exp_in = int(exp - time())
    exp_in_min = int(exp_in/60)

    interval = 0
    if exp_in < 0:
        interval = 0
    elif exp_in_min < 2:
        interval = 1000
    elif exp_in_min < 90:
        interval = 1000 * 60
    elif exp_in_min < 1440:
        interval = 1000 * 60 * 60

    return interval
