import math
import re

from functools import wraps
from time import time
from typing import Tuple

from PyQt6.QtCore import pyqtSignal

from electrum.i18n import _
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


# TODO: copied from qt password_dialog.py, move to common code
def check_password_strength(password: str) -> Tuple[int, str]:
    """Check the strength of the password entered by the user and return back the same
    :param password: password entered by user in New Password
    :return: password strength Weak or Medium or Strong"""
    password = password
    n = math.log(len(set(password)))
    num = re.search("[0-9]", password) is not None and re.match("^[0-9]*$", password) is None
    caps = password != password.upper() and password != password.lower()
    extra = re.match("^[a-zA-Z0-9]*$", password) is None
    score = len(password)*(n + caps + num + extra)/20
    password_strength = {0: _('Weak'), 1: _('Medium'), 2: _('Strong'), 3: _('Very Strong')}
    return min(3, int(score)), password_strength[min(3, int(score))]
