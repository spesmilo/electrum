import math
import re
import sys
import queue

from functools import wraps
from time import time
from typing import Callable, Optional, NamedTuple, Tuple

from PyQt6.QtCore import pyqtSignal, QThread

from electrum.i18n import _
from electrum.logging import Logger
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


# TODO: copied from desktop client, this could be moved to a set of common code.
class TaskThread(QThread, Logger):
    """Thread that runs background tasks.  Callbacks are guaranteed
    to happen in the context of its parent."""

    class Task(NamedTuple):
        task: Callable
        cb_success: Optional[Callable]
        cb_done: Optional[Callable]
        cb_error: Optional[Callable]
        cancel: Optional[Callable] = None

    doneSig = pyqtSignal(object, object, object)

    def __init__(self, parent, on_error=None):
        QThread.__init__(self, parent)
        Logger.__init__(self)
        self.on_error = on_error
        self.tasks = queue.Queue()
        self._cur_task = None  # type: Optional[TaskThread.Task]
        self._stopping = False
        self.doneSig.connect(self.on_done)
        self.start()

    def add(self, task, on_success=None, on_done=None, on_error=None, *, cancel=None):
        if self._stopping:
            self.logger.warning(f"stopping or already stopped but tried to add new task.")
            return
        on_error = on_error or self.on_error
        task_ = TaskThread.Task(task, on_success, on_done, on_error, cancel=cancel)
        self.tasks.put(task_)

    def run(self):
        while True:
            if self._stopping:
                break
            task = self.tasks.get()  # type: TaskThread.Task
            self._cur_task = task
            if not task or self._stopping:
                break
            try:
                result = task.task()
                self.doneSig.emit(result, task.cb_done, task.cb_success)
            except BaseException:
                self.doneSig.emit(sys.exc_info(), task.cb_done, task.cb_error)

    def on_done(self, result, cb_done, cb_result):
        # This runs in the parent's thread.
        if cb_done:
            cb_done()
        if cb_result:
            cb_result(result)

    def stop(self):
        self._stopping = True
        # try to cancel currently running task now.
        # if the task does not implement "cancel", we will have to wait until it finishes.
        task = self._cur_task
        if task and task.cancel:
            task.cancel()
        # cancel the remaining tasks in the queue
        while True:
            try:
                task = self.tasks.get_nowait()
            except queue.Empty:
                break
            if task and task.cancel:
                task.cancel()
        self.tasks.put(None)  # in case the thread is still waiting on the queue
        self.exit()
        self.wait()
