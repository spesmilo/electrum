from java import dynamic_proxy
from java.lang import Runnable
import six
import sys
import threading


# Patch the threading module to use sys.excepthook, which it currently doesn't
# (https://bugs.python.org/issue1230540).
init_original = threading.Thread.__init__
def Thread_init(self, *args, **kwargs):
    init_original(self, *args, **kwargs)
    run_original = self.run
    def run(*args2, **kwargs2):
        try:
            run_original(*args2, **kwargs2)
        except:  # noqa: E722
            sys.excepthook(*sys.exc_info())
    self.run = run

threading.Thread.__init__ = Thread_init


excepthook_original = None

# Sets sys.excepthook to reraise the exception on the thread of the given Handler.
def set_excepthook(handler):
    global excepthook_original
    assert excepthook_original is None
    excepthook_original = sys.excepthook
    def excepthook(type, value, traceback):
        class R(dynamic_proxy(Runnable)):
            def run(self):
                six.reraise(type, value, traceback)
        handler.post(R())
    sys.excepthook = excepthook

def unset_excepthook():
    global excepthook_original
    if excepthook_original is not None:
        sys.excepthook = excepthook_original
        excepthook_original = None


def make_callback(daemon_model):
    return lambda event, *args: daemon_model.onCallback(event)
