from java import dynamic_proxy
from java.lang import Runnable
import six
import sys
import threading


# To catch programming errors in the back end, WalletStorage._write doesn't allow daemon
# threads to write the wallet. But on Android, background threads created from Java will also
# have the daemon attribute set.
DummyThread_init_original = threading._DummyThread.__init__
def DummyThread_init(self):
    DummyThread_init_original(self)
    self._daemonic = False
threading._DummyThread.__init__ = DummyThread_init


# Patch the threading module to reraise any unhandled exceptions on the thread of the given
# Handler. We don't use sys.excepthook, because it isn't used by non-main threads
# (https://bugs.python.org/issue1230540), but it *is* used for unhandled exceptions in the
# InteractiveConsole, which we don't want.
def set_excepthook(handler):
    def excepthook(type, value, traceback):
        class R(dynamic_proxy(Runnable)):
            def run(self):
                six.reraise(type, value, traceback)
        handler.post(R())

    init_original = threading.Thread.__init__
    def Thread_init(self, *args, **kwargs):
        init_original(self, *args, **kwargs)
        run_original = self.run
        def run(*args2, **kwargs2):
            try:
                run_original(*args2, **kwargs2)
            except:  # noqa: E722
                excepthook(*sys.exc_info())
        self.run = run
    threading.Thread.__init__ = Thread_init


def make_callback(daemon_model):
    return lambda event, *args: daemon_model.onCallback(event)
