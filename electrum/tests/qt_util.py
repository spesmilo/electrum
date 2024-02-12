import threading
import traceback
import unittest
from functools import wraps, partial
from unittest import SkipTest

from PyQt6.QtCore import QCoreApplication, QTimer, QMetaObject, Qt, pyqtSlot, QObject


class TestQCoreApplication(QCoreApplication):
    @pyqtSlot()
    def doInvoke(self):
        getattr(self._instance, self._method)()


class QEventReceiver(QObject):
    def __init__(self, *signals):
        super().__init__()
        self.received = []
        self.signals = []
        for signal in signals:
            self.signals.append(signal)
            signal.connect(partial(self.doReceive, signal))

    # intentionally no pyqtSlot decorator, to catch all
    def doReceive(self, signal, *args):
        self.received.append((signal, args))

    def receivedForSignal(self, signal):
        return list(filter(lambda x: x[0] == signal, self.received))

    def clear(self):
        self.received.clear()


class QETestCase(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        super().setUp()
        self.app = None
        self._e = None
        self._event = threading.Event()

        def start_qt_task():
            self.app = TestQCoreApplication([])

            self.timer = QTimer(self.app)
            self.timer.setSingleShot(False)
            self.timer.setInterval(500)  # msec
            self.timer.timeout.connect(lambda: None)  # periodically enter python scope

            self.app.exec()
            self.app = None

        self.qt_thread = threading.Thread(target=start_qt_task)
        self.qt_thread.start()

    def tearDown(self):
        self.app.exit()
        if self.qt_thread.is_alive():
            self.qt_thread.join()


def qt_test(func):
    @wraps(func)
    def decorator(self, *args):
        if threading.current_thread().name == 'MainThread':
            self.app._instance = self
            self.app._method = func.__name__
            QMetaObject.invokeMethod(self.app, 'doInvoke', Qt.ConnectionType.QueuedConnection)
            self._event.wait(15)
            if self._e:
                print("".join(traceback.format_exception(self._e)))
                # deallocate stored exception from qt thread otherwise we SEGV garbage collector
                # instead, re-create using the exception message, special casing AssertionError and SkipTest
                e = None
                if isinstance(self._e, AssertionError):
                    e = AssertionError(str(self._e))
                elif isinstance(self._e, SkipTest):
                    e = SkipTest(str(self._e))
                else:
                    e = Exception(str(self._e))
                self._e = None
                raise e
            return
        try:
            func(self, *args)
        except Exception as e:
            self._e = e
        finally:
            self._event.set()
            self._event.clear()
    return decorator
