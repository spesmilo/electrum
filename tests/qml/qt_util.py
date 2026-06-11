import threading
import traceback
import unittest
from functools import wraps, partial
from typing import List, Sequence
from unittest import SkipTest

from PyQt6.QtCore import QCoreApplication, QMetaObject, Qt, pyqtSlot, QObject, QEventLoop, QTimer

from electrum.util import create_and_start_event_loop

from electrum.logging import get_logger


logger = get_logger(__name__)


class TestQCoreApplication(QCoreApplication):
    @pyqtSlot()
    def doInvoke(self):
        getattr(self._instance, self._method)()


class QEventReceiver(QObject):
    def __init__(self, *signals):
        super().__init__()
        self._lock = threading.Lock()
        self.received = []
        self.signals = []
        for signal in signals:
            self.signals.append(signal)
            signal.connect(partial(self._doReceive, signal))

    # intentionally no pyqtSlot decorator, to catch all
    def _doReceive(self, signal, *args):
        logger.debug(f'received {signal=} {repr(args)}')
        with self._lock:
            self.received.append((signal, args))

    def receivedForSignal(self, signal) -> List:
        with self._lock:
            return list(filter(lambda x: x[0] == signal, self.received))

    def receivedExactSequence(self, signals: List) -> bool:
        """check if the exact signal sequence was received
           if the signals parameter is a list of tuples/lists, the received
           signal parameters are checked as well
        """
        with self._lock:
            if len(self.received) != len(signals):
                logger.error(f'num of received signals {len(self.received)} != num of required signals {len(signals)}')
                return False

            for i in range(0, len(signals)):
                signal = signals[i]
                rcvd = self.received[i]
                if not isinstance(signal, Sequence):
                    # ignore the received signal args
                    rcvd = rcvd[0]
                if rcvd == signal:
                    continue
                logger.error(f'received signal {rcvd} was unexpected at #{i}\n'
                             f'received: {repr(rcvd)}\n'
                             f'expected: {repr(signal)}\n')
                return False

            return True

    def clear(self):
        with self._lock:
            self.received.clear()


class QETestCase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # One QCoreApplication on its own thread and one asyncio loop for the
        # whole test case. Per-test object cleanup is handled by qt_teardown()
        super().setUpClass()
        cls.app = None
        cls._app_ready_event = threading.Event()

        def start_qt_task():
            try:
                assert cls.app is None
                cls.app = TestQCoreApplication([])
                cls._app_ready_event.set()
                logger.debug('about to start QApplication')
                cls.app.exec()
                logger.debug('QApplication stopped')
                cls.app = None
            except Exception as e:
                logger.exception(f'Problem starting QCoreApplication: {str(e)}')

        cls._qt_thread = threading.Thread(target=start_qt_task, name='QtTestThread')
        cls._qt_thread.start()
        cls._loop, cls._stopping_fut, cls._loop_thread = create_and_start_event_loop()

        if not cls._app_ready_event.wait(3):
            raise Exception('app not ready in time')
        logger.debug(f'started event loop {cls._loop=}, {cls._loop_thread=}')

    @classmethod
    def tearDownClass(cls):
        cls.app.exit()
        if cls._qt_thread.is_alive():
            cls._qt_thread.join()

        def _resolve_stopping_fut():
            if not cls._stopping_fut.done():
                cls._stopping_fut.set_result(1)

        try:
            cls._loop.call_soon_threadsafe(_resolve_stopping_fut)
        except RuntimeError:
            pass  # loop already stopped/closed
        if cls._loop_thread.is_alive():
            cls._loop_thread.join()
        super().tearDownClass()

    def setUp(self):
        super().setUp()
        self._e = None
        self._testcase_event = threading.Event()

    def qt_teardown(self):
        """override to destroy QObjects created during the test"""
        pass

    def waitForSignal(self, receiver, signal, *, timeout=5.0):
        if receiver.receivedForSignal(signal):
            return True
        loop = QEventLoop()
        signal.connect(loop.quit)
        timer = QTimer()
        timer.setSingleShot(True)
        timer.timeout.connect(loop.quit)
        timer.start(int(timeout * 1000))
        try:
            # exec() returns when either the awaited signal or the timeout fires;
            # re-check the predicate and re-enter in case of a spurious wakeup.
            while not receiver.receivedForSignal(signal) and timer.isActive():
                loop.exec()
        finally:
            timer.stop()
            try:
                signal.disconnect(loop.quit)
            except (TypeError, RuntimeError):
                pass
        return bool(receiver.receivedForSignal(signal))


def qt_test(func):
    @wraps(func)
    def decorator(self, *args):
        logger.debug(f'qt_test decorator, thread={threading.current_thread().name}')
        if threading.current_thread().name != 'QtTestThread':
            res = self._app_ready_event.wait(3)
            if not res:
                raise Exception('app not ready in time')
            self._testcase_event.clear()
            self.app._instance = self
            self.app._method = func.__name__
            try:
                QMetaObject.invokeMethod(self.app, 'doInvoke', Qt.ConnectionType.QueuedConnection)
            except Exception as e:
                logger.exception(f'exception calling invokeMethod on TestQCoreApplication.doInvoke(...): {str(e)}')

            res = self._testcase_event.wait(15)
            if not res:
                self._e = Exception('testcase timed out')
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
            # teardown on the QtTestThread, while the app event loop is still running,
            # so subclasses can destroy the QObjects they created on their owning thread.
            try:
                self.qt_teardown()
            except Exception as e:
                if self._e is None:
                    self._e = e
            self._testcase_event.set()
    return decorator
