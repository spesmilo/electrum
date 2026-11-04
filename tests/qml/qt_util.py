import locale
import threading
import traceback
import unittest
from functools import wraps, partial
from unittest import SkipTest

from PyQt6 import sip
from PyQt6.QtCore import QCoreApplication, QEvent, QMetaObject, Qt, pyqtSlot, QObject

from electrum.address_synchronizer import TX_HEIGHT_UNCONFIRMED
from electrum.bitcoin import address_to_script
from electrum.transaction import Transaction


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


class QETestCase(unittest.TestCase):

    def setUp(self):
        super().setUp()
        # restore process locale changed through construction of QCoreApplication
        saved_locale = locale.setlocale(locale.LC_ALL)
        self.addCleanup(locale.setlocale, locale.LC_ALL, saved_locale)
        self.app = None
        self._e = None
        self._testcase_event = threading.Event()
        self._app_ready_event = threading.Event()

        def start_qt_task():
            try:
                assert self.app is None
                self.app = TestQCoreApplication([])
                self._app_ready_event.set()
                self.app.exec()
                self.app = None
            except Exception as e:
                print(f'Problem starting QCoreApplication: {str(e)}')

        self._qt_thread = threading.Thread(target=start_qt_task)
        self._qt_thread.start()

    def tearDown(self):
        self.app.exit()
        if self._qt_thread.is_alive():
            self._qt_thread.join()


def qt_test(func):
    @wraps(func)
    def decorator(self, *args):
        if threading.current_thread().name == 'MainThread':
            res = self._app_ready_event.wait(3)
            if not res:
                raise Exception('app not ready in time')
            self._testcase_event.clear()
            self.app._instance = self
            self.app._method = func.__name__
            QMetaObject.invokeMethod(self.app, 'doInvoke', Qt.ConnectionType.QueuedConnection)
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
            self._testcase_event.set()
    return decorator


def create_qcoreapplication(testcase_cls: type[unittest.TestCase]) -> None:
    """Creates a QCoreApplication for a test class that uses QObjects without
    running a Qt event loop, unless there is one already.
    Without one, deleted QObjects never free PyQt's slot proxies, see delete_qobject.
    """
    if QCoreApplication.instance() is None:
        saved_locale = locale.setlocale(locale.LC_ALL)
        app = QCoreApplication([])
        locale.setlocale(locale.LC_ALL, saved_locale)  # changed by QCoreApplication
        testcase_cls.addClassCleanup(sip.delete, app)


def delete_qobject(obj: QObject) -> None:
    # delete explicitly: if the GC deletes it, its destroyed handler might run on a half-cleared object
    sip.delete(obj)
    # free PyQt's slot proxies of the deleted object, they hold references to it (and so e.g. to a wallet).
    # The proxies only get scheduled for deletion by a posted event, hence the two calls.
    QCoreApplication.sendPostedEvents()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete.value)


def receive_incoming_tx(wallet, prevout_byte: str, outputs: list[tuple[str, int]]) -> str:
    """Adds an unconfirmed tx with one dummy (not ismine) input to the wallet, returns its txid."""
    outs = ''
    for addr, value in outputs:
        spk = address_to_script(addr)
        outs += value.to_bytes(8, 'little').hex() + bytes([len(spk)]).hex() + spk.hex()
    tx = Transaction(
        '02000000' + '01' + prevout_byte * 32 + '00000000' + '00' + 'fdffffff'
        + f'{len(outputs):02x}' + outs + '00000000')
    wallet.adb.receive_tx_callback(tx, tx_height=TX_HEIGHT_UNCONFIRMED)
    return tx.txid()
