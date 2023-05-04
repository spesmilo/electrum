from functools import wraps, partial

from PyQt5.QtCore import pyqtSignal, pyqtSlot

from electrum.logging import get_logger


def auth_protect(func=None, reject=None, method='pin', message=''):
    if func is None:
        return partial(auth_protect, reject=reject, method=method, message=message)

    @wraps(func)
    def wrapper(self, *args, **kwargs):
        _logger = get_logger(__name__)
        _logger.debug(f'{str(self)}.{func.__name__}')
        if hasattr(self, '__auth_fcall'):
            _logger.debug('object already has a pending authed function call')
            raise Exception('object already has a pending authed function call')
        setattr(self, '__auth_fcall', (func, args, kwargs, reject))
        getattr(self, 'authRequired').emit(method, message)

    return wrapper


class AuthMixin:
    _auth_logger = get_logger(__name__)
    authRequired = pyqtSignal([str, str], arguments=['method', 'authMessage'])

    @pyqtSlot()
    @pyqtSlot(str)
    def authProceed(self, password=None):
        self._auth_logger.debug('Proceeding with authed fn()')
        try:
            self._auth_logger.debug(str(getattr(self, '__auth_fcall')))
            (func, args, kwargs, reject) = getattr(self, '__auth_fcall')
            if password and 'password' in func.__code__.co_varnames:
                r = func(self, *args, **dict(kwargs, password=password))
            else:
                r = func(self, *args, **kwargs)
            return r
        except Exception as e:
            self._auth_logger.error(f'Error executing wrapped fn(): {repr(e)}')
            raise e
        finally:
            delattr(self, '__auth_fcall')

    @pyqtSlot()
    def authCancel(self):
        self._auth_logger.debug('Cancelling authed fn()')
        if not hasattr(self, '__auth_fcall'):
            return

        try:
            (func, args, kwargs, reject) = getattr(self, '__auth_fcall')
            if reject is not None:
                if hasattr(self, reject):
                    getattr(self, reject)()
                else:
                    self._auth_logger.error(f'Reject method "{reject}" not defined')
        except Exception as e:
            self._auth_logger.error(f'Error executing reject function "{reject}": {repr(e)}')
            raise e
        finally:
            delattr(self, '__auth_fcall')
