from functools import wraps, partial

from PyQt6.QtCore import pyqtSignal, pyqtSlot

from electrum.logging import get_logger


def auth_protect(func=None, reject=None, method='payment_auth', message=''):
    """
    Supported methods:
        * payment_auth: If the user has enabled the 'Payment authentication' config
                        they need to authenticate to continue. If biometrics are enabled they
                        can authenticate using the Android system dialog, else they will see the
                        wallet password dialog.
                        If the option is disabled they will have to confirm a dialog.
        * wallet: Same as payment_auth, but not dependent on user configuration,
                  always requires authentication.
        * wallet_password_only: No biometric/system authentication, user has to enter wallet password.
    """
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
    def authProceed(self):
        self._auth_logger.debug('Proceeding with authed fn()')
        try:
            self._auth_logger.debug(str(getattr(self, '__auth_fcall')))
            (func, args, kwargs, reject) = getattr(self, '__auth_fcall')
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
