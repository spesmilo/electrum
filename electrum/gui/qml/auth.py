from functools import wraps, partial

from PyQt5.QtCore import pyqtSignal, pyqtSlot

from electrum.logging import get_logger

def auth_protect(func=None, reject=None, method='pin'):
    if func is None:
        return partial(auth_protect, reject=reject, method=method)

    @wraps(func)
    def wrapper(self, *args, **kwargs):
        self._logger.debug(str(self))
        if hasattr(self, '__auth_fcall'):
            self._logger.debug('object already has a pending authed function call')
            raise Exception('object already has a pending authed function call')
        setattr(self, '__auth_fcall', (func,args,kwargs,reject))
        getattr(self, 'authRequired').emit(method)

    return wrapper

class AuthMixin:
    _auth_logger = get_logger(__name__)

    authRequired = pyqtSignal([str],arguments=['method'])

    @pyqtSlot()
    def authProceed(self):
        self._auth_logger.debug('Proceeding with authed fn()')
        try:
            self._auth_logger.debug(str(getattr(self, '__auth_fcall')))
            (func,args,kwargs,reject) = getattr(self, '__auth_fcall')
            r = func(self, *args, **kwargs)
            return r
        except Exception as e:
            self._auth_logger.error('Error executing wrapped fn(): %s' % repr(e))
            raise e
        finally:
            delattr(self,'__auth_fcall')

    @pyqtSlot()
    def authCancel(self):
        self._auth_logger.debug('Cancelling authed fn()')
        if not hasattr(self, '__auth_fcall'):
            return

        try:
            (func,args,kwargs,reject) = getattr(self, '__auth_fcall')
            if reject is not None:
                if hasattr(self, reject):
                    getattr(self, reject)()
                else:
                    self._auth_logger.error('Reject method \'%s\' not defined' % reject)
        except Exception as e:
            self._auth_logger.error('Error executing reject function \'%s\': %s' % (reject, repr(e)))
            raise e
        finally:
            delattr(self, '__auth_fcall')
