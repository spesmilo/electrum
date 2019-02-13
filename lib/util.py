# Electrum - lightweight Bitcoin client
# Copyright (C) 2011 Thomas Voegtlin
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import binascii
import os, sys, re, json, time
from collections import defaultdict
from datetime import datetime
from decimal import Decimal
import traceback
import threading
import hmac
import stat
import inspect, weakref

from .i18n import _

import queue

def inv_dict(d):
    return {v: k for k, v in d.items()}


base_units = {'BCH':8, 'mBCH':5, 'cash':2}
fee_levels = [_('Within 25 blocks'), _('Within 10 blocks'), _('Within 5 blocks'), _('Within 2 blocks'), _('In the next block')]

class NotEnoughFunds(Exception): pass

class ExcessiveFee(Exception): pass

class InvalidPassword(Exception):
    def __str__(self):
        return _("Incorrect password")


class FileImportFailed(Exception):
    def __str__(self):
        return _("Failed to import file.")


class FileImportFailedEncrypted(FileImportFailed):
    def __str__(self):
        return (_('Failed to import file.') + ' ' +
                _('Perhaps it is encrypted...') + '\n' +
                _('Importing encrypted files is not supported.'))


# Throw this exception to unwind the stack like when an error occurs.
# However unlike other exceptions the user won't be informed.
class UserCancelled(Exception):
    '''An exception that is suppressed from the user'''
    pass

class MyEncoder(json.JSONEncoder):
    def default(self, obj):
        from .transaction import Transaction
        if isinstance(obj, Transaction):
            return obj.as_dict()
        return super(MyEncoder, self).default(obj)

class PrintError(object):
    '''A handy base class'''
    def diagnostic_name(self):
        return self.__class__.__name__

    def print_error(self, *msg):
        # only prints with --verbose flag
        print_error("[%s]" % self.diagnostic_name(), *msg)

    def print_stderr(self, *msg):
        print_stderr("[%s]" % self.diagnostic_name(), *msg)

    def print_msg(self, *msg):
        print_msg("[%s]" % self.diagnostic_name(), *msg)

class ThreadJob(PrintError):
    """A job that is run periodically from a thread's main loop.  run() is
    called from that thread's context.
    """

    def run(self):
        """Called periodically from the thread"""
        pass

class DebugMem(ThreadJob):
    '''A handy class for debugging GC memory leaks'''
    def __init__(self, classes, interval=30):
        self.next_time = 0
        self.classes = classes
        self.interval = interval

    def mem_stats(self):
        import gc
        self.print_error("Start memscan")
        gc.collect()
        objmap = defaultdict(list)
        for obj in gc.get_objects():
            for class_ in self.classes:
                if isinstance(obj, class_):
                    objmap[class_].append(obj)
        for class_, objs in objmap.items():
            self.print_error("%s: %d" % (class_.__name__, len(objs)))
        self.print_error("Finish memscan")

    def run(self):
        if time.time() > self.next_time:
            self.mem_stats()
            self.next_time = time.time() + self.interval

class DaemonThread(threading.Thread, PrintError):
    """ daemon thread that terminates cleanly """

    def __init__(self):
        threading.Thread.__init__(self)
        self.parent_thread = threading.currentThread()
        self.running = False
        self.running_lock = threading.Lock()
        self.job_lock = threading.Lock()
        self.jobs = []

    def add_jobs(self, jobs):
        with self.job_lock:
            self.jobs.extend(jobs)

    def run_jobs(self):
        # Don't let a throwing job disrupt the thread, future runs of
        # itself, or other jobs.  This is useful protection against
        # malformed or malicious server responses
        with self.job_lock:
            for job in self.jobs:
                try:
                    job.run()
                except Exception as e:
                    traceback.print_exc(file=sys.stderr)

    def remove_jobs(self, jobs):
        with self.job_lock:
            for job in jobs:
                self.jobs.remove(job)

    def start(self):
        with self.running_lock:
            self.running = True
        return threading.Thread.start(self)

    def is_running(self):
        with self.running_lock:
            return self.running and self.parent_thread.is_alive()

    def stop(self):
        with self.running_lock:
            self.running = False

    def on_stop(self):
        if 'ANDROID_DATA' in os.environ:
            try:
                import jnius
                jnius.detach()
                self.print_error("jnius detach")
            except ImportError:
                pass  # Chaquopy detaches automatically.
        self.print_error("stopped")


# TODO: disable
is_verbose = True
verbose_timestamps = True
def set_verbosity(b, *, timestamps=True):
    global is_verbose, verbose_timestamps
    is_verbose = b
    verbose_timestamps = timestamps

# Method decorator.  To be used for calculations that will always
# deliver the same result.  The method cannot take any arguments
# and should be accessed as an attribute.
class cachedproperty(object):

    def __init__(self, f):
        self.f = f

    def __get__(self, obj, type):
        obj = obj or type
        value = self.f(obj)
        setattr(obj, self.f.__name__, value)
        return value

_t0 = time.time()
def print_error(*args):
    if not is_verbose: return
    if verbose_timestamps:
        args = ("|%7.3f|"%(time.time() - _t0), *args)
    print_stderr(*args)

def print_stderr(*args):
    args = [str(item) for item in args]
    sys.stderr.write(" ".join(args) + "\n")
    sys.stderr.flush()

def print_msg(*args):
    # Stringify args
    args = [str(item) for item in args]
    sys.stdout.write(" ".join(args) + "\n")
    sys.stdout.flush()

def json_encode(obj):
    try:
        s = json.dumps(obj, sort_keys = True, indent = 4, cls=MyEncoder)
    except TypeError:
        s = repr(obj)
    return s

def json_decode(x):
    try:
        return json.loads(x, parse_float=Decimal)
    except:
        return x


# taken from Django Source Code
def constant_time_compare(val1, val2):
    """Return True if the two strings are equal, False otherwise."""
    return hmac.compare_digest(to_bytes(val1, 'utf8'), to_bytes(val2, 'utf8'))


# decorator that prints execution time
def profiler(func):
    def do_profile(args, kw_args):
        t0 = time.time()
        o = func(*args, **kw_args)
        t = time.time() - t0
        print_error("[profiler]", func.__qualname__, "%.4f"%t)
        return o
    return lambda *args, **kw_args: do_profile(args, kw_args)


def android_ext_dir():
    try:
        import jnius
        env = jnius.autoclass('android.os.Environment')
    except ImportError:
        from android.os import Environment as env  # Chaquopy import hook
    return env.getExternalStorageDirectory().getPath()

def android_data_dir():
    try:
        import jnius
        context = jnius.autoclass('org.kivy.android.PythonActivity').mActivity
    except ImportError:
        from com.chaquo.python import Python
        context = Python.getPlatform().getApplication()
    return context.getFilesDir().getPath() + '/data'

def android_headers_dir():
    try:
        import jnius
        d = android_ext_dir() + '/org.electron.electron'
        if not os.path.exists(d):
            os.mkdir(d)
        return d
    except ImportError:
        return android_data_dir()

def ensure_sparse_file(filename):
    if os.name == "nt":
        try:
            os.system("fsutil sparse setFlag \""+ filename +"\" 1")
        except:
            pass

def get_headers_dir(config):
    return android_headers_dir() if 'ANDROID_DATA' in os.environ else config.path

def assert_datadir_available(config_path):
    path = config_path
    if os.path.exists(path):
        return
    else:
        raise FileNotFoundError(
            'Electron Cash datadir does not exist. Was it deleted while running?' + '\n' +
            'Should be at {}'.format(path))

def assert_file_in_datadir_available(path, config_path):
    if os.path.exists(path):
        return
    else:
        assert_datadir_available(config_path)
        raise FileNotFoundError(
            'Cannot find file but datadir is there.' + '\n' +
            'Should be at {}'.format(path))

def standardize_path(path):
    if path is not None:
        path = os.path.normcase(os.path.realpath(os.path.abspath(path)))
    return path

def get_new_wallet_name(wallet_folder: str) -> str:
    i = 1
    while True:
        filename = "wallet_%d" % i
        if os.path.exists(os.path.join(wallet_folder, filename)):
            i += 1
        else:
            break
    return filename

def assert_bytes(*args):
    """
    porting helper, assert args type
    """
    try:
        for x in args:
            assert isinstance(x, (bytes, bytearray))
    except:
        print('assert bytes failed', list(map(type, args)))
        raise


def assert_str(*args):
    """
    porting helper, assert args type
    """
    for x in args:
        assert isinstance(x, str)



def to_string(x, enc):
    if isinstance(x, (bytes, bytearray)):
        return x.decode(enc)
    if isinstance(x, str):
        return x
    else:
        raise TypeError("Not a string or bytes like object")

def to_bytes(something, encoding='utf8'):
    """
    cast string to bytes() like object, but for python2 support it's bytearray copy
    """
    if isinstance(something, bytes):
        return something
    if isinstance(something, str):
        return something.encode(encoding)
    elif isinstance(something, bytearray):
        return bytes(something)
    else:
        raise TypeError("Not a string or bytes like object")


bfh = bytes.fromhex
hfu = binascii.hexlify

def bh2u(x):
    """
    str with hex representation of a bytes-like object

    >>> x = bytes((1, 2, 10))
    >>> bh2u(x)
    '01020A'

    :param x: bytes
    :rtype: str
    """
    return hfu(x).decode('ascii')


def user_dir(prefer_local=False):
    if 'ANDROID_DATA' in os.environ:
        return android_data_dir()
    elif os.name == 'posix' and "HOME" in os.environ:
        return os.path.join(os.environ["HOME"], ".electron-cash" )
    elif "APPDATA" in os.environ or "LOCALAPPDATA" in os.environ:
        app_dir = os.environ.get("APPDATA")
        localapp_dir = os.environ.get("LOCALAPPDATA")
        # Prefer APPDATA, but may get LOCALAPPDATA if present and req'd.
        if localapp_dir is not None and prefer_local or app_dir is None:
            app_dir = localapp_dir
        return os.path.join(app_dir, "ElectronCash")
    else:
        #raise Exception("No home directory found in environment variables.")
        return


def make_dir(path):
    # Make directory if it does not yet exist.
    if not os.path.exists(path):
        if os.path.islink(path):
            raise BaseException('Dangling link: ' + path)
        os.mkdir(path)
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)


def format_satoshis_plain(x, decimal_point = 8):
    """Display a satoshi amount scaled.  Always uses a '.' as a decimal
    point and has no thousands separator"""
    scale_factor = pow(10, decimal_point)
    return "{:.8f}".format(Decimal(x) / scale_factor).rstrip('0').rstrip('.')


def format_satoshis(x, num_zeros=0, decimal_point=8, precision=None, is_diff=False, whitespaces=False):
    from locale import localeconv
    if x is None:
        return 'unknown'
    if precision is None:
        precision = decimal_point
    decimal_format = ".0" + str(precision) if precision > 0 else ""
    if is_diff:
        decimal_format = '+' + decimal_format
    try:
        result = ("{:" + decimal_format + "f}").format(x / pow (10, decimal_point)).rstrip('0')
    except ArithmeticError:
        return 'unknown' # Normally doesn't happen but if x is a huge int, we may get OverflowError or other ArithmeticError subclass exception. See #1024
    integer_part, fract_part = result.split(".")
    dp = localeconv()['decimal_point']
    if len(fract_part) < num_zeros:
        fract_part += "0" * (num_zeros - len(fract_part))
    result = integer_part + dp + fract_part
    if whitespaces:
        result += " " * (decimal_point - len(fract_part))
        result = " " * (15 - len(result)) + result
    return result

def format_fee_satoshis(fee, num_zeros=0):
    return format_satoshis(fee, num_zeros, 0, precision=num_zeros)

def timestamp_to_datetime(timestamp):
    try:
        return datetime.fromtimestamp(timestamp)
    except:
        return None

def format_time(timestamp):
    if timestamp:
        date = timestamp_to_datetime(timestamp)
        if date:
            return date.isoformat(' ')[:-3]
    return _("Unknown")


# Takes a timestamp and returns a string with the approximation of the age
def age(from_date, since_date = None, target_tz=None, include_seconds=False):
    if from_date is None:
        return "Unknown"

    from_date = datetime.fromtimestamp(from_date)
    if since_date is None:
        since_date = datetime.now(target_tz)

    td = time_difference(from_date - since_date, include_seconds)
    return td + " ago" if from_date < since_date else "in " + td


def time_difference(distance_in_time, include_seconds):
    #distance_in_time = since_date - from_date
    distance_in_seconds = int(round(abs(distance_in_time.days * 86400 + distance_in_time.seconds)))
    distance_in_minutes = int(round(distance_in_seconds/60))

    if distance_in_minutes <= 1:
        if include_seconds:
            for remainder in [5, 10, 20]:
                if distance_in_seconds < remainder:
                    return "less than %s seconds" % remainder
            if distance_in_seconds < 40:
                return "half a minute"
            elif distance_in_seconds < 60:
                return "less than a minute"
            else:
                return "1 minute"
        else:
            if distance_in_minutes == 0:
                return "less than a minute"
            else:
                return "1 minute"
    elif distance_in_minutes < 45:
        return "%s minutes" % distance_in_minutes
    elif distance_in_minutes < 90:
        return "about 1 hour"
    elif distance_in_minutes < 1440:
        return "about %d hours" % (round(distance_in_minutes / 60.0))
    elif distance_in_minutes < 2880:
        return "1 day"
    elif distance_in_minutes < 43220:
        return "%d days" % (round(distance_in_minutes / 1440))
    elif distance_in_minutes < 86400:
        return "about 1 month"
    elif distance_in_minutes < 525600:
        return "%d months" % (round(distance_in_minutes / 43200))
    elif distance_in_minutes < 1051200:
        return "about 1 year"
    else:
        return "over %d years" % (round(distance_in_minutes / 525600))

# Python bug (http://bugs.python.org/issue1927) causes raw_input
# to be redirected improperly between stdin/stderr on Unix systems
#TODO: py3
def raw_input(prompt=None):
    if prompt:
        sys.stdout.write(prompt)
    return builtin_raw_input()

import builtins
builtin_raw_input = builtins.input
builtins.input = raw_input


def parse_json(message):
    # TODO: check \r\n pattern
    n = message.find(b'\n')
    if n==-1:
        return None, message
    try:
        j = json.loads(message[0:n].decode('utf8'))
    except:
        j = None
    return j, message[n+1:]


class timeout(Exception):
    ''' Server timed out on broadcast tx (normally due to a bad connection).
    Exception string is the translated error string.'''
    pass

TimeoutException = timeout # Future compat. with Electrum codebase/cherrypicking

class ServerError(Exception):
    ''' Note exception string is the translated, gui-friendly error message.
    self.server_msg may be a dict or a string containing the raw response from
    the server.  Do NOT display self.server_msg in GUI code due to potential for
    phishing attacks from the untrusted server.
    See: https://github.com/spesmilo/electrum/issues/4968  '''
    def __init__(self, msg, server_msg = None):
        super().__init__(msg)
        self.server_msg = server_msg or '' # prefer empty string if none supplied

class ServerErrorResponse(ServerError):
    ''' Raised by network.py broadcast_transaction2() when the server sent an
    error response. The actual server error response is contained in a dict
    and/or str in self.server_msg. Warning: DO NOT display the server text.
    Displaying server text harbors a phishing risk. Instead, a translated
    GUI-friendly 'deduced' response is in the exception string.
    See: https://github.com/spesmilo/electrum/issues/4968 '''
    pass

class TxHashMismatch(ServerError):
    ''' Raised by network.py broadcast_transaction2().
    Server sent an OK response but the txid it supplied does not match our
    signed tx id that we requested to broadcast. The txid returned is
    stored in self.server_msg. It's advised not to display
    the txid response as there is also potential for phishing exploits if
    one does. Instead, the exception string contians a suitable translated
    GUI-friendly error message. '''
    pass

import socket
import ssl

class SocketPipe(PrintError):
    def __init__(self, socket):
        self.socket = socket
        self.message = b''
        self.set_timeout(0.1)
        self.recv_time = time.time()

    def set_timeout(self, t):
        self.socket.settimeout(t)

    def idle_time(self):
        return time.time() - self.recv_time

    def get(self):
        while True:
            response, self.message = parse_json(self.message)
            if response is not None:
                return response
            try:
                data = self.socket.recv(1024)
            except socket.timeout:
                raise timeout
            except ssl.SSLError:
                raise timeout
            except socket.error as err:
                if err.errno == 60:
                    raise timeout
                elif err.errno in [11, 35, 10035]:
                    self.print_error("socket errno %d (resource temporarily unavailable)"% err.errno)
                    time.sleep(0.2)
                    raise timeout
                else:
                    self.print_error("socket error:", err)
                    data = b''
            except:
                traceback.print_exc(file=sys.stderr)
                data = b''

            if not data:  # Connection closed remotely
                return None
            self.message += data
            self.recv_time = time.time()

    def send(self, request):
        out = json.dumps(request) + '\n'
        out = out.encode('utf8')
        self._send(out)

    def send_all(self, requests):
        out = b''.join(map(lambda x: (json.dumps(x) + '\n').encode('utf8'), requests))
        self._send(out)

    def _send(self, out):
        while out:
            sent = self.socket.send(out)
            out = out[sent:]


def setup_thread_excepthook():
    """
    Workaround for `sys.excepthook` thread bug from:
    http://bugs.python.org/issue1230540

    Call once from the main thread before creating any threads.
    """

    init_original = threading.Thread.__init__

    def init(self, *args, **kwargs):

        init_original(self, *args, **kwargs)
        run_original = self.run

        def run_with_except_hook(*args2, **kwargs2):
            try:
                run_original(*args2, **kwargs2)
            except Exception:
                sys.excepthook(*sys.exc_info())

        self.run = run_with_except_hook

    threading.Thread.__init__ = init


def versiontuple(v):
    return tuple(map(int, (v.split("."))))


class Weak:
    '''
    Weak reference factory. Create either a weak proxy to a bound method
    or a weakref.proxy, depending on whether this factory class's __new__ is
    invoked with a bound method or a regular function/object as its first
    argument.

    If used with an object/function reference this factory just creates a
    weakref.proxy and returns that.

        myweak = Weak(myobj)
        type(myweak) == weakref.proxy # <-- True

    The interesting usage is when this factory is used with a bound method
    instance.  In which case it returns a MethodProxy which behaves like
    a proxy to a bound method in that you can call the MethodProxy object
    directly:

        mybound = Weak(someObj.aMethod)
        mybound(arg1, arg2) # <-- invokes someObj.aMethod(arg1, arg2)

    This is unlike regular weakref.WeakMethod which is not a proxy and requires
    unsightly `foo()(args)`, or perhaps `foo() and foo()(args)` idioms.

    Also note that no exception is raised with MethodProxy instances when
    calling them on dead references.

    Instead, if the weakly bound method is no longer alive (because its object
    died), the situation is ignored as if no method were called (with an
    optional print facility provided to print debug information in such a
    situation).

    The optional `print_func` class attribute can be set in MethodProxy
    globally or for each instance specifically in order to specify a debug
    print function (which will receive exactly two arguments: the
    MethodProxy instance and an info string), so you can track when your weak
    bound method is being called after its object died (defaults to
    `print_error`).

    Note you may specify a second postional argument to this factory,
    `callback`, which is identical to the `callback` argument in the weakref
    documentation and will be called on target object finalization
    (destruction).

    This usage/idiom is intented to be used with Qt's signal/slots mechanism
    to allow for Qt bound signals to not prevent target objects from being
    garbage collected due to reference cycles -- hence the permissive,
    exception-free design.'''

    def __new__(cls, obj_or_bound_method, *args, **kwargs):
        if inspect.ismethod(obj_or_bound_method):
            # is a method -- use our custom proxy class
            return cls.MethodProxy(obj_or_bound_method, *args, **kwargs)
        else:
            # Not a method, just return a weakref.proxy
            return weakref.proxy(obj_or_bound_method, *args, **kwargs)

    ref = weakref.ref # alias for convenience so you don't have to import weakref
    Set = weakref.WeakSet # alias for convenience
    ValueDictionary = weakref.WeakValueDictionary # alias for convenience
    KeyDictionary = weakref.WeakKeyDictionary # alias for convenience
    Method = weakref.WeakMethod # alias
    finalize = weakref.finalize # alias

    class MethodProxy(weakref.WeakMethod):
        ''' Direct-use of this class is discouraged (aside from assigning to
            its print_func attribute). Instead use of the wrapper class 'Weak'
            defined in the enclosing scope is encouraged. '''

        print_func = lambda x, this, info: print_error(this, info) # <--- set this attribute if needed, either on the class or instance level, to control debug printing behavior. None is ok here.

        def __init__(self, meth, *args, **kwargs):
            super().__init__(meth, *args, **kwargs)
            # teehee.. save some information about what to call this thing for debug print purposes
            self.qname, self.sname = meth.__qualname__, str(meth.__self__)
    
        def __call__(self, *args, **kwargs):
            ''' Either directly calls the method for you or prints debug info
                if the target object died '''
            meth = super().__call__() # if dead, None is returned
            if meth: # could also do callable() as the test but hopefully this is sightly faster
                return meth(*args,**kwargs)
            elif callable(self.print_func):
                self.print_func(self, "MethodProxy for '{}' called on a dead reference. Referent was: {})".format(self.qname,
                                                                                                                  self.sname))
