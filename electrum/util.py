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
from . import constants as cnstnts
import binascii
import os, sys, re, json
from collections import defaultdict
from typing import NamedTuple
from datetime import datetime
import decimal
from decimal import Decimal
import traceback
import urllib
import threading
import hmac
import stat
import inspect
from locale import localeconv

from .i18n import _


import urllib.request, urllib.parse, urllib.error
import queue
import functools

def inv_dict(d):
    return {v: k for k, v in d.items()}


base_units = {'DGLD':8, 'mDGLD':5, 'Au':0, 'test':3}
base_units_inverse = inv_dict(base_units)
base_units_list = ['DGLD', 'mDGLD', 'Au', 'test']  # list(dict) does not guarantee order


def decimal_point_to_base_unit_name(dp: int) -> str:
    # e.g. 8 -> "BTC"
    try:
        return base_units_inverse[dp]
    except KeyError:
        raise Exception('Unknown base unit')


def base_unit_name_to_decimal_point(unit_name: str) -> int:
    # e.g. "BTC" -> 8
    try:
        return base_units[unit_name]
    except KeyError:
        raise Exception('Unknown base unit')


def normalize_version(v):
    return [int(x) for x in re.sub(r'(\.0+)*$','', v).split(".")]

class NotEnoughFunds(Exception): pass


class NoDynamicFeeEstimates(Exception):
    def __str__(self):
        return _('Dynamic fee estimates not available')


class InvalidPassword(Exception):
    def __str__(self):
        return _("Incorrect password")


class FileImportFailed(Exception):
    def __init__(self, message=''):
        self.message = str(message)

    def __str__(self):
        return _("Failed to import from file.") + "\n" + self.message


class FileExportFailed(Exception):
    def __init__(self, message=''):
        self.message = str(message)

    def __str__(self):
        return _("Failed to export to file.") + "\n" + self.message


class TimeoutException(Exception):
    def __init__(self, message=''):
        self.message = str(message)

    def __str__(self):
        if not self.message:
            return _("Operation timed out.")
        return self.message


class WalletFileException(Exception): pass


class BitcoinException(Exception): pass


class UserFacingException(Exception):
    """Exception that contains information intended to be shown to the user."""

class InvoiceError(UserFacingException): pass

# Throw this exception to unwind the stack like when an error occurs.
# However unlike other exceptions the user won't be informed.
class UserCancelled(Exception):
    '''An exception that is suppressed from the user'''
    pass

class Satoshis(object):
    __slots__ = ('value',)

    def __new__(cls, value):
        self = super(Satoshis, cls).__new__(cls)
        self.value = value
        return self

    def __repr__(self):
        return 'Satoshis(%d)'%self.value

    def __str__(self):
        return format_satoshis(self.value) + " CBT"

class Fiat(object):
    __slots__ = ('value', 'ccy')

    def __new__(cls, value, ccy):
        self = super(Fiat, cls).__new__(cls)
        self.ccy = ccy
        self.value = value
        return self

    def __repr__(self):
        return 'Fiat(%s)'% self.__str__()

    def __str__(self):
        if self.value.is_nan():
            return _('No Data')
        else:
            return "{:.2f}".format(self.value) + ' ' + self.ccy

class MyEncoder(json.JSONEncoder):
    def default(self, obj):
        from .transaction import Transaction
        if isinstance(obj, Transaction):
            return obj.as_dict()
        if isinstance(obj, Satoshis):
            return str(obj)
        if isinstance(obj, Fiat):
            return str(obj)
        if isinstance(obj, Decimal):
            return str(obj)
        if isinstance(obj, datetime):
            return obj.isoformat(' ')[:-3]
        if isinstance(obj, set):
            return list(obj)
        return super(MyEncoder, self).default(obj)

    
class PrintError(object):
    '''A handy base class'''
    verbosity_filter = ''
        
    def diagnostic_name(self):
        return self.__class__.__name__

    def print_error(self, *msg):
        if self.verbosity_filter in verbosity or verbosity == '*':
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
    verbosity_filter = 'd'

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
            import jnius
            jnius.detach()
            self.print_error("jnius detach")
        self.print_error("stopped")


verbosity = '*'
def set_verbosity(b):
    global verbosity
    verbosity = b

def log_file_writer(func):
    @functools.wraps(func)
    def wrapper(*args):
        print_to_file(*args)
        return func(*args)
    return wrapper

def print_to_file(*args):
    args = [str(item) for item in args]
    log_file=open("electrum.log", "a")        
    log_file.write(" ".join(args) + "\n")
    log_file.flush()
    log_file.close()

def print_error(*args):
    if not verbosity: return
    print_stderr(*args)

@log_file_writer
def print_stderr(*args):
    args = [str(item) for item in args]
    sys.stderr.write(" ".join(args) + "\n")
    sys.stderr.flush()

@log_file_writer
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
    def get_func_name(args):
        arg_names_from_sig = inspect.getfullargspec(func).args
        # prepend class name if there is one (and if we can find it)
        if len(arg_names_from_sig) > 0 and len(args) > 0 \
                and arg_names_from_sig[0] in ('self', 'cls', 'klass'):
            classname = args[0].__class__.__name__
        else:
            classname = ''
        name = '{}.{}'.format(classname, func.__name__) if classname else func.__name__
        return name
    def do_profile(args, kw_args):
        name = get_func_name(args)
        t0 = time.time()
        o = func(*args, **kw_args)
        t = time.time() - t0
        print_error("[profiler]", name, "%.4f"%t)
        return o
    return lambda *args, **kw_args: do_profile(args, kw_args)


def android_acquire_permissions(permission_list, timeout):
    import time
    import jnius

    PythonActivity = jnius.autoclass('org.kivy.android.PythonActivity')
    ContextCompat = jnius.autoclass('android.support.v4.content.ContextCompat')

    currentActivity = jnius.cast('android.app.Activity', PythonActivity.mActivity)
    if all(ContextCompat.checkSelfPermission(currentActivity, _p) == 0 for _p in permission_list):
        return
    
    currentActivity.requestPermissions(permission_list, 0)
    
    haveperms = False
    t0 = time.time()
    while time.time() - t0 < timeout and not haveperms:
        haveperms = all(ContextCompat.checkSelfPermission(currentActivity, _p) == 0 for _p in permission_list)
    if not haveperms:
        raise RuntimeError("Permissions not granted")


android_storage_permissions = ['android.permission.READ_EXTERNAL_STORAGE', 'android.permission.WRITE_EXTERNAL_STORAGE']

def android_acquire_storage_permissions(timeout=30):
    android_acquire_permissions(android_storage_permissions, timeout)


android_camera_permissions = ['android.permission.CAMERA']

def android_acquire_camera_permissions(timeout=30):
    android_acquire_permissions(android_camera_permissions, timeout)



def android_ext_dir():
    android_acquire_storage_permissions()
    import jnius
    env = jnius.autoclass('android.os.Environment')
    return env.getExternalStorageDirectory().getPath()

def android_data_dir():
    import jnius
    PythonActivity = jnius.autoclass('org.kivy.android.PythonActivity')
    return PythonActivity.mActivity.getFilesDir().getPath() + '/data'

def android_headers_dir():
    d = android_ext_dir() + '/org.electrum.electrum'
    if not os.path.exists(d):
        try:
            os.mkdir(d)
        except FileExistsError:
            pass  # in case of race
    return d

def android_check_data_dir():
    """ if needed, move old directory to sandbox """
    ext_dir = android_ext_dir()
    data_dir = android_data_dir()
    old_electrum_dir = ext_dir + '/electrum'
    if not os.path.exists(data_dir) and os.path.exists(old_electrum_dir):
        import shutil
        new_headers_path = android_headers_dir() + '/blockchain_headers'
        old_headers_path = old_electrum_dir + '/blockchain_headers'
        if not os.path.exists(new_headers_path) and os.path.exists(old_headers_path):
            print_error("Moving headers file to", new_headers_path)
            shutil.move(old_headers_path, new_headers_path)
        print_error("Moving data to", data_dir)
        shutil.move(old_electrum_dir, data_dir)
    return data_dir


def get_headers_dir(config):
    return android_headers_dir() if 'ANDROID_DATA' in os.environ else config.path


def assert_datadir_available(config_path):
    path = config_path
    if os.path.exists(path):
        return
    else:
        raise FileNotFoundError(
            'Electrum datadir does not exist. Was it deleted while running?' + '\n' +
            'Should be at {}'.format(path))


def assert_file_in_datadir_available(path, config_path):
    if os.path.exists(path):
        return
    else:
        assert_datadir_available(config_path)
        raise FileNotFoundError(
            'Cannot find file but datadir is there.' + '\n' +
            'Should be at {}'.format(path))


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


def user_dir():
    if 'ANDROID_DATA' in os.environ:
        return android_check_data_dir()
    elif os.name == 'posix':
        return os.path.join(os.environ["HOME"], "." + cnstnts.net.WALLETPATH)
    elif "APPDATA" in os.environ:
        return os.path.join(os.environ["APPDATA"], cnstnts.net.WALLETPATH)
    elif "LOCALAPPDATA" in os.environ:
        return os.path.join(os.environ["LOCALAPPDATA"], cnstnts.net.WALLETPATH)
    else:
        #raise Exception("No home directory found in environment variables.")
        return

def is_valid_email(s):
    regexp = r"[^@]+@[^@]+\.[^@]+"
    return re.match(regexp, s) is not None


def format_satoshis_plain(x, decimal_point = 8):
    """Display a satoshi amount scaled.  Always uses a '.' as a decimal
    point and has no thousands separator"""
    scale_factor = pow(10, decimal_point)
    return "{:.8f}".format(Decimal(x) / scale_factor).rstrip('0').rstrip('.')


DECIMAL_POINT = localeconv()['decimal_point']


def format_satoshis(x, num_zeros=0, decimal_point=8, precision=None, is_diff=False, whitespaces=False):
    if x is None:
        return 'unknown'
    if precision is None:
        precision = decimal_point
    decimal_format = ".0" + str(precision) if precision > 0 else ""
    if is_diff:
        decimal_format = '+' + decimal_format
    result = ("{:" + decimal_format + "f}").format(x / pow (10, decimal_point)).rstrip('0')
    integer_part, fract_part = result.split(".")
    dp = DECIMAL_POINT
    if len(fract_part) < num_zeros:
        fract_part += "0" * (num_zeros - len(fract_part))
    result = integer_part + dp + fract_part
    if whitespaces:
        result += " " * (decimal_point - len(fract_part))
        result = " " * (15 - len(result)) + result
    return result


FEERATE_PRECISION = 2  # num fractional decimal places for sat/byte fee rates
_feerate_quanta = Decimal(10) ** (-FEERATE_PRECISION)


def format_fee_satoshis(fee, num_zeros=0):
    return format_satoshis(fee, num_zeros, 0, precision=FEERATE_PRECISION)


def quantize_feerate(fee):
    """Strip sat/byte fee rate of excess precision."""
    if fee is None:
        return None
    return Decimal(fee).quantize(_feerate_quanta, rounding=decimal.ROUND_HALF_DOWN)


def timestamp_to_datetime(timestamp):
    if timestamp is None:
        return None
    return datetime.fromtimestamp(timestamp)

def format_time(timestamp):
    date = timestamp_to_datetime(timestamp)
    return date.isoformat(' ')[:-3] if date else _("Unknown")


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

mainnet_block_explorers = {
    'explorer.dgld.ch': ('https://explorer.dgld.ch/',
                        {'tx': 'tx/', 'addr': 'addr/'}),
    'system default': ('blockchain:/',
                        {'tx': 'tx/', 'addr': 'address/'}),
}

testnet_block_explorers = {
    'cbtexplorer.com': ('https://www.cbtexplorer.com/',
                        {'tx': 'tx/', 'addr': 'addr/'}),
    'system default': ('blockchain://000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943/',
                       {'tx': 'tx/', 'addr': 'address/'}),
}

def block_explorer_info():
    from . import constants
    return testnet_block_explorers if constants.net.TESTNET else mainnet_block_explorers

def block_explorer(config):
    return config.get('block_explorer', 'explorer.dgld.ch')

def block_explorer_tuple(config):
    return block_explorer_info().get(block_explorer(config))

def block_explorer_URL(config, kind, item):
    be_tuple = block_explorer_tuple(config)
    if not be_tuple:
        return
    kind_str = be_tuple[1].get(kind)
    if not kind_str:
        return
    url_parts = [be_tuple[0], kind_str, item]
    return ''.join(url_parts)

# URL decode
#_ud = re.compile('%([0-9a-hA-H]{2})', re.MULTILINE)
#urldecode = lambda x: _ud.sub(lambda m: chr(int(m.group(1), 16)), x)

def parse_URI(uri, on_pr=None):
    from . import bitcoin
    from .bitcoin import COIN

    if ':' not in uri:
        if not bitcoin.is_address(uri):
            raise Exception("Not a bitcoin address")
        return {'address': uri}

    u = urllib.parse.urlparse(uri)
    if u.scheme != 'bitcoin':
        raise Exception("Not a bitcoin URI")
    address = u.path

    # python for android fails to parse query
    if address.find('?') > 0:
        address, query = u.path.split('?')
        pq = urllib.parse.parse_qs(query)
    else:
        pq = urllib.parse.parse_qs(u.query)

    for k, v in pq.items():
        if len(v)!=1:
            raise Exception('Duplicate Key', k)

    out = {k: v[0] for k, v in pq.items()}
    if address:
        if not bitcoin.is_address(address):
            raise Exception("Invalid bitcoin address:" + address)
        out['address'] = address
    if 'amount' in out:
        am = out['amount']
        m = re.match('([0-9\.]+)X([0-9])', am)
        if m:
            k = int(m.group(2)) - 8
            amount = Decimal(m.group(1)) * pow(  Decimal(10) , k)
        else:
            amount = Decimal(am) * COIN
        out['amount'] = int(amount)
    if 'message' in out:
        out['message'] = out['message']
        out['memo'] = out['message']
    if 'time' in out:
        out['time'] = int(out['time'])
    if 'exp' in out:
        out['exp'] = int(out['exp'])
    if 'sig' in out:
        out['sig'] = bh2u(bitcoin.base_decode(out['sig'], None, base=58))

    r = out.get('r')
    sig = out.get('sig')
    name = out.get('name')
    if on_pr and (r or (name and sig)):
        def get_payment_request_thread():
            from . import paymentrequest as pr
            if name and sig:
                s = pr.serialize_request(out).SerializeToString()
                request = pr.PaymentRequest(s)
            else:
                request = pr.get_payment_request(r)
            if on_pr:
                on_pr(request)
        t = threading.Thread(target=get_payment_request_thread)
        t.setDaemon(True)
        t.start()

    return out


def create_URI(addr, amount, message):
    from . import bitcoin
    if not bitcoin.is_address(addr):
        return ""
    query = []
    if amount:
        query.append('amount=%s'%format_satoshis_plain(amount))
    if message:
        query.append('message=%s'%urllib.parse.quote(message))
    p = urllib.parse.ParseResult(scheme='bitcoin', netloc='', path=addr, params='', query='&'.join(query), fragment='')
    return urllib.parse.urlunparse(p)


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
    pass

import socket
import json
import ssl
import time


class SocketPipe:
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
                    print_error("socket errno %d (resource temporarily unavailable)"% err.errno)
                    time.sleep(0.2)
                    raise timeout
                else:
                    print_error("pipe: socket error", err)
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
            try:
                sent = self.socket.send(out)
                out = out[sent:]
            except ssl.SSLError as e:
                print_error("SSLError:", e)
                time.sleep(0.1)
                continue


class QueuePipe:

    def __init__(self, send_queue=None, get_queue=None):
        self.send_queue = send_queue if send_queue else queue.Queue()
        self.get_queue = get_queue if get_queue else queue.Queue()
        self.set_timeout(0.1)

    def get(self):
        try:
            return self.get_queue.get(timeout=self.timeout)
        except queue.Empty:
            raise timeout

    def get_all(self):
        responses = []
        while True:
            try:
                r = self.get_queue.get_nowait()
                responses.append(r)
            except queue.Empty:
                break
        return responses

    def set_timeout(self, t):
        self.timeout = t

    def send(self, request):
        self.send_queue.put(request)

    def send_all(self, requests):
        for request in requests:
            self.send(request)




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


def import_meta(path, validater, load_meta):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            d = validater(json.loads(f.read()))
        load_meta(d)
    #backwards compatibility for JSONDecodeError
    except ValueError:
        traceback.print_exc(file=sys.stderr)
        raise FileImportFailed(_("Invalid JSON code."))
    except BaseException as e:
        traceback.print_exc(file=sys.stdout)
        raise FileImportFailed(e)


def export_meta(meta, fileName):
    try:
        with open(fileName, 'w+', encoding='utf-8') as f:
            json.dump(meta, f, indent=4, sort_keys=True)
    except (IOError, os.error) as e:
        traceback.print_exc(file=sys.stderr)
        raise FileExportFailed(e)


def make_dir(path, allow_symlink=True):
    """Make directory if it does not yet exist."""
    if not os.path.exists(path):
        if not allow_symlink and os.path.islink(path):
            raise Exception('Dangling link: ' + path)
        os.mkdir(path)
        if 'ANDROID_DATA' not in os.environ:
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)


TxMinedStatus = NamedTuple("TxMinedStatus", [("height", int),
                                             ("conf", int),
                                             ("timestamp", int),
                                             ("header_hash", str)])
VerifiedTxInfo = NamedTuple("VerifiedTxInfo", [("height", int),
                                               ("timestamp", int),
                                               ("txpos", int),
                                               ("header_hash", str)])
