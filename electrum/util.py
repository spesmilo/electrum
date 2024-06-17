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
import concurrent.futures
import logging
import os, sys, re, json
from collections import defaultdict, OrderedDict
from typing import (NamedTuple, Union, TYPE_CHECKING, Tuple, Optional, Callable, Any,
                    Sequence, Dict, Generic, TypeVar, List, Iterable, Set, Awaitable)
from datetime import datetime, timezone
import decimal
from decimal import Decimal
import traceback
import urllib
import threading
import hmac
import stat
import locale
import asyncio
import urllib.request, urllib.parse, urllib.error
import builtins
import json
import time
from typing import NamedTuple, Optional
import ssl
import ipaddress
from ipaddress import IPv4Address, IPv6Address
import random
import secrets
import functools
from functools import partial
from abc import abstractmethod, ABC
import socket
import enum

import attr
import aiohttp
from aiohttp_socks import ProxyConnector, ProxyType
import aiorpcx
import certifi
import dns.resolver

from .i18n import _
from .logging import get_logger, Logger

if TYPE_CHECKING:
    from .network import Network
    from .interface import Interface
    from .simple_config import SimpleConfig
    from .paymentrequest import PaymentRequest


_logger = get_logger(__name__)


def inv_dict(d):
    return {v: k for k, v in d.items()}


def all_subclasses(cls) -> Set:
    """Return all (transitive) subclasses of cls."""
    res = set(cls.__subclasses__())
    for sub in res.copy():
        res |= all_subclasses(sub)
    return res


ca_path = certifi.where()


base_units = {'BTC':8, 'mBTC':5, 'bits':2, 'sat':0}
base_units_inverse = inv_dict(base_units)
base_units_list = ['BTC', 'mBTC', 'bits', 'sat']  # list(dict) does not guarantee order

DECIMAL_POINT_DEFAULT = 5  # mBTC


class UnknownBaseUnit(Exception): pass


def decimal_point_to_base_unit_name(dp: int) -> str:
    # e.g. 8 -> "BTC"
    try:
        return base_units_inverse[dp]
    except KeyError:
        raise UnknownBaseUnit(dp) from None


def base_unit_name_to_decimal_point(unit_name: str) -> int:
    """Returns the max number of digits allowed after the decimal point."""
    # e.g. "BTC" -> 8
    try:
        return base_units[unit_name]
    except KeyError:
        raise UnknownBaseUnit(unit_name) from None

def parse_max_spend(amt: Any) -> Optional[int]:
    """Checks if given amount is "spend-max"-like.
    Returns None or the positive integer weight for "max". Never raises.

    When creating invoices and on-chain txs, the user can specify to send "max".
    This is done by setting the amount to '!'. Splitting max between multiple
    tx outputs is also possible, and custom weights (positive ints) can also be used.
    For example, to send 40% of all coins to address1, and 60% to address2:
    ```
    address1, 2!
    address2, 3!
    ```
    """
    if not (isinstance(amt, str) and amt and amt[-1] == '!'):
        return None
    if amt == '!':
        return 1
    x = amt[:-1]
    try:
        x = int(x)
    except ValueError:
        return None
    if x > 0:
        return x
    return None

class NotEnoughFunds(Exception):
    def __str__(self):
        return _("Insufficient funds")


class NoDynamicFeeEstimates(Exception):
    def __str__(self):
        return _('Dynamic fee estimates not available')


class BelowDustLimit(Exception):
    pass


class InvalidPassword(Exception):
    def __init__(self, message: Optional[str] = None):
        self.message = message

    def __str__(self):
        if self.message is None:
            return _("Incorrect password")
        else:
            return str(self.message)


class AddTransactionException(Exception):
    pass


class UnrelatedTransactionException(AddTransactionException):
    def __str__(self):
        return _("Transaction is unrelated to this wallet.")


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


class WalletFileException(Exception):
    def __init__(self, message='', *, should_report_crash: bool = False):
        Exception.__init__(self, message)
        self.should_report_crash = should_report_crash


class BitcoinException(Exception): pass


class UserFacingException(Exception):
    """Exception that contains information intended to be shown to the user."""


class InvoiceError(UserFacingException): pass


class NetworkOfflineException(UserFacingException):
    """Can be raised if we are running in offline mode (--offline flag)
    and the user requests an operation that requires the network.
    """
    def __str__(self):
        return _("You are offline.")


# Throw this exception to unwind the stack like when an error occurs.
# However unlike other exceptions the user won't be informed.
class UserCancelled(Exception):
    '''An exception that is suppressed from the user'''
    pass


def to_decimal(x: Union[str, float, int, Decimal]) -> Decimal:
    # helper function mainly for float->Decimal conversion, i.e.:
    #   >>> Decimal(41754.681)
    #   Decimal('41754.680999999996856786310672760009765625')
    #   >>> Decimal("41754.681")
    #   Decimal('41754.681')
    if isinstance(x, Decimal):
        return x
    return Decimal(str(x))


# note: this is not a NamedTuple as then its json encoding cannot be customized
class Satoshis(object):
    __slots__ = ('value',)

    def __new__(cls, value):
        self = super(Satoshis, cls).__new__(cls)
        # note: 'value' sometimes has msat precision
        assert isinstance(value, (int, Decimal)), f"unexpected type for {value=!r}"
        self.value = value
        return self

    def __repr__(self):
        return f'Satoshis({self.value})'

    def __str__(self):
        # note: precision is truncated to satoshis here
        return format_satoshis(self.value)

    def __eq__(self, other):
        return self.value == other.value

    def __ne__(self, other):
        return not (self == other)

    def __add__(self, other):
        return Satoshis(self.value + other.value)


# note: this is not a NamedTuple as then its json encoding cannot be customized
class Fiat(object):
    __slots__ = ('value', 'ccy')

    def __new__(cls, value: Optional[Decimal], ccy: str):
        self = super(Fiat, cls).__new__(cls)
        self.ccy = ccy
        if not isinstance(value, (Decimal, type(None))):
            raise TypeError(f"value should be Decimal or None, not {type(value)}")
        self.value = value
        return self

    def __repr__(self):
        return 'Fiat(%s)'% self.__str__()

    def __str__(self):
        if self.value is None or self.value.is_nan():
            return _('No Data')
        else:
            return "{:.2f}".format(self.value)

    def to_ui_string(self):
        if self.value is None or self.value.is_nan():
            return _('No Data')
        else:
            return "{:.2f}".format(self.value) + ' ' + self.ccy

    def __eq__(self, other):
        if not isinstance(other, Fiat):
            return False
        if self.ccy != other.ccy:
            return False
        if isinstance(self.value, Decimal) and isinstance(other.value, Decimal) \
                and self.value.is_nan() and other.value.is_nan():
            return True
        return self.value == other.value

    def __ne__(self, other):
        return not (self == other)

    def __add__(self, other):
        assert self.ccy == other.ccy
        return Fiat(self.value + other.value, self.ccy)


class MyEncoder(json.JSONEncoder):
    def default(self, obj):
        # note: this does not get called for namedtuples :(  https://bugs.python.org/issue30343
        from .transaction import Transaction, TxOutput
        if isinstance(obj, Transaction):
            return obj.serialize()
        if isinstance(obj, TxOutput):
            return obj.to_legacy_tuple()
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
        if isinstance(obj, bytes): # for nametuples in lnchannel
            return obj.hex()
        if hasattr(obj, 'to_json') and callable(obj.to_json):
            return obj.to_json()
        return super(MyEncoder, self).default(obj)


class ThreadJob(Logger):
    """A job that is run periodically from a thread's main loop.  run() is
    called from that thread's context.
    """

    def __init__(self):
        Logger.__init__(self)

    def run(self):
        """Called periodically from the thread"""
        pass

class DebugMem(ThreadJob):
    '''A handy class for debugging GC memory leaks'''
    def __init__(self, classes, interval=30):
        ThreadJob.__init__(self)
        self.next_time = 0
        self.classes = classes
        self.interval = interval

    def mem_stats(self):
        import gc
        self.logger.info("Start memscan")
        gc.collect()
        objmap = defaultdict(list)
        for obj in gc.get_objects():
            for class_ in self.classes:
                if isinstance(obj, class_):
                    objmap[class_].append(obj)
        for class_, objs in objmap.items():
            self.logger.info(f"{class_.__name__}: {len(objs)}")
        self.logger.info("Finish memscan")

    def run(self):
        if time.time() > self.next_time:
            self.mem_stats()
            self.next_time = time.time() + self.interval

class DaemonThread(threading.Thread, Logger):
    """ daemon thread that terminates cleanly """

    LOGGING_SHORTCUT = 'd'

    def __init__(self):
        threading.Thread.__init__(self)
        Logger.__init__(self)
        self.parent_thread = threading.current_thread()
        self.running = False
        self.running_lock = threading.Lock()
        self.job_lock = threading.Lock()
        self.jobs = []
        self.stopped_event = threading.Event()        # set when fully stopped
        self.stopped_event_async = asyncio.Event()    # set when fully stopped
        self.wake_up_event = threading.Event()  # for perf optimisation of polling in run()

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
                    self.logger.exception('')

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
            self.wake_up_event.set()
            self.wake_up_event.clear()

    def on_stop(self):
        if 'ANDROID_DATA' in os.environ:
            import jnius
            jnius.detach()
            self.logger.info("jnius detach")
        self.logger.info("stopped")
        self.stopped_event.set()
        loop = get_asyncio_loop()
        loop.call_soon_threadsafe(self.stopped_event_async.set)


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
    except Exception:
        return x

def json_normalize(x):
    # note: The return value of commands, when going through the JSON-RPC interface,
    #       is json-encoded. The encoder used there cannot handle some types, e.g. electrum.util.Satoshis.
    # note: We should not simply do "json_encode(x)" here, as then later x would get doubly json-encoded.
    # see #5868
    return json_decode(json_encode(x))


# taken from Django Source Code
def constant_time_compare(val1, val2):
    """Return True if the two strings are equal, False otherwise."""
    return hmac.compare_digest(to_bytes(val1, 'utf8'), to_bytes(val2, 'utf8'))


_profiler_logger = _logger.getChild('profiler')
def profiler(func=None, *, min_threshold: Union[int, float, None] = None):
    """Function decorator that logs execution time.

    min_threshold: if set, only log if time taken is higher than threshold
    NOTE: does not work with async methods.
    """
    if func is None:  # to make "@profiler(...)" work. (in addition to bare "@profiler")
        return partial(profiler, min_threshold=min_threshold)
    def do_profile(*args, **kw_args):
        name = func.__qualname__
        t0 = time.time()
        o = func(*args, **kw_args)
        t = time.time() - t0
        if min_threshold is None or t > min_threshold:
            _profiler_logger.debug(f"{name} {t:,.4f} sec")
        return o
    return do_profile


class AsyncHangDetector:
    """Context manager that logs every `n` seconds if encapsulated context still has not exited."""

    def __init__(
        self,
        *,
        period_sec: int = 15,
        message: str,
        logger: logging.Logger = None,
    ):
        self.period_sec = period_sec
        self.message = message
        self.logger = logger or _logger

    async def _monitor(self):
        # note: this assumes that the event loop itself is not blocked
        t0 = time.monotonic()
        while True:
            await asyncio.sleep(self.period_sec)
            t1 = time.monotonic()
            self.logger.info(f"{self.message} (after {t1 - t0:.2f} sec)")

    async def __aenter__(self):
        self.mtask = asyncio.create_task(self._monitor())

    async def __aexit__(self, exc_type, exc, tb):
        self.mtask.cancel()


def android_ext_dir():
    from android.storage import primary_external_storage_path
    return primary_external_storage_path()

def android_backup_dir():
    pkgname = get_android_package_name()
    d = os.path.join(android_ext_dir(), pkgname)
    if not os.path.exists(d):
        os.mkdir(d)
    return d

def android_data_dir():
    import jnius
    PythonActivity = jnius.autoclass('org.kivy.android.PythonActivity')
    return PythonActivity.mActivity.getFilesDir().getPath() + '/data'

def ensure_sparse_file(filename):
    # On modern Linux, no need to do anything.
    # On Windows, need to explicitly mark file.
    if os.name == "nt":
        try:
            os.system('fsutil sparse setflag "{}" 1'.format(filename))
        except Exception as e:
            _logger.info(f'error marking file {filename} as sparse: {e}')


def get_headers_dir(config):
    return config.path


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


def standardize_path(path):
    # note: os.path.realpath() is not used, as on Windows it can return non-working paths (see #8495).
    #       This means that we don't resolve symlinks!
    return os.path.normcase(
                os.path.abspath(
                    os.path.expanduser(
                        path
    )))


def get_new_wallet_name(wallet_folder: str) -> str:
    """Returns a file basename for a new wallet to be used.
    Can raise OSError.
    """
    i = 1
    while True:
        filename = "wallet_%d" % i
        if filename in os.listdir(wallet_folder):
            i += 1
        else:
            break
    return filename


def is_android_debug_apk() -> bool:
    is_android = 'ANDROID_DATA' in os.environ
    if not is_android:
        return False
    from jnius import autoclass
    pkgname = get_android_package_name()
    build_config = autoclass(f"{pkgname}.BuildConfig")
    return bool(build_config.DEBUG)


def get_android_package_name() -> str:
    is_android = 'ANDROID_DATA' in os.environ
    assert is_android
    from jnius import autoclass
    from android.config import ACTIVITY_CLASS_NAME
    activity = autoclass(ACTIVITY_CLASS_NAME).mActivity
    pkgname = str(activity.getPackageName())
    return pkgname


def assert_bytes(*args):
    """
    porting helper, assert args type
    """
    try:
        for x in args:
            assert isinstance(x, (bytes, bytearray))
    except Exception:
        print('assert bytes failed', list(map(type, args)))
        raise


def assert_str(*args):
    """
    porting helper, assert args type
    """
    for x in args:
        assert isinstance(x, str)


def to_string(x, enc) -> str:
    if isinstance(x, (bytes, bytearray)):
        return x.decode(enc)
    if isinstance(x, str):
        return x
    else:
        raise TypeError("Not a string or bytes like object")


def to_bytes(something, encoding='utf8') -> bytes:
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


def xor_bytes(a: bytes, b: bytes) -> bytes:
    size = min(len(a), len(b))
    return ((int.from_bytes(a[:size], "big") ^ int.from_bytes(b[:size], "big"))
            .to_bytes(size, "big"))


def user_dir():
    if "ELECTRUMDIR" in os.environ:
        return os.environ["ELECTRUMDIR"]
    elif 'ANDROID_DATA' in os.environ:
        return android_data_dir()
    elif os.name == 'posix':
        return os.path.join(os.environ["HOME"], ".electrum")
    elif "APPDATA" in os.environ:
        return os.path.join(os.environ["APPDATA"], "Electrum")
    elif "LOCALAPPDATA" in os.environ:
        return os.path.join(os.environ["LOCALAPPDATA"], "Electrum")
    else:
        #raise Exception("No home directory found in environment variables.")
        return


def resource_path(*parts):
    return os.path.join(pkg_dir, *parts)


# absolute path to python package folder of electrum ("lib")
pkg_dir = os.path.split(os.path.realpath(__file__))[0]


def is_valid_email(s):
    regexp = r"[^@]+@[^@]+\.[^@]+"
    return re.match(regexp, s) is not None


def is_hash256_str(text: Any) -> bool:
    if not isinstance(text, str): return False
    if len(text) != 64: return False
    return is_hex_str(text)


def is_hex_str(text: Any) -> bool:
    if not isinstance(text, str): return False
    try:
        b = bytes.fromhex(text)
    except Exception:
        return False
    # forbid whitespaces in text:
    if len(text) != 2 * len(b):
        return False
    return True


def is_integer(val: Any) -> bool:
    return isinstance(val, int)


def is_non_negative_integer(val: Any) -> bool:
    if is_integer(val):
        return val >= 0
    return False


def is_int_or_float(val: Any) -> bool:
    return isinstance(val, (int, float))


def is_non_negative_int_or_float(val: Any) -> bool:
    if is_int_or_float(val):
        return val >= 0
    return False


def chunks(items, size: int):
    """Break up items, an iterable, into chunks of length size."""
    if size < 1:
        raise ValueError(f"size must be positive, not {repr(size)}")
    for i in range(0, len(items), size):
        yield items[i: i + size]


def format_satoshis_plain(
        x: Union[int, float, Decimal, str],  # amount in satoshis,
        *,
        decimal_point: int = 8,  # how much to shift decimal point to left (default: sat->BTC)
) -> str:
    """Display a satoshi amount scaled.  Always uses a '.' as a decimal
    point and has no thousands separator"""
    if parse_max_spend(x):
        return f'max({x})'
    assert isinstance(x, (int, float, Decimal)), f"{x!r} should be a number"
    scale_factor = pow(10, decimal_point)
    return "{:.8f}".format(Decimal(x) / scale_factor).rstrip('0').rstrip('.')


# Check that Decimal precision is sufficient.
# We need at the very least ~20, as we deal with msat amounts, and
# log10(21_000_000 * 10**8 * 1000) ~= 18.3
# decimal.DefaultContext.prec == 28 by default, but it is mutable.
# We enforce that we have at least that available.
assert decimal.getcontext().prec >= 28, f"PyDecimal precision too low: {decimal.getcontext().prec}"

# DECIMAL_POINT = locale.localeconv()['decimal_point']  # type: str
DECIMAL_POINT = "."
THOUSANDS_SEP = " "
assert len(DECIMAL_POINT) == 1, f"DECIMAL_POINT has unexpected len. {DECIMAL_POINT!r}"
assert len(THOUSANDS_SEP) == 1, f"THOUSANDS_SEP has unexpected len. {THOUSANDS_SEP!r}"


def format_satoshis(
        x: Union[int, float, Decimal, str, None],  # amount in satoshis
        *,
        num_zeros: int = 0,
        decimal_point: int = 8,  # how much to shift decimal point to left (default: sat->BTC)
        precision: int = 0,  # extra digits after satoshi precision
        is_diff: bool = False,  # if True, enforce a leading sign (+/-)
        whitespaces: bool = False,  # if True, add whitespaces, to align numbers in a column
        add_thousands_sep: bool = False,  # if True, add whitespaces, for better readability of the numbers
) -> str:
    if x is None:
        return 'unknown'
    if parse_max_spend(x):
        return f'max({x})'
    assert isinstance(x, (int, float, Decimal)), f"{x!r} should be a number"
    # lose redundant precision
    x = Decimal(x).quantize(Decimal(10) ** (-precision))
    # format string
    overall_precision = decimal_point + precision  # max digits after final decimal point
    decimal_format = "." + str(overall_precision) if overall_precision > 0 else ""
    if is_diff:
        decimal_format = '+' + decimal_format
    # initial result
    scale_factor = pow(10, decimal_point)
    result = ("{:" + decimal_format + "f}").format(x / scale_factor)
    if "." not in result: result += "."
    result = result.rstrip('0')
    # add extra decimal places (zeros)
    integer_part, fract_part = result.split(".")
    if len(fract_part) < num_zeros:
        fract_part += "0" * (num_zeros - len(fract_part))
    # add whitespaces as thousands' separator for better readability of numbers
    if add_thousands_sep:
        sign = integer_part[0] if integer_part[0] in ("+", "-") else ""
        if sign == "-":
            integer_part = integer_part[1:]
        integer_part = "{:,}".format(int(integer_part)).replace(',', THOUSANDS_SEP)
        integer_part = sign + integer_part
        fract_part = THOUSANDS_SEP.join(fract_part[i:i+3] for i in range(0, len(fract_part), 3))
    result = integer_part + DECIMAL_POINT + fract_part
    # add leading/trailing whitespaces so that numbers can be aligned in a column
    if whitespaces:
        target_fract_len = overall_precision
        target_integer_len = 14 - decimal_point  # should be enough for up to unsigned 999999 BTC
        if add_thousands_sep:
            target_fract_len += max(0, (target_fract_len - 1) // 3)
            target_integer_len += max(0, (target_integer_len - 1) // 3)
        # add trailing whitespaces
        result += " " * (target_fract_len - len(fract_part))
        # add leading whitespaces
        target_total_len = target_integer_len + 1 + target_fract_len
        result = " " * (target_total_len - len(result)) + result
    return result


FEERATE_PRECISION = 1  # num fractional decimal places for sat/byte fee rates
_feerate_quanta = Decimal(10) ** (-FEERATE_PRECISION)
UI_UNIT_NAME_FEERATE_SAT_PER_VBYTE = "sat/vbyte"
UI_UNIT_NAME_FEERATE_SAT_PER_VB = "sat/vB"
UI_UNIT_NAME_TXSIZE_VBYTES = "vbytes"
UI_UNIT_NAME_MEMPOOL_MB = "vMB"


def format_fee_satoshis(fee, *, num_zeros=0, precision=None):
    if precision is None:
        precision = FEERATE_PRECISION
    num_zeros = min(num_zeros, FEERATE_PRECISION)  # no more zeroes than available prec
    return format_satoshis(fee, num_zeros=num_zeros, decimal_point=0, precision=precision)


def quantize_feerate(fee) -> Union[None, Decimal, int]:
    """Strip sat/byte fee rate of excess precision."""
    if fee is None:
        return None
    return Decimal(fee).quantize(_feerate_quanta, rounding=decimal.ROUND_HALF_DOWN)


def timestamp_to_datetime(timestamp: Union[int, float, None], *, utc: bool = False) -> Optional[datetime]:
    if timestamp is None:
        return None
    tz = None
    if utc:
        tz = timezone.utc
    return datetime.fromtimestamp(timestamp, tz=tz)


def format_time(timestamp: Union[int, float, None]) -> str:
    date = timestamp_to_datetime(timestamp)
    return date.isoformat(' ', timespec="minutes") if date else _("Unknown")


def age(
    from_date: Union[int, float, None],  # POSIX timestamp
    *,
    since_date: datetime = None,
    target_tz=None,
    include_seconds: bool = False,
) -> str:
    """Takes a timestamp and returns a string with the approximation of the age"""
    if from_date is None:
        return _("Unknown")

    from_date = datetime.fromtimestamp(from_date)
    if since_date is None:
        since_date = datetime.now(target_tz)

    distance_in_time = from_date - since_date
    is_in_past = from_date < since_date
    distance_in_seconds = int(round(abs(distance_in_time.days * 86400 + distance_in_time.seconds)))
    distance_in_minutes = int(round(distance_in_seconds / 60))

    if distance_in_minutes == 0:
        if include_seconds:
            if is_in_past:
                return _("{} seconds ago").format(distance_in_seconds)
            else:
                return _("in {} seconds").format(distance_in_seconds)
        else:
            if is_in_past:
                return _("less than a minute ago")
            else:
                return _("in less than a minute")
    elif distance_in_minutes < 45:
        if is_in_past:
            return _("about {} minutes ago").format(distance_in_minutes)
        else:
            return _("in about {} minutes").format(distance_in_minutes)
    elif distance_in_minutes < 90:
        if is_in_past:
            return _("about 1 hour ago")
        else:
            return _("in about 1 hour")
    elif distance_in_minutes < 1440:
        if is_in_past:
            return _("about {} hours ago").format(round(distance_in_minutes / 60.0))
        else:
            return _("in about {} hours").format(round(distance_in_minutes / 60.0))
    elif distance_in_minutes < 2880:
        if is_in_past:
            return _("about 1 day ago")
        else:
            return _("in about 1 day")
    elif distance_in_minutes < 43220:
        if is_in_past:
            return _("about {} days ago").format(round(distance_in_minutes / 1440))
        else:
            return _("in about {} days").format(round(distance_in_minutes / 1440))
    elif distance_in_minutes < 86400:
        if is_in_past:
            return _("about 1 month ago")
        else:
            return _("in about 1 month")
    elif distance_in_minutes < 525600:
        if is_in_past:
            return _("about {} months ago").format(round(distance_in_minutes / 43200))
        else:
            return _("in about {} months").format(round(distance_in_minutes / 43200))
    elif distance_in_minutes < 1051200:
        if is_in_past:
            return _("about 1 year ago")
        else:
            return _("in about 1 year")
    else:
        if is_in_past:
            return _("over {} years ago").format(round(distance_in_minutes / 525600))
        else:
            return _("in over {} years").format(round(distance_in_minutes / 525600))

mainnet_block_explorers = {
    '3xpl.com': ('https://3xpl.com/bitcoin/',
                        {'tx': 'transaction/', 'addr': 'address/'}),
    'Bitflyer.jp': ('https://chainflyer.bitflyer.jp/',
                        {'tx': 'Transaction/', 'addr': 'Address/'}),
    'Blockchain.info': ('https://blockchain.com/btc/',
                        {'tx': 'tx/', 'addr': 'address/'}),
    'Blockstream.info': ('https://blockstream.info/',
                        {'tx': 'tx/', 'addr': 'address/'}),
    'Bitaps.com': ('https://btc.bitaps.com/',
                        {'tx': '', 'addr': ''}),
    'BTC.com': ('https://btc.com/',
                        {'tx': '', 'addr': ''}),
    'Chain.so': ('https://www.chain.so/',
                        {'tx': 'tx/BTC/', 'addr': 'address/BTC/'}),
    'Insight.is': ('https://insight.bitpay.com/',
                        {'tx': 'tx/', 'addr': 'address/'}),
    'BlockCypher.com': ('https://live.blockcypher.com/btc/',
                        {'tx': 'tx/', 'addr': 'address/'}),
    'Blockchair.com': ('https://blockchair.com/bitcoin/',
                        {'tx': 'transaction/', 'addr': 'address/'}),
    'blockonomics.co': ('https://www.blockonomics.co/',
                        {'tx': 'api/tx?txid=', 'addr': '#/search?q='}),
    'mempool.space': ('https://mempool.space/',
                        {'tx': 'tx/', 'addr': 'address/'}),
    'mempool.emzy.de': ('https://mempool.emzy.de/',
                        {'tx': 'tx/', 'addr': 'address/'}),
    'OXT.me': ('https://oxt.me/',
                        {'tx': 'transaction/', 'addr': 'address/'}),
    'mynode.local': ('http://mynode.local:3002/',
                        {'tx': 'tx/', 'addr': 'address/'}),
    'system default': ('blockchain:/',
                        {'tx': 'tx/', 'addr': 'address/'}),
}

testnet_block_explorers = {
    'Bitaps.com': ('https://tbtc.bitaps.com/',
                       {'tx': '', 'addr': ''}),
    'BlockCypher.com': ('https://live.blockcypher.com/btc-testnet/',
                       {'tx': 'tx/', 'addr': 'address/'}),
    'Blockchain.info': ('https://www.blockchain.com/btc-testnet/',
                       {'tx': 'tx/', 'addr': 'address/'}),
    'Blockstream.info': ('https://blockstream.info/testnet/',
                        {'tx': 'tx/', 'addr': 'address/'}),
    'mempool.space': ('https://mempool.space/testnet/',
                        {'tx': 'tx/', 'addr': 'address/'}),
    'smartbit.com.au': ('https://testnet.smartbit.com.au/',
                       {'tx': 'tx/', 'addr': 'address/'}),
    'system default': ('blockchain://000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943/',
                       {'tx': 'tx/', 'addr': 'address/'}),
}

signet_block_explorers = {
    'bc-2.jp': ('https://explorer.bc-2.jp/',
                        {'tx': 'tx/', 'addr': 'address/'}),
    'mempool.space': ('https://mempool.space/signet/',
                        {'tx': 'tx/', 'addr': 'address/'}),
    'bitcoinexplorer.org': ('https://signet.bitcoinexplorer.org/',
                       {'tx': 'tx/', 'addr': 'address/'}),
    'wakiyamap.dev': ('https://signet-explorer.wakiyamap.dev/',
                       {'tx': 'tx/', 'addr': 'address/'}),
    'ex.signet.bublina.eu.org': ('https://ex.signet.bublina.eu.org/',
                       {'tx': 'tx/', 'addr': 'address/'}),
    'system default': ('blockchain:/',
                       {'tx': 'tx/', 'addr': 'address/'}),
}

_block_explorer_default_api_loc = {'tx': 'tx/', 'addr': 'address/'}


def block_explorer_info():
    from . import constants
    if constants.net.NET_NAME == "testnet":
        return testnet_block_explorers
    elif constants.net.NET_NAME == "signet":
        return signet_block_explorers
    return mainnet_block_explorers


def block_explorer(config: 'SimpleConfig') -> Optional[str]:
    """Returns name of selected block explorer,
    or None if a custom one (not among hardcoded ones) is configured.
    """
    if config.BLOCK_EXPLORER_CUSTOM is not None:
        return None
    be_key = config.BLOCK_EXPLORER
    be_tuple = block_explorer_info().get(be_key)
    if be_tuple is None:
        be_key = config.cv.BLOCK_EXPLORER.get_default_value()
    assert isinstance(be_key, str), f"{be_key!r} should be str"
    return be_key


def block_explorer_tuple(config: 'SimpleConfig') -> Optional[Tuple[str, dict]]:
    custom_be = config.BLOCK_EXPLORER_CUSTOM
    if custom_be:
        if isinstance(custom_be, str):
            return custom_be, _block_explorer_default_api_loc
        if isinstance(custom_be, (tuple, list)) and len(custom_be) == 2:
            return tuple(custom_be)
        _logger.warning(f"not using {config.cv.BLOCK_EXPLORER_CUSTOM.key()!r} from config. "
                        f"expected a str or a pair but got {custom_be!r}")
        return None
    else:
        # using one of the hardcoded block explorers
        return block_explorer_info().get(block_explorer(config))


def block_explorer_URL(config: 'SimpleConfig', kind: str, item: str) -> Optional[str]:
    be_tuple = block_explorer_tuple(config)
    if not be_tuple:
        return
    explorer_url, explorer_dict = be_tuple
    kind_str = explorer_dict.get(kind)
    if kind_str is None:
        return
    if explorer_url[-1] != "/":
        explorer_url += "/"
    url_parts = [explorer_url, kind_str, item]
    return ''.join(url_parts)





# Python bug (http://bugs.python.org/issue1927) causes raw_input
# to be redirected improperly between stdin/stderr on Unix systems
#TODO: py3
def raw_input(prompt=None):
    if prompt:
        sys.stdout.write(prompt)
    return builtin_raw_input()

builtin_raw_input = builtins.input
builtins.input = raw_input


def parse_json(message):
    # TODO: check \r\n pattern
    n = message.find(b'\n')
    if n==-1:
        return None, message
    try:
        j = json.loads(message[0:n].decode('utf8'))
    except Exception:
        j = None
    return j, message[n+1:]


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


def send_exception_to_crash_reporter(e: BaseException):
    from .base_crash_reporter import send_exception_to_crash_reporter
    send_exception_to_crash_reporter(e)


def versiontuple(v):
    return tuple(map(int, (v.split("."))))


def read_json_file(path):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.loads(f.read())
    except json.JSONDecodeError:
        _logger.exception('')
        raise FileImportFailed(_("Invalid JSON code."))
    except BaseException as e:
        _logger.exception('')
        raise FileImportFailed(e)
    return data


def write_json_file(path, data):
    try:
        with open(path, 'w+', encoding='utf-8') as f:
            json.dump(data, f, indent=4, sort_keys=True, cls=MyEncoder)
    except (IOError, os.error) as e:
        _logger.exception('')
        raise FileExportFailed(e)


def os_chmod(path, mode):
    """os.chmod aware of tmpfs"""
    try:
        os.chmod(path, mode)
    except OSError as e:
        xdg_runtime_dir = os.environ.get("XDG_RUNTIME_DIR", None)
        if xdg_runtime_dir and is_subpath(path, xdg_runtime_dir):
            _logger.info(f"Tried to chmod in tmpfs. Skipping... {e!r}")
        else:
            raise


def make_dir(path, allow_symlink=True):
    """Make directory if it does not yet exist."""
    if not os.path.exists(path):
        if not allow_symlink and os.path.islink(path):
            raise Exception('Dangling link: ' + path)
        os.mkdir(path)
        os_chmod(path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)


def is_subpath(long_path: str, short_path: str) -> bool:
    """Returns whether long_path is a sub-path of short_path."""
    try:
        common = os.path.commonpath([long_path, short_path])
    except ValueError:
        return False
    short_path = standardize_path(short_path)
    common     = standardize_path(common)
    return short_path == common


def log_exceptions(func):
    """Decorator to log AND re-raise exceptions."""
    assert asyncio.iscoroutinefunction(func), 'func needs to be a coroutine'
    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        self = args[0] if len(args) > 0 else None
        try:
            return await func(*args, **kwargs)
        except asyncio.CancelledError as e:
            raise
        except BaseException as e:
            mylogger = self.logger if hasattr(self, 'logger') else _logger
            try:
                mylogger.exception(f"Exception in {func.__name__}: {repr(e)}")
            except BaseException as e2:
                print(f"logging exception raised: {repr(e2)}... orig exc: {repr(e)} in {func.__name__}")
            raise
    return wrapper


def ignore_exceptions(func):
    """Decorator to silently swallow all exceptions."""
    assert asyncio.iscoroutinefunction(func), 'func needs to be a coroutine'
    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        try:
            return await func(*args, **kwargs)
        except Exception as e:
            pass
    return wrapper


def with_lock(func):
    """Decorator to enforce a lock on a function call."""
    def func_wrapper(self, *args, **kwargs):
        with self.lock:
            return func(self, *args, **kwargs)
    return func_wrapper


class TxMinedInfo(NamedTuple):
    height: int                        # height of block that mined tx
    conf: Optional[int] = None         # number of confirmations, SPV verified. >=0, or None (None means unknown)
    timestamp: Optional[int] = None    # timestamp of block that mined tx
    txpos: Optional[int] = None        # position of tx in serialized block
    header_hash: Optional[str] = None  # hash of block that mined tx
    wanted_height: Optional[int] = None  # in case of timelock, min abs block height

    def short_id(self) -> Optional[str]:
        if self.txpos is not None and self.txpos >= 0:
            assert self.height > 0
            return f"{self.height}x{self.txpos}"
        return None

    def is_local_like(self) -> bool:
        """Returns whether the tx is local-like (LOCAL/FUTURE)."""
        from .address_synchronizer import TX_HEIGHT_UNCONFIRMED, TX_HEIGHT_UNCONF_PARENT
        if self.height > 0:
            return False
        if self.height in (TX_HEIGHT_UNCONFIRMED, TX_HEIGHT_UNCONF_PARENT):
            return False
        return True


class ShortID(bytes):

    def __repr__(self):
        return f"<ShortID: {format_short_id(self)}>"

    def __str__(self):
        return format_short_id(self)

    @classmethod
    def from_components(cls, block_height: int, tx_pos_in_block: int, output_index: int) -> 'ShortID':
        bh = block_height.to_bytes(3, byteorder='big')
        tpos = tx_pos_in_block.to_bytes(3, byteorder='big')
        oi = output_index.to_bytes(2, byteorder='big')
        return ShortID(bh + tpos + oi)

    @classmethod
    def from_str(cls, scid: str) -> 'ShortID':
        """Parses a formatted scid str, e.g. '643920x356x0'."""
        components = scid.split("x")
        if len(components) != 3:
            raise ValueError(f"failed to parse ShortID: {scid!r}")
        try:
            components = [int(x) for x in components]
        except ValueError:
            raise ValueError(f"failed to parse ShortID: {scid!r}") from None
        return ShortID.from_components(*components)

    @classmethod
    def normalize(cls, data: Union[None, str, bytes, 'ShortID']) -> Optional['ShortID']:
        if isinstance(data, ShortID) or data is None:
            return data
        if isinstance(data, str):
            assert len(data) == 16
            return ShortID.fromhex(data)
        if isinstance(data, (bytes, bytearray)):
            assert len(data) == 8
            return ShortID(data)

    @property
    def block_height(self) -> int:
        return int.from_bytes(self[:3], byteorder='big')

    @property
    def txpos(self) -> int:
        return int.from_bytes(self[3:6], byteorder='big')

    @property
    def output_index(self) -> int:
        return int.from_bytes(self[6:8], byteorder='big')


def format_short_id(short_channel_id: Optional[bytes]):
    if not short_channel_id:
        return _('Not yet available')
    return str(int.from_bytes(short_channel_id[:3], 'big')) \
        + 'x' + str(int.from_bytes(short_channel_id[3:6], 'big')) \
        + 'x' + str(int.from_bytes(short_channel_id[6:], 'big'))


def make_aiohttp_session(proxy: Optional[dict], headers=None, timeout=None):
    if headers is None:
        headers = {'User-Agent': 'Electrum'}
    if timeout is None:
        # The default timeout is high intentionally.
        # DNS on some systems can be really slow, see e.g. #5337
        timeout = aiohttp.ClientTimeout(total=45)
    elif isinstance(timeout, (int, float)):
        timeout = aiohttp.ClientTimeout(total=timeout)
    ssl_context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH, cafile=ca_path)

    if proxy:
        connector = ProxyConnector(
            proxy_type=ProxyType.SOCKS5 if proxy['mode'] == 'socks5' else ProxyType.SOCKS4,
            host=proxy['host'],
            port=int(proxy['port']),
            username=proxy.get('user', None),
            password=proxy.get('password', None),
            rdns=True,  # needed to prevent DNS leaks over proxy
            ssl=ssl_context,
        )
    else:
        connector = aiohttp.TCPConnector(ssl=ssl_context)

    return aiohttp.ClientSession(headers=headers, timeout=timeout, connector=connector)


class OldTaskGroup(aiorpcx.TaskGroup):
    """Automatically raises exceptions on join; as in aiorpcx prior to version 0.20.
    That is, when using TaskGroup as a context manager, if any task encounters an exception,
    we would like that exception to be re-raised (propagated out). For the wait=all case,
    the OldTaskGroup class is emulating the following code-snippet:
    ```
    async with TaskGroup() as group:
        await group.spawn(task1())
        await group.spawn(task2())

        async for task in group:
            if not task.cancelled():
                task.result()
    ```
    So instead of the above, one can just write:
    ```
    async with OldTaskGroup() as group:
        await group.spawn(task1())
        await group.spawn(task2())
    ```
    # TODO see if we can migrate to asyncio.timeout, introduced in python 3.11, and use stdlib instead of aiorpcx.curio...
    """
    async def join(self):
        if self._wait is all:
            exc = False
            try:
                async for task in self:
                    if not task.cancelled():
                        task.result()
            except BaseException:  # including asyncio.CancelledError
                exc = True
                raise
            finally:
                if exc:
                    await self.cancel_remaining()
                await super().join()
        else:
            await super().join()
            if self.completed:
                self.completed.result()

# We monkey-patch aiorpcx TimeoutAfter (used by timeout_after and ignore_after API),
# to fix a timing issue present in asyncio as a whole re timing out tasks.
# To see the issue we are trying to fix, consider example:
#     async def outer_task():
#         async with timeout_after(0.1):
#             await inner_task()
# When the 0.1 sec timeout expires, inner_task will get cancelled by timeout_after (=internal cancellation).
# If around the same time (in terms of event loop iterations) another coroutine
# cancels outer_task (=external cancellation), there will be a race.
# Both cancellations work by propagating a CancelledError out to timeout_after, which then
# needs to decide (in TimeoutAfter.__aexit__) whether it's due to an internal or external cancellation.
# AFAICT asyncio provides no reliable way of distinguishing between the two.
# This patch tries to always give priority to external cancellations.
# see https://github.com/kyuupichan/aiorpcX/issues/44
# see https://github.com/aio-libs/async-timeout/issues/229
# see https://bugs.python.org/issue42130 and https://bugs.python.org/issue45098
# TODO see if we can migrate to asyncio.timeout, introduced in python 3.11, and use stdlib instead of aiorpcx.curio...
def _aiorpcx_monkeypatched_set_new_deadline(task, deadline):
    def timeout_task():
        task._orig_cancel()
        task._timed_out = None if getattr(task, "_externally_cancelled", False) else deadline
    def mycancel(*args, **kwargs):
        task._orig_cancel(*args, **kwargs)
        task._externally_cancelled = True
        task._timed_out = None
    if not hasattr(task, "_orig_cancel"):
        task._orig_cancel = task.cancel
        task.cancel = mycancel
    task._deadline_handle = task._loop.call_at(deadline, timeout_task)


def _aiorpcx_monkeypatched_set_task_deadline(task, deadline):
    ret = _aiorpcx_orig_set_task_deadline(task, deadline)
    task._externally_cancelled = None
    return ret


def _aiorpcx_monkeypatched_unset_task_deadline(task):
    if hasattr(task, "_orig_cancel"):
        task.cancel = task._orig_cancel
        del task._orig_cancel
    return _aiorpcx_orig_unset_task_deadline(task)


_aiorpcx_orig_set_task_deadline    = aiorpcx.curio._set_task_deadline
_aiorpcx_orig_unset_task_deadline  = aiorpcx.curio._unset_task_deadline

aiorpcx.curio._set_new_deadline    = _aiorpcx_monkeypatched_set_new_deadline
aiorpcx.curio._set_task_deadline   = _aiorpcx_monkeypatched_set_task_deadline
aiorpcx.curio._unset_task_deadline = _aiorpcx_monkeypatched_unset_task_deadline


async def wait_for2(fut: Awaitable, timeout: Union[int, float, None]):
    """Replacement for asyncio.wait_for,
     due to bugs: https://bugs.python.org/issue42130 and https://github.com/python/cpython/issues/86296 ,
     which are only fixed in python 3.12+.
     """
    if sys.version_info[:3] >= (3, 12):
        return await asyncio.wait_for(fut, timeout)
    else:
        async with async_timeout(timeout):
            return await asyncio.ensure_future(fut, loop=get_running_loop())


if hasattr(asyncio, 'timeout'):  # python 3.11+
    async_timeout = asyncio.timeout
else:
    class TimeoutAfterAsynciolike(aiorpcx.curio.TimeoutAfter):
        async def __aexit__(self, exc_type, exc_value, traceback):
            try:
                await super().__aexit__(exc_type, exc_value, traceback)
            except (aiorpcx.TaskTimeout, aiorpcx.UncaughtTimeoutError):
                raise asyncio.TimeoutError from None
            except aiorpcx.TimeoutCancellationError:
                raise asyncio.CancelledError from None

    def async_timeout(delay: Union[int, float, None]):
        if delay is None:
            return nullcontext()
        return TimeoutAfterAsynciolike(delay)


class NetworkJobOnDefaultServer(Logger, ABC):
    """An abstract base class for a job that runs on the main network
    interface. Every time the main interface changes, the job is
    restarted, and some of its internals are reset.
    """
    def __init__(self, network: 'Network'):
        Logger.__init__(self)
        self.network = network
        self.interface = None  # type: Interface
        self._restart_lock = asyncio.Lock()
        # Ensure fairness between NetworkJobs. e.g. if multiple wallets
        # are open, a large wallet's Synchronizer should not starve the small wallets:
        self._network_request_semaphore = asyncio.Semaphore(100)

        self._reset()
        # every time the main interface changes, restart:
        register_callback(self._restart, ['default_server_changed'])
        # also schedule a one-off restart now, as there might already be a main interface:
        asyncio.run_coroutine_threadsafe(self._restart(), network.asyncio_loop)

    def _reset(self):
        """Initialise fields. Called every time the underlying
        server connection changes.
        """
        self.taskgroup = OldTaskGroup()
        self.reset_request_counters()

    async def _start(self, interface: 'Interface'):
        self.logger.debug(f"starting. interface.server={repr(str(interface.server))}")
        self.interface = interface

        taskgroup = self.taskgroup
        async def run_tasks_wrapper():
            self.logger.debug(f"starting taskgroup ({hex(id(taskgroup))}).")
            try:
                await self._run_tasks(taskgroup=taskgroup)
            except Exception as e:
                self.logger.error(f"taskgroup died ({hex(id(taskgroup))}). exc={e!r}")
                raise
            finally:
                self.logger.debug(f"taskgroup stopped ({hex(id(taskgroup))}).")
        await interface.taskgroup.spawn(run_tasks_wrapper)

    @abstractmethod
    async def _run_tasks(self, *, taskgroup: OldTaskGroup) -> None:
        """Start tasks in taskgroup. Called every time the underlying
        server connection changes.
        """
        # If self.taskgroup changed, don't start tasks. This can happen if we have
        # been restarted *just now*, i.e. after the _run_tasks coroutine object was created.
        if taskgroup != self.taskgroup:
            raise asyncio.CancelledError()

    async def stop(self, *, full_shutdown: bool = True):
        self.logger.debug(f"stopping. {full_shutdown=}")
        if full_shutdown:
            unregister_callback(self._restart)
        await self.taskgroup.cancel_remaining()

    @log_exceptions
    async def _restart(self, *args):
        interface = self.network.interface
        if interface is None:
            return  # we should get called again soon

        async with self._restart_lock:
            await self.stop(full_shutdown=False)
            self._reset()
            await self._start(interface)

    def reset_request_counters(self):
        self._requests_sent = 0
        self._requests_answered = 0

    def num_requests_sent_and_answered(self) -> Tuple[int, int]:
        return self._requests_sent, self._requests_answered

    @property
    def session(self):
        s = self.interface.session
        assert s is not None
        return s


def detect_tor_socks_proxy() -> Optional[Tuple[str, int]]:
    # Probable ports for Tor to listen at
    candidates = [
        ("127.0.0.1", 9050),
        ("127.0.0.1", 9150),
    ]
    for net_addr in candidates:
        if is_tor_socks_port(*net_addr):
            return net_addr
    return None


def is_tor_socks_port(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=10) as s:
            # mimic "tor-resolve 0.0.0.0".
            # see https://github.com/spesmilo/electrum/issues/7317#issuecomment-1369281075
            # > this is a socks5 handshake, followed by a socks RESOLVE request as defined in
            # > [tor's socks extension spec](https://github.com/torproject/torspec/blob/7116c9cdaba248aae07a3f1d0e15d9dd102f62c5/socks-extensions.txt#L63),
            # > resolving 0.0.0.0, which being an IP, tor resolves itself without needing to ask a relay.
            s.send(b'\x05\x01\x00\x05\xf0\x00\x03\x070.0.0.0\x00\x00')
            if s.recv(1024) == b'\x05\x00\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00':
                return True
    except socket.error:
        pass
    return False


AS_LIB_USER_I_WANT_TO_MANAGE_MY_OWN_ASYNCIO_LOOP = False  # used by unit tests

_asyncio_event_loop = None  # type: Optional[asyncio.AbstractEventLoop]
def get_asyncio_loop() -> asyncio.AbstractEventLoop:
    """Returns the global asyncio event loop we use."""
    if loop := _asyncio_event_loop:
        return loop
    if AS_LIB_USER_I_WANT_TO_MANAGE_MY_OWN_ASYNCIO_LOOP:
        if loop := get_running_loop():
            return loop
    raise Exception("event loop not created yet")


def create_and_start_event_loop() -> Tuple[asyncio.AbstractEventLoop,
                                           asyncio.Future,
                                           threading.Thread]:
    global _asyncio_event_loop
    if _asyncio_event_loop is not None:
        raise Exception("there is already a running event loop")

    # asyncio.get_event_loop() became deprecated in python3.10. (see https://github.com/python/cpython/issues/83710)
    # We set a custom event loop policy purely to be compatible with code that
    # relies on asyncio.get_event_loop().
    # - in python 3.8-3.9, asyncio.Event.__init__, asyncio.Lock.__init__,
    #   and similar, calls get_event_loop. see https://github.com/python/cpython/pull/23420
    class MyEventLoopPolicy(asyncio.DefaultEventLoopPolicy):
        def get_event_loop(self):
            # In case electrum is being used as a library, there might be other
            # event loops in use besides ours. To minimise interfering with those,
            # if there is a loop running in the current thread, return that:
            running_loop = get_running_loop()
            if running_loop is not None:
                return running_loop
            # Otherwise, return our global loop:
            return get_asyncio_loop()
    asyncio.set_event_loop_policy(MyEventLoopPolicy())

    loop = asyncio.new_event_loop()
    _asyncio_event_loop = loop

    def on_exception(loop, context):
        """Suppress spurious messages it appears we cannot control."""
        SUPPRESS_MESSAGE_REGEX = re.compile('SSL handshake|Fatal read error on|'
                                            'SSL error in data received')
        message = context.get('message')
        if message and SUPPRESS_MESSAGE_REGEX.match(message):
            return
        loop.default_exception_handler(context)

    def run_event_loop():
        try:
            loop.run_until_complete(stopping_fut)
        finally:
            # clean-up
            global _asyncio_event_loop
            _asyncio_event_loop = None

    loop.set_exception_handler(on_exception)
    # loop.set_debug(True)
    stopping_fut = loop.create_future()
    loop_thread = threading.Thread(
        target=run_event_loop,
        name='EventLoop',
    )
    loop_thread.start()
    # Wait until the loop actually starts.
    # On a slow PC, or with a debugger attached, this can take a few dozens of ms,
    # and if we returned without a running loop, weird things can happen...
    t0 = time.monotonic()
    while not loop.is_running():
        time.sleep(0.01)
        if time.monotonic() - t0 > 5:
            raise Exception("been waiting for 5 seconds but asyncio loop would not start!")
    return loop, stopping_fut, loop_thread


class OrderedDictWithIndex(OrderedDict):
    """An OrderedDict that keeps track of the positions of keys.

    Note: very inefficient to modify contents, except to add new items.
    """

    def __init__(self):
        super().__init__()
        self._key_to_pos = {}
        self._pos_to_key = {}

    def _recalc_index(self):
        self._key_to_pos = {key: pos for (pos, key) in enumerate(self.keys())}
        self._pos_to_key = {pos: key for (pos, key) in enumerate(self.keys())}

    def pos_from_key(self, key):
        return self._key_to_pos[key]

    def value_from_pos(self, pos):
        key = self._pos_to_key[pos]
        return self[key]

    def popitem(self, *args, **kwargs):
        ret = super().popitem(*args, **kwargs)
        self._recalc_index()
        return ret

    def move_to_end(self, *args, **kwargs):
        ret = super().move_to_end(*args, **kwargs)
        self._recalc_index()
        return ret

    def clear(self):
        ret = super().clear()
        self._recalc_index()
        return ret

    def pop(self, *args, **kwargs):
        ret = super().pop(*args, **kwargs)
        self._recalc_index()
        return ret

    def update(self, *args, **kwargs):
        ret = super().update(*args, **kwargs)
        self._recalc_index()
        return ret

    def __delitem__(self, *args, **kwargs):
        ret = super().__delitem__(*args, **kwargs)
        self._recalc_index()
        return ret

    def __setitem__(self, key, *args, **kwargs):
        is_new_key = key not in self
        ret = super().__setitem__(key, *args, **kwargs)
        if is_new_key:
            pos = len(self) - 1
            self._key_to_pos[key] = pos
            self._pos_to_key[pos] = key
        return ret


def multisig_type(wallet_type):
    '''If wallet_type is mofn multi-sig, return [m, n],
    otherwise return None.'''
    if not wallet_type:
        return None
    match = re.match(r'(\d+)of(\d+)', wallet_type)
    if match:
        match = [int(x) for x in match.group(1, 2)]
    return match


def is_ip_address(x: Union[str, bytes]) -> bool:
    if isinstance(x, bytes):
        x = x.decode("utf-8")
    try:
        ipaddress.ip_address(x)
        return True
    except ValueError:
        return False


def is_localhost(host: str) -> bool:
    if str(host) in ('localhost', 'localhost.',):
        return True
    if host[0] == '[' and host[-1] == ']':  # IPv6
        host = host[1:-1]
    try:
        ip_addr = ipaddress.ip_address(host)  # type: Union[IPv4Address, IPv6Address]
        return ip_addr.is_loopback
    except ValueError:
        pass  # not an IP
    return False


def is_private_netaddress(host: str) -> bool:
    if is_localhost(host):
        return True
    if host[0] == '[' and host[-1] == ']':  # IPv6
        host = host[1:-1]
    try:
        ip_addr = ipaddress.ip_address(host)  # type: Union[IPv4Address, IPv6Address]
        return ip_addr.is_private
    except ValueError:
        pass  # not an IP
    return False


def list_enabled_bits(x: int) -> Sequence[int]:
    """e.g. 77 (0b1001101) --> (0, 2, 3, 6)"""
    binary = bin(x)[2:]
    rev_bin = reversed(binary)
    return tuple(i for i, b in enumerate(rev_bin) if b == '1')


def resolve_dns_srv(host: str):
    # FIXME this method is not using the network proxy. (although the proxy might not support UDP?)
    srv_records = dns.resolver.resolve(host, 'SRV')
    # priority: prefer lower
    # weight: tie breaker; prefer higher
    srv_records = sorted(srv_records, key=lambda x: (x.priority, -x.weight))

    def dict_from_srv_record(srv):
        return {
            'host': str(srv.target),
            'port': srv.port,
        }
    return [dict_from_srv_record(srv) for srv in srv_records]


def randrange(bound: int) -> int:
    """Return a random integer k such that 1 <= k < bound, uniformly
    distributed across that range.
    This is guaranteed to be cryptographically strong.
    """
    # secrets.randbelow(bound) returns a random int: 0 <= r < bound,
    # hence transformations:
    return secrets.randbelow(bound - 1) + 1


class CallbackManager(Logger):
    # callbacks set by the GUI or any thread
    # guarantee: the callbacks will always get triggered from the asyncio thread.

    def __init__(self):
        Logger.__init__(self)
        self.callback_lock = threading.Lock()
        self.callbacks = defaultdict(list)      # note: needs self.callback_lock
        self._running_cb_futs = set()

    def register_callback(self, func, events):
        with self.callback_lock:
            for event in events:
                self.callbacks[event].append(func)

    def unregister_callback(self, callback):
        with self.callback_lock:
            for callbacks in self.callbacks.values():
                if callback in callbacks:
                    callbacks.remove(callback)

    def trigger_callback(self, event, *args):
        """Trigger a callback with given arguments.
        Can be called from any thread. The callback itself will get scheduled
        on the event loop.
        """
        loop = get_asyncio_loop()
        assert loop.is_running(), "event loop not running"
        with self.callback_lock:
            callbacks = self.callbacks[event][:]
        for callback in callbacks:
            if asyncio.iscoroutinefunction(callback):  # async cb
                fut = asyncio.run_coroutine_threadsafe(callback(*args), loop)
                # keep strong references around to avoid GC issues:
                self._running_cb_futs.add(fut)
                def on_done(fut_: concurrent.futures.Future):
                    assert fut_.done()
                    self._running_cb_futs.remove(fut_)
                    if fut_.cancelled():
                        self.logger.debug(f"cb cancelled. {event=}.")
                    elif exc := fut_.exception():
                        self.logger.error(f"cb errored. {event=}. {exc=}", exc_info=exc)
                fut.add_done_callback(on_done)
            else:  # non-async cb
                # note: the cb needs to run in the asyncio thread
                if get_running_loop() == loop:
                    # run callback immediately, so that it is guaranteed
                    # to have been executed when this method returns
                    callback(*args)
                else:
                    # note: if cb raises, asyncio will log the exception
                    loop.call_soon_threadsafe(callback, *args)


callback_mgr = CallbackManager()
trigger_callback = callback_mgr.trigger_callback
register_callback = callback_mgr.register_callback
unregister_callback = callback_mgr.unregister_callback
_event_listeners = defaultdict(set)  # type: Dict[str, Set[str]]


class EventListener:

    def _list_callbacks(self):
        for c in self.__class__.__mro__:
            classpath = f"{c.__module__}.{c.__name__}"
            for method_name in _event_listeners[classpath]:
                method = getattr(self, method_name)
                assert callable(method)
                assert method_name.startswith('on_event_')
                yield method_name[len('on_event_'):], method

    def register_callbacks(self):
        for name, method in self._list_callbacks():
            #_logger.debug(f'registering callback {method}')
            register_callback(method, [name])

    def unregister_callbacks(self):
        for name, method in self._list_callbacks():
            #_logger.debug(f'unregistering callback {method}')
            unregister_callback(method)


def event_listener(func):
    classname, method_name = func.__qualname__.split('.')
    assert method_name.startswith('on_event_')
    classpath = f"{func.__module__}.{classname}"
    _event_listeners[classpath].add(method_name)
    return func


_NetAddrType = TypeVar("_NetAddrType")
# requirements for _NetAddrType:
# - reasonable __hash__() implementation (e.g. based on host/port of remote endpoint)

class NetworkRetryManager(Generic[_NetAddrType]):
    """Truncated Exponential Backoff for network connections."""

    def __init__(
            self, *,
            max_retry_delay_normal: float,
            init_retry_delay_normal: float,
            max_retry_delay_urgent: float = None,
            init_retry_delay_urgent: float = None,
    ):
        self._last_tried_addr = {}  # type: Dict[_NetAddrType, Tuple[float, int]]  # (unix ts, num_attempts)

        # note: these all use "seconds" as unit
        if max_retry_delay_urgent is None:
            max_retry_delay_urgent = max_retry_delay_normal
        if init_retry_delay_urgent is None:
            init_retry_delay_urgent = init_retry_delay_normal
        self._max_retry_delay_normal = max_retry_delay_normal
        self._init_retry_delay_normal = init_retry_delay_normal
        self._max_retry_delay_urgent = max_retry_delay_urgent
        self._init_retry_delay_urgent = init_retry_delay_urgent

    def _trying_addr_now(self, addr: _NetAddrType) -> None:
        last_time, num_attempts = self._last_tried_addr.get(addr, (0, 0))
        # we add up to 1 second of noise to the time, so that clients are less likely
        # to get synchronised and bombard the remote in connection waves:
        cur_time = time.time() + random.random()
        self._last_tried_addr[addr] = cur_time, num_attempts + 1

    def _on_connection_successfully_established(self, addr: _NetAddrType) -> None:
        self._last_tried_addr[addr] = time.time(), 0

    def _can_retry_addr(self, addr: _NetAddrType, *,
                        now: float = None, urgent: bool = False) -> bool:
        if now is None:
            now = time.time()
        last_time, num_attempts = self._last_tried_addr.get(addr, (0, 0))
        if urgent:
            max_delay = self._max_retry_delay_urgent
            init_delay = self._init_retry_delay_urgent
        else:
            max_delay = self._max_retry_delay_normal
            init_delay = self._init_retry_delay_normal
        delay = self.__calc_delay(multiplier=init_delay, max_delay=max_delay, num_attempts=num_attempts)
        next_time = last_time + delay
        return next_time < now

    @classmethod
    def __calc_delay(cls, *, multiplier: float, max_delay: float,
                     num_attempts: int) -> float:
        num_attempts = min(num_attempts, 100_000)
        try:
            res = multiplier * 2 ** num_attempts
        except OverflowError:
            return max_delay
        return max(0, min(max_delay, res))

    def _clear_addr_retry_times(self) -> None:
        self._last_tried_addr.clear()


class MySocksProxy(aiorpcx.SOCKSProxy):
    # note: proxy will not leak DNS as create_connection()
    # sets (local DNS) resolve=False by default

    async def open_connection(self, host=None, port=None, **kwargs):
        loop = asyncio.get_running_loop()
        reader = asyncio.StreamReader(loop=loop)
        protocol = asyncio.StreamReaderProtocol(reader, loop=loop)
        transport, _ = await self.create_connection(
            lambda: protocol, host, port, **kwargs)
        writer = asyncio.StreamWriter(transport, protocol, reader, loop)
        return reader, writer

    @classmethod
    def from_proxy_dict(cls, proxy: dict = None) -> Optional['MySocksProxy']:
        if not proxy:
            return None
        username, pw = proxy.get('user'), proxy.get('password')
        if not username or not pw:
            auth = None
        else:
            auth = aiorpcx.socks.SOCKSUserAuth(username, pw)
        addr = aiorpcx.NetAddress(proxy['host'], proxy['port'])
        if proxy['mode'] == "socks4":
            ret = cls(addr, aiorpcx.socks.SOCKS4a, auth)
        elif proxy['mode'] == "socks5":
            ret = cls(addr, aiorpcx.socks.SOCKS5, auth)
        else:
            raise NotImplementedError  # http proxy not available with aiorpcx
        return ret


class JsonRPCError(Exception):

    class Codes(enum.IntEnum):
        # application-specific error codes
        USERFACING = 1
        INTERNAL = 2

    def __init__(self, *, code: int, message: str, data: Optional[dict] = None):
        Exception.__init__(self)
        self.code = code
        self.message = message
        self.data = data


class JsonRPCClient:

    def __init__(self, session: aiohttp.ClientSession, url: str):
        self.session = session
        self.url = url
        self._id = 0

    async def request(self, endpoint, *args):
        """Send request to server, parse and return result.
        note: parsing code is naive, the server is assumed to be well-behaved.
              Up to the caller to handle exceptions, including those arising from parsing errors.
        """
        self._id += 1
        data = ('{"jsonrpc": "2.0", "id":"%d", "method": "%s", "params": %s }'
                % (self._id, endpoint, json.dumps(args)))
        async with self.session.post(self.url, data=data) as resp:
            if resp.status == 200:
                r = await resp.json()
                result = r.get('result')
                error = r.get('error')
                if error:
                    raise JsonRPCError(code=error["code"], message=error["message"], data=error.get("data"))
                else:
                    return result
            else:
                text = await resp.text()
                return 'Error: ' + str(text)

    def add_method(self, endpoint):
        async def coro(*args):
            return await self.request(endpoint, *args)
        setattr(self, endpoint, coro)


T = TypeVar('T')

def random_shuffled_copy(x: Iterable[T]) -> List[T]:
    """Returns a shuffled copy of the input."""
    x_copy = list(x)  # copy
    random.shuffle(x_copy)  # shuffle in-place
    return x_copy


def test_read_write_permissions(path) -> None:
    # note: There might already be a file at 'path'.
    #       Make sure we do NOT overwrite/corrupt that!
    temp_path = "%s.tmptest.%s" % (path, os.getpid())
    echo = "fs r/w test"
    try:
        # test READ permissions for actual path
        if os.path.exists(path):
            with open(path, "rb") as f:
                f.read(1)  # read 1 byte
        # test R/W sanity for "similar" path
        with open(temp_path, "w", encoding='utf-8') as f:
            f.write(echo)
        with open(temp_path, "r", encoding='utf-8') as f:
            echo2 = f.read()
        os.remove(temp_path)
    except Exception as e:
        raise IOError(e) from e
    if echo != echo2:
        raise IOError('echo sanity-check failed')


class nullcontext:
    """Context manager that does no additional processing.
    This is a ~backport of contextlib.nullcontext from Python 3.10
    """

    def __init__(self, enter_result=None):
        self.enter_result = enter_result

    def __enter__(self):
        return self.enter_result

    def __exit__(self, *excinfo):
        pass

    async def __aenter__(self):
        return self.enter_result

    async def __aexit__(self, *excinfo):
        pass


def traceback_format_exception(exc: BaseException) -> Sequence[str]:
    """Compatibility wrapper for stdlib traceback.format_exception using python 3.10+ API."""
    if sys.version_info[:3] >= (3, 10):
        return traceback.format_exception(exc)
    else:
        return traceback.format_exception(type(exc), value=exc, tb=exc.__traceback__)


class classproperty(property):
    """~read-only class-level @property
    from https://stackoverflow.com/a/13624858 by denis-ryzhkov
    """
    def __get__(self, owner_self, owner_cls):
        return self.fget(owner_cls)


def get_running_loop() -> Optional[asyncio.AbstractEventLoop]:
    """Returns the asyncio event loop that is *running in this thread*, if any."""
    try:
        return asyncio.get_running_loop()
    except RuntimeError:
        return None


def error_text_str_to_safe_str(err: str, *, max_len: Optional[int] = 500) -> str:
    """Converts an untrusted error string to a sane printable ascii str.
    Never raises.
    """
    text = error_text_bytes_to_safe_str(
        err.encode("ascii", errors='backslashreplace'),
        max_len=None)
    return truncate_text(text, max_len=max_len)


def error_text_bytes_to_safe_str(err: bytes, *, max_len: Optional[int] = 500) -> str:
    """Converts an untrusted error bytes text to a sane printable ascii str.
    Never raises.

    Note that naive ascii conversion would be insufficient. Fun stuff:
    >>> b = b"my_long_prefix_blabla" + 21 * b"\x08" + b"malicious_stuff"
    >>> s = b.decode("ascii")
    >>> print(s)
    malicious_stuffblabla
    """
    # convert to ascii, to get rid of unicode stuff
    ascii_text = err.decode("ascii", errors='backslashreplace')
    # do repr to handle ascii special chars (especially when printing/logging the str)
    text = repr(ascii_text)
    return truncate_text(text, max_len=max_len)


def truncate_text(text: str, *, max_len: Optional[int]) -> str:
    if max_len is None or len(text) <= max_len:
        return text
    else:
        return text[:max_len] + f"... (truncated. orig_len={len(text)})"
