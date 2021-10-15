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
import os, sys, re, json
from collections import defaultdict, OrderedDict
from typing import (NamedTuple, Union, TYPE_CHECKING, Tuple, Optional, Callable, Any,
                    Sequence, Dict, Generic, TypeVar, List, Iterable, Set)
from datetime import datetime
import decimal
from decimal import Decimal
import traceback
import urllib
import threading
import hmac
import stat
from locale import localeconv
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
from abc import abstractmethod, ABC

import attr
import aiohttp
from aiohttp_socks import ProxyConnector, ProxyType
import aiorpcx
from aiorpcx import TaskGroup
import certifi
import dns.resolver

from .i18n import _
from .logging import get_logger, Logger

if TYPE_CHECKING:
    from .network import Network
    from .interface import Interface
    from .simple_config import SimpleConfig


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


class UneconomicFee(Exception):
    def __str__(self):
        return _("The fee for the transaction is higher than the funds gained from it.")


class NoDynamicFeeEstimates(Exception):
    def __str__(self):
        return _('Dynamic fee estimates not available')


class InvalidPassword(Exception):
    def __str__(self):
        return _("Incorrect password")


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


# note: this is not a NamedTuple as then its json encoding cannot be customized
class Satoshis(object):
    __slots__ = ('value',)

    def __new__(cls, value):
        self = super(Satoshis, cls).__new__(cls)
        # note: 'value' sometimes has msat precision
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
        from .lnutil import UpdateAddHtlc
        if isinstance(obj, UpdateAddHtlc):
            return obj.to_tuple()
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
        self.stopped_event = threading.Event()  # set when fully stopped

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

    def on_stop(self):
        if 'ANDROID_DATA' in os.environ:
            import jnius
            jnius.detach()
            self.logger.info("jnius detach")
        self.logger.info("stopped")
        self.stopped_event.set()


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


# decorator that prints execution time
_profiler_logger = _logger.getChild('profiler')
def profiler(func):
    def do_profile(args, kw_args):
        name = func.__qualname__
        t0 = time.time()
        o = func(*args, **kw_args)
        t = time.time() - t0
        _profiler_logger.debug(f"{name} {t:,.4f}")
        return o
    return lambda *args, **kw_args: do_profile(args, kw_args)


def android_ext_dir():
    from android.storage import primary_external_storage_path
    return primary_external_storage_path()

def android_backup_dir():
    d = os.path.join(android_ext_dir(), 'org.electrum.electrum')
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
    return os.path.normcase(
            os.path.realpath(
                os.path.abspath(
                    os.path.expanduser(
                        path
    ))))


def get_new_wallet_name(wallet_folder: str) -> str:
    i = 1
    while True:
        filename = "wallet_%d" % i
        if filename in os.listdir(wallet_folder):
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


def bh2u(x: bytes) -> str:
    """
    str with hex representation of a bytes-like object

    >>> x = bytes((1, 2, 10))
    >>> bh2u(x)
    '01020A'
    """
    return x.hex()


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
    except:
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

DECIMAL_POINT = localeconv()['decimal_point']  # type: str


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
        integer_part = "{:,}".format(int(integer_part)).replace(',', " ")
        integer_part = sign + integer_part
        fract_part = " ".join(fract_part[i:i+3] for i in range(0, len(fract_part), 3))
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


def timestamp_to_datetime(timestamp: Optional[int]) -> Optional[datetime]:
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

    if distance_in_minutes == 0:
        if include_seconds:
            return "%s seconds" % distance_in_seconds
        else:
            return "less than a minute"
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
    'Bitupper Explorer': ('https://bitupper.com/en/explorer/bitcoin/',
                        {'tx': 'transactions/', 'addr': 'addresses/'}),
    'Bitflyer.jp': ('https://chainflyer.bitflyer.jp/',
                        {'tx': 'Transaction/', 'addr': 'Address/'}),
    'Blockchain.info': ('https://blockchain.com/btc/',
                        {'tx': 'tx/', 'addr': 'address/'}),
    'blockchainbdgpzk.onion': ('https://blockchainbdgpzk.onion/',
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
    'TradeBlock.com': ('https://tradeblock.com/blockchain/',
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
    'smartbit.com.au': ('https://www.smartbit.com.au/',
                        {'tx': 'tx/', 'addr': 'address/'}),
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
    if config.get('block_explorer_custom') is not None:
        return None
    default_ = 'Blockstream.info'
    be_key = config.get('block_explorer', default_)
    be_tuple = block_explorer_info().get(be_key)
    if be_tuple is None:
        be_key = default_
    assert isinstance(be_key, str), f"{be_key!r} should be str"
    return be_key


def block_explorer_tuple(config: 'SimpleConfig') -> Optional[Tuple[str, dict]]:
    custom_be = config.get('block_explorer_custom')
    if custom_be:
        if isinstance(custom_be, str):
            return custom_be, _block_explorer_default_api_loc
        if isinstance(custom_be, (tuple, list)) and len(custom_be) == 2:
            return tuple(custom_be)
        _logger.warning(f"not using 'block_explorer_custom' from config. "
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

# URL decode
#_ud = re.compile('%([0-9a-hA-H]{2})', re.MULTILINE)
#urldecode = lambda x: _ud.sub(lambda m: chr(int(m.group(1), 16)), x)


# note: when checking against these, use .lower() to support case-insensitivity
BITCOIN_BIP21_URI_SCHEME = 'bitcoin'
LIGHTNING_URI_SCHEME = 'lightning'


class InvalidBitcoinURI(Exception): pass


# TODO rename to parse_bip21_uri or similar
def parse_URI(uri: str, on_pr: Callable = None, *, loop=None) -> dict:
    """Raises InvalidBitcoinURI on malformed URI."""
    from . import bitcoin
    from .bitcoin import COIN, TOTAL_COIN_SUPPLY_LIMIT_IN_BTC

    if not isinstance(uri, str):
        raise InvalidBitcoinURI(f"expected string, not {repr(uri)}")

    if ':' not in uri:
        if not bitcoin.is_address(uri):
            raise InvalidBitcoinURI("Not a bitcoin address")
        return {'address': uri}

    u = urllib.parse.urlparse(uri)
    if u.scheme.lower() != BITCOIN_BIP21_URI_SCHEME:
        raise InvalidBitcoinURI("Not a bitcoin URI")
    address = u.path

    # python for android fails to parse query
    if address.find('?') > 0:
        address, query = u.path.split('?')
        pq = urllib.parse.parse_qs(query)
    else:
        pq = urllib.parse.parse_qs(u.query)

    for k, v in pq.items():
        if len(v) != 1:
            raise InvalidBitcoinURI(f'Duplicate Key: {repr(k)}')

    out = {k: v[0] for k, v in pq.items()}
    if address:
        if not bitcoin.is_address(address):
            raise InvalidBitcoinURI(f"Invalid bitcoin address: {address}")
        out['address'] = address
    if 'amount' in out:
        am = out['amount']
        try:
            m = re.match(r'([0-9.]+)X([0-9])', am)
            if m:
                k = int(m.group(2)) - 8
                amount = Decimal(m.group(1)) * pow(Decimal(10), k)
            else:
                amount = Decimal(am) * COIN
            if amount > TOTAL_COIN_SUPPLY_LIMIT_IN_BTC * COIN:
                raise InvalidBitcoinURI(f"amount is out-of-bounds: {amount!r} BTC")
            out['amount'] = int(amount)
        except Exception as e:
            raise InvalidBitcoinURI(f"failed to parse 'amount' field: {repr(e)}") from e
    if 'message' in out:
        out['message'] = out['message']
        out['memo'] = out['message']
    if 'time' in out:
        try:
            out['time'] = int(out['time'])
        except Exception as e:
            raise InvalidBitcoinURI(f"failed to parse 'time' field: {repr(e)}") from e
    if 'exp' in out:
        try:
            out['exp'] = int(out['exp'])
        except Exception as e:
            raise InvalidBitcoinURI(f"failed to parse 'exp' field: {repr(e)}") from e
    if 'sig' in out:
        try:
            out['sig'] = bh2u(bitcoin.base_decode(out['sig'], base=58))
        except Exception as e:
            raise InvalidBitcoinURI(f"failed to parse 'sig' field: {repr(e)}") from e

    r = out.get('r')
    sig = out.get('sig')
    name = out.get('name')
    if on_pr and (r or (name and sig)):
        @log_exceptions
        async def get_payment_request():
            from . import paymentrequest as pr
            if name and sig:
                s = pr.serialize_request(out).SerializeToString()
                request = pr.PaymentRequest(s)
            else:
                request = await pr.get_payment_request(r)
            if on_pr:
                on_pr(request)
        loop = loop or asyncio.get_event_loop()
        asyncio.run_coroutine_threadsafe(get_payment_request(), loop)

    return out


def create_bip21_uri(addr, amount_sat: Optional[int], message: Optional[str],
                     *, extra_query_params: Optional[dict] = None) -> str:
    from . import bitcoin
    if not bitcoin.is_address(addr):
        return ""
    if extra_query_params is None:
        extra_query_params = {}
    query = []
    if amount_sat:
        query.append('amount=%s'%format_satoshis_plain(amount_sat))
    if message:
        query.append('message=%s'%urllib.parse.quote(message))
    for k, v in extra_query_params.items():
        if not isinstance(k, str) or k != urllib.parse.quote(k):
            raise Exception(f"illegal key for URI: {repr(k)}")
        v = urllib.parse.quote(v)
        query.append(f"{k}={v}")
    p = urllib.parse.ParseResult(
        scheme=BITCOIN_BIP21_URI_SCHEME,
        netloc='',
        path=addr,
        params='',
        query='&'.join(query),
        fragment='',
    )
    return str(urllib.parse.urlunparse(p))


def maybe_extract_bolt11_invoice(data: str) -> Optional[str]:
    data = data.strip()  # whitespaces
    data = data.lower()
    if data.startswith(LIGHTNING_URI_SCHEME + ':ln'):
        data = data[10:]
    if data.startswith('ln'):
        return data
    return None


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
    except:
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
    #backwards compatibility for JSONDecodeError
    except ValueError:
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


def make_dir(path, allow_symlink=True):
    """Make directory if it does not yet exist."""
    if not os.path.exists(path):
        if not allow_symlink and os.path.islink(path):
            raise Exception('Dangling link: ' + path)
        os.mkdir(path)
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)


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
        except asyncio.CancelledError:
            # note: with python 3.8, CancelledError no longer inherits Exception, so this catch is redundant
            raise
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
    conf: Optional[int] = None         # number of confirmations, SPV verified (None means unknown)
    timestamp: Optional[int] = None    # timestamp of block that mined tx
    txpos: Optional[int] = None        # position of tx in serialized block
    header_hash: Optional[str] = None  # hash of block that mined tx


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
            rdns=True,
            ssl=ssl_context,
        )
    else:
        connector = aiohttp.TCPConnector(ssl=ssl_context)

    return aiohttp.ClientSession(headers=headers, timeout=timeout, connector=connector)


class SilentTaskGroup(TaskGroup):

    def spawn(self, *args, **kwargs):
        # don't complain if group is already closed.
        if self._closed:
            raise asyncio.CancelledError()
        return super().spawn(*args, **kwargs)


class NetworkJobOnDefaultServer(Logger, ABC):
    """An abstract base class for a job that runs on the main network
    interface. Every time the main interface changes, the job is
    restarted, and some of its internals are reset.
    """
    def __init__(self, network: 'Network'):
        Logger.__init__(self)
        asyncio.set_event_loop(network.asyncio_loop)
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
        self.taskgroup = SilentTaskGroup()

    async def _start(self, interface: 'Interface'):
        self.interface = interface
        await interface.taskgroup.spawn(self._run_tasks(taskgroup=self.taskgroup))

    @abstractmethod
    async def _run_tasks(self, *, taskgroup: TaskGroup) -> None:
        """Start tasks in taskgroup. Called every time the underlying
        server connection changes.
        """
        # If self.taskgroup changed, don't start tasks. This can happen if we have
        # been restarted *just now*, i.e. after the _run_tasks coroutine object was created.
        if taskgroup != self.taskgroup:
            raise asyncio.CancelledError()

    async def stop(self, *, full_shutdown: bool = True):
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

    @property
    def session(self):
        s = self.interface.session
        assert s is not None
        return s


def create_and_start_event_loop() -> Tuple[asyncio.AbstractEventLoop,
                                           asyncio.Future,
                                           threading.Thread]:
    def on_exception(loop, context):
        """Suppress spurious messages it appears we cannot control."""
        SUPPRESS_MESSAGE_REGEX = re.compile('SSL handshake|Fatal read error on|'
                                            'SSL error in data received')
        message = context.get('message')
        if message and SUPPRESS_MESSAGE_REGEX.match(message):
            return
        loop.default_exception_handler(context)

    loop = asyncio.get_event_loop()
    loop.set_exception_handler(on_exception)
    # loop.set_debug(1)
    stopping_fut = loop.create_future()
    loop_thread = threading.Thread(target=loop.run_until_complete,
                                         args=(stopping_fut,),
                                         name='EventLoop')
    loop_thread.start()
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


def is_private_netaddress(host: str) -> bool:
    if str(host) in ('localhost', 'localhost.',):
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
    distributed across that range."""
    # secrets.randbelow(bound) returns a random int: 0 <= r < bound,
    # hence transformations:
    return secrets.randbelow(bound - 1) + 1


class CallbackManager:
    # callbacks set by the GUI or any thread
    # guarantee: the callbacks will always get triggered from the asyncio thread.

    def __init__(self):
        self.callback_lock = threading.Lock()
        self.callbacks = defaultdict(list)      # note: needs self.callback_lock
        self.asyncio_loop = None

    def register_callback(self, callback, events):
        with self.callback_lock:
            for event in events:
                self.callbacks[event].append(callback)

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
        if self.asyncio_loop is None:
            self.asyncio_loop = asyncio.get_event_loop()
            assert self.asyncio_loop.is_running(), "event loop not running"
        with self.callback_lock:
            callbacks = self.callbacks[event][:]
        for callback in callbacks:
            # FIXME: if callback throws, we will lose the traceback
            if asyncio.iscoroutinefunction(callback):
                asyncio.run_coroutine_threadsafe(callback(event, *args), self.asyncio_loop)
            else:
                self.asyncio_loop.call_soon_threadsafe(callback, event, *args)


callback_mgr = CallbackManager()
trigger_callback = callback_mgr.trigger_callback
register_callback = callback_mgr.register_callback
unregister_callback = callback_mgr.unregister_callback


_NetAddrType = TypeVar("_NetAddrType")


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

    async def open_connection(self, host=None, port=None, **kwargs):
        loop = asyncio.get_event_loop()
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


class JsonRPCClient:

    def __init__(self, session: aiohttp.ClientSession, url: str):
        self.session = session
        self.url = url
        self._id = 0

    async def request(self, endpoint, *args):
        self._id += 1
        data = ('{"jsonrpc": "2.0", "id":"%d", "method": "%s", "params": %s }'
                % (self._id, endpoint, json.dumps(args)))
        async with self.session.post(self.url, data=data) as resp:
            if resp.status == 200:
                r = await resp.json()
                result = r.get('result')
                error = r.get('error')
                if error:
                    return 'Error: ' + str(error)
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

def get_running_loop():
    """Mimics _get_running_loop convenient functionality for sanity checks on all python versions"""
    if sys.version_info < (3, 7):
        return asyncio._get_running_loop()
    try:
        return asyncio.get_running_loop()
    except RuntimeError:
        return None
