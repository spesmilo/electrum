# Copyright (C) 2019 The Electrum developers
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://www.opensource.org/licenses/mit-license.php

import ast
import hmac
import ipaddress
import logging
import logging.handlers
import datetime
from functools import lru_cache
import sys
import pathlib
import os
import platform as py_platform
import re
from typing import Optional, TYPE_CHECKING, Set, Iterable, List, Callable
import copy
import subprocess
import hashlib

from electrum import platform

if TYPE_CHECKING:
    from .simple_config import SimpleConfig
    from .wallet import Abstract_Wallet


class LogFormatterForFiles(logging.Formatter):

    def formatTime(self, record, datefmt=None):
        # timestamps follow ISO 8601 UTC
        date = datetime.datetime.fromtimestamp(record.created).astimezone(datetime.timezone.utc)
        if not datefmt:
            datefmt = "%Y%m%dT%H%M%S.%fZ"
        return date.strftime(datefmt)

    def format(self, record):
        record = _shorten_name_of_logrecord(record)
        return super().format(record)


file_formatter = LogFormatterForFiles(fmt="%(asctime)22s | %(levelname)8s | %(name)s | %(message)s")


class LogFormatterForConsole(logging.Formatter):

    def formatTime(self, record, datefmt=None):
        t = record.relativeCreated / 1000
        return f"{t:6.2f}"

    def format(self, record):
        record = copy.copy(record)  # avoid mutating arg
        record = _shorten_name_of_logrecord(record)
        text = super().format(record)
        return text


# try to make console log lines short... no timestamp, short levelname, no "electrum."
console_formatter = LogFormatterForConsole(fmt="%(asctime)s | %(levelname).1s | %(name)s | %(message)s")


def _shorten_name_of_logrecord(record: logging.LogRecord) -> logging.LogRecord:
    record = copy.copy(record)  # avoid mutating arg
    # strip the main module name from the logger name
    if record.name.startswith("electrum."):
        record.name = record.name[9:]
    # manual map to shorten common module names
    record.name = record.name.replace("interface.Interface", "interface", 1)
    record.name = record.name.replace("network.Network", "network", 1)
    record.name = record.name.replace("synchronizer.Synchronizer", "synchronizer", 1)
    record.name = record.name.replace("verifier.SPV", "verifier", 1)
    record.name = record.name.replace("gui.qt.main_window.ElectrumWindow", "gui.qt.main_window", 1)
    return record


class TruncatingMemoryHandler(logging.handlers.MemoryHandler):
    """An in-memory log handler that only keeps the first N log messages
    and discards the rest.
    """
    target: Optional['logging.Handler']

    def __init__(self):
        logging.handlers.MemoryHandler.__init__(
            self,
            capacity=1,  # note: this is the flushing frequency, ~unused by us
            flushLevel=logging.DEBUG,
        )
        self.max_size = 100  # max num of messages we keep
        self.num_messages_seen = 0
        self.__never_dumped = True

    # note: this flush implementation *keeps* the buffer as-is, instead of clearing it
    def flush(self):
        self.acquire()
        try:
            if self.target:
                for record in self.buffer:
                    if record.levelno >= self.target.level:
                        self.target.handle(record)
        finally:
            self.release()

    def dump_to_target(self, target: 'logging.Handler'):
        self.acquire()
        try:
            self.setTarget(target)
            self.flush()
            self.setTarget(None)
        finally:
            self.__never_dumped = False
            self.release()

    def emit(self, record):
        self.num_messages_seen += 1
        if len(self.buffer) < self.max_size:
            super().emit(record)

    def close(self) -> None:
        # Check if captured log lines were never to dumped to e.g. stderr,
        # and if so, try to do it now. This is useful e.g. in case of sys.exit().
        if self.__never_dumped:
            _configure_stderr_logging()
        super().close()


def _sortkey_of_log_file_oldest_first(p: pathlib.PurePath):
    fname = p.name
    basename, ext, counter = str(fname).partition(".log")
    # - each time electrum is launched, there will be a new basename, ordered by date
    # - for any given basename, there might be multiple log files, differing by counter
    #   - empty counter is newest, then .1 is older, .2 is even older, etc
    try:
        counter = int(counter[1:]) if counter else 0  # convert ".2" -> 2
    except ValueError:
        _logger.warning(f"failed to parse log file name: {fname}")
        counter = 0
    return basename, -counter


def _log_files_oldest_first(path) -> List[pathlib.Path]:
    return sorted(pathlib.Path(path).glob("electrum_log_*.log*"), key=_sortkey_of_log_file_oldest_first)


def _delete_old_logs(path, *, num_files_keep: int, max_total_size: int):
    """Delete old logfiles, only keeping the latest few."""
    files = _log_files_oldest_first(path)
    total_size = sum(os.stat(f).st_size for f in files)  # in bytes
    num_files_remaining = len(files)
    for f in files:
        fsize = os.stat(f).st_size
        if total_size < max_total_size and num_files_remaining <= num_files_keep:
            break
        total_size -= fsize
        num_files_remaining -= 1
        try:
            os.remove(f)
        except OSError as e:
            _logger.warning(f"cannot delete old logfile: {e}")


_logfile_path = None
_file_handler = None  # type: Optional[logging.Handler]
def _configure_file_logging(
    log_directory: pathlib.Path,
    *,
    num_files_keep: int,
    max_total_size: int,
):
    from .util import os_chmod

    global _logfile_path, _file_handler
    assert _logfile_path is None, 'file logging already initialized'
    log_directory.mkdir(exist_ok=True, mode=0o700)

    _delete_old_logs(log_directory, num_files_keep=num_files_keep, max_total_size=max_total_size)

    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    PID = os.getpid()
    _logfile_path = log_directory / f"electrum_log_{timestamp}_{PID}.log"
    num = 1
    while _logfile_path.exists():  # file logging got switched off and on again within the second
        _logfile_path = log_directory / f"electrum_log_{timestamp}_{PID}_{num}.log"
        num += 1
    # we create the file with restrictive perms, instead of letting FileHandler create it
    with open(_logfile_path, "w+") as f:
        os_chmod(_logfile_path, 0o600)

    logfile_backupcount = 4
    file_handler = logging.handlers.RotatingFileHandler(
        _logfile_path,
        maxBytes=max_total_size // (logfile_backupcount+1),
        backupCount=logfile_backupcount,
        encoding='utf-8')
    file_handler.setFormatter(file_formatter)
    file_handler.setLevel(logging.DEBUG)
    root_logger.addHandler(file_handler)
    _file_handler = file_handler
    if _inmemory_startup_logs:
        _inmemory_startup_logs.dump_to_target(file_handler)


console_stderr_handler = None
def _configure_stderr_logging(*, verbosity=None):
    # log to stderr; by default only WARNING and higher
    global console_stderr_handler
    if console_stderr_handler is not None:
        _logger.warning("stderr handler already exists")
        return
    console_stderr_handler = logging.StreamHandler(sys.stderr)
    console_stderr_handler.setFormatter(console_formatter)
    if not verbosity:
        console_stderr_handler.setLevel(logging.WARNING)
        root_logger.addHandler(console_stderr_handler)
    else:
        console_stderr_handler.setLevel(logging.DEBUG)
        root_logger.addHandler(console_stderr_handler)
        _process_verbosity_log_levels(verbosity)
    if _inmemory_startup_logs:
        _inmemory_startup_logs.dump_to_target(console_stderr_handler)


def _process_verbosity_log_levels(verbosity):
    if verbosity == '*' or not isinstance(verbosity, str):
        return
    # example verbosity:
    #   debug,network=error,interface=error      // effectively blacklists network and interface
    #   warning,network=debug,interface=debug    // effectively whitelists network and interface
    filters = verbosity.split(',')
    for filt in filters:
        if not filt: continue
        items = filt.split('=')
        if len(items) == 1:
            level = items[0]
            electrum_logger.setLevel(level.upper())
        elif len(items) == 2:
            logger_name, level = items
            logger = get_logger(logger_name)
            logger.setLevel(level.upper())
        else:
            raise Exception(f"invalid log filter: {filt}")


class _CustomLogger(logging.getLoggerClass()):
    def __init__(self, name, *args, **kwargs):
        super().__init__(name, *args, **kwargs)
        self.msg_hashes_seen = set()  # type: Set[bytes]
        # ^ note: size grows without bounds, but only for log lines using "only_once".

    def _log(self, level, msg: str, *args, only_once: bool = False, **kwargs) -> None:
        """Overridden to add 'only_once' arg to logger.debug()/logger.info()/logger.warning()/etc."""
        if only_once:  # if set, this logger will only log this msg a single time during its lifecycle
            msg_hash = hashlib.sha256(msg.encode("utf-8")).digest()
            if msg_hash in self.msg_hashes_seen:
                return
            self.msg_hashes_seen.add(msg_hash)
        super()._log(level, msg, *args, **kwargs)

logging.setLoggerClass(_CustomLogger)


# enable logs universally (including for other libraries)
root_logger = logging.getLogger()
root_logger.setLevel(logging.WARNING)

# Start collecting log messages now, into an in-memory buffer. This buffer is only
# used until the proper log handlers are fully configured, including their verbosity,
# at which point we will dump its contents into those, and remove this log handler.
# Note: this is set up at import-time instead of e.g. as part of a function that is
#       called from run_electrum (the main script). This is to have this run as early
#       as possible.
# Note: some users might use Electrum as a python library and not use run_electrum,
#       in which case these logs might never get redirected or cleaned up.
#       Also, the python docs recommend libraries not to set a handler, to
#       avoid interfering with the user's logging.
_inmemory_startup_logs = None
if getattr(sys, "_ELECTRUM_RUNNING_VIA_RUNELECTRUM", False):
    _inmemory_startup_logs = TruncatingMemoryHandler()
    root_logger.addHandler(_inmemory_startup_logs)

# creates a logger specifically for electrum library
electrum_logger = logging.getLogger("electrum")
electrum_logger.setLevel(logging.DEBUG)


# --- External API

def get_logger(name: str) -> _CustomLogger:
    prefix = "electrum."
    if name.startswith(prefix):
        name = name[len(prefix):]
    return electrum_logger.getChild(name)


_logger = get_logger(__name__)
_logger.setLevel(logging.INFO)


class Logger:

    def __init__(self):
        self.logger = self.__get_logger_for_obj()

    def __get_logger_for_obj(self) -> logging.Logger:
        cls = self.__class__
        if cls.__module__:
            name = f"{cls.__module__}.{cls.__name__}"
        else:
            name = cls.__name__
        try:
            diag_name = self.diagnostic_name()
        except Exception as e:
            raise Exception("diagnostic name not yet available?") from e
        if diag_name:
            name += f".[{diag_name}]"
        logger = get_logger(name)
        return logger

    def diagnostic_name(self):
        return ''


def configure_logging(config: 'SimpleConfig', *, log_to_file: Optional[bool] = None) -> None:
    from .util import is_android_debug_apk

    verbosity = config.get('verbosity')
    if not verbosity and config.GUI_ENABLE_DEBUG_LOGS:
        verbosity = '*'
    _configure_stderr_logging(verbosity=verbosity)

    if log_to_file is None:
        log_to_file = config.WRITE_LOGS_TO_DISK
        log_to_file |= is_android_debug_apk()
    if log_to_file:
        log_directory = pathlib.Path(config.path) / "logs"
        num_files_keep = config.LOGS_NUM_FILES_KEEP
        max_total_size = config.LOGS_MAX_TOTAL_SIZE_BYTES
        _configure_file_logging(log_directory, num_files_keep=num_files_keep, max_total_size=max_total_size)

    # clean up and delete in-memory logs
    global _inmemory_startup_logs
    if _inmemory_startup_logs:
        num_discarded = _inmemory_startup_logs.num_messages_seen - _inmemory_startup_logs.max_size
        if num_discarded > 0:
            _logger.warning(f"Too many log messages! Some have been discarded. "
                            f"(discarded {num_discarded} messages)")
        _inmemory_startup_logs.close()
        root_logger.removeHandler(_inmemory_startup_logs)
        _inmemory_startup_logs = None

    _log_versions()
    _logger.info(f"Logging to file: {str(_logfile_path)}")
    _logger.info(f"Log filters: verbosity {repr(verbosity)}")


def _log_versions() -> None:
    from . import ELECTRUM_VERSION
    from .constants import GIT_REPO_URL
    _logger.info(f"Electrum version: {ELECTRUM_VERSION} - https://electrum.org - {GIT_REPO_URL}")
    _logger.info(f"Python version: {sys.version}. On platform: {describe_os_version()}")


def get_logfile_path() -> Optional[pathlib.Path]:
    return _logfile_path


def set_file_logging(config: 'SimpleConfig', enabled: bool) -> None:
    """Starts or stops writing the logs to files, while running. (configure_logging does it at startup)"""
    from .util import is_android_debug_apk
    global _logfile_path, _file_handler
    if enabled and _logfile_path is None:
        _configure_file_logging(
            pathlib.Path(config.path) / "logs",
            num_files_keep=config.LOGS_NUM_FILES_KEEP,
            max_total_size=config.LOGS_MAX_TOTAL_SIZE_BYTES)
        _logger.info(f"Logging to file: {str(_logfile_path)}")
        _log_versions()  # (at the start of each log file)
    elif not enabled and _file_handler is not None and not is_android_debug_apk():
        _logger.info("Logging to file stops")
        root_logger.removeHandler(_file_handler)
        _file_handler.close()
        _file_handler = None
        _logfile_path = None


def read_recent_logs(config: 'SimpleConfig', *, max_size: int) -> str:
    """Returns the end of the newest log files, oldest first: at most max_size bytes, starting at a whole line."""
    parts = []  # newest first
    size = 0
    starts_mid_line = False  # whether the oldest part we read starts in the middle of a line
    for path in reversed(_log_files_oldest_first(pathlib.Path(config.path) / "logs")):
        if size >= max_size:
            break
        try:
            with open(path, 'rb') as f:
                start = max(0, os.path.getsize(path) - (max_size - size))
                f.seek(max(0, start - 1))
                data = f.read(max_size - size + (1 if start else 0))
        except OSError:
            continue
        if start:
            # (the byte before tells whether we start at a whole line)
            starts_mid_line, data = data[:1] != b'\n', data[1:]
        else:
            starts_mid_line = False
        if data and not data.endswith(b'\n'):
            data += b'\n'  # the file got cut, e.g. as we were killed while writing it
        parts.append(data)
        size += len(data)
    text = b''.join(reversed(parts)).decode('utf-8', 'replace')
    if starts_mid_line:
        text = text[text.find('\n') + 1:]
    return text


# The logs that a user may send to the developers keep only what is about Lightning payments and the network
# graph: the loggers of these modules. Others print transactions, PSBTs, addresses, labels and the like.
SHARED_LOG_SOURCES = (
    'lnworker', 'lnrouter', 'lnpeer', 'channel_db', 'gossip_catch_up', 'trampoline', 'lnverifier', 'lnonion',
    'mpp_split', 'lnutil',
    'logging',  # the version of Electrum and of the OS
)
_LOG_ENTRY_HEAD = re.compile(r'^\d{8}T\d{6}\.\d+Z \|\s*\w+ \| ([^.| \[]+)')


def filter_log_for_sharing(text: str) -> str:
    """Keeps the entries of the log written by SHARED_LOG_SOURCES, with the lines that continue them."""
    kept = []
    keep = False
    for line in text.splitlines(keepends=True):
        if m := _LOG_ENTRY_HEAD.match(line):
            keep = m.group(1) in SHARED_LOG_SOURCES
        if keep:
            kept.append(line)
    return ''.join(kept)


class _LogRedactor:
    """Replaces what identifies the user's coins, payments, channels and peers in log text by labels like
    <hash 3fa9c1d2>: an HMAC of the value with a secret key. The same value gets the same label, so what
    refers to the same thing can still be told, but the value cannot be got back from the label, nor found
    by trying the values one knows (like the public nodes of the network), without the key."""

    _BECH32 = '02-9ac-hj-np-z'
    _BYTES = re.compile(r"""\bb(?:'(?:[^'\\\n]|\\.)*'|"(?:[^"\\\n]|\\.)*")""")
    _RULES = (  # (kind, pattern, group to replace or 0). order matters
        ('invoice', re.compile(rf'\b(?:lightning:)?ln(?:bc|tbs|tb|bcrt|sb)[0-9]*[munp]?1[{_BECH32}]{{20,}}', re.I), 0),
        ('invoice', re.compile(rf'\b(?:lightning:)?ln[oir]1[{_BECH32}]{{20,}}', re.I), 0),
        ('lnurl', re.compile(rf'\b(?:lightning:)?lnurl1[{_BECH32}]{{20,}}', re.I), 0),
        ('address', re.compile(rf'\b(?:bc|tb|bcrt)1[{_BECH32}]{{8,87}}\b', re.I), 0),
        ('key', re.compile(r'\b[xyztuvYZUV](?:pub|prv)[1-9A-HJ-NP-Za-km-z]{100,}'), 0),
        ('key', re.compile(r'\b[5KLc9][1-9A-HJ-NP-Za-km-z]{50,51}\b'), 0),  # WIF
        ('address', re.compile(r'\b[13mn2][1-9A-HJ-NP-Za-km-z]{25,34}\b'), 0),
        ('onion', re.compile(r'\b[a-z2-7]{56}\.onion\b', re.I), 0),
        ('channel in hex', re.compile(r'(?<![0-9a-fA-F])([0-9a-f]{16}):\d'), 1),  # the key of an htlc
        ('host', re.compile(r'@([A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*\.?):\d'), 1),  # of a peer: node_id@host:port
        ('host', re.compile(r'failed to connect ([^\s<]+) '), 1),
        ('node', re.compile(r'(?<![0-9a-fA-F])0[23][0-9a-fA-F]{64}(?![0-9a-fA-F])'), 0),
        # 20 bytes or more in hex: hashes, secrets, txids, channel ids, scripts, transactions
        ('hash', re.compile(r'(?<![0-9a-fA-F])[0-9a-fA-F]{40,}(?![0-9a-fA-F])'), 0),
        ('data', re.compile(r'(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=])'), 0),  # base64
        # the start of node ids, as routes and peers are logged
        ('node', re.compile(r'(?<![0-9A-Za-z])0[23][0-9a-f]{8}(?![0-9A-Za-z])'), 0),
        ('node', re.compile(r'(?:peers \(msgs/s, old updates\): |, )(0[23][0-9a-f]{4})(?= )'), 1),
        ('channel', re.compile(r'(?<![\w.])\d+x\d+x\d+(?!\w)'), 0),
        ('ip', re.compile(r'(?<![\w.:])(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}(?![\w:])'), 0),
        ('ip', re.compile(r'(?<![\w.:])(?:[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4})*)?::'
                          r'(?:(?:[0-9a-fA-F]{1,4}:)*(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]{1,4}))?(?![\w:.])'), 0),
        ('ip', re.compile(r'(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?!\.?\d)(?!\w)'), 0),
        ('server', re.compile(r'interface\.\[([^\]]+)\]'), 1),
        ('payment', re.compile(r'PaySession\.\[([0-9a-f]{8}-[0-9a-f]{4})\]'), 1),
    )
    _LABEL = re.compile(r'(<(?:our )?[a-z]+ [0-9a-f]{8}>)')
    _CHANNELS_WITH_FUNDS = re.compile(r'channels_with_funds: \{.*?\}(?=, have_direct_channel|$)', re.M)
    # where the logs name a wallet, and what a wallet logs about its own payments
    _WALLET_NAMES = (
        # (in the head of the entries only, as the messages may be anything a peer sent; names of a sane length)
        re.compile(r'^\d{8}T\d{6}\.\d+Z \|\s*\w+ \| lnworker\.(?:LNWallet|LNPeerManager)\.\[(?!LNGossip\])'
                   r'(.{1,255}?)\](?= \||\Z)', re.M),
        re.compile(r'^\d{8}T\d{6}\.\d+Z \|\s*\w+ \| lnpeer\.Peer\.\[(?!LNGossip,)'
                   r'(.{1,255}?), (?=[^,\]\n]*\] \||\Z)', re.M),  # (up to the name of the transport)
    )
    _WALLET_PATH = re.compile(r'/wallets/([^/\s\'"]+)')
    _OUR_CHANNEL = re.compile(r'sent htlc \d+ over ([0-9]+x[0-9]+x[0-9]+)')
    _SCID = re.compile(r'(?<![\w.])\d+x\d+x\d+(?!\w)')
    # the peers of a wallet and the route hints of its invoices are about its channels
    _ABOUT_OUR_CHANNELS = re.compile(
        r'^[^|\n]*\|[^|\n]*\| (?:lnpeer\.Peer\.\[(?!LNGossip,)[^\]\n]*\] \| .*'
        r'|lnworker\.LNWallet\.\[[^\]\n]*\] \| creating bolt11 invoice with routing_hints: .*)$', re.M)
    _OUR_FIRST_HOP = re.compile(r'route: (0[23][0-9a-f]{8}) -\[([0-9]+x[0-9]+x[0-9]+) ')

    def __init__(self, *, key: bytes, our_node_ids: Iterable[str] = (), our_channels: Iterable[str] = (),
                 wallet_names: Iterable[str] = ()):
        self._key = key
        self._our_nodes = {n[:10].lower() for n in our_node_ids if n}  # (routes are logged with the start of node ids)
        self._our_channels = set(our_channels)
        self._wallet_names = {name for name in wallet_names if name and len(name) >= 3}
        home = os.path.expanduser('~')
        self._home = home if len(home) > 1 else ''  # (tracebacks show paths in it, with the user name)

    def _label(self, kind: str, value: str) -> str:
        """kind is what the value is: the values of nodes are the starts of their ids, see _RULES"""
        if kind == 'node':
            value = value[:10].lower()
        elif kind == 'hash':
            value = value.lower()
        digest = hmac.new(self._key, f'{kind}:{value}'.encode('utf-8'), hashlib.sha256).hexdigest()[:8]
        if kind == 'node' and value in self._our_nodes:
            kind = 'our node'
        elif kind == 'channel' and value in self._our_channels:
            kind = 'our channel'
        return f'<{kind} {digest}>'

    @staticmethod
    def _is_ip(value: str) -> bool:
        try:
            ipaddress.ip_address(value)
        except ValueError:
            return False
        return True

    def _label_of_bytes(self, literal: str) -> str:
        try:
            value = ast.literal_eval(literal)
            assert isinstance(value, bytes)
        except Exception:
            return self._label('bytes', literal)
        if len(value) == 33 and value[0] in (2, 3):
            return self._label('node', value.hex())
        if len(value) == 8:  # a short channel id, likely
            return self._label('channel', '{}x{}x{}'.format(
                int.from_bytes(value[:3], 'big'), int.from_bytes(value[3:6], 'big'), int.from_bytes(value[6:], 'big')))
        if len(value) >= 20:  # the same label as the same bytes in hex
            return self._label('hash', value.hex())
        return self._label('bytes', value.hex())

    def redact(self, text: str) -> str:
        self._our_channels.update(m.group(1) for m in self._OUR_CHANNEL.finditer(text))
        for m in self._ABOUT_OUR_CHANNELS.finditer(text):
            self._our_channels.update(self._SCID.findall(m.group(0)))
        for m in self._OUR_FIRST_HOP.finditer(text):
            self._our_nodes.add(m.group(1))
            self._our_channels.add(m.group(2))
        # (names in logger names, any of them; elsewhere, those long enough not to be found in other words)
        names_in_logger_names = {
            name for pattern in self._WALLET_NAMES for m in pattern.finditer(text)
            if not self._LABEL.fullmatch(name := m.group(1))}
        wallet_names = {name for name in names_in_logger_names | self._wallet_names if len(name) >= 3}
        if self._home:
            text = text.replace(self._home, '~')
        text = self._CHANNELS_WITH_FUNDS.sub('channels_with_funds: <balances>', text)
        text = self._BYTES.sub(lambda m: self._label_of_bytes(m.group(0)), text)
        for kind, pattern, group in self._RULES:
            def replace(m, kind=kind, group=group):
                if group == 0:
                    return self._label(kind, m.group(0))
                if kind == 'channel in hex':
                    value = bytes.fromhex(m.group(group))
                    new = self._label('channel', '{}x{}x{}'.format(
                        int.from_bytes(value[:3], 'big'), int.from_bytes(value[3:6], 'big'), int.from_bytes(value[6:], 'big')))
                elif kind == 'host' and self._is_ip(m.group(group)):
                    new = self._label('ip', m.group(group))  # (the same label as where the ip is logged otherwise)
                else:
                    new = self._label(kind, m.group(group))
                start, end = m.span(group)
                return m.group(0)[:start - m.start()] + new + m.group(0)[end - m.start():]
            text = pattern.sub(replace, text)
        # the names of wallets last, as they may be anything (e.g. a number that is part of an ip address),
        # and not within the labels
        def outside_labels(replace: Callable[[str], str], text: str) -> str:
            return ''.join(part if i % 2 else replace(part) for i, part in enumerate(self._LABEL.split(text)))

        def in_logger_name(m: re.Match) -> str:
            if m.group(1) not in names_in_logger_names:
                return m.group(0)
            start, end = m.start(1) - m.start(), m.end(1) - m.start()
            return m.group(0)[:start] + self._label('wallet', m.group(1)) + m.group(0)[end:]
        # (the whole names first, then what is left in logger names: e.g. short names)
        if wallet_names:
            names = re.compile(
                r'(?<![0-9A-Za-z])(?:' + '|'.join(re.escape(v) for v in sorted(wallet_names, key=len, reverse=True))
                + r')(?![0-9A-Za-z])')
            text = outside_labels(lambda part: names.sub(lambda m: self._label('wallet', m.group(0)), part), text)
        for pattern in self._WALLET_NAMES:
            text = outside_labels(lambda part, pattern=pattern: pattern.sub(in_logger_name, part), text)
        # and the files of wallets that are named nowhere else
        text = outside_labels(lambda part: self._WALLET_PATH.sub(
            lambda m: '/wallets/' + self._label('wallet', m.group(1)), part), text)
        return text


def what_identifies_us_in_logs(wallets: Iterable['Abstract_Wallet']) -> dict:
    """The node ids, channels and wallet names of these wallets, as redact_log_text takes them."""
    from .lnutil import ShortChannelID
    ours = {'our_node_ids': [], 'our_channels': [], 'wallet_names': []}
    for wallet in wallets:
        ours['wallet_names'].append(wallet.basename())
        lnworker = wallet.lnworker
        if lnworker is None:
            continue
        ours['our_node_ids'].append(lnworker.node_keypair.pubkey.hex())
        for chan in list(lnworker.channels.values()) + list(lnworker.channel_backups.values()):
            if chan.short_channel_id:
                ours['our_channels'].append(str(chan.short_channel_id))
            for alias in (chan.get_local_scid_alias(), chan.get_remote_scid_alias()):
                if alias:
                    ours['our_channels'].append(str(ShortChannelID(alias)))
    return ours


def log_sharing_key(config: 'SimpleConfig') -> bytes:
    """The key of the labels in the logs we share (see _LogRedactor), created the first time. It is kept,
    so that the same value gets the same label in the logs shared later too."""
    key = config.LOGS_SHARING_KEY
    if not key or len(key) != 64:
        key = os.urandom(32).hex()
        config.LOGS_SHARING_KEY = key
    return bytes.fromhex(key)


def redact_log_text(text: str, *, key: Optional[bytes] = None, our_node_ids: Iterable[str] = (),
                    our_channels: Iterable[str] = (), wallet_names: Iterable[str] = ()) -> str:
    """See _LogRedactor. Without a key, a new random one. The node ids, channels and wallet names given are
    labelled as ours: those of the wallets loaded now. Those of other wallets are found where the logs mention
    them as ours, and are replaced all the same."""
    return _LogRedactor(key=key if key is not None else os.urandom(32), our_node_ids=our_node_ids,
                        our_channels=our_channels, wallet_names=wallet_names).redact(text)


def describe_os_version() -> str:
    if platform.is_android():
        import jnius
        bv = jnius.autoclass('android.os.Build$VERSION')
        b = jnius.autoclass('android.os.Build')
        return "Android {} on {} {} ({})".format(bv.RELEASE, b.BRAND, b.DEVICE, b.DISPLAY)
    else:
        return py_platform.platform()


@lru_cache  # result unlikely to change while running. though "-dirty" could technically change
def get_git_version() -> Optional[str]:
    dir = os.path.dirname(os.path.realpath(__file__))
    try:
        # note: this searches $PATH and perhaps $PWD for an executable named "git".  attack surface?
        version = subprocess.check_output(
            ['git', 'describe', '--always', '--dirty'],
            cwd=dir,
            timeout=5,  # seconds
        )
        version = str(version, "utf8").strip()
    except Exception:
        version = None
    return version
