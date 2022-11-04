# Copyright (C) 2019 The Electrum developers
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://www.opensource.org/licenses/mit-license.php

import logging
import logging.handlers
import datetime
import sys
import pathlib
import os
import platform
from typing import Optional, TYPE_CHECKING
import copy
import subprocess

if TYPE_CHECKING:
    from .simple_config import SimpleConfig


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

    def format(self, record):
        record = _shorten_name_of_logrecord(record)
        text = super().format(record)
        shortcut = getattr(record, 'custom_shortcut', None)
        if shortcut:
            text = text[:1] + f"/{shortcut}" + text[1:]
        return text


# try to make console log lines short... no timestamp, short levelname, no "electrum."
console_formatter = LogFormatterForConsole(fmt="%(levelname).1s | %(name)s | %(message)s")


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


def _delete_old_logs(path, keep=10):
    files = sorted(list(pathlib.Path(path).glob("electrum_log_*.log")), reverse=True)
    for f in files[keep:]:
        try:
            os.remove(str(f))
        except OSError as e:
            _logger.warning(f"cannot delete old logfile: {e}")


_logfile_path = None
def _configure_file_logging(log_directory: pathlib.Path):
    global _logfile_path
    assert _logfile_path is None, 'file logging already initialized'
    log_directory.mkdir(exist_ok=True)

    _delete_old_logs(log_directory)

    timestamp = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    PID = os.getpid()
    _logfile_path = log_directory / f"electrum_log_{timestamp}_{PID}.log"

    file_handler = logging.FileHandler(_logfile_path, encoding='utf-8')
    file_handler.setFormatter(file_formatter)
    file_handler.setLevel(logging.DEBUG)
    root_logger.addHandler(file_handler)
    if _inmemory_startup_logs:
        _inmemory_startup_logs.dump_to_target(file_handler)


console_stderr_handler = None
def _configure_stderr_logging(*, verbosity=None, verbosity_shortcuts=None):
    # log to stderr; by default only WARNING and higher
    global console_stderr_handler
    if console_stderr_handler is not None:
        _logger.warning("stderr handler already exists")
        return
    console_stderr_handler = logging.StreamHandler(sys.stderr)
    console_stderr_handler.setFormatter(console_formatter)
    if not verbosity and not verbosity_shortcuts:
        console_stderr_handler.setLevel(logging.WARNING)
        root_logger.addHandler(console_stderr_handler)
    else:
        console_stderr_handler.setLevel(logging.DEBUG)
        root_logger.addHandler(console_stderr_handler)
        _process_verbosity_log_levels(verbosity)
        _process_verbosity_filter_shortcuts(verbosity_shortcuts, handler=console_stderr_handler)
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


def _process_verbosity_filter_shortcuts(verbosity_shortcuts, *, handler: 'logging.Handler'):
    if not isinstance(verbosity_shortcuts, str):
        return
    if len(verbosity_shortcuts) < 1:
        return
    # depending on first character being '^', either blacklist or whitelist
    is_blacklist = verbosity_shortcuts[0] == '^'
    if is_blacklist:
        filters = verbosity_shortcuts[1:]
    else:  # whitelist
        filters = verbosity_shortcuts[0:]
    filt = ShortcutFilteringFilter(is_blacklist=is_blacklist, filters=filters)
    # apply filter directly (and only!) on stderr handler
    # note that applying on one of the root loggers directly would not work,
    # see https://docs.python.org/3/howto/logging.html#logging-flow
    handler.addFilter(filt)


class ShortcutInjectingFilter(logging.Filter):

    def __init__(self, *, shortcut: Optional[str]):
        super().__init__()
        self.__shortcut = shortcut

    def filter(self, record):
        record.custom_shortcut = self.__shortcut
        return True


class ShortcutFilteringFilter(logging.Filter):

    def __init__(self, *, is_blacklist: bool, filters: str):
        super().__init__()
        self.__is_blacklist = is_blacklist
        self.__filters = filters

    def filter(self, record):
        # all errors are let through
        if record.levelno >= logging.ERROR:
            return True
        # the logging module itself is let through
        if record.name == __name__:
            return True
        # do filtering
        shortcut = getattr(record, 'custom_shortcut', None)
        if self.__is_blacklist:
            if shortcut is None:
                return True
            if shortcut in self.__filters:
                return False
            return True
        else:  # whitelist
            if shortcut is None:
                return False
            if shortcut in self.__filters:
                return True
            return False


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

def get_logger(name: str) -> logging.Logger:
    if name.startswith("electrum."):
        name = name[9:]
    return electrum_logger.getChild(name)


_logger = get_logger(__name__)
_logger.setLevel(logging.INFO)


class Logger:

    # Single character short "name" for this class.
    # Can be used for filtering log lines. Does not need to be unique.
    LOGGING_SHORTCUT = None  # type: Optional[str]

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
        if self.LOGGING_SHORTCUT:
            logger.addFilter(ShortcutInjectingFilter(shortcut=self.LOGGING_SHORTCUT))
        return logger

    def diagnostic_name(self):
        return ''


def configure_logging(config: 'SimpleConfig', *, log_to_file: Optional[bool] = None) -> None:
    from .util import is_android_debug_apk

    verbosity = config.get('verbosity')
    verbosity_shortcuts = config.get('verbosity_shortcuts')
    if not verbosity and config.get('gui_enable_debug_logs'):
        verbosity = '*'
    _configure_stderr_logging(verbosity=verbosity, verbosity_shortcuts=verbosity_shortcuts)

    if log_to_file is None:
        log_to_file = config.get('log_to_file', False)
        log_to_file |= is_android_debug_apk()
    if log_to_file:
        log_directory = pathlib.Path(config.path) / "logs"
        _configure_file_logging(log_directory)

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

    # if using kivy, avoid kivy's own logs to get printed twice
    logging.getLogger('kivy').propagate = False

    from . import ELECTRUM_VERSION
    from .constants import GIT_REPO_URL
    _logger.info(f"Electrum version: {ELECTRUM_VERSION} - https://electrum.org - {GIT_REPO_URL}")
    _logger.info(f"Python version: {sys.version}. On platform: {describe_os_version()}")
    _logger.info(f"Logging to file: {str(_logfile_path)}")
    _logger.info(f"Log filters: verbosity {repr(verbosity)}, verbosity_shortcuts {repr(verbosity_shortcuts)}")


def get_logfile_path() -> Optional[pathlib.Path]:
    return _logfile_path


def describe_os_version() -> str:
    if 'ANDROID_DATA' in os.environ:
        #from kivy import utils
        #if utils.platform != "android":
        #    return utils.platform
        import jnius
        bv = jnius.autoclass('android.os.Build$VERSION')
        b = jnius.autoclass('android.os.Build')
        return "Android {} on {} {} ({})".format(bv.RELEASE, b.BRAND, b.DEVICE, b.DISPLAY)
    else:
        return platform.platform()


def get_git_version() -> Optional[str]:
    dir = os.path.dirname(os.path.realpath(__file__))
    try:
        version = subprocess.check_output(
            ['git', 'describe', '--always', '--dirty'], cwd=dir)
        version = str(version, "utf8").strip()
    except Exception:
        version = None
    return version
