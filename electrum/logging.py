# Copyright (C) 2019 The Electrum developers
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://www.opensource.org/licenses/mit-license.php

import logging
import datetime
import sys
import pathlib
import os
import platform
from typing import Optional
import copy


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


# enable logs universally (including for other libraries)
root_logger = logging.getLogger()
root_logger.setLevel(logging.WARNING)

# log to stderr; by default only WARNING and higher
console_stderr_handler = logging.StreamHandler(sys.stderr)
console_stderr_handler.setFormatter(console_formatter)
console_stderr_handler.setLevel(logging.WARNING)
root_logger.addHandler(console_stderr_handler)

# creates a logger specifically for electrum library
electrum_logger = logging.getLogger("electrum")
electrum_logger.setLevel(logging.DEBUG)


def _delete_old_logs(path, keep=10):
    files = sorted(list(pathlib.Path(path).glob("electrum_log_*.log")), reverse=True)
    for f in files[keep:]:
        os.remove(str(f))


_logfile_path = None
def _configure_file_logging(log_directory: pathlib.Path):
    global _logfile_path
    assert _logfile_path is None, 'file logging already initialized'
    log_directory.mkdir(exist_ok=True)

    _delete_old_logs(log_directory)

    timestamp = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    PID = os.getpid()
    _logfile_path = log_directory / f"electrum_log_{timestamp}_{PID}.log"

    file_handler = logging.FileHandler(_logfile_path)
    file_handler.setFormatter(file_formatter)
    file_handler.setLevel(logging.DEBUG)
    root_logger.addHandler(file_handler)


def _configure_verbosity(*, verbosity, verbosity_shortcuts):
    if not verbosity and not verbosity_shortcuts:
        return
    console_stderr_handler.setLevel(logging.DEBUG)
    _process_verbosity_log_levels(verbosity)
    _process_verbosity_filter_shortcuts(verbosity_shortcuts)


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


def _process_verbosity_filter_shortcuts(verbosity_shortcuts):
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
    console_stderr_handler.addFilter(filt)


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


def configure_logging(config):
    verbosity = config.get('verbosity')
    verbosity_shortcuts = config.get('verbosity_shortcuts')
    _configure_verbosity(verbosity=verbosity, verbosity_shortcuts=verbosity_shortcuts)

    is_android = 'ANDROID_DATA' in os.environ
    if is_android or not config.get('log_to_file', False):
        pass  # disable file logging
    else:
        log_directory = pathlib.Path(config.path) / "logs"
        _configure_file_logging(log_directory)

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
        from kivy import utils
        if utils.platform is not "android":
            return utils.platform
        import jnius
        bv = jnius.autoclass('android.os.Build$VERSION')
        b = jnius.autoclass('android.os.Build')
        return "Android {} on {} {} ({})".format(bv.RELEASE, b.BRAND, b.DEVICE, b.DISPLAY)
    else:
        return platform.platform()
