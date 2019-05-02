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
        return super().format(record)


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


def _configure_verbosity(config):
    verbosity = config.get('verbosity')
    if not verbosity:
        return
    console_stderr_handler.setLevel(logging.DEBUG)
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


# --- External API

def get_logger(name: str) -> logging.Logger:
    if name.startswith("electrum."):
        name = name[9:]
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
        return get_logger(name)

    def diagnostic_name(self):
        return ''


def configure_logging(config):
    _configure_verbosity(config)

    is_android = 'ANDROID_DATA' in os.environ
    if is_android or config.get('disablefilelogging'):
        pass  # disable file logging
    else:
        log_directory = pathlib.Path(config.path) / "logs"
        _configure_file_logging(log_directory)

    # if using kivy, avoid kivy's own logs to get printed twice
    logging.getLogger('kivy').propagate = False

    from . import ELECTRUM_VERSION
    _logger.info(f"Electrum version: {ELECTRUM_VERSION} - https://electrum.org - https://github.com/spesmilo/electrum")
    _logger.info(f"Python version: {sys.version}. On platform: {platform.platform()}")
    _logger.info(f"Logging to file: {str(_logfile_path)}")


def get_logfile_path() -> Optional[pathlib.Path]:
    return _logfile_path
