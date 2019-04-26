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


class LogFormatter(logging.Formatter):

    def formatTime(self, record, datefmt=None):
        # timestamps follow ISO 8601 UTC
        date = datetime.datetime.fromtimestamp(record.created).astimezone(datetime.timezone.utc)
        if not datefmt:
            datefmt = "%Y%m%dT%H%M%S.%fZ"
        return date.strftime(datefmt)


LOG_FORMAT = "%(asctime)22s | %(levelname)8s | %(name)s | %(message)s"
console_formatter = LogFormatter(fmt=LOG_FORMAT)
file_formatter = LogFormatter(fmt=LOG_FORMAT)

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


# --- External API

def get_logger(name: str) -> logging.Logger:
    if name.startswith("electrum."):
        name = name[9:]
    return electrum_logger.getChild(name)


_logger = get_logger(__name__)


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
    if config.get('verbosity'):
        console_stderr_handler.setLevel(logging.DEBUG)

    is_android = 'ANDROID_DATA' in os.environ
    if is_android or config.get('disablefilelogging'):
        pass  # disable file logging
    else:
        log_directory = pathlib.Path(config.path) / "logs"
        _configure_file_logging(log_directory)

    from . import ELECTRUM_VERSION
    _logger.info(f"Electrum version: {ELECTRUM_VERSION} - https://electrum.org - https://github.com/spesmilo/electrum")
    _logger.info(f"Python version: {sys.version}. On platform: {platform.platform()}")
    _logger.info(f"Logging to file: {str(_logfile_path)}")


def get_logfile_path() -> Optional[pathlib.Path]:
    return _logfile_path
