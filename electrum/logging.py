import logging, datetime, sys, pathlib, os
from . import ELECTRUM_VERSION

# How it works:
#   *enable logs* (but not stdout < warning )
#   *configures* logs >= warning to goto to stderr
#   *THEN* config is loaded
#   *configures* logging to files using config location
#   *IF* verbosity -v is turned on, enable console logs < warning

# Why:
#   Enable logs as soon as possible, before config is loaded, as it could
#    report information on config / electrum location operations.
#   You need config to know where to put file logs.
#   Enable stdout logs, if verbosity enabled (also in config)
#   This implementation is easy to refactor.

# Why this formatting?:
#   "%(asctime)22s | %(levelname)-4s | %(name)s.%(module)s.%(lineno)s | %(message)s"
#   UTC ISO8601 timestamp
#   LEVEL
#   Python Module . Line Number - Super easy to locate things.
#   and of course, the message

# USAGE:
# initialization:
#    import electrum.logging
#    electrum.logging.configure_logging(config)
#
# logging:
#    from electrum.logging import Logger
#    class Thing(Logger):
#        def __init__(*args, **kwargs):
#            Logger(self, *args, **kargs)
#
#    from electrum.logging import electrum_logger
#    electrum_logger.info("Sup")
#
#    # include exception traceback in FILE
#    electrum_logger.info("Yo. exc_info=True)


class ISO8601UTCTimeFormatter(logging.Formatter):
    converter = datetime.datetime.fromtimestamp

    def formatTime(self, record, datefmt=None):
        current_time = self.converter(record.created).astimezone(datetime.timezone.utc)
        if not datefmt:
            datefmt = "%Y%m%dT%H%M%S.%fZ"
        return current_time.strftime(datefmt)


class ExceptionTracebackSquasherFormatter(logging.Formatter):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def formatException(self, ei):
        return ''


# house multiple formatters as one
class ElectrumConsoleLogFormatter(ISO8601UTCTimeFormatter, ExceptionTracebackSquasherFormatter):
    def __init__(self, *args, **kwargs):
        ISO8601UTCTimeFormatter.__init__(self, *args, **kwargs)
        ExceptionTracebackSquasherFormatter.__init__(self, *args, **kwargs)


class ElectrumFileLogFormatter(ISO8601UTCTimeFormatter):
    def __init__(self, *args, **kwargs):
        ISO8601UTCTimeFormatter.__init__(self, *args, **kwargs)


# errors won't go to stdout
class StdoutErrorFilter(logging.Filter):
    def filter(self, record):
        return record.levelno <= logging.INFO


# enable logs universally (including for other libraries)
log_format = "%(asctime)22s | %(levelname)8s | %(name)s.%(module)s.%(lineno)s | %(message)s"
date_format = "%Y%m%dT%H%M%S.%fZ"
console_formatter = ElectrumConsoleLogFormatter(fmt=log_format, datefmt=date_format)
file_formatter = ElectrumFileLogFormatter(fmt=log_format, datefmt=date_format)

root_logger = logging.getLogger()
root_logger.setLevel(logging.DEBUG)

# log errors to console (stderr)
console_stderr_handler = logging.StreamHandler(sys.stderr)
console_stderr_handler.setFormatter(console_formatter)
console_stderr_handler.setLevel(logging.WARNING)
root_logger.addHandler(console_stderr_handler)

# creates a logger specifically for electrum library
electrum_logger = logging.getLogger("Electrum")


class Logger:
    def __init__(self):
        self.log = electrum_logger


def delete_old_logs(path, keep=10):
    files = list(pathlib.Path(path).glob("elecrum_*_*.log"))
    if len(files) >= keep:
        for f in files[keep:]:
            os.remove(str(f))


def configure_file_logging(log_directory):
    log_directory.mkdir(exist_ok=True)

    delete_old_logs(log_directory, 10)

    timestamp = datetime.datetime.utcnow().strftime(date_format[:13])
    new_log_file = log_directory / f"electrum_{ELECTRUM_VERSION}_{timestamp}.log"

    file_handler = logging.FileHandler(new_log_file)
    file_handler.setFormatter(file_formatter)
    file_handler.setLevel(logging.DEBUG)
    root_logger.addHandler(file_handler)

    electrum_logger.info(f"Electrum - {ELECTRUM_VERSION} - Electrum Technologies GmbH - https://electrum.org")
    electrum_logger.info(f"Log: {new_log_file}")


def configure_logging(config):
    log_directory = pathlib.Path(config.path) / "logs"

    if config.cmdline_options['verbosity']:
        # log to console
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(console_formatter)
        console_handler.addFilter(StdoutErrorFilter())
        root_logger.addHandler(console_handler)

    configure_file_logging(log_directory)
