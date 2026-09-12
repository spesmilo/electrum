# Copyright (C) 2026 The Electrum developers
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://www.opensource.org/licenses/mit-license.php
#
# This module is a companion to crandom.py and is only intended to be accessed from there.

import ctypes
import ctypes.util
from ctypes import byref, create_string_buffer, c_size_t
import gc
import locale
import os
import platform
import socket
import ssl
import sys
import threading
import time
from typing import TYPE_CHECKING, Callable, Optional
from uuid import getnode as get_mac_address

try:
    import pwd
except ImportError:  # only available on UNIX
    pwd = None
try:
    import resource
except ImportError:  # only available on UNIX
    resource = None

from .logging import get_logger

if TYPE_CHECKING:
    from .crandom import CRANDOM_FEEDER_API


_logger = get_logger(__name__)


def _safe_feed(do_feed: Callable[[], None]) -> None:
    try:
        do_feed()
    except Exception as e:
        _logger.debug(f"skipping an entropy source due to error: {e!r}", only_once=True)


def add_path(feed: 'CRANDOM_FEEDER_API', path: str) -> None:
    """stat a path"""
    feed(path)
    try:
        stat = os.stat(path)
    except OSError:
        stat = ""
    feed(str(stat))


def add_file(feed: 'CRANDOM_FEEDER_API', path: str) -> None:
    """read file at path"""
    add_path(feed, path)
    try:
        with open(path, "rb") as f:
            data = f.read(1024*1024)  # up to 1 MB
    except OSError:
        data = b""
    feed(data)


_libc = None  # type: ctypes.CDLL | None | False  # False means failed to load libc
def _load_libc():
    global _libc
    if _libc is not None:
        return
    try:
        _libc_path = ctypes.util.find_library("c")  # can raise OSError
        _libc = ctypes.CDLL(_libc_path, use_errno=True)
    except Exception as e:
        _logger.debug(f"failed to load libc: {e!r}", only_once=True)
        _libc = False


def sysctl_byname(name: bytes) -> Optional[bytes]:
    """
    ref https://man.freebsd.org/cgi/man.cgi?query=sysctlbyname
    ref https://github.com/freebsd/freebsd-src/blob/edb230c4af499203d7a6894b3711fe6574b26040/sys/sys/sysctl.h#L961
    from https://gist.github.com/pudquick/581a71425439f2cf8f09
    """
    _load_libc()
    if not _libc:
        return None
    size = c_size_t(0)
    # Find out how big our buffer will be
    ret = _libc.sysctlbyname(name, None, byref(size), None, 0)
    if ret != 0:
        return None
    # Make the buffer
    buf = create_string_buffer(size.value)
    # Re-run, but provide the buffer
    ret = _libc.sysctlbyname(name, buf, byref(size), None, 0)
    if ret != 0:
        return None
    return buf.raw


def add_sysctl(feed: 'CRANDOM_FEEDER_API', name: bytes) -> None:
    feed(name)
    _safe_feed(lambda: feed(sysctl_byname(name) or b""))


def supports_sysctl() -> bool:
    _load_libc()
    if not _libc:
        return False
    return hasattr(_libc, "sysctlbyname")


def rand_add_static_env(feed: 'CRANDOM_FEEDER_API') -> None:
    """Gather non-cryptographic environment data that does not change over time
    and feed it into feed().

    Never raises.
    """
    # os
    _safe_feed(lambda: feed(str(os.environ)))
    _safe_feed(lambda: feed(os.ctermid()))
    _safe_feed(lambda: feed(os.getcwd()))
    _safe_feed(lambda: feed(str(os.get_exec_path())))
    _safe_feed(lambda: feed(str(os.getgroups())))
    _safe_feed(lambda: feed(str(os.getlogin())))
    _safe_feed(lambda: feed(os.getpgrp()))
    _safe_feed(lambda: feed(os.getpid()))
    _safe_feed(lambda: feed(os.getppid()))
    _safe_feed(lambda: feed(str(os.getresuid())))
    _safe_feed(lambda: feed(str(os.getresgid())))
    _safe_feed(lambda: feed(str(os.uname())))
    # timezone
    _safe_feed(lambda: feed(time.timezone))
    _safe_feed(lambda: feed(str(time.tzname)))
    # system locale
    _safe_feed(lambda: feed(str(locale.getlocale())))
    # mac address
    _safe_feed(lambda: feed(get_mac_address()))
    # hostname
    _safe_feed(lambda: feed(socket.gethostname()))
    # sys
    _safe_feed(lambda: feed(str(sys.argv)))
    _safe_feed(lambda: feed(str(sys.builtin_module_names)))
    _safe_feed(lambda: feed(sys.executable))
    _safe_feed(lambda: feed(str(sys.float_info)))
    _safe_feed(lambda: feed(str(sys.hash_info)))
    _safe_feed(lambda: feed(str(sys.implementation)))
    _safe_feed(lambda: feed(str(sys.int_info)))
    _safe_feed(lambda: feed(str(sys.meta_path)))
    _safe_feed(lambda: feed(str(sys.orig_argv)))
    _safe_feed(lambda: feed(str(sys.path)))
    _safe_feed(lambda: feed(str(sys.thread_info)))
    _safe_feed(lambda: feed(sys.version))
    # platform
    _safe_feed(lambda: feed(str(platform.architecture())))
    _safe_feed(lambda: feed(platform.machine()))
    _safe_feed(lambda: feed(platform.node()))
    _safe_feed(lambda: feed(platform.platform()))
    _safe_feed(lambda: feed(platform.processor()))
    _safe_feed(lambda: feed(str(platform.uname())))
    _safe_feed(lambda: feed(str(platform.win32_ver())))
    _safe_feed(lambda: feed(str(platform.mac_ver())))
    _safe_feed(lambda: feed(str(platform.ios_ver())))
    _safe_feed(lambda: feed(str(platform.libc_ver())))
    _safe_feed(lambda: feed(str(platform.freedesktop_os_release())))
    _safe_feed(lambda: feed(str(platform.android_ver())))
    from .logging import describe_os_version
    _safe_feed(lambda: feed(describe_os_version()))
    # version of electrum
    from . import ELECTRUM_VERSION
    feed(ELECTRUM_VERSION)
    from .logging import get_git_version
    #feed(get_git_version() or "")  # skipping for now as resolving "git" from $PATH might open up its own issues
    # path to this file
    feed(__file__)
    # memory locations
    feed(id(__file__))
    feed(id(id))
    feed(id(os))
    feed(id(feed))
    feed(id(ELECTRUM_VERSION))
    feed(id(_logger))
    feed(id("longish_string_literal"))
    feed(id(0))
    # misc
    if pwd is not None:
        _safe_feed(lambda: feed(str(pwd.getpwall())))
    if resource is not None:
        _safe_feed(lambda: feed(resource.getpagesize()))
    # filesystem-provided data
    add_path(feed, "/")
    add_path(feed, ".")
    add_path(feed, "/tmp")
    add_path(feed, "/home")
    add_path(feed, "/proc")
    add_file(feed, "/proc/cmdline")
    add_file(feed, "/proc/cpuinfo")
    add_file(feed, "/proc/version")
    add_file(feed, "/etc/passwd")
    add_file(feed, "/etc/group")
    add_file(feed, "/etc/hosts")
    add_file(feed, "/etc/resolv.conf")
    add_file(feed, "/etc/timezone")
    add_file(feed, "/etc/localtime")
    # sysctls (macOS and BSDs)
    if supports_sysctl():
        add_sysctl(feed, b"hw.machine")
        add_sysctl(feed, b"hw.model")
        add_sysctl(feed, b"hw.ncpu")
        add_sysctl(feed, b"hw.physmem")
        add_sysctl(feed, b"hw.usermem")
        add_sysctl(feed, b"hw.memsize")
        add_sysctl(feed, b"hw.machine.arch")
        add_sysctl(feed, b"hw.realmem")
        add_sysctl(feed, b"hw.cpu.freq")
        add_sysctl(feed, b"hw.cpufrequency")
        add_sysctl(feed, b"hw.bus.freq")
        add_sysctl(feed, b"hw.busfrequency")
        add_sysctl(feed, b"hw.cacheline")
        add_sysctl(feed, b"hw.cachelinesize")
        add_sysctl(feed, b"hw.cachesize")
        add_sysctl(feed, b"kern.bootfile")
        add_sysctl(feed, b"kern.boottime")
        add_sysctl(feed, b"kern.clockrate")
        add_sysctl(feed, b"kern.hostid")
        add_sysctl(feed, b"kern.hostuuid")
        add_sysctl(feed, b"kern.hostname")
        add_sysctl(feed, b"kern.osreldate")
        add_sysctl(feed, b"kern.osrelease")
        add_sysctl(feed, b"kern.osrev")
        add_sysctl(feed, b"kern.ostype")
        add_sysctl(feed, b"kern.version")
        add_sysctl(feed, b"kern.uuid")
        add_sysctl(feed, b"kern.bootuuid")
        add_sysctl(feed, b"kern.bootsessionuuid")
        add_sysctl(feed, b"kern.kernelcacheuuid")
        add_sysctl(feed, b"kern.filesetuuid")


def rand_add_dynamic_env(feed: 'CRANDOM_FEEDER_API', *, include_slow_sources: bool) -> None:
    """Gather non-cryptographic environment data that changes over time and feed it into feed().

    Never raises.
    """
    # time
    feed(time.time_ns())
    feed(time.process_time_ns())
    feed(time.perf_counter_ns())
    # openssl
    try:
        feed(ssl.RAND_bytes(32))
    except ssl.SSLError as e:
        _logger.warning(f"failed to get randomness from openssl: {e!r}", only_once=True)
    # memory locations
    feed(id("longish_string_literal"))
    # threading
    active_threads = threading.enumerate()
    feed(str(active_threads))
    _safe_feed(lambda: feed(str([t.native_id for t in active_threads])))
    # sys
    feed(sys.getallocatedblocks())
    _safe_feed(lambda: feed(sys.getunicodeinternedsize()))
    _safe_feed(lambda: feed(str(sys._current_frames())))
    _safe_feed(lambda: feed(str(sys._current_exceptions())))
    _safe_feed(lambda: feed(str(sys.path_importer_cache)))
    # gc
    feed(str(gc.get_stats()))
    feed(str(gc.get_count()))
    feed(str(gc.get_threshold()))
    # resource
    if resource is not None:
        _safe_feed(lambda: feed(str(resource.getrusage(resource.RUSAGE_SELF))))
        _safe_feed(lambda: feed(str(resource.getrusage(resource.RUSAGE_CHILDREN))))
        _safe_feed(lambda: feed(str(resource.getrusage(resource.RUSAGE_THREAD))))
    # filesystem-provided data (whole section takes around 0.9 msec, but content changes fast)
    add_file(feed, "/proc/diskstats")
    add_file(feed, "/proc/vmstat")
    add_file(feed, "/proc/schedstat")
    add_file(feed, "/proc/zoneinfo")
    add_file(feed, "/proc/meminfo")
    add_file(feed, "/proc/softirqs")
    add_file(feed, "/proc/stat")
    add_file(feed, "/proc/self/schedstat")
    add_file(feed, "/proc/self/status")
    # sysctls (macOS and BSDs)
    if supports_sysctl():
        add_sysctl(feed, b"kern.proc.all")  # takes around 0.9 msec, content changes fast
        add_sysctl(feed, b"kern.memorystatus_level")
        add_sysctl(feed, b"hw.diskstats")
        add_sysctl(feed, b"vm.swapusage")
        add_sysctl(feed, b"vm.loadavg")
        add_sysctl(feed, b"vm.total")
        add_sysctl(feed, b"vm.meter")
        add_sysctl(feed, b"vm.page_free_count")
        add_sysctl(feed, b"net.inet.tcp.pcbcount")
        add_sysctl(feed, b"net.inet.udp.pcbcount")
    # --- end of fast sources ---
    if not include_slow_sources:
        return
    _safe_feed(lambda: feed(str(sys.modules)))  # takes 1.5 msec, and content changes slowly
