# Copyright (C) 2020 cptpcrd
# Copyright (C) 2025 The Electrum developers
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://www.opensource.org/licenses/mit-license.php
#
# based on https://github.com/cptpcrd/pyprctl/blob/578ed3e81066a8a61dede912454d5eeaef37eeea/pyprctl/ffi.py#L28
#
# This module tries to restrict the ability of other processes to access the memory of our process.
# Traditionally, on Linux, one process can access the memory of another arbitrary process
# if both are running as the same user (uid). (Root can ofc access the memory of ~any process)
# Programs can opt-out from this by setting prctl(PR_SET_DUMPABLE, 0);
#
# Besides PR_SET_DUMPABLE, there are ways to globally restrict this for all processes:
# 1. The Yama (Linux Security Module) ptrace scope can be used to reduce these permissions
#    This runtime kernel parameter can be set to the following options:
#      0 - Default attach security permissions.
#      1 - Restricted attach. Only child processes plus normal permissions.
#      2 - Admin-only attach. Only executables with CAP_SYS_PTRACE.
#      3 - No attach. No process may call ptrace at all. Irrevocable.
#    # Note: The default value of kernel.yama.ptrace_scope is distro-specific.
#    #       See `$ cat /proc/sys/kernel/yama/ptrace_scope`.
#    #       - ubuntu 22.04 sets it to 1 (see /etc/sysctl.d/10-ptrace.conf),
#    #       - debian 12 sets it to 0
#    #       - manjaro sets it to 1
# 2. SELinux: ptrace can be restricted by setting the selinux deny_ptrace boolean.
#
# For a quick test on your system, try:
#   $ cat /proc/$$/mem > /dev/null
#   cat: /proc/4907/mem: Permission denied
# Getting "Permission denied" means access failed, "Input/output error" means access succeeded.

import ctypes
import ctypes.util
import os
import sys
from typing import Optional

from .logging import get_logger


_logger = get_logger(__name__)

PR_GET_DUMPABLE = 3
PR_SET_DUMPABLE = 4


_libc = None  # type: Optional[ctypes.CDLL]
def _load_libc():
    global _libc
    if _libc is not None:
        return
    #assert sys.platform == "linux", sys.platform
    # note: find_library can raise FileNotFoundError(OSError), see https://github.com/python/cpython/issues/93094
    _libc_path = ctypes.util.find_library("c")
    _libc = ctypes.CDLL(_libc_path, use_errno=True)
    _libc.prctl.argtypes = (ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong)
    _libc.prctl.restype = ctypes.c_int


def set_dumpable(flag: bool) -> None:
    """Set the "dumpable" attribute on the current process.
    This controls whether a core dump will be produced if the process receives a signal whose
    default behavior is to produce a core dump.
    In addition, processes that are not dumpable cannot be attached with ptrace() PTRACE_ATTACH.

    In effect, another process running as the same user as us can read our memory if we are dumpable.
    """
    _load_libc()
    res = _libc.prctl(PR_SET_DUMPABLE, int(bool(flag)), 0, 0, 0)
    if res < 0:
        eno = ctypes.get_errno()
        raise OSError(eno, os.strerror(eno), None, None, None)


def set_dumpable_safe(flag: bool) -> None:
    try:
        _load_libc()
    except Exception as e:
        _logger.exception("error loading libc")
        return
    assert _libc is not None
    try:
        set_dumpable(flag)
    except OSError as e:
        _logger.error(f"libc.prctl(PR_SET_DUMPABLE, {flag}) errored: {e}")


def get_dumpable() -> bool:
    _load_libc()
    res = _libc.prctl(PR_GET_DUMPABLE, 0, 0, 0, 0)
    if res < 0:
        eno = ctypes.get_errno()
        raise OSError(eno, os.strerror(eno), None, None, None)
    return res != 0
