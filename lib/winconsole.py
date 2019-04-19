# Electron Cash - lightweight Bitcoin client
# Copyright (C) 2019 Axel Gembe <derago@gmail.com>
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

"""
This module is for to handling console attaching and / or creation in Windows binaries that are
built for the Windows subsystem and therefore do not automatically allocate a console.
"""

import sys
import os
import ctypes

STD_OUTPUT_HANDLE = -11
FILE_TYPE_DISK = 1

def parent_process_pids() -> int:
    """
    Returns all parent process PIDs, starting with the closest parent
    """
    try:
        import psutil
        pid = os.getpid()
        while pid > 0:
            pid = psutil.Process(pid).ppid()
            yield pid
    except psutil.NoSuchProcess:
        # Parent process not found, likely terminated, nothing we can do
        pass

def create_or_attach_console(attach: bool = True, create: bool = False, title: str = None) -> bool:
    """
    First this checks if output is redirected to a file and does nothing if it is. Then it tries
    to attach to the console of any parent process and if not successful it optionally creates a
    console or fails.
    If a console was found or created, it will redirect current output handles to this console.
    """
    std_out_handle = ctypes.windll.kernel32.GetStdHandle(STD_OUTPUT_HANDLE)

    has_console = std_out_handle > 0

    if has_console:
        # Output is being redirected to a file, or we have an msys console.
        # do nothing
        return True

    try:
        if attach:
            # Try to attach to a parent console
            for pid in parent_process_pids():
                if ctypes.windll.kernel32.AttachConsole(pid):
                    has_console = True
                    break
    except ImportError:
        # User's system lacks psutil
        return  # Return None in case caller wants to differntiate exceptional failures from regular False return

    if not has_console and create:
        # Try to allocate a new console
        if ctypes.windll.kernel32.AllocConsole():
            has_console = True

    if not has_console:
        # Indicate to caller no console is to be had.
        return False

    try:
        # Reopen Pythons console input and output handles
        conout = open('CONOUT$', 'w')
        sys.stdout = conout
        sys.stderr = conout
        sys.stdin = open('CONIN$', 'r')
    except OSError:
        # If we get here, we likely were in MinGW / MSYS where CONOUT$ / CONIN$
        # are not valid files or some other weirdness occurred. Give up.
        return  # return None to indicate underlying exception

    if title:
        # Set the console title
        ctypes.windll.kernel32.SetConsoleTitleW(title)

    return True
