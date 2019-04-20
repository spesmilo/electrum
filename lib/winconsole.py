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
This module is for to handling console attaching and / or creation in Windows
binaries that are built for the Windows subsystem and therefore do not
automatically allocate a console.
"""

import sys
import os
import ctypes
import atexit

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

def get_console_title() -> str:
    ''' Return the current console title as a string. May return None on error. '''
    b = bytes(1024)
    b_ptr = ctypes.c_char_p(b)
    title = None
    title_len = ctypes.windll.kernel32.GetConsoleTitleW(b_ptr, len(b)//2)  # GetConsoleTitleW expects size in 2-byte chars
    if title_len > 0:
        title = b.decode('utf-16')[:title_len]
    return title

def create_or_attach_console(*, attach: bool = True, create: bool = False,
                             title: str = None) -> bool:
    """
    Workaround to the fact that cmd.exe based execution of this program means
    it has no stdout handles and thus is always silent, thereby rendering
    vernbose console output or command-line usage problematic.

    First, check if we have STD_OUTPUT_HANDLE (a console) and do nothing if
    there is one, returning True.

    Otherwise, try to attach to the console of any ancestor process, and return
    True.

    If not successful, optionally (create=True) create a new console.

    NB: Creating a new console results in a 'cmd.exe' console window to be
    created on the Windows desktop, so only pass create=True if that's
    acceptable.

    If a console was found or created, we redirect current output handles
    (sys.stdout, sys.stderr) to this found and/or created console.

    Always return True on success or if there was a console already,
    False or None on failure (a None return indicates a missing lib or some
    other unspecified exception was raised when attempting to create a console).
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

    created = False

    if not has_console and create:
        # Try to allocate a new console
        if ctypes.windll.kernel32.AllocConsole():
            has_console = True
            created = True

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
        old_title = get_console_title() if not created else None  # save the old title only if not created by us
        # Set the console title, if specified
        ctypes.windll.kernel32.SetConsoleTitleW(title)
        if old_title is not None:
            # undo the setting of the console title at app exit
            atexit.register(ctypes.windll.kernel32.SetConsoleTitleW, old_title)

    return True
