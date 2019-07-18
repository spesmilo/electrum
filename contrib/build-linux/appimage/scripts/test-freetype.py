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
Tests if the system has libfreetype.so.6 and query its version.
The AppImage bundles libfreetype version 2.8 and if the system freetype
is older or cannot be found, return error status. If system >= 2.8, return
success status.
"""

import ctypes
import sys
import os
from ctypes import POINTER, c_int, c_void_p


MIN_OK_VERSION = (2,8,1)  # We bundle 2.8.1 -- if system is older we use our bundled version.

try:
    freetype = ctypes.CDLL('libfreetype.so.6')

    # see freetype API docs: https://www.freetype.org/freetype2/docs/reference/ft2-base_interface.html#ft_init_freetype
    freetype.FT_Init_FreeType.restype = c_int
    freetype.FT_Init_FreeType.argtypes = [ POINTER(c_void_p) ]

    freetype.FT_Done_FreeType.restype = c_int
    freetype.FT_Done_FreeType.argtypes = [ c_void_p ]

    freetype.FT_Library_Version.restype = None
    freetype.FT_Library_Version.argtypes = [ c_void_p, POINTER(c_int), POINTER(c_int), POINTER(c_int) ]


    # allocate FT_Library object -- required to query version
    lib_handle = c_void_p()
    err = freetype.FT_Init_FreeType(lib_handle)
    if err or not lib_handle:
        raise RuntimeError()

    major, minor, rev = c_int(), c_int(), c_int()

    # Query version: void FT_Library_Version(void *, int *, int *, int *)
    freetype.FT_Library_Version(lib_handle, major, minor, rev)
    major, minor, rev = int(major.value), int(minor.value), int(rev.value)

    # destroy library instance, freeing its resources and memory
    freetype.FT_Done_FreeType(lib_handle)
    del lib_handle
except Exception:
    sys.exit(2)  # error talking to library, use bundled lib

if (major, minor, rev) < MIN_OK_VERSION:
    sys.exit(1)  # indicate system not new enough, use bundled lib

# system lib ok -- do not use bundled lib
sys.exit(0)
