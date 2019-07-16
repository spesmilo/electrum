# Electron Cash - lightweight Bitcoin client
# Copyright (C) 2019 Axel Gembe <derago@gmail.com>
# Copyright (C) 2019 Calin Culianu <calin.culianu@gmail.com>
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
Tests if the system has libfontconfig.so.1 and if its version is
< 2.12.7, exit(1).  If version >= 2.12.7, exit 0.  Exit 2 on
library load error.

In other words, if this script returns success it means the system
has a newer fontconfig library than we bundle and we should use that
instead.
"""

import ctypes
import sys
import os

# On CentOS we always use the systems font libraries
if os.path.isfile('/etc/centos-release'):
    sys.exit(0)


TOO_NEW_VERSION = 21207  # 2.12.7 is "too new" since we use 2.12.6

try:
    fontconfig = ctypes.CDLL('libfontconfig.so.1')
    # ctypes default is a function takng 0 args and returning int,
    # which is already the prototype of this fontconfig function
    ver = fontconfig.FcGetVersion()
except Exception:
    sys.exit(2)  # error exit indicates to caller to use bundled fontconfig

if ver < TOO_NEW_VERSION:
    sys.exit(1) # error exit indicates to caller to use bundled fontconfig

# Success exit -- do not use bundled fontconfig
sys.exit(0)
