#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2015 Thomas Voegtlin
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

import os
import sys
import ctypes

if sys.platform == 'darwin':
    name = 'libzbar.dylib'
elif sys.platform == 'windows':
    name = 'libzbar.dll'
else:
    name = 'libzbar.so.0'

try:
    libzbar = ctypes.cdll.LoadLibrary(name)
except OSError:
    libzbar = None


def scan_barcode(device='', timeout=-1, display=True, threaded=False):
    if libzbar is None:
        raise RuntimeError("Cannot start QR scanner; zbar not available.")
    libzbar.zbar_symbol_get_data.restype = ctypes.c_char_p
    libzbar.zbar_processor_create.restype = ctypes.POINTER(ctypes.c_int)
    libzbar.zbar_processor_get_results.restype = ctypes.POINTER(ctypes.c_int)
    libzbar.zbar_symbol_set_first_symbol.restype = ctypes.POINTER(ctypes.c_int)
    proc = libzbar.zbar_processor_create(threaded)
    libzbar.zbar_processor_request_size(proc, 640, 480)
    if libzbar.zbar_processor_init(proc, device.encode('utf-8'), display) != 0:
        raise RuntimeError("Can not start QR scanner; initialization failed.")
    libzbar.zbar_processor_set_visible(proc)
    if libzbar.zbar_process_one(proc, timeout):
        symbols = libzbar.zbar_processor_get_results(proc)
    else:
        symbols = None
    libzbar.zbar_processor_destroy(proc)
    if symbols is None:
        return
    if not libzbar.zbar_symbol_set_get_size(symbols):
        return
    symbol = libzbar.zbar_symbol_set_first_symbol(symbols)
    data = libzbar.zbar_symbol_get_data(symbol)
    return data.decode('utf8')

def _find_system_cameras():
    device_root = "/sys/class/video4linux"
    devices = {} # Name -> device
    if os.path.exists(device_root):
        for device in os.listdir(device_root):
            try:
                with open(os.path.join(device_root, device, 'name')) as f:
                    name = f.read()
            except IOError:
                continue
            name = name.strip('\n')
            devices[name] = os.path.join("/dev", device)
    return devices


if __name__ == "__main__":
    print(scan_barcode())
