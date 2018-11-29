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
elif sys.platform in ('windows', 'win32'):
    name = 'libzbar-0.dll'
else:
    name = 'libzbar.so.0'

try:
    libzbar = ctypes.cdll.LoadLibrary(name)
except BaseException:
    libzbar = None


def scan_barcode_ctypes(device='', timeout=-1, display=True, threaded=False, try_again=True):
    if libzbar is None:
        raise RuntimeError("Cannot start QR scanner; zbar not available.")
    libzbar.zbar_symbol_get_data.restype = ctypes.c_char_p
    libzbar.zbar_processor_create.restype = ctypes.POINTER(ctypes.c_int)
    libzbar.zbar_processor_get_results.restype = ctypes.POINTER(ctypes.c_int)
    libzbar.zbar_symbol_set_first_symbol.restype = ctypes.POINTER(ctypes.c_int)
    proc = libzbar.zbar_processor_create(threaded)
    libzbar.zbar_processor_request_size(proc, 640, 480)
    if libzbar.zbar_processor_init(proc, device.encode('utf-8'), display) != 0:
        if try_again:
            # workaround for a bug in "ZBar for Windows"
            # libzbar.zbar_processor_init always seem to fail the first time around
            return scan_barcode(device, timeout, display, threaded, try_again=False)
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

def scan_barcode_osx(*args_ignored, **kwargs_ignored):
    import subprocess
    # NOTE: This code needs to be modified if the positions of this file changes with respect to the helper app!
    # This assumes the built macOS .app bundle which ends up putting the helper app in
    # .app/contrib/osx/CalinsQRReader/build/Release/CalinsQRReader.app.
    root_ec_dir = os.path.abspath(os.path.dirname(__file__) + "/../")
    prog = root_ec_dir + "/" + "contrib/osx/CalinsQRReader/build/Release/CalinsQRReader.app/Contents/MacOS/CalinsQRReader"
    if not os.path.exists(prog):
        raise RuntimeError("Cannot start QR scanner; helper app not found.")
    data = ''
    try:
        # This will run the "CalinsQRReader" helper app (which also gets bundled with the built .app)
        # Just like the zbar implementation -- the main app will hang until the QR window returns a QR code
        # (or is closed). Communication with the subprocess is done via stdout.
        # See contrib/CalinsQRReader for the helper app source code.
        with subprocess.Popen([prog], stdout=subprocess.PIPE) as p:
            data = p.stdout.read().decode('utf-8').strip()
        return data
    except OSError as e:
        raise RuntimeError("Cannot start camera helper app; {}".format(e.strerror))

scan_barcode = scan_barcode_osx if sys.platform == 'darwin' else scan_barcode_ctypes

def _find_system_cameras():
    device_root = "/sys/class/video4linux"
    devices = {} # Name -> device
    if os.path.exists(device_root):
        for device in os.listdir(device_root):
            path = os.path.join(device_root, device, 'name')
            try:
                with open(path, encoding='utf-8') as f:
                    name = f.read()
            except Exception:
                continue
            name = name.strip('\n')
            devices[name] = os.path.join("/dev", device)
    return devices


if __name__ == "__main__":
    print(scan_barcode())
