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

import ctypes
import usb1
import sys

_libusb_version = usb1.getVersion()
_libusb_version = (_libusb_version.major, _libusb_version.minor, _libusb_version.micro)

_libusb_use_set_option = sys.platform == 'win32' and _libusb_version >= (1, 0, 22)

if _libusb_use_set_option:
    # Needs to be CFUNCTYPE as only that allows variadic arguments
    libusb_set_option_prototype = ctypes.CFUNCTYPE(ctypes.c_int, usb1.libusb1.libusb_context_p, ctypes.c_int, ctypes.c_int)
    libusb_set_option = libusb_set_option_prototype(("libusb_set_option", usb1.libusb1.libusb))

    LIBUSB_OPTION_IGNORE_HID_ACCESS_DENIED = 2

def _USBDevice_getPath(self):
    return ":".join(str(x) for x in ["%03i" % (self.getBusNumber(),)] + self.getPortNumberList())

usb1.USBDevice.getPath = _USBDevice_getPath

class USBContext(usb1.USBContext):
    def open(self):
        res = super().open()
        if _libusb_use_set_option:
            # Ignore access denied errors when opening the HID interface of composite devices
            libusb_set_option(self.__context_p, LIBUSB_OPTION_IGNORE_HID_ACCESS_DENIED, 1)
        return res
