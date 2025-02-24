# This file is part of the Trezor project.
#
# Copyright (C) 2012-2018 SatoshiLabs and contributors
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3
# as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the License along with this library.
# If not, see <https://www.gnu.org/licenses/lgpl-3.0.html>.

import importlib
import logging
import sys
import time
import atexit

from .transport import Transport, ConnectionError

import usb1

_libusb_version = usb1.getVersion()
_libusb_version = (_libusb_version.major, _libusb_version.minor, _libusb_version.micro)

class FakeRead(object):
    # Let's pretend we have a file-like interface
    def __init__(self, func):
        self.func = func

    def read(self, size):
        return self.func(size)

DEVICE_IDS = [
    (0x2B24, 0x0002),  # KeepKey
]

class WebUsbTransport(Transport):
    """
    WebUsbTransport implements transport over WebUSB interface.
    """

    context = None

    def __init__(self, device, *args, **kwargs):
        self.buffer = bytearray()

        if kwargs.get("debug_link", False):
            self.interface = 1
            self.endpoint = 2
        else:
            self.interface = 0
            self.endpoint = 1

        self.device = device
        self.handle = None

        super(WebUsbTransport, self).__init__(device, *args, **kwargs)

    def _open(self):
        self.handle = self.device.open()
        if self.handle is None:
            if sys.platform.startswith("linux"):
                args = (UDEV_RULES_STR,)
            else:
                args = ()
            raise IOError("Cannot open device", *args)

        self.handle.claimInterface(self.interface)

    def _close(self):
        if self.handle is not None:
            self.handle.releaseInterface(self.interface)
            self.handle.close()
        self.handle = None

    @classmethod
    def enumerate(cls):
        if not cls.context:
            cls.context = usb1.USBContext()
            cls.context.open()
            atexit.register(cls.context.close)

        devices = []
        for dev in cls.context.getDeviceIterator(skip_on_error=True):

            usb_id = (dev.getVendorID(), dev.getProductID())
            if usb_id not in DEVICE_IDS:
                continue
            try:
                # Workaround for libusb < 1.0.22 on windows
                if sys.platform == 'win32' and _libusb_version < (1, 0, 22):
                    # this windows workaround pulled from github.com/trezor/python-trezor
                    # workaround for issue #223:
                    # on certain combinations of Windows USB drivers and libusb versions,
                    # Trezor is returned twice (possibly because Windows know it as both
                    # a HID and a WebUSB device), and one of the returned devices is
                    # non-functional.
                    dev.getProduct()
                devices.append(dev)
            except usb1.USBErrorNotSupported:
                pass

        return devices

    def _write(self, msg, protobuf_msg):

        msg = bytearray(msg)
        while len(msg):
            # add reportID and padd with zeroes if necessary
            self.handle.interruptWrite(self.endpoint, [63, ] + list(msg[:63]) + [0] * (63 - len(msg[:63])))
            msg = msg[63:]

    def _read(self):
        (msg_type, datalen) = self._read_headers(FakeRead(self._raw_read))
        return (msg_type, self._raw_read(datalen))

    def _raw_read(self, length):
        start = time.time()
        endpoint = 0x80 | self.endpoint
        while len(self.buffer) < length:
            while True:
                data = self.handle.interruptRead(endpoint, 64)
                if data:
                    break
                else:
                    time.sleep(0.001)

            if len(data) != 64:
                raise TransportException("Unexpected chunk size: %d" % len(chunk))

            self.buffer.extend(bytearray(data[1:]))

        ret = self.buffer[:length]
        self.buffer = self.buffer[length:]
        return bytes(ret)

