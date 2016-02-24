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
from i18n import _

try:
    import zbar
except ImportError:
    zbar = None

proc = None


def scan_qr(config):
    global proc
    if not zbar:
        raise RuntimeError("\n".join([_("Cannot start QR scanner."),_("The zbar package is not available."),_("On Linux, try 'sudo pip install zbar'")]))
    if proc is None:
        device = config.get("video_device", "default")
        if device == 'default':
            device = ''
        _proc = zbar.Processor()
        _proc.init(video_device=device)
        # set global only if init did not raise an exception
        proc = _proc


    proc.visible = True
    while True:
        try:
            proc.process_one()
        except Exception:
            # User closed the preview window
            return ""
        for r in proc.results:
            if str(r.type) != 'QRCODE':
                continue
            # hiding the preview window stops the camera
            proc.visible = False
            return r.data

def _find_system_cameras():
    device_root = "/sys/class/video4linux"
    devices = {} # Name -> device
    if os.path.exists(device_root):
        for device in os.listdir(device_root):
            name = open(os.path.join(device_root, device, 'name')).read()
            name = name.strip('\n')
            devices[name] = os.path.join("/dev",device)
    return devices
