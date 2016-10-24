#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2012 thomasv@gitorious
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
#
# Kivy GUI

import sys
import os

try:
    sys.argv = ['']
    import kivy
except ImportError:
    # This error ideally shouldn't raised with pre-built packages
    sys.exit("Error: Could not import kivy. Please install it using the" + \
             "instructions mentioned here `http://kivy.org/#download` .")

# minimum required version for kivy
kivy.require('1.8.0')
from kivy.logger import Logger
from main_window import ElectrumWindow




class ElectrumGui:

    def __init__(self, config, daemon, plugins):
        Logger.debug('ElectrumGUI: initialising')
        self.daemon = daemon
        self.network = daemon.network
        self.config = config
        self.plugins = plugins

    def main(self):
        self.config.open_last_wallet()
        w = ElectrumWindow(config=self.config,
                           network=self.network,
                           plugins = self.plugins,
                           gui_object=self)
        w.run()
        if w.wallet:
            self.config.save_last_wallet(w.wallet)
