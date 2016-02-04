#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2012 thomasv@gitorious
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#
# Kivy GUI

import sys
import os
os.environ['KIVY_DATA_DIR'] = os.path.abspath(os.path.dirname(__file__)) + '/data/'

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
        self.network = daemon.network
        self.config = config
        self.plugins = plugins

    def main(self):
        w = ElectrumWindow(config=self.config,
                           network=self.network,
                           plugins = self.plugins,
                           gui_object=self)
        w.run()
