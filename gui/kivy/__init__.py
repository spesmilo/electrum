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
#, time, datetime, re, threading
#from electrum.i18n import _, set_language
from electrum.util import print_error, print_msg

#:TODO: replace this with kivy's own plugin managment
#from electrum.plugins import run_hook
#import os.path, json, ast, traceback
#import shutil

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

from electrum.bitcoin import MIN_RELAY_TX_FEE

from main_window import ElectrumWindow
#from electrum.plugins import init_plugins

#:TODO find a equivalent method to register to `bitcoin:` uri
#: ref: http://stackoverflow.com/questions/30931/register-file-extensions-mime-types-in-linux
#class OpenFileEventFilter(object):
#    def __init__(self, windows):
#        self.windows = windows
#        super(OpenFileEventFilter, self).__init__()
#
#    def eventFilter(self, obj, event):
#        if event.type() == QtCore.QEvent.FileOpen:
#            if len(self.windows) >= 1:
#                self.windows[0].set_url(event.url().toEncoded())
#                return True
#        return False

class ElectrumGui:

    def __init__(self, config, network, plugins, app=None):
        Logger.debug('ElectrumGUI: initialising')
        self.network = network
        self.config = config
        self.plugins = plugins

        #:TODO
        # implement kivy plugin mechanism that needs to be more extensible
        # and integrated into the ui so can't be common with existing plugin
        # base
        #init_plugins(self)

    def main(self):
        ''' The main entry point of the kivy ux
        :param url: 'bitcoin:' uri as mentioned in bip0021
        :type url: str
        :ref: https://github.com/bitcoin/bips/blob/master/bip-0021.mediawiki
        '''

        self.main_window = w = ElectrumWindow(config=self.config,
                                              network=self.network,
                                              plugins = self.plugins,
                                              gui_object=self)
        w.run()
