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
from electrum.util import print_error, print_msg, parse_url

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

    def __init__(self, config, network, app=None):
        Logger.debug('ElectrumGUI: initialising')
        self.network = network
        self.config = config

        #:TODO
        # implement kivy plugin mechanism that needs to be more extensible
        # and integrated into the ui so can't be common with existing plugin
        # base
        #init_plugins(self)

    def set_url(self, url):
        from electrum import util
        from decimal import Decimal

        try:
            address, amount, label, message,\
                request_url, url = util.parse_url(url)
        except Exception:
            self.main_window.show_error(_('Invalid bitcoin URL'))
            return

        if amount:
            try:
                if main_window.base_unit == 'mBTC':
                    amount = str( 1000* Decimal(amount))
                else:
                    amount = str(Decimal(amount))
            except Exception:
                amount = "0.0"
                self.main_window.show_error(_('Invalid Amount'))

        if request_url:
            try:
                from electrum import paymentrequest
            except:
                self.main_window.show_error("cannot import payment request")
                request_url = None

        if not request_url:
            self.main_window.set_send(address, amount, label, message)
            return

        def payment_request():
            self.payment_request = paymentrequest.PaymentRequest(request_url)
            if self.payment_request.verify():
                Clock.schedule_once(self.main_window.payment_request_ok)
            else:
                Clock.schedule_once(self.main_window.payment_request_error)

        threading.Thread(target=payment_request).start()
        self.main_window.prepare_for_payment_request()

    def main(self, url):
        ''' The main entry point of the kivy ux
        :param url: 'bitcoin:' uri as mentioned in bip0021
        :type url: str
        :ref: https://github.com/bitcoin/bips/blob/master/bip-0021.mediawiki
        '''

        self.main_window = w = ElectrumWindow(config=self.config,
                                              network=self.network,
                                              url=url,
                                              gui_object=self)
        w.run()