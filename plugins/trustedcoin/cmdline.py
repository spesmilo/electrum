#!/usr/bin/env python
#
# Electrum - Lightweight Bitcoin Client
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

from functools import partial
from threading import Thread
import re
from decimal import Decimal

from PyQt5.QtGui import *
from PyQt5.QtCore import *

from electrum_gui.qt.util import *
from electrum_gui.qt.qrcodewidget import QRCodeWidget
from electrum_gui.qt.amountedit import AmountEdit
from electrum_gui.qt.main_window import StatusBarButton
from electrum.i18n import _
from electrum.plugins import hook
from .trustedcoin import TrustedCoinPlugin, server


class QTOSSignalObject(QObject):
    two_factor_tos_signal = pyqtSignal()


class Plugin(TrustedCoinPlugin):

    @hook
    def sign_tx(self, wallet, tx):
        if not isinstance(wallet, self.wallet_class):
            return
        if not wallet.can_sign_without_server():
            self.print_error("twofactor:sign_tx")
            auth_code = None
            if wallet.keystores['x3/'].get_tx_derivations(tx):
                msg = _('Please enter your Google Authenticator code:')
                auth_code = int(input(msg))
            else:
                self.print_error("twofactor: xpub3 not needed")
            wallet.auth_code = auth_code

