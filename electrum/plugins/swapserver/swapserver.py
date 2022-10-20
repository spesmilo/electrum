#!/usr/bin/env python
#
# Electrum - Lightweight Bitcoin Client
# Copyright (C) 2023 The Electrum Developers
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


import asyncio
import os
import random
from electrum.plugin import BasePlugin, hook
from electrum.util import log_exceptions, ignore_exceptions
from electrum import ecc

from .server import SwapServer


class SwapServerPlugin(BasePlugin):

    def __init__(self, parent, config, name):
        BasePlugin.__init__(self, parent, config, name)
        self.config = config
        self.server = None

    @hook
    def daemon_wallet_loaded(self, daemon, wallet):
        # we use the first wallet loaded
        if self.server is not None:
            return
        if self.config.get('offline'):
            return

        self.server = SwapServer(self.config, wallet)
        sm = wallet.lnworker.swap_manager
        jobs = [
            sm.pay_pending_invoices(),
            self.server.run(),
        ]
        asyncio.run_coroutine_threadsafe(daemon._run(jobs=jobs), daemon.asyncio_loop)
