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
from typing import TYPE_CHECKING

from electrum_grs.plugin import BasePlugin, hook

from .server import SwapServer

if TYPE_CHECKING:
    from electrum_grs.simple_config import SimpleConfig
    from electrum_grs.daemon import Daemon
    from electrum_grs.wallet import Abstract_Wallet


class SwapServerPlugin(BasePlugin):

    def __init__(self, parent, config: 'SimpleConfig', name):
        BasePlugin.__init__(self, parent, config, name)
        self.config = config
        self.server = None

    @hook
    def daemon_wallet_loaded(self, daemon: 'Daemon', wallet: 'Abstract_Wallet'):
        # we use the first wallet loaded
        if self.server is not None:
            return
        if self.config.NETWORK_OFFLINE:
            return

        self.server = SwapServer(self.config, wallet)
        sm = wallet.lnworker.swap_manager
        for coro in [
            sm.pay_pending_invoices(),  # FIXME this method can raise, which is not properly handled...?
            self.server.run(),
        ]:
            asyncio.run_coroutine_threadsafe(daemon.taskgroup.spawn(coro), daemon.asyncio_loop)
