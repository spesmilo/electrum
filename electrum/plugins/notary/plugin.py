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


import asyncio
import os
import random
import electrum_ecc as ecc

from electrum.plugin import BasePlugin, hook
from electrum.util import log_exceptions, ignore_exceptions, OldTaskGroup
from electrum import bitcoin

from .notary import Notary
from .server import NotaryServer


class NotaryPlugin(BasePlugin):

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
        self.notary = Notary(self.config, wallet)
        self.server = NotaryServer(self.config, wallet, self.notary)
        asyncio.run_coroutine_threadsafe(self.main_loop(), daemon.asyncio_loop)

    async def main_loop(self):
        print('running notary jobs')
        jobs = [
            self.notary.run(),
            self.notary.publish_proofs(),
            self.server.run(),
        ]
        self.taskgroup = OldTaskGroup()
        async with self.taskgroup as group:
            for task in jobs:
                await group.spawn(task)
