#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2025 The Electrum Developers
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
from electrum.util import print_stderr, raw_input
from electrum.logging import get_logger

from .plugin import HardwareHandlerBase


_logger = get_logger(__name__)


class CmdLineHandler(HardwareHandlerBase):

    def get_passphrase(self, msg, confirm):
        import getpass
        print_stderr(msg)
        return getpass.getpass('')

    def get_pin(self, msg, *, show_strength=True):
        t = {'a': '7', 'b': '8', 'c': '9', 'd': '4', 'e': '5', 'f': '6', 'g': '1', 'h': '2', 'i': '3'}
        t.update({str(i): str(i) for i in range(1, 10)})  # sneakily also support numpad-conversion
        print_stderr(msg)
        print_stderr("a b c\nd e f\ng h i\n-----")
        o = raw_input()
        try:
            return ''.join(map(lambda x: t[x], o))
        except KeyError as e:
            raise Exception("Character {} not in matrix!".format(e)) from e

    def prompt_auth(self, msg):
        import getpass
        print_stderr(msg)
        response = getpass.getpass('')
        if len(response) == 0:
            return None
        return response

    def yes_no_question(self, msg):
        print_stderr(msg)
        return raw_input() in 'yY'

    def stop(self):
        pass

    def show_message(self, msg, on_cancel=None):
        print_stderr(msg)

    def show_error(self, msg, blocking=False):
        print_stderr(msg)

    def update_status(self, b):
        _logger.info(f'hw device status {b}')

    def finished(self):
        pass
