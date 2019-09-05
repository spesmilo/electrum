#!/usr/bin/env python3
#
# Electron Cash - lightweight Bitcoin Cash client
# Copyright (C) 2016  The Electrum developers
# Copyright (C) 2019  The Electron Cash developers
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

from electroncash.plugins import BasePlugin, hook
from electroncash.i18n import _, ngettext
from electroncash import Transaction
from electroncash.bitcoin import TYPE_SCRIPT
from electroncash.util import bfh, finalization_print_error
from electroncash.address import OpCodes, Address, Script

class HW_PluginBase(BasePlugin):
    # Derived classes provide:
    #
    #  class-static variables: client_class, firmware_URL, handler_class,
    #     libraries_available, libraries_URL, minimum_firmware,
    #     wallet_class, ckd_public, types, HidTransport

    def __init__(self, parent, config, name):
        BasePlugin.__init__(self, parent, config, name)
        self.device = self.keystore_class.device
        self.keystore_class.plugin = self

    def is_enabled(self):
        return True

    def device_manager(self):
        return self.parent.device_manager

    @hook
    def close_wallet(self, wallet):
        for keystore in wallet.get_keystores():
            if isinstance(keystore, self.keystore_class):
                self.device_manager().unpair_xpub(keystore.xpub)
                self._cleanup_keystore_extra(keystore)

    def _cleanup_keystore_extra(self, keystore):
        # awkward cleanup code for the keystore 'thread' object (see qt.py)
        finalization_print_error(keystore)  # track object lifecycle
        if callable(getattr(keystore.thread, 'stop', None)):
            keystore.thread.stop()

    def show_address(self, wallet, address, keystore=None):
        pass  # implemented in child classes

    def show_address_helper(self, wallet, address, keystore=None):
        if keystore is None:
            keystore = wallet.get_keystore()
        if not wallet.is_mine(address):
            keystore.handler.show_error(_('Address not in wallet.'))
            return False
        if type(keystore) != self.keystore_class:
            return False
        return True

def is_any_tx_output_on_change_branch(tx: Transaction) -> bool:
    if not tx.output_info:
        return False
    for o in tx.outputs():
        info = tx.output_info.get(o[1])
        if info is not None:
            if info[0][0] == 1:
                return True
    return False

def validate_op_return_output_and_get_data(output: tuple,        # tuple(typ, 'address', amount)
                                           max_size: int = 220,  # in bytes
                                           max_pushes: int = 1   # number of pushes supported after the OP_RETURN, most HW wallets support only 1 push, some more than 1.  Specify None to omit the number-of-pushes check.
                                           ) -> bytes:  # will return address.script[2:] (everyting after the first OP_RETURN & PUSH bytes)
    _type, address, _amount = output

    if max_pushes is None:
        # Caller says "no limit", so just to keep the below code simple, we
        # do this and effectively sets the limit on pushes to "unlimited",
        # since there can never be more pushes than bytes in the payload!
        max_pushes = max_size

    assert max_pushes >= 1

    if _type != TYPE_SCRIPT:
        raise Exception("Unexpected output type: {}".format(_type))

    ops = Script.get_ops(address.script)

    num_pushes = len(ops) - 1

    if len(ops) < 1 or ops[0][0] != OpCodes.OP_RETURN:
        raise RuntimeError(_("Only OP_RETURN scripts are supported."))

    if num_pushes < 1 or num_pushes > max_pushes or any(ops[i+1][1] is None for i in range(num_pushes)):
        raise RuntimeError(ngettext("OP_RETURN is limited to {max_pushes} data push.",
                                    "OP_RETURN is limited to {max_pushes} data pushes.",
                                    max_pushes).format(max_pushes=max_pushes))

    data = address.script[2:]  # caller expects everything after the OP_RETURN and PUSHDATA op

    if len(data) > max_size:
        raise RuntimeError(_("OP_RETURN data size exceeds the maximum of {} bytes.".format(max_size)))

    if _amount != 0:
        raise RuntimeError(_("Amount for OP_RETURN output must be zero."))

    return data

def only_hook_if_libraries_available(func):
    # note: this decorator must wrap @hook, not the other way around,
    # as 'hook' uses the name of the function it wraps
    def wrapper(self, *args, **kwargs):
        if not self.libraries_available: return None
        return func(self, *args, **kwargs)
    return wrapper
