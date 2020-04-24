#!/usr/bin/env python2
# -*- mode: python -*-
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2016  The Electrum developers
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

from electrum.plugin import BasePlugin, hook
from electrum.i18n import _
from electrum.bitcoin import is_address, TYPE_SCRIPT
from electrum.util import bfh
from electrum.transaction import opcodes, TxOutput


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

    def setup_device(self, device_info, wizard, purpose):
        """Called when creating a new wallet or when using the device to decrypt
        an existing wallet. Select the device to use.  If the device is
        uninitialized, go through the initialization process.
        """
        raise NotImplementedError()

    def show_address(self, wallet, address, keystore=None):
        pass  # implemented in child classes

    def show_address_helper(self, wallet, address, keystore=None):
        if keystore is None:
            keystore = wallet.get_keystore()
        if not is_address(address):
            keystore.handler.show_error(_('Invalid Bitcoin Address'))
            return False
        if not wallet.is_mine(address):
            keystore.handler.show_error(_('Address not in wallet.'))
            return False
        if type(keystore) != self.keystore_class:
            return False
        return True


def is_any_tx_output_on_change_branch(tx):
    if not hasattr(tx, 'output_info'):
        return False
    for _type, address, amount, *args in tx.outputs():
        info = tx.output_info.get(address)
        if info is not None:
            index, xpubs, m = info
            if index[0] == 1:
                return True
    return False


def trezor_validate_op_return_output_and_get_data(output: TxOutput) -> bytes:
    if output.type != TYPE_SCRIPT:
        raise Exception("Unexpected output type: {}".format(output.type))
    script = bfh(output.address)
    if not (script[0] == opcodes.OP_RETURN and
            script[1] == len(script) - 2 and script[1] <= 75):
        raise Exception(_("Only OP_RETURN scripts, with one constant push, are supported."))
    if output.value != 0:
        raise Exception(_("Amount for OP_RETURN output must be zero."))
    return script[2:]
