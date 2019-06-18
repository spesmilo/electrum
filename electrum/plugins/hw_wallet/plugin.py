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
from electrum.bitcoin import is_address, TYPE_SCRIPT, opcodes
from electrum.util import bfh, versiontuple, UserFacingException
from electrum.transaction import TxOutput, Transaction


class HW_PluginBase(BasePlugin):
    # Derived classes provide:
    #
    #  class-static variables: client_class, firmware_URL, handler_class,
    #     libraries_available, libraries_URL, minimum_firmware,
    #     wallet_class, ckd_public, types, HidTransport

    minimum_library = (0, )

    def __init__(self, parent, config, name):
        BasePlugin.__init__(self, parent, config, name)
        self.device = self.keystore_class.device
        self.keystore_class.plugin = self
        self._ignore_outdated_fw = False

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

    def get_library_version(self) -> str:
        """Returns the version of the 3rd party python library
        for the hw wallet. For example '0.9.0'

        Returns 'unknown' if library is found but cannot determine version.
        Raises 'ImportError' if library is not found.
        Raises 'LibraryFoundButUnusable' if found but there was some problem (includes version num).
        """
        raise NotImplementedError()

    def check_libraries_available(self) -> bool:
        def version_str(t):
            return ".".join(str(i) for i in t)

        try:
            # this might raise ImportError or LibraryFoundButUnusable
            library_version = self.get_library_version()
            # if no exception so far, we might still raise LibraryFoundButUnusable
            if (library_version == 'unknown'
                    or versiontuple(library_version) < self.minimum_library
                    or hasattr(self, "maximum_library") and versiontuple(library_version) >= self.maximum_library):
                raise LibraryFoundButUnusable(library_version=library_version)
        except ImportError:
            return False
        except LibraryFoundButUnusable as e:
            library_version = e.library_version
            max_version_str = version_str(self.maximum_library) if hasattr(self, "maximum_library") else "inf"
            self.libraries_available_message = (
                    _("Library version for '{}' is incompatible.").format(self.name)
                    + '\nInstalled: {}, Needed: {} <= x < {}'
                    .format(library_version, version_str(self.minimum_library), max_version_str))
            self.logger.warning(self.libraries_available_message)
            return False

        return True

    def get_library_not_available_message(self) -> str:
        if hasattr(self, 'libraries_available_message'):
            message = self.libraries_available_message
        else:
            message = _("Missing libraries for {}.").format(self.name)
        message += '\n' + _("Make sure you install it with python3")
        return message

    def set_ignore_outdated_fw(self):
        self._ignore_outdated_fw = True

    def is_outdated_fw_ignored(self) -> bool:
        return self._ignore_outdated_fw


def is_any_tx_output_on_change_branch(tx: Transaction):
    if not tx.output_info:
        return False
    for o in tx.outputs():
        info = tx.output_info.get(o.address)
        if info is not None:
            if info.address_index[0] == 1:
                return True
    return False


def trezor_validate_op_return_output_and_get_data(output: TxOutput) -> bytes:
    if output.type != TYPE_SCRIPT:
        raise Exception("Unexpected output type: {}".format(output.type))
    script = bfh(output.address)
    if not (script[0] == opcodes.OP_RETURN and
            script[1] == len(script) - 2 and script[1] <= 75):
        raise UserFacingException(_("Only OP_RETURN scripts, with one constant push, are supported."))
    if output.value != 0:
        raise UserFacingException(_("Amount for OP_RETURN output must be zero."))
    return script[2:]


def only_hook_if_libraries_available(func):
    # note: this decorator must wrap @hook, not the other way around,
    # as 'hook' uses the name of the function it wraps
    def wrapper(self, *args, **kwargs):
        if not self.libraries_available: return None
        return func(self, *args, **kwargs)
    return wrapper


class LibraryFoundButUnusable(Exception):
    def __init__(self, library_version='unknown'):
        self.library_version = library_version


class OutdatedHwFirmwareException(UserFacingException):

    def text_ignore_old_fw_and_continue(self) -> str:
        suffix = (_("The firmware of your hardware device is too old. "
                    "If possible, you should upgrade it. "
                    "You can ignore this error and try to continue, however things are likely to break.") + "\n\n" +
                  _("Ignore and continue?"))
        if str(self):
            return str(self) + "\n\n" + suffix
        else:
            return suffix
