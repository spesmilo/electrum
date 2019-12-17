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

from typing import TYPE_CHECKING, Dict, List, Union, Tuple, Sequence, Optional, Type

from electrum.plugin import BasePlugin, hook, Device, DeviceMgr
from electrum.i18n import _
from electrum.bitcoin import is_address, opcodes
from electrum.util import bfh, versiontuple, UserFacingException
from electrum.transaction import TxOutput, Transaction, PartialTransaction, PartialTxInput, PartialTxOutput
from electrum.bip32 import BIP32Node

if TYPE_CHECKING:
    from electrum.wallet import Abstract_Wallet
    from electrum.keystore import Hardware_KeyStore


class HW_PluginBase(BasePlugin):
    keystore_class: Type['Hardware_KeyStore']
    libraries_available: bool

    minimum_library = (0, )

    def __init__(self, parent, config, name):
        BasePlugin.__init__(self, parent, config, name)
        self.device = self.keystore_class.device
        self.keystore_class.plugin = self
        self._ignore_outdated_fw = False

    def is_enabled(self):
        return True

    def device_manager(self) -> 'DeviceMgr':
        return self.parent.device_manager

    @hook
    def close_wallet(self, wallet: 'Abstract_Wallet'):
        for keystore in wallet.get_keystores():
            if isinstance(keystore, self.keystore_class):
                self.device_manager().unpair_xpub(keystore.xpub)

    def setup_device(self, device_info, wizard, purpose):
        """Called when creating a new wallet or when using the device to decrypt
        an existing wallet. Select the device to use.  If the device is
        uninitialized, go through the initialization process.
        """
        raise NotImplementedError()

    def get_client(self, keystore: 'Hardware_KeyStore', force_pair: bool = True):
        raise NotImplementedError()

    def show_address(self, wallet: 'Abstract_Wallet', address, keystore: 'Hardware_KeyStore' = None):
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

    def create_client(self, device: 'Device', handler) -> Optional['HardwareClientBase']:
        raise NotImplementedError()

    def get_xpub(self, device_id, derivation: str, xtype, wizard) -> str:
        raise NotImplementedError()


class HardwareClientBase:

    def is_pairable(self) -> bool:
        raise NotImplementedError()

    def close(self):
        raise NotImplementedError()

    def timeout(self, cutoff) -> None:
        pass

    def is_initialized(self) -> bool:
        """True if initialized, False if wiped."""
        raise NotImplementedError()

    def label(self) -> Optional[str]:
        """The name given by the user to the device.

        Note: labels are shown to the user to help distinguish their devices,
        and they are also used as a fallback to distinguish devices programmatically.
        So ideally, different devices would have different labels.
        """
        raise NotImplementedError()

    def has_usable_connection_with_device(self) -> bool:
        raise NotImplementedError()

    def get_xpub(self, bip32_path: str, xtype) -> str:
        raise NotImplementedError()

    def request_root_fingerprint_from_device(self) -> str:
        # digitalbitbox (at least) does not reveal xpubs corresponding to unhardened paths
        # so ask for a direct child, and read out fingerprint from that:
        child_of_root_xpub = self.get_xpub("m/0'", xtype='standard')
        root_fingerprint = BIP32Node.from_xkey(child_of_root_xpub).fingerprint.hex().lower()
        return root_fingerprint


def is_any_tx_output_on_change_branch(tx: PartialTransaction) -> bool:
    return any([txout.is_change for txout in tx.outputs()])


def trezor_validate_op_return_output_and_get_data(output: TxOutput) -> bytes:
    validate_op_return_output(output)
    script = output.scriptpubkey
    if not (script[0] == opcodes.OP_RETURN and
            script[1] == len(script) - 2 and script[1] <= 75):
        raise UserFacingException(_("Only OP_RETURN scripts, with one constant push, are supported."))
    return script[2:]


def validate_op_return_output(output: TxOutput, *, max_size: int = None) -> None:
    script = output.scriptpubkey
    if script[0] != opcodes.OP_RETURN:
        raise UserFacingException(_("Only OP_RETURN scripts are supported."))
    if max_size is not None and len(script) > max_size:
        raise UserFacingException(_("OP_RETURN payload too large." + "\n"
                                  + f"(scriptpubkey size {len(script)} > {max_size})"))
    if output.value != 0:
        raise UserFacingException(_("Amount for OP_RETURN output must be zero."))


def get_xpubs_and_der_suffixes_from_txinout(tx: PartialTransaction,
                                            txinout: Union[PartialTxInput, PartialTxOutput]) \
        -> List[Tuple[str, List[int]]]:
    xfp_to_xpub_map = {xfp: bip32node for bip32node, (xfp, path)
                       in tx.xpubs.items()}  # type: Dict[bytes, BIP32Node]
    xfps = [txinout.bip32_paths[pubkey][0] for pubkey in txinout.pubkeys]
    try:
        xpubs = [xfp_to_xpub_map[xfp] for xfp in xfps]
    except KeyError as e:
        raise Exception(f"Partial transaction is missing global xpub for "
                        f"fingerprint ({str(e)}) in input/output") from e
    xpubs_and_deriv_suffixes = []
    for bip32node, pubkey in zip(xpubs, txinout.pubkeys):
        xfp, path = txinout.bip32_paths[pubkey]
        der_suffix = list(path)[bip32node.depth:]
        xpubs_and_deriv_suffixes.append((bip32node.to_xpub(), der_suffix))
    return xpubs_and_deriv_suffixes


def only_hook_if_libraries_available(func):
    # note: this decorator must wrap @hook, not the other way around,
    # as 'hook' uses the name of the function it wraps
    def wrapper(self: 'HW_PluginBase', *args, **kwargs):
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
