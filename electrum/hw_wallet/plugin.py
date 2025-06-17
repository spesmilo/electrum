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
from abc import abstractmethod, ABC
from typing import TYPE_CHECKING, Sequence, Optional, Type, Iterable, Any

from electrum.plugin import (BasePlugin, hook, Device, DeviceMgr,
                             assert_runs_in_hwd_thread, runs_in_hwd_thread)
from electrum.i18n import _
from electrum.bitcoin import is_address, opcodes
from electrum.util import versiontuple, UserFacingException, ChoiceItem
from electrum.transaction import TxOutput, PartialTransaction
from electrum.bip32 import BIP32Node
from electrum.storage import get_derivation_used_for_hw_device_encryption
from electrum.keystore import Xpub, Hardware_KeyStore

if TYPE_CHECKING:
    import threading
    from electrum.plugin import DeviceInfo
    from electrum.wallet import Abstract_Wallet


class HW_PluginBase(BasePlugin, ABC):
    keystore_class: Type['Hardware_KeyStore']
    libraries_available: bool
    SUPPORTED_XTYPES = ()

    # define supported library versions:  minimum_library <= x < maximum_library
    minimum_library = (0,)
    maximum_library = (float('inf'),)

    DEVICE_IDS: Iterable[Any]

    def __init__(self, parent, config, name):
        BasePlugin.__init__(self, parent, config, name)
        self.device = self.keystore_class.device
        self.keystore_class.plugin = self
        self._ignore_outdated_fw = False

    def is_enabled(self):
        return True

    def device_manager(self) -> 'DeviceMgr':
        return self.parent.device_manager

    def create_device_from_hid_enumeration(self, d: dict, *, product_key) -> Optional['Device']:
        # note: id_ needs to be unique between simultaneously connected devices,
        #       and ideally unchanged while a device is connected.
        # Older versions of hid don't provide interface_number
        interface_number = d.get('interface_number', -1)
        usage_page = d['usage_page']
        # id_=str(d['path']) in itself might be sufficient, but this had to be touched
        # a number of times already, so let's just go for the overkill approach:
        id_ = f"{d['path']},{d['serial_number']},{interface_number},{usage_page}"
        device = Device(path=d['path'],
                        interface_number=interface_number,
                        id_=id_,
                        product_key=product_key,
                        usage_page=usage_page,
                        transport_ui_string='hid')
        return device

    @hook
    def close_wallet(self, wallet: 'Abstract_Wallet'):
        for keystore in wallet.get_keystores():
            if isinstance(keystore, self.keystore_class):
                self.device_manager().unpair_pairing_code(keystore.pairing_code())
                if keystore.thread:
                    keystore.thread.stop()

    def get_client(self, keystore: 'Hardware_KeyStore', force_pair: bool = True, *,
                   devices: Sequence['Device'] = None,
                   allow_user_interaction: bool = True) -> Optional['HardwareClientBase']:
        devmgr = self.device_manager()
        handler = keystore.handler
        client = devmgr.client_for_keystore(self, handler, keystore, force_pair,
                                            devices=devices,
                                            allow_user_interaction=allow_user_interaction)
        return client

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
                    or versiontuple(library_version) >= self.maximum_library):
                raise LibraryFoundButUnusable(library_version=library_version)
        except ImportError as e:
            self.libraries_available_message = (
                _("Missing libraries for {}.").format(self.name)
                + f"\n    {e!r}"
            )
            return False
        except LibraryFoundButUnusable as e:
            library_version = e.library_version
            self.libraries_available_message = (
                    _("Library version for '{}' is incompatible.").format(self.name)
                    + '\nInstalled: {}, Needed: {} <= x < {}'
                    .format(library_version, version_str(self.minimum_library), version_str(self.maximum_library)))
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

    def create_client(self, device: 'Device',
                      handler: Optional['HardwareHandlerBase']) -> Optional['HardwareClientBase']:
        raise NotImplementedError()

    def create_handler(self, window) -> 'HardwareHandlerBase':
        # note: in Qt GUI, 'window' is either an ElectrumWindow or an QENewWalletWizard
        raise NotImplementedError()

    def can_recognize_device(self, device: Device) -> bool:
        """Whether the plugin thinks it can handle the given device.
        Used for filtering all connected hardware devices to only those by this vendor.
        """
        return device.product_key in self.DEVICE_IDS

    @abstractmethod
    def wizard_entry_for_device(self, device_info: 'DeviceInfo', *, new_wallet: bool) -> str:
        """Return view name for device
        """
        pass


class HardwareClientBase(ABC):
    handler = None  # type: Optional['HardwareHandlerBase']

    def __init__(self, *, plugin: 'HW_PluginBase'):
        assert_runs_in_hwd_thread()
        self.plugin = plugin

    def device_manager(self) -> 'DeviceMgr':
        return self.plugin.device_manager()

    @abstractmethod
    def is_pairable(self) -> bool:
        pass

    @abstractmethod
    def close(self):
        pass

    def timeout(self, cutoff) -> None:  # noqa: B027
        pass

    @abstractmethod
    def is_initialized(self) -> bool:
        """True if initialized, False if wiped."""
        pass

    def label(self) -> Optional[str]:
        """The name given by the user to the device.

        Note: labels are shown to the user to help distinguish their devices,
        and they are also used as a fallback to distinguish devices programmatically.
        So ideally, different devices would have different labels.
        """
        # When returning a constant here (i.e. not implementing the method in the way
        # it is supposed to work), make sure the return value is in electrum.plugin.PLACEHOLDER_HW_CLIENT_LABELS
        return " "

    def get_soft_device_id(self) -> Optional[str]:
        """An id-like string that is used to distinguish devices programmatically.
        This is a long term id for the device, that does not change between reconnects.
        This method should not prompt the user, i.e. no user interaction, as it is used
        during USB device enumeration (called for each unpaired device).
        Stored in the wallet file.
        """
        root_fp = self.request_root_fingerprint_from_device()
        return root_fp

    @abstractmethod
    def has_usable_connection_with_device(self) -> bool:
        pass

    @abstractmethod
    def get_xpub(self, bip32_path: str, xtype) -> str:
        pass

    @runs_in_hwd_thread
    def request_root_fingerprint_from_device(self) -> str:
        # digitalbitbox (at least) does not reveal xpubs corresponding to unhardened paths
        # so ask for a direct child, and read out fingerprint from that:
        child_of_root_xpub = self.get_xpub("m/0'", xtype='standard')
        root_fingerprint = BIP32Node.from_xkey(child_of_root_xpub).fingerprint.hex().lower()
        return root_fingerprint

    @runs_in_hwd_thread
    def get_password_for_storage_encryption(self) -> str:
        # note: using a different password based on hw device type is highly undesirable! see #5993
        derivation = get_derivation_used_for_hw_device_encryption()
        xpub = self.get_xpub(derivation, "standard")
        password = Xpub.get_pubkey_from_xpub(xpub, ()).hex()
        return password

    def device_model_name(self) -> Optional[str]:
        """Return the name of the model of this device, which might be displayed in the UI.
        E.g. for Trezor, "Trezor One" or "Trezor T".
        If this method is not defined for a plugin, the plugin name is used as default
        """
        return self.plugin.name


class HardwareClientDummy(HardwareClientBase):
    """Hw device we recognize but do not support.
    E.g. for Ledger HW.1 devices that we used to support in the past, but no longer do.
    This allows showing an error message to the user.
    """
    def __init__(self, *, plugin: 'HW_PluginBase', error_text: str):
        HardwareClientBase.__init__(self, plugin=plugin)
        self.error_text = error_text

    def get_xpub(self, bip32_path: str, xtype) -> str:
        raise Exception(self.error_text)

    def is_pairable(self) -> bool:
        return False

    def close(self):
        pass

    def is_initialized(self) -> bool:
        """True if initialized, False if wiped."""
        return True

    def label(self) -> Optional[str]:
        return "dummy_client"

    def has_usable_connection_with_device(self) -> bool:
        return True


class HardwareHandlerBase:
    """An interface between the GUI and the device handling logic for handling I/O."""
    win = None
    device: str

    def get_wallet(self) -> Optional['Abstract_Wallet']:
        if self.win is not None:
            if hasattr(self.win, 'wallet'):
                return self.win.wallet

    def get_gui_thread(self) -> Optional['threading.Thread']:
        if self.win is not None:
            if hasattr(self.win, 'gui_thread'):
                return self.win.gui_thread

    def update_status(self, paired: bool) -> None:
        pass

    def query_choice(self, msg: str, choices: Sequence[ChoiceItem]) -> Optional[Any]:
        """Returns ChoiceItem.key (for selected item), or None if the user cancels the dialog."""
        raise NotImplementedError()

    def yes_no_question(self, msg: str) -> bool:
        raise NotImplementedError()

    def show_message(self, msg: str, on_cancel=None) -> None:
        raise NotImplementedError()

    def show_error(self, msg: str, blocking: bool = False) -> None:
        raise NotImplementedError()

    def finished(self) -> None:
        pass

    def get_word(self, msg: str) -> str:
        raise NotImplementedError()

    def get_passphrase(self, msg: str, confirm: bool) -> Optional[str]:
        raise NotImplementedError()

    def get_pin(self, msg: str, *, show_strength: bool = True) -> str:
        raise NotImplementedError()


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


class OperationCancelled(UserFacingException):
    """Emitted when an operation is cancelled by user on a HW device
    """
    pass
