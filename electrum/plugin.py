#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2015-2024 Thomas Voegtlin
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

import os
import pkgutil
import importlib.util
import time
import threading
import traceback
import sys
import aiohttp

from typing import (NamedTuple, Any, Union, TYPE_CHECKING, Optional, Tuple,
                    Dict, Iterable, List, Sequence, Callable, TypeVar, Mapping)
import concurrent
import zipimport
from concurrent import futures
from functools import wraps, partial

from .i18n import _
from .util import (profiler, DaemonThread, UserCancelled, ThreadJob, UserFacingException)
from . import bip32
from . import plugins
from .simple_config import SimpleConfig
from .logging import get_logger, Logger

if TYPE_CHECKING:
    from .plugins.hw_wallet import HW_PluginBase, HardwareClientBase, HardwareHandlerBase
    from .keystore import Hardware_KeyStore, KeyStore
    from .wallet import Abstract_Wallet


_logger = get_logger(__name__)
plugin_loaders = {}
hook_names = set()
hooks = {}


class Plugins(DaemonThread):

    LOGGING_SHORTCUT = 'p'
    pkgpath = os.path.dirname(plugins.__file__)

    @profiler
    def __init__(self, config: SimpleConfig, gui_name):
        DaemonThread.__init__(self)
        self.name = 'Plugins'  # set name of thread
        self.config = config
        self.hw_wallets = {}
        self.plugins = {}  # type: Dict[str, BasePlugin]
        self.internal_plugin_metadata = {}
        self.external_plugin_metadata = {}
        self.gui_name = gui_name
        self.device_manager = DeviceMgr(config)
        self.user_pkgpath = os.path.join(self.config.electrum_path_root(), 'plugins')
        if not os.path.exists(self.user_pkgpath):
            os.mkdir(self.user_pkgpath)
        self.find_internal_plugins()
        self.find_external_plugins()
        self.load_plugins()
        self.add_jobs(self.device_manager.thread_jobs())
        self.start()

    @property
    def descriptions(self):
        return dict(list(self.internal_plugin_metadata.items()) + list(self.external_plugin_metadata.items()))

    def find_internal_plugins(self):
        """Populates self.internal_plugin_metadata
        """
        iter_modules = list(pkgutil.iter_modules([self.pkgpath]))
        for loader, name, ispkg in iter_modules:
            # FIXME pyinstaller binaries are packaging each built-in plugin twice:
            #       once as data and once as code. To honor the "no duplicates" rule below,
            #       we exclude the ones packaged as *code*, here:
            if loader.__class__.__qualname__ == "PyiFrozenImporter":
                continue
            full_name = f'electrum.plugins.{name}'
            spec = importlib.util.find_spec(full_name)
            if spec is None:  # pkgutil found it but importlib can't ?!
                raise Exception(f"Error pre-loading {full_name}: no spec")
            try:
                module = importlib.util.module_from_spec(spec)
                # sys.modules needs to be modified for relative imports to work
                # see https://stackoverflow.com/a/50395128
                sys.modules[spec.name] = module
                spec.loader.exec_module(module)
            except Exception as e:
                raise Exception(f"Error pre-loading {full_name}: {repr(e)}") from e
            d = module.__dict__
            if 'fullname' not in d:
                continue
            d['display_name'] = d['fullname']
            gui_good = self.gui_name in d.get('available_for', [])
            if not gui_good:
                continue
            details = d.get('registers_wallet_type')
            if details:
                self.register_wallet_type(name, gui_good, details)
            details = d.get('registers_keystore')
            if details:
                self.register_keystore(name, gui_good, details)
            if d.get('requires_wallet_type'):
                # trustedcoin will not be added to list
                continue
            if name in self.internal_plugin_metadata:
                _logger.info(f"Found the following plugin modules: {iter_modules=}")
                raise Exception(f"duplicate plugins? for {name=}")
            self.internal_plugin_metadata[name] = d

    def load_plugins(self):
        self.load_internal_plugins()
        self.load_external_plugins()

    def load_internal_plugins(self):
        for name, d in self.internal_plugin_metadata.items():
            if not d.get('requires_wallet_type') and self.config.get('enable_plugin_' + name):
                try:
                    self.load_internal_plugin(name)
                except BaseException as e:
                    self.logger.exception(f"cannot initialize plugin {name}: {e}")

    def requires_download(self, name):
        metadata = self.external_plugin_metadata.get(name)
        if not metadata:
            return False
        if os.path.exists(self.external_plugin_path(name)):
            return False
        return True

    def check_plugin_hash(self, name: str)-> bool:
        from .crypto import sha256
        metadata = self.external_plugin_metadata.get(name)
        filename = self.external_plugin_path(name)
        if not os.path.exists(filename):
            return False
        with open(filename, 'rb') as f:
            s = f.read()
        if sha256(s).hex() != metadata['hash']:
            return False
        return True

    async def download_external_plugin(self, name):
        metadata = self.external_plugin_metadata.get(name)
        if metadata is None:
            raise Exception(f"unknown external plugin {name}")
        url = metadata['download_url']
        filename = self.external_plugin_path(name)
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as resp:
                if resp.status == 200:
                    with open(filename, 'wb') as fd:
                        async for chunk in resp.content.iter_chunked(10):
                            fd.write(chunk)
        if not self.check_plugin_hash(name):
            os.unlink(filename)
            raise Exception(f"wrong plugin hash {name}")

    def load_external_plugin(self, name):
        if name in self.plugins:
            return self.plugins[name]
        # If we do not have the metadata, it was not detected by `load_external_plugins`
        # on startup, or added by manual user installation after that point.
        metadata = self.external_plugin_metadata.get(name)
        if metadata is None:
            self.logger.exception(f"attempted to load unknown external plugin {name}")
            return
        filename = self.external_plugin_path(name)
        if not os.path.exists(filename):
            return
        if not self.check_plugin_hash(name):
            self.logger.exception(f"wrong hash for plugin '{name}'")
            os.unlink(filename)
            return
        try:
            zipfile = zipimport.zipimporter(filename)
        except zipimport.ZipImportError:
            self.logger.exception(f"unable to load zip plugin '{filename}'")
            return
        try:
            module = zipfile.load_module(name)
        except zipimport.ZipImportError as e:
            self.logger.exception(f"unable to load zip plugin '{filename}' package '{name}'")
            return
        sys.modules['electrum_external_plugins.' + name] = module
        full_name = f'electrum_external_plugins.{name}.{self.gui_name}'
        spec = importlib.util.find_spec(full_name)
        if spec is None:
            raise RuntimeError(f"{self.gui_name} implementation for {name} plugin not found")
        module = importlib.util.module_from_spec(spec)
        self._register_module(spec, module)
        if sys.version_info >= (3, 10):
            spec.loader.exec_module(module)
        else:
            module = spec.loader.load_module(full_name)
        plugin = module.Plugin(self, self.config, name)
        self.add_jobs(plugin.thread_jobs())
        self.plugins[name] = plugin
        self.logger.info(f"loaded external plugin {name}")
        return plugin

    @staticmethod
    def _register_module(spec, module):
        # sys.modules needs to be modified for relative imports to work
        # see https://stackoverflow.com/a/50395128
        sys.modules[spec.name] = module

    def get_external_plugin_dir(self):
        return self.user_pkgpath

    def external_plugin_path(self, name):
        return os.path.join(self.get_external_plugin_dir(), name + '.zip')

    def find_external_plugins(self):
        """ read json file """
        from .constants import read_json
        self.external_plugin_metadata = read_json('plugins.json', {})

    def load_external_plugins(self):
        for name, d in self.external_plugin_metadata.items():
            if not d.get('requires_wallet_type') and self.config.get('use_' + name):
                try:
                    self.load_external_plugin(name)
                except BaseException as e:
                    traceback.print_exc(file=sys.stdout)  # shouldn't this be... suppressed unless -v?
                    self.logger.exception(f"cannot initialize plugin {name} {e!r}")

    def get(self, name):
        return self.plugins.get(name)

    def count(self):
        return len(self.plugins)

    def load_plugin(self, name) -> 'BasePlugin':
        """Imports the code of the given plugin.
        note: can be called from any thread.
        """
        if name in self.internal_plugin_metadata:
            return self.load_internal_plugin(name)
        elif name in self.external_plugin_metadata:
            return self.load_external_plugin(name)
        else:
            raise Exception(f"could not find plugin {name!r}")

    def load_internal_plugin(self, name) -> 'BasePlugin':
        if name in self.plugins:
            return self.plugins[name]
        full_name = f'electrum.plugins.{name}.{self.gui_name}'
        spec = importlib.util.find_spec(full_name)
        if spec is None:
            raise RuntimeError(f"{self.gui_name} implementation for {name} plugin not found")
        try:
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            plugin = module.Plugin(self, self.config, name)
        except Exception as e:
            raise Exception(f"Error loading {name} plugin: {repr(e)}") from e
        self.add_jobs(plugin.thread_jobs())
        self.plugins[name] = plugin
        self.logger.info(f"loaded plugin {name!r}. (from thread: {threading.current_thread().name!r})")
        return plugin

    def close_plugin(self, plugin):
        self.remove_jobs(plugin.thread_jobs())

    def enable(self, name: str) -> 'BasePlugin':
        self.config.set_key('enable_plugin_' + name, True, save=True)
        p = self.get(name)
        if p:
            return p
        return self.load_plugin(name)

    def disable(self, name: str) -> None:
        self.config.set_key('enable_plugin_' + name, False, save=True)
        p = self.get(name)
        if not p:
            return
        self.plugins.pop(name)
        p.close()
        self.logger.info(f"closed {name}")

    @classmethod
    def is_plugin_enabler_config_key(cls, key: str) -> bool:
        return key.startswith('enable_plugin_')

    def toggle(self, name: str) -> Optional['BasePlugin']:
        p = self.get(name)
        return self.disable(name) if p else self.enable(name)

    def is_available(self, name: str, wallet: 'Abstract_Wallet') -> bool:
        d = self.descriptions.get(name)
        if not d:
            return False
        deps = d.get('requires', [])
        for dep, s in deps:
            try:
                __import__(dep)
            except ImportError as e:
                self.logger.warning(f'Plugin {name} unavailable: {repr(e)}')
                return False
        requires = d.get('requires_wallet_type', [])
        return not requires or wallet.wallet_type in requires

    def get_hardware_support(self):
        out = []
        for name, (gui_good, details) in self.hw_wallets.items():
            if gui_good:
                try:
                    p = self.get_plugin(name)
                    if p.is_available():
                        out.append(HardwarePluginToScan(name=name,
                                                        description=details[2],
                                                        plugin=p,
                                                        exception=None))
                except Exception as e:
                    self.logger.exception(f"cannot load plugin for: {name}")
                    out.append(HardwarePluginToScan(name=name,
                                                    description=details[2],
                                                    plugin=None,
                                                    exception=e))
        return out

    def register_wallet_type(self, name, gui_good, wallet_type):
        from .wallet import register_wallet_type, register_constructor
        self.logger.info(f"registering wallet type {(wallet_type, name)}")

        def loader():
            plugin = self.get_plugin(name)
            register_constructor(wallet_type, plugin.wallet_class)
        register_wallet_type(wallet_type)
        plugin_loaders[wallet_type] = loader

    def register_keystore(self, name, gui_good, details):
        from .keystore import register_keystore

        def dynamic_constructor(d):
            return self.get_plugin(name).keystore_class(d)
        if details[0] == 'hardware':
            self.hw_wallets[name] = (gui_good, details)
            self.logger.info(f"registering hardware {name}: {details}")
            register_keystore(details[1], dynamic_constructor)

    def get_plugin(self, name: str) -> 'BasePlugin':
        if name not in self.plugins:
            self.load_plugin(name)
        return self.plugins[name]

    def run(self):
        while self.is_running():
            self.wake_up_event.wait(0.1)  # time.sleep(0.1) OR event
            self.run_jobs()
        self.on_stop()


def hook(func):
    hook_names.add(func.__name__)
    return func


def run_hook(name, *args):
    results = []
    f_list = hooks.get(name, [])
    for p, f in f_list:
        if p.is_enabled():
            try:
                r = f(*args)
            except Exception:
                _logger.exception(f"Plugin error. plugin: {p}, hook: {name}")
                r = False
            if r:
                results.append(r)

    if results:
        assert len(results) == 1, results
        return results[0]


class BasePlugin(Logger):

    def __init__(self, parent, config: 'SimpleConfig', name):
        self.parent = parent  # type: Plugins  # The plugins object
        self.name = name
        self.config = config
        self.wallet = None  # fixme: this field should not exist
        Logger.__init__(self)
        # add self to hooks
        for k in dir(self):
            if k in hook_names:
                l = hooks.get(k, [])
                l.append((self, getattr(self, k)))
                hooks[k] = l

    def __str__(self):
        return self.name

    def close(self):
        # remove self from hooks
        for attr_name in dir(self):
            if attr_name in hook_names:
                # found attribute in self that is also the name of a hook
                l = hooks.get(attr_name, [])
                try:
                    l.remove((self, getattr(self, attr_name)))
                except ValueError:
                    # maybe attr name just collided with hook name and was not hook
                    continue
                hooks[attr_name] = l
        self.parent.close_plugin(self)
        self.on_close()

    def on_close(self):
        pass

    def requires_settings(self) -> bool:
        return False

    def thread_jobs(self):
        return []

    def is_enabled(self):
        return self.is_available() and self.config.get('enable_plugin_' + self.name) is True

    def is_available(self):
        return True

    def can_user_disable(self):
        return True

    def settings_widget(self, window):
        raise NotImplementedError()

    def settings_dialog(self, window):
        raise NotImplementedError()

    def read_file(self, filename: str) -> bytes:
        """ note: only for external plugins """
        import zipfile
        plugin_filename = self.parent.external_plugin_path(self.name)
        with zipfile.ZipFile(plugin_filename) as myzip:
            with myzip.open(os.path.join(self.name, filename)) as myfile:
                s = myfile.read()
                return s


class DeviceUnpairableError(UserFacingException): pass
class HardwarePluginLibraryUnavailable(Exception): pass
class CannotAutoSelectDevice(Exception): pass


class Device(NamedTuple):
    path: Union[str, bytes]
    interface_number: int
    id_: str
    product_key: Any   # when using hid, often Tuple[int, int]
    usage_page: int
    transport_ui_string: str


class DeviceInfo(NamedTuple):
    device: Device
    label: Optional[str] = None
    initialized: Optional[bool] = None
    exception: Optional[Exception] = None
    plugin_name: Optional[str] = None  # manufacturer, e.g. "trezor"
    soft_device_id: Optional[str] = None  # if available, used to distinguish same-type hw devices
    model_name: Optional[str] = None  # e.g. "Ledger Nano S"


class HardwarePluginToScan(NamedTuple):
    name: str
    description: str
    plugin: Optional['HW_PluginBase']
    exception: Optional[Exception]


PLACEHOLDER_HW_CLIENT_LABELS = {None, "", " "}


# hidapi is not thread-safe
# see https://github.com/signal11/hidapi/issues/205#issuecomment-527654560
#     https://github.com/libusb/hidapi/issues/45
#     https://github.com/signal11/hidapi/issues/45#issuecomment-4434598
#     https://github.com/signal11/hidapi/pull/414#issuecomment-445164238
# It is not entirely clear to me, exactly what is safe and what isn't, when
# using multiple threads...
# Hence, we use a single thread for all device communications, including
# enumeration. Everything that uses hidapi, libusb, etc, MUST run on
# the following thread:
_hwd_comms_executor = concurrent.futures.ThreadPoolExecutor(
    max_workers=1,
    thread_name_prefix='hwd_comms_thread'
)

# hidapi needs to be imported from the main thread. Otherwise, at least on macOS,
# segfaults will follow. (see https://github.com/trezor/cython-hidapi/pull/150#issuecomment-1542391087)
# To keep it simple, let's just import it now, as we are likely in the main thread here.
if threading.current_thread() is not threading.main_thread():
    _logger.warning("expected to be in main thread... hidapi will not be safe to use now!")
try:
    import hid
except ImportError:
    pass


T = TypeVar('T')


def run_in_hwd_thread(func: Callable[[], T]) -> T:
    if threading.current_thread().name.startswith("hwd_comms_thread"):
        return func()
    else:
        fut = _hwd_comms_executor.submit(func)
        return fut.result()
        #except (concurrent.futures.CancelledError, concurrent.futures.TimeoutError) as e:


def runs_in_hwd_thread(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        return run_in_hwd_thread(partial(func, *args, **kwargs))
    return wrapper


def assert_runs_in_hwd_thread():
    if not threading.current_thread().name.startswith("hwd_comms_thread"):
        raise Exception("must only be called from HWD communication thread")


class DeviceMgr(ThreadJob):
    """Manages hardware clients.  A client communicates over a hardware
    channel with the device.

    In addition to tracking device HID IDs, the device manager tracks
    hardware wallets and manages wallet pairing.  A HID ID may be
    paired with a wallet when it is confirmed that the hardware device
    matches the wallet, i.e. they have the same master public key.  A
    HID ID can be unpaired if e.g. it is wiped.

    Because of hotplugging, a wallet must request its client
    dynamically each time it is required, rather than caching it
    itself.

    The device manager is shared across plugins, so just one place
    does hardware scans when needed.  By tracking HID IDs, if a device
    is plugged into a different port the wallet is automatically
    re-paired.

    Wallets are informed on connect / disconnect events.  It must
    implement connected(), disconnected() callbacks.  Being connected
    implies a pairing.  Callbacks can happen in any thread context,
    and we do them without holding the lock.

    Confusingly, the HID ID (serial number) reported by the HID system
    doesn't match the device ID reported by the device itself.  We use
    the HID IDs.

    This plugin is thread-safe.  Currently only devices supported by
    hidapi are implemented."""

    def __init__(self, config: SimpleConfig):
        ThreadJob.__init__(self)
        # A pairing_code->id_ map. Item only present if we have active pairing. Needs self.lock.
        self.pairing_code_to_id = {}  # type: Dict[str, str]
        # A client->id_ map. Needs self.lock.
        self.clients = {}  # type: Dict[HardwareClientBase, str]
        # What we recognise.  (vendor_id, product_id) -> Plugin
        self._recognised_hardware = {}  # type: Dict[Tuple[int, int], HW_PluginBase]
        self._recognised_vendor = {}  # type: Dict[int, HW_PluginBase]  # vendor_id -> Plugin
        # Custom enumerate functions for devices we don't know about.
        self._enumerate_func = set()  # Needs self.lock.

        self.lock = threading.RLock()

        self.config = config

    def thread_jobs(self):
        # Thread job to handle device timeouts
        return [self]

    def run(self):
        '''Handle device timeouts.  Runs in the context of the Plugins
        thread.'''
        with self.lock:
            clients = list(self.clients.keys())
        cutoff = time.time() - self.config.get_session_timeout()
        for client in clients:
            client.timeout(cutoff)

    def register_devices(self, device_pairs, *, plugin: 'HW_PluginBase'):
        for pair in device_pairs:
            self._recognised_hardware[pair] = plugin

    def register_vendor_ids(self, vendor_ids: Iterable[int], *, plugin: 'HW_PluginBase'):
        for vendor_id in vendor_ids:
            self._recognised_vendor[vendor_id] = plugin

    def register_enumerate_func(self, func):
        with self.lock:
            self._enumerate_func.add(func)

    @runs_in_hwd_thread
    def create_client(self, device: 'Device', handler: Optional['HardwareHandlerBase'],
                      plugin: 'HW_PluginBase') -> Optional['HardwareClientBase']:
        # Get from cache first
        client = self._client_by_id(device.id_)
        if client:
            return client
        client = plugin.create_client(device, handler)
        if client:
            self.logger.info(f"Registering {client}")
            with self.lock:
                self.clients[client] = device.id_
        return client

    def id_by_pairing_code(self, pairing_code):
        with self.lock:
            return self.pairing_code_to_id.get(pairing_code)

    def pairing_code_by_id(self, id_):
        with self.lock:
            for pairing_code, id2 in self.pairing_code_to_id.items():
                if id2 == id_:
                    return pairing_code
            return None

    def unpair_pairing_code(self, pairing_code):
        with self.lock:
            if pairing_code not in self.pairing_code_to_id:
                return
            _id = self.pairing_code_to_id.pop(pairing_code)
        self._close_client(_id)

    def unpair_id(self, id_):
        pairing_code = self.pairing_code_by_id(id_)
        if pairing_code:
            self.unpair_pairing_code(pairing_code)
        else:
            self._close_client(id_)

    def _close_client(self, id_):
        with self.lock:
            client = self._client_by_id(id_)
            self.clients.pop(client, None)
        if client:
            client.close()

    def _client_by_id(self, id_) -> Optional['HardwareClientBase']:
        with self.lock:
            for client, client_id in self.clients.items():
                if client_id == id_:
                    return client
        return None

    def client_by_id(self, id_, *, scan_now: bool = True) -> Optional['HardwareClientBase']:
        '''Returns a client for the device ID if one is registered.  If
        a device is wiped or in bootloader mode pairing is impossible;
        in such cases we communicate by device ID and not wallet.'''
        if scan_now:
            self.scan_devices()
        return self._client_by_id(id_)

    @runs_in_hwd_thread
    def client_for_keystore(self, plugin: 'HW_PluginBase', handler: Optional['HardwareHandlerBase'],
                            keystore: 'Hardware_KeyStore',
                            force_pair: bool, *,
                            devices: Sequence['Device'] = None,
                            allow_user_interaction: bool = True) -> Optional['HardwareClientBase']:
        self.logger.info("getting client for keystore")
        if handler is None:
            raise Exception(_("Handler not found for {}").format(plugin.name) + '\n' + _("A library is probably missing."))
        handler.update_status(False)
        pcode = keystore.pairing_code()
        client = None
        # search existing clients first (fast-path)
        if not devices:
            client = self.client_by_pairing_code(plugin=plugin, pairing_code=pcode, handler=handler, devices=[])
        # search clients again, now allowing a (slow) scan
        if client is None:
            if devices is None:
                devices = self.scan_devices()
            client = self.client_by_pairing_code(plugin=plugin, pairing_code=pcode, handler=handler, devices=devices)
        if client is None and force_pair:
            try:
                info = self.select_device(plugin, handler, keystore, devices,
                                          allow_user_interaction=allow_user_interaction)
            except CannotAutoSelectDevice:
                pass
            else:
                client = self.force_pair_keystore(plugin=plugin, handler=handler, info=info, keystore=keystore)
        if client:
            handler.update_status(True)
            # note: if select_device was called, we might also update label etc here:
            keystore.opportunistically_fill_in_missing_info_from_device(client)
        self.logger.info("end client for keystore")
        return client

    def client_by_pairing_code(
        self, *, plugin: 'HW_PluginBase', pairing_code: str, handler: 'HardwareHandlerBase',
        devices: Sequence['Device'],
    ) -> Optional['HardwareClientBase']:
        _id = self.id_by_pairing_code(pairing_code)
        client = self._client_by_id(_id)
        if client:
            if type(client.plugin) != type(plugin):
                return
            # An unpaired client might have another wallet's handler
            # from a prior scan.  Replace to fix dialog parenting.
            client.handler = handler
            return client

        for device in devices:
            if device.id_ == _id:
                return self.create_client(device, handler, plugin)

    def force_pair_keystore(
        self,
        *,
        plugin: 'HW_PluginBase',
        handler: 'HardwareHandlerBase',
        info: 'DeviceInfo',
        keystore: 'Hardware_KeyStore',
    ) -> 'HardwareClientBase':
        xpub = keystore.xpub
        derivation = keystore.get_derivation_prefix()
        assert derivation is not None
        xtype = bip32.xpub_type(xpub)
        client = self._client_by_id(info.device.id_)
        if client and client.is_pairable() and type(client.plugin) == type(plugin):
            # See comment above for same code
            client.handler = handler
            # This will trigger a PIN/passphrase entry request
            try:
                client_xpub = client.get_xpub(derivation, xtype)
            except (UserCancelled, RuntimeError):
                # Bad / cancelled PIN / passphrase
                client_xpub = None
            if client_xpub == xpub:
                keystore.opportunistically_fill_in_missing_info_from_device(client)
                with self.lock:
                    self.pairing_code_to_id[keystore.pairing_code()] = info.device.id_
                return client

        # The user input has wrong PIN or passphrase, or cancelled input,
        # or it is not pairable
        raise DeviceUnpairableError(
            _('Electrum cannot pair with your {}.\n\n'
              'Before you request bitcoins to be sent to addresses in this '
              'wallet, ensure you can pair with your device, or that you have '
              'its seed (and passphrase, if any).  Otherwise all bitcoins you '
              'receive will be unspendable.').format(plugin.device))

    def list_pairable_device_infos(
        self,
        *,
        handler: Optional['HardwareHandlerBase'],
        plugin: 'HW_PluginBase',
        devices: Sequence['Device'] = None,
        include_failing_clients: bool = False,
    ) -> List['DeviceInfo']:
        """Returns a list of DeviceInfo objects: one for each connected device accepted by the plugin.
        Already paired devices are also included, as it is okay to reuse them.
        """
        if not plugin.libraries_available:
            message = plugin.get_library_not_available_message()
            raise HardwarePluginLibraryUnavailable(message)
        if devices is None:
            devices = self.scan_devices()
        infos = []
        for device in devices:
            if not plugin.can_recognize_device(device):
                continue
            try:
                client = self.create_client(device, handler, plugin)
                if not client:
                    continue
                label = client.label()
                is_initialized = client.is_initialized()
                soft_device_id = client.get_soft_device_id()
                model_name = client.device_model_name()
            except Exception as e:
                self.logger.error(f'failed to create client for {plugin.name} at {device.path}: {repr(e)}')
                if include_failing_clients:
                    infos.append(DeviceInfo(device=device, exception=e, plugin_name=plugin.name))
                continue
            infos.append(DeviceInfo(device=device,
                                    label=label,
                                    initialized=is_initialized,
                                    plugin_name=plugin.name,
                                    soft_device_id=soft_device_id,
                                    model_name=model_name))

        return infos

    def select_device(self, plugin: 'HW_PluginBase', handler: 'HardwareHandlerBase',
                      keystore: 'Hardware_KeyStore', devices: Sequence['Device'] = None,
                      *, allow_user_interaction: bool = True) -> 'DeviceInfo':
        """Select the device to use for keystore."""
        # ideally this should not be called from the GUI thread...
        # assert handler.get_gui_thread() != threading.current_thread(), 'must not be called from GUI thread'
        while True:
            infos = self.list_pairable_device_infos(handler=handler, plugin=plugin, devices=devices)
            if infos:
                break
            if not allow_user_interaction:
                raise CannotAutoSelectDevice()
            msg = _('Please insert your {}').format(plugin.device)
            msg += " ("
            if keystore.label and keystore.label not in PLACEHOLDER_HW_CLIENT_LABELS:
                msg += f"label: {keystore.label}, "
            msg += f"bip32 root fingerprint: {keystore.get_root_fingerprint()!r}"
            msg += ').\n\n{}\n\n{}'.format(
                _('Verify the cable is connected and that '
                  'no other application is using it.'),
                _('Try to connect again?')
            )
            if not handler.yes_no_question(msg):
                raise UserCancelled()
            devices = None

        # select device automatically. (but only if we have reasonable expectation it is the correct one)
        # method 1: select device by id
        if keystore.soft_device_id:
            for info in infos:
                if info.soft_device_id == keystore.soft_device_id:
                    self.logger.debug(f"select_device. auto-selected(1) {plugin.device}: soft_device_id matched")
                    return info
        # method 2: select device by label
        #           but only if not a placeholder label and only if there is no collision
        device_labels = [info.label for info in infos]
        if (keystore.label not in PLACEHOLDER_HW_CLIENT_LABELS
                and device_labels.count(keystore.label) == 1):
            for info in infos:
                if info.label == keystore.label:
                    self.logger.debug(f"select_device. auto-selected(2) {plugin.device}: label recognised")
                    return info
        # method 3: if there is only one device connected, and we don't have useful label/soft_device_id
        #           saved for keystore anyway, select it
        if (len(infos) == 1
                and keystore.label in PLACEHOLDER_HW_CLIENT_LABELS
                and keystore.soft_device_id is None):
            self.logger.debug(f"select_device. auto-selected(3) {plugin.device}: only one device")
            return infos[0]

        self.logger.debug(f"select_device. auto-select failed for {plugin.device}. {allow_user_interaction=}")
        if not allow_user_interaction:
            raise CannotAutoSelectDevice()
        # ask user to select device manually
        msg = (
                _("Could not automatically pair with device for given keystore.") + "\n"
                + f"(keystore label: {keystore.label!r}, "
                + f"bip32 root fingerprint: {keystore.get_root_fingerprint()!r})\n\n")
        msg += _("Please select which {} device to use:").format(plugin.device)
        msg += "\n(" + _("Or click cancel to skip this keystore instead.") + ")"
        descriptions = ["{label} ({maybe_model}{init}, {transport})"
                        .format(label=info.label or _("An unnamed {}").format(info.plugin_name),
                                init=(_("initialized") if info.initialized else _("wiped")),
                                transport=info.device.transport_ui_string,
                                maybe_model=f"{info.model_name}, " if info.model_name else "")
                        for info in infos]
        self.logger.debug(f"select_device. prompting user for manual selection of {plugin.device}. "
                          f"num options: {len(infos)}. options: {infos}")
        c = handler.query_choice(msg, descriptions)
        if c is None:
            raise UserCancelled()
        info = infos[c]
        self.logger.debug(f"select_device. user manually selected {plugin.device}. device info: {info}")
        # note: updated label/soft_device_id will be saved after pairing succeeds
        return info

    @runs_in_hwd_thread
    def _scan_devices_with_hid(self) -> List['Device']:
        try:
            import hid
        except ImportError:
            return []

        devices = []
        for d in hid.enumerate(0, 0):
            vendor_id = d['vendor_id']
            product_key = (vendor_id, d['product_id'])
            plugin = None
            if product_key in self._recognised_hardware:
                plugin = self._recognised_hardware[product_key]
            elif vendor_id in self._recognised_vendor:
                plugin = self._recognised_vendor[vendor_id]
            if plugin:
                device = plugin.create_device_from_hid_enumeration(d, product_key=product_key)
                if device:
                    devices.append(device)
        return devices

    @runs_in_hwd_thread
    @profiler
    def scan_devices(self) -> Sequence['Device']:
        self.logger.info("scanning devices...")

        # First see what's connected that we know about
        devices = self._scan_devices_with_hid()

        # Let plugin handlers enumerate devices we don't know about
        with self.lock:
            enumerate_funcs = list(self._enumerate_func)
        for f in enumerate_funcs:
            try:
                new_devices = f()
            except BaseException as e:
                self.logger.error(f'custom device enum failed. func {str(f)}, error {e!r}')
            else:
                devices.extend(new_devices)

        # find out what was disconnected
        client_ids = [dev.id_ for dev in devices]
        disconnected_clients = []
        with self.lock:
            connected = {}
            for client, id_ in self.clients.items():
                if id_ in client_ids and client.has_usable_connection_with_device():
                    connected[client] = id_
                else:
                    disconnected_clients.append((client, id_))
            self.clients = connected

        # Unpair disconnected devices
        for client, id_ in disconnected_clients:
            self.unpair_id(id_)
            if client.handler:
                client.handler.update_status(False)

        return devices

    @classmethod
    def version_info(cls) -> Mapping[str, Optional[str]]:
        ret = {}
        # add libusb
        try:
            import usb1
        except Exception as e:
            ret["libusb.version"] = None
        else:
            ret["libusb.version"] = ".".join(map(str, usb1.getVersion()[:4]))
            try:
                ret["libusb.path"] = usb1.libusb1.libusb._name
            except AttributeError:
                ret["libusb.path"] = None
        # add hidapi
        try:
            import hid
            ret["hidapi.version"] = hid.__version__  # available starting with 0.12.0.post2
        except Exception as e:
            from importlib.metadata import version
            try:
                ret["hidapi.version"] = version("hidapi")
            except ImportError:
                ret["hidapi.version"] = None
        return ret

    def trigger_pairings(
            self,
            keystores: Sequence['KeyStore'],
            *,
            allow_user_interaction: bool = True,
            devices: Sequence['Device'] = None,
    ) -> None:
        """Given a list of keystores, try to pair each with a connected hardware device.

        E.g. for a multisig-wallet, it is more user-friendly to use this method than to
        try to pair each keystore individually. Consider the following scenario:
        - three hw keystores in a 2-of-3 multisig wallet, devices d2 (for ks2) and d3 (for ks3) are connected
        - assume none of the devices are paired yet
        1. if we tried to individually pair keystores, we might try with ks1 first
           - but ks1 cannot be paired automatically, as neither d2 nor d3 matches the stored fingerprint
           - the user might then be prompted if they want to manually pair ks1 with either d2 or d3,
             which is confusing and error-prone. It's especially problematic if the hw device does
             not support labels (such as Ledger), as then the user cannot easily distinguish
             same-type devices. (see #4199)
        2. instead, if using this method, we would auto-pair ks2-d2 and ks3-d3 first,
           and then tell the user ks1 could not be paired (and there are no devices left to try)
        """
        from .keystore import Hardware_KeyStore
        keystores = [ks for ks in keystores if isinstance(ks, Hardware_KeyStore)]
        if not keystores:
            return
        if devices is None:
            devices = self.scan_devices()
        # first pair with all devices that can be auto-selected
        for ks in keystores:
            try:
                ks.get_client(
                    force_pair=True,
                    allow_user_interaction=False,
                    devices=devices,
                )
            except UserCancelled:
                pass
        if allow_user_interaction:
            # now do manual selections
            for ks in keystores:
                try:
                    ks.get_client(
                        force_pair=True,
                        allow_user_interaction=True,
                        devices=devices,
                    )
                except UserCancelled:
                    pass
