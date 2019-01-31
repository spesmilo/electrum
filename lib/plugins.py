#!/usr/bin/env python3
#
# Electrum - lightweight Bitcoin client
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
from collections import namedtuple
import codecs
import traceback
import os
import imp
import json
import pkgutil
import sys
import time
import shutil
import threading
import zipimport

from .i18n import _
from .util import print_error, user_dir, make_dir, versiontuple
from .util import profiler, PrintError, DaemonThread, UserCancelled, ThreadJob
from . import bitcoin
from . import version

plugin_loaders = {}
hook_names = set()
hooks = {}


class ExternalPluginCodes:
    SUCCESS = 0
    MISSING_MANIFEST = 1
    NAME_ALREADY_IN_USE = 2
    UNABLE_TO_COPY_FILE = 3
    INSTALLED_BUT_FAILED_LOAD = 4
    INCOMPATIBLE_VERSION = 5
    INCOMPATIBLE_ZIP_FORMAT = 6
    INVALID_MANIFEST_JSON = 7
    INVALID_MAMIFEST_DISPLAY_NAME = 8
    INVALID_MAMIFEST_DESCRIPTION = 9
    INVALID_MAMIFEST_VERSION = 10
    INVALID_MAMIFEST_MINIMUM_EC_VERSION = 11
    INVALID_MAMIFEST_PACKAGE_NAME = 12

INTERNAL_USE_PREFIX = 'use_'
EXTERNAL_USE_PREFIX = 'use_external_'


class Plugins(DaemonThread):

    @profiler
    def __init__(self, config, gui_name):
        DaemonThread.__init__(self)
        try:
            internal_plugins_namespace = __import__('electroncash_plugins')
        except ImportError:
            # Assume we're running within the source tree.
            find = imp.find_module('plugins')
            internal_plugins_namespace = imp.load_module('electroncash_plugins', *find)
        self.internal_plugins_pkgpath = os.path.dirname(internal_plugins_namespace.__file__)
        self.config = config
        self.gui_name = gui_name
        self.hw_wallets = {}
        self.internal_plugins = {}
        self.internal_plugin_metadata = {}
        self.external_plugins = {}
        self.external_plugin_metadata = {}
        self.device_manager = DeviceMgr(config)
        self.load_internal_plugins()
        self.load_external_plugins()
        self.add_jobs(self.device_manager.thread_jobs())
        self.start()

    def register_plugin(self, name, metadata, is_external=False):
        gui_good = self.gui_name in metadata.get('available_for', [])
        if not gui_good:
            return False
        details = metadata.get('registers_wallet_type')
        if details:
            self.register_wallet_type(name, gui_good, details, is_external)
        details = metadata.get('registers_keystore')
        if details:
            self.register_keystore(name, gui_good, details, is_external)
        return True

    def load_internal_plugins(self):
        for loader, name, ispkg in pkgutil.iter_modules([self.internal_plugins_pkgpath]):
            # do not load deprecated plugins
            if name in ['plot', 'exchange_rate']:
                continue
            m = loader.find_module(name).load_module(name)
            d = m.__dict__
            if not self.register_plugin(name, d):
                continue
            self.internal_plugin_metadata[name] = d
            if not d.get('requires_wallet_type') and self.config.get(INTERNAL_USE_PREFIX + name):
                try:
                    self.load_internal_plugin(name)
                except BaseException as e:
                    traceback.print_exc(file=sys.stdout)
                    self.print_error("cannot initialize plugin %s:" % name, str(e))

    def load_external_plugins(self):
        external_plugin_dir = self.get_external_plugin_dir()
        # Unit tests, environment does not lead to finding a user dir, there will be none to load anyway.
        if external_plugin_dir is None:
            return

        for file_name in os.listdir(external_plugin_dir):
            plugin_file_path = os.path.join(external_plugin_dir, file_name)
            leading_name, ext = os.path.splitext(file_name)
            if ext.lower() != ".zip" or not os.path.isfile(plugin_file_path):
                continue
            metadata, error_code = self.get_metadata_from_external_plugin_zip_file(plugin_file_path)
            if metadata is None:
                continue
            package_name = metadata['package_name']
            if package_name in self.internal_plugin_metadata:
                self.print_error("internal plugin also named '%s', external '%s' rejected" % (package_name, file_name))
                continue
            if not self.register_plugin(package_name, metadata, is_external=True):
                continue
            metadata["__file__"] = plugin_file_path
            self.external_plugin_metadata[package_name] = metadata

            if not metadata.get('requires_wallet_type') and self.config.get(EXTERNAL_USE_PREFIX + package_name):
                try:
                    self.load_external_plugin(package_name)
                except BaseException as e:
                    traceback.print_exc(file=sys.stdout)
                    self.print_error("cannot initialize plugin %s:" % package_name, str(e))

    def get_internal_plugin(self, name, force_load=False):
        if force_load and name not in self.internal_plugins:
            self.load_internal_plugin(name)
        return self.internal_plugins.get(name)

    def get_external_plugin(self, name, force_load=False):
        if force_load and name not in self.external_plugins:
            return self.load_external_plugin(name)
        return self.external_plugins.get(name)

    def get_internal_plugin_count(self):
        return len(self.internal_plugins)

    def get_external_plugin_count(self):
        return len(self.external_plugins)

    def load_internal_plugin(self, name):
        if name in self.internal_plugins:
            return self.internal_plugins[name]

        full_name = 'electroncash_plugins.' + name + '.' + self.gui_name
        loader = pkgutil.find_loader(full_name)
        if not loader:
            raise RuntimeError("%s implementation for %s plugin not found"
                               % (self.gui_name, name))
        p = loader.load_module(full_name)
        plugin = p.Plugin(self, self.config, name)
        plugin.set_enabled_prefix(INTERNAL_USE_PREFIX)
        self.add_jobs(plugin.thread_jobs())
        self.internal_plugins[name] = plugin
        self.print_error("loaded internal plugin", name)
        return plugin

    def load_external_plugin(self, name):
        if name in self.external_plugins:
            return self.external_plugins[name]
        # If we do not have the metadata, it was not detected by `load_external_plugins`
        # on startup, or added by manual user installation after that point.
        metadata = self.external_plugin_metadata.get(name, None)
        if metadata is None:
            self.print_error("attempted to load unknown external plugin %s" % name)
            return

        plugin_file_path = metadata["__file__"]
        try:
            zipfile = zipimport.zipimporter(plugin_file_path)
        except zipimport.ZipImportError:
            self.print_error("unable to load zip plugin '%s'" % plugin_file_path)
            return

        try:
            module = zipfile.load_module(name)
        except zipimport.ZipImportError as e:
            self.print_error("unable to load zip plugin '%s' package '%s'" % (plugin_file_path, name), str(e))
            return

        sys.modules['electroncash_external_plugins.'+ name] = module

        full_name = 'electroncash_external_plugins.' + name + '.' + self.gui_name
        loader = pkgutil.find_loader(full_name)
        if not loader:
            raise RuntimeError("%s implementation for %s plugin not found"
                               % (self.gui_name, name))
        p = loader.load_module(full_name)
        plugin = p.Plugin(self, self.config, name)
        plugin.set_enabled_prefix(EXTERNAL_USE_PREFIX)
        self.add_jobs(plugin.thread_jobs())
        self.external_plugins[name] = plugin
        self.print_error("loaded external plugin", name)
        return plugin

    def close_plugin(self, plugin):
        self.remove_jobs(plugin.thread_jobs())

    def enable_internal_plugin(self, name):
        self.config.set_key(INTERNAL_USE_PREFIX + name, True, True)
        return self.get_internal_plugin(name, force_load=True)

    def enable_external_plugin(self, name):
        self.config.set_key(EXTERNAL_USE_PREFIX + name, True, True)
        return self.get_external_plugin(name, force_load=True)

    def disable_internal_plugin(self, name):
        self.config.set_key(INTERNAL_USE_PREFIX + name, False, True)
        p = self.get_internal_plugin(name)
        if not p:
            return
        self.internal_plugins.pop(name)
        p.close()
        self.print_error("closed", name)

    def disable_external_plugin(self, name):
        self.config.set_key(EXTERNAL_USE_PREFIX + name, False, True)
        p = self.get_external_plugin(name)
        if not p:
            return
        self.external_plugins.pop(name)
        p.close()
        self.print_error("closed", name)

    def toggle_internal_plugin(self, name):
        p = self.get_internal_plugin(name)
        return self.disable_internal_plugin(name) if p else self.enable_internal_plugin(name)

    def toggle_external_plugin(self, name):
        p = self.get_external_plugin(name)
        return self.disable_external_plugin(name) if p else self.enable_external_plugin(name)

    def is_plugin_available(self, metadata, w):
        if not metadata:
            return False
        deps = metadata.get('requires', [])
        for dep, s in deps:
            try:
                __import__(dep)
            except ImportError:
                return False
        requires = metadata.get('requires_wallet_type', [])
        return not requires or w.wallet_type in requires

    def is_internal_plugin_available(self, name, w):
        d = self.internal_plugin_metadata.get(name)
        return self.is_plugin_available(d, w)

    def is_external_plugin_available(self, name, w):
        d = self.external_plugin_metadata.get(name)
        return self.is_plugin_available(d, w)

    def get_external_plugin_dir(self):
        # It's possible the plugins are being stored in a local directory
        # and the rest of the data is being stored in the non-local directory.
        local_user_dir = user_dir(prefer_local=True)
        # Environment does not have a user directory (will be unit tests where there are no external plugins).
        if local_user_dir is None:
            return None
        make_dir(local_user_dir)
        external_plugin_dir = os.path.join(local_user_dir, "external_plugins")
        make_dir(external_plugin_dir)
        return external_plugin_dir

    def get_metadata_from_external_plugin_zip_file(self, plugin_file_path):
        file_name = os.path.basename(plugin_file_path)
        try:
            zipfile = zipimport.zipimporter(plugin_file_path)
        except zipimport.ZipImportError:
            self.print_error("unable to load zip plugin for %s" % file_name)
            return None, ExternalPluginCodes.INCOMPATIBLE_ZIP_FORMAT

        try:
            metadata_text = zipfile.get_data("manifest.json")
        except OSError:
            self.print_error("missing 'manifest.json' (zip plugin %s)" % file_name)
            return None, ExternalPluginCodes.MISSING_MANIFEST

        # START: json.loads for Python < 3.6 does not support bytes.  Delete this when we upgrade to 3.6.
        if not (sys.version_info.major > 3 or sys.version_info.major == 3 and sys.version_info.minor >= 6):
            # Copied from `json\__init__.py` in the 3.6 standard library.
            # Python standard license applies to this if statement.
            if isinstance(metadata_text, (bytes, bytearray)):
                def detect_encoding(b):
                    bstartswith = b.startswith
                    if bstartswith((codecs.BOM_UTF32_BE, codecs.BOM_UTF32_LE)):
                        return 'utf-32'
                    if bstartswith((codecs.BOM_UTF16_BE, codecs.BOM_UTF16_LE)):
                        return 'utf-16'
                    if bstartswith(codecs.BOM_UTF8):
                        return 'utf-8-sig'

                    if len(b) >= 4:
                        if not b[0]:
                            # 00 00 -- -- - utf-32-be
                            # 00 XX -- -- - utf-16-be
                            return 'utf-16-be' if b[1] else 'utf-32-be'
                        if not b[1]:
                            # XX 00 00 00 - utf-32-le
                            # XX 00 00 XX - utf-16-le
                            # XX 00 XX -- - utf-16-le
                            return 'utf-16-le' if b[2] or b[3] else 'utf-32-le'
                    elif len(b) == 2:
                        if not b[0]:
                            # 00 XX - utf-16-be
                            return 'utf-16-be'
                        if not b[1]:
                            # XX 00 - utf-16-le
                            return 'utf-16-le'
                    # default
                    return 'utf-8'
                metadata_text = metadata_text.decode(detect_encoding(metadata_text), 'surrogatepass')
        # END

        try:
            metadata = json.loads(metadata_text)
        except json.JSONDecodeError:
            self.print_error("invalid json in 'manifest.json' (zip plugin %s)" % file_name)
            return None, ExternalPluginCodes.INVALID_MANIFEST_JSON

        expected_keys = {
            'display_name': (str, ExternalPluginCodes.INVALID_MAMIFEST_DISPLAY_NAME),
            'description': (str, ExternalPluginCodes.INVALID_MAMIFEST_DESCRIPTION),
            'version': (versiontuple, ExternalPluginCodes.INVALID_MAMIFEST_VERSION),
            'minimum_ec_version': (versiontuple, ExternalPluginCodes.INVALID_MAMIFEST_MINIMUM_EC_VERSION),
            'package_name': (str, ExternalPluginCodes.INVALID_MAMIFEST_PACKAGE_NAME),
        }
        for k, (expected_type, error_code) in expected_keys.items():
            v = metadata.get(k, None)
            if v is None:
                self.print_error("missing metadata key %s (zip plugin %s)" % (k, file_name))
                return None, error_code
            if expected_type is versiontuple:
                try:
                    v = versiontuple(v)
                except ValueError:
                    self.print_error("metadata %s = %s, expected a.b.c version string (zip plugin %s)" % (k, v, file_name))
                    return None, error_code
            elif type(metadata[k]) is not expected_type:
                self.print_error("metadata %s = %s, expected %s (zip plugin %s)" % (k, v, expected_type, file_name))
                return None, error_code

        return metadata, ExternalPluginCodes.SUCCESS

    def install_external_plugin(self, plugin_original_path):
        # Do the minimum verification necessary to check if the archive looks
        # like a valid plugin zip archive.
        metadata, error_code = self.get_metadata_from_external_plugin_zip_file(plugin_original_path)
        if metadata is None:
            return error_code

        file_name = os.path.basename(plugin_original_path)
        leading_name, ext = os.path.splitext(file_name)
        package_name = metadata.get("package_name", leading_name)
        # Ensure it is not already installed.
        if package_name in self.external_plugins or package_name in self.external_plugin_metadata:
            return ExternalPluginCodes.NAME_ALREADY_IN_USE

        if versiontuple(metadata['minimum_ec_version']) > versiontuple(version.PACKAGE_VERSION):
            return ExternalPluginCodes.INCOMPATIBLE_VERSION

        # Copy the original file to the external plugin hosting dir.
        install_dir = self.get_external_plugin_dir()
        plugin_file_path = os.path.join(install_dir, file_name)
        try:
            shutil.copyfile(plugin_original_path, plugin_file_path)
        except OSError:
            return ExternalPluginCodes.UNABLE_TO_COPY_FILE
        metadata["__file__"] = plugin_file_path

        # Register the existence of the newly placed plugin archive.
        # This would otherwise be recorded in `load_external_plugins`.
        self.external_plugin_metadata[package_name] = metadata

        # Not documented wallet type constraint.  Follow pattern elsewhere.
        if metadata.get('requires_wallet_type'):
            return ExternalPluginCodes.SUCCESS

        # Otherwise, we enable all other installed plugins.  This causes the
        # plugin to be loaded, afterward.
        try:
            self.enable_external_plugin(package_name)
        except BaseException as e:
            traceback.print_exc(file=sys.stdout)
            self.print_error("cannot enable/load external plugin %s:" % package_name, str(e))
            return ExternalPluginCodes.INSTALLED_BUT_FAILED_LOAD

        return ExternalPluginCodes.SUCCESS

    def uninstall_external_plugin(self, name):
        self.disable_external_plugin(name)
        if 'electroncash_external_plugins.'+ name in sys.modules:
            del sys.modules['electroncash_external_plugins.'+ name]

        metadata = self.external_plugin_metadata[name]
        plugin_file_path = metadata["__file__"]
        del self.external_plugin_metadata[name]

        os.remove(plugin_file_path)

    def find_plugin(self, name, force_load=False):
        if name in self.internal_plugin_metadata:
            return self.get_internal_plugin(name, force_load)
        else:
            return self.get_external_plugin(name, force_load)

    def get_hardware_support(self):
        out = []
        for name, (gui_good, details) in self.hw_wallets.items():
            if gui_good:
                try:
                    p = self.find_plugin(name, force_load=True)
                    if p.is_enabled():
                        out.append([name, details[2], p])
                except:
                    traceback.print_exc()
                    self.print_error("cannot load plugin for:", name)
        return out

    def register_wallet_type(self, name, gui_good, wallet_type, is_external):
        from .wallet import register_wallet_type, register_constructor
        self.print_error("registering wallet type", (wallet_type, name))
        def loader():
            if is_external:
                plugin = self.get_external_plugin(name, force_load=True)
            else:
                plugin = self.get_internal_plugin(name, force_load=True)
            register_constructor(wallet_type, plugin.wallet_class)
        register_wallet_type(wallet_type)
        plugin_loaders[wallet_type] = loader

    def register_keystore(self, name, gui_good, details, is_external):
        from .keystore import register_keystore
        def dynamic_constructor(d):
            if is_external:
                plugin = self.get_external_plugin(name, force_load=True)
            else:
                plugin = self.get_internal_plugin(name, force_load=True)
            return plugin.keystore_class(d)
        if details[0] == 'hardware':
            self.hw_wallets[name] = (gui_good, details)
            self.print_error("registering hardware %s: %s" %(name, details))
            register_keystore(details[1], dynamic_constructor)

    def run(self):
        while self.is_running():
            time.sleep(0.1)
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
                print_error("Plugin error")
                traceback.print_exc(file=sys.stdout)
                r = False
            if r:
                results.append(r)

    if results:
        assert len(results) == 1, results
        return results[0]


class BasePlugin(PrintError):
    def __init__(self, parent, config, name):
        self.parent = parent  # The plugins object
        self.name = name
        self.config = config
        self.wallet = None
        # add self to hooks
        for k in dir(self):
            if k in hook_names:
                l = hooks.get(k, [])
                l.append((self, getattr(self, k)))
                hooks[k] = l

    def set_enabled_prefix(self, prefix):
        # This is set via a method in order not to break the existing API.
        self.enabled_use_prefix = prefix

    def diagnostic_name(self):
        return self.name

    def __str__(self):
        return self.name

    def close(self):
        # remove self from hooks
        for k in dir(self):
            if k in hook_names:
                l = hooks.get(k, [])
                l.remove((self, getattr(self, k)))
                hooks[k] = l
        self.parent.close_plugin(self)
        self.on_close()

    def on_close(self):
        pass

    def thread_jobs(self):
        return []

    def is_enabled(self):
        return self.is_available() and self.config.get(self.enabled_use_prefix + self.name) is True

    def is_available(self):
        return True

    def can_user_disable(self):
        return True

    # Internal plugin settings support. `settings_widget(dialog)` is called on the plugin.
    def requires_settings(self):
        return False

    def settings_dialog(self, parent):
        pass

    # External plugin settings support. `settings_dialog(parent_dialog)` is called on the plugin.
    def has_settings_dialog(self):
        return False


class DeviceNotFoundError(Exception):
    pass

class DeviceUnpairableError(Exception):
    pass

Device = namedtuple("Device", "path interface_number id_ product_key usage_page")
DeviceInfo = namedtuple("DeviceInfo", "device label initialized")

class DeviceMgr(ThreadJob, PrintError):
    '''Manages hardware clients.  A client communicates over a hardware
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
    hidapi are implemented.'''

    def __init__(self, config):
        super(DeviceMgr, self).__init__()
        # Keyed by xpub.  The value is the device id
        # has been paired, and None otherwise.
        self.xpub_ids = {}
        # A list of clients.  The key is the client, the value is
        # a (path, id_) pair.
        self.clients = {}
        # What we recognise.  Each entry is a (vendor_id, product_id)
        # pair.
        self.recognised_hardware = set()
        # Custom enumerate functions for devices we don't know about.
        self.enumerate_func = set()
        # For synchronization
        self.lock = threading.RLock()
        self.hid_lock = threading.RLock()
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

    def register_devices(self, device_pairs):
        for pair in device_pairs:
            self.recognised_hardware.add(pair)

    def register_enumerate_func(self, func):
        self.enumerate_func.add(func)

    def create_client(self, device, handler, plugin):
        # Get from cache first
        client = self.client_lookup(device.id_)
        if client:
            return client
        client = plugin.create_client(device, handler)
        if client:
            self.print_error("Registering", client)
            with self.lock:
                self.clients[client] = (device.path, device.id_)
        return client

    def xpub_id(self, xpub):
        with self.lock:
            return self.xpub_ids.get(xpub)

    def xpub_by_id(self, id_):
        with self.lock:
            for xpub, xpub_id in self.xpub_ids.items():
                if xpub_id == id_:
                    return xpub
            return None

    def unpair_xpub(self, xpub):
        with self.lock:
            if not xpub in self.xpub_ids:
                return
            _id = self.xpub_ids.pop(xpub)
            self._close_client(_id)

    def unpair_id(self, id_):
        xpub = self.xpub_by_id(id_)
        if xpub:
            self.unpair_xpub(xpub)
        else:
            self._close_client(id_)

    def _close_client(self, id_):
        client = self.client_lookup(id_)
        self.clients.pop(client, None)
        if client:
            client.close()

    def pair_xpub(self, xpub, id_):
        with self.lock:
            self.xpub_ids[xpub] = id_

    def client_lookup(self, id_):
        with self.lock:
            for client, (path, client_id) in self.clients.items():
                if client_id == id_:
                    return client
        return None

    def client_by_id(self, id_):
        '''Returns a client for the device ID if one is registered.  If
        a device is wiped or in bootloader mode pairing is impossible;
        in such cases we communicate by device ID and not wallet.'''
        self.scan_devices()
        return self.client_lookup(id_)

    def client_for_keystore(self, plugin, handler, keystore, force_pair):
        self.print_error("getting client for keystore")
        if handler is None:
            raise BaseException(_("Handler not found for") + ' ' + plugin.name + '\n' + _("A library is probably missing."))
        handler.update_status(False)
        devices = self.scan_devices()
        xpub = keystore.xpub
        derivation = keystore.get_derivation()
        client = self.client_by_xpub(plugin, xpub, handler, devices)
        if client is None and force_pair:
            info = self.select_device(plugin, handler, keystore, devices)
            client = self.force_pair_xpub(plugin, handler, info, xpub, derivation, devices)
        if client:
            handler.update_status(True)
        self.print_error("end client for keystore")
        return client

    def client_by_xpub(self, plugin, xpub, handler, devices):
        _id = self.xpub_id(xpub)
        client = self.client_lookup(_id)
        if client:
            # An unpaired client might have another wallet's handler
            # from a prior scan.  Replace to fix dialog parenting.
            client.handler = handler
            return client

        for device in devices:
            if device.id_ == _id:
                return self.create_client(device, handler, plugin)


    def force_pair_xpub(self, plugin, handler, info, xpub, derivation, devices):
        # The wallet has not been previously paired, so let the user
        # choose an unpaired device and compare its first address.
        xtype = bitcoin.xpub_type(xpub)
        client = self.client_lookup(info.device.id_)
        if client and client.is_pairable():
            # See comment above for same code
            client.handler = handler
            # This will trigger a PIN/passphrase entry request
            try:
                client_xpub = client.get_xpub(derivation, xtype)
            except (UserCancelled, RuntimeError):
                 # Bad / cancelled PIN / passphrase
                client_xpub = None
            if client_xpub == xpub:
                self.pair_xpub(xpub, info.device.id_)
                return client

        # The user input has wrong PIN or passphrase, or cancelled input,
        # or it is not pairable
        raise DeviceUnpairableError(
            _('Electron Cash cannot pair with your {}.\n\n'
              'Before you request bitcoins to be sent to addresses in this '
              'wallet, ensure you can pair with your device, or that you have '
              'its seed (and passphrase, if any).  Otherwise all bitcoins you '
              'receive will be unspendable.').format(plugin.device))

    def unpaired_device_infos(self, handler, plugin, devices=None):
        '''Returns a list of DeviceInfo objects: one for each connected,
        unpaired device accepted by the plugin.'''
        if devices is None:
            devices = self.scan_devices()
        devices = [dev for dev in devices if not self.xpub_by_id(dev.id_)]
        infos = []
        for device in devices:
            if not device.product_key in plugin.DEVICE_IDS:
                continue
            client = self.create_client(device, handler, plugin)
            if not client:
                continue
            infos.append(DeviceInfo(device, client.label(), client.is_initialized()))

        return infos

    def select_device(self, plugin, handler, keystore, devices=None):
        '''Ask the user to select a device to use if there is more than one,
        and return the DeviceInfo for the device.'''
        while True:
            infos = self.unpaired_device_infos(handler, plugin, devices)
            if infos:
                break
            msg = _('Please insert your {}.  Verify the cable is '
                    'connected and that no other application is using it.\n\n'
                    'Try to connect again?').format(plugin.device)
            if not handler.yes_no_question(msg):
                raise UserCancelled()
            devices = None
        if len(infos) == 1:
            return infos[0]
        # select device by label
        for info in infos:
            if info.label == keystore.label:
                return info
        msg = _("Please select which {} device to use:").format(plugin.device)
        descriptions = [info.label + ' (%s)'%(_("initialized") if info.initialized else _("wiped")) for info in infos]
        c = handler.query_choice(msg, descriptions)
        if c is None:
            raise UserCancelled()
        info = infos[c]
        # save new label
        keystore.set_label(info.label)
        handler.win.wallet.save_keystore()
        return info

    def _scan_devices_with_hid(self):
        try:
            import hid
        except ImportError:
            return []

        with self.hid_lock:
            hid_list = hid.enumerate(0, 0)
        # First see what's connected that we know about
        devices = []
        for d in hid_list:
            product_key = (d['vendor_id'], d['product_id'])
            if product_key in self.recognised_hardware:
                # Older versions of hid don't provide interface_number
                interface_number = d.get('interface_number', -1)
                usage_page = d['usage_page']
                id_ = d['serial_number']
                if len(id_) == 0:
                    id_ = str(d['path'])
                id_ += str(interface_number) + str(usage_page)
                devices.append(Device(d['path'], interface_number,
                                      id_, product_key, usage_page))
        return devices

    def scan_devices(self):
        self.print_error("scanning devices...")

        # First see what's connected that we know about
        devices = self._scan_devices_with_hid()

        # Let plugin handlers enumerate devices we don't know about
        for f in self.enumerate_func:
            try:
                new_devices = f()
            except BaseException as e:
                self.print_error('custom device enum failed. func {}, error {}'
                                 .format(str(f), str(e)))
            else:
                devices.extend(new_devices)

        # find out what was disconnected
        pairs = [(dev.path, dev.id_) for dev in devices]
        disconnected_ids = []
        with self.lock:
            connected = {}
            for client, pair in self.clients.items():
                if pair in pairs and client.has_usable_connection_with_device():
                    connected[client] = pair
                else:
                    disconnected_ids.append(pair[1])
            self.clients = connected

        # Unpair disconnected devices
        for id_ in disconnected_ids:
            self.unpair_id(id_)

        return devices
