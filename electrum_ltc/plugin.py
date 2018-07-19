#!/usr/bin/env python
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
import traceback
import sys
import os
import imp
import pkgutil
import time
import threading

from .util import print_error
from .i18n import _
from .util import profiler, PrintError, DaemonThread, UserCancelled, ThreadJob
from . import bitcoin
from . import plugins

plugin_loaders = {}
hook_names = set()
hooks = {}


class Plugins(DaemonThread):
    verbosity_filter = 'p'

    @profiler
    def __init__(self, config, is_local, gui_name):
        DaemonThread.__init__(self)
        self.pkgpath = os.path.dirname(plugins.__file__)
        self.config = config
        self.hw_wallets = {}
        self.plugins = {}
        self.gui_name = gui_name
        self.descriptions = {}
        self.device_manager = DeviceMgr(config)
        self.load_plugins()
        self.add_jobs(self.device_manager.thread_jobs())
        self.start()

    def load_plugins(self):
        for loader, name, ispkg in pkgutil.iter_modules([self.pkgpath]):
            mod = pkgutil.find_loader('electrum_ltc.plugins.' + name)
            m = mod.load_module()
            d = m.__dict__
            gui_good = self.gui_name in d.get('available_for', [])
            if not gui_good:
                continue
            details = d.get('registers_wallet_type')
            if details:
                self.register_wallet_type(name, gui_good, details)
            details = d.get('registers_keystore')
            if details:
                self.register_keystore(name, gui_good, details)
            self.descriptions[name] = d
            if not d.get('requires_wallet_type') and self.config.get('use_' + name):
                try:
                    self.load_plugin(name)
                except BaseException as e:
                    traceback.print_exc(file=sys.stdout)
                    self.print_error("cannot initialize plugin %s:" % name, str(e))

    def get(self, name):
        return self.plugins.get(name)

    def count(self):
        return len(self.plugins)

    def load_plugin(self, name):
        if name in self.plugins:
            return self.plugins[name]
        full_name = 'electrum_ltc.plugins.' + name + '.' + self.gui_name
        loader = pkgutil.find_loader(full_name)
        if not loader:
            raise RuntimeError("%s implementation for %s plugin not found"
                               % (self.gui_name, name))
        p = loader.load_module()
        plugin = p.Plugin(self, self.config, name)
        self.add_jobs(plugin.thread_jobs())
        self.plugins[name] = plugin
        self.print_error("loaded", name)
        return plugin

    def close_plugin(self, plugin):
        self.remove_jobs(plugin.thread_jobs())

    def enable(self, name):
        self.config.set_key('use_' + name, True, True)
        p = self.get(name)
        if p:
            return p
        return self.load_plugin(name)

    def disable(self, name):
        self.config.set_key('use_' + name, False, True)
        p = self.get(name)
        if not p:
            return
        self.plugins.pop(name)
        p.close()
        self.print_error("closed", name)

    def toggle(self, name):
        p = self.get(name)
        return self.disable(name) if p else self.enable(name)

    def is_available(self, name, w):
        d = self.descriptions.get(name)
        if not d:
            return False
        deps = d.get('requires', [])
        for dep, s in deps:
            try:
                __import__(dep)
            except ImportError as e:
                self.print_error('Plugin', name, 'unavailable:', type(e).__name__, ':', str(e))
                return False
        requires = d.get('requires_wallet_type', [])
        return not requires or w.wallet_type in requires

    def get_hardware_support(self):
        out = []
        for name, (gui_good, details) in self.hw_wallets.items():
            if gui_good:
                try:
                    p = self.get_plugin(name)
                    if p.is_enabled():
                        out.append([name, details[2], p])
                except:
                    traceback.print_exc()
                    self.print_error("cannot load plugin for:", name)
        return out

    def register_wallet_type(self, name, gui_good, wallet_type):
        from .wallet import register_wallet_type, register_constructor
        self.print_error("registering wallet type", (wallet_type, name))
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
            self.print_error("registering hardware %s: %s" %(name, details))
            register_keystore(details[1], dynamic_constructor)

    def get_plugin(self, name):
        if not name in self.plugins:
            self.load_plugin(name)
        return self.plugins[name]

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

    def requires_settings(self):
        return False

    def thread_jobs(self):
        return []

    def is_enabled(self):
        return self.is_available() and self.config.get('use_'+self.name) is True

    def is_available(self):
        return True

    def can_user_disable(self):
        return True

    def settings_dialog(self):
        pass


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
            raise Exception(_("Handler not found for") + ' ' + plugin.name + '\n' + _("A library is probably missing."))
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
            _('Electrum cannot pair with your {}.\n\n'
              'Before you request litecoins to be sent to addresses in this '
              'wallet, ensure you can pair with your device, or that you have '
              'its seed (and passphrase, if any).  Otherwise all litecoins you '
              'receive will be unspendable.').format(plugin.device))

    def unpaired_device_infos(self, handler, plugin, devices=None):
        '''Returns a list of DeviceInfo objects: one for each connected,
        unpaired device accepted by the plugin.'''
        if not plugin.libraries_available:
            raise Exception('Missing libraries for {}'.format(plugin.name))
        if devices is None:
            devices = self.scan_devices()
        devices = [dev for dev in devices if not self.xpub_by_id(dev.id_)]
        infos = []
        for device in devices:
            if device.product_key not in plugin.DEVICE_IDS:
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
            msg = _('Please insert your {}').format(plugin.device)
            if keystore.label:
                msg += ' ({})'.format(keystore.label)
            msg += '. {}\n\n{}'.format(
                _('Verify the cable is connected and that '
                  'no other application is using it.'),
                _('Try to connect again?')
            )
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
        descriptions = [str(info.label) + ' (%s)'%(_("initialized") if info.initialized else _("wiped")) for info in infos]
        c = handler.query_choice(msg, descriptions)
        if c is None:
            raise UserCancelled()
        info = infos[c]
        # save new label
        keystore.set_label(info.label)
        if handler.win.wallet is not None:
            handler.win.wallet.save_keystore()
        return info

    def _scan_devices_with_hid(self):
        try:
            import hid
        except ImportError:
            return []

        with self.hid_lock:
            hid_list = hid.enumerate(0, 0)

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
