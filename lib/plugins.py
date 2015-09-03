#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2015 Thomas Voegtlin
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

import traceback
import sys
import os
import imp
import pkgutil

from util import *
from i18n import _
from util import print_error, profiler

plugins = {}
descriptions = []
loader = None

def is_available(name, w):
    for d in descriptions:
        if d.get('name') == name:
            break
    else:
        return False
    deps = d.get('requires', [])
    for dep, s in deps:
        try:
            __import__(dep)
        except ImportError:
            return False
    wallet_types = d.get('requires_wallet_type')
    if wallet_types:
        if w.wallet_type not in wallet_types:
            return False
    return True


def plugin_loader(config, name):
    global plugins
    if plugins.get(name) is None:
        print_error(_("Loading plugin by constructor:"), name)
        p = loader(name)
        plugins[name] = p.Plugin(config, name)
    return plugins[name]

@profiler
def init_plugins(config, is_local, gui_name):
    global plugins, descriptions, loader
    if is_local:
        fp, pathname, description = imp.find_module('plugins')
        electrum_plugins = imp.load_module('electrum_ltc_plugins', fp, pathname, description)
        loader = lambda name: imp.load_source('electrum_ltc_plugins.' + name, os.path.join(pathname, name + '.py'))
    else:
        electrum_plugins = __import__('electrum_ltc_plugins')
        loader = lambda name: __import__('electrum_ltc_plugins.' + name, fromlist=['electrum_ltc_plugins'])

    def register_wallet_type(name, x):
        import wallet
        x += (lambda: plugin_loader(config, name),)
        wallet.wallet_types.append(x)

    descriptions = electrum_plugins.descriptions
    for item in descriptions:
        name = item['name']
        if gui_name not in item.get('available_for', []):
            continue
        x = item.get('registers_wallet_type')
        if x:
            register_wallet_type(name, x)
        if not config.get('use_' + name):
            continue
        try:
            p = loader(name)
            plugins[name] = p.Plugin(config, name)
        except Exception:
            print_msg(_("Error: cannot initialize plugin"), name)
            traceback.print_exc(file=sys.stdout)


hook_names = set()
hooks = {}

def hook(func):
    hook_names.add(func.func_name)
    return func

def run_hook(name, *args):
    return _run_hook(name, False, *args)

def always_hook(name, *args):
    return _run_hook(name, True, *args)

def _run_hook(name, always, *args):
    results = []
    f_list = hooks.get(name, [])
    for p, f in f_list:
        if name == 'load_wallet':
            p.wallet = args[0]
        if name == 'init_qt':
            gui = args[0]
            p.window = gui.main_window
        if always or p.is_enabled():
            try:
                r = f(*args)
            except Exception:
                print_error("Plugin error")
                traceback.print_exc(file=sys.stdout)
                r = False
            if r:
                results.append(r)
        if name == 'close_wallet':
            p.wallet = None

    if results:
        assert len(results) == 1, results
        return results[0]


class BasePlugin:

    def __init__(self, config, name):
        self.name = name
        self.config = config
        self.wallet = None
        # add self to hooks
        for k in dir(self):
            if k in hook_names:
                l = hooks.get(k, [])
                l.append((self, getattr(self, k)))
                hooks[k] = l

    def close(self):
        # remove self from hooks
        for k in dir(self):
            if k in hook_names:
                l = hooks.get(k, [])
                l.remove((self, getattr(self, k)))
                hooks[k] = l

    def print_error(self, *msg):
        print_error("[%s]"%self.name, *msg)

    def requires_settings(self):
        return False

    def enable(self):
        self.set_enabled(True)
        return True

    def disable(self):
        self.set_enabled(False)
        return True

    @hook
    def load_wallet(self, wallet, window): pass

    @hook
    def close_wallet(self): pass

    #def init(self): pass

    def is_enabled(self):
        return self.is_available() and self.config.get('use_'+self.name) is True

    def is_available(self):
        return True

    def set_enabled(self, enabled):
        self.config.set_key('use_'+self.name, enabled, True)

    def settings_dialog(self):
        pass
