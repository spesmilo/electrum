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
import time

from util import *
from i18n import _
from util import profiler, PrintError, DaemonThread
import wallet

class Plugins(DaemonThread):

    @profiler
    def __init__(self, config, is_local, gui_name):
        DaemonThread.__init__(self)
        if is_local:
            find = imp.find_module('plugins')
            plugins = imp.load_module('electrum_ltc_plugins', *find)
        else:
            plugins = __import__('electrum_ltc_plugins')
        self.pkgpath = os.path.dirname(plugins.__file__)
        self.config = config
        self.hw_wallets = {}
        self.plugins = {}
        self.gui_name = gui_name
        self.descriptions = []
        for loader, name, ispkg in pkgutil.iter_modules([self.pkgpath]):
            m = loader.find_module(name).load_module(name)
            d = m.__dict__
            gui_good = gui_name in d.get('available_for', [])
            details = d.get('registers_wallet_type')
            if details:
                self.register_plugin_wallet(name, gui_good, details)
            if not gui_good:
                continue
            self.descriptions.append(d)
            if not d.get('requires_wallet_type') and config.get('use_' + name):
                self.load_plugin(config, name)

    def get(self, name):
        return self.plugins.get(name)

    def count(self):
        return len(self.plugins)

    def load_plugin(self, config, name):
        full_name = 'electrum_ltc_plugins.' + name + '.' + self.gui_name
        try:
            p = pkgutil.find_loader(full_name).load_module(full_name)
            plugin = p.Plugin(self, config, name)
            self.add_jobs(plugin.thread_jobs())
            self.plugins[name] = plugin
            self.print_error("loaded", name)
            return plugin
        except Exception:
            print_msg(_("Error: cannot initialize plugin"), name)
            traceback.print_exc(file=sys.stdout)
            return None

    def close_plugin(self, plugin):
        self.remove_jobs(plugin.thread_jobs())

    def toggle_enabled(self, config, name):
        p = self.get(name)
        config.set_key('use_' + name, p is None, True)
        if p:
            self.plugins.pop(name)
            p.close()
            self.print_error("closed", name)
            return None
        return self.load_plugin(config, name)

    def is_available(self, name, w):
        for d in self.descriptions:
            if d.get('__name__') == name:
                break
        else:
            return False
        deps = d.get('requires', [])
        for dep, s in deps:
            try:
                __import__(dep)
            except ImportError:
                return False
        requires = d.get('requires_wallet_type', [])
        return not requires or w.wallet_type in requires

    def hardware_wallets(self, action):
        result = []
        for name, (gui_good, details) in self.hw_wallets.items():
            if gui_good:
                try:
                    p = self.wallet_plugin_loader(name)
                    if action == 'restore' or p.is_enabled():
                        result.append((details[1], details[2]))
                except:
                    self.print_error("cannot load plugin for:", name)
        return result

    def register_plugin_wallet(self, name, gui_good, details):
        def dynamic_constructor(storage):
            return self.wallet_plugin_loader(name).wallet_class(storage)

        if details[0] == 'hardware':
            self.hw_wallets[name] = (gui_good, details)
        self.print_error("registering wallet %s: %s" %(name, details))
        wallet.wallet_types.append(details + (dynamic_constructor,))

    def wallet_plugin_loader(self, name):
        if not name in self.plugins:
            self.load_plugin(self.config, name)
        return self.plugins[name]

    def run(self):
        jobs = [job for plugin in self.plugins.values()
                for job in plugin.thread_jobs()]
        self.add_jobs(jobs)
        while self.is_running():
            time.sleep(0.1)
            self.run_jobs()
        self.print_error("stopped")


hook_names = set()
hooks = {}

def hook(func):
    hook_names.add(func.func_name)
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

    def settings_dialog(self):
        pass
