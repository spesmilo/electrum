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

import json
import os
import pkgutil
import importlib.util
import time
import threading
import sys
import aiohttp
import zipfile as zipfile_lib
from urllib.parse import urlparse

from typing import (NamedTuple, Any, Union, TYPE_CHECKING, Optional, Tuple,
                    Dict, Iterable, List, Sequence, Callable, TypeVar, Mapping)
import concurrent
import zipimport
from functools import wraps, partial
from itertools import chain

from electrum_ecc import ECPrivkey, ECPubkey

from ._vendor.distutils.version import StrictVersion
from .version import ELECTRUM_VERSION
from .i18n import _
from .util import (profiler, DaemonThread, UserCancelled, ThreadJob, UserFacingException, ChoiceItem,
                   make_dir, make_aiohttp_session)
from . import bip32
from . import plugins
from .simple_config import SimpleConfig
from .logging import get_logger, Logger
from .crypto import sha256
from .network import Network

if TYPE_CHECKING:
    from .hw_wallet import HW_PluginBase, HardwareClientBase, HardwareHandlerBase
    from .keystore import Hardware_KeyStore, KeyStore
    from .wallet import Abstract_Wallet


_logger = get_logger(__name__)
plugin_loaders = {}
hook_names = set()
hooks = {}
_exec_module_failure = {}  # type: Dict[str, Exception]

PLUGIN_PASSWORD_VERSION = 1


class Plugins(DaemonThread):

    pkgpath = os.path.dirname(plugins.__file__)
    # TODO: use XDG Base Directory Specification instead of hardcoding /etc
    keyfile_posix = '/etc/electrum/plugins_key'
    keyfile_windows = r'HKEY_LOCAL_MACHINE\SOFTWARE\Electrum\PluginsKey'

    @profiler
    def __init__(self, config: SimpleConfig, gui_name: str = None, cmd_only: bool = False):
        self.config = config
        self.cmd_only = cmd_only  # type: bool
        self.internal_plugin_metadata = {}
        self.external_plugin_metadata = {}
        if cmd_only:
            # only import the command modules of plugins
            Logger.__init__(self)
            self.find_plugins()
            self.load_plugins()
            return
        DaemonThread.__init__(self)
        self.device_manager = DeviceMgr(config)
        self.name = 'Plugins'  # set name of thread
        self._hw_wallets = {}
        self.plugins = {}  # type: Dict[str, BasePlugin]
        self.gui_name = gui_name
        self.find_plugins()
        self.load_plugins()
        self.add_jobs(self.device_manager.thread_jobs())
        self.start()

    @property
    def descriptions(self):
        return dict(list(self.internal_plugin_metadata.items()) + list(self.external_plugin_metadata.items()))

    def find_directory_plugins(self, pkg_path: str, external: bool):
        """Finds plugins in directory form from the given pkg_path and populates the metadata dicts"""
        iter_modules = list(pkgutil.iter_modules([pkg_path]))
        for loader, name, ispkg in iter_modules:
            # FIXME pyinstaller binaries are packaging each built-in plugin twice:
            #       once as data and once as code. To honor the "no duplicates" rule below,
            #       we exclude the ones packaged as *code*, here:
            if loader.__class__.__qualname__ == "PyiFrozenImporter":
                continue
            module_path = os.path.join(pkg_path, name)
            if self.cmd_only and not self.config.get(f'plugins.{name}.enabled') is True:
                continue
            try:
                with open(os.path.join(module_path, 'manifest.json'), 'r') as f:
                    d = json.load(f)
            except FileNotFoundError:
                self.logger.info(f"could not find manifest.json of plugin {name}, skipping...")
                continue
            if 'fullname' not in d:
                continue
            d['path'] = module_path
            if not self.cmd_only:
                gui_good = self.gui_name in d.get('available_for', [])
                if not gui_good:
                    continue
                details = d.get('registers_wallet_type')
                if details:
                    self.register_wallet_type(name, gui_good, details)
                details = d.get('registers_keystore')
                if details:
                    self.register_keystore(name, details)
            if name in self.internal_plugin_metadata or name in self.external_plugin_metadata:
                _logger.info(f"Found the following plugin modules: {iter_modules=}")
                _logger.info(f"duplicate plugins? for {name=}")
                continue
            if not external:
                self.internal_plugin_metadata[name] = d
            else:
                self.external_plugin_metadata[name] = d

    @staticmethod
    def exec_module_from_spec(spec, path: str):
        if prev_fail := _exec_module_failure.get(path):
            raise Exception(f"exec_module already failed once before, with: {prev_fail!r}")
        try:
            module = importlib.util.module_from_spec(spec)
            # sys.modules needs to be modified for relative imports to work
            # see https://stackoverflow.com/a/50395128
            sys.modules[path] = module
            spec.loader.exec_module(module)
        except Exception as e:
            # We can't undo all side-effects, but we at least rm the module from sys.modules,
            # so the import system knows it failed. If called again for the same plugin, we do not
            # retry due to potential interactions with not-undone side-effects (e.g. plugin
            # might have defined commands).
            _exec_module_failure[path] = e
            if path in sys.modules:
                sys.modules.pop(path, None)
            raise Exception(f"Error pre-loading {path}: {repr(e)}") from e
        return module

    def find_plugins(self):
        internal_plugins_path = (self.pkgpath, False)
        external_plugins_path = (self.get_external_plugin_dir(), True)
        for pkg_path, external in (internal_plugins_path, external_plugins_path):
            if pkg_path and os.path.exists(pkg_path):
                if not external:
                    self.find_directory_plugins(pkg_path=pkg_path, external=external)
                else:
                    self.find_zip_plugins(pkg_path=pkg_path, external=external)

    def load_plugins(self):
        for name, d in chain(self.internal_plugin_metadata.items(), self.external_plugin_metadata.items()):
            if not d.get('requires_wallet_type') and self.config.get(f'plugins.{name}.enabled'):
                try:
                    if self.cmd_only:  # only load init method to register commands
                        self.maybe_load_plugin_init_method(name)
                    else:
                        self.load_plugin_by_name(name)
                except BaseException as e:
                    self.logger.exception(f"cannot initialize plugin {name}: {e}")

    def _has_root_permissions(self, path):
        return os.stat(path).st_uid == 0 and not os.access(path, os.W_OK)

    def get_keyfile_path(self, key_hex: Optional[str]) -> Tuple[str, str]:
        if sys.platform in ['windows', 'win32']:
            keyfile_path = self.keyfile_windows
            keyfile_help = _('This file can be edited with Regdit')
        elif 'ANDROID_DATA' in os.environ:
            raise Exception('platform not supported')
        else:
            # treat unknown platforms and macOS as linux-like
            keyfile_path = self.keyfile_posix
            keyfile_help = "" if not key_hex else "".join([
                                         _('The file must have root permissions'),
                                         ".\n\n",
                                         _("To set it you can also use the Auto-Setup or run "
                                           "the following terminal command"),
                                         ":\n\n",
                                         f"sudo sh -c \"{self._posix_plugin_key_creation_command(key_hex)}\"",
            ])
        return keyfile_path, keyfile_help

    def try_auto_key_setup(self, pubkey_hex: str) -> bool:
        """Can be called from the GUI to store the plugin pubkey as root/admin user"""
        try:
            if sys.platform in ['windows', 'win32']:
                self._write_key_to_regedit_windows(pubkey_hex)
            elif 'ANDROID_DATA' in os.environ:
                raise Exception('platform not supported')
            elif sys.platform.startswith('darwin'):  # macOS
                self._write_key_to_root_file_macos(pubkey_hex)
            else:
                self._write_key_to_root_file_linux(pubkey_hex)
        except Exception:
            self.logger.exception(f"auto-key setup for {pubkey_hex} failed")
            return False
        return True

    def try_auto_key_reset(self) -> bool:
        try:
            if sys.platform in ['windows', 'win32']:
                self._delete_plugin_key_from_windows_registry()
            elif 'ANDROID_DATA' in os.environ:
                raise Exception('platform not supported')
            elif sys.platform.startswith('darwin'):  # macOS
                self._delete_macos_plugin_keyfile()
            else:
                self._delete_linux_plugin_keyfile()
        except Exception:
            self.logger.exception(f'auto-reset of plugin key failed')
            return False
        return True

    def _posix_plugin_key_creation_command(self, pubkey_hex: str) -> str:
        """creates the dir (dir_path), writes the key in file, and sets permissions to 644"""
        dir_path: str = os.path.dirname(self.keyfile_posix)
        sh_command = (
                     f"mkdir -p {dir_path} "  # create the /etc/electrum dir
                     f"&& printf '%s' '{pubkey_hex}' > {self.keyfile_posix} "  # write the key to the file
                     f"&& chmod 644 {self.keyfile_posix} "  # set read permissions for the file
                     f"&& chmod 755 {dir_path}"  # set read permissions for the dir
        )
        return sh_command

    @staticmethod
    def _get_macos_osascript_command(commands: List[str]) -> List[str]:
        """
        Inspired by
        https://github.com/barneygale/elevate/blob/01263b690288f022bf6fa702711ac96816bc0e74/elevate/posix.py
        Wraps the given commands in a macOS osascript command to prompt for root permissions.
        """
        from shlex import quote

        def quote_shell(args):
            return " ".join(quote(arg) for arg in args)

        def quote_applescript(string):
            charmap = {
                "\n": "\\n",
                "\r": "\\r",
                "\t": "\\t",
                "\"": "\\\"",
                "\\": "\\\\",
            }
            return '"%s"' % "".join(charmap.get(char, char) for char in string)

        commands = [
            "osascript",
            "-e",
            "do shell script %s "
            "with administrator privileges "
            "without altering line endings"
            % quote_applescript(quote_shell(commands))
        ]
        return commands

    @staticmethod
    def _run_win_regedit_as_admin(reg_exe_command: str) -> None:
        """
        Runs reg.exe reg_exe_command and requests admin privileges through UAC prompt.
        """
        # has to use ShellExecuteEx as ShellExecuteW (the simpler api) doesn't allow to wait
        # for the result of the process (returns no process handle)
        from ctypes import byref, sizeof, windll, Structure, c_ulong
        from ctypes.wintypes import HANDLE, DWORD, HWND, HINSTANCE, HKEY, LPCWSTR

        # https://learn.microsoft.com/en-us/windows/win32/api/shellapi/ns-shellapi-shellexecuteinfoa
        class SHELLEXECUTEINFO(Structure):
            _fields_ = [
                ('cbSize', DWORD),
                ('fMask', c_ulong),
                ('hwnd', HWND),
                ('lpVerb', LPCWSTR),
                ('lpFile', LPCWSTR),
                ('lpParameters', LPCWSTR),
                ('lpDirectory', LPCWSTR),
                ('nShow', c_ulong),
                ('hInstApp', HINSTANCE),
                ('lpIDList', c_ulong),
                ('lpClass', LPCWSTR),
                ('hkeyClass', HKEY),
                ('dwHotKey', DWORD),
                ('hIcon', HANDLE),
                ('hProcess', HANDLE)
            ]

        info = SHELLEXECUTEINFO()
        info.cbSize = sizeof(SHELLEXECUTEINFO)
        info.fMask = 0x00000040 # SEE_MASK_NOCLOSEPROCESS (so we can check the result of the process)
        info.hwnd = None
        info.lpVerb = 'runas'  # run as administrator
        info.lpFile = 'reg.exe'  # the executable to run
        info.lpParameters = reg_exe_command  # the registry edit command
        info.lpDirectory = None
        info.nShow = 1

        # Execute and wait
        if not windll.shell32.ShellExecuteExW(byref(info)):
            error = windll.kernel32.GetLastError()
            raise Exception(f'Error executing registry command: {error}')

        # block until the process is done or 5 sec timeout
        windll.kernel32.WaitForSingleObject(info.hProcess, 0x1338)

        # Close handle
        windll.kernel32.CloseHandle(info.hProcess)

    @staticmethod
    def _execute_commands_in_subprocess(commands: List[str]) -> None:
        """
        Executes the given commands in a subprocess and asserts that it was successful.
        """
        import subprocess
        with subprocess.Popen(
            commands,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        ) as process:
            stdout, stderr = process.communicate()
            if process.returncode != 0:
                raise Exception(f'error executing command ({process.returncode}): {stderr}')

    def _write_key_to_root_file_linux(self, key_hex: str) -> None:
        """
        Spawns a pkexec subprocess to write the key to a file with root permissions.
        This will open an OS dialog asking for the root password. Can only succeed if
        the system has polkit installed.
        """
        assert os.path.exists("/etc"), "System does not have /etc directory"

        sh_command: str = self._posix_plugin_key_creation_command(key_hex)
        commands = ['pkexec', 'sh', '-c', sh_command]
        self._execute_commands_in_subprocess(commands)

        # check if the key was written correctly
        with open(self.keyfile_posix, 'r') as f:
            assert f.read() == key_hex, f'file content mismatch: {f.read()} != {key_hex}'
        self.logger.debug(f'file saved successfully to {self.keyfile_posix}')

    def _delete_linux_plugin_keyfile(self) -> None:
        """
        Deletes the root owned key file at self.keyfile_posix.
        """
        if not os.path.exists(self.keyfile_posix):
            self.logger.debug(f'file {self.keyfile_posix} does not exist')
            return
        if not self._has_root_permissions(self.keyfile_posix):
            os.unlink(self.keyfile_posix)
            return

        # use pkexec to delete the file as root user
        commands = ['pkexec', 'rm', self.keyfile_posix]
        self._execute_commands_in_subprocess(commands)
        assert not os.path.exists(self.keyfile_posix), f'file {self.keyfile_posix} still exists'

    def _write_key_to_root_file_macos(self, key_hex: str) -> None:
        assert os.path.exists("/etc"), "System does not have /etc directory"

        sh_command: str = self._posix_plugin_key_creation_command(key_hex)
        macos_commands = self._get_macos_osascript_command(["sh", "-c", sh_command])

        self._execute_commands_in_subprocess(macos_commands)
        with open(self.keyfile_posix, 'r') as f:
            assert f.read() == key_hex, f'file content mismatch: {f.read()} != {key_hex}'
        self.logger.debug(f'file saved successfully to {self.keyfile_posix}')

    def _delete_macos_plugin_keyfile(self) -> None:
        if not os.path.exists(self.keyfile_posix):
            self.logger.debug(f'file {self.keyfile_posix} does not exist')
            return
        if not self._has_root_permissions(self.keyfile_posix):
            os.unlink(self.keyfile_posix)
            return
        # use osascript to delete the file as root user
        macos_commands = self._get_macos_osascript_command(["rm", self.keyfile_posix])
        self._execute_commands_in_subprocess(macos_commands)
        assert not os.path.exists(self.keyfile_posix), f'file {self.keyfile_posix} still exists'

    def _write_key_to_regedit_windows(self, key_hex: str) -> None:
        """
        Writes the key to the Windows registry with windows UAC prompt.
        """
        from winreg import ConnectRegistry, OpenKey, QueryValue, HKEY_LOCAL_MACHINE

        value_type = 'REG_SZ'
        command = f'add "{self.keyfile_windows}" /ve /t {value_type} /d "{key_hex}" /f'

        self._run_win_regedit_as_admin(command)

        # check if the key was written correctly
        with ConnectRegistry(None, HKEY_LOCAL_MACHINE) as hkey:
            with OpenKey(hkey, r'SOFTWARE\Electrum') as key:
                assert key_hex == QueryValue(key, 'PluginsKey'), "incorrect registry key value"
        self.logger.debug(f'key saved successfully to {self.keyfile_windows}')

    def _delete_plugin_key_from_windows_registry(self) -> None:
        """
        Deletes the PluginsKey dir in the Windows registry.
        """
        from winreg import ConnectRegistry, OpenKey, HKEY_LOCAL_MACHINE

        command = f'delete "{self.keyfile_windows}" /f'
        self._run_win_regedit_as_admin(command)

        try:
            # do a sanity check to see if the key has been deleted
            with ConnectRegistry(None, HKEY_LOCAL_MACHINE) as hkey:
                with OpenKey(hkey, r'SOFTWARE\Electrum\PluginsKey'):
                    raise Exception(f'Key {self.keyfile_windows} still exists, deletion failed')
        except FileNotFoundError:
            pass

    def create_new_key(self, password:str) -> str:
        salt = os.urandom(32)
        privkey = self.derive_privkey(password, salt)
        pubkey = privkey.get_public_key_bytes()
        key = bytes([PLUGIN_PASSWORD_VERSION]) + salt + pubkey
        return key.hex()

    def get_pubkey_bytes(self) -> Tuple[Optional[bytes], bytes]:
        """
        returns pubkey, salt
        returns None, None if the pubkey has not been set
        """
        if sys.platform in ['windows', 'win32']:
            import winreg
            with winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE) as hkey:
                try:
                    with winreg.OpenKey(hkey, r"SOFTWARE\\Electrum") as key:
                        key_hex = winreg.QueryValue(key, "PluginsKey")
                except Exception as e:
                    self.logger.info(f'winreg error: {e}')
                    return None, None
        elif 'ANDROID_DATA' in os.environ:
            return None, None
        else:
            # treat unknown platforms as linux-like
            if not os.path.exists(self.keyfile_posix):
                return None, None
            if not self._has_root_permissions(self.keyfile_posix):
                return
            with open(self.keyfile_posix) as f:
                key_hex = f.read()
        try:
            key = bytes.fromhex(key_hex)
            version = key[0]
        except Exception:
            self.logger.exception(f'{key_hex=} invalid')
            return None, None
        if version != PLUGIN_PASSWORD_VERSION:
            self.logger.info(f'unknown plugin password version: {version}')
            return None, None
        # all good
        salt = key[1:1+32]
        pubkey = key[1+32:]
        return pubkey, salt

    def get_external_plugin_dir(self) -> str:
        pkg_path = os.path.join(self.config.electrum_path(), 'plugins')
        make_dir(pkg_path)
        return pkg_path

    async def download_external_plugin(self, url: str) -> str:
        filename = os.path.basename(urlparse(url).path)
        pkg_path = self.get_external_plugin_dir()
        path = os.path.join(pkg_path, filename)
        if os.path.exists(path):
            raise FileExistsError(f"Plugin {filename} already exists at {path}")
        network = Network.get_instance()
        proxy = network.proxy if network else None
        async with make_aiohttp_session(proxy=proxy) as session:
            async with session.get(url) as resp:
                if resp.status == 200:
                    with open(path, 'wb') as fd:
                        async for chunk in resp.content.iter_chunked(10):
                            fd.write(chunk)
        return path

    def read_manifest(self, path) -> dict:
        """ return json dict """
        with zipfile_lib.ZipFile(path) as file:
            for filename in file.namelist():
                if filename.endswith('manifest.json'):
                    break
            else:
                raise Exception('could not find manifest.json in zip archive')
            with file.open(filename, 'r') as f:
                manifest = json.load(f)
                manifest['path'] = path  # external, path of the zipfile
                manifest['dirname'] = os.path.dirname(filename)  # internal
                manifest['is_zip'] = True
                manifest['zip_hash_sha256'] = get_file_hash256(path).hex()
                return manifest

    def zip_plugin_path(self, name) -> str:
        path = self.get_metadata(name)['path']
        filename = os.path.basename(path)
        if name in self.internal_plugin_metadata:
            pkg_path = self.pkgpath
        else:
            pkg_path = self.get_external_plugin_dir()
        return os.path.join(pkg_path, filename)

    def find_zip_plugins(self, pkg_path: str, external: bool):
        """Finds plugins in zip form in the given pkg_path and populates the metadata dicts"""
        if pkg_path is None:
            return
        for filename in os.listdir(pkg_path):
            path = os.path.join(pkg_path, filename)
            if not filename.endswith('.zip'):
                continue
            try:
                d = self.read_manifest(path)
                name = d['name']
            except Exception:
                self.logger.info(f"could not load manifest.json from zip plugin {filename}", exc_info=True)
                continue
            if name in self.internal_plugin_metadata or name in self.external_plugin_metadata:
                self.logger.info(f"duplicate plugins for {name=}")
                continue
            if self.cmd_only and not self.config.get(f'plugins.{name}.enabled'):
                continue
            min_version = d.get('min_electrum_version')
            if min_version and StrictVersion(min_version) > StrictVersion(ELECTRUM_VERSION):
                self.logger.info(f"version mismatch for zip plugin {filename}", exc_info=True)
                continue
            max_version = d.get('max_electrum_version')
            if max_version and StrictVersion(max_version) < StrictVersion(ELECTRUM_VERSION):
                self.logger.info(f"version mismatch for zip plugin {filename}", exc_info=True)
                continue

            if not self.cmd_only:
                gui_good = self.gui_name in d.get('available_for', [])
                if not gui_good:
                    continue
                if 'fullname' not in d:
                    continue
                details = d.get('registers_keystore')
                if details:
                    self.register_keystore(name, details)
            if external:
                self.external_plugin_metadata[name] = d
            else:
                self.internal_plugin_metadata[name] = d

    def get(self, name):
        return self.plugins.get(name)

    def count(self):
        return len(self.plugins)

    def load_plugin(self, name) -> 'BasePlugin':
        """Imports the code of the given plugin.
        note: can be called from any thread.
        """
        if self.get_metadata(name):
            return self.load_plugin_by_name(name)
        else:
            raise Exception(f"could not find plugin {name!r}")

    def maybe_load_plugin_init_method(self, name: str) -> None:
        """Loads the __init__.py module of the plugin if it is not already loaded."""
        base_name = ('electrum_external_plugins.' if self.is_external(name) else 'electrum.plugins.') + name
        if base_name not in sys.modules:
            metadata = self.get_metadata(name)
            is_zip = metadata.get('is_zip', False)
            # if the plugin was not enabled on startup the init module hasn't been loaded yet
            if not is_zip:
                if self.is_external(name):
                    # this branch is deprecated: external plugins are always zip files
                    path = os.path.join(metadata['path'], '__init__.py')
                    init_spec = importlib.util.spec_from_file_location(base_name, path)
                else:
                    init_spec = importlib.util.find_spec(base_name)
            else:
                zipfile = zipimport.zipimporter(metadata['path'])
                dirname = metadata['dirname']
                init_spec = zipfile.find_spec(dirname)

            self.exec_module_from_spec(init_spec, base_name)

    def load_plugin_by_name(self, name: str) -> 'BasePlugin':
        if name in self.plugins:
            return self.plugins[name]
        # if the plugin was not enabled on startup the init module hasn't been loaded yet
        self.maybe_load_plugin_init_method(name)
        is_external = self.is_external(name)
        if is_external and not self.is_authorized(name):
            self.logger.info(f'plugin not authorized {name}')
            return
        if not is_external:
            full_name = f'electrum.plugins.{name}.{self.gui_name}'
        else:
            full_name = f'electrum_external_plugins.{name}.{self.gui_name}'

        spec = importlib.util.find_spec(full_name)
        if spec is None:
            raise RuntimeError(f"{self.gui_name} implementation for {name} plugin not found")
        try:
            module = self.exec_module_from_spec(spec, full_name)
            plugin = module.Plugin(self, self.config, name)
        except Exception as e:
            raise Exception(f"Error loading {name} plugin: {repr(e)}") from e
        self.add_jobs(plugin.thread_jobs())
        self.plugins[name] = plugin
        self.logger.info(f"loaded plugin {name!r}. (from thread: {threading.current_thread().name!r})")
        return plugin

    def close_plugin(self, plugin):
        self.remove_jobs(plugin.thread_jobs())

    def derive_privkey(self, pw: str, salt:bytes) -> ECPrivkey:
        from hashlib import pbkdf2_hmac
        secret = pbkdf2_hmac('sha256', pw.encode('utf-8'), salt, iterations=10**5)
        return ECPrivkey(secret)

    def uninstall(self, name: str):
        if self.config.get(f'plugins.{name}'):
            self.config.set_key(f'plugins.{name}', None)
        if name in self.external_plugin_metadata:
            zipfile = self.zip_plugin_path(name)
            os.unlink(zipfile)
            self.external_plugin_metadata.pop(name)

    def is_internal(self, name) -> bool:
        return name in self.internal_plugin_metadata

    def is_external(self, name) -> bool:
        return name in self.external_plugin_metadata

    def is_auto_loaded(self, name):
        metadata = self.external_plugin_metadata.get(name) or self.internal_plugin_metadata.get(name)
        return metadata and (metadata.get('registers_keystore') or metadata.get('registers_wallet_type'))

    def is_installed(self, name) -> bool:
        """an external plugin may be installed but not authorized """
        return (name in self.internal_plugin_metadata or name in self.external_plugin_metadata)

    def is_authorized(self, name) -> bool:
        if name in self.internal_plugin_metadata:
            return True
        if name not in self.external_plugin_metadata:
            return False
        pubkey_bytes, salt = self.get_pubkey_bytes()
        if not pubkey_bytes:
            return False
        if not self.is_plugin_zip(name):
            return False
        filename = self.zip_plugin_path(name)
        plugin_hash = get_file_hash256(filename)
        sig = self.config.get(f'plugins.{name}.authorized')
        if not sig:
            return False
        pubkey = ECPubkey(pubkey_bytes)
        return pubkey.ecdsa_verify(bytes.fromhex(sig), plugin_hash)

    def authorize_plugin(self, name: str, filename, privkey: ECPrivkey):
        pubkey_bytes, salt = self.get_pubkey_bytes()
        assert pubkey_bytes == privkey.get_public_key_bytes()
        plugin_hash = get_file_hash256(filename)
        sig = privkey.ecdsa_sign(plugin_hash)
        value = sig.hex()
        self.config.set_key(f'plugins.{name}.authorized', value)
        self.config.set_key(f'plugins.{name}.enabled', True)

    def enable(self, name: str) -> 'BasePlugin':
        self.config.enable_plugin(name)
        p = self.get(name)
        if p:
            return p
        return self.load_plugin(name)

    def disable(self, name: str) -> None:
        self.config.disable_plugin(name)
        p = self.get(name)
        if not p:
            return
        self.plugins.pop(name)
        p.close()
        self.logger.info(f"closed {name}")

    @classmethod
    def is_plugin_enabler_config_key(cls, key: str) -> bool:
        return key.startswith('plugins.')

    def is_available(self, name: str) -> bool:
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
        return True

    def get_hardware_support(self):
        out = []
        for name, details in self._hw_wallets.items():
            try:
                p = self.get_plugin(name)
                if p.is_available():
                    out.append(HardwarePluginToScan(
                        name=name,
                        description=details[2],
                        plugin=p,
                        exception=None))
            except Exception as e:
                self.logger.exception(f"cannot load plugin for: {name}")
                out.append(HardwarePluginToScan(
                    name=name,
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

    def register_keystore(self, name, details):
        from .keystore import register_keystore

        def dynamic_constructor(d):
            return self.get_plugin(name).keystore_class(d)
        if details[0] == 'hardware':
            self._hw_wallets[name] = details
            self.logger.info(f"registering hardware {name}: {details}")
            register_keystore(details[1], dynamic_constructor)

    def get_plugin(self, name: str) -> 'BasePlugin':
        if name not in self.plugins:
            self.load_plugin(name)
        return self.plugins[name]

    def is_plugin_zip(self, name: str) -> bool:
        """Returns True if the plugin is a zip file"""
        if (metadata := self.get_metadata(name)) is None:
            return False
        return metadata.get('is_zip', False)

    def get_metadata(self, name: str) -> Optional[dict]:
        """Returns the metadata of the plugin"""
        metadata = self.internal_plugin_metadata.get(name) or self.external_plugin_metadata.get(name)
        if not metadata:
            return None
        return metadata

    def run(self):
        while self.is_running():
            self.wake_up_event.wait(0.1)  # time.sleep(0.1) OR event
            self.run_jobs()
        self.on_stop()

    def read_file(self, name: str, filename: str) -> bytes:
        if self.is_plugin_zip(name):
            plugin_filename = self.zip_plugin_path(name)
            metadata = self.external_plugin_metadata[name]
            dirname = metadata['dirname']
            with zipfile_lib.ZipFile(plugin_filename) as myzip:
                with myzip.open(os.path.join(dirname, filename)) as myfile:
                    return myfile.read()
        elif name in self.internal_plugin_metadata:
            path = os.path.join(os.path.dirname(__file__), 'plugins', name, filename)
            with open(path, 'rb') as myfile:
                return myfile.read()
        else:
            # no icon
            return None

def get_file_hash256(path: str) -> bytes:
    '''Get the sha256 hash of a file, similar to `sha256sum`.'''
    with open(path, 'rb') as f:
        return sha256(f.read())


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
        if not self.is_available():
            return False
        if not self.parent.is_authorized(self.name):
            return False
        return self.config.is_plugin_enabled(self.name)

    def is_available(self):
        return True

    def can_user_disable(self):
        return True

    def settings_widget(self, window):
        raise NotImplementedError()

    def settings_dialog(self, window):
        raise NotImplementedError()

    def read_file(self, filename: str) -> bytes:
        return self.parent.read_file(self.name, filename)

    def get_storage(self, wallet: 'Abstract_Wallet') -> dict:
        """Returns a dict which is persisted in the per-wallet database."""
        plugin_storage = wallet.db.get_plugin_storage()
        return plugin_storage.setdefault(self.name, {})

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

    def label_for_device_select(self) -> str:
        return (
            "{label} ({maybe_model}{init}, {transport})"
            .format(
                label=self.label or _("An unnamed {}").format(self.plugin_name),
                init=(_("initialized") if self.initialized else _("wiped")),
                transport=self.device.transport_ui_string,
                maybe_model=f"{self.model_name}, " if self.model_name else ""
            )
        )


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
        choices = [ChoiceItem(key=idx, label=info.label_for_device_select())
                   for (idx, info) in enumerate(infos)]
        self.logger.debug(f"select_device. prompting user for manual selection of {plugin.device}. "
                          f"num options: {len(infos)}. options: {infos}")
        c = handler.query_choice(msg, choices)
        if c is None:
            raise UserCancelled()
        info = infos[c]
        self.logger.debug(f"select_device. user manually selected {plugin.device}. device info: {info}")
        # note: updated label/soft_device_id will be saved after pairing succeeds
        return info

    @runs_in_hwd_thread
    def _scan_devices_with_hid(self) -> List['Device']:
        try:
            import hid  # noqa: F811
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
            import hid  # noqa: F811
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
