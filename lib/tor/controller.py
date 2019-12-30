# Electron Cash - lightweight Bitcoin client
# Copyright (C) 2019 Axel Gembe <derago@gmail.com>
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
import re
import subprocess
import sys
import threading
from enum import Enum

import stem.process
import stem.control

from .. import util
from ..util import PrintError
from ..utils import Event
from ..simple_config import SimpleConfig

if sys.platform in ('windows', 'win32'):
    _TOR_BINARY_NAME = os.path.join(
        os.path.dirname(__file__), '..', '..', 'tor.exe')
else:
    _TOR_BINARY_NAME = os.path.join(os.path.dirname(__file__), 'bin', 'tor')

_TOR_ENABLED_KEY = 'tor_enabled'
_TOR_ENABLED_DEFAULT = False

_TOR_SOCKS_PORT_KEY = 'tor_socks_port'
_TOR_SOCKS_PORT_DEFAULT = 0

class TorController(PrintError):
    class Status(Enum):
        STOPPING = 0
        STOPPED = 1
        STARTED = 2
        READY = 3

    _config: SimpleConfig = None
    _tor_process: subprocess.Popen = None
    _tor_read_thread: threading.Thread = None
    _tor_controller: stem.control.Controller = None

    status = Status.STOPPED
    status_changed = Event()

    active_socks_port: int = None
    active_control_port: int = None
    active_port_changed = Event()

    def __init__(self, config: SimpleConfig):
        if not config:
            raise AssertionError('TorController: config must be set')

        self._config = config

        socks_port = self._config.get(
            _TOR_SOCKS_PORT_KEY, _TOR_SOCKS_PORT_DEFAULT)
        if not socks_port or not self._check_port(int(socks_port)):
            # If no valid SOCKS port is set yet, we set the default
            self._config.set_key(_TOR_SOCKS_PORT_KEY, _TOR_SOCKS_PORT_DEFAULT)

    def __del__(self):
        self.status_changed.clear()
        self.active_port_changed.clear()

    # Opened Socks listener on 127.0.0.1:53544
    # Opened Control listener on 127.0.0.1:3300
    _listener_re = re.compile(r".*\[notice\] Opened ([^ ]*) listener on (.*)$")
    _endpoint_re = re.compile(r".*:(\d*)")

    def _tor_msg_handler(self, message: str):
        if util.is_verbose:
            self.print_msg(message)

        # Check if this is a "Opened listener" message and extract the information
        # into the active_socks_port and active_control_port variables
        listener_match = TorController._listener_re.match(message)
        if listener_match:
            listener_type = listener_match.group(1)
            listener_endpoint = listener_match.group(2)
            endpoint_match = TorController._endpoint_re.match(
                listener_endpoint)
            if endpoint_match:
                endpoint_port = int(endpoint_match.group(1))
                if listener_type == 'Socks':
                    self.active_socks_port = endpoint_port
                elif listener_type == 'Control':
                    self.active_control_port = endpoint_port
                    # The control port is the last port opened, so only notify after it
                    self.active_port_changed(self)

    def _read_tor_msg(self):
        while self._tor_process and not self._tor_process.poll():
            line = self._tor_process.stdout.readline().decode('utf-8', 'replace').strip()
            if not line:
                break
            self._tor_msg_handler(line)

    _orig_subprocess_popen = subprocess.Popen

    @staticmethod
    def _popen_monkey_patch(*args, **kwargs):
        if sys.platform in ('win32'):
            if hasattr(subprocess, 'CREATE_NO_WINDOW'):
                kwargs['creationflags'] = subprocess.CREATE_NO_WINDOW
            elif hasattr(subprocess, 'STARTUPINFO'):
                si = subprocess.STARTUPINFO()
                si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                kwargs['startupinfo'] = si
        return TorController._orig_subprocess_popen(*args, **kwargs)

    def start(self):
        if self._tor_process:
            # Tor is already running
            return

        if not self.is_enabled():
            # Don't start Tor if not enabled
            return

        # When the socks port is set to zero, we let tor choose one
        socks_port = str(self.get_socks_port())
        if socks_port == '0':
            socks_port = 'auto'

        try:
            subprocess.Popen = TorController._popen_monkey_patch
            self._tor_process = stem.process.launch_tor_with_config(
                tor_cmd=_TOR_BINARY_NAME,
                completion_percent=0,  # We will monitor the bootstrap status
                init_msg_handler=self._tor_msg_handler,
                take_ownership=True,
                close_output=False,
                config={
                    'SocksPort': socks_port,
                    'ControlPort': 'auto',
                    'CookieAuthentication': '1',
                    'DataDirectory': os.path.join(self._config.path, 'tor'),
                    'Log': 'NOTICE stdout',
                },
            )
        except:
            self.print_exception("Failed to start Tor")
            self._tor_process = None
            return
        finally:
            subprocess.Popen = TorController._orig_subprocess_popen

        self._tor_read_thread = threading.Thread(
            target=self._read_tor_msg, name="Tor message reader")
        self._tor_read_thread.start()

        self.status = TorController.Status.STARTED
        self.status_changed(self)

        try:
            self._tor_controller = stem.control.Controller.from_port(
                port=self.active_control_port)
            self._tor_controller.authenticate()
            self._tor_controller.add_event_listener(
                self._handle_network_liveliness_event, stem.control.EventType.NETWORK_LIVENESS)
        except:
            self.print_exception("Failed to connect to Tor control port")
            self.stop()
            return

        self.print_error("started (Tor version {})".format(
            self._tor_controller.get_version()))

    def stop(self):
        if not self._tor_process:
            # Tor is not running
            return

        self.status = TorController.Status.STOPPING
        self.status_changed(self)

        self.active_socks_port = None
        self.active_control_port = None
        self.active_port_changed(self)

        if self._tor_controller:
            self._tor_controller.close()
            self._tor_controller = None

        if self._tor_process:
            self._tor_process.terminate()
            self._tor_process.wait()
            self._tor_process = None

        if self._tor_read_thread:
            self._tor_read_thread.join()
            self._tor_read_thread = None

        self.status = TorController.Status.STOPPED
        self.status_changed(self)
        self.print_error("stopped")

    def _handle_network_liveliness_event(self, event: stem.response.events.NetworkLivenessEvent):
        old_status = self.status
        self.status = TorController.Status.READY if event.status == 'UP' else TorController.Status.STARTED
        if old_status != self.status:
            self.status_changed(self)

    def _check_port(self, port: int) -> bool:
        if not isinstance(port, int):
            return False
        if port is None:
            return False
        if port != 0:  # Port 0 is automatic
            if port < 1024 or port > 65535:
                return False
        return True

    def set_enabled(self, enabled: bool):
        self._config.set_key(_TOR_ENABLED_KEY, enabled)
        if enabled:
            self.start()
        else:
            self.stop()

    def is_enabled(self) -> bool:
        return bool(self._config.get(_TOR_ENABLED_KEY, _TOR_ENABLED_DEFAULT))

    def set_socks_port(self, port: int):
        if not self._check_port(port):
            raise AssertionError('TorController: invalid port')

        self.stop()
        self._config.set_key(_TOR_SOCKS_PORT_KEY, port)
        self.start()

    def get_socks_port(self) -> int:
        socks_port = self._config.get(
            _TOR_SOCKS_PORT_KEY, _TOR_SOCKS_PORT_DEFAULT)
        if not self._check_port(int(socks_port)):
            raise AssertionError('TorController: invalid port')
        return int(socks_port)
