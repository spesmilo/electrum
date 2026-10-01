import os
import re
import sys
import traceback
from typing import TYPE_CHECKING, Optional

from PyQt6.QtCore import pyqtProperty, pyqtSignal, pyqtSlot, QObject

import electrum
from electrum import bitcoin, commands, lnutil, util
from electrum.base_crash_reporter import taint_reports_by_console_usage
from electrum.i18n import _
from electrum.logging import get_logger

if TYPE_CHECKING:
    from electrum.daemon import Daemon
    from electrum.plugin import Plugins
    from electrum.simple_config import SimpleConfig
    from electrum.wallet import Abstract_Wallet
    from .qedaemon import QEDaemon


class QEConsole(QObject):
    """Python REPL for the QML GUI.

    Port of the toolkit-independent parts of electrum/gui/qt/console.py.
    Lives at application scope so namespace, history and scrollback survive
    page navigation.
    """
    _logger = get_logger(__name__)

    MAX_OUTPUT_SIZE = 100_000  # characters kept in the scrollback buffer
    MAX_HISTORY_SIZE = 50      # same cap as the Qt console

    outputChanged = pyqtSignal()
    promptChanged = pyqtSignal()

    def __init__(
            self,
            config: 'SimpleConfig',
            *,
            daemon: Optional['Daemon'] = None,
            qedaemon: Optional['QEDaemon'] = None,
            plugins: Optional['Plugins'] = None,
            parent=None,
    ):
        super().__init__(parent)
        self._config = config
        self._daemon = daemon
        self._qedaemon = qedaemon
        self._plugins = plugins
        self._output = ''
        self._history = []
        self._history_index = 0
        self._construct = []
        self._is_json = False
        self._namespace = {}
        self._namespace_initialized = False
        self._namespace_wallet = object()  # sentinel != any wallet (incl. None)

    @pyqtProperty(str, notify=outputChanged)
    def output(self):
        return self._output

    @pyqtProperty(str, notify=promptChanged)
    def prompt(self):
        return '... ' if self._construct else '>>> '

    @pyqtProperty(bool, notify=promptChanged)
    def inConstruct(self):
        return bool(self._construct)

    def _append(self, text: str) -> None:
        self._output += text
        if len(self._output) > self.MAX_OUTPUT_SIZE:
            self._output = self._output[-self.MAX_OUTPUT_SIZE:]
        self.outputChanged.emit()

    def _show_message(self, message: str) -> None:
        self._append(message + '\n')

    @pyqtSlot()
    def clear(self):
        self._output = ''
        self.outputChanged.emit()

    @pyqtSlot()
    def keyboardInterrupt(self):
        """Abort a pending multiline construct (Ctrl+C equivalent)."""
        self._construct = []
        self._show_message('KeyboardInterrupt')
        self.promptChanged.emit()

    @pyqtSlot(str)
    def runCommand(self, line: str) -> None:
        command = line.rstrip()
        self._append(self.prompt + command + '\n')
        self._add_to_history(command)
        command = self._get_construct(command)
        if command:
            self._exec_command(command)
        self._is_json = False
        self.promptChanged.emit()

    def _get_construct(self, command: str) -> str:
        # multiline blocks: a line ending in ':' starts a construct,
        # an empty line terminates and returns it for execution
        if self._construct:
            self._construct.append(command)
            if not command:
                ret_val = '\n'.join(self._construct)
                self._construct = []
                return ret_val
            else:
                return ''
        else:
            if command and command[-1] == ':':
                self._construct.append(command)
                return ''
            else:
                return command

    def _add_to_history(self, command: str) -> None:
        if not self._construct and command[0:1] == ' ':
            return
        if command and (not self._history or self._history[-1] != command):
            while len(self._history) >= self.MAX_HISTORY_SIZE:
                self._history.pop(0)
            self._history.append(command)
        self._history_index = len(self._history)

    @pyqtSlot(result=str)
    def getPrevHistoryEntry(self) -> str:
        if self._history:
            self._history_index = max(0, self._history_index - 1)
            return self._history[self._history_index]
        return ''

    @pyqtSlot(result=str)
    def getNextHistoryEntry(self) -> str:
        if self._history:
            hist_len = len(self._history)
            self._history_index = min(hist_len, self._history_index + 1)
            if self._history_index < hist_len:
                return self._history[self._history_index]
        return ''

    def _get_current_wallet(self) -> Optional['Abstract_Wallet']:
        if self._qedaemon is None:
            return None
        qewallet = self._qedaemon.currentWallet
        return qewallet.wallet if qewallet else None

    def _password_getter(self):
        raise Exception(_('This wallet is encrypted. Pass the wallet password explicitly, e.g.: command(..., password="...")'))

    def _set_json(self, b: bool) -> None:
        self._is_json = b

    def _run_script(self, filename: str) -> None:
        with open(filename) as f:
            script = f.read()
        self._exec_command(script)

    def _update_namespace(self) -> None:
        if not self._namespace_initialized:
            self._namespace_initialized = True
            self._namespace.update({
                'run': self._run_script,
                'config': self._config,
                'daemon': self._daemon,
                'network': self._daemon.network if self._daemon else None,
                'plugins': self._plugins,
                'electrum': electrum,
                'util': util,
                'bitcoin': bitcoin,
                'lnutil': lnutil,
                'app': self.parent(),
            })
            c = commands.Commands(
                config=self._config,
                daemon=self._daemon,
                network=self._daemon.network if self._daemon else None,
                callback=lambda: self._set_json(True))
            def mkfunc(f, method):
                return lambda *args, **kwargs: f(
                    method,
                    args,
                    self._password_getter,
                    **{**kwargs, 'wallet': self._get_current_wallet()})
            for m in dir(c):
                if m[0] == '_' or m in ['network', 'wallet', 'config', 'daemon']:
                    continue
                self._namespace[m] = mkfunc(c._run, m)
        # re-inject wallet-dependent entries when the open wallet changes
        # (like the Qt console does on wallet load); not on every command,
        # so user assignments to these names survive unrelated commands
        wallet = self._get_current_wallet()
        if wallet is not self._namespace_wallet:
            self._namespace_wallet = wallet
            self._namespace.update({
                'wallet': wallet,
                'channels': list(wallet.lnworker.channels.values()) if wallet and wallet.lnworker else [],
            })

    def _exec_command(self, command: str) -> None:
        taint_reports_by_console_usage()
        self._update_namespace()

        if type(self._namespace.get(command)) == type(lambda: None):
            self._show_message(
                "'{}' is a function. Type '{}()' to use it in the Python console."
                .format(command, command))
            return

        class StdoutProxy:
            def __init__(self, write_func):
                self.write_func = write_func
            def flush(self):
                pass
            def write(self, text):
                self.write_func(text)

        tmp_stdout = sys.stdout
        sys.stdout = StdoutProxy(self._append)
        try:
            try:
                # eval is generally considered bad practice. use it wisely!
                result = eval(command, self._namespace, self._namespace)
                if result is not None:
                    if self._is_json:
                        self._show_message(util.json_encode(result))
                    else:
                        self._show_message(repr(result))
            except SyntaxError:
                # exec is generally considered bad practice. use it wisely!
                exec(command, self._namespace, self._namespace)
        except SystemExit:
            # unlike the Qt console (which closes its tab), never let
            # SystemExit propagate: it would take down the whole app
            self._show_message('SystemExit')
        except BaseException as e:
            te = traceback.TracebackException.from_exception(e)
            # rm part of traceback mentioning this file
            te.stack = traceback.StackSummary.from_list(te.stack[1:])
            tb_str = "".join(te.format())
            if not tb_str.endswith('\n'):
                tb_str += '\n'
            self._append(tb_str)
        finally:
            sys.stdout = tmp_stdout

    @pyqtSlot(str, result='QVariant')
    def getCompletions(self, cmd: str) -> dict:
        self._update_namespace()
        # note for regex: new words start after ' ' or '(' or ')'
        lastword = re.split(r'[ ()]', cmd)[-1]
        beginning = cmd[:len(cmd) - len(lastword)] if lastword else cmd

        path = lastword.split('.')
        prefix = '.'.join(path[:-1])
        prefix = (prefix + '.') if prefix else prefix
        ns = self._namespace.keys()

        if len(path) > 1:
            obj = self._namespace.get(path[0])
            try:
                for attr in path[1:-1]:
                    obj = getattr(obj, attr)
            except AttributeError:
                ns = []
            else:
                ns = dir(obj)

        completions = []
        for name in ns:
            if name[0] == '_':
                continue
            if name.startswith(path[-1]):
                completions.append(prefix + name)
        completions.sort()

        text = cmd
        candidates = []
        if not completions:
            pass
        elif len(completions) == 1:
            text = beginning + completions[0]
        else:
            p = os.path.commonprefix(completions)
            if len(p) > len(lastword):
                text = beginning + p
            else:
                candidates = completions
        return {'text': text, 'candidates': candidates, 'beginning': beginning}
