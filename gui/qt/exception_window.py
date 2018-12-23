#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
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
import locale
import platform
import traceback
import html

import requests
from PyQt5.QtCore import QObject
import PyQt5.QtCore as QtCore
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import *

from electroncash.i18n import _
import sys
from electroncash import PACKAGE_VERSION
from electroncash.util import Weak, print_error


issue_template = """<h2>Traceback</h2>
<pre>
{traceback}
</pre>

<h2>Additional information</h2>
<ul>
  <li>Electron Cash version: {app_version}</li>
  <li>Python version: {python_version}</li>
  <li>Operating system: {os}</li>
  <li>Wallet type: {wallet_type}</li>
  <li>Locale: {locale}</li>
</ul>
"""
report_server = "https://crashhub.electroncash.org/crash"


class Exception_Window(QWidget):
    _active_window = None

    def __init__(self, config, wallet_types, exctype, value, tb):
        super().__init__(None) # Top-level window. Note PyQt top level windows are kept alive by strong references, hence _active_window
        self.exc_args = (exctype, value, tb)
        self.config = config
        self.wallet_types = wallet_types
        self.setWindowTitle('Electron Cash - ' + _('An Error Occurred'))
        self.setMinimumSize(600, 300)

        main_box = QVBoxLayout()

        heading = QLabel('<h2>' + _('Sorry!') + '</h2>')
        main_box.addWidget(heading)
        main_box.addWidget(QLabel(_('Something went wrong running Electron Cash.')))

        main_box.addWidget(QLabel(
            _('To help us diagnose and fix the problem, you can send us a bug report that contains useful debug '
              'information:')))

        collapse_info = QPushButton(_("Show report contents"))
        collapse_info.clicked.connect(lambda: QMessageBox.about(self, "Report contents", self.get_report_string()))
        main_box.addWidget(collapse_info)

        label = QLabel(_("Please briefly describe what led to the error (optional):") +"<br/>"+
            "<i>"+ _("Feel free to add your email address if you are willing to provide further detail, but note that it will appear in the relevant github issue.") +"</i>")
        label.setTextFormat(QtCore.Qt.RichText)
        main_box.addWidget(label)

        self.description_textfield = QTextEdit()
        self.description_textfield.setFixedHeight(50)
        main_box.addWidget(self.description_textfield)

        main_box.addWidget(QLabel(_("Do you want to send this report?")))

        buttons = QHBoxLayout()

        report_button = QPushButton(_('Send Bug Report'))
        report_button.clicked.connect(self.send_report)
        report_button.setIcon(QIcon(":icons/tab_send.png"))
        buttons.addWidget(report_button)

        never_button = QPushButton(_('Never'))
        never_button.clicked.connect(self.show_never)
        buttons.addWidget(never_button)

        close_button = QPushButton(_('Not Now'))
        close_button.clicked.connect(self.close)
        buttons.addWidget(close_button)

        main_box.addLayout(buttons)

        self.setLayout(main_box)
        self.show()

    def send_report(self):
        report = self.get_traceback_info()
        report.update(self.get_additional_info())
        report = json.dumps(report)
        response = requests.post(report_server, data=report)
        QMessageBox.about(self, "Crash report", response.text)
        self.close()

    def on_close(self):
        Exception_Window._active_window = None
        sys.__excepthook__(*self.exc_args)
        self.close()

    def show_never(self):
        self.config.set_key("show_crash_reporter", False)
        Exception_Hook.uninstall()
        self.close()

    def closeEvent(self, event):
        self.on_close()
        event.accept()

    def get_traceback_info(self):
        exc_string = str(self.exc_args[1])
        stack = traceback.extract_tb(self.exc_args[2])
        readable_trace = "".join(traceback.format_list(stack))
        id = {
            "file": stack[-1].filename,
            "name": stack[-1].name,
            "type": self.exc_args[0].__name__
        }
        return {
            "exc_string": exc_string,
            "stack": readable_trace,
            "id": id
        }

    def get_additional_info(self):
        args = {
            "app_version": PACKAGE_VERSION,
            "python_version": sys.version,
            "os": platform.platform(),
            "locale": locale.getdefaultlocale()[0],
            "description": self.description_textfield.toPlainText(),
            "wallet_type": ",".join([str(x) for x in self.wallet_types])
        }
        return args

    def get_report_string(self):
        info = self.get_additional_info()
        info["traceback"] = html.escape("".join(traceback.format_exception(*self.exc_args)), quote=False)
        return issue_template.format(**info)


def _show_window(config, wallet_types, exctype, value, tb):
    if not Exception_Window._active_window:
        Exception_Window._active_window = Exception_Window(config, wallet_types, exctype, value, tb)


class Exception_Hook(QObject):
    ''' Exception Hook singleton.  Only one of these will be extant. The first
    one is created by the first ElectrumWindow, and it lives forever until app
    exit.  But ONLY if the `show_crash_reporter` config key is set. '''
    
    _report_exception = QtCore.pyqtSignal(object, object, object, object, object)
    _instance = None

    def __init__(self, main_window, wallet):
        assert hasattr(wallet, 'wallet_type'), "Wallet must have a wallet type defined before the Exception_Hook can be installed"
        super().__init__(None) # Top-level Object
        if Exception_Hook._instance:
            Exception_Hook._instance.wallet_types.add(wallet.wallet_type)
            return # This is ok. We will get auto-gc'd
        if not main_window.config.get("show_crash_reporter", default=True):
            print_error("[{}] Not installed due to user config.".format(__class__.__qualname__))
            return # self will get auto-gc'd
        Exception_Hook._instance = self # strong reference to self should keep us alive until uninstall() is called
        self.wallet_types = {wallet.wallet_type}
        self.config = main_window.config
        sys.excepthook = self.handler # yet another strong reference. We really won't die unless uninstall() is called
        self._report_exception.connect(_show_window)
        print_error("[{}] Installed.".format(__class__.__qualname__))
        self.weak_self = Weak(self, lambda *args: print_error("[{}] Finalized.".format(__class__.__qualname__)))

    @staticmethod
    def uninstall(*args):
        sys.excepthook = sys.__excepthook__
        print_error("[{}] Uninstalled.".format(__class__.__qualname__))
        Exception_Hook._instance = None

    def handler(self, exctype, value, tb):
        if exctype is KeyboardInterrupt or exctype is SystemExit or not self.config.get("show_crash_reporter", default=True):
            sys.__excepthook__(exctype, value, tb)
        else:
            self._report_exception.emit(self.config, self.wallet_types, exctype, value, tb)
