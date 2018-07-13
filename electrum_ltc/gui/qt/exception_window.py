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
import platform
import sys
import traceback

from PyQt5.QtCore import QObject
import PyQt5.QtCore as QtCore
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import *

from electrum_ltc.i18n import _
from electrum_ltc.base_crash_reporter import BaseCrashReporter
from .util import MessageBoxMixin


class Exception_Window(BaseCrashReporter, QWidget, MessageBoxMixin):
    _active_window = None

    def __init__(self, main_window, exctype, value, tb):
        BaseCrashReporter.__init__(self, exctype, value, tb)
        self.main_window = main_window
        QWidget.__init__(self)
        self.setWindowTitle('Electrum-LTC - ' + _('An Error Occurred'))
        self.setMinimumSize(600, 300)

        main_box = QVBoxLayout()

        heading = QLabel('<h2>' + BaseCrashReporter.CRASH_TITLE + '</h2>')
        main_box.addWidget(heading)
        main_box.addWidget(QLabel(BaseCrashReporter.CRASH_MESSAGE))

        main_box.addWidget(QLabel(BaseCrashReporter.REQUEST_HELP_MESSAGE))

        collapse_info = QPushButton(_("Show report contents"))
        collapse_info.clicked.connect(
            lambda: self.msg_box(QMessageBox.NoIcon,
                                 self, _("Report contents"), self.get_report_string()))

        main_box.addWidget(collapse_info)

        main_box.addWidget(QLabel(BaseCrashReporter.DESCRIBE_ERROR_MESSAGE))

        self.description_textfield = QTextEdit()
        self.description_textfield.setFixedHeight(50)
        main_box.addWidget(self.description_textfield)

        main_box.addWidget(QLabel(BaseCrashReporter.ASK_CONFIRM_SEND))

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
        try:
            response = BaseCrashReporter.send_report(self)
        except BaseException as e:
            traceback.print_exc(file=sys.stderr)
            self.main_window.show_critical(_('There was a problem with the automatic reporting:') + '\n' +
                                           str(e) + '\n' +
                                           _("Please report this issue manually."))
            return
        QMessageBox.about(self, _("Crash report"), response.text)
        self.close()

    def on_close(self):
        Exception_Window._active_window = None
        sys.__excepthook__(*self.exc_args)
        self.close()

    def show_never(self):
        self.main_window.config.set_key(BaseCrashReporter.config_key, False)
        self.close()

    def closeEvent(self, event):
        self.on_close()
        event.accept()

    def get_user_description(self):
        return self.description_textfield.toPlainText()

    def get_wallet_type(self):
        return self.main_window.wallet.wallet_type

    def get_os_version(self):
        return platform.platform()


def _show_window(*args):
    if not Exception_Window._active_window:
        Exception_Window._active_window = Exception_Window(*args)


class Exception_Hook(QObject):
    _report_exception = QtCore.pyqtSignal(object, object, object, object)

    def __init__(self, main_window, *args, **kwargs):
        super(Exception_Hook, self).__init__(*args, **kwargs)
        if not main_window.config.get(BaseCrashReporter.config_key, default=True):
            return
        self.main_window = main_window
        sys.excepthook = self.handler
        self._report_exception.connect(_show_window)

    def handler(self, *args):
        self._report_exception.emit(self.main_window, *args)
