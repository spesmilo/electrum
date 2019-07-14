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
from PyQt5.QtWidgets import (QWidget, QLabel, QPushButton, QTextEdit,
                             QMessageBox, QHBoxLayout, QVBoxLayout)

from electrum.i18n import _
from electrum.base_crash_reporter import BaseCrashReporter
from electrum.logging import Logger
from electrum import constants

from .util import MessageBoxMixin, read_QIcon, WaitingDialog


class Exception_Window(BaseCrashReporter, QWidget, MessageBoxMixin, Logger):
    _active_window = None

    def __init__(self, main_window, exctype, value, tb):
        BaseCrashReporter.__init__(self, exctype, value, tb)
        self.main_window = main_window

        QWidget.__init__(self)
        self.setWindowTitle('Electrum - ' + _('An Error Occurred'))
        self.setMinimumSize(600, 300)

        Logger.__init__(self)

        main_box = QVBoxLayout()

        heading = QLabel('<h2>' + BaseCrashReporter.CRASH_TITLE + '</h2>')
        main_box.addWidget(heading)
        main_box.addWidget(QLabel(BaseCrashReporter.CRASH_MESSAGE))

        main_box.addWidget(QLabel(BaseCrashReporter.REQUEST_HELP_MESSAGE))

        collapse_info = QPushButton(_("Show report contents"))
        collapse_info.clicked.connect(
            lambda: self.msg_box(QMessageBox.NoIcon,
                                 self, _("Report contents"), self.get_report_string(),
                                 rich_text=True))

        main_box.addWidget(collapse_info)

        main_box.addWidget(QLabel(BaseCrashReporter.DESCRIBE_ERROR_MESSAGE))

        self.description_textfield = QTextEdit()
        self.description_textfield.setFixedHeight(50)
        self.description_textfield.setPlaceholderText(_("Do not enter sensitive/private information here. "
                                                        "The report will be visible on the public issue tracker."))
        main_box.addWidget(self.description_textfield)

        main_box.addWidget(QLabel(BaseCrashReporter.ASK_CONFIRM_SEND))

        buttons = QHBoxLayout()

        report_button = QPushButton(_('Send Bug Report'))
        report_button.clicked.connect(self.send_report)
        report_button.setIcon(read_QIcon("tab_send.png"))
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
        def on_success(response):
            # note: 'response' coming from (remote) crash reporter server.
            # It contains a URL to the GitHub issue, so we allow rich text.
            self.show_message(parent=self,
                              title=_("Crash report"),
                              msg=response,
                              rich_text=True)
            self.close()
        def on_failure(exc_info):
            e = exc_info[1]
            self.logger.error('There was a problem with the automatic reporting', exc_info=exc_info)
            self.show_critical(parent=self,
                               msg=(_('There was a problem with the automatic reporting:') + '<br/>' +
                                    repr(e)[:120] + '<br/>' +
                                    _("Please report this issue manually") +
                                    f' <a href="{constants.GIT_REPO_ISSUES_URL}">on GitHub</a>.'),
                               rich_text=True)

        proxy = self.main_window.network.proxy
        task = lambda: BaseCrashReporter.send_report(self, self.main_window.network.asyncio_loop, proxy)
        msg = _('Sending crash report...')
        WaitingDialog(self, msg, task, on_success, on_failure)

    def on_close(self):
        Exception_Window._active_window = None
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


def _show_window(*args):
    if not Exception_Window._active_window:
        Exception_Window._active_window = Exception_Window(*args)


class Exception_Hook(QObject, Logger):
    _report_exception = QtCore.pyqtSignal(object, object, object, object)

    def __init__(self, main_window, *args, **kwargs):
        QObject.__init__(self, *args, **kwargs)
        Logger.__init__(self)
        if not main_window.config.get(BaseCrashReporter.config_key, default=True):
            return
        self.main_window = main_window
        sys.excepthook = self.handler
        self._report_exception.connect(_show_window)

    def handler(self, *exc_info):
        self.logger.error('exception caught by crash reporter', exc_info=exc_info)
        self._report_exception.emit(self.main_window, *exc_info)
