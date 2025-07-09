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
import sys
import html
from typing import TYPE_CHECKING, Optional, Set

from PyQt6.QtCore import QObject, Qt
import PyQt6.QtCore as QtCore
from PyQt6.QtWidgets import (QWidget, QLabel, QPushButton, QTextEdit,
                             QMessageBox, QHBoxLayout, QVBoxLayout, QDialog, QScrollArea)

from electrum.i18n import _
from electrum.base_crash_reporter import BaseCrashReporter, EarlyExceptionsQueue, CrashReportResponse
from electrum.logging import Logger
from electrum import constants
from electrum.network import Network

from .util import MessageBoxMixin, read_QIcon, WaitingDialog, font_height

if TYPE_CHECKING:
    from electrum.simple_config import SimpleConfig
    from electrum.wallet import Abstract_Wallet


class Exception_Window(BaseCrashReporter, QWidget, MessageBoxMixin, Logger):
    _active_window = None

    def __init__(self, config: 'SimpleConfig', exctype, value, tb):
        BaseCrashReporter.__init__(self, exctype, value, tb)
        self.network = Network.get_instance()
        self.config = config

        QWidget.__init__(self)
        self.setWindowTitle('Electrum - ' + _('An Error Occurred'))
        self.setMinimumSize(600, 300)

        Logger.__init__(self)

        main_box = QVBoxLayout()

        heading = QLabel('<h2>' + BaseCrashReporter.CRASH_TITLE + '</h2>')
        main_box.addWidget(heading)
        main_box.addWidget(QLabel(BaseCrashReporter.CRASH_MESSAGE))

        main_box.addWidget(QLabel(BaseCrashReporter.REQUEST_HELP_MESSAGE))

        self._report_contents_dlg = None  # type: Optional[ReportContentsDialog]
        collapse_info = QPushButton(_("Show report contents"))
        collapse_info.clicked.connect(lambda _checked: self.show_report_contents_dlg())

        main_box.addWidget(collapse_info)

        main_box.addWidget(QLabel(BaseCrashReporter.DESCRIBE_ERROR_MESSAGE))

        self.description_textfield = QTextEdit()
        self.description_textfield.setFixedHeight(4 * font_height())
        self.description_textfield.setPlaceholderText(self.USER_COMMENT_PLACEHOLDER)
        main_box.addWidget(self.description_textfield)

        main_box.addWidget(QLabel(BaseCrashReporter.ASK_CONFIRM_SEND))

        buttons = QHBoxLayout()

        report_button = QPushButton(_('Send Bug Report'))
        report_button.clicked.connect(lambda _checked: self.send_report())
        report_button.setIcon(read_QIcon("tab_send.png"))
        buttons.addWidget(report_button)

        never_button = QPushButton(_('Never'))
        never_button.clicked.connect(lambda _checked: self.show_never())
        buttons.addWidget(never_button)

        close_button = QPushButton(_('Not Now'))
        close_button.clicked.connect(lambda _checked: self.close())
        buttons.addWidget(close_button)

        main_box.addLayout(buttons)

        # prioritizes the window input over all other windows
        self.setWindowModality(QtCore.Qt.WindowModality.ApplicationModal)

        self.setLayout(main_box)
        self.show()

    def send_report(self):
        def on_success(response: CrashReportResponse):
            text = response.text
            if response.url:
                text += f" You can track further progress on <a href='{response.url}'>GitHub</a>."
            self.show_message(parent=self,
                              title=_("Crash report"),
                              msg=text,
                              rich_text=True)
            self.close()

        def on_failure(exc_info):
            e = exc_info[1]
            self.logger.error('There was a problem with the automatic reporting', exc_info=exc_info)
            self.show_critical(parent=self,
                               msg=(_('There was a problem with the automatic reporting:') + '<br/>' +
                                    repr(e)[:120] + '<br/><br/>' +
                                    _("Please report this issue manually") +
                                    f' <a href="{constants.GIT_REPO_ISSUES_URL}">on GitHub</a>.'),
                               rich_text=True)

        proxy = self.network.proxy
        task = lambda: BaseCrashReporter.send_report(self, self.network.asyncio_loop, proxy)
        msg = _('Sending crash report...')
        WaitingDialog(self, msg, task, on_success, on_failure)

    def on_close(self):
        Exception_Window._active_window = None
        self.close()

    def show_never(self):
        self.config.SHOW_CRASH_REPORTER = False
        self.close()

    def closeEvent(self, event):
        self.on_close()
        event.accept()

    def get_user_description(self):
        return self.description_textfield.toPlainText()

    def get_wallet_type(self):
        wallet_types = Exception_Hook._INSTANCE.wallet_types_seen
        return ",".join(wallet_types)

    def _get_traceback_str_to_display(self) -> str:
        # The msg_box that shows the report uses rich_text=True, so
        # if traceback contains special HTML characters, e.g. '<',
        # they need to be escaped to avoid formatting issues.
        traceback_str = super()._get_traceback_str_to_display()
        return html.escape(traceback_str)

    def show_report_contents_dlg(self):
        if self._report_contents_dlg is None:
            self._report_contents_dlg = ReportContentsDialog(
                parent=self,
                text=self.get_report_string(),
            )
        self._report_contents_dlg.show()
        self._report_contents_dlg.raise_()


def _show_window(*args):
    if not Exception_Window._active_window:
        Exception_Window._active_window = Exception_Window(*args)


class Exception_Hook(QObject, Logger):
    _report_exception = QtCore.pyqtSignal(object, object, object, object)

    _INSTANCE = None  # type: Optional[Exception_Hook]  # singleton

    def __init__(self, *, config: 'SimpleConfig'):
        QObject.__init__(self)
        Logger.__init__(self)
        assert self._INSTANCE is None, "Exception_Hook is supposed to be a singleton"
        self.config = config
        self.wallet_types_seen = set()  # type: Set[str]

        sys.excepthook = self.handler
        self._report_exception.connect(_show_window)
        EarlyExceptionsQueue.set_hook_as_ready()

    @classmethod
    def maybe_setup(cls, *, config: 'SimpleConfig', wallet: 'Abstract_Wallet' = None) -> None:
        if not config.SHOW_CRASH_REPORTER:
            EarlyExceptionsQueue.set_hook_as_ready()  # flush already queued exceptions
            return
        if not cls._INSTANCE:
            cls._INSTANCE = Exception_Hook(config=config)
        if wallet:
            cls._INSTANCE.wallet_types_seen.add(wallet.wallet_type)

    def handler(self, *exc_info):
        self.logger.error('exception caught by crash reporter', exc_info=exc_info)
        self._report_exception.emit(self.config, *exc_info)


class ReportContentsDialog(QDialog):

    def __init__(self, *, parent: QWidget, text: str):
        QDialog.__init__(self, parent)
        self.setWindowTitle(_("Report contents"))
        self.setMinimumSize(800, 500)
        vbox = QVBoxLayout(self)
        scroll_area = QScrollArea(self)

        report_text = QLabel(text)
        report_text.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        report_text.setTextFormat(Qt.TextFormat.AutoText)  # likely rich text

        scroll_area.setWidget(report_text)
        vbox.addWidget(scroll_area)
