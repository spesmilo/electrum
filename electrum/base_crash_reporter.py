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
import asyncio
import json
import locale
import traceback
import sys
import queue
from typing import TYPE_CHECKING, NamedTuple, Optional, TypedDict
from types import TracebackType

from .version import ELECTRUM_VERSION
from . import constants
from .i18n import _
from .util import make_aiohttp_session, error_text_str_to_safe_str
from .logging import describe_os_version, Logger, get_git_version
from .crypto import sha256

if TYPE_CHECKING:
    from .network import ProxySettings


class CrashReportResponse(NamedTuple):
    status: Optional[str]
    text: str
    url: Optional[str]


class BaseCrashReporter(Logger):
    report_server = "https://crashhub.electrum.org"
    issue_template = """<h2>Traceback</h2>
<pre>
{traceback}
</pre>

<h2>Additional information</h2>
<ul>
  <li>Electrum version: {app_version}</li>
  <li>Python version: {python_version}</li>
  <li>Operating system: {os}</li>
  <li>Wallet type: {wallet_type}</li>
  <li>Locale: {locale}</li>
</ul>
    """
    CRASH_MESSAGE = _('Something went wrong while executing Electrum.')
    CRASH_TITLE = _('Sorry!')
    REQUEST_HELP_MESSAGE = _('To help us diagnose and fix the problem, you can send us a bug report that contains '
                             'useful debug information:')
    DESCRIBE_ERROR_MESSAGE = _("Please briefly describe what led to the error (optional):")
    ASK_CONFIRM_SEND = _("Do you want to send this report?")
    USER_COMMENT_PLACEHOLDER = _("Do not enter sensitive/private information here. "
                                 "The report will be visible on the public issue tracker.")

    exc_args: tuple[type[BaseException], BaseException, TracebackType | None]

    def __init__(
        self,
        exctype: type[BaseException],
        excvalue: BaseException,
        tb: TracebackType | None,
    ):
        Logger.__init__(self)
        self.exc_args = (exctype, excvalue, tb)

    def send_report(self, asyncio_loop, proxy: 'ProxySettings', *, timeout=None) -> CrashReportResponse:
        # FIXME the caller needs to catch generic "Exception", as this method does not have a well-defined API...
        if (constants.net.GENESIS[-4:] not in [
            "e26f",  # mainnet
            "4943",  # testnet 3
            "f043",  # testnet 4
            "1ef6",  # signet
        ] and ".electrum.org" in BaseCrashReporter.report_server):
            # Gah! Some kind of altcoin wants to send us crash reports.
            raise Exception(_("Missing report URL."))
        report = self.get_traceback_info(*self.exc_args)
        report.update(self.get_additional_info())
        report = json.dumps(report)
        coro = self.do_post(proxy, BaseCrashReporter.report_server + "/crash.json", data=report)
        response = asyncio.run_coroutine_threadsafe(coro, asyncio_loop).result(timeout)
        self.logger.info(
            f"Crash report sent. Got response [DO NOT TRUST THIS MESSAGE]: {error_text_str_to_safe_str(response)}")
        response = json.loads(response)
        assert isinstance(response, dict), type(response)
        # sanitize URL
        if location := response.get("location"):
            assert isinstance(location, str)
            base_issues_url = constants.GIT_REPO_ISSUES_URL
            if not base_issues_url.endswith("/"):
                base_issues_url = base_issues_url + "/"
            if not location.startswith(base_issues_url):
                location = None
        ret = CrashReportResponse(
            status=response.get("status"),
            url=location,
            text=_("Thanks for reporting this issue!"),
        )
        return ret

    async def do_post(self, proxy: 'ProxySettings', url, data) -> str:
        async with make_aiohttp_session(proxy) as session:
            async with session.post(url, data=data, raise_for_status=True) as resp:
                return await resp.text()

    @classmethod
    def get_traceback_info(
        cls,
        exctype: type[BaseException],
        excvalue: BaseException,
        tb: TracebackType | None,
    ) -> TypedDict('TBInfo', {'exc_string': str, 'stack': str, 'id': dict[str, str]}):
        exc_string = str(excvalue)
        stack = traceback.extract_tb(tb)
        readable_trace = cls._get_traceback_str_to_send(exctype, excvalue, tb)
        _id = {
            "file": stack[-1].filename if len(stack) else '<no stack>',
            "name": stack[-1].name if len(stack) else '<no stack>',
            "type": exctype.__name__
        }  # note: this is the "id" the crash reporter server uses to group together reports.
        return {
            "exc_string": exc_string,
            "stack": readable_trace,
            "id": _id,
        }

    @classmethod
    def get_traceback_groupid_hash(
        cls,
        exctype: type[BaseException],
        excvalue: BaseException,
        tb: TracebackType | None,
    ) -> bytes:
        tb_info = cls.get_traceback_info(exctype, excvalue, tb)
        _id = tb_info["id"]
        return sha256(str(_id))

    def get_additional_info(self):
        args = {
            "app_version": get_git_version() or ELECTRUM_VERSION,
            "python_version": sys.version,
            "os": describe_os_version(),
            "wallet_type": "unknown",
            "locale": locale.getlocale()[0] or "?",
            "description": self.get_user_description()
        }
        try:
            args["wallet_type"] = self.get_wallet_type()
        except Exception:
            # Maybe the wallet isn't loaded yet
            pass
        return args

    @classmethod
    def _get_traceback_str_to_send(
        cls,
        exctype: type[BaseException],
        excvalue: BaseException,
        tb: TracebackType | None,
    ) -> str:
        # make sure that traceback sent to crash reporter contains
        # e.__context__ and e.__cause__, i.e. if there was a chain of
        # exceptions, we want the full traceback for the whole chain.
        return "".join(traceback.format_exception(exctype, excvalue, tb))

    def _get_traceback_str_to_display(self) -> str:
        # overridden in Qt subclass
        return self._get_traceback_str_to_send(*self.exc_args)

    def get_report_string(self):
        info = self.get_additional_info()
        info["traceback"] = self._get_traceback_str_to_display()
        return self.issue_template.format(**info)

    def get_user_description(self):
        raise NotImplementedError

    def get_wallet_type(self) -> str:
        raise NotImplementedError


class EarlyExceptionsQueue:
    """Helper singleton for explicitly sending exceptions to crash reporter.

    Typically the GUIs set up an "exception hook" that catches all otherwise
    uncaught exceptions (which unroll the stack of a thread completely).
    This class provides methods to report *any* exception, and queueing logic
    that delays processing until the exception hook is set up.
    """

    _is_exc_hook_ready = False
    _exc_queue = queue.Queue()

    @classmethod
    def set_hook_as_ready(cls):
        """Flush the queue and disable it for future exceptions."""
        if cls._is_exc_hook_ready:
            return
        cls._is_exc_hook_ready = True
        while cls._exc_queue.qsize() > 0:
            e = cls._exc_queue.get()
            cls._send_exception_to_crash_reporter(e)

    @classmethod
    def send_exception_to_crash_reporter(cls, e: BaseException):
        if cls._is_exc_hook_ready:
            cls._send_exception_to_crash_reporter(e)
        else:
            cls._exc_queue.put(e)

    @staticmethod
    def _send_exception_to_crash_reporter(e: BaseException):
        assert EarlyExceptionsQueue._is_exc_hook_ready
        sys.excepthook(type(e), e, e.__traceback__)


send_exception_to_crash_reporter = EarlyExceptionsQueue.send_exception_to_crash_reporter


def trigger_crash():
    # note: do not change the type of the exception, the message,
    # or the name of this method. All reports generated through this
    # method will be grouped together by the crash reporter, and thus
    # don't spam the issue tracker.

    class TestingException(Exception):
        pass

    def crash_test():
        raise TestingException("triggered crash for testing purposes")

    import threading
    t = threading.Thread(target=crash_test)
    t.start()
