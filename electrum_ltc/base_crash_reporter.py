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
import traceback
import subprocess
import sys
import os

import requests

from .version import ELECTRUM_VERSION
from .import constants
from .i18n import _


class BaseCrashReporter(object):
    report_server = "https://crashhub.electrum-ltc.org"
    config_key = "show_crash_reporter"
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

    def __init__(self, exctype, value, tb):
        self.exc_args = (exctype, value, tb)

    def send_report(self, endpoint="/crash"):
        if constants.net.GENESIS[-4:] not in ["29a0", "bfe2"] and ".electrum-ltc.org" in BaseCrashReporter.report_server:
            # Gah! Some kind of altcoin wants to send us crash reports.
            raise Exception(_("Missing report URL."))
        report = self.get_traceback_info()
        report.update(self.get_additional_info())
        report = json.dumps(report)
        response = requests.post(BaseCrashReporter.report_server + endpoint, data=report)
        return response

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
            "app_version": ELECTRUM_VERSION,
            "python_version": sys.version,
            "os": self.get_os_version(),
            "wallet_type": "unknown",
            "locale": locale.getdefaultlocale()[0] or "?",
            "description": self.get_user_description()
        }
        try:
            args["wallet_type"] = self.get_wallet_type()
        except:
            # Maybe the wallet isn't loaded yet
            pass
        try:
            args["app_version"] = self.get_git_version()
        except:
            # This is probably not running from source
            pass
        return args

    @staticmethod
    def get_git_version():
        dir = os.path.dirname(os.path.realpath(sys.argv[0]))
        version = subprocess.check_output(
            ['git', 'describe', '--always', '--dirty'], cwd=dir)
        return str(version, "utf8").strip()

    def get_report_string(self):
        info = self.get_additional_info()
        info["traceback"] = "".join(traceback.format_exception(*self.exc_args))
        return self.issue_template.format(**info)

    def get_user_description(self):
        raise NotImplementedError

    def get_wallet_type(self):
        raise NotImplementedError

    def get_os_version(self):
        raise NotImplementedError 
