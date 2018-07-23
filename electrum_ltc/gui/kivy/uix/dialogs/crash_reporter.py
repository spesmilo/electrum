import sys

import requests
from kivy import base, utils
from kivy.clock import Clock
from kivy.core.window import Window
from kivy.factory import Factory
from kivy.lang import Builder
from kivy.uix.label import Label
from kivy.utils import platform

from electrum_ltc.gui.kivy.i18n import _

from electrum_ltc.base_crash_reporter import BaseCrashReporter


Builder.load_string('''
<CrashReporter@Popup>
    BoxLayout:
        orientation: 'vertical'
        Label:
            id: crash_message
            text_size: root.width, None
            size: self.texture_size
            size_hint: None, None
        Label:
            id: request_help_message
            text_size: root.width*.95, None
            size: self.texture_size
            size_hint: None, None
        BoxLayout:
            size_hint: 1, 0.1
        Button:
            text: 'Show report contents'
            height: '48dp'
            size_hint: 1, None
            on_press: root.show_contents()
        BoxLayout:
            size_hint: 1, 0.1
        Label:
            id: describe_error_message
            text_size: root.width, None
            size: self.texture_size
            size_hint: None, None
        TextInput:
            id: user_message
            size_hint: 1, 0.3
        BoxLayout:
            size_hint: 1, 0.7
        BoxLayout:
            size_hint: 1, None
            height: '48dp'
            orientation: 'horizontal'
            Button:
                height: '48dp'
                text: 'Send'
                on_release: root.send_report()
            Button:
                text: 'Never'
                on_release: root.show_never()
            Button:
                text: 'Not now'
                on_release: root.dismiss()

<CrashReportDetails@Popup>
    BoxLayout:
        orientation: 'vertical'
        ScrollView:
            do_scroll_x: False
            Label:
                id: contents
                text_size: root.width*.9, None
                size: self.texture_size
                size_hint: None, None
        Button:
            text: 'Close'
            height: '48dp'
            size_hint: 1, None
            on_release: root.dismiss()
''')


class CrashReporter(BaseCrashReporter, Factory.Popup):
    issue_template = """[b]Traceback[/b]

[i]{traceback}[/i]


[b]Additional information[/b]
 * Electrum version: {app_version}
 * Operating system: {os}
 * Wallet type: {wallet_type}
 * Locale: {locale}
        """

    def __init__(self, main_window, exctype, value, tb):
        BaseCrashReporter.__init__(self, exctype, value, tb)
        Factory.Popup.__init__(self)
        self.main_window = main_window
        self.title = BaseCrashReporter.CRASH_TITLE
        self.title_size = "24sp"
        self.ids.crash_message.text = BaseCrashReporter.CRASH_MESSAGE
        self.ids.request_help_message.text = BaseCrashReporter.REQUEST_HELP_MESSAGE
        self.ids.describe_error_message.text = BaseCrashReporter.DESCRIBE_ERROR_MESSAGE

    def show_contents(self):
        details = CrashReportDetails(self.get_report_string())
        details.open()

    def show_popup(self, title, content):
        popup = Factory.Popup(title=title,
                              content=Label(text=content, text_size=(Window.size[0] * 3/4, None)),
                              size_hint=(3/4, 3/4))
        popup.open()

    def send_report(self):
        try:
            response = BaseCrashReporter.send_report(self, "/crash.json").json()
        except requests.exceptions.RequestException:
            self.show_popup(_('Unable to send report'), _("Please check your network connection."))
        else:
            self.show_popup(_('Report sent'), response["text"])
            if response["location"]:
                self.open_url(response["location"])
        self.dismiss()

    def open_url(self, url):
        if platform != 'android':
            return
        from jnius import autoclass, cast
        String = autoclass("java.lang.String")
        url = String(url)
        PythonActivity = autoclass('org.kivy.android.PythonActivity')
        activity = PythonActivity.mActivity
        Intent = autoclass('android.content.Intent')
        Uri = autoclass('android.net.Uri')
        browserIntent = Intent()
        # This line crashes the app:
        # browserIntent.setAction(Intent.ACTION_VIEW)
        # Luckily we don't need it because the OS is smart enough to recognize the URL
        browserIntent.setData(Uri.parse(url))
        currentActivity = cast('android.app.Activity', activity)
        currentActivity.startActivity(browserIntent)

    def show_never(self):
        self.main_window.electrum_config.set_key(BaseCrashReporter.config_key, False)
        self.dismiss()

    def get_user_description(self):
        return self.ids.user_message.text

    def get_wallet_type(self):
        return self.main_window.wallet.wallet_type

    def get_os_version(self):
        if utils.platform is not "android":
            return utils.platform
        import jnius
        bv = jnius.autoclass('android.os.Build$VERSION')
        b = jnius.autoclass('android.os.Build')
        return "Android {} on {} {} ({})".format(bv.RELEASE, b.BRAND, b.DEVICE, b.DISPLAY)


class CrashReportDetails(Factory.Popup):
    def __init__(self, text):
        Factory.Popup.__init__(self)
        self.title = "Report Details"
        self.ids.contents.text = text
        print(text)


class ExceptionHook(base.ExceptionHandler):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        if not main_window.electrum_config.get(BaseCrashReporter.config_key, default=True):
            return
        # For exceptions in Kivy:
        base.ExceptionManager.add_handler(self)
        # For everything else:
        sys.excepthook = lambda exctype, value, tb: self.handle_exception(value)

    def handle_exception(self, _inst):
        exc_info = sys.exc_info()
        # Check if this is an exception from within the exception handler:
        import traceback
        for item in traceback.extract_tb(exc_info[2]):
            if item.filename.endswith("crash_reporter.py"):
                return
        e = CrashReporter(self.main_window, *exc_info)
        # Open in main thread:
        Clock.schedule_once(lambda _: e.open(), 0)
        return base.ExceptionManager.PASS
