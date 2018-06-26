#
# This file is:
#     Copyright (C) 2018 Calin Culianu <calin.culianu@gmail.com>
#
# MIT License

from . import utils
from . import gui
from electroncash.i18n import _

from .uikit_bindings import *
from .custom_objc import *
import json, traceback, requests, sys
from electroncash import PACKAGE_VERSION


issue_template = """<font face=arial color="#414141">
<h2>Traceback</h2>
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
</font>
"""
#BauerJ's testing server
#report_server = "https://crashhubtest.bauerj.eu/crash"
# "Live" (Marcel's server)
report_server = "https://crashhub.electroncash.org/crash"

Singleton = None

class CrashReporterVC(CrashReporterBase):
    
    @objc_method
    def dealloc(self) -> None:
        global Singleton
        Singleton = None
        utils.nspy_pop(self)
        send_super(__class__, self, 'dealloc')
        
    @objc_method
    def viewDidLoad(self) -> None:
        send_super(__class__, self, 'viewDidLoad')
        global Singleton
        Singleton = self
        self.report.text = ""
        self.reportTit.setText_withKerning_(_("Report Contents"), utils._kern)
        self.descTit.setText_withKerning_(_("Please briefly describe what led to the error (optional):").translate({ord(':'):None}), utils._kern)
        utils.uilabel_replace_attributed_text(self.errMsg,
                                               _('Sorry!')  + " " + _('Something went wrong running Electron Cash.') + " " + _('To help us diagnose and fix the problem, you can send us a bug report that contains useful debug information:').translate({ord(':'):None}),
                                               font = UIFont.italicSystemFontOfSize_(12.0)
                                              )
        self.descDel.placeholderFont = UIFont.italicSystemFontOfSize_(14.0)
        self.descDel.font = UIFont.systemFontOfSize_(14.0)
        self.descDel.placeholderText = _('Tap to enter text...')
        self.descDel.text = ""
        
        self.title = _('Crash Reporter')
        
    @objc_method
    def viewWillAppear_(self, animated : bool) -> None:
        send_super(__class__, self, 'viewWillAppear:', animated, argtypes=[c_bool])
        self.kbas = utils.register_keyboard_autoscroll(self.sv)

        # Below will be enabled if we have valid exception info
        self.sendBut.setEnabled_(False)
        utils.uiview_set_enabled(self.sendBut, False)

    @objc_method
    def viewWillDisappear_(self, animated : bool) -> None:
        send_super(__class__, self, 'viewWillDisappear:', animated, argtypes=[c_bool])
        if self.kbas:
            utils.unregister_keyboard_autoscroll(self.kbas)
            self.kbas = 0

    @objc_method
    def viewDidAppear_(self, animated : bool) -> None:
        send_super(__class__, self, 'viewDidAppear:', animated, argtypes=[c_bool])
        ei = _Get(self)
        if ei:
            self.report.attributedText = utils.nsattributedstring_from_html(_get_report_string(self))
            self.sendBut.setEnabled_(True)
            utils.uiview_set_enabled(self.sendBut, True)

        
    @objc_method
    def onSendBut_(self, sender) -> None:
        def SendReport() -> str:
            reportDict = _get_traceback_info(self)
            reportDict.update(_get_additional_info(self))
            report = json.dumps(reportDict)
            #reportPretty = json.dumps(reportDict, indent=4)
            #utils.NSLog("Report contents: %s", reportPretty)
            response = requests.post(report_server, data=report)
            return response.text
        def onOk() -> None: self.presentingViewController.dismissViewControllerAnimated_completion_(True, None)
        def OnSuccess(response : str) -> None:
            utils.NSLog("Response from server: %s", response)
            response = response.strip()
            if len(response) > 255: response = response[:255] + "..."
            try:
                response = str(utils.nsattributedstring_from_html(response).string)
            except:
                pass
            parent().show_message(message = response, title=_("Report Sent"), vc = self, onOk=onOk)
        def OnError(exc) -> None:
            parent().show_error(message = str(exc[1]), vc = self)

        utils.WaitingDialog(self, _("Sending Report..."), SendReport,  OnSuccess, OnError)
        
def _Get(vc: CrashReporterVC) -> tuple:
    return utils.nspy_get_byname(vc, 'exc_info')

def Set(vc : CrashReporterVC, exc_info : tuple) -> None:
    utils.nspy_put_byname(vc, exc_info, 'exc_info')

def parent() -> object:
    return gui.ElectrumGui.gui

def _get_traceback_info(vc : CrashReporterVC) -> dict:
    ei = _Get(vc)
    if not ei: return dict()
    exc_string = str(ei[1])
    stack = traceback.extract_tb(ei[2])
    readable_trace = "".join(traceback.format_list(stack))
    ident = {
        "file": stack[-1].filename,
        "name": stack[-1].name,
        "type": ei[0].__name__
    }
    return {
        "exc_string": exc_string,
        "stack": readable_trace,
        "id": ident
    }

def _get_additional_info(vc : CrashReporterVC) -> dict:
    import platform
    bundleVer = "iOS Build: " + str(NSBundle.mainBundle.objectForInfoDictionaryKey_("CFBundleVersion"))
    #xtraInfo = bundleVer + "\niOS Version String: " + utils.ios_version_string() + "\n\n"
    args = {
        "app_version": PACKAGE_VERSION + (" (%s)"%bundleVer),
        "python_version": sys.version,
        "os": platform.platform() + " " + utils.ios_version_string(),
        "wallet_type": "unknown",
        "locale": (parent().language or 'UNK'),
        "description": (vc.descDel.text if vc.descDel.text else "")
    }
    if len(args['os']) > 255:
        args['os'] = args['os'][:255]
    try:
        args["wallet_type"] = parent().wallet.wallet_type
    except:
        # Maybe the wallet isn't loaded yet
        pass
    return args

def _get_report_string(vc : CrashReporterVC) -> str:
    info = _get_additional_info(vc)
    ei = _Get(vc)
    if not ei: return ""
    info["traceback"] = "".join(traceback.format_exception(*ei))
    return issue_template.format(**info)


'''
th = None
def Test():
    # testing
    import time
    def duh() -> None:
        raise Exception("A random exception!!")
    
    utils.call_later(2.0, duh)
    utils.call_later(3.0, duh)
    #utils.call_later(10.0, duh)

    def duh2() -> None:
        global th
        def thrd():
            global th
            try:
                utils.NSLog("In another thread.. sleeping 5 secs")
                print(th)
                time.sleep(5.0)
                utils.NSLog("Woke up.. raising exception...")
                raise Exception("From another thread!!")
            finally:
                th = None
        
        import threading
        th = threading.Thread(target=thrd, name="Exception thread...", daemon=True)
        th.start()

    utils.call_later(5.0, duh2)
'''
