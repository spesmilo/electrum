#!/usr/bin/env python3
#
# This file is:
#     Copyright (C) 2018 Calin Culianu <calin.culianu@gmail.com>
#
# MIT License
#

from .uikit_bindings import *
from . import gui
from . import utils
import app
import time

BG_HARD_LIMIT_SECS = 120.0

class PythonAppDelegate(UIResponder):

    firstRun = objc_property()
    blurView = objc_property()

    @objc_method
    def init(self) -> ObjCInstance:
        self = ObjCInstance(send_super(__class__, self, 'init'))
        if self is not None:
            self.firstRun = True
            self.blurView = None

        return self

    @objc_method
    def dealloc(self) -> None:
        self.cleanupBlurView()
        self.firstRun = None # clear out var
        send_super(__class__, self, 'dealloc')

    @objc_method
    def application_willFinishLaunchingWithOptions_(self, application : ObjCInstance, launchOptions : ObjCInstance) -> bool:
        # tell iOS that our app refreshes content in the background
        #application.setMinimumBackgroundFetchInterval_(UIApplicationBackgroundFetchIntervalMinimum)
        #bgStatus = "Enabled for this app." if UIBackgroundRefreshStatusAvailable == int(application.backgroundRefreshStatus) else "DISABLED"
        #print("Background refresh status: %s\nBackground fetch minimum interval: %f s\nMinimum Keep Alive Timeout: %f s"%(bgStatus,UIApplicationBackgroundFetchIntervalMinimum,UIMinimumKeepAliveTimeout))

        utils.ios13_status_bar_workaround.appdelegate_hook(appdelegate = self,
                                                           application = application)

        return True

    @objc_method
    def application_didFinishLaunchingWithOptions_(self, application : ObjCInstance, launchOptions : ObjCInstance) -> bool:
        #utils.NSLog("App finished launching. Options: %s",str(py_from_ns(launchOptions) if launchOptions else dict()))

        app.main()

        return True

    @objc_method
    def application_openURL_options_(self, application : ObjCInstance, url : ObjCInstance, options : ObjCInstance) -> bool:
        scheme = url.scheme.lower()
        url_string = url.absoluteString or url.relativeString
        utils.NSLog("Got URL using scheme: %s, absoluteURL/relativeURL: %s", scheme, url_string)
        eg = gui.ElectrumGui.gui
        ret = True
        if eg:
            if scheme == 'bitcoincash':
                eg.open_bitcoincash_url(url_string)
            elif scheme == 'file':
                data, filename = utils.nsurl_read_local_file(url)
                utils.NSLog("App file openURL: %s Options: %s",str(filename),str(py_from_ns(options) if options else dict()))
                eg.open_ext_txn(data)
            else:
                utils.NSLog("Unknown URL scheme, ignoring!")
        else:
            utils.NSLog("ERROR -- no gui! Cannot open txn!")
            ret = False
        return ret

    # NB: According to apple docs, it's bad to abuse this method if you actually do no downloading, so disabled.
    # If we reenable be sure to add the appropriate BackgroundModes key to Info.plist
    '''@objc_method
    def application_performFetchWithCompletionHandler_(self, application : ObjCInstance, completionHandler : ObjCInstance) -> None:
        print("Background: WOAH DUDE! AppDelegate fetch handler called! It worked!")
        print("Background: About to call completion handler.. lord have mercy!")
        completionHandler(UIBackgroundFetchResultNewData)
    '''

    @objc_method
    def application_didChangeStatusBarOrientation_(self, application, oldStatusBarOrientation: int) -> None:
        print("ROTATED", oldStatusBarOrientation)
        gui.ElectrumGui.gui.on_rotated()

## BG/FG management... do some work in the BG

    @objc_method
    def applicationDidBecomeActive_(self, application : ObjCInstance) -> None:
        s,f = cleanup_possible_bg_task_stuff()
        f()
        msg = "App became active " + s
        utils.NSLog("%s",msg)

        self.cleanupBlurView()
        eg = gui.ElectrumGui.gui
        if eg is not None and not self.firstRun:
            if not eg.daemon_is_running():
                utils.NSLog("Background: Restarting Daemon...")
                eg.start_daemon()
            else:
                # <50MB disk space will show an error and stop daemon
                eg.check_low_diskspace()

        self.firstRun = False


    @objc_method
    def cleanupBlurView(self) -> None:
        if self.blurView:
            self.blurView.removeFromSuperview()
            self.blurView = None

    @objc_method
    def addBlurView(self) -> None:
        self.cleanupBlurView()
        self.blurView = utils.boilerplate.create_and_add_blur_view(UIApplication.sharedApplication.keyWindow)


    @objc_method
    def applicationDidEnterBackground_(self, application : ObjCInstance) -> None:
        if not self.firstRun:
            startup_bg_task_stuff(application)
            eg = gui.ElectrumGui.gui
            if eg:
                eg.on_backgrounded()
                if eg.wallet:
                    self.addBlurView() # protect user's privacy -- this makes the snapshot view on iOS be blurred.

    @objc_method
    def applicationWillTerminate_(self, application : ObjCInstance) -> None:
        eg = gui.ElectrumGui.gui
        if eg is not None and eg.daemon_is_running():
            utils.NSLog("Termination: Stopping Daemon...")
            eg.stop_daemon()

    # this gets fired when another app window overlays out app and/or user pulls down notification bar, etc
    @objc_method
    def applicationWillResignActive_(self, application : ObjCInstance) -> None:
        utils.NSLog("Appliction will resign active message received")


## Global helper functions for this bgtask stuff
bgTask = UIBackgroundTaskInvalid
bgTimer = None

def startup_bg_task_stuff(application : ObjCInstance) -> None:
    global bgTask
    global bgTimer
    utils.NSLog("Background: Entered background, notifying iOS about bgTask, starting bgTimer.")

    bgTask = application.beginBackgroundTaskWithName_expirationHandler_(at("Electron_Cash_Background_Task"), on_bg_task_expiration)

    if bgTimer is not None: utils.NSLog("Background: bgTimer was not None. FIXME!")

    def onTimer() -> None:
        global bgTask
        global bgTimer
        bgTimer = None
        if bgTask != UIBackgroundTaskInvalid:
            utils.NSLog("Background: Our expiry timer fired, will force expiration handler to execute early.")
            on_bg_task_expiration()
        else:
            utils.NSLog("Background: Our expiry timer fired, but bgTask was already stopped.")

    timerTime = max(min(BG_HARD_LIMIT_SECS, application.backgroundTimeRemaining-5.0), 0.010)
    utils.NSLog("Background: Time remaining is %f secs, our timer will fire in %f secs.",float(application.backgroundTimeRemaining),float(timerTime))
    bgTimer = utils.call_later(timerTime,onTimer) # if we don't do this we get problems because iOS freezes our task and that crashes stuff in the daemon

def cleanup_possible_bg_task_stuff() -> (str, callable):
    global bgTask
    global bgTimer

    func = lambda: False

    msg = ""

    if bgTimer is not None:
        bgTimer.invalidate()
        bgTimer = None
        msg += "killed extant bgTimer"
    else:
        msg += "no bgTimer was running"

    if bgTask != UIBackgroundTaskInvalid:
        bgTask_saved = bgTask
        bgTask = UIBackgroundTaskInvalid
        def sleepThenKill() -> None:
            if UIApplication.sharedApplication.applicationState == UIApplicationStateBackground:
                #print("Sleeping 1 sec...")
                time.sleep(1.0) # give threads a chance to do stuff
            UIApplication.sharedApplication.endBackgroundTask_(bgTask_saved)
            # at this point our process may be suspended if we were in the background state
        func = sleepThenKill
        msg += ", told UIKit to end our bgTask"
    else:
        msg += ", we did not have a bgTask active"
    return msg, func

def on_bg_task_expiration() -> None:
    utils.NSLog("Background: Expiration handler called")

    daemonStopped = False
    eg = gui.ElectrumGui.gui
    if eg is not None and eg.daemon_is_running():
        utils.NSLog("Background: Stopping Daemon...")
        eg.stop_daemon()
        daemonStopped = True

    msg = "Background: "
    s,func = cleanup_possible_bg_task_stuff()
    msg += s
    msg += ", stopped daemon" if daemonStopped else ""
    utils.NSLog("%s",msg)
    func()         # at this point we may get suspended if we were in the background state..
