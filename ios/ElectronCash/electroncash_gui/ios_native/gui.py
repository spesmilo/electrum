#!/usr/bin/env python3
#
# Electron Cash - lightweight Bitcoin Cash client
# Copyright (C) 2012 thomasv@gitorious
#
# This file is:
#     Copyright (C) 2018 Calin Culianu <calin.culianu@gmail.com>
#
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

import sys, os, time, threading, shutil
from decimal import Decimal
from functools import partial
from typing import Callable, Any
from .uikit_bindings import *
from . import utils
from . import history
from . import addresses
from . import send
from . import receive
from . import prefs
from . import password_dialog
from . import seed_dialog
from . import network_dialog
from . import coins
from . import contacts
from . import wallets
from . import newwallet  # Do not remove -- needed to declare NewWalletVC to ObjC runtime  (used by storyboard instantiation)
from .custom_objc import *

from electroncash.i18n import _, set_language, languages
from electroncash.plugins import run_hook
from electroncash import WalletStorage, Wallet, Transaction
from electroncash.address import Address
from electroncash.util import UserCancelled, print_error, format_satoshis, format_satoshis_plain, PrintError, InvalidPassword, inv_base_units
import electroncash.web as web

class WalletFileNotFound(Exception):
    pass

class MyTabBarController(UITabBarController):

    didLayout = objc_property()

    @objc_method
    def init(self) -> ObjCInstance:
        self = ObjCInstance(send_super(__class__, self, 'init'))
        if self is not None:
            self.didLayout = False
            self.modalPresentationStyle = UIModalPresentationFullScreen
        return self

    @objc_method
    def viewDidLayoutSubviews(self) -> None:
        self.didLayout = True
        send_super(__class__, self, 'viewDidLayoutSubviews')

    @objc_method
    def supportedInterfaceOrientations(self) -> int:
        pvc = self.presentedViewController
        if pvc:
            while pvc.presentedViewController:
                pvc = pvc.presentedViewController
            if not isinstance(pvc, UIAlertController):
                return pvc.supportedInterfaceOrientations()
        return send_super(__class__, self, 'supportedInterfaceOrientations', restype=c_int)

    @objc_method
    def shouldAutorotate(self) -> bool:
        pvc = self.presentedViewController
        if pvc:
            while pvc.presentedViewController:
                pvc = pvc.presentedViewController
            if not isinstance(pvc, UIAlertController):
                return pvc.shouldAutorotate()
        return send_super(__class__, self, 'shouldAutorotate', restype=c_bool)


class GuiHelper(NSObject):

    @objc_method
    def init(self):
        self = ObjCInstance(send_super(__class__, self, 'init'))
        ElectrumGui.gui.sigHelper.connect(lambda: self.doUpdate(), self.ptr.value)
        return self

    @objc_method
    def dealloc(self) -> None:
        ElectrumGui.gui.sigHelper.disconnect(self.ptr.value)
        send_super(__class__, self, 'dealloc')

    @objc_method
    def onTimer_(self, ignored):
        pass

    @objc_method
    def doUpdate(self):
        if ElectrumGui.gui is not None:
            ElectrumGui.gui.on_status_update()

    @objc_method
    def onRefreshControl_(self, refreshControl : ObjCInstance) -> None:
        if ElectrumGui.gui is not None:
            ElectrumGui.gui.refresh_all()

    @objc_method
    def bindRefreshControl_(self, refreshControl: ObjCInstance) -> None:
        if (refreshControl is not None
            and refreshControl.actionsForTarget_forControlEvent_(self, UIControlEventValueChanged) is None):
            refreshControl.addTarget_action_forControlEvents_(self,SEL('onRefreshControl:'), UIControlEventValueChanged)

    @objc_method
    def createAndBindRefreshControl(self) -> ObjCInstance:
        rc = UIRefreshControl.new().autorelease()
        self.bindRefreshControl_(rc)
        return rc

    @objc_method
    def onModalClose_(self,but) -> None:
        if ElectrumGui.gui is not None:
            ElectrumGui.gui.on_modal_close(but)

    @objc_method
    def navigationController_willShowViewController_animated_(self, nav, vc, anim : bool) -> None:
        return

    @objc_method
    def tabBarController_didEndCustomizingViewControllers_changed_(self, tabController, viewControllers, changed : bool) -> None:
        return

    @objc_method
    def tabBarController_shouldSelectViewController_(self, vc) -> bool:
        if not isinstance(vc, wallets.WalletsNav):
            return not ElectrumGui.gui.warn_user_if_no_wallet()


# Manages the GUI. Part of the ElectronCash API so you can't rename this class easily.
class ElectrumGui(PrintError):

    gui = None

    def __init__(self, config):
        ElectrumGui.gui = self
        self.appName = 'Electron-Cash'
        self.appDomain = 'com.c3-soft.ElectronCash'
        self.set_language()

        # Signals mechanism for publishing data to interested components asynchronously -- see self.refresh_components()
        self.sigHelper = utils.PySig()
        self.sigHistory = history.HistoryMgr() # this DataMgr instance also caches history data
        self.sigAddresses = addresses.AddressesMgr()
        self.sigPrefs = utils.PySig()
        self.sigRequests = receive.RequestsMgr()
        self.sigNetwork = utils.PySig()
        self.sigContacts = contacts.ContactsMgr()
        self.sigCoins = coins.CoinsMgr()
        self.sigWallets = wallets.WalletsMgr()
        self.contactHistSync = history.ContactsHistorySynchronizer(self)
        # More signals.. Qt desktop workalikes
        self.payment_request_ok_signal = utils.PySig(); self.payment_request_ok_signal.connect(self.payment_request_ok)
        self.payment_request_error_signal = utils.PySig(); self.payment_request_error_signal.connect(self.payment_request_error)
        self.payment_request_lock = threading.Lock()

        #todo: support multiple wallets in 1 UI?
        self.config = config
        self.daemon = None
        self.plugins = None
        self.wallet = None
        self.window = None
        self.tabController = None
        self.rootVCs = None
        self.tabs = None
        self.sendVC = None
        self.sendNav = None
        self.receiveVC = None
        self.receiveNav = None
        self.addressesNav = None
        self.addressesVC = None
        self.coinsNav = None
        self.coinsVC = None
        self.contactsVC = None
        self.contactsNav = None
        self.walletsNav = None
        self.walletsVC = None

        self.prefsVC = None
        self.prefsNav = None
        self.networkVC = None
        self.networkNav = None

        self.onboardingWizard = None

        self.decimal_point = config.get('decimal_point', 5)
        self.fee_unit = config.get('fee_unit', 0)
        self.num_zeros     = self.prefs_get_num_zeros()
        self.alias_info = None # TODO: IMPLEMENT alias stuff
        self.lastHeightSeen = -2
        self.lastSplitNotify = 0

        Address.show_cashaddr(self.prefs_get_use_cashaddr())

        self.cash_addr_sig = utils.PySig()

        self.tx_notifications = list()
        self.tx_notify_timer = None
        self.tx_notify_last_ts = 0.0
        self.helper = None
        self.helperTimer = None
        self.lowMemoryToken = None
        self.downloadingNotif = None
        self.downloadingNotif_view = None
        self.queued_ext_txn = None
        self.queued_payto_uri = None
        self.queued_refresh_components = set()
        self.queued_refresh_components_mut = threading.Lock()
        self.last_refresh = 0
        self.refresh_rate_min = 0.300
        self.refresh_rate_max = 5.0
        self.refresh_rate_current = self.refresh_rate_min
        self.refresh_cost_stats = dict()
        self.header_dl_start_height = 0

        self.keyEnclave = utils.SecureKeyEnclave(self.appDomain)
        self.encPasswords = utils.FileBackedDict(os.path.join(self.config.path, 'enc_pws.json'))
        self.touchIdAsked = utils.FileBackedDict(os.path.join(self.config.path, 'touch_id_asked.json'))
        self.killableAlerts = dict()

        self.window = UIWindow.alloc().initWithFrame_(UIScreen.mainScreen.bounds)

        # If this is uncommented, use launch screen with logo and activity animation.
        NSBundle.mainBundle.loadNibNamed_owner_options_("Splash2",self.window,None)

        # To swith to the 'basic' fake UI launch screen:
        #
        #  1. Rename LaunchScreen.storyboard -> LaunchScreen_WithLogo.storyboard
        #  2. Rename LaunchScreen_Basic.storyboard -> LaunchScreen.storyboard
        #  3. Get rid of the call_later(0.010,gui.main) call in app.py and call gui.main() directly
        #  4. Comment-out the above Splash2 load, uncomment the subsequent triple-quoted section
        #
        # To switch to the 'logo-based' launch screen:
        #
        #  1. Rename LaunchScreen.storyboard -> LaunchScreen_Basic.storyboard
        #  2. Rename LaunchScreen_WithLogo.storyboard -> LaunchScreen.storyboard
        #  3. Add call_later(0.010,gui.main) call in app.py, rather than calling gui.main() directly
        #  4. Uncomment the above Splash2 load, comment-out the below section
        '''
        # This is seemingly redundant but..
        # 1. We do the below in case user is on a very slow device so that iOS doesn't kill us for not creating a window in time.
        #    I timed it and on my iPhone 6s this adds about 20-30ms to startup time. Surprisingly quick. So we do it.
        # 2. This also safeguards against us possibly doing callbacks later that delay the creation of the window and root view controller
        #
        sb = UIStoryboard.storyboardWithName_bundle_("LaunchScreen", None)
        if not sb:
            utils.NSLog("*** ERROR: LaunchScreen.storyboard not found! WTF?")
        else:
            tb = sb.instantiateViewControllerWithIdentifier_("TabController")
            self.window.rootViewController = tb
        '''
        #

        self.window.makeKeyAndVisible()
        utils.NSLog("GUI instance created, splash screen 2 presented")

    def createAndShowUI(self):
        self.helper = GuiHelper.alloc().init()

        self.tabController = MyTabBarController.alloc().init().autorelease()
        self.tabController.tabBar.tintColor = utils.uicolor_custom('nav')
        self.tabController.tabBar.setTranslucent_(False)

        self.addressesVC = adr = addresses.AddressesVC.alloc().initWithMode_(UITableViewStylePlain, addresses.ModeNormal).autorelease()

        self.coinsVC = cns = coins.CoinsTableVC.alloc().initWithStyle_(UITableViewStylePlain).autorelease()

        self.contactsVC = cntcts = contacts.ContactsVC.new().autorelease()
        self.prefsVC = prefs.PrefsVC.new().autorelease()

        # Wallets tab
        objs = NSBundle.mainBundle.loadNibNamed_owner_options_("WalletsTab",None,None)
        for obj in objs:
            if isinstance(obj, wallets.WalletsNav):
                self.walletsNav = nav1 = obj
                self.walletsVC = self.walletsNav.topViewController
                self.walletsVC.reqstv.refreshControl = self.helper.createAndBindRefreshControl()

                # translate text hardcoded in .nib
                self.walletsNav.tabBarItem.title = _("Wallets")
                for state in UIControlState_ALL_RELEVANT_TUPLE:
                    self.walletsVC.sendBut.setTitle_forState_(_("Send"), state)
                    self.walletsVC.receiveBut.setTitle_forState_(_("Receive"), state)
                utils.uilabel_replace_attributed_text(lbl = self.walletsVC.noTXsLabel,
                                                      text = _("There are no transactions for this wallet on the blockchain."),
                                                      template = self.walletsVC.noTXsLabel.attributedText)
                utils.uilabel_replace_attributed_text(lbl = self.walletsVC.noReqsLabel,
                                                      text = _("No payment requests found. Feel free to create one."),
                                                      template = self.walletsVC.noReqsLabel.attributedText)

                break
        if not self.walletsNav:
            raise Exception('Wallets Nav is None!')

        self.addressesNav = nav2 = CustomNavController.alloc().initWithRootViewController_(adr).autorelease()
        self.coinsNav = nav3 = CustomNavController.alloc().initWithRootViewController_(cns).autorelease()
        self.contactsNav = nav4 = CustomNavController.alloc().initWithRootViewController_(cntcts).autorelease()
        self.prefsNav = nav5 = CustomNavController.alloc().initWithRootViewController_(self.prefsVC).autorelease()

        self.tabs = [utils.tintify(x) for x in [nav1, nav2, nav3, nav4, nav5]]
        self.rootVCs = dict()
        bii = self.walletsNav.navigationBar.backIndicatorImage if self.walletsNav and self.walletsNav.navigationBar else None
        for i,nav in enumerate(self.tabs):
            vc = nav.viewControllers[0]
            nav.tabBarItem.tag = i
            if bii:
                nav.navigationBar.backIndicatorImage = bii
                nav.navigationBar.backIndicatorTransitionMaskImage = bii
            nav.viewControllers[0].tabBarItem.tag = i
            self.rootVCs[nav.ptr.value] = vc

        self.tabController.viewControllers = self.tabs
        self.tabController.delegate = self.helper # just in case we need this for later UI stuff...

        self.helper.doUpdate()

        self.lowMemoryToken = NSNotificationCenter.defaultCenter.addObserverForName_object_queue_usingBlock_(
            UIApplicationDidReceiveMemoryWarningNotification,
            UIApplication.sharedApplication,
            None,
            Block(lambda: self.on_low_memory(), restype=None)
        ).retain()

        self.window.backgroundColor = UIColor.whiteColor
        self.window.rootViewController = self.tabController

        self.window.makeKeyAndVisible()

        sys.excepthook = self.exception_handler
        utils.setup_thread_excepthook()

        utils.NSLog("UI Created Ok")

    def register_network_callbacks(self):
        # network callbacks
        if self.daemon.network:
            self.daemon.network.register_callback(self.on_history, ['on_history'])
            self.daemon.network.register_callback(self.on_quotes, ['on_quotes'])
            interests = ['wallet_updated', 'blockchain_updated',
                         'new_transaction', 'status', 'banner', 'verified2',
                         'fee', 'interfaces']
            # To avoid leaking references to "self" that prevent the
            # window from being GC-ed when closed, callbacks should be
            # methods of this class only, and specifically not be
            # partials, lambdas or methods of subobjects.  Hence...
            self.daemon.network.register_callback(self.on_network, interests)
            # Set the node and server retry interval to more reasonable valus for iOS
            # This is because on mobile we really may have a spotty connection so
            # it pays to retry often
            self.daemon.network.NODES_RETRY_INTERVAL = 20  # seconds
            self.daemon.network.SERVER_RETRY_INTERVAL = 3  # seconds
            utils.NSLog("REGISTERED NETWORK CALLBACKS")

    def unregister_network_callbacks(self):
        if self.daemon and self.daemon.network:
            self.daemon.network.unregister_callback(self.on_history)
            self.daemon.network.unregister_callback(self.on_quotes)
            self.daemon.network.unregister_callback(self.on_network)
            utils.NSLog("UN-REGISTERED NETWORK CALLBACKS")


    def get_image_for_tab_index(self, index) -> ObjCInstance:
        if not self.tabController: return None
        vcs = self.tabController.viewControllers
        if index < 0 or index >= len(vcs): return None
        return vcs[index].tabBarItem.image

    def setup_downloading_notif(self):
        if self.downloadingNotif is not None: return
        self.downloadingNotif = CWStatusBarNotification.new()
        def OnTap() -> None:
            self.query_hide_downloading_notif()
            pass
        # NB: if I change the type it crashes sometimes on app startup due to bugs in this control.. perhaps?
        self.downloadingNotif.notificationAnimationType = CWNotificationAnimationTypeOverlay
        self.downloadingNotif.notificationTappedBlock = OnTap
        if self.downloadingNotif_view is None:
            objs = NSBundle.mainBundle.loadNibNamed_owner_options_("ActivityStatusNotificationView",None,None)
            if objs is None or not len(objs):
                raise Exception("Could not load ActivityStatusNotificationView nib!")
            lbl = objs[0].viewWithTag_(2)
            if lbl is not None:
                lbl.text = _("Downloading blockchain headers...")
            self.downloadingNotif_view = objs[0].retain()

    def __del__(self):
        utils.NSLog("GUI instance __del__")
        self.dispose()

    def dispose(self):
        self.queued_ext_txn = None
        if self.window is None:
            return

        utils.cleanup_thread_excepthook()

        if sys.excepthook != sys.__excepthook__:
            sys.excepthook = sys.__excepthook__

        self.stop_daemon()
        if self.lowMemoryToken is not None:
            NSNotificationCenter.defaultCenter.removeObserver_(self.lowMemoryToken.autorelease())
            self.lowMemoryToken = None
        if self.downloadingNotif is not None:
            self.dismiss_downloading_notif()
        if self.downloadingNotif_view is not None:
            self.downloadingNotif_view.autorelease()
            self.downloadingNotif_view = None
        self.networkNav = None
        self.networkVC = None
        self.prefsVC = None
        self.prefsNav = None
        if self.tx_notify_timer is not None:
            self.tx_notify_timer.invalidate()
            self.tx_notify_timer = None
        if self.helperTimer is not None:
            self.helperTimer.invalidate()
            self.helperTimer = None
        if self.tabController is not None:
            self.tabController.viewControllers = None
        if self.sendNav: self.sendNav.release()
        if self.receiveNav: self.receiveNav.release()
        self.sendNav = None
        self.sendVC = None
        self.receiveVC = None
        self.receiveNav = None
        self.addressesNav = None
        self.addressesVC = None
        self.coinsVC = None
        self.coinsNav = None
        self.contactsNav = None
        self.contactsVC = None
        self.window.rootViewController = None
        self.tabController = None
        self.window.release()
        self.window = None
        self.rootVCs = None
        self.tabs = None
        if self.helper is not None: self.helper.release()
        self.helper = None
        self.keyEnclave = None
        self.encPasswords = None
        self.touchIdAsked = None
        self.killableAlerts = dict()
        self.cash_addr_sig.clear()

        self.sigHelper.clear()
        self.sigHistory.clear()
        self.sigAddresses.clear()
        self.sigPrefs.clear()
        self.sigRequests.clear()
        self.sigNetwork.clear()
        self.sigContacts.clear()
        self.sigCoins.clear()
        self.sigWallets.clear()
        self.contactHistSync = None
        self.payment_request_ok_signal.clear(); self.payment_request_ok_signal = None
        self.payment_request_error_signal.clear(); self.payment_request_error_signal = None

    def on_backgrounded(self):
        ct = 0
        for a in self.killableAlerts:
            if a.presentingViewController:
                cb = self.killableAlerts[a]
                a.dismissViewControllerAnimated_completion_(False, Block(lambda: cb(),restype=None) if callable(cb) else None)
                ct += 1
        wasLen = len(self.killableAlerts)
        self.killableAlerts = dict()
        if ct or wasLen:
            utils.NSLog("on_backgrounded: Dismissed %d of %d extant killable alerts", ct, wasLen)

    # killable alerts are immediately dismissed when app goes to background (user hits home button) -- they are for things
    # like convenient questions for the user that aren't important or critical (such as whether to enable touchid, etc)
    # Be sure to use the 'onKilled' callback to react to the alert being killed due to user hitting home button.
    def register_killable_alert(self, alert : UIViewController, onKilled : Callable[[],None] = None) -> None:
        if alert not in self.killableAlerts:
            self.killableAlerts[alert] = onKilled
            def OnDealloc(x : objc_id):
                if alert in self.killableAlerts:
                    self.killableAlerts.pop(alert, None)
                    utils.NSLog("KillableAlert: Reaped 1 alert")
                else:
                    utils.NSLog("KillableAlert: Alert was not found in list. Must have been auto-dismissed.")
            utils.NSDeallocObserver(alert).connect(OnDealloc)

    def on_rotated(self): # called by PythonAppDelegate after screen rotation
        utils.ios13_status_bar_workaround.on_rotated()

    def on_history(self, event, *args):
        utils.NSLog("ON HISTORY '%s' (IsMainThread: %s)",event,str(NSThread.currentThread.isMainThread))
        assert self.walletsVC is not None
        self.refresh_components('history', 'helper')

    def on_quotes(self, event, *args):
        utils.NSLog("ON QUOTES '%s' (IsMainThread: %s)",event,str(NSThread.currentThread.isMainThread))
        #if self.daemon.fx.history_used_spot: #TODO: this is from qt gui.. figure out what this means.. does it help rate-limit?
        self.refresh_components('history', 'addresses', 'helper', 'requests')

    def on_network(self, event, *args):
        utils.NSLog("ON NETWORK: '%s' (IsMainThread: %s)",event,str(NSThread.currentThread.isMainThread))
        if not self.daemon:
            utils.NSLog("(Returning early.. daemon stopped)")
            return
        assert self.walletsVC is not None
        if event == 'blockchain_updated':
            self.refresh_components('helper', 'network')
        elif event == 'new_transaction':
            tx, wallet = args
            if wallet is self.wallet:
                self.tx_notifications.append(tx)
                self.refresh_components('history', 'addresses', 'helper')
        elif event == 'banner':
            #todo: handle console stuff here
            pass
        elif event == 'status':
            #todo: handle status update here
            self.refresh_components('helper')
        elif event in ('verified2', 'wallet_updated'):
            wallet = args[0]
            if wallet is self.wallet:  # this should always be the case. But we check anyway in case in the future we support multiple wallets open at once.
                self.refresh_components('history', 'addresses', 'helper')
        elif event == 'fee':
            # todo: handle fee stuff here
            pass
        elif event in ('interfaces',):
            self.refresh_components('network')
        else:
            self.print_error("unexpected network message:", event, args)

    def show_downloading_notif(self, txt = None):
        if self.prefs_get_downloading_notif_hidden():
            return
        if self.downloadingNotif is None:
            self.setup_downloading_notif()

        if txt is not None and type(txt) is str:
            lbl = self.downloadingNotif_view.viewWithTag_(2)
            if lbl is not None: lbl.text = txt

        activityIndicator = self.downloadingNotif_view.viewWithTag_(1)

        if not activityIndicator.animating:
            activityIndicator.animating = True

        if self.is_downloading_notif_showing():
            return

        def Completion() -> None:
            pass
        self.downloadingNotif_view.removeFromSuperview()
        utils.ios13_status_bar_workaround.push()
        self.downloadingNotif.displayNotificationWithView_completion_(
            self.downloadingNotif_view,
            Completion
        )

    def is_downloading_notif_showing(self):
        return (self.downloadingNotif
                and self.downloadingNotif.notificationIsShowing
                and not self.downloadingNotif.notificationIsDismissing)

    def dismiss_downloading_notif(self):
        if not self.is_downloading_notif_showing(): return
        dnf = self.downloadingNotif
        self.downloadingNotif = None
        def compl() -> None:
            #print("Dismiss completion")
            if (self.downloadingNotif_view is not None
                    and dnf.customView is not None
                    and self.downloadingNotif_view.isDescendantOfView_(dnf.customView)):
                activityIndicator = self.downloadingNotif_view.viewWithTag_(1)
                activityIndicator.animating = False # turn off animation to save CPU cycles
                self.downloadingNotif_view.removeFromSuperview()
            utils.ios13_status_bar_workaround.pop()
            dnf.release()
        dnf.dismissNotificationWithCompletion_(compl)

    def on_status_update(self):
        utils.NSLog("ON STATUS UPDATE (IsMainThread: %s)",str(NSThread.currentThread.isMainThread))
        show_dl_pct = None

        if not self.wallet or not self.daemon:
            utils.NSLog("(Returning early.. wallet and/or daemon stopped)")
            self.walletsVC.status = wallets.StatusOffline
            return

        walletStatus = wallets.StatusOffline
        walletStatusExtraInfo = ""
        walletBalanceTxt = ""
        walletUnitTxt = ""
        walletUnconfTxt = ""
        networkStatusText = _("Offline")
        blockHeightChanged = False
        num_chains = 0
        #icon = ""

        if self.daemon.network is None or not self.daemon.network.is_running():
            text = _("Offline")
            networkStatusText = text
            walletUnitTxt = text
            #icon = "status_disconnected.png"

        elif self.daemon.network.is_connected():
            lh, sh = self.daemon.network.get_status_value('blockchain_updated')
            # lh = local_height, sh = server_height
            if self.lastHeightSeen != lh:
                self.lastHeightSeen = lh
                blockHeightChanged = True
            server_lag = lh - sh
            num_chains = len(self.daemon.network.get_blockchains())

            # Server height can be 0 after switching to a new server
            # until we get a headers subscription request response.
            # Display the synchronizing message in that case.
            if not self.wallet.up_to_date or sh == 0:
                text = _("Synchronizing...")
                networkStatusText = text
                walletUnitTxt = text
                #icon = "status_waiting.png"
                walletStatus = wallets.StatusSynchronizing
            else:
                walletStatus = wallets.StatusOnline
                networkStatusText = _("Online")
                c, u, x = self.wallet.get_balance()
                walletBalanceTxt = self.format_amount(c+u+x)
                walletUnitTxt = self.base_unit()
                text =  _("Balance" ) + ": %s "%(self.format_amount_and_units(c+u+x))
                ux = 0
                adjective = 'unconf.'
                if u:
                    s = " [%s unconfirmed]"%(self.format_amount(u, u < 0).strip())
                    text +=  s
                    ux += u
                if x:
                    s = " [%s unmatured]"%(self.format_amount(x, x < 0).strip())
                    text += s
                    ux += x
                    adjective = 'unavail.'
                if ux:
                    walletUnconfTxt += "[%s %s]"%(self.format_amount(ux, ux < 0).strip(), adjective)  # [134 unconf.]

                # append fiat balance and price
                if self.daemon.fx.is_enabled():
                    text += self.daemon.fx.get_fiat_status_text(c + u + x, self.base_unit(), self.get_decimal_point()) or ''
                    fiatAmtTxt = self.daemon.fx.format_amount_and_units(c)
                    walletUnitTxt += " (" + fiatAmtTxt + ")" if fiatAmtTxt and not u and not x else ''
                #if not self.daemon.network.proxy:
                #    icon = "status_connected.png"
                #else:
                #    icon = "status_connected_proxy.png"
                if server_lag > 1:
                    text = _("Server is lagging ({} blocks)").format(server_lag)
                    networkStatusText = text
                    #icon = "status_lagging.png"
                    walletStatus = wallets.StatusLagging
                    walletStatusExtraInfo = text

            ''' Chain split notify -- show a banner in the status bar for 60 seconds every 120 seconds until they
                ackwowledge the banner and check network settings. '''
            if num_chains > 1 and (time.time() - self.lastSplitNotify) > 120:
                def ShowSplitNotify():
                    chain = self.daemon.network.blockchain()
                    checkpoint = chain.get_base_height()
                    name = chain.get_name()
                    msg = _('Chain split detected at block %d')%checkpoint
                    def onTapCB():
                        self.lastSplitNotify = time.time()+86400 # suppress for a day or until app restart if they tap
                        self.show_network_dialog()
                    self.notify(msg, duration=60, color=(0.5, 0.0, 0.25, 1.0), onTapCallback=onTapCB, style=CWNotificationStyleStatusBarNotification)
                ShowSplitNotify()
                self.lastSplitNotify = time.time()


            '''utils.NSLog("lh=%d sh=%d is_up_to_date=%d Wallet Network is_up_to_date=%d is_connecting=%d is_connected=%d",
                        int(lh), int(sh),
                        int(self.wallet.up_to_date),
                        int(self.daemon.network.is_up_to_date()),
                        int(self.daemon.network.is_connecting()),
                        int(self.daemon.network.is_connected()))
            '''
            if lh is not None and sh is not None and lh >= 0 and sh > 0 and lh < sh:
                self.header_dl_start_height = lh0 = self.header_dl_start_height or lh
                if lh0 > lh:
                    # guard in case cached start height is wonky or there was a reorg
                    self.header_dl_start_height = lh0 = lh
                show_dl_pct = int(((lh-lh0)*100.0)/float(sh-lh0))
                walletStatus = wallets.StatusDownloadingHeaders
                del lh0

            if blockHeightChanged:
                self.refresh_components('history')
        else:
            text = _("Not connected")
            walletUnitTxt = text
            #icon = "status_disconnected.png"
            walletStatus = wallets.StatusOffline
            networkStatusText = _("Offline")


        #lockIcon = "lock.png" if self.wallet and self.wallet.has_password() else "unlock.png"
        hasSeed =  bool(self.wallet.has_seed())
        hasPW = not bool(self.wallet.is_watching_only())

        if len(self.tx_notifications):
            self.notify_transactions()

        if show_dl_pct is not None and self.tabController.didLayout:
            self.show_downloading_notif(_("Downloading headers {}% ...").format(show_dl_pct) if show_dl_pct > 0 else None)
        else:
            self.header_dl_start_height = 0 # reset the counter
            self.dismiss_downloading_notif()

        self.walletsVC.status = walletStatus
        self.walletsVC.statusExtraInfo = walletStatusExtraInfo
        self.walletsVC.setAmount_andUnits_unconf_(walletBalanceTxt, walletUnitTxt, walletUnconfTxt)

        if self.prefsVC and (self.prefsVC.networkStatusText != networkStatusText
                             #or self.prefsVC.lockIcon != lockIcon
                             or self.prefsVC.hasSeed != hasSeed
                             or self.prefsVC.hasPW != hasPW):
            self.prefsVC.networkStatusText = networkStatusText
            #self.prefsVC.networkStatusIcon = UIImage.imageNamed_(icon)
            #self.prefsVC.lockIcon = lockIcon
            self.prefsVC.hasSeed = hasSeed
            self.prefsVC.hasPW = hasPW
            self.prefsVC.refresh()

    def notify_transactions(self):
        if not self.daemon.network or not self.daemon.network.is_connected():
            return

        if len(self.tx_notifications) > 0:

            if self.tx_notify_timer:
                # already have a timer active, return early
                return

            def do_notify_cb():
                n_ok = 0
                if self.wallet and self.daemon.network and self.daemon.network.is_connected(): # check for spurious call or walled closed.
                    num_txns = len(self.tx_notifications)
                    if num_txns:
                        # Combine the transactions if there are at least 2
                        total_amount = 0
                        for tx in self.tx_notifications:
                            if tx and tx.raw:
                                is_relevant, is_mine, v, fee = self.wallet.get_wallet_delta(Transaction(tx.raw))
                                if v > 0 and is_relevant:
                                    total_amount += v
                                    n_ok += 1
                        if n_ok:
                            self.print_error("Notifying GUI %d tx"%(n_ok))
                            if n_ok > 1:
                                self.notify(_("{} new transactions received: Total amount received in the new transactions {}")
                                            .format(n_ok, self.format_amount_and_units(total_amount)))
                            else:
                                self.notify(_("New transaction received: {}").format(self.format_amount_and_units(total_amount)))
                self.tx_notify_timer = None
                self.tx_notifications = list()
                self.tx_notify_last_ts = time.time() if n_ok else self.tx_notify_last_ts
            # end do_notify_cb

            elapsed_since_last_notify = time.time() - self.tx_notify_last_ts
            if elapsed_since_last_notify < 15.0:
                # we have been spammed tx notifications, so set up a timer to deliver them later
                self.tx_notify_timer = utils.call_later(15.0-elapsed_since_last_notify, do_notify_cb)
            else:
                # no spam, do it immediately
                do_notify_cb()


    def notify(self, message,
               duration=10.0,
               color=(0.0, .5, .25, 1.0), # deeper green
               textColor=UIColor.whiteColor,
               font=UIFont.systemFontOfSize_(12.0),
               style=CWNotificationStyleNavigationBarNotification,
               onTapCallback = None # should take no args and return nothing.
               ):
        lines = message.split(': ')
        utils.show_notification(message=':\n'.join(lines),
                                duration=duration,
                                color=color,
                                textColor=textColor,
                                font=font,
                                style=style,
                                multiline=bool(len(lines)),
                                onTapCallback=onTapCallback)

    def query_hide_downloading_notif(self):
        vc = self.tabController if self.tabController.presentedViewController is None else self.tabController.presentedViewController
        utils.show_alert(vc = vc,
                         title = _("Hide Download Banner"),
                         message = _("Do you wish to hide the download progress banner?\n(You can re-enabled it in Settings later)"),
                         actions= [
                            [ _('Yes'), self.prefs_set_downloading_notif_hidden, True],
                            [ _('No') ],
                            ],
                         cancel = _('No')
                        )


    def get_root_vc(self, nav : ObjCInstance) -> ObjCInstance:
        if nav is None or not nav.ptr.value: return None
        ret = self.rootVCs.get(nav.ptr.value, None)
        if ret is None and isinstance(nav, UINavigationController) and len(nav.viewControllers):
            ret = nav.viewControllers[0]
        return ret


    def unimplemented(self, componentName : str) -> None:
        utils.show_timed_alert(self.get_presented_viewcontroller(),
                               "UNIMPLEMENTED", "%s unimplemented -- coming soon!"%(str(componentName)), 2.0)


    def on_modal_close(self, but : ObjCInstance) -> None:
        title = "UNKNOWN View Controller"
        try:
            presented = self.tabController.presentedViewController
            title = py_from_ns(presented.visibleViewController.title)
        except:
            pass
        vc = self.tabController
        if but and but.tag:
            vc = ObjCInstance(objc_id(but.tag))
        vc.dismissViewControllerAnimated_completion_(True, None)

    def add_navigation_bar_close_to_modal_vc(self, vc : ObjCInstance, leftSide = True, useXIcon = True) -> ObjCInstance:
        if useXIcon:
            closeButton = UIBarButtonItem.alloc().initWithBarButtonSystemItem_target_action_(UIBarButtonSystemItemStop, self.helper, SEL(b'onModalClose:')).autorelease()
        else:
            closeButton = UIBarButtonItem.alloc().initWithTitle_style_target_action_(_('Cancel'), UIBarButtonItemStylePlain, self.helper, SEL(b'onModalClose:')).autorelease()
        # poor man's weak ref -- used in above on_modal_close() to properly close nested modals
        closeButton.tag = vc.ptr.value
        if leftSide:
            extra = vc.navigationItem.leftBarButtonItems if vc.navigationItem.leftBarButtonItems else []
            vc.navigationItem.leftBarButtonItems = [closeButton, *extra]
        else:
            extra = vc.navigationItem.rightBarButtonItems if vc.navigationItem.rightBarButtonItems else []
            vc.navigationItem.rightBarButtonItems = [closeButton, *extra]
        return closeButton


    def cashaddr_icon(self):
        imgname = "cashaddr_off_new"
        #if self.prefs_get_use_cashaddr():
        #    imgname = "cashaddr_on_new"
        return UIImage.imageNamed_(imgname)#.imageWithRenderingMode_(UIImageRenderingModeAlwaysOriginal)

    def toggle_cashaddr(self, on : bool) -> None:
        self.config.set_key('show_cashaddr', on)
        Address.show_cashaddr(on)
        self.refresh_all()
        self.cash_addr_sig.emit(on)

    def format_amount(self, x, is_diff=False, whitespaces=False):
        return format_satoshis(x, is_diff=is_diff, num_zeros=self.num_zeros, decimal_point=self.decimal_point, whitespaces=whitespaces)

    def format_amount_and_units(self, amount, usenl=False):
        text = self.format_amount(amount) + ' '+ self.base_unit()
        x = self.daemon.fx.format_amount_and_units(amount)
        if text and x:
            text += "\n" if usenl else ''
            text += ' (%s)'%x
        return text

    def format_fee_rate(self, fee_rate):
        if self.fee_unit == 0:
            return '{:.2f} sats/byte'.format(fee_rate/1000)
        else:
            return self.format_amount(fee_rate) + ' ' + self.base_unit() + '/kB'

    def base_unit(self):
        if self.decimal_point in inv_base_units:
            return inv_base_units[self.decimal_point]
        raise Exception('Unknown base unit')

    def get_decimal_point(self):
        return self.decimal_point

    def on_label_edited(self, key, newvalue):
        if self.wallet is None:
            return
        self.wallet.set_label(key, newvalue)
        self.wallet.storage.write()
        self.refresh_components("addresses", "history")


    def set_language(self):
        langs = NSLocale.preferredLanguages
        self.language = 'en'
        if langs:
            l = langs[0].replace('-','_')
            if not languages.get(l):
                # iOS sometimes returns a mixed language_REGION code, so try and match it to what we have
                pre1 = l.split('_')[0]
                if pre1 == 'es':
                    l = 'es_AR' # hack to force all Spanish to be South American Spanish as that's a more complete translation
                else:
                    for k in languages.keys():
                        pre2 = k.split('_')[0]
                        if pre1 == pre2:
                            print("OS language is '%s', but we are guessing this matches our language code '%s'"%(l, k))
                            l = k
                            break
            print ("Setting language to {}".format(l))
            self.language = l
            set_language(l)

    def prefs_set_downloading_notif_hidden(self, b : bool) -> None:
        was = self.prefs_get_downloading_notif_hidden()
        if b == was: return
        if b: self.dismiss_downloading_notif()
        self.config.set_key('hide_downloading_banner', bool(b))
        self.prefsVC.refresh()
        self.on_status_update()

    def prefs_get_downloading_notif_hidden(self) -> bool:
        return self.config.get('hide_downloading_banner', False)

    def prefs_get_show_fee(self) -> bool:
        return self.config.get('show_fee', True)

    def prefs_set_show_fee(self, b : bool) -> None:
        self.config.set_key('show_fee', bool(b))

    def prefs_get_max_fee_rate(self) -> float:
        return  float(format_satoshis_plain(self.config.max_fee_rate(), self.decimal_point))

    def prefs_set_max_fee_rate(self, r) -> float:
        amt = self.validate_amount(r)
        if amt is not None:
            self.config.set_key('max_fee_rate', amt)
        return self.prefs_get_max_fee_rate()

    def prefs_get_confirmed_only(self) -> bool:
        return bool(self.config.get('confirmed_only', False))

    def prefs_set_confirmed_only(self, b : bool) -> None:
        self.config.set_key('confirmed_only', bool(b))

    @property
    def prefs_use_schnorr(self) -> bool:
        if not self.wallet: return False
        return bool(self.wallet.is_schnorr_enabled())

    @prefs_use_schnorr.setter
    def prefs_use_schnorr(self, b):
        if self.wallet:
            self.wallet.set_schnorr_enabled(b)

    @property
    def prefs_is_schnorr_possible(self) -> bool:
        if not self.wallet: return False
        return self.wallet.is_schnorr_possible()

    def prefs_get_use_change(self) -> tuple: # returns the setting plus a second bool that indicates whether this setting can be modified
        if not self.wallet: return False, False
        r1 = self.wallet.use_change
        return r1, True

    def prefs_set_use_change(self, x : bool) -> None:
        if not self.wallet: return
        usechange_result = bool(x)
        if self.wallet.use_change != usechange_result:
            self.wallet.use_change = usechange_result
            self.wallet.storage.put('use_change', self.wallet.use_change)

    def prefs_get_multiple_change(self) -> tuple:
        if not self.wallet: return False, False
        multiple_change = self.wallet.multiple_change
        enabled = self.wallet.use_change
        return multiple_change, enabled

    def prefs_set_multiple_change(self, x : bool) -> None:
        if not self.wallet: return
        multiple = bool(x)
        if self.wallet.multiple_change != multiple:
            self.wallet.multiple_change = multiple
            self.wallet.storage.put('multiple_change', multiple)

    def prefs_get_use_cashaddr(self) -> bool:
        return bool(self.config.get('show_cashaddr', True))

    def prefs_set_decimal_point(self, dec: int) -> None:
        if dec in [2, 5, 8]:
            if dec == self.decimal_point:
                return
            self.decimal_point = dec
            self.config.set_key('decimal_point', self.decimal_point, True)
            self.refresh_all()
            print("Decimal point set to: %d"%dec)
        else:
            raise ValueError('Passed-in decimal point %s is not one of [2,5,8]'%str(dec))

    def prefs_get_num_zeros(self) -> int:
        return int(self.config.get('num_zeros', 2))

    def prefs_set_num_zeros(self, nz : int) -> None:
        value = int(nz)
        if self.num_zeros != value:
            self.num_zeros = value
            self.config.set_key('num_zeros', value, True)
            self.refresh_all()

    def view_on_block_explorer(self, item : str, which : str) -> None:
        which = which if which in ['tx', 'addr'] else None
        assert which is not None and item is not None
        url = web.BE_URL(self.config, which, item)
        if UIApplication.sharedApplication.respondsToSelector_(SEL(b'openURL:options:completionHandler:')):
            UIApplication.sharedApplication.openURL_options_completionHandler_(NSURL.URLWithString_(url),dict(),None)
        else:
            UIApplication.sharedApplication.openURL_(NSURL.URLWithString_(url))

    def validate_amount(self, text):
        try:
            x = Decimal(str(text))
        except:
            return None
        p = pow(10, self.decimal_point)
        return int( p * x ) if x > 0 else None

    def has_modal(self) -> ObjCInstance:
        rvc = self.window.rootViewController if self.window else None
        if rvc:
            return rvc.presentedViewController is not None
        return False

    def get_presented_viewcontroller(self) -> ObjCInstance:
        rvc = self.window.rootViewController if self.window else None
        pvc = rvc.presentedViewController if rvc is not None else None
        while pvc and pvc.presentedViewController and not pvc.presentedViewController.isBeingDismissed():
            # keep looking up the view controller hierarchy until we find a modal that is *NOT* being dismissed currently
            pvc = pvc.presentedViewController
        if pvc and pvc.isBeingDismissed():
            utils.NSLog("**** WARNING: presentedViewController %s is being dismissed; will default to rootViewController %s", repr(pvc), repr(rvc))
            # Avoid "being dismissed" viewControllers. This appears redundant
            # but this check is needed in case the first pvc was "beingDismissed"
            pvc = None
        return pvc if pvc else rvc

    def get_current_nav_controller(self) -> ObjCInstance:
        return self.tabController.selectedViewController

    def show_warning_if_watching_only(self, vc = None, onOk = None) -> None:
        if not self.wallet: return
        if self.wallet.is_watching_only():
            self.show_message(title = _("This is a watching-only wallet"),
                              message = _("This means you will not be able to spend Bitcoin Cash with it."),
                              vc = vc,
                              onOk = onOk)


    # can be called from any thread, always runs in main thread
    def show_error(self, message, title = _("Error"), onOk = None, localRunLoop = False, vc = None):
        message = str(message)  # ensure message is string in case calling code passed us an Exception subclass, see #1273
        return self.show_message(message=message, title=title, onOk=onOk, localRunLoop=localRunLoop, vc=vc)

    # full stop question for user -- appropriate for send tx dialog
    def question(self, message, title = _("Question"), yesno = False, onOk = None, vc = None, destructive = False, okButTitle = None,
                 onCancel = None) -> bool:
        ret = None
        localRunLoop = True if onOk is None else False
        if localRunLoop:
            utils.NSLog("*** WARNING: It's been shown that local run loops are buggy on iOS. You are using one with an ElectrumGui.question() call.  Please fix this.")
        def local_onOk() -> None:
            nonlocal ret
            ret = True
        okFun = local_onOk if localRunLoop else onOk
        extrakwargs = {}
        if yesno:
            extrakwargs = { 'cancelButTitle' : _("No"), 'okButTitle' : _("Yes") }
        if okButTitle:
            extrakwargs['okButTitle'] = okButTitle
        self.show_message(message=message, title=title, onOk=okFun, localRunLoop = localRunLoop, hasCancel = True, **extrakwargs, vc = vc, destructive = destructive, onCancel = onCancel)
        return ret

    # can be called from any thread, always runs in main thread
    def show_message(self, message, title = _("Information"), onOk = None, localRunLoop = False, hasCancel = False,
                     cancelButTitle = _('Cancel'), okButTitle = _('OK'), vc = None, destructive = False, onCancel = None):
        def func() -> None:
            myvc = self.get_presented_viewcontroller() if vc is None else vc
            actions = [ [str(okButTitle)] ]
            if onOk is not None and callable(onOk): actions[0].append(onOk)
            nonlocal hasCancel
            if onCancel: hasCancel = True
            if hasCancel:
                cancA = [ str(cancelButTitle) ]
                if onCancel: cancA.append(onCancel)
                actions.append( cancA )
            utils.show_alert(
                vc = myvc,
                title = title,
                message = message,
                actions = actions,
                localRunLoop = localRunLoop,
                cancel = cancelButTitle if hasCancel else None,
                destructive = str(okButTitle) if destructive else None,
            )
        if localRunLoop: return utils.do_in_main_thread_sync(func)
        return utils.do_in_main_thread(func)

    def delete_payment_request(self, addr : Address, refreshDelay : float = -1.0) -> bool:
        if self.wallet and self.wallet.remove_payment_request(addr, self.config):
            self.wallet.storage.write() # commit it to disk
            if refreshDelay <= 0.0:
                self.refresh_components('requests')
            else:
                utils.call_later(refreshDelay, lambda: self.refresh_components('requests'))
            return True
        return False

    def do_clear_send(self):
        if self.sendVC: self.sendVC.clear() # implicitly clears 'payment_request' nspy attr

    def payment_request_ok(self):
        #print("Payment request OK called")
        if not self.wallet:
            self.do_clear_send()
            return
        pr = send.get_PR(self.sendVC)
        if not pr:
            self.show_error("Payment request OK called but no 'payment_request' attribute set on sendVC!")
            return
        key = self.wallet.invoices.add(pr)
        status = self.wallet.invoices.get_status(key)
        #self.invoice_list.update()
        from electroncash.paymentrequest import PR_PAID
        if status == PR_PAID:
            self.show_message("invoice already paid", onOk = lambda: self.do_clear_send())
            return
        self.sendVC.doChkPR() # freezes UI elements, etc
        if not pr.has_expired():
            self.sendVC.setPayToGreen()
        else:
            self.sendVC.setPayToExpired()
        self.sendVC.onPayTo_message_amount_(None, None, None) # special usage of function will pick up fields from pr
        # need to update fee
        self.sendVC.updateFee()

    def payment_request_error(self):
        #print("Payment request ERROR called")
        pr = send.get_PR(self.sendVC)
        self.show_message(str(pr.error if pr else _("Payment Request Error")), onOk = lambda: self.do_clear_send())

    def on_pr(self, request):
        with self.payment_request_lock:
            send.set_PR(self.sendVC, request)
            if self.wallet and request and request.verify(self.wallet.contacts):
                self.payment_request_ok_signal.emit()
            else:
                self.payment_request_error_signal.emit()

    def prepare_for_payment_request(self):
        #print("Prepare for payment request...")
        def onShow() -> None:
            if self.sendVC and not self.sendVC.isPR():
                self.sendVC.payTo.text = _("please wait...")
        self.show_send_modal(completion=onShow)

    def sign_payment_request(self, addr : Address, onSuccess : Callable[[],None] = None, onFailure : Callable[[],None] = None, vc : ObjCInstance = None):
        assert isinstance(addr, Address)
        if not self.wallet:
            if callable(onFailure): onFailure()
            return
        alias = self.config.get('alias')
        alias_privkey = None
        if alias and self.alias_info:
            # NB: this branch is never taken. self.alias_info is always None for now. TO DO: IMPLEMENT alias functionality.
            alias_addr, alias_name, validated = self.alias_info
            if alias_addr:
                if self.wallet.is_mine(alias_addr):
                    msg = _('This payment request will be signed.') #+ '\n' + _('Please provide credentials')
                    def DoSign(password) -> None:
                        if password:
                            try:
                                self.wallet.sign_payment_request(addr, alias, alias_addr, password)
                                if callable(onSuccess): onSuccess()
                            except Exception as e:
                                if callable(onFailure): onFailure()
                                self.show_error(str(e), vc = vc)
                    self.prompt_password_if_needed_asynch(callBack = DoSign, prompt = msg, vc = vc, onCancel = onFailure, onForcedDismissal = onFailure)
        else:
            if callable(onSuccess): onSuccess()

    def pay_to_URI(self, URI, showErr : bool = True) -> bool:
        with self.payment_request_lock:
            utils.NSLog("PayTo URI: %s", str(URI))
            if not URI or not self.wallet:
                return False
            try:
                out = web.parse_URI(URI, self.on_pr)
            except:
                e = sys.exc_info()[1]
                utils.NSLog("Invalid bitcoincash URI: %s, exception: %s", URI, str(e))
                if showErr: self.show_error(_('Invalid bitcoincash URI:') + '\n' + str(e))
                return False
            r = out.get('r')
            sig = out.get('sig')
            name = out.get('name')
            if r or (name and sig):
                ''' NOTE about potential race conditions: (do not remove self.payment_request_lock!)
                    self.on_pr() will be called once the paymentrequest thread is finished (in the web.pare_URI() function called above).
                    But, self.on_pr() assumes the self.sendVC modal is already up (so it can save the payment_request to it).
                    Thus, there is a potential race condition involved. The self.payment_request_lock was added to prevent that.
                    And so, after the addition of the above lock, it is impossible for self.on_pr() to execute before the sendVC
                    is created (by the call to self.prepare_for_payment_request() below). '''
                self.prepare_for_payment_request() # starts up the self.sendVC modal. note how we are holding the lock until after this runs.
                return True
            self.show_send_modal()
            address = out.get('address')
            amount = out.get('amount')
            label = out.get('label')
            message = out.get('message')
            # use label as description (not BIP21 compliant)
            if self.sendVC:
                self.sendVC.onPayTo_message_amount_(address,message,amount)
                return True
            else:
                self.show_error("Oops! Something went wrong! Email the developers!")
            return False

    def refresh_all(self):
        self.refresh_components('*')

    def refresh_components(self, *args) -> None:
        # BEGIN SPECIAL LOGIC TO RATE-LIMIT refresh_components spam
        dummy = "dummy_for_queue"
        #utils.NSLog("refresh_components...")
        #print(*args)
        if not args: args = ['*']
        doLater = False
        abortEarly = False
        self.queued_refresh_components_mut.acquire() # Lock
        qsize = len(self.queued_refresh_components)
        #oldq = self.queued_refresh_components.copy()
        # pick up queued as well as this call's components for refreshing..
        components = set(map(lambda x: str(x).strip().lower(),args)) | self.queued_refresh_components
        self.queued_refresh_components = set() # immediately empty queue while we hold the lock
        diff = time.time() - float(self.last_refresh)
        if {dummy} == components: # spurious self-call
            abortEarly = True
        else:
            if diff < self.refresh_rate_current:
                # rate-limit to at least 300ms between refreshes
                doLater = True
                self.queued_refresh_components = components.copy()
            else:
                # ok, we're going to refresh this time around.. update timestamp
                self.last_refresh = time.time()
        self.queued_refresh_components_mut.release() # Unlock

        if abortEarly:
            #print("refresh_components: aborting early.. got dummy set...")
            return

        if doLater:
            # enqueue a call to this function at most 1 times
            if not qsize:
                #print("refresh_components: rate limiting.. calling later ",diff,"(",*args,")")
                utils.call_later((self.refresh_rate_current-diff) + 0.010, lambda: self.refresh_components(dummy))
            else:
                # already had a queue -- this means another call_later() is pending, so do nothing but return and assume subsequent
                # call_later() will execute this function in the future.
                pass
                #print("refresh_components: already Queued! Q=",oldq)
            return
        # END SPECIAL LOGIC TO RATE-LIMIT refresh_components spam

        signalled = set()
        al = {'*','all','world','everything'}
        #print("components: ",*components)
        if components & {'helper', *al} and self.sigHelper not in signalled:
            signalled.add(self.sigHelper)
            self.sigHelper.emit()
        if components & {'history', *al} and self.sigHistory not in signalled:
            signalled.add(self.sigHistory)
            self.sigHistory.emit()  # implicitly does an emptyCache() then emit()
            if self.sigCoins not in signalled:
                signalled.add(self.sigCoins)
                self.sigCoins.emit()
        if components & {'address', 'addresses', *al} and self.sigAddresses not in signalled:
            signalled.add(self.sigAddresses)
            self.sigAddresses.emit()
            if self.sigCoins not in signalled:
                signalled.add(self.sigCoins)
                self.sigCoins.emit()
        if components & {'prefs', 'preferences', 'settings', *al} and self.sigPrefs not in signalled:
            signalled.add(self.sigPrefs)
            self.sigPrefs.emit()
        if components & {'receive', 'requests', 'paymentrequests', 'pr', *al} and self.sigRequests not in signalled:
            signalled.add(self.sigRequests)
            self.sigRequests.emit() # implicitly does an emptyCache() then emit()
        if components & {'network', 'servers','connection', 'interfaces', *al} and self.sigNetwork not in signalled:
            signalled.add(self.sigNetwork)
            self.sigNetwork.emit()
        # history implies contacts refresh because contacts contain HistoryEntries embedded in them.. so need to rebuild
        if components & {'contact', 'contacts', 'history', *al} and self.sigContacts not in signalled:
            signalled.add(self.sigContacts)
            self.sigContacts.emit() # implicitly does an emptyCache() then emit()
        if components & {'wallet', 'wallets', *al} and self.sigWallets not in signalled:
            signalled.add(self.sigWallets)
            self.sigWallets.emit()

    def refresh_cost(self, component : str, time_cost : float) -> None:
        l = self.refresh_cost_stats.get(component, list())
        if not len(l): self.refresh_cost_stats[component] = l
        l.insert(0, (time_cost, time.time()))
        self.refresh_rate_update()

    def refresh_rate_update(self) -> None:
        now = time.time()
        the_times = list()
        for comp in self.refresh_cost_stats.keys():
            stats = self.refresh_cost_stats.get(comp)
            # 1. take the last 30 seconds worth of refresh timestamps, per component
            # 2. insert them in a list
            # 3. order the list in descending order
            # 4. take the worst case time, add 250ms. That's the refresh rate limit.
            for i in range(len(stats)):
                cost, ts = stats[i]
                if now - ts < 30.0:
                    the_times.append(cost)
                else:
                    # got to entries that are too old, purge list
                    stats = stats[:i]
                    break
        the_times.sort(reverse=True)
        rate = the_times[0] if len(the_times) else 0.0
        rate = rate + 0.250
        #utils.NSLog("Computed %f rate limit, len(the_times)=%d, len(refresh_cost_stats)=%d", limit, len(the_times), len(self.refresh_cost_stats) )
        if rate < self.refresh_rate_min: rate = self.refresh_rate_min # minimum 300ms rate
        elif rate > self.refresh_rate_max: rate = self.refresh_rate_max # maximum 5.0 sec rate
        self.refresh_rate_current = rate
        utils.NSLog("Component refresh rate set to: %f", self.refresh_rate_current)

    def empty_caches(self, doEmit = False):
        self.sigHistory.emptyCache(noEmit=not doEmit)
        self.sigRequests.emptyCache(noEmit=not doEmit)
        self.sigContacts.emptyCache(noEmit=not doEmit)
        self.sigWallets.emptyCache(noEmit=not doEmit)


    def on_new_daemon(self):
        self.daemon.gui = self
        self.open_last_wallet()
        self.register_network_callbacks()

    # pass password param optionally if you want to prompt user for touchid if they don't have it enabled and it's possible to do
    def on_wallet_opened(self, password : str = None) -> None:
        if self.wallet:
            if self.onboardingWizard and not self.onboardingWizard.isBeingDismissed():
                self.onboardingWizard.presentingViewController.dismissViewControllerAnimated_completion_(False, None)
            # Below conditional is because we used to force Schnorr to 0 on all
            # wallets on iOS, and now we have to "undo the damage" of that.
            if self.wallet.storage.get('_ios_undid_force_no_sign_schnorr') is None:
                # indicate that this branch should never be taken again
                self.wallet.storage.put('_ios_undid_force_no_sign_schnorr', True)
                if self.wallet.storage.get('sign_schnorr') == 0:
                    # clear key only if it was 0
                    self.wallet.storage.put('sign_schnorr', None)
            self.config.set_key('gui_last_wallet', self.wallet.storage.path)
            self.config.open_last_wallet() # this badly named function just sets the 'default wallet path' to the gui_last_wallet..
            vcs = self.tabController.viewControllers
            for i in range(0, len(vcs)):
                # make sure that all our tabs are on the root viewcontroller.
                # (this is to remove stale addresses, coins, contacts, etc screens from old wallet which are irrelevant to this new wallet)
                if isinstance(vcs[i], UINavigationController): vcs[i].popToRootViewControllerAnimated_(False)
            self.contactHistSync.restart()
            self.tx_notifications = list() # make sure the tx_notifications are reset when we open a new wallet
            self.refresh_cost_stats = dict()
            self.refresh_rate_current = self.refresh_rate_min
            self.refresh_all()

            def onWalletDelayed() -> None:
                # This is a hack to prevent an esoteric crash.. TODO: fix me!
                self.ext_txn_check() or self.open_uri_check()
                self.queued_ext_txn = None # force these to None here .. no matter what happened above..
                self.queued_payto_uri = None

            utils.call_later(1.0, onWalletDelayed)

    def on_open_last_wallet_fail(self):
        if not self.present_on_boarding_wizard_if_needed():
            self.warn_user_if_no_wallet()

    def _no_wallet(self) -> None:
        if self.walletsVC:
            self.walletsVC.setAmount_andUnits_unconf_(_('No Wallet'), '', '')

    def warn_user_if_no_wallet(self) -> bool:
        if not self.wallet:
            def showDrawer() -> None:
                self.walletsVC.openDrawer()
            self.tabController.selectedIndex = 0
            self.walletsNav.popToRootViewControllerAnimated_(False)
            self._no_wallet()
            self.show_message(title = _("No Wallet Is Open"),
                              message = _("To proceed, please select a wallet to open.") + " " + _("You can also create a new wallet by selecting the 'Add new wallet' option."), onOk = showDrawer)
            return True
        return False



    def on_low_memory(self) -> None:
        utils.NSLog("GUI: Low memory")
        if self.downloadingNotif_view is not None and self.downloadingNotif is None:
            self.downloadingNotif_view.release()
            self.downloadingNotif_view = None
            utils.NSLog("Released cached 'downloading notification banner view' due to low memory")
        import gc
        ct = gc.collect()
        if ct:
            utils.NSLog("Garbage collected {} python objects due to low memory".format(ct))

    def check_low_diskspace(self) -> None:
        # Return True if <50MB of disk space
        free = shutil.disk_usage(utils.get_user_dir()).free
        if free < 1024*1024*50.0: # less that 50MB space...
            utils.NSLog("GUI: Low disk space (%f MB free)", free/(1024.0*1024.0))
            self.stop_daemon()
            self._no_wallet()
            self.refresh_all()
            self.show_message(title = _("Disk Space Low"),
                              message = _("Electron Cash cannot proceed because this device is very low on disk space. Please free up some disk space and try again."))
            return True
        return False


    def stop_daemon(self):
        if not self.daemon_is_running(): return
        password_dialog.kill_extant_asynch_pw_prompts()
        if self.tabController:
            pres = self.tabController.presentedViewController
            if pres and not pres.isBeingDismissed(): self.tabController.dismissViewControllerAnimated_completion_(False, None)
            vcs = self.tabController.viewControllers or list()
            for vc in vcs:
                if isinstance(vc, UINavigationController):
                    vc.popToRootViewControllerAnimated_(False)
            if vcs: self.tabController.selectedIndex = 0
        self.unregister_network_callbacks()
        self.contactHistSync.stop()
        self.empty_caches(doEmit=False)
        if self.wallet and self.wallet.storage:
            self.daemon.stop_wallet(self.wallet.storage.path)
        self.daemon.stop()
        self.wallet = None
        self.daemon = None
        self.dismiss_downloading_notif()
        utils.cleanup_tmp_dir()

    def start_daemon(self):
        if self.daemon_is_running(): return
        import electroncash.daemon as ed
        try:
            # Force remove of lock file so the code below cuts to the chase and starts a new daemon without
            # uselessly trying to connect to one that doesn't exist anyway.
            # (We're guaranteed only 1 instance of this app by iOS regardless)
            os.remove(ed.get_lockfile(self.config))
            utils.NSLog("Pre-existing 'daemon' lock-file removed!")
        except:
            pass
        if not self.config.get('use_exchange'):
            self.config.set_key('use_exchange', 'BitcoinAverage')
            utils.NSLog("Forced default exchange to 'BitcoinAverage'")
        if self.check_low_diskspace():
            # Not enough disk space.
            # Will stop the daemon if running and show a pop-up window warning user.
            # This fixes github issue #1072 and also prevents possible wallet
            # or data file corruption in low disk space conditions.
            return
        fd, server = ed.get_fd_or_server(self.config)
        self.daemon = ed.Daemon(self.config, fd, True, None)
        self.daemon.start()
        self.on_new_daemon()

    def daemon_is_running(self) -> bool:
        return self.daemon is not None and self.daemon.is_running()


    def check_wallet_exists(self, wallet_filename : str) -> bool:
        return wallets.WalletsMgr.check_wallet_exists(wallet_filename)

    # supports only standard wallets for now...
    def generate_new_wallet(self, wallet_name : str,
                            wallet_pass : str = '',
                            wallet_seed : str = '',
                            seed_ext : str = '',
                            seed_type : str = 'standard',
                            have_keystore : object = None, # not required but if we already have generated a keystore, will use this and ignore wallet_seed param
                            private_keys : list = [], # if specified, ignores wallet_seed and have_keystore, do not specify this and watching_addresses at the same time
                            watching_addresses : list = [], # if specified, ignores wallet_seed and have_keystore and wallet_pass.. do not specify this and private_keys at the same time
                            onSuccess = None, # signature: fun()
                            onFailure = None, # signature: fun(errMsg)
                            encrypt : bool = True,
                            vc : UIViewController = None,
                            message : str = None,
                            wants_touchid : bool = True) -> None:
        if not onSuccess: onSuccess = lambda: None
        if not onFailure: onFailure = lambda x: None
        if not vc: vc = self.get_presented_viewcontroller()
        if self.check_wallet_exists(wallet_name):
            onFailure("A wallet with the same name already exists")
            return

        if private_keys and (watching_addresses or wallet_seed or have_keystore):
            raise ValueError('Cannot specify private_keys along with other seed related params or watching addresses')
        if watching_addresses and (wallet_seed or have_keystore or wallet_pass or private_keys):
            raise ValueError('Cannot specify watching_addresses along with other seed related params, private keys, or a wallet password')


        waitDlg = None

        def doDismiss(animated = True, compl = None) -> None:
            nonlocal waitDlg
            if waitDlg:
                waitDlg.dismissViewControllerAnimated_completion_(animated, compl)
                waitDlg = None
            elif compl:
                compl()

        def DoIt_Seed_Or_Keystore() -> None:
            nonlocal waitDlg
            try:
                from electroncash import keystore
                from electroncash.wallet import Standard_Wallet

                k = have_keystore

                if not k:
                    k = keystore.from_seed(wallet_seed, seed_ext, False)
                    has_xpub = isinstance(k, keystore.Xpub)
                    if has_xpub:
                        from electroncash.bitcoin import xpub_type
                        t1 = xpub_type(k.xpub)
                    if has_xpub and t1 not in ['standard']:
                        def compl() -> None: onFailure(_('Wrong key type') + ": '%s'"%t1)
                        doDismiss(animated = False, compl = compl)
                        return

                path = os.path.join(wallets.WalletsMgr.wallets_dir(), wallet_name)
                storage = WalletStorage(path, manual_upgrades=True)
                if wallet_pass:
                    storage.set_password(wallet_pass, encrypt)
                    if k.may_have_password():
                        k.update_password(None, wallet_pass)
                storage.put('seed_type', seed_type)
                keys = k.dump()
                storage.put('keystore', keys)
                wallet = Standard_Wallet(storage)
                wallet.synchronize()
                wallet.storage.write()
                if wallet_pass and wants_touchid:
                    self.set_wallet_use_touchid(wallet_name, wallet_pass)
                    self.touchIdAsked.set(wallet_name, True)
                else:
                    self.set_wallet_use_touchid(wallet_name, None)
                self.refresh_components('wallets')
                def myOnSuccess() -> None: onSuccess()
                doDismiss(animated = True, compl = myOnSuccess)

            except:
                einfo = str(sys.exc_info()[1])
                def myCompl() -> None:
                    onFailure(einfo)
                utils.NSLog("Generate keystore/seed wallet failure: %s", einfo)
                doDismiss(animated = False, compl = myCompl)

        def DoIt_Imported() -> None:
            nonlocal waitDlg
            try:
                from electroncash import keystore
                from electroncash.wallet import ImportedAddressWallet, ImportedPrivkeyWallet

                path = os.path.join(wallets.WalletsMgr.wallets_dir(), wallet_name)
                storage = WalletStorage(path, manual_upgrades=True)
                keystores = list()

                if private_keys:
                    text = ' '.join(private_keys)
                    wallet = ImportedPrivkeyWallet.from_text(storage, text, None)
                    keystores = wallet.get_keystores()
                elif watching_addresses:
                    text = ' '.join(watching_addresses)
                    wallet = ImportedAddressWallet.from_text(storage, text)
                else:
                    raise ValueError('Missing one of private_keys or watching_addresses!')

                if wallet_pass:
                    storage.set_password(wallet_pass, encrypt)
                    for k in keystores:
                        if k.may_have_password():
                            k.update_password(None, wallet_pass)
                    wallet.save_keystore()
                wallet.synchronize()
                wallet.storage.write()
                if wallet_pass and wants_touchid:
                    self.set_wallet_use_touchid(wallet_name, wallet_pass)
                    self.touchIdAsked.set(wallet_name, True)
                else:
                    self.set_wallet_use_touchid(wallet_name, None)
                self.refresh_components('wallets')
                def myOnSuccess() -> None: onSuccess()
                doDismiss(animated = True, compl = myOnSuccess)

            except:
                einfo = str(sys.exc_info()[1])
                def myCompl() -> None:
                    onFailure(einfo)
                utils.NSLog("Generate imported wallet failure: %s", einfo)
                doDismiss(animated = False, compl = myCompl)


        if private_keys or watching_addresses:
            func = DoIt_Imported
        else:
            func = DoIt_Seed_Or_Keystore
        if not message: message = _("Generating your addresses...")
        waitDlg = utils.show_please_wait(vc = vc, message = message, completion = func)


    def switch_wallets(self, wallet_name : str,
                       onSuccess = None, # cb signature is fun(), and this indicates the new wallet is now opened successfully
                       onFailure = None, # cb signature is fun(errmsg : str)
                       onCancel = None,  # cb signature is fun()
                       vc = None,
                       wallet_pass = None # if None, will prompt for password as needed
                       ) -> None:
        if not self.daemon:
            utils.NSLog("Switch wallets but no daemon running!")
            return
        if not vc: vc = self.get_presented_viewcontroller()
        if not onFailure: onFailure = lambda x: utils.NSLog("Failure: %s", str(x))
        if not onSuccess: onSuccess = lambda: None
        if not onCancel: onCancel = lambda: print("User Cancel")
        wallet_name = os.path.split(wallet_name)[1]
        path = os.path.join(wallets.WalletsMgr.wallets_dir(), wallet_name)
        storage = WalletStorage(path, manual_upgrades=True)
        if not storage.file_exists():
            onFailure("Wallet File Not Found")
            return

        def DoSwicheroo(pw = None) -> None:
            if not self.daemon:
                onFailure(_("Daemon was not running."))
                return
            try:
                wallet = Wallet(storage)
                wallet.start_threads(self.daemon.network)
                if self.wallet:
                    self.contactHistSync.stop()
                    self.daemon.stop_wallet(self.wallet.storage.path)
                self.wallet = wallet
                self.daemon.add_wallet(self.wallet)
                self.on_wallet_opened()
                onSuccess()
            except:
                import traceback
                traceback.print_exc(file=sys.stdout)
                utils.NSLog("Exception in opening wallet: %s",str(sys.exc_info()[1]))
                onFailure(str(sys.exc_info()[1]))

        if storage.is_encrypted():
            waitDlg = None
            def promptPW() -> None:
                nonlocal waitDlg
                nonlocal wallet_pass
                def closeDlg() -> None:
                    nonlocal waitDlg
                    if waitDlg:
                        waitDlg.dismissViewControllerAnimated_completion_(True, None)
                        waitDlg = None
                def myOnCancel() -> None:
                    closeDlg()
                    onCancel()
                def onOk(password : str) -> None:
                    try:
                        storage.decrypt(password)
                        closeDlg()
                        DoSwicheroo(password)
                    except:
                        self.show_error(message=_("The password was incorrect for this encrypted wallet, please try again."),
                                        title=_('Password Incorrect'), vc = waitDlg, onOk = promptPwLater)
                if wallet_pass:
                    # try the passed-in password once.. if no good, will end up prompting user
                    tmppw = wallet_pass
                    wallet_pass = None # clear it now so we don't keep retrying it if it's bad
                    onOk(tmppw)
                else:
                    prompt = _("Opening encrypted wallet: '{}'").format(wallet_name)
                    title = _("Password Required")
                    self.prompt_password_if_needed_asynch(callBack = onOk, prompt = prompt, title = title, onCancel = myOnCancel,
                                                          onForcedDismissal = myOnCancel, usingStorage = storage, vc = waitDlg)
            def promptPwLater() -> None:
                utils.call_later(0.1, promptPW)
            waitDlg = utils.show_please_wait(vc = vc, message = _("Opening {}...").format(wallet_name[:25]), completion = promptPwLater)
        else:
            DoSwicheroo()

    def show_wallet_share_actions(self, info : wallets.WalletsMgr.Info, vc : UIViewController = None, ipadAnchor : object = None, warnIfUnsafe : bool = True) -> None:
        if vc is None: vc = self.get_presented_viewcontroller()
        if not os.path.exists(info.full_path):
            self.show_error("Wallet file not found", vc = vc)
            return
        if warnIfUnsafe:
            try:
                storage = WalletStorage(info.full_path, manual_upgrades=True)
                if not storage.is_encrypted():
                    w = Wallet(storage)
                    if not w.is_watching_only() and not w.has_password():
                        self.question(title = _("Potentially Unsafe Operation"),
                                      message = _("This spending wallet is not encrypted and not password protected. Sharing it over the internet could result in others intercepting the data and for you to potentially lose funds.\n\nContinue anyway?"), yesno = True, vc = vc,
                                      onOk = lambda: self.show_wallet_share_actions(info = info, vc = vc, ipadAnchor = ipadAnchor, warnIfUnsafe = False))
                        return
            except:
                self.show_error(str(sys.exc_info()[1]), vc = vc)
                return
        waitDlg = None
        def Dismiss(compl = None, animated = True) -> None:
            nonlocal waitDlg
            if waitDlg:
                waitDlg.presentingViewController.dismissViewControllerAnimated_completion_(animated, compl)
                waitDlg = None

        def DoIt() -> None:
            try:
                fn = shutil.copy2(info.full_path, utils.get_tmp_dir())
                if fn:
                    print("copied wallet to:", fn)
                    utils.show_share_actions(vc = waitDlg, fileName = fn, ipadAnchor = ipadAnchor, objectName = _('Wallet file'),
                                             finishedCompletion = lambda x: Dismiss())
                else:
                    def MyCompl() -> None: self.show_error("Could not copy wallet file", vc = vc)
                    Dismiss(MyCompl, False)
            except:
                err = str(sys.exc_info()[1])
                def MyCompl() -> None: self.show_error(err, vc = vc)
                Dismiss(MyCompl, False)
                utils.NSLog("Got exception copying wallet: %s", err)
        waitDlg = utils.show_please_wait(vc = vc, message = _("Exporting Wallet..."), completion = DoIt)

    def do_wallet_rename(self, info : wallets.WalletsMgr.Info, newName : str, vc : UIViewController = None, password : str = None):
        if not self.wallet: return # disallow this operation if they don't have a wallet open
        if not vc: vc = self.get_presented_viewcontroller()
        if not os.path.exists(info.full_path):
            self.show_error("File not found", vc = vc)
            return
        isCurrent = info.full_path == self.wallet.storage.path
        if isCurrent and self.wallet.storage.is_encrypted() and not password:
            def gotPW(pw : str) -> None:
                self.do_wallet_rename(info = info, vc = vc, password = pw, newName = newName)
            self.prompt_password_if_needed_asynch(callBack = gotPW, vc = vc,
                                                  prompt = _("You are renaming the currently open encrypted wallet '{}'.").format(info.name))
            return
        newName = utils.pathsafeify(newName)
        new_path = os.path.join(os.path.split(info.full_path)[0], newName)
        if os.path.exists(new_path):
            self.show_error(_("A wallet with that name already exists. Cannot proceed."), vc = vc)
            return
        try:
            if isCurrent:
                self.daemon.stop_wallet(self.wallet.storage.path)
                self.wallet = None

            os.rename(info.full_path, new_path)
            oldEncPw = self.encPasswords.get(info.name)
            if oldEncPw:
                self.encPasswords.set(newName, oldEncPw, save = False) # migrate encrypted password to new name if present
            self.encPasswords.pop(info.name, save = True) # remove encrypted password for old name
            if self.touchIdAsked.get(info.name):
                self.touchIdAsked.set(newName, True, save = False)
                self.touchIdAsked.pop(info.name, save = True)
            utils.show_notification(_("Wallet successfully renamed"))
            self.refresh_components('wallets')
            if isCurrent:
                self.switch_wallets(wallet_name = newName, wallet_pass = password, vc = vc)
        except:
            self.show_error(str(sys.exc_info()[1]), vc = vc)

    def prompt_password_if_needed_asynch(self, callBack, prompt = None, title = None, vc = None, onCancel = None, onForcedDismissal = None,
                                         usingStorage : Any = None) -> ObjCInstance:
        if vc is None: vc = self.get_presented_viewcontroller()
        touchIdTry = 0
        wallet_name = None
        keyWasLost = False
        def GotAPasswordCallback(password : str) -> None:
            def CallUserCallback(wallet_name, password) -> None:
                callBack(password)
            if not touchIdTry or keyWasLost:
                self.prompt_user_maybe_wants_touchid(wallet_name = wallet_name, password = password, completion = CallUserCallback, vc = vc)
            else:
                CallUserCallback(wallet_name, password)
        def DoPromptPW(my_callback) -> ObjCInstance:
            nonlocal touchIdTry
            encpw = self.encPasswords.get(wallet_name)
            if not touchIdTry and encpw:
                touchIdTry += 1
                def MyTouchID_CB(pw : str, lostKey : bool) -> None:
                    nonlocal keyWasLost
                    if pw:
                        # decrypted a password using touchid -- pass it along to calling code
                        my_callback(pw)
                    else:
                        if lostKey:
                            keyWasLost = True
                            self.encPasswords.pop(wallet_name)
                            self.touchIdAsked.pop(wallet_name)
                            # Full stop.. will proceed with DoPromptPW (calling self recursively) after msg box is dismissed
                            self.show_error(title=_('Secure Enclave Key Reset'),
                                            message=_('Your biometrics-based key for this wallet was reset. This means you will need to enter your password for this wallet again.\n\n(Then, you can optionally re-enable Touch/Face ID as before.)'),
                                            onOk = lambda: DoPromptPW(my_callback))
                        else:
                            # Some other error occurred with touch id besides a lost key (perhaps they hit "cancel" on
                            # the touchid prompt), so call self recursively to try again!
                            DoPromptPW(my_callback)
                self.get_wallet_password_using_touchid(wallet_name, MyTouchID_CB, prompt = prompt)
                return None
            else:
                return password_dialog.prompt_password_asynch(vc = vc, onOk = my_callback, prompt = prompt, title = title, onCancel = onCancel, onForcedDismissal = onForcedDismissal)
        if usingStorage:
            storage = WalletStorage(usingStorage, manual_upgrades=True) if not isinstance(usingStorage, WalletStorage) else usingStorage
            if not isinstance(storage, WalletStorage):
                raise ValueError('usingStorage parameter needs to be a WalletStorage instance or a string path!')
            if not storage.file_exists():
                raise WalletFileNotFound('Wallet File Not Found')
            wallet_name = os.path.split(storage.path)[-1]
            if not storage.is_encrypted():
                callBack(None)
                return None
            def cb(pw : str) -> None:
                try:
                    storage.decrypt(pw)
                    GotAPasswordCallback(pw)
                except Exception as e:
                    self.show_error(str(e), onOk = lambda: DoPromptPW(cb), vc = vc)
            return DoPromptPW(cb)
        else:
            if self.wallet is None: return None
            wallet_name = wallets.CurrentWalletName()
            if not self.wallet.has_password():
                callBack(None)
                return None
            def cb(pw : str) -> None:
                try:
                    if not self.wallet: return
                    self.wallet.check_password(pw)
                    GotAPasswordCallback(pw)
                except Exception as e:
                    self.show_error(str(e), onOk = lambda: DoPromptPW(cb), vc = vc)
            return DoPromptPW(cb)

    def open_last_wallet(self) -> None:
        guiLast = self.config.get('gui_last_wallet')
        if guiLast:
            # mogrify the path as Apple changes container path names on us all the time...
            walletName = os.path.split(guiLast)[1]
            walletPath = os.path.join(os.path.split(self.config.get_wallet_path())[0],walletName)
            self.config.set_key('gui_last_wallet', walletPath)
            guiLast = walletPath

        path = None

        if guiLast and os.path.exists(guiLast):
            path = guiLast
        if not path:
            infos = wallets.WalletsMgr.list_wallets()
            for info in infos:
                if os.path.exists(info.full_path):
                    path = info.full_path
                    break

        if not path or not os.path.exists(path):
            self.on_open_last_wallet_fail()
        else:
            def do_wallet_open(path : str) -> None:
                def cancelled() -> None:
                    self.on_open_last_wallet_fail()
                def gotpw(password) -> None:
                    if not self.daemon or self.wallet:
                        return
                    try:
                        self.wallet = self.daemon.load_wallet(path, password)
                        self.on_wallet_opened(password)
                    except:
                        import traceback
                        traceback.print_exc(file=sys.stdout)
                        self.show_error(str(sys.exc_info()[1]), onOk = lambda: self.on_open_last_wallet_fail())
                def forciblyDismissed() -> None:
                    #self.on_open_last_wallet_fail()
                    # the assumption here is it was dimmissed because they exited app, then it backgrounded, then they came back.
                    # ... we'll let it slide
                    pass

                name = os.path.split(path)[1]
                if len(name) > 30:
                    name = name[:14] + "..." + name[-13:]
                msg = _("Opening encrypted wallet: '{}'").format(name)
                if not self.wallet:
                    # hide sensitive information
                    self.walletsVC.setAmount_andUnits_unconf_('-', '', '')
                    self.refresh_all()
                self.prompt_password_if_needed_asynch(callBack = gotpw, prompt = msg, onCancel = cancelled,
                                                      onForcedDismissal = forciblyDismissed,
                                                      usingStorage = path)
            do_wallet_open(path)

    def sign_tx_with_password(self, tx, callback, password, vc = None):
        '''Sign the transaction in a separate thread.  When done, calls
        the callback with a success code of True or False.
        '''
        # call hook to see if plugin needs gui interaction
        run_hook('sign_tx', self, tx)
        if not vc:
            vc = self.get_presented_viewcontroller()

        def on_error(exc_info):
            if not isinstance(exc_info[1], UserCancelled):
                if not isinstance(exc_info[1], InvalidPassword):
                    import traceback
                    traceback.print_exception(*exc_info)
                self.show_error(str(exc_info[1]))
        def on_signed(result):
            callback(True)
        def on_failed(exc_info):
            on_error(exc_info)
            callback(False)

        if False:#self.tx_external_keypairs:
            task = partial(Transaction.sign, tx, self.tx_external_keypairs)
        else:
            task = partial(self.wallet.sign_transaction, tx, password)
        utils.WaitingDialog(vc, _('Signing transaction...'), task,
                            on_signed, on_failed)

    def broadcast_transaction(self, tx, tx_desc, doneCallback = None, vc = None):
        if not self.wallet or not self.daemon: return
        if not vc:
            vc = self.get_presented_viewcontroller()
        def broadcast_thread(): # non-GUI thread
            pr = send.get_PR(self.sendVC)
            if pr and pr.has_expired():
                #send.set_PR(self.sendVC, None)
                return False, _("Payment request has expired")
            if not pr:
                # only broadcast tx if NOT a payment request! Otherwise, merchant/bitpay broadcasts it as per BIP70 spec.
                status, msg =  self.daemon.network.broadcast_transaction(tx)
            else:
                refund_address = self.wallet.get_receiving_addresses()[0]
                ack_status, ack_msg = pr.send_payment(str(tx), refund_address) # merchant will broadcast tx for us.
                if not ack_status:
                    if ack_msg == "no url":
                        # "no url" hard-coded in send_payment method
                        # it means merchant doesn't need the tx sent to him
                        # since he didn't specify a POST url.
                        # so we just broadcast and rely on that result status.
                        ack_msg = None
                    else:
                        return False, ack_msg
                # at this point either ack_status is True or there is "no url"
                # and we proceed anyway with the broadcast
                status, msg = self.daemon.network.broadcast_transaction(tx)

                # figure out what to return...
                msg = ack_msg or msg  # prefer the merchant's ack_msg over the broadcast msg, but fallback to broadcast msg if no ack_msg.
                status = bool(ack_status or status)  # if both broadcast and merchant ACK failed -- it's a failure. if either succeeded -- it's a success

                #if status:
                # TODO: invoice list stuff in a future release.
                #    self.invoices.set_paid(pr, tx.txid())
                #    self.invoices.save()
                #    send.set_PR(self.sendVC, None) # may never want to clear here as the modal send relies on this being set..?

            return status, msg

        parent = self

        def broadcast_done(result):
            # GUI thread
            if result:
                status, msg = result
                if status:
                    if tx_desc is not None and tx.is_complete():
                        self.wallet.set_label(tx.txid(), tx_desc)
                    onOk = None
                    if callable(doneCallback):
                        onOk = doneCallback
                    def myCallback() -> None:
                        if onOk: onOk()
                        #self.invoice_list.update()
                        if self.sendVC and not self.sendVC.isBeingDismissed():
                            self.sendVC.clear()
                            self.sendVC.dismissOnAppear = True
                            if self.sendVC.presentingViewController and not self.sendVC.presentedViewController and self.sendNav and self.sendNav.topViewController.ptr.value == self.sendVC.ptr.value:
                                self.sendVC.presentingViewController.dismissViewControllerAnimated_completion_(True, None)
                    parent.show_message(message=_('Payment sent.') + '\n' + msg, onOk = myCallback)
                else:
                    if msg.startswith('error: '):
                        msg = msg.split(' ', 1)[-1] # grab last part after the error:
                    parent.show_error(msg)
        def on_error(exc_info):
            if not isinstance(exc_info[1], UserCancelled):
                import traceback
                traceback.print_exception(*exc_info)
                self.show_error(str(exc_info[1]))

        utils.WaitingDialog(vc, _('Broadcasting transaction...'),
                            broadcast_thread, broadcast_done, on_error)

    def change_password(self, oldpw : str, newpw : str, enc : bool, touchid : bool = False) -> None:
        print("change pw, old=",oldpw,"new=",newpw, "enc=", str(enc), "touchid=",touchid)
        try:
            wallet_name = wallets.CurrentWalletName()
            self.wallet.update_password(oldpw, newpw, enc)
            hadTouchId = self.encPasswords.get(wallet_name)
            if touchid and self.is_touchid_possible():
                self.set_wallet_use_touchid(wallet_name, newpw)
                if not hadTouchId:
                    utils.show_notification(_("Touch/Face ID enabled for wallet"))
            else:
                self.set_wallet_use_touchid(wallet_name, None)
                if self.is_touchid_possible() and hadTouchId:
                    utils.show_notification(_("Touch/Face ID disabled for wallet"))

        except BaseException as e:
            self.show_error(str(e))
            return
        except:
            import traceback
            traceback.print_exc(file=sys.stdout)
            self.show_error(_('Failed to update password'))
            return
        msg = _('Password was updated successfully') if newpw else _('Password is disabled, this wallet is not protected')
        self.show_message(msg, title=_("Success"))
        self.refresh_components('helper')

    def is_touchid_possible(self) -> bool:
        return bool(not utils.is_simulator() and self.keyEnclave.has_keys())

    def is_touchid_available(self) -> bool:
        return bool(self.is_touchid_possible() and self.keyEnclave.biometrics_available())

    def check_touchid_for_gui(self, onOff : bool) -> bool:
        if not onOff: return False
        if self.keyEnclave.has_keys():
            if not self.keyEnclave.biometrics_available():
                self.show_error(title=_("Biometrics Unavailable"),
                                message = _("We will flag this wallet as requesting to use Touch/Face ID, however it is currently disabled on the device. Please enable Touch/Face ID from the iOS General settings in order to use biometrics for this wallet."))
            return True
        else:
            self.show_error(title=_("Secure Enclave Unavailable"),
                            message = _("This device lacks the secure enclave service. As such, Touch/Face ID based wallet authentication is unavailable."))
        return False


    def show_change_password(self, msg = None, vc = None):
        if self.wallet is None or self.wallet.storage is None: return

        pwvc = password_dialog.Create_PWChangeVC(msg, self.wallet.has_password(),
                                                 self.wallet.storage.is_encrypted(),
                                                 (self.encPasswords.has(wallets.CurrentWalletName()) and self.is_touchid_possible()),
                                                 self.change_password,
                                                 self.check_touchid_for_gui)
        (self.get_presented_viewcontroller() if not vc else vc).presentViewController_animated_completion_(pwvc, True, None)


    def show_seed_dialog(self, password, vc = None):
        if self.wallet is None or self.wallet.storage is None: return
        if not self.wallet.has_seed():
            self.show_message(_('This wallet has no seed'))
            return
        keystore = self.wallet.get_keystore()
        seed = ""
        passphrase = ""
        try:
            seed = keystore.get_seed(password)
            passphrase = keystore.get_passphrase(password)
        except BaseException as e:
            self.show_error(str(e))
            return
        seedvc = seed_dialog.Create_SeedDisplayVC(seed, passphrase)
        (vc if vc else self.get_presented_viewcontroller()).presentViewController_animated_completion_(seedvc, True, None)

    def show_network_dialog(self, vc = None) -> None:
        ''' Provide this dialog on-demand to save on startup time and/or on memory consumption '''
        if self.networkNav is not None:
            utils.NSLog("**** WARNING **** Network Nav is not None!! FIXME!")
            return
        if not self.daemon:
            utils.NSLog('"Show Network Dialog" request failed -- daemon is not active!')
            return
        self.networkVC = network_dialog.NetworkDialogVC.new().autorelease()
        self.networkVC.title = _("Network")
        self.networkNav = utils.tintify(CustomNavController.alloc().initWithRootViewController_(self.networkVC).autorelease())
        def doCleanup(oid : objc_id) -> None:
            if self.networkVC is not None and oid == self.networkVC.ptr:
                #print("NetworkDialogVC dealloc caught!")
                self.networkVC = None
            if self.networkNav is not None and oid == self.networkNav.ptr:
                #print("Network Nav dealloc caught!")
                self.networkNav = None
        utils.NSDeallocObserver(self.networkVC).connect(doCleanup)
        utils.NSDeallocObserver(self.networkNav).connect(doCleanup)
        self.add_navigation_bar_close_to_modal_vc(self.networkVC)
        (vc if vc else self.get_presented_viewcontroller()).presentViewController_animated_completion_(self.networkNav, True, None)

    def send_create_if_none(self) -> None:
        if self.sendVC: return
        self.sendVC = send.SendVC.alloc().init().autorelease()
        self.sendNav = utils.tintify(CustomNavController.alloc().initWithRootViewController_(self.sendVC).autorelease())
        self.sendNav.navigationBar.backIndicatorImage = self.walletsNav.navigationBar.backIndicatorImage
        self.sendNav.navigationBar.backIndicatorTransitionMaskImage = self.walletsNav.navigationBar.backIndicatorTransitionMaskImage
        self.add_navigation_bar_close_to_modal_vc(self.sendVC, leftSide = True, useXIcon = True)
        def doCleanup(oid : objc_id) -> None:
            self.sendVC = None
            self.sendNav = None
        utils.NSDeallocObserver(self.sendVC).connect(doCleanup)

    def show_send_modal(self, vc = None, completion = None) -> None:
        self.send_create_if_none()
        if not self.tabController or not self.sendNav: return
        if self.sendNav.topViewController.ptr.value != self.sendVC.ptr.value:
            self.sendNav.popToRootViewControllerAnimated_(False)
        if self.sendNav.presentingViewController:
            # already presented, return early
            if callable(completion):
                completion()
            return
        if not vc: vc = self.get_presented_viewcontroller()
        vc.presentViewController_animated_completion_(self.sendNav, True, completion)

    def show_receive_modal(self, vc = None, onDone = None) -> None:
        self.receive_create_if_none()
        if not self.tabController or not self.receiveNav: return
        if self.receiveNav.topViewController.ptr.value != self.receiveVC.ptr.value:
            self.receiveNav.popToRootViewControllerAnimated_(False)
        if self.receiveNav.presentingViewController: return # already presented, return early
        if not vc: vc = self.get_presented_viewcontroller()
        if callable(onDone): utils.add_callback(self.receiveVC, 'on_done', onDone)
        vc.presentViewController_animated_completion_(self.receiveNav, True, None)

    def show_addresses_tab(self) -> None:
        if not self.tabController or not self.addressesNav: return
        self.tabController.selectedViewController = self.addressesNav
        if self.addressesNav.topViewController.ptr.value != self.addressesVC.ptr.value:
            self.addressesNav.popToRootViewControllerAnimated_(True)

    def jump_to_send_with_spend_from(self, coins, vc = None) -> None:
        self.send_create_if_none()
        utils.nspy_put_byname(self.sendVC, coins, 'spend_from')
        self.show_send_modal(vc=vc)

    def jump_to_send_with_pay_to(self, addr, vc = None) -> None:
        self.send_create_if_none()
        utils.nspy_put_byname(self.sendVC, addr, 'pay_to')
        self.show_send_modal(vc=vc)

    def receive_create_if_none(self) -> None:
        if self.receiveVC: return
        # Receive modal
        self.receiveVC = receive.ReceiveVC.alloc().init().autorelease()
        self.receiveNav = utils.tintify(CustomNavController.alloc().initWithRootViewController_(self.receiveVC).autorelease())
        self.receiveNav.navigationBar.backIndicatorImage = self.walletsNav.navigationBar.backIndicatorImage
        self.receiveNav.navigationBar.backIndicatorTransitionMaskImage = self.walletsNav.navigationBar.backIndicatorTransitionMaskImage
        self.add_navigation_bar_close_to_modal_vc(self.receiveVC, leftSide = True, useXIcon = True)
        def doCleanup(oid : objc_id) -> None:
            self.receiveVC = None
            self.receiveNav = None
        utils.NSDeallocObserver(self.receiveVC).connect(doCleanup)

    def jump_to_receive_with_address(self, address) -> None:
        self.receive_create_if_none()
        if not isinstance(address, (Address, str)): return
        self.receiveVC.addr = (str(address))
        self.show_receive_modal()

    def get_history_entry(self, tx_hash) -> tuple:
        ''' returns a history.HistoryEntry namedtuple instance if tx_hash exists in history, or None if not found '''
        history = self.sigHistory.get(tx_hash) # NEW! Can get history by tx_hash
        if history:
            for entry in history:
                if entry.tx_hash == tx_hash:
                    return entry
        return None

    def get_address_entry(self, address) -> tuple:
        ''' returns an addresses.AddrData.Entry namedtuple or None if not found. Accepts either a string or an Address instance'''
        if isinstance(address, str):
            address = Address.from_string(address)
        return self.sigAddresses.get(address)

    def copy_to_clipboard(self, text, messagePrefix = "Text") -> None:
        UIPasteboard.generalPasteboard.string = text
        utils.show_notification(message=_(messagePrefix.strip() + " copied to clipboard"))

    def open_bitcoincash_url(self, uri : str) -> None:
        if not self.wallet:
            self.queued_payto_uri = uri
        else:
            self.pay_to_URI(uri)

    def open_ext_txn(self, data : str) -> None:
        if not self.wallet:
            self.queued_ext_txn = data
        else:
            self.show_ext_txn(data)

    def ext_txn_check(self) -> bool:
        if self.queued_ext_txn and self.wallet and self.window and self.tabController and self.window.rootViewController and self.window.rootViewController.ptr.value == self.tabController.ptr.value:
            txn = self.queued_ext_txn
            self.queued_ext_txn = None
            return self.show_ext_txn(txn)
        return False

    def open_uri_check(self) -> bool:
        if self.queued_payto_uri and self.wallet and self.window and self.tabController and self.window.rootViewController and self.window.rootViewController.ptr.value == self.tabController.ptr.value:
            uri = self.queued_payto_uri
            self.queued_payto_uri = None
            return self.pay_to_URI(uri)
        return False


    def show_ext_txn(self, txn : str) -> bool:
        if isinstance(txn, bytes):
            txn = txn.decode('utf-8')
            print("Warning: show_ext_txn got bytes instead of a str for the txn.. this may be bad...")
        from electroncash.transaction import tx_from_str, Transaction
        from . import txdetail
        try:
            if not self.wallet:
                self.show_error(_("Cannot display the requested transaction as you don't have a wallet open.\n\nOpen a wallet and try again."))
                return False
            txt_tx = tx_from_str(txn)
            tx = Transaction(txt_tx)
            tx.deserialize()
            my_coins = self.wallet.get_spendable_coins(None, self.config)
            my_outpoints = [vin['prevout_hash'] + ':' + str(vin['prevout_n']) for vin in my_coins]
            for i, txin in enumerate(tx.inputs()):
                outpoint = txin['prevout_hash'] + ':' + str(txin['prevout_n'])
                if outpoint in my_outpoints:
                    my_index = my_outpoints.index(outpoint)
                    tx._inputs[i]['value'] = my_coins[my_index]['value']
            print("ext txn read ok")
            if self.has_modal():
                self.show_error(_("Cannot display the requested transaction since you already have a modal dialog open.\n\nClose the current dialog and try again."))
            else:
                vc = self.get_presented_viewcontroller()
                txvc = txdetail.CreateTxDetailWithTx(tx, asModalNav = True)
                vc.presentViewController_animated_completion_(txvc, True, None)
                return True
        except:
            import traceback
            traceback.print_exc(file=sys.stderr)
            self.show_error(_("Electron Cash was unable to parse your transaction"))
        return False

    def present_on_boarding_wizard_if_needed(self) -> ObjCInstance:
        if ( (not self.onboardingWizard or self.onboardingWizard.isBeingDismissed())
            and not self.wallet and not wallets.WalletsMgr.list_wallets() ):

            wiz = None
            def Completion() -> None:
                nonlocal wiz
                if wiz and not self.onboardingWizard:
                    self.onboardingWizard = wiz
                    obs = utils.NSDeallocObserver(wiz)
                    def Deallocd(obj : objc_id) -> None:
                        if self.onboardingWizard and obj.value == self.onboardingWizard.ptr.value:
                            self.onboardingWizard = None
                    obs.connect(Deallocd)
            if self.tabController and self.tabController.presentedViewController and not self.tabController.presentedViewController.isBeingDismissed():
                self.tabController.dismissViewControllerAnimated_completion_(False, None)
            wiz = newwallet.PresentOnBoardingWizard(vc = self.tabController, completion = Block(Completion))
            return wiz
        return None

    def prompt_user_maybe_wants_touchid(self, wallet_name : str, password : str, completion : Callable[[str,str],None],
                                        vc : UIViewController = None) -> None:
        if (password and self.is_touchid_available() and not self.touchIdAsked.get(wallet_name)
            and not self.encPasswords.has(wallet_name)):
                def SaidYes() -> None:
                    def Compl(b : bool) -> None:
                        if b:
                            self.touchIdAsked.set(wallet_name, True)
                            utils.show_notification(_("Touch/Face ID enabled for wallet"))
                        completion(wallet_name, password)
                    self.set_wallet_use_touchid(wallet_name, password, Compl)
                def SaidNo() -> None:
                    self.touchIdAsked.set(wallet_name, True)
                    completion(wallet_name, password)

                actions = [ [_("No"), SaidNo], [ _("Yes"), SaidYes ] ]
                alert = utils.show_alert(vc = vc or self.get_presented_viewcontroller(),
                                         title = (_("Use Touch/Face ID") + '?'), actions=actions, cancel=_("No"),
                                         message = _("For convenience, would you like to use Touch ID or Face ID to " +
                                                     "open this wallet?\n\n" +
                                                     "Your wallet password will still be used as a backup mechanism for when " +
                                                     "Touch/Face ID fails or is unavailable.\n\n" +
                                                     "Your wallet will continue to be protected and secure.") )
                self.register_killable_alert(alert, lambda: completion(wallet_name, password))
        else:
            completion(wallet_name, password)


    def set_wallet_use_touchid(self, wallet_name : str, wallet_pass_or_none : str, completion : Callable[[bool],None] = None,
                               clear_asked : bool = False) -> None:
        if not callable(completion): completion = lambda x: None
        if wallet_pass_or_none is None:
            self.encPasswords.pop(wallet_name)
            if clear_asked:
                self.touchIdAsked.pop(wallet_name)
            completion(True)
            return
        wallet_pass = wallet_pass_or_none
        def DoEnc(b : bool, s : str) -> None:
            if not b:
                completion(False)
            else:
                self.encPasswords.set(wallet_name, self.keyEnclave.encrypt_str2hex(wallet_pass))
                completion(True)
        if not self.keyEnclave.has_keys():
            self.keyEnclave.generate_keys(DoEnc)
        else:
            DoEnc(True, None)

    def get_wallet_password_using_touchid(self, wallet_name : str, completion : Callable[[str, bool],None], prompt : str = None) -> None:
        hexpass = self.encPasswords.get(wallet_name)
        bug_alert_vc = None
        if not hexpass:
            completion(None)
            return
        #
        # The below piece of contortion is to effect a workaround iOS bugs  in
        # iOS versions in the inclusive range [13.1.0,13.1.2].
        # The bug is that the Touch ID dialog from the OS libs doesn't always
        # pop up.
        # See: https://forums.developer.apple.com/thread/122628
        #
        def do_it() -> None:
            def MyCallback(pw : str, err : str) -> None:
                nonlocal bug_alert_vc
                if bug_alert_vc:
                    bug_alert_vc.dismissViewControllerAnimated_completion_(False, None)
                    bug_alert_vc = None
                lostKey = False
                if err:
                    if self.keyEnclave.lastErrorCode == -50:
                        lostKey = True
                    utils.NSLog("Got error (Code=%d) from enclave attempting to get password for %s: %s", self.keyEnclave.lastErrorCode, wallet_name, err)
                completion(pw, lostKey)
            self.keyEnclave.decrypt_hex2str(hexpass, MyCallback, prompt = prompt)
        vtup = utils.ios_version_tuple()
        vc = self.get_presented_viewcontroller()
        if vc and vtup >= (13, 1, 0) and vtup < (13, 1, 3) and not utils.is_iphoneX():
            # Workaround for TouchID prompt missing bug in iOS.
            # https://forums.developer.apple.com/thread/122628
            # Broken for: 13.1.0, 13.1.1, 13.1.2; confirmed fixed in 13.1.3.
            bug_alert_vc = utils.show_please_wait(vc = vc,
                                                  title = _('Waiting for Touch ID...'),
                                                  message = _('Please touch the home button'),
                                                  completion = do_it,
                                                  animated = False)
        else:
            do_it()

    def setup_key_enclave(self, completion : Callable[[],None]) -> None:
        # TODO: Find out why simulator crashes when trying to
        # create a key (even when simulator has biometrics enabled).
        #   -Calin 10/16/2019
        if (not utils.is_simulator()
                and not self.keyEnclave.has_keys()
                and self.keyEnclave.biometrics_available()):
            # UGH.. they lost their keys, or never had them.  Zero out our enc_pws and our touchIdAsked files..
            self.encPasswords.clearAll()
            self.touchIdAsked.clearAll()
            def Compl(b : bool, err : str) -> None:
                if not b:
                    utils.NSLog("*** WARNING: could not generate secure enclave keys. Error was: %s", err)
                else:
                    utils.NSLog("Secure enclave generated new public/private keys for biometrics-based auth.")
                completion()
            self.keyEnclave.generate_keys(Compl)
        else:
            completion()

    def show_crash_reporter(self, etype : type, eobj : object, tb : object) -> bool:
        from . import crashreporter
        if crashreporter.Singleton:
            utils.NSLog("*** WARNING: A crash reporter is already active! Cannot show another crash reporter!")
            return False
        objs = NSBundle.mainBundle.loadNibNamed_owner_options_("CrashReporter", None, None)
        nav = None
        for o in objs:
            if isinstance(o, UINavigationController):
                nav = o
                break
        if nav:
            vc = nav.viewControllers[0]
            crashreporter.Set(vc, (etype, eobj, tb))
            self.add_navigation_bar_close_to_modal_vc(vc, leftSide = True, useXIcon = True)
            self.get_presented_viewcontroller().presentViewController_animated_completion_(nav, True, None)
            return True
        return False

    def exception_handler(self, etype : type, eobj : object, tb : object) -> None:
        def InMain(etype, eobj, tb):
            if not self.show_crash_reporter(etype, eobj, tb):
                sys.__excepthook__(etype, eobj, tb)
        utils.do_in_main_thread(InMain, etype, eobj, tb)

    # this method is called by Electron Cash libs to start the GUI
    def main(self):
        self.createAndShowUI()

        self.setup_key_enclave(lambda: self.start_daemon())
