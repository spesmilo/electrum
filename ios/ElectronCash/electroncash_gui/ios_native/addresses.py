#
# This file is:
#     Copyright (C) 2018 Calin Culianu <calin.culianu@gmail.com>
#
# MIT License
#
from . import utils
from . import gui
from . import private_key_dialog
from . import sign_decrypt_dialog
from . import history
from electroncash import WalletStorage, Wallet
from electroncash.util import timestamp_to_datetime
import electroncash.exchange_rate
from electroncash.i18n import _, language
from electroncash.address import Address

import time, html, sys, enum
from collections import namedtuple

from .uikit_bindings import *
from .custom_objc import *

_TYPES = ("Any","Receiving","Change")
_STATUSES = ("All", "Funded", "Unused", "Used")
_TYPES_BY_NAME = dict()
_STATUSES_BY_NAME = dict()
if False:
    # this is here simply to get picked up by i18n messages.pot, etc.
    __DUMMY_FOR_TRANSLATION = ( _("Any"), _("All"), _("Funded"), _("Unused"),
                               _("Used"), _("Receiving"), _("Change") )

for i,k in enumerate(_TYPES):
    _TYPES_BY_NAME[k] = i
for i,k in enumerate(_STATUSES):
    _STATUSES_BY_NAME[k] = i

class AddressDetail(AddressDetailBase):

    blockRefresh = objc_property()
    needsRefresh = objc_property()
    domain = objc_property() # string repr of adddress in question -- used to get the cached address entry from the datamgr
    kbas = objc_property()

    @objc_method
    def init(self) -> ObjCInstance:
        raise ValueError("INVALID USAGE: Cannot construct an AddressDetail with a simple 'init' call! Use 'initWithAddress:' instead ")


    @objc_method
    def initWithAddress_(self, address) -> ObjCInstance:
        self = ObjCInstance(send_super(__class__, self, 'init'))
        if self:
            self.title = "Address Details"
            self.domain = address
            self.optionsBarBut = UIBarButtonItem.alloc().initWithImage_style_target_action_(UIImage.imageNamed_("barbut_options"), UIBarButtonItemStylePlain, self, SEL(b'onOptions')).autorelease()
            self.navigationItem.rightBarButtonItem = self.optionsBarBut

            gui.ElectrumGui.gui.sigAddresses.connect(lambda:self.refresh(), self)
            gui.ElectrumGui.gui.sigHistory.connect(lambda:self.refresh(), self)

            bb = UIBarButtonItem.new().autorelease()
            bb.title = _("Back")
            self.navigationItem.backBarButtonItem = bb

        return self

    @objc_method
    def dealloc(self) -> None:
        #print("AddressDetail dealloc")
        gui.ElectrumGui.gui.sigAddresses.disconnect(self)
        gui.ElectrumGui.gui.sigHistory.disconnect(self)
        utils.nspy_pop(self)
        self.domain = None
        self.blockRefresh = None
        self.needsRefresh = None
        self.kbas = None
        send_super(__class__, self, 'dealloc')

    @objc_method
    def loadView(self) -> None:
        NSBundle.mainBundle.loadNibNamed_owner_options_("AddressDetail",self,None)
        parent = gui.ElectrumGui.gui
        entry = _Get(self.domain)

        self.statusTopSaved = self.statusTopCS.constant
        self.txHistoryTopSaved = self.txHistoryTopCS.constant

        self.descDel.placeholderFont = UIFont.italicSystemFontOfSize_(14.0)
        self.descDel.placeholderText = '\n' + _(str(self.descDel.placeholderText).strip())

        # Re-use of TxHistoryHelper below...
        helper = history.NewTxHistoryHelper(tv = self.tv, vc = self, noRefreshControl = True, domain = [entry.address], cls=history.TxHistoryHelperWithHeader)

    @objc_method
    def viewDidLoad(self) -> None:
        # setup callbacks
        def didBeginEditing() -> None:
            self.blockRefresh = True # temporarily block refreshing since that kills our keyboard/textfield

        self.descDel.didBeginEditing = Block(didBeginEditing)

        def didEndEditing(text : ObjCInstance) -> None:
            text = py_from_ns(text)
            self.blockRefresh = False # unblock block refreshing
            entry = _Get(self.domain)

            text = str(text).strip()
            new_label = text
            utils.NSLog("new label for address %s = %s", entry.address.to_storage_string(), new_label)
            gui.ElectrumGui.gui.on_label_edited(entry.address, new_label)
            # Note that above should implicitly refresh us due to sigAddresses signal
            self.doRefreshIfNeeded() # just in case we had a blocked refresh and electrumgui didn't signal.

        self.descDel.didEndEditing = Block(didEndEditing)

    @objc_method
    def viewWillAppear_(self, animated : bool) -> None:
        send_super(__class__, self, 'viewWillAppear:', animated, argtypes=[c_bool])
        self.kbas = utils.register_keyboard_autoscroll(self.view)
        self.refresh()

    @objc_method
    def viewWillDisappear_(self, animated : bool) -> None:
        send_super(__class__, self, 'viewWillDisappear:', animated, argtypes=[c_bool])
        if self.kbas:
            utils.unregister_keyboard_autoscroll(self.kbas)
            self.kbas = None

    @objc_method
    def refresh(self) -> None:
        if self.viewIfLoaded is None or self.blockRefresh:
            self.needsRefresh = True
            return
        entry = _Get(self.domain)
        if not entry:
            return # wallet may have been closed...

         # kern the tits! ;)
        tits = [self.balanceTit, self.numTxTit, self.statusTit, self.descTit]
        for tit in tits:
            tit.setText_withKerning_(tit.text, utils._kern)

        self.address.text = entry.address.to_ui_string()

        self.balance.text = entry.balance_str.strip() + " " + entry.base_unit.strip()
        self.fiatBalance.text = entry.fiat_balance_str.strip()

        if self.fiatBalance.text:
            self.fiatBalance.setHidden_(False)
            self.statusTopCS.constant = self.statusTopSaved
        else:
            self.fiatBalance.setHidden_(True)
            self.statusTopCS.constant = 0.0

        if entry.is_frozen:
            c = utils.uicolor_custom('frozentext')
        else:
            c = utils.uicolor_custom('dark')

        self.address.textColor = c
        self.balance.textColor = c
        self.fiatBalance.textColor = c

        def numTXsAttrStr() -> ObjCInstance:
            ats = NSMutableAttributedString.alloc().initWithString_(str(entry.num_tx)).autorelease()
            hadUTXOs = entry.num_utxos
            utxos = '   (' + str(hadUTXOs) + ' UTXOs)' if entry.num_tx else ''
            attrs = { NSFontAttributeName: UIFont.systemFontOfSize_weight_(14.0, UIFontWeightLight) }
            ats.appendAttributedString_(NSAttributedString.alloc().initWithString_attributes_(utxos, attrs).autorelease())
            if hadUTXOs and utxos:
                attrs = dict()
                l = len(str(hadUTXOs))
                r = NSRange(ats.length()-(7+l),l+6)
                attrs[NSForegroundColorAttributeName] = utils.uicolor_custom('link')
                attrs[NSUnderlineStyleAttributeName] = NSUnderlineStyleSingle
                ats.addAttributes_range_(attrs, r)
                self.utxoGr.setEnabled_(True)
            else:
                self.utxoGr.setEnabled_(False)
            return ats
        self.numTx.attributedText = numTXsAttrStr()


        self.descDel.text = entry.label.strip()

        xtra = []

        if entry.is_watch_only:
            xtra.append(_('watching only'))
        if entry.is_change:
            xtra.append(_('Change'))
        if entry.is_used:
            xtra.append(_('Used'))
        if entry.is_frozen:
            xtra.append(_('Frozen'))
        if xtra:
            self.status.text = ', '.join(xtra)
        else:
            self.status.text = ''

        if not self.status.text:
            self.status.text = _('Receiving Address')
        elif self.status.text == _('Change'):
            self.status.text = _('Change Address')


        froz = _('Frozen')
        lfroz = len(froz)
        stext = self.status.text
        if stext[-lfroz:] == froz:
            ats = NSMutableAttributedString.alloc().initWithString_(stext).autorelease()
            r = NSRange(len(stext)-lfroz, lfroz)
            ats.addAttribute_value_range_(NSForegroundColorAttributeName, utils.uicolor_custom('frozentext'), r)
            self.status.attributedText = ats

        size = CGSizeMake(200.0,200.0) # the returned image has a 10 pix margin -- this compensates for it
        self.qr.contentMode = UIViewContentModeCenter # if the image pix margin changes -- FIX THIS
        self.qr.image = utils.get_qrcode_image_for_data(self.address.text, size = size)


        self.refreshButs()
        self.tv.reloadData() # might be a sometimes-redundant call since WalletsTxHelper also calls reload data..

        self.needsRefresh = False

    @objc_method
    def onOptions(self) -> None:
        entry = _Get(self.domain)
        _ShowAddressContextMenu(entry, self, ipadAnchor = self.optionsBarBut)

    @objc_method
    def onSpendFrom(self) -> None:
        entry = _Get(self.domain)
        _SpendFrom(entry, self)

    @objc_method
    def onUTXOs(self) -> None:
        from .coins import PushCoinsVC
        coinsvc = PushCoinsVC([_Get(self.domain).address], self.navigationController)


    @objc_method
    def toggleFreezeAddress(self) -> None:
        _ToggleFreeze(_Get(self.domain)) # will implicitly refresh us due to signal being emitte

    @objc_method
    def cpyAddress(self) -> None:
        entry = _Get(self.domain)
        gui.ElectrumGui.gui.copy_to_clipboard(entry.addr_str, "Address")

    @objc_method
    def refreshButs(self) -> None:
        v = self.viewIfLoaded
        if v is None: return
        entry = _Get(self.domain)
        watch_only = entry.is_watch_only
        but = self.freezeBut
        but.setSelected_(bool(entry.is_frozen))
        but.setHidden_(watch_only)

        but = self.spendFromBut
        but.setHidden_(bool(watch_only or entry.is_frozen or not entry.balance))
        if but.isHidden():
            self.txHistoryTopCS.constant = -50.0
        else:
            self.txHistoryTopCS.constant = self.txHistoryTopSaved


    @objc_method
    def doRefreshIfNeeded(self) -> None:
        if self.needsRefresh: self.refresh()


    @objc_method
    def onCloseKeyboard_(self, sender : ObjCInstance) -> None:
        self.view.endEditing_(True)

    @objc_method
    def onQRImgTap(self) -> None:
        if not self.qr.image: gui.ElectrumGui.gui.show_error(vc = self, message = "Error, No QR Image")
        else:
            def ShowIt() -> None:
                utils.show_share_actions(vc = self, img = self.qr.image, ipadAnchor = self.qr.convertRect_toView_(self.qr.bounds, self.view), objectName = _("Image"))
            c1 = UIColor.clearColor
            c2 = UIColor.colorWithRed_green_blue_alpha_(0.0,0.0,0.0,0.3)
            self.qr.backgroundColorAnimationFromColor_toColor_duration_reverses_completion_(c1, c2, 0.2, True, ShowIt)



ModeNormal = 0
ModePicker = 1

# Addresses Tab -- shows addresses, etc
class AddressesVC(AddressesVCBase):
    needsRefresh = objc_property()
    blockRefresh = objc_property()
    mode = objc_property()
    refreshControl = objc_property()
    comboL = objc_property()
    comboR = objc_property()
    comboPreset = objc_property()

    @objc_method
    def initWithMode_(self, mode : int):
        self = ObjCInstance(send_super(__class__, self, 'init'))
        if self:
            self.comboL = None
            self.comboR = None
            self.needsRefresh = False
            self.blockRefresh = False
            self.mode = int(mode)
            ad = _("&Addresses").translate({ord('&') : None})
            self.title = ad if self.mode == ModeNormal else _("Choose Address")
            if self.mode == ModeNormal:
                self.tabBarItem.image = UIImage.imageNamed_("tab_addresses_new")
                bb = UIBarButtonItem.alloc().initWithTitle_style_target_action_(_GetBBTitle(), UIBarButtonItemStylePlain, self, SEL(b'toggleCashAddr')).autorelease()
                bb.possibleTitles = NSSet.setWithArray_(_GetBBTitle('*'))
                d = { NSFontAttributeName : UIFont.systemFontOfSize_(14.0) }
                bb.setTitleTextAttributes_forState_(d, UIControlStateNormal)
                d[NSFontAttributeName] = UIFont.systemFontOfSize_weight_(14.0, UIFontWeightRegular)
                bb.setTitleTextAttributes_forState_(d, UIControlStateHighlighted)
                self.navigationItem.rightBarButtonItem = bb

            if self.mode == ModePicker:
                def onRefreshCtl() -> None:
                    self.refresh()
                self.refreshControl = UIRefreshControl.new().autorelease()
                self.refreshControl.handleControlEvent_withBlock_(UIControlEventValueChanged, onRefreshCtl)

            bb = UIBarButtonItem.new().autorelease()
            bb.title = _("Back")
            self.navigationItem.backBarButtonItem = bb

            gui.ElectrumGui.gui.sigAddresses.connect(lambda:self.refresh(), self)

        return self

    @objc_method
    def dealloc(self) -> None:
        gui.ElectrumGui.gui.sigAddresses.disconnect(self)
        self.needsRefresh = None
        self.mode = None
        self.blockRefresh = None
        self.refreshControl = None
        self.comboL = None
        self.comboR = None
        self.comboPreset = None
        utils.nspy_pop(self)
        utils.remove_all_callbacks(self)
        send_super(__class__, self, 'dealloc')

    @objc_method
    def loadView(self) -> None:
        NSBundle.mainBundle.loadNibNamed_owner_options_("Addresses", self, None) # auto-attaches view

        if self.mode == ModeNormal:
            uinib = UINib.nibWithNibName_bundle_("AddressesCell", None)
            self.tableView.registerNib_forCellReuseIdentifier_(uinib, "AddressesCell")

        # set up the combodrawer "child" vc's (they aren't really children in the iOS sense since I hate the way iOS treats embedded VCs)
        objs = NSBundle.mainBundle.loadNibNamed_owner_options_("ComboDrawerPicker", None, None)
        for o in objs:
            if isinstance(o, ComboDrawerPicker):
                self.comboL = o
                break
        objs = NSBundle.mainBundle.loadNibNamed_owner_options_("ComboDrawerPicker", None, None)
        for o in objs:
            if isinstance(o, ComboDrawerPicker):
                self.comboR = o
                break

        self.comboL.flushLeft = True

    @objc_method
    def viewDidLoad(self) -> None:
        send_super(__class__, self, 'viewDidLoad')
        self.refreshControl = gui.ElectrumGui.gui.helper.createAndBindRefreshControl()
        self.tableView.refreshControl = self.refreshControl
        self.setupComboCallbacks()
        self.setupComboItems()

    @objc_method
    def viewWillAppear_(self, animated : bool) -> None:
        send_super(__class__, self, 'viewWillAppear:', animated, argtype=[c_bool])

        # hacky pulling in of attributed text string form the 'child' vc into our proxy stub
        self.topLblL.attributedText = self.comboL.attributedStringForTopTitle
        self.topLblR.attributedText = self.comboR.attributedStringForTopTitle


    @objc_method
    def numberOfSectionsInTableView_(self, tableView) -> int:
        try:
            addrData = _Get()
            return 1 if addrData.master[self.comboL.selection][self.comboR.selection] is not None else 0
        except:
            print("Error in addresses 1:",str(sys.exc_info()[1]))
        return 0

    @objc_method
    def tableView_numberOfRowsInSection_(self, tableView : ObjCInstance, section : int) -> int:
        try:
            addrData = _Get()
            return max(1,len(addrData.master[self.comboL.selection][self.comboR.selection])) if addrData is not None else 0
        except:
            print("Error in addresses 2:",str(sys.exc_info()[1]))
        return 0

    @objc_method
    def tableView_cellForRowAtIndexPath_(self, tableView, indexPath):
        #todo: - allow for label editing (popup menu?)
        identifier = "AddressesCell" if self.mode == ModeNormal else "Cell"
        cell = tableView.dequeueReusableCellWithIdentifier_(identifier)
        newCell = False
        if self.mode == ModePicker and cell is None:
            cell = UITableViewCell.alloc().initWithStyle_reuseIdentifier_(UITableViewCellStyleSubtitle,identifier).autorelease()
            newCell = True

        try:
            addrData = _Get()
            entries = addrData.master[self.comboL.selection][self.comboR.selection]
        except:
            print("Error in addresses 3:",str(sys.exc_info()[1]))
            entries = list()

        if indexPath.row >= len(entries) or cell is None:
            cell = UITableViewCell.alloc().initWithStyle_reuseIdentifier_(UITableViewCellStyleSubtitle,"NoMatchCell").autorelease()
            cell.textLabel.text = _("No Match")
            cell.textLabel.textColor = utils.uicolor_custom('dark')
            cell.detailTextLabel.text = _("No addresses match the specified criteria")
            cell.detailTextLabel.textColor = utils.uicolor_custom('light')
            return cell

        entry = entries[indexPath.row]
        if self.mode == ModeNormal:
            cell.address.linkText = entry.addr_str

            if entry.label:
                cell.desc.setText_withKerning_(entry.label, utils._kern)
                cell.topCS.constant = 7
                cell.midCS.constant = 6
            else:
                cell.desc.text = ""
                cell.topCS.constant = 15
                cell.midCS.constant = 10
            cell.balanceTit.setText_withKerning_(_('Balance'), utils._kern)
            baltxt = entry.balance_str.strip() + " " + entry.base_unit
            if entry.is_frozen:
                amtColor = utils.uicolor_custom('frozentext')
                fiatColor = utils.uicolor_custom('frozentextlight')
            else:
                amtColor = utils.uicolor_custom('dark')
                fiatColor = utils.uicolor_custom('light')
            cell.balance.attributedText = utils.hackyFiatAmtAttrStr(baltxt, entry.fiat_balance_str, '', 0.0, fiatColor, None, -0.5, amtColor = amtColor)
            xtra = []
            if entry.is_frozen:
                if entry.is_change:
                    xtra += [_('Change')]
                xtra += [_('Frozen')]
                cell.flags.textColor = utils.uicolor_custom('frozentext')
            else:
                cell.flags.textColor = utils.uicolor_custom('dark')
                if entry.is_change:
                    xtra += [_('Change')]
                if entry.is_used:
                    xtra += [_('Used')]
                xtra += [ str(entry.num_tx) + ' Tx' + ('s' if entry.num_tx != 1 else '')]
            cell.flags.setText_withKerning_(', '.join(xtra) if xtra else '', utils._kern)


            def linkTarget(celladdy : objc_id) -> None:
                if self.navigationController and self.navigationController.visibleViewController.ptr == self.ptr:
                    celladdy = ObjCInstance(celladdy)
                    self.onTapAddress_(celladdy)

            cell.address.tag = (self.comboL.selection << 24) | (self.comboR.selection << 16) | (indexPath.row & 0xffff) # useful for onTapAddress to figure out what tapped it
            cell.address.linkTarget = linkTarget

            return cell


        else: # picker mode
            if newCell:
                cell.accessoryType = UITableViewCellAccessoryNone
                cell.textLabel.adjustsFontSizeToFitWidth = False
                #cell.textLabel.minimumScaleFactor = 0.9
                cell.textLabel.lineBreakMode = NSLineBreakByTruncatingMiddle
                font = cell.textLabel.font
                cell.textLabel.font = UIFont.systemFontOfSize_weight_(font.pointSize, UIFontWeightRegular)
                cell.detailTextLabel.adjustsFontSizeToFitWidth = True
                cell.detailTextLabel.minimumScaleFactor = 0.85
            cell.textLabel.text = str(entry.address)
            cell.detailTextLabel.text = "bal: " + entry.balance_str + ( (' (' + entry.fiat_balance_str + ')') if addrData.show_fx else '') + " numtx: " + str(entry.num_tx) + ((" - " + entry.label) if entry.label else "")
            font = cell.detailTextLabel.font
            cell.detailTextLabel.font = UIFont.systemFontOfSize_weight_(font.pointSize, UIFontWeightRegular)
            cell.backgroundColor = tableView.backgroundColor
            cell.textLabel.textColor = utils.uicolor_custom('dark')
            cell.detailTextLabel.textColor = utils.uicolor_custom('light')
            if entry.is_frozen:
                #cell.backgroundColor = utils.uicolor_custom('frozen address')
                cell.textLabel.textColor = utils.uicolor_custom('frozentext')
                cell.detailTextLabel.textColor = utils.uicolor_custom('frozentextlight')
            if entry.is_change:
                cell.detailTextLabel.text = cell.detailTextLabel.text + " (Change Address)"
                #cell.backgroundColor = utils.uicolor_custom('change address')

        return cell

    @objc_method
    def tableView_heightForRowAtIndexPath_(self, tv, indexPath) -> float:
        if self.mode == ModeNormal:
            return 91.0
        return 44.0

    # Below 2 methods conform to UITableViewDelegate protocol
    @objc_method
    def tableView_accessoryButtonTappedForRowWithIndexPath_(self, tv, indexPath):
        #print("ACCESSORY TAPPED CALLED")
        pass

    @objc_method
    def tableView_didSelectRowAtIndexPath_(self, tv, indexPath):
        #print("DID SELECT ROW CALLED FOR SECTION %s, ROW %s"%(str(indexPath.section),str(indexPath.row)))
        tv.deselectRowAtIndexPath_animated_(indexPath,True)
        try:
            addrData = _Get()
            section = addrData.master[self.comboL.selection][self.comboR.selection]
            if indexPath.row >= len(section):
                print("User tapped invalid cell.  Possibly the 'No Results' cell.")
                return
            entry = section[indexPath.row]
            if self.mode == ModeNormal:
                PushDetail(entry, self.navigationController)
            else:
                cb = utils.get_callback(self, 'on_picked')
                if callable(cb): cb(entry)
        except:
            print ("Exception encountered:",str(sys.exc_info()[1]))


    @objc_method
    def refresh(self):
        self.needsRefresh = True # mark that a refresh was called in case refresh is blocked
        if self.blockRefresh:
            return
        if self.refreshControl: self.refreshControl.endRefreshing()
        if self.tableView:
            self.tableView.reloadData()
        if self.mode == ModeNormal and self.navigationItem.rightBarButtonItem:
            self.navigationItem.rightBarButtonItem.title = _GetBBTitle()
        #print("did address refresh")
        self.needsRefresh = False # indicate refreshing done

    # This method runs in the main thread as it's enqueue using our hacky "Heartbeat" mechanism/workaround for iOS
    @objc_method
    def doRefreshIfNeeded(self) -> None:
        if self.needsRefresh:
            self.refresh()
            #print ("ADDRESSES REFRESHED")

    @objc_method
    def toggleCashAddr(self) -> None:
        gui.ElectrumGui.gui.toggle_cashaddr(not gui.ElectrumGui.gui.prefs_get_use_cashaddr())

    @objc_method
    def onTapAddress_(self, linkView : ObjCInstance) -> None:
        tag = linkView.tag
        typ = (tag >> 24)&0xff
        stat = (tag >> 16)&0xff
        row = tag & 0xffff
        try:
            entry = _Get().master[typ][stat][row]
        except:
            print("onTapAddress exception:",str(sys.exc_info()[1]))
            return
        _ShowAddressContextMenu(entry, self, ipadAnchor = linkView.convertRect_toView_(linkView.bounds, self.view))


    # -----------------------------------
    # COMBO DRAWER RELATED STUFF BELOW...
    # -----------------------------------
    @objc_method
    def setupComboItems(self) -> None:
        self.comboL.topTitle = _("Type")
        self.comboL.items = [ _(x) for x in _TYPES ]
        self.comboR.topTitle = _("Status")
        self.comboR.items = [ _(x) for x in _STATUSES ]
        parent = gui.ElectrumGui.gui
        presetOK = False
        if self.comboPreset:
            try:
                cpl = list(self.comboPreset)
                self.comboL.selection = cpl[0]
                self.comboR.selection = cpl[1]
                presetOK = True # success!
            except:
                utils.NSLog("Exception trying to read comboPreset in setupComboItems: %s", str(sys.exc_info()[1]))
        # if above fails... read from config...
        if parent.config and not presetOK:
            self.comboL.selection = parent.config.get("AddressTab_Type_Filter", 0)
            self.comboR.selection = parent.config.get("AddressTab_Status_Filter", 0)


    @objc_method
    def setupComboCallbacks(self) -> None:
        # TODO: set up comboL and comboR vc's, and other misc. setup
        def closeLAnim() -> None:
            self.doComboClose_(self.comboL)
        def closeRAnim() -> None:
            self.doComboClose_(self.comboR)
        def bgTapChk(p : CGPoint) -> None:
            this = self.presentedViewController
            if isinstance(this, ComboDrawerPicker):
                fwl = self.topComboProxyL.convertRect_toView_(self.topComboProxyL.bounds, self.view)
                fwr = self.topComboProxyR.convertRect_toView_(self.topComboProxyR.bounds, self.view)
                p = self.view.convertPoint_fromView_(p, self.presentedViewController.view)
                that = None
                if CGRectContainsPoint(fwl, p): that = self.comboL
                elif CGRectContainsPoint(fwr, p): that = self.comboR
                if that:
                    # this hack to prevent screen flicker due to delays in present and dismiss viewcontroller.. very hacky but works!!
                    window = gui.ElectrumGui.gui.window
                    hax = UIView.alloc().initWithFrame_(window.bounds).autorelease()
                    hax.backgroundColor = that.view.backgroundColor
                    hax.opaque = False
                    hax2 = UIView.alloc().initWithFrame_(this.bottomView.convertRect_toView_(this.bottomView.bounds,None)).autorelease()
                    hax2.backgroundColor = this.bottomView.backgroundColor
                    hax.addSubview_(hax2)
                    window.addSubview_(hax)
                    that.view.backgroundColor = UIColor.clearColor
                    this.view.backgroundColor = UIColor.clearColor
                    def showIt() -> None:
                        def killHax() -> None:
                            this.view.backgroundColor = hax.backgroundColor
                            that.view.backgroundColor = hax.backgroundColor
                            hax.removeFromSuperview()
                        that.openAnimated_(False)
                        self.presentViewController_animated_completion_(that, False, killHax)
                    self.dismissViewControllerAnimated_completion_(False, showIt)
                    this.closeAnimated_(False)
                else:
                    self.doComboClose_(this)
        def selectionChanged(sel : int) -> None:
            which = self.presentedViewController
            if isinstance(which, ComboDrawerPicker):
                parent = gui.ElectrumGui.gui
                if parent.config and not self.comboPreset:
                    whichKey = "AddressTab_Status_Filter" if which == self.comboR else "AddressTab_Type_Filter"
                    parent.config.set_key(whichKey, sel, True)
                whichLbl = self.topLblL if which == self.comboL else self.topLblR
                whichLbl.attributedText = which.attributedStringForTopTitle
                self.doComboClose_(which)
                # TODO: make the selection change take effect in how the table is filtered below..
                self.tableView.reloadData()

        self.comboL.backgroundTappedBlock = bgTapChk
        self.comboL.controlTappedBlock = closeLAnim
        self.comboL.controlTappedBlock = closeLAnim
        self.comboL.selectedBlock = selectionChanged
        self.comboR.backgroundTappedBlock = bgTapChk
        self.comboR.controlTappedBlock = closeRAnim
        self.comboR.selectedBlock = selectionChanged

    @objc_method
    def doComboOpen_(self, vc) -> None:
        semiclear = vc.view.backgroundColor.copy()
        vc.view.backgroundColor = UIColor.clearColor
        def compl() -> None:
            vc.view.backgroundColorAnimationToColor_duration_reverses_completion_(semiclear.autorelease(), 0.2, False, None)
            vc.openAnimated_(True)
        self.presentViewController_animated_completion_(vc, False, compl)

    @objc_method
    def doComboClose_(self, vc) -> None:
        self.doComboClose_animated_(vc, True)

    @objc_method
    def doComboClose_animated_(self, vc, animated : bool) -> None:
        # NB: weak ref self.modalDrawerVC will be auto-cleared by obj-c runtime after it is dismissed
        if animated:
            utils.call_later(0.050, self.dismissViewControllerAnimated_completion_,True, None)
        else:
            self.dismissViewControllerAnimated_completion_(False, None)
        vc.closeAnimated_(animated)

    @objc_method
    def onTapComboProxyL(self) -> None:
        self.doComboOpen_(self.comboL)

    @objc_method
    def onTapComboProxyR(self) -> None:
        self.doComboOpen_(self.comboR)

class AddressData:

    Entry = namedtuple("Entry", "address addr_str addr_idx label balance_str fiat_balance_str num_tx is_frozen balance is_change is_used base_unit is_watch_only num_utxos")

    def __init__(self, gui_parent):
        self.parent = gui_parent
        self.clear()

    def clear(self):
        self.show_fx = False
        self.master = [ [list() for s in range(0,len(_STATUSES))]  for t in range(0, len(_TYPES)) ]

    def refresh(self):
        t0 = time.time()

        self.clear()

        wallet = self.parent.wallet
        daemon = self.parent.daemon
        if wallet is None: return

        receiving_addresses = wallet.get_receiving_addresses()
        change_addresses = wallet.get_change_addresses()

        numAddresses = 0
        base_unit = self.parent.base_unit()
        is_watch_only = wallet.is_watching_only()

        if daemon and daemon.fx and daemon.fx.is_enabled() and daemon.fx.get_fiat_address_config():
            fx = daemon.fx
            self.show_fx = True
        else:
            self.show_fx = False
            fx = None
        sequences = [0,1] if change_addresses else [0]
        from .coins import get_coin_counts
        for is_change in sequences:
            addr_list = change_addresses if is_change else receiving_addresses
            for n, address in enumerate(addr_list):
                numAddresses += 1
                num = wallet.get_num_tx(address)
                is_used = wallet.is_used(address)
                balance = sum(wallet.get_addr_balance(address))
                address_text = address.to_ui_string()
                label = wallet.labels.get(address.to_storage_string(), '')
                balance_text = self.parent.format_amount(balance, whitespaces=False)
                is_frozen = wallet.is_frozen(address)
                fiat_balance = (fx.value_str(balance, fx.exchange_rate()) + " " + fx.get_currency()) if fx else ""
                num_utxos = get_coin_counts([address])
                #Entry = "address addr_str addr_idx, label, balance_str, fiat_balance_str, num_tx, is_frozen, balance, is_change, is_used, base_unit is_watch_only num_utxos"
                item = AddressData.Entry(address, address_text, n, label, balance_text, fiat_balance, num,
                                         bool(is_frozen), balance, bool(is_change), bool(is_used), base_unit, is_watch_only, num_utxos)

                #_TYPES = ("Any","Receiving","Change")
                #_STATUSES = ("All", "Funded", "Unused", "Used")
                self.master[0][0].append(item) # item belongs in 'Any,All' regardless
                self.master[2 if item.is_change else 1][0].append(item) # append to either change or receiving of 'All' list
                if item.balance:
                    self.master[0][1].append(item) # item belongs in 'Any,Funded' regardless
                    self.master[2 if item.is_change else 1][1].append(item) # append to either change or receiving of 'Funded' list
                if item.is_used:
                    self.master[0][3].append(item) # item belongs in the 'Any,Used' always, if used
                    self.master[2 if item.is_change else 1][3].append(item) # append to either change or receiving of 'All' list
                else: # Unused list
                    self.master[0][2].append(item) # item belongs in the 'Any,Unused' always, if unused
                    self.master[2 if item.is_change else 1][2].append(item) # append to either change or receiving of 'All' list

        # sort addresses by balance, num_tx, and index, descending
        for i,l1 in enumerate(self.master):
            for j,l2 in enumerate(l1):
                l2.sort(key=lambda x: [x.balance,x.num_tx,0-x.addr_idx], reverse=True )
                #print(_TYPES[i],_STATUSES[j],"len",len(l2))

        utils.NSLog("fetched %d addresses from wallet in %f ms",numAddresses,(time.time()-t0)*1e3)


def present_modal_address_picker(callback, vc = None, comboPreset : list = None) -> None:
    parent = gui.ElectrumGui.gui
    avc = AddressesVC.alloc().initWithMode_(ModePicker).autorelease()
    nav = utils.tintify(CustomNavController.alloc().initWithRootViewController_(avc).autorelease())
    avc.comboPreset = list(comboPreset) if isinstance(comboPreset, (tuple, list)) and len(comboPreset) == 2 else None
    def pickedAddress(entry) -> None:
        if callable(callback):
            callback(entry)
        nav.presentingViewController.dismissViewControllerAnimated_completion_(True, None)
    utils.add_callback(avc, 'on_picked', pickedAddress)
    parent.add_navigation_bar_close_to_modal_vc(avc, leftSide = True)
    if vc is None: vc = parent.get_presented_viewcontroller()
    vc.presentViewController_animated_completion_(nav, True, None)

def EntryForAddress(address : str) -> object:
    return gui.ElectrumGui.gui.get_address_entry(address)

def PushDetail(address_or_entry : object, navController : ObjCInstance) -> ObjCInstance:
    entry = None
    if isinstance(address_or_entry, (str,Address)): entry = EntryForAddress(address_or_entry)
    elif isinstance(address_or_entry, AddressData.Entry):
        entry = address_or_entry
    if not entry:
        raise ValueError('PushDetailForAddress -- missing entry for address!')
    addrDetail = AddressDetail.alloc().initWithAddress_(entry.address.to_storage_string()).autorelease()
    navController.pushViewController_animated_(addrDetail, True)
    return addrDetail

from typing import Any
class AddressesMgr(utils.DataMgr):
    def doReloadForKey(self, key : Any) -> Any:
        if key is None:
            a = AddressData(gui.ElectrumGui.gui)
            a.refresh()
            utils.NSLog("AddressMgr refresh (full)")
            return a
        elif key and isinstance(key, (str, Address)):
            if isinstance(key, str):
                key = Address.from_string(key)
            a = self.get(None) # recursive call to self to get cached 'all' or rebuild 'all' if not cached
            if a:
                entries = a.master[0][0]
                for entry in entries:
                    if entry.address == key:
                        return entry
        return None

def _Get(domain = None) -> AddressData:
    if isinstance(domain, ObjCInstance): domain = py_from_ns(domain)
    return gui.ElectrumGui.gui.sigAddresses.get(domain)

def _GetBBTitle(x = None) -> Any:
    if x is not None:
        #return [ _("Show CashAddr"), _("Show Legacy") ]
        return [ _("Toggle Format"), _("Toggle Format") ]
    if gui.ElectrumGui.gui.prefs_get_use_cashaddr():
        return _("Toggle Format") #_("Show Legacy")
    return _("Toggle Format")  #_("Show CashAddr")

def _ShowAddressContextMenu(entry, parentvc, ipadAnchor, toggleFreezeCallback = None):
    parent = gui.ElectrumGui.gui
    if not parent.wallet:
        utils.NSLog("_ShowAddressContextMenu: wallet is None -- possibly backgrounded/closed wallet. Returning early.")
        return
    def on_block_explorer() -> None:
        parent.view_on_block_explorer(entry.address, 'addr')
    def on_request_payment() -> None:
        parent.jump_to_receive_with_address(entry.address)
    def on_private_key() -> None:
        def onPw(password : str) -> None:
            # present the private key view controller here.
            pk = None
            try:
                pk = parent.wallet.export_private_key(entry.address, password) if parent.wallet else None
            except:
                parent.show_error(str(sys.exc_info()[1]))
                return
            if pk:
                vc = private_key_dialog.PrivateKeyDialog.alloc().init().autorelease()
                pkentry = private_key_dialog.PrivateKeyEntry(entry.address, pk, entry.is_frozen, entry.is_change)
                utils.nspy_put_byname(vc, pkentry, 'entry')
                parentvc.navigationController.pushViewController_animated_(vc, True)
        parent.prompt_password_if_needed_asynch(onPw)
    def on_sign_verify() -> None:
        vc = sign_decrypt_dialog.Create_SignVerify_VC(entry.address)
        parentvc.navigationController.pushViewController_animated_(vc, True)

    def on_encrypt_decrypt() -> None:
        if not parent.wallet: return
        try:
            pubkey = parent.wallet.get_public_key(entry.address)
        except:
            print("exception extracting public key:",str(sys.exc_info()[1]))
            return
        if pubkey is not None and not isinstance(pubkey, str):
            pubkey = pubkey.to_ui_string()
        if not pubkey:
            return
        vc = sign_decrypt_dialog.Create_EncryptDecrypt_VC(entry.address, pubkey)
        parentvc.navigationController.pushViewController_animated_(vc, True)

    def on_copy() -> None:
        parent.copy_to_clipboard(entry.addr_str, 'Address')

    actions = [
            [ _('Cancel') ],
            [ _('Copy Address'), on_copy ],
            [ _("Request payment"), on_request_payment ],
        ]

    watch_only = entry.is_watch_only

    if entry.num_utxos and parentvc.navigationController:
        from .coins import PushCoinsVC
        actions.insert(2, [_('Show Coins (UTXOs)'), PushCoinsVC, [entry.address], parentvc.navigationController])

    if isinstance(parentvc, AddressDetail):
        actions.insert(2, [ _('Share/Save QR...'), lambda: parentvc.onQRImgTap() ])

    if not watch_only:

        try:
            pubkey = parent.wallet.get_public_key(entry.address)
            pubkey = pubkey.to_ui_string() if pubkey and not isinstance(pubkey, str) else pubkey
            if pubkey:
                actions.insert(2, [ _('Copy Public key'), lambda: parent.copy_to_clipboard(pubkey, _('Public key')) ] )
        except:
            pass

        def onToggleFreeze() -> None:
            _ToggleFreeze(entry)
            if callable(toggleFreezeCallback):
                toggleFreezeCallback()
        actions.append([ _('Freeze') if not entry.is_frozen else _('Unfreeze'), onToggleFreeze ])

    if not watch_only and not entry.is_frozen and entry.balance > 0:
        actions.append([ _('Spend from this Address'), lambda: _SpendFrom(entry, vc = parentvc) ] )


    actions.append([ _("View on block explorer"), on_block_explorer ])

    if not watch_only:
        actions.append([ _('Private key'), on_private_key ] )

    if entry.address.kind == entry.address.ADDR_P2PKH:
        if not watch_only:
            actions.append([ _('Sign/verify Message'), on_sign_verify ] )
            actions.append([ _('Encrypt/decrypt Message'), on_encrypt_decrypt ] )
        else:
            actions.append([ _('Verify Message'), on_sign_verify ] )

    utils.show_alert(
        vc = parentvc,
        title = _("Options"),
        message = entry.addr_str,#[0:12] + "..." + entry.addr_str[-12:],
        actions = actions,
        cancel = _('Cancel'),
        style = UIAlertControllerStyleActionSheet,
        ipadAnchor = ipadAnchor
    )

def _ToggleFreeze(entry):
    parent = gui.ElectrumGui.gui
    if parent.wallet:
        parent.wallet.set_frozen_state([entry.address], not entry.is_frozen)
        parent.wallet.storage.write()
        parent.refresh_components('addresses')

def _SpendFrom(entry, vc = None):
    parent = gui.ElectrumGui.gui
    if parent.wallet:
        coins = parent.wallet.get_spendable_coins([entry.address], parent.config)
        if coins:
            parent.jump_to_send_with_spend_from(coins, vc = vc)
        else:
            # Figure out why no coins despite menu option -- and provide
            # a reasonable error message.
            coins = parent.wallet.get_addr_utxo(entry.address)
            msg = _('Address has no spendable coins')
            if coins:
                if all(bool(x['slp_token']) for x in coins.values()):
                    msg = _('Address contains only spend-locked SLP tokens')
                elif all(bool(x['is_frozen_coin']) for x in coins.values()):
                    msg = _('Address contains only frozen coins')

            parent.show_error(msg, title = _('Cannot Spend'))
