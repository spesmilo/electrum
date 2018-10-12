#
# This file is:
#     Copyright (C) 2018 Calin Culianu <calin.culianu@gmail.com>
#
# MIT License
#
from . import utils
from . import gui
from . import addrconv
from . import amountedit
from electroncash.util import timestamp_to_datetime
from electroncash.i18n import _, language
import time
import html
from .uikit_bindings import *
import electroncash.web as web


SECTION_TITLES = [ 'Tools', 'Fees', 'Transactions', 'Appearance', 'Fiat',
                  #'Identity'
                  ]
if False:
    # This is here to get picked up by i18n stuff for messages.pot
    __DUMMY_FOR_TRANSLATION = (_("Tools"), _("Fees"), _("Transactions"), _("Appearance"), _("Fiat"),)

TAG_MULTIPLE_CHANGE_CELL = 12345
TAG_CONTENTVIEW = 100
TAG_BASE_UNIT = 302
TAG_NZ = 303
TAG_BLOCK_EXPLORER = 304
TAG_FIAT_CURRENCY = 401
TAG_FIAT_EXCHANGE = 404

UNITS = { 'BCH': 8, 'mBCH': 5, 'cash' : 2}
UNIT_KEYS = list(UNITS.keys())
UNIT_KEYS.sort(key=lambda x: UNITS[x],reverse=True)


class PrefsVC(UITableViewController):
        
    currencies = objc_property() # NSArray of strings...
    exchanges = objc_property() # NSArray of strings...
    
    normalButtonColor = objc_property() # UIColor instance
    warnButtonColor = objc_property()
    
    networkStatusText = objc_property()
    #networkStatusIcon = objc_property()
    #lockIcon = objc_property()
    hasSeed = objc_property()
    hasPW = objc_property()
        
    @objc_method
    def init(self) -> ObjCInstance:
        self = ObjCInstance(send_super(__class__, self, 'initWithStyle:', UITableViewStyleGrouped, argtypes=[c_int]))
        self.title = _("Settings")
        self.tabBarItem.image = UIImage.imageNamed_("tab_settings.png")
        self.currencies = None
        self.exchanges = None
        self.normalButtonColor = None
        self.networkStatusText = None
        #self.networkStatusIcon = None
        #self.lockIcon = None
        self.hasSeed = None
        self.hasPW = None
        self.warnButtonColor = UIColor.colorWithRed_green_blue_alpha_(0.8,0.0,0.0,1.0)
        self.updateCurrencies()
        self.updateExchanges()
        bb = UIBarButtonItem.new().autorelease()
        bb.title = _("Back")
        self.navigationItem.backBarButtonItem = bb
        gui.ElectrumGui.gui.sigPrefs.connect(lambda:self.refresh(), self)
        return self
    
    @objc_method
    def initWithStyle_(self, style : int) -> ObjCInstance:
        print("WARNING: PrefsVC doesn't support the initWithStyle: method -- use plain old 'init' instead!")
        assert style == UITableViewStyleGrouped
        return self.init()
        
    @objc_method
    def dealloc(self) -> None:
        gui.ElectrumGui.gui.sigPrefs.disconnect(self)
        self.warnButtonColor = None
        self.normalButtonColor = None
        self.currencies = None
        self.exchanges = None
        self.networkStatusText = None
        #self.networkStatusIcon = None
        #self.lockIcon = None
        self.hasSeed = None
        self.hasPW = None
        send_super(__class__, self, 'dealloc')

    @objc_method
    def refresh(self):
        if self.refreshControl: self.refreshControl.endRefreshing()
        if self.viewIfLoaded is not None:
            self.updateCurrencies()
            self.updateExchanges()
            self.tableView.reloadData()
 
    @objc_method
    def viewDidAppear_(self, animated : bool) -> None:
        # do polish here?
        send_super(__class__, self,'viewDidAppear:', animated, arg_types=[c_bool])

    @objc_method
    def updateCurrencies(self):
        parent = gui.ElectrumGui.gui
        self.currencies = [_('None')]
        if not parent.daemon or not parent.daemon.fx: return
        currencies = [self.currencies[0],*sorted(parent.daemon.fx.get_currencies(parent.daemon.fx.get_history_config()))]
        special = [ 'USD', 'EUR', 'GBP', 'CAD', 'AUD' ]
        i = 1
        for s in special:
            try:
                ix = currencies.index(s)
                currencies.pop(ix)
                currencies.insert(i, s)
                i += 1
            except:
                pass
        self.currencies = currencies

    @objc_method
    def updateExchanges(self):
        parent = gui.ElectrumGui.gui
        fx = parent.daemon.fx if parent.daemon else None
        self.exchanges = []
        if not fx: return
        b = fx.is_enabled()
        #ex_combo.setEnabled(b)
        if b:
            h = fx.get_history_config()
            c = fx.get_currency()
            self.exchanges = sorted(fx.get_exchanges_by_ccy(c, h))
        else:
            self.exchanges = sorted(fx.get_exchanges_by_ccy('USD', False))
        
        self.setFiatExchangeButtonText_(None)
    
    ## TableView methods below...   
    @objc_method
    def numberOfSectionsInTableView_(self, tableView) -> int:
        return len(SECTION_TITLES)
    
    @objc_method
    def tableView_titleForHeaderInSection_(self, tv : ObjCInstance, section : int) -> ObjCInstance:
        assert section >= 0 and section < len(SECTION_TITLES)
        return ns_from_py(_(SECTION_TITLES[section]))
    
    @objc_method
    def tableView_numberOfRowsInSection_(self, tableView, section : int) -> int:
        assert section >= 0 and section < len(SECTION_TITLES)
        secName = SECTION_TITLES[section]
        if secName == 'Tools':
            if self.hasPW:
                return 3 if not self.hasSeed else 4
            else:
                return 2
        elif secName == 'Fees':
            return 2
        elif secName == 'Transactions':
            return 3
        elif secName == 'Appearance':
            return 5
        elif secName == 'Fiat':
            return 4
        return 0

    @objc_method
    def tableView_cellForRowAtIndexPath_(self, tableView, indexPath) -> ObjCInstance:
        assert indexPath.section >= 0 and indexPath.section < len(SECTION_TITLES)
        section,row = indexPath.section, indexPath.row
        secName = SECTION_TITLES[section]
        identifier = "%s_%s"%(str(secName), str(row))
        cell = tableView.dequeueReusableCellWithIdentifier_(identifier)
        if cell is None:
            cell = self.createCellForSection_row_(secName,row)
        self.setupCell_section_row_(cell,secName,row)
        return cell
    
    @objc_method
    def tableView_heightForRowAtIndexPath_(self, tableView, indexPath) -> float:
        return 44.0
    
    @objc_method
    def tableView_didSelectRowAtIndexPath_(self, tv, indexPath) -> None:
        tv.deselectRowAtIndexPath_animated_(indexPath,True)
        parent = gui.ElectrumGui.gui
        section,row = indexPath.section, indexPath.row
        secName = SECTION_TITLES[section]
        
        if secName == "Tools":
            if row == 0: # AddrConv
                if not self.navigationController: return
                vc = addrconv.AddrConvVC.new().autorelease()
                self.navigationController.pushViewController_animated_(vc, True)
            elif row == 1: # Network Dialog
                parent.show_network_dialog(vc = self)
            elif row == 2 and self.hasPW: # Password dialog
                parent.show_change_password(vc = self)
            elif row == 3 and self.hasSeed:
                def gotPW(pw) -> None:
                    parent.show_seed_dialog(pw)
                parent.prompt_password_if_needed_asynch(vc=self, callBack = gotPW)

    @objc_method
    def tableView_accessoryButtonTappedForRowWithIndexPath_(self, tv, indexPath) -> None:
        section,row = indexPath.section, indexPath.row
        secName = SECTION_TITLES[section]
        parent = gui.ElectrumGui.gui
        
        if secName == 'Tools' and row == 1: parent.show_network_dialog()

    @objc_method
    def setupCell_section_row_(self, cell : ObjCInstance, secName_oc : ObjCInstance, row : int) -> None:
        secName = py_from_ns(secName_oc)
        parent = gui.ElectrumGui.gui
        fx = parent.daemon.fx if parent.daemon else None
        cell.tag = 0
        cell.contentView.tag = TAG_CONTENTVIEW
        if secName == 'Tools':
            if row == 0:
                cell.imageView.image = parent.cashaddr_icon()
                cell.textLabel.text = _("Address Converter")
                cell.detailTextLabel.text = _("Convert between Legacy and Cashaddr formats")
                cell.accessoryType = UITableViewCellAccessoryDisclosureIndicator
            elif row == 1:
                statusText = self.networkStatusText if self.networkStatusText else _("Offline")
                cell.imageView.image = UIImage.imageNamed_("network_icon_new")
                cell.textLabel.text = _("Network Settings")
                cell.detailTextLabel.text = _("Status:") + " " + statusText
                cell.accessoryType = UITableViewCellAccessoryNone
            elif row == 2:
                cell.imageView.image = UIImage.imageNamed_("password_icon_new")
                cell.textLabel.text = _("Change or Set Password")
                cell.detailTextLabel.text = _("Modify wallet password & encryption settings")
                cell.accessoryType = UITableViewCellAccessoryNone
            elif row == 3:
                cell.imageView.image = UIImage.imageNamed_("seed_icon_new")
                cell.textLabel.text = _("Wallet Recovery Seed")
                cell.detailTextLabel.text = _("View the wallet seed phrase used for wallet recovery")
                cell.accessoryType = UITableViewCellAccessoryNone

            # ensure all of the above icons are the same size: 24x24, centered, unscaled
            cell.imageView.contentMode = UIViewContentModeCenter
            f = cell.imageView.frame
            f.size = CGSizeMake(24,24)
            cell.imageView.frame = f
            cell.textLabel.textColor = utils.uicolor_custom('dark')
            cell.detailTextLabel.textColor = utils.uicolor_custom('dark')
            cell.textLabel.font = UIFont.systemFontOfSize_weight_(16.0, UIFontWeightRegular)
            cell.detailTextLabel.font = UIFont.systemFontOfSize_weight_(12.0, UIFontWeightThin)

        elif secName == 'Fees':
            if row == 0:
                l = cell.viewWithTag_(1)
                tf = cell.viewWithTag_(2)
                l.text = _('Max static fee')
                tf.placeholder = parent.base_unit()
                tf.delegate = self
                tf.text = get_max_static_fee_str(parent)
                if tf.allTargets.count <= 0:
                    tf.addTarget_action_forControlEvents_(self, SEL(b'onMaxStaticFee:'), UIControlEventEditingChanged)
                if isinstance(tf, amountedit.BTCkBEdit):
                    tf.setUseUnitLabel_(True)
                    tf.fixedUnitLabelWidth = 75.0
                utils.uitf_redo_attrs(tf)
            elif row == 1: # 'edit fees manually', a bool cell
                l = cell.viewWithTag_(1)
                s = cell.viewWithTag_(2)
                if s.allTargets.count <= 0:
                    s.addTarget_action_forControlEvents_(self, SEL(b'onShowFee:'), UIControlEventValueChanged)
                l.text = _('Edit fees manually')
                s.on =  parent.prefs_get_show_fee()
        elif secName == 'Transactions':
            l = cell.viewWithTag_(1)
            s = cell.viewWithTag_(2)
            if row == 0:
                l.text = _("Use change addresses")
                b, enabled = parent.prefs_get_use_change()
                s.on = b
                utils.uiview_set_enabled(cell, enabled)
                if s.allTargets.count <= 0:
                    s.addTarget_action_forControlEvents_(self, SEL(b'onUseChange:'), UIControlEventValueChanged)
            elif row == 1:
                l.text = _("Use multiple change addresses")
                cell.contentView.tag = TAG_MULTIPLE_CHANGE_CELL
                b1, enabled = parent.prefs_get_multiple_change()
                s.on = b1
                utils.uiview_set_enabled(cell.contentView, enabled)
                if s.allTargets.count <= 0:
                    s.addTarget_action_forControlEvents_(self, SEL(b'onUseMultiple:'), UIControlEventValueChanged)
            elif row == 2:
                l.text = _("Spend only confirmed coins")
                s.on = parent.prefs_get_confirmed_only()
                if s.allTargets.count <= 0:
                    s.addTarget_action_forControlEvents_(self, SEL(b'onConfirmedOnly:'), UIControlEventValueChanged)
        elif secName == 'Appearance':
            if row == 0:
                l = cell.viewWithTag_(1)
                s = cell.viewWithTag_(2)
                l.text = _('Hide download banner')
                s.on = parent.prefs_get_downloading_notif_hidden()
                if s.allTargets.count <= 0:
                    s.addTarget_action_forControlEvents_(self, SEL(b'onHideDLBanner:'), UIControlEventValueChanged)
            elif row == 1:
                l = cell.viewWithTag_(1)
                s = cell.viewWithTag_(2)
                l.text = _('CashAddr address format')
                s.on = parent.prefs_get_use_cashaddr()
                if s.allTargets.count <= 0:
                    s.addTarget_action_forControlEvents_(self, SEL(b'onUseCashAddr:'), UIControlEventValueChanged)
            elif row == 2:
                l = cell.viewWithTag_(1)
                b = cell.viewWithTag_(2)
                b = b if b is not None else cell.viewWithTag_(TAG_NZ)
                l.text = _('Zeros after decimal point')
                if b is not None:
                    b.tag = TAG_NZ
                    if b.allTargets.count <= 0:
                        b.addTarget_action_forControlEvents_(self, SEL(b'onNZBut:'), UIControlEventPrimaryActionTriggered)
                    nr = len(self.getNumZerosList())
                    nz_prefs = parent.prefs_get_num_zeros()
                    if nz_prefs >= nr:
                        nz_prefs = nr-1
                    b.setTitle_forState_(str(nz_prefs),UIControlStateNormal)
            elif row == 3:
                l = cell.viewWithTag_(1)
                b = cell.viewWithTag_(2)
                b = b if b is not None else cell.viewWithTag_(TAG_BASE_UNIT)
                l.text = _('Base unit')
                if b is not None:
                    b.tag = TAG_BASE_UNIT
                    b.setTitle_forState_(parent.base_unit(),UIControlStateNormal)
                    if b.allTargets.count <= 0:
                        b.addTarget_action_forControlEvents_(self, SEL(b'onBaseUnitBut:'), UIControlEventPrimaryActionTriggered)
            elif row == 4:
                l = cell.viewWithTag_(1)
                b = cell.viewWithTag_(2)
                b = b if b is not None else cell.viewWithTag_(TAG_BLOCK_EXPLORER)
                l.text = _('Online Block Explorer')
                if b is not None:
                    b.tag = TAG_BLOCK_EXPLORER
                    be = web.BE_sorted_list()
                    be = be if be is not None and len(be) > 0 else ["None"]
                    beprefs = web.BE_from_config(parent.config)
                    if beprefs not in be:  beprefs = be[0]
                    b.setTitle_forState_(beprefs,UIControlStateNormal)
                    if b.allTargets.count <= 0:
                        b.addTarget_action_forControlEvents_(self, SEL(b'onBlockExplorerBut:'), UIControlEventPrimaryActionTriggered)
        elif secName == 'Fiat':
            if row == 0:
                l = cell.viewWithTag_(1)
                b = cell.viewWithTag_(2)
                b = b if b is not None else cell.viewWithTag_(TAG_FIAT_CURRENCY)
                l.text = _('Fiat currency')
                if b is not None:
                    b.tag = TAG_FIAT_CURRENCY
                    b.enabled = True
                    curr = fx.get_currency() if fx and fx.is_enabled() else _('None')
                    b.setTitle_forState_(curr, UIControlStateNormal)
                    if b.allTargets.count <= 0:
                        b.addTarget_action_forControlEvents_(self, SEL(b'onFiatCurrencyBut:'), UIControlEventPrimaryActionTriggered)                        
            elif row == 1:
                l = cell.viewWithTag_(1)
                s = cell.viewWithTag_(2)
                l.text = _('Show history rates')
                s.on = bool(fx and fx.get_history_config())
                if s.allTargets.count <= 0:
                    s.addTarget_action_forControlEvents_(self, SEL(b'onFiatHistory:'), UIControlEventValueChanged)
                enabled = bool(bool(fx) and fx.is_enabled())
                utils.uiview_set_enabled(cell.contentView, enabled)
            elif row == 2:
                l = cell.viewWithTag_(1)
                s = cell.viewWithTag_(2)
                l.text = _('Show Fiat balance for addresses')
                s.on = bool(fx and fx.get_fiat_address_config())
                if s.allTargets.count <= 0:
                    s.addTarget_action_forControlEvents_(self, SEL(b'onFiatBal:'), UIControlEventValueChanged)
                enabled = bool(bool(fx) and fx.is_enabled())
                utils.uiview_set_enabled(cell.contentView, enabled)
            elif row == 3:
                l = cell.viewWithTag_(1)
                b = cell.viewWithTag_(2)
                b = b if b is not None else cell.viewWithTag_(TAG_FIAT_EXCHANGE)
                l.text = _('Source')
                if b is not None:
                    b.tag = TAG_FIAT_EXCHANGE
                    b.setTitle_forState_(_("None"), UIControlStateNormal)
                    self.setFiatExchangeButtonText_(b)
                    if b.allTargets.count <= 0:
                        b.addTarget_action_forControlEvents_(self, SEL(b'onFiatExchangeBut:'), UIControlEventPrimaryActionTriggered)
                        
   
    @objc_method
    def setFiatExchangeButtonText_(self, b : ObjCInstance) -> None:
        b = self.tableView.viewWithTag_(TAG_FIAT_EXCHANGE) if b is None else b
        if b is None: return
        fx = gui.ElectrumGui.gui.daemon.fx if gui.ElectrumGui.gui.daemon else None
        ex = fx.config_exchange() if fx else None
        ex = ex if ex in self.exchanges else None
        if ex is None:
            ex = _("None")
            if self.normalButtonColor is None: self.normalButtonColor = b.titleColorForState_(UIControlStateNormal)
            b.setTitleColor_forState_(self.warnButtonColor,UIControlStateNormal)
        elif self.normalButtonColor is not None:
            b.setTitleColor_forState_(self.normalButtonColor,UIControlStateNormal)            
        b.setTitle_forState_(str(ex), UIControlStateNormal)
        
    @objc_method
    def createCellForSection_row_(self, secName_oc : ObjCInstance, row : int) -> ObjCInstance:
        secName = py_from_ns(secName_oc)
        cell = None
        ident = "%s_%s"%(str(secName), str(row))
        
        if secName in ['Tools']:
            cell =  UITableViewCell.alloc().initWithStyle_reuseIdentifier_(UITableViewCellStyleSubtitle, ident).autorelease()
        elif ident in ['Fees_1', 'Transactions_0', 'Transactions_1', 'Transactions_2', 'Appearance_0', 'Appearance_1','Fiat_1', 'Fiat_2']:
            objs = NSBundle.mainBundle.loadNibNamed_owner_options_("BoolCell",self.tableView,None)
            assert objs is not None and len(objs)
            cell = objs[0] 
        elif ident in ['Fees_0']:
            objs = NSBundle.mainBundle.loadNibNamed_owner_options_("TFCell",self.tableView,None)
            assert objs is not None and len(objs)
            cell = objs[0]
        elif ident in ['Appearance_2', 'Appearance_3', 'Appearance_4', 'Fiat_0', 'Fiat_3']:
            objs = NSBundle.mainBundle.loadNibNamed_owner_options_("ButtonCell",self.tableView,None)
            assert objs is not None and len(objs)
            cell = objs[0]

        assert cell is not None
        return cell

    ### TextField delegate crap ###
    @objc_method
    def textFieldShouldReturn_(self, tf : ObjCInstance) -> bool:
        tf.resignFirstResponder()
        return True
    
    @objc_method
    def textFieldDidEndEditing_(self, tf : ObjCInstance) -> None:
        self.onMaxStaticFee_(tf)
        utils.uitf_redo_attrs(tf)
   
    @objc_method
    def getNumZerosList(self) -> ObjCInstance:
        parent = gui.ElectrumGui.gui
        nr = min(parent.get_decimal_point(), 8) + 1
        ret = [str(i) for i in range(0,nr)]
        return ns_from_py(ret)
    
    ### ACTION HANDLERS -- basically calls back into gui object ###
    @objc_method
    def onNZBut_(self, but : ObjCInstance) -> None:
        parent = gui.ElectrumGui.gui
        nzl = py_from_ns(self.getNumZerosList())
        nz = parent.prefs_get_num_zeros()
        def onOk(selIdx : int) -> None:
            parent.prefs_set_num_zeros(selIdx)
            nz_prefs = parent.prefs_get_num_zeros()
            b = self.view.viewWithTag_(TAG_NZ)
            if b is not None: b.setTitle_forState_(str(nz_prefs),UIControlStateNormal)
        utils.present_modal_picker(parentVC = self, items = nzl, selectedIndex = int(nz),
                                   okCallback = onOk, okButtonTitle=_("OK"), cancelButtonTitle=_("Cancel"))        
    @objc_method
    def onBaseUnitBut_(self, but : ObjCInstance) -> None:
        parent = gui.ElectrumGui.gui
        def onOk(selIdx : int) -> None:
            bu_str = UNIT_KEYS[selIdx]
            dec = UNITS.get(bu_str,None)
            if dec is None: raise Exception('Unknown base unit')
            b = self.view.viewWithTag_(TAG_BASE_UNIT)
            if b is not None: b.setTitle_forState_(bu_str,UIControlStateNormal)
            parent.prefs_set_decimal_point(dec)
        sel = [i for i,v in enumerate(UNIT_KEYS) if v == parent.base_unit()]
        sel = 0 if len(sel) <= 0 else sel[0]
        utils.present_modal_picker(parentVC = self, items = UNIT_KEYS, selectedIndex = int(sel),
                                   okCallback = onOk, okButtonTitle=_("OK"), cancelButtonTitle=_("Cancel"))
    
    @objc_method
    def onBlockExplorerBut_(self, but: ObjCInstance) -> None:
        parent = gui.ElectrumGui.gui
        config = parent.config
        be = web.BE_sorted_list()
        if be is None or len(be) <= 0:
            be = ["None"]
        def onOk(selIdx : int) -> None:
            be_str = be[selIdx] if selIdx < len(be) else be[0]
            b = self.view.viewWithTag_(TAG_BLOCK_EXPLORER)
            if b is not None: b.setTitle_forState_(be_str,UIControlStateNormal)
            config.set_key('block_explorer', be_str, True)
        beprefs = config.get('block_explorer', be[0])
        sel = [i for i,v in enumerate(be) if v == beprefs]
        sel = 0 if len(sel) <= 0 else sel[0]
        if len(be):
            utils.present_modal_picker(parentVC = self, items = be, selectedIndex = int(sel),
                                       okCallback = onOk, okButtonTitle=_("OK"), cancelButtonTitle=_("Cancel"))
        
    @objc_method
    def onFiatCurrencyBut_(self, but : ObjCInstance) -> None:
        parent = gui.ElectrumGui.gui
        fx = parent.daemon.fx if parent.daemon else None
        ccy = fx.get_currency()
        ccys = py_from_ns(self.currencies)
        idx = [i for i,v in enumerate(ccys) if v == ccy]
        idx = 0 if len(idx) <= 0 or not bool(fx.is_enabled()) else idx[0]
        def onOk(row : int) -> None:
            is_en = bool(row)
            ccy = ccys[row] if is_en else None
            was_en = bool(fx.is_enabled())
            need_refresh = ccy != fx.ccy or was_en != is_en
            fx.set_enabled(is_en)
            if is_en and ccy is not None and ccy != fx.ccy:
                fx.set_currency(ccy)
            if need_refresh: parent.refresh_all()
        if len(ccys):
            utils.present_modal_picker(parentVC = self, items = ccys, selectedIndex = int(idx),
                                       okCallback = onOk, okButtonTitle=_("OK"), cancelButtonTitle=_("Cancel"))
        
    @objc_method
    def onFiatExchangeBut_(self, but : ObjCInstance) -> None:
        parent = gui.ElectrumGui.gui
        fx = parent.daemon.fx if parent.daemon else None
        ex = fx.config_exchange() if fx else 'None'
        exs = py_from_ns(self.exchanges)
        idx = [i for i,v in enumerate(exs) if v == ex]
        idx = 0 if len(idx) <= 0 else idx[0]
        def onOk(choice : int) -> None:
            ex = exs[choice]
            if fx and fx.is_enabled() and ex and ex != fx.exchange.name():
                fx.set_exchange(ex)
            self.setFiatExchangeButtonText_(None)
        if len(exs) and fx:    
            utils.present_modal_picker(parentVC = self, items = exs, selectedIndex = int(idx),
                                       okCallback = onOk, okButtonTitle = _("OK"), cancelButtonTitle = _("Cancel"))

    @objc_method
    def onShowFee_(self, but : ObjCInstance) -> None:
        parent = gui.ElectrumGui.gui
        parent.prefs_set_show_fee(but.isOn())
    @objc_method
    def onMaxStaticFee_(self, tf : ObjCInstance) -> None:
        parent = gui.ElectrumGui.gui
        print("On Max Static Fee: %s"%str(tf.text))
        val = parent.prefs_set_max_fee_rate(tf.text)
        if str(val) != str(tf.text) and not tf.isFirstResponder:
            tf.text = get_max_static_fee_str(parent)
    @objc_method
    def onConfirmedOnly_(self, s : ObjCInstance) -> None:
        parent = gui.ElectrumGui.gui
        parent.prefs_set_confirmed_only(bool(s.isOn()))
    @objc_method
    def onUseChange_(self, s: ObjCInstance) -> None:
        parent = gui.ElectrumGui.gui
        parent.prefs_set_use_change(bool(s.isOn()))
        b1, enabled = parent.prefs_get_multiple_change()
        if self.viewIfLoaded:
            cell = self.viewIfLoaded.viewWithTag_(TAG_MULTIPLE_CHANGE_CELL)
            utils.uiview_set_enabled(cell, enabled)
    @objc_method
    def onUseMultiple_(self, s: ObjCInstance) -> None:
        parent = gui.ElectrumGui.gui
        parent.prefs_set_multiple_change(bool(s.isOn()))
    @objc_method
    def onHideDLBanner_(self, s: ObjCInstance) -> None:
        parent = gui.ElectrumGui.gui
        parent.prefs_set_downloading_notif_hidden(bool(s.isOn()))
    @objc_method
    def onUseCashAddr_(self, s: ObjCInstance) -> None:
        parent = gui.ElectrumGui.gui
        parent.toggle_cashaddr(bool(s.isOn()))
    @objc_method
    def onFiatHistory_(self, s: ObjCInstance) -> None:
        parent = gui.ElectrumGui.gui
        fx = parent.daemon.fx if parent.daemon else None
        if not fx: return
        fx.set_history_config(s.isOn())
        self.updateExchanges()
        parent.refresh_components('history')
        if fx.is_enabled() and s.isOn():
            # reset timeout to get historical rates
            fx.timeout = 0
    @objc_method
    def onFiatBal_(self, s: ObjCInstance) -> None:
        parent = gui.ElectrumGui.gui
        fx = parent.daemon.fx if parent.daemon else None
        if not fx: return
        fx.set_fiat_address_config(s.isOn())
        parent.refresh_components('addresses')

def get_max_static_fee_str(parent) -> str:
    fee = parent.prefs_get_max_fee_rate()
    parts = str(fee).replace(',','.').split('.')
    nrzs = len(parts[1]) if len(parts) > 1 else 0
    nrzs = max(parent.prefs_get_num_zeros(), nrzs)
    fmt = '%0.' + str(nrzs) + 'f'
    return fmt%(fee)
