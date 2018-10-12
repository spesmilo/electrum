#
# This file is:
#     Copyright (C) 2018 Calin Culianu <calin.culianu@gmail.com>
#
# MIT License
#
from . import utils
from . import gui
from . import txdetail
from . import addresses
from electroncash import WalletStorage, Wallet
from electroncash.util import timestamp_to_datetime
from electroncash.i18n import _, language
import time
from .uikit_bindings import *
from .custom_objc import *
from collections import namedtuple

CoinsEntry = namedtuple("CoinsEntry", "utxo tx_hash address address_str height name label amount amount_str is_frozen is_change base_unit")


class CoinsDetail(CoinsDetailBase):
    outputhash = objc_property()
    blockRefresh = objc_property()
    needsRefresh = objc_property()
    kbas = objc_property()

    @objc_method
    def init(self) -> ObjCInstance:
        self = ObjCInstance(send_super(__class__, self, 'init'))
        if self:
            self.title = _("Coin Info")
            self.optionsBarBut = UIBarButtonItem.alloc().initWithImage_style_target_action_(UIImage.imageNamed_("barbut_options"), UIBarButtonItemStylePlain, self, SEL(b'onOptions')).autorelease()
            self.navigationItem.rightBarButtonItem = self.optionsBarBut
            bb = UIBarButtonItem.new().autorelease()
            bb.title = _("Back")
            self.navigationItem.backBarButtonItem = bb
            gui.ElectrumGui.gui.sigCoins.connect(lambda: self.refresh(), self)
            gui.ElectrumGui.gui.cash_addr_sig.connect(lambda: self.refresh(), self)
        return self

    @objc_method
    def dealloc(self) -> None:
        self.outputhash = None
        self.blockRefresh = None
        self.needsRefresh = None
        self.kbas = None
        utils.nspy_pop(self)
        utils.remove_all_callbacks(self)
        gui.ElectrumGui.gui.sigCoins.disconnect(self)
        gui.ElectrumGui.gui.cash_addr_sig.disconnect(self)
        send_super(__class__, self, 'dealloc')


    @objc_method
    def loadView(self) -> None:
        NSBundle.mainBundle.loadNibNamed_owner_options_("CoinsDetail", self, None)
        self.addressTopSaved = self.addressTopCS.constant
        self.statusTopSaved = self.statusTopCS.constant
        self.descDel.placeholderFont = UIFont.italicSystemFontOfSize_(14.0)
        self.descDel.placeholderText = '\n' + _(str(self.descDel.placeholderText).strip())

        # kern the tits
        tits = [ self.addressTit, self.utxoTit, self.heightTit, self.descTit, self.amountTit ]
        for tit in tits:
            tit.setText_withKerning_(_(tit.text), utils._kern)


    @objc_method
    def viewDidLoad(self) -> None:
        #setup callbacks..
        def didBeginEditing() -> None:
            self.blockRefresh = True
        def didEndEditing(text : ObjCInstance) -> None:
            self.blockRefresh = False
            text = str(py_from_ns(text)).strip()
            coin = _Get(self)
            if coin:
                new_label = text
                print ("new label for coin %s = %s"%(coin.tx_hash, new_label))
                gui.ElectrumGui.gui.on_label_edited(coin.tx_hash, new_label)
                # Note that above should implicitly refresh us due to sigAddresses signal
            if self.needsRefresh: self.refresh()
        self.descDel.didBeginEditing = Block(didBeginEditing)
        self.descDel.didEndEditing = Block(didEndEditing)


    @objc_method
    def viewWillAppear_(self, animated : bool) -> None:
        send_super(__class__, self, 'viewWillAppear:', animated, argtypes=[c_bool])
        self.kbas = utils.register_keyboard_autoscroll(self.view)
        self.blockRefresh = False
        self.needsRefresh = False
        self.refresh()

    @objc_method
    def viewWillDisappear_(self, animated : bool) -> None:
        send_super(__class__, self, 'viewWillDisappear:', animated, argtypes=[c_bool])
        if self.kbas:
            utils.unregister_keyboard_autoscroll(int(self.kbas))
            self.kbas = None

    @objc_method
    def refresh(self) -> None:
        parent = gui.ElectrumGui.gui
        if not self.viewIfLoaded or not parent or not parent.wallet or self.blockRefresh:
            self.needsRefresh = True
            return
        coin = _Get(self)

        if not coin:
            # if coin goes None.. that means the user spent this UTXO.. so we back out!
            if (self.navigationController and self.navigationController.topViewController
                and self.navigationController.topViewController.ptr.value == self.ptr.value):
                self.navigationController.popViewControllerAnimated_(True)
            utils.NSLog("WARNING: CoinsDetailVC lost its 'coin' entry from underneath its own feet. This could mean the user spent the coin on another screen or something else strange happened. Backing out!")
            return

        self.address.text = coin.address.to_ui_string()
        self.utxo.text = str(coin.name)
        self.height.text = str(coin.height)
        self.descDel.text = coin.label.strip() if coin.label else ''
        self.amount.text = str(coin.amount_str).strip() + " " + coin.base_unit
        fx = parent.daemon.fx if parent.daemon else None
        if fx and fx.is_enabled() and fx.get_fiat_address_config():
            self.fiatAmount.text = fx.format_amount_and_units(coin.amount).strip()
        else:
            self.fiatAmount.text = ''
        if not self.fiatAmount.text:
            self.addressTopCS.constant = 0.0
        else:
            self.addressTopCS.constant = self.addressTopSaved

        self.freezeBut.selected = coin.is_frozen

        watch_only = bool(hasattr(parent.wallet,'is_watching_only') and parent.wallet.is_watching_only())
        self.freezeBut.setHidden_(watch_only)


        self.status.setText_withKerning_(("Change" if coin.is_change else "Receiving") + " Address", utils._kern)

        color = utils.uicolor_custom('dark')
        if coin.is_frozen:
            self.status.setText_withKerning_(_("Frozen"), 0.0)
            color = utils.uicolor_custom('frozentext')
        self.address.textColor = color
        self.utxo.textColor = color
        self.status.textColor = color
        self.amount.textColor = color
        self.fiatAmount.textColor = color

        self.spendFromBut.setHidden_(coin.is_frozen or watch_only)

        size = CGSizeMake(174.0,174.0) # the returned image has a 10 pix margin -- this compensates for it
        self.qr.contentMode = UIViewContentModeCenter # if the image pix margin changes -- FIX THIS
        self.qr.image = utils.get_qrcode_image_for_data(coin.tx_hash or '', size = size)

        if gui.ElectrumGui.gui.prefs_get_use_cashaddr() and not utils.is_landscape() and not utils.is_ipad():
            self.statusTopCS.constant = self.statusTopSaved
        else:
            self.statusTopCS.constant = self.statusTopSaved + 8

        self.needsRefresh = False

        f = self.descBox.frame
        self.contentHeightCS.constant = f.origin.y + f.size.height + 75

    @objc_method
    def viewWillTransitionToSize_withTransitionCoordinator_(self, size : CGSize, coordinator : ObjCInstance) -> None:
        send_super(__class__, self, 'viewWillTransitionToSize:withTransitionCoordinator:', size, coordinator.ptr, argtypes=[CGSize,objc_id])
        # this method gets called on rotation of the device.. this forces us to re-lay out our custom stuff (mainly the status label)
        # will call self.refresh() in 0.4 seconds.. it's a hack but it works.
        def later() -> None:
            self.refresh()
            self.autorelease()
        self.retain()
        utils.call_later(0.4, later)

    @objc_method
    def onOptions(self) -> None:
        entry = _Get(self)
        actions = _BuildGenericOptionsList(entry, self.navigationController)
        if not actions: return

        actions.insert(2, [_('Share/Save QR...'), lambda: self.onQRImgTap()])

        utils.show_alert(
            vc = self,
            title = _("Options"),
            message = _("Output") + ":" + " " + entry.name[0:10] + "..." + entry.name[-2:],
            actions = actions,
            cancel = _('Cancel'),
            style = UIAlertControllerStyleActionSheet,
            ipadAnchor =  self.optionsBarBut
        )

    @objc_method
    def toggleFreezeAddress(self) -> None:
        toggle_freeze(_Get(self))

    @objc_method
    def cpyAddress(self) -> None:
        gui.ElectrumGui.gui.copy_to_clipboard(str(self.address.text), "Address")

    @objc_method
    def cpyUTXO(self) -> None:
        gui.ElectrumGui.gui.copy_to_clipboard(str(self.utxo.text), "UTXO")

    @objc_method
    def onSpendFrom(self) -> None:
        c = _Get(self)
        if c and c.utxo:
            spend_from([c.utxo])

    @objc_method
    def onQRImgTap(self) -> None:
        if not self.qr.image: gui.ElectrumGui.gui.show_error(vc = self, message = "Error, No QR Image")
        else:
            def ShowIt() -> None:
                utils.show_share_actions(vc = self, img = self.qr.image, ipadAnchor = self.qr.convertRect_toView_(self.qr.bounds, self.view), objectName = _("Image"))
            c1 = UIColor.clearColor
            c2 = UIColor.colorWithRed_green_blue_alpha_(0.0,0.0,0.0,0.3)
            self.qr.backgroundColorAnimationFromColor_toColor_duration_reverses_completion_(c1, c2, 0.2, True, ShowIt)


_CellIdentifier = ( "CoinsCell", "EmptyCell")

class CoinsTableVC(UITableViewController):
    ''' Coins Tab -- shows utxos
    '''
    needsRefresh = objc_property()
    blockRefresh = objc_property()
    selected = objc_property() # NSArray of entry.name strings
    clearBut = objc_property()
    spendBut = objc_property()
    noCoins = objc_property()

    @objc_method
    def initWithStyle_(self, style : int) -> ObjCInstance:
        self = ObjCInstance(send_super(__class__, self, 'initWithStyle:', style, argtypes=[c_int]))
        self.needsRefresh = False
        self.blockRefresh = False
        self.title = _("Coins")
        self.selected = []
        self.tabBarItem.image = UIImage.imageNamed_("tab_coins_new")

        buts = [
            UIBarButtonItem.alloc().initWithTitle_style_target_action_(_("Spend"), UIBarButtonItemStyleDone, self, SEL(b'spendFromSelection')).autorelease(),
            UIBarButtonItem.alloc().initWithTitle_style_target_action_(_("Clear"), UIBarButtonItemStylePlain, self, SEL(b'clearSelection')).autorelease(),
        ]
        self.spendBut = buts[0]
        self.clearBut = buts[1]
        self.spendBut.enabled = False
        self.clearBut.enabled = False
        self.navigationItem.rightBarButtonItems = buts
        bb = UIBarButtonItem.new().autorelease()
        bb.title = _("Back")
        self.navigationItem.backBarButtonItem = bb

        gui.ElectrumGui.gui.sigCoins.connect(lambda: self.refresh(), self)

        return self

    @objc_method
    def dealloc(self) -> None:
        gui.ElectrumGui.gui.sigCoins.disconnect(self)
        self.needsRefresh = None
        self.blockRefresh = None
        self.selected = None
        self.clearBut = None
        self.spendBut = None
        self.noCoins = None
        utils.nspy_pop(self)
        utils.remove_all_callbacks(self)
        send_super(__class__, self, 'dealloc')

    @objc_method
    def viewDidLoad(self) -> None:
        send_super(__class__, self, 'viewDidLoad')
        objs = NSBundle.mainBundle.loadNibNamed_owner_options_("Misc", None, None)
        objs = tuple(filter(lambda x: isinstance(x, UIView) and x.tag==6000, objs)) if objs else None
        if objs:
            self.noCoins = objs[0]
            lbl = self.noCoins.viewWithTag_(6061)
            if lbl:
                lbl.attributedText = utils.ats_replace_font(lbl.attributedText, UIFont.italicSystemFontOfSize_(14.0))
                utils.uilabel_replace_attributed_text(lbl = lbl,
                                                      # translate text for i18n
                                                      text = _("This wallet has no unspent outputs (coins) to display."),
                                                      template = lbl.attributedText)

        else: NSLog("WARNING: Could not find the 'no coins' view in Misc.xib!")
        nib = UINib.nibWithNibName_bundle_(_CellIdentifier[0], None)
        self.tableView.registerNib_forCellReuseIdentifier_(nib, _CellIdentifier[0])
        self.refreshControl = gui.ElectrumGui.gui.helper.createAndBindRefreshControl()
        self.refresh()

    @objc_method
    def viewWillDisappear_(self, animated : bool) -> None:
        send_super(__class__, self, 'viewWillDisappear:', animated, argtypes=[c_bool])
        utils.nspy_pop_byname(self, 'HAVE_CELL_ANIM') # remove any extant cell anims

    @objc_method
    def numberOfSectionsInTableView_(self, tableView) -> int:
        return 1

    @objc_method
    def tableView_numberOfRowsInSection_(self, tableView, section : int) -> int:
        num = 0
        try:
            coins = _Get(self)
            num = len(coins) if coins else 0
        except:
            print("Error, exception retrieving coins from nspy cache")
        self.showHideNoCoins_(num > 0)
        return num

    @objc_method
    def showHideNoCoins_(self, hide : bool) -> None:
        if not self.noCoins: return
        if hide:
            self.noCoins.removeFromSuperview()
        else:
            self.noCoins.removeFromSuperview()
            self.view.addSubview_(self.noCoins)
            utils.boilerplate.layout_peg_view_to_superview(self.noCoins)


    @objc_method
    def tableView_cellForRowAtIndexPath_(self, tableView, indexPath):
        try:
            coins = _Get(self)
            identifier = _CellIdentifier[0 if coins else -1]
            cell = tableView.dequeueReusableCellWithIdentifier_(identifier)
            parent = gui.ElectrumGui.gui
            isGood = True
            if cell is None:
                cell = UITableViewCell.alloc().initWithStyle_reuseIdentifier_(UITableViewCellStyleSubtitle, identifier).autorelease()
                isGood = False
            if coins and isGood:
                entry = coins[indexPath.row]
                idx = indexPath.row
                setup_cell_for_coins_entry(cell, entry)
                cell.tag = idx
                cell.address.tag = idx
                def linkTapped(o : objc_id) -> None:
                    if self.navigationController and self.navigationController.visibleViewController.ptr == self.ptr:
                        self.onOptions_(ObjCInstance(o))
                def butTapped(acell : objc_id) -> None:
                    self.selectDeselectCell_(ObjCInstance(acell))
                def doDetail(acell : objc_id) -> None:
                    cellAnim = acell
                    acell = ObjCInstance(acell)
                    animDur = 0.3
                    def doPush() -> None:
                        if utils.nspy_get_byname(self, 'HAVE_CELL_ANIM') != cellAnim:
                            # 'poor man's weak ref':
                            # this detects multiple firings of event and/or if self was dealloc'd before anim finished..
                            return
                        utils.nspy_pop_byname(self, 'HAVE_CELL_ANIM')
                        if self.navigationController and self.navigationController.visibleViewController.ptr == self.ptr:
                            PushCoinsDetailVC(entry, self.navigationController)
                    utils.nspy_put_byname(self, cellAnim, 'HAVE_CELL_ANIM')
                    acell.accessoryFlashView.backgroundColorAnimationFromColor_toColor_duration_reverses_completion_(
                        UIColor.colorWithRed_green_blue_alpha_(0.5,0.5,0.5,0.4), UIColor.clearColor, animDur, False, None
                    )
                    utils.call_later(animDur/2.0, doPush)
                cell.address.linkTarget = Block(linkTapped)
                cell.onButton = Block(butTapped)
                cell.onAccessory = Block(doDetail)
                self.setupSelectionButtonCell_atIndex_(cell, idx)

            else:
                empty_cell(cell,_("No coins"),True)
        except Exception as e:
            utils.NSLog("exception in Coins tableView_cellForRowAtIndexPath_: %s",str(e))
            cell = UITableViewCell.alloc().initWithStyle_reuseIdentifier_(UITableViewCellStyleSubtitle, _CellIdentifier[-1]).autorelease()
            empty_cell(cell)
        return cell


    @objc_method
    def tableView_didSelectRowAtIndexPath_(self, tv, indexPath) -> None:
        #print("DID SELECT ROW CALLED FOR ROW %d"%indexPath.row)
        animated = True

        cell = tv.cellForRowAtIndexPath_(indexPath)
        if cell:
            animated = self.selectDeselectCell_(cell)

        tv.deselectRowAtIndexPath_animated_(indexPath, animated)

    @objc_method
    def selectDeselectCell_(self, cell : ObjCInstance) -> bool: # returns False IFF it was a frozen address and select/deselect failed
        coins = _Get(self)
        if not coins or not len(coins): return True

        index = cell.tag
        self.setIndex_selected_(index, not self.isIndexSelected_(index))
        wasSel = self.setupSelectionButtonCell_atIndex_(cell, index) # this sometimes fails if address is frozen and/or we are watching only
        self.setIndex_selected_(index, wasSel)

        self.selected = self.updateSelectionButtons()

        # animate to indicate to user why they were DENIED
        if not wasSel and index < len(coins) and coins[index].is_frozen:
            cell.amount.textColorAnimationFromColor_toColor_duration_reverses_completion_(
                utils.uicolor_custom('frozentext'),
                utils.uicolor_custom('frozentextbright'),
                0.4, True, None
            )
            cell.flags.textColorAnimationFromColor_toColor_duration_reverses_completion_(
                utils.uicolor_custom('frozentext'),
                utils.uicolor_custom('frozentextbright'),
                0.4, True, None
            )
            return False
        return True


    @objc_method
    def tableView_heightForRowAtIndexPath_(self, tv, indexPath) -> float:
        coins = _Get(self)
        if coins and indexPath.row < len(coins):
            # NEW layout: 113 for no desc, 136 for desc
            lbl = coins[indexPath.row].label
            return 136.0 if lbl and lbl.strip() else 113.0
        return 44.0

    @objc_method
    def refresh(self):
        self.needsRefresh = True # mark that a refresh was called in case refresh is blocked
        if self.blockRefresh:
            return
        if self.refreshControl: self.refreshControl.endRefreshing()
        self.selected = self.updateSelectionButtons()
        if self.tableView:
            self.tableView.reloadData()
        self.needsRefresh = False


    @objc_method
    def doRefreshIfNeeded(self):
        if self.needsRefresh:
            self.refresh()
            #print ("COINS REFRESHED")


    @objc_method
    def onOptions_(self, obj : ObjCInstance) -> None:
        #print ("On Options But")
        try:
            if isinstance(obj, UIGestureRecognizer):
                obj = obj.view
            elif isinstance(obj, (UITableViewCell, LinkLabel)):
                pass
            entry = _Get(self)[obj.tag]
            parent = gui.ElectrumGui.gui
            watch_only = False if parent.wallet and (not hasattr(parent.wallet, 'is_watching_only') or not parent.wallet.is_watching_only()) else True
            def spend_from2(utxos : list) -> None:
                validSels = list(self.updateSelectionButtons())
                coins = _Get(self)
                for entry in coins:
                    if entry.name in validSels and entry.utxo not in utxos:
                        utxos.append(entry.utxo)
                if utxos:
                    spend_from(utxos)

            actions = _BuildGenericOptionsList(entry, self.navigationController)
            if not actions: return

            if not watch_only and not entry.is_frozen:
                if len(list(self.updateSelectionButtons())):
                    actions.insert(-1,[ _('Spend from this UTXO + Selected'), lambda: spend_from2([entry.utxo]) ] )


            utils.show_alert(
                vc = self,
                title = _("Options"),
                message = _("Output") + ":" + " " + entry.name[0:10] + "..." + entry.name[-2:],
                actions = actions,
                cancel = _('Cancel'),
                style = UIAlertControllerStyleActionSheet,
                ipadAnchor =  obj.convertRect_toView_(obj.bounds, self.view)
            )
            #print ("address =", entry.address_str)
        except:
            import sys
            utils.NSLog("Exception during coins.py 'onOptions': %s",str(sys.exc_info()[1]))

    @objc_method
    def isIndexSelected_(self, index : int) -> bool:
        try:
            entry = _Get(self)[index]
            sels = set(list(self.selected))
            return bool(entry.name in sels)
        except:
            import sys
            utils.NSLog("Exception during coins.py 'isIndexSelected': %s",str(sys.exc_info()[1]))
        return False

    @objc_method
    def setIndex_selected_(self, index : int, b : bool) -> None:
        try:
            entry = _Get(self)[index]
            sels = set(list(self.selected))
            if not b: sels.discard(entry.name)
            else: sels.add(entry.name)
            self.selected = list(sels)
        except:
            import sys
            utils.NSLog("Exception during coins.py 'setIndex_selected_': %s",str(sys.exc_info()[1]))

    @objc_method
    def clearSelection(self) -> None:
        self.selected = []
        self.refresh()

    @objc_method
    def spendFromSelection(self) -> None:
        #print ("spend selected...")
        validSels = list(self.updateSelectionButtons())
        #print("valid selections:",*validSels)
        coins = _Get(self)
        utxos = []
        for entry in coins:
            if entry.name in validSels:
                utxos.append(entry.utxo)
        if utxos:
            spend_from(utxos)

    @objc_method
    def updateSelectionButtons(self) -> ObjCInstance:
        parent = gui.ElectrumGui.gui
        newSels = set()
        self.clearBut.enabled = False
        self.spendBut.enabled = False
        if parent.wallet and not parent.wallet.is_watching_only():
            sels = set(list(self.selected))
            coins = _Get(self)
            for coin in coins:
                if not coin.is_frozen and coin.name in sels:
                    newSels.add(coin.name)
            if len(newSels):
                self.spendBut.enabled = True
            if len(sels):
                self.clearBut.enabled = True
        return ns_from_py(list(newSels))

    @objc_method
    def setupSelectionButtonCell_atIndex_(self, cell, index : int) -> bool:
        if not isinstance(cell, CoinsCell):
            utils.NSLog("*** WARNING: setupSelectionButtonCell_atIndex_ called with an unknown cell type! Returning early...")
            return False
        parent = gui.ElectrumGui.gui
        no_good = parent.wallet is None or parent.wallet.is_watching_only()
        try:
            entry = _Get(self)[index]
            if entry.is_frozen:
                no_good = True
                frozen = True
        except:
            no_good = True

        ret = False

        if no_good or not self.isIndexSelected_(index):
            cell.buttonSelected = False
        else:
            cell.buttonSelected = True
            ret = True

        cell.buttonEnabled = not no_good

        return ret


def setup_cell_for_coins_entry(cell : ObjCInstance, entry : CoinsEntry) -> None:
    if not isinstance(cell, CoinsCell):
        empty_cell(cell)
        return

    #CoinsEntry = namedtuple("CoinsEntry", "utxo tx_hash address address_str height name label amount amount_str is_frozen is_change base_unit")


    cell.address.linkTarget = None # clear objc blocks.. caller sets these
    cell.onButton = None
    # initialize it to base values
    cell.buttonSelected = False
    cell.chevronHidden = False

    cell.address.linkText = entry.address_str

    kern = utils._kern

    cell.amountTit.setText_withKerning_(_("Amount"), kern)
    cell.utxoTit.setText_withKerning_(_("UTXO"), kern)
    cell.heightTit.setText_withKerning_(_("Height"), kern)

    cell.desc.setText_withKerning_(entry.label.strip() if entry.label else '', kern)

    cell.utxo.setText_withKerning_(str(entry.name), kern)
    specialColor = utils.uicolor_custom('dark')
    if entry.is_frozen:
        cell.flags.text = _("Frozen")
        specialColor = utils.uicolor_custom('frozentext')
    else:
        cell.flags.text = _("Change") if entry.is_change else _("Receiving")
    cell.amount.text = entry.amount_str + ' ' + entry.base_unit
    cell.height.text = str(entry.height)

    cell.amount.textColor = specialColor
    cell.flags.textColor = specialColor

def _BuildGenericOptionsList(entry : CoinsEntry, navController : UINavigationController) -> list():
    parent = gui.ElectrumGui.gui
    if not navController or not parent.wallet or not entry:
        return list()
    def on_block_explorer() -> None:
        parent.view_on_block_explorer(entry.tx_hash, 'tx')
    def on_request_payment() -> None:
        parent.jump_to_receive_with_address(entry.address)
    def on_address_details() -> None:
        addrDetail = addresses.PushDetail(entry.address, navController)

    actions = [
            [ _('Copy Address'), parent.copy_to_clipboard, entry.address_str, _('Address') ],
            [ _('Copy UTXO'), parent.copy_to_clipboard, entry.name, _('UTXO') ],
            [ _('Cancel') ],
            [ _("Address Details"), on_address_details ],
            [ _("Transaction Details"), _ShowTxDetailForEntry, entry, navController],
            [ _("Request payment"), on_request_payment ],
        ]

    watch_only = False if parent.wallet and not parent.wallet.is_watching_only() else True

    if not watch_only:
        actions.append([ _('Freeze') if not entry.is_frozen else _('Unfreeze'), lambda: toggle_freeze(entry) ])

    if not watch_only and not entry.is_frozen:
        actions.append([ _('Spend from this UTXO'), lambda: spend_from([entry.utxo]) ] )

    # make sure this is last
    actions.append([ _("View on block explorer"), on_block_explorer ] )

    return actions

def _ShowTxDetailForEntry(entry : CoinsEntry, navController : UINavigationController) -> None:
    parent = gui.ElectrumGui.gui
    if parent.wallet is None:
        return
    try:
        hentry = parent.get_history_entry(entry.tx_hash)
        if hentry is None: raise Exception("NoHEntry")
    except:
        import sys
        utils.NSLog("coins._ShowTxDetailForEntry got exception: %s",str(sys.exc_info()[1]))
        return
    tx = parent.wallet.transactions.get(entry.tx_hash, None)
    rawtx = None
    if tx is None:
        raise Exception("Could not find Transaction for tx '%s'"%str(entry.tx_hash))
    navController.pushViewController_animated_(txdetail.CreateTxDetailWithEntry(hentry, tx=tx), True)


def _Get(vc : ObjCInstance) -> list:
    if isinstance(vc, CoinsTableVC):
        return gui.ElectrumGui.gui.sigCoins.get(utils.nspy_get_byname(vc, 'domain'))
    elif isinstance(vc, CoinsDetail):
        # this case returns a bare CoinsEntry (not wrapped in a list)
        c = utils.nspy_get_byname(vc, 'coin')
        if c:
            vc.outputhash = c.name
            utils.nspy_pop_byname(vc, 'coin')
            return c
        elif vc.outputhash:
            return Find(py_from_ns(vc.outputhash))
        utils.NSLog("WARNING: could not find 'coin' for a CoinsDetail. Returning None!")
        return None
    utils.NSLog("WARNING: coins._Get() received an unknown type as argument. Returning an empty list!")
    return list()

def Find(utxo_name : str) -> CoinsEntry:
    coins = gui.ElectrumGui.gui.sigCoins.get(None)
    for c in coins:
        if c.name == utxo_name:
            return c
    return None

from typing import Any
class CoinsMgr(utils.DataMgr):
    def doReloadForKey(self, key : Any) -> Any:
        t0 = time.time()
        c = get_coins(key)
        elapsed = time.time()-t0
        utils.NSLog("CoinsMgr: Fetched %d utxo entries [domain=%s] in %f ms", len(c), str(key)[:16], elapsed*1e3)
        return c

def get_coin_counts(domain : list, exclude_frozen : bool = False, mature : bool = False, confirmed_only : bool = False) -> int:
    ''' Like the below but just returns the counts.. a slight optimization for addresses.py which just cares about counts. '''
    parent = gui.ElectrumGui.gui
    wallet = parent.wallet
    if wallet is None:
        utils.NSLog("get_coin_counts: wallet was None, returning early")
        return 0
    c = wallet.get_utxos(domain, exclude_frozen, mature, confirmed_only)
    return len(c) if c else 0

def get_coins(domain : list = None, exclude_frozen : bool = False, mature : bool = False, confirmed_only : bool = False) -> list:
    ''' For a given set of addresses (or None for all addresses), builds a list of
        CoinsEntry tuples:

        CoinsEntry = namedtuple("CoinsEntry", "utxo tx_hash address address_str height name label amount amount_str is_frozen is_change base_unit"))

    '''
    parent = gui.ElectrumGui.gui
    wallet = parent.wallet
    coins = list()
    if wallet is None:
        utils.NSLog("get_coins: wallet was None, returning early")
        return coins
    c = wallet.get_utxos(domain, exclude_frozen, mature, confirmed_only)
    def get_name(x):
        return x.get('prevout_hash') + ":%d"%x.get('prevout_n')
    base_unit = parent.base_unit()
    for x in c:
        address = x['address']
        address_str = address.to_ui_string()
        height = x['height']
        name = get_name(x)
        tx_hash = x['prevout_hash']
        label = wallet.get_label(tx_hash)
        amount = x['value']
        amount_str = parent.format_amount(amount)
        is_frozen = wallet.is_frozen(address)
        is_change = wallet.is_change(address)
        entry = CoinsEntry(x, tx_hash, address, address_str, height, name, label, amount, amount_str, is_frozen, is_change, base_unit)
        coins.append(entry)

    coins.sort(key=lambda x: [x.address_str, x.amount, x.height], reverse=True)

    return coins

def empty_cell(cell : ObjCInstance, txt : str = "*Error*", italic : bool = False) -> ObjCInstance:
    if isinstance(cell, CoinsCell):
        cell.amount.text = ''
        cell.utxo.text = ''
        cell.flags.text = ''
        cell.desc.text = txt
        cell.address.text = ''
        cell.height.text = ''
        cell.tag = -1
        cell.onButton = None
        cell.chevronHidden = True
        cell.buttonSelected = False
    else:
        cell.textLabel.attributedText = None
        cell.textLabel.text = txt
        if italic:
            cell.textLabel.font = UIFont.italicSystemFontOfSize_(cell.textLabel.font.pointSize)
        else:
            cell.textLabel.font = UIFont.systemFontOfSize_(cell.textLabel.font.pointSize)
        cell.detailTextLabel.attributedText = None
        cell.detailTextLabel.text = None
    cell.accessoryType = UITableViewCellAccessoryNone
    cell.accessoryView = None
    return cell


def toggle_freeze(entry) -> None:
    parent = gui.ElectrumGui.gui
    if parent.wallet and entry:
        parent.wallet.set_frozen_state([entry.address], not entry.is_frozen)
        parent.wallet.storage.write()
        parent.refresh_components('addresses')

def spend_from(coins: list) -> None:
    #print("SpendFrom")
    parent = gui.ElectrumGui.gui
    if parent.wallet and coins:
        parent.jump_to_send_with_spend_from(coins)

def PushCoinsVC(domain : list, navController : ObjCInstance) -> ObjCInstance:
    vc = CoinsTableVC.alloc()
    utils.nspy_put_byname(vc, domain, 'domain')
    vc = vc.initWithStyle_(UITableViewStylePlain).autorelease()
    navController.pushViewController_animated_(vc, True)
    return vc

def PushCoinsDetailVC(entry : CoinsEntry, navController : ObjCInstance) -> ObjCInstance:
    vc = CoinsDetail.alloc()
    utils.nspy_put_byname(vc, entry, 'coin')
    vc = vc.init().autorelease()
    navController.pushViewController_animated_(vc, True)
