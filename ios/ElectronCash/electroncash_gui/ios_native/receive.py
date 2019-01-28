#
# This file is:
#     Copyright (C) 2018 Calin Culianu <calin.culianu@gmail.com>
#
# MIT License
#
from . import utils
from . import gui
from . import addresses
from .amountedit import BTCAmountEdit, FiatAmountEdit, BTCkBEdit  # Makes sure ObjC classes are imported into ObjC runtime
from electroncash import WalletStorage, Wallet
from electroncash.util import timestamp_to_datetime, format_time
from electroncash.i18n import _, language
from electroncash.address import Address, ScriptOutput
from electroncash.paymentrequest import PR_UNPAID, PR_EXPIRED, PR_UNKNOWN, PR_PAID
from electroncash import bitcoin
import electroncash.web as web
import sys, traceback, time
from .uikit_bindings import *
from .custom_objc import *

from decimal import Decimal
from collections import namedtuple

pr_icons = {
    PR_UNPAID:"unpaid.png",
    PR_PAID:"confirmed.png",
    PR_EXPIRED:"expired.png"
}

pr_tooltips = {
    PR_UNPAID:'Pending',
    PR_PAID:'Paid',
    PR_EXPIRED:'Expired'
}

ReqItem = namedtuple("ReqItem", "dateStr addrStr signedBy message amountStr statusStr addr iconSign iconStatus fiatStr timestamp expiration expirationStr amount fiat")

def parent():
    return gui.ElectrumGui.gui

def decodeAddress(addr : str) -> Address:
    ret = None
    if addr:
        try:
            # re-encode addr in case they went to/from cashaddr
            ret = Address.from_string(addr)
        except BaseException as e:
            utils.NSLog("Caught exception decoding address %s: %s",addr,str(e))
    return ret

class ReceiveVC(ReceiveBase):
    expiresIdx = objc_property() # the index of their 'expires' pick -- saved for ui translation
    expiresList = objc_property()
    addrStr = objc_property() # string repr of address
    savedAmtSats = objc_property()
    fxIsEnabled = objc_property()
    lastQRData = objc_property()
    kbas = objc_property()
    savedOk = objc_property()
    
    @objc_method
    def init(self):
        self = ObjCInstance(send_super(__class__, self, 'init'))
        self.expiresIdx = 0
        self.expiresList =  [
            ['Never', 0],
            ['1 hour', 60*60],
            ['1 day', 24*60*60],
            ['1 week', 7*24*60*60],
        ]
        self.title = _("Receive")
        self.fxIsEnabled = None
        self.addrStr = None
        self.lastQRData = ""
        bb = UIBarButtonItem.new().autorelease()
        bb.title = _("Back")
        self.navigationItem.backBarButtonItem = bb
        return self
    
    @objc_method
    def dealloc(self) -> None:
        self.expiresList = None
        self.expiresIdx = None
        self.fxIsEnabled = None
        self.addrStr = None
        self.lastQRData = None
        self.kbas = None
        self.savedOk = None
        self.savedAmtSats = None
        utils.nspy_pop(self)
        utils.remove_all_callbacks(self)
        send_super(__class__, self, 'dealloc')
    
    @objc_method
    def loadView(self) -> None:
        NSBundle.mainBundle.loadNibNamed_owner_options_("Receive",self,None)
                    
    @objc_method
    def viewDidLoad(self) -> None:
        # do setup...
        def onAmtChg(amtEdit) -> None:
            print("onAmtChg tag = ", amtEdit.tag)
            if not amtEdit.isModified(): return
            if amtEdit.tag == 310:
                self.updateFXFromAmt()
            elif amtEdit.tag == 330:
                self.updateAmtFromFX()
            utils.uitf_redo_attrs(self.amt)
            utils.uitf_redo_attrs(self.amtFiat)
            self.redoQR()
            
        def onLinkTapped(lbl : objc_id) -> None:
            self.onAddressTap_(ObjCInstance(lbl).gr)
        
        self.addr.linkTarget = onLinkTapped

        def onExpiresLink(l : objc_id) -> None:
            self.showExpiresMenu_(ObjCInstance(l))
        self.expiresLink.linkTarget = onExpiresLink
    
        utils.add_callback(self.amt, 'textChanged', onAmtChg)
        utils.add_callback(self.amtFiat, 'textChanged', onAmtChg)
        
        self.amt.setUseUnitLabel_(True)
        self.amtFiat.setUseUnitLabel_(True)
        self.amt.fixedUnitLabelWidth = 50.0
        self.amtFiat.fixedUnitLabelWidth = 50.0

        self.amt.delegate = self
        self.amtFiat.delegate = self
        self.desc.delegate = self

        self.cpyBut.addTarget_action_forControlEvents_(self, SEL(b'onCopyBut:'), UIControlEventPrimaryActionTriggered)
        
        pr = utils.nspy_get_byname(self, 'payment_request')
        if pr:
            if pr.fiat: self.amtFiat.setAmount_(int(pr.fiat))
            if pr.amount: self.amt.setAmount_(int(pr.amount))
            if pr.addr:
                self.addr.linkDisabled = True
                self.setReceiveAddress_(pr.addr.to_ui_string())
            else:
                self.getUnusedAddress()
            if pr.message:
                self.desc.text = pr.message
            self.setExpiresByTS_( (pr.timestamp + (pr.expiration or 0.0)) if pr.expiration and pr.timestamp else 0.0)
            self.setEditable_(False)
        else:
            self.setEditable_(True)
            self.getUnusedAddress()
            self.expiresLink.linkDisabled = False
            self.expiresLink.setHidden_(False)
            self.setExpiresByIndex_(self.expiresIdx or 0)
   
        
        self.translateUI()
    
    @objc_method
    def setEditable_(self, b : bool) -> None:
        if not b:
            self.expiresLink.linkDisabled = True
            self.expiresLink.setHidden_(True)
            self.amt.userInteractionEnabled = False
            self.amtFiat.userInteractionEnabled = False
            self.desc.userInteractionEnabled = False
            self.amt.backgroundColor = UIColor.clearColor
            self.amtFiat.backgroundColor = UIColor.clearColor
            self.desc.backgroundColor = UIColor.clearColor
            self.amt.placeholder = ''
            self.amtFiat.placeholder = ''
            self.desc.placeholder = ''
            self.navigationItem.rightBarButtonItem = None
        else:
            bb = UIBarButtonItem.alloc().initWithImage_style_target_action_(UIImage.imageNamed_('barbut_chk'), UIBarButtonItemStylePlain, self, SEL('onSaveDone:')).autorelease()
            self.navigationItem.rightBarButtonItem = bb
            self.saveBarBut = bb
            self.expiresLink.linkDisabled = False
            self.expiresLink.setHidden_(False)
            self.amt.userInteractionEnabled = True
            self.amtFiat.userInteractionEnabled = True
            self.desc.userInteractionEnabled = True
            c = utils.uicolor_custom('ultralight')
            self.amt.backgroundColor = c
            self.amtFiat.backgroundColor = c
            self.desc.backgroundColor = c
            
    @objc_method
    def isEditable(self) -> bool:
        return self.amt and self.amt.isUserInteractionEnabled()
            
        
    @objc_method
    def translateUI(self) -> None:
        ''' The plan: In the future all of our GUI view controllers will implement this method to re-do language-specific text '''
        # Setup translation-based stuff
        self.addrTit.setText_withKerning_( _("Receiving address"), utils._kern )
        self.descTit.setText_withKerning_( _("Description"), utils._kern )
        self.amtTit.setText_withKerning_( _("Requested amount"), utils._kern )
        self.amtFiatTit.setText_withKerning_( _("Fiat amount"), utils._kern )
        self.expiresTit.setText_withKerning_( _("Request expires"), utils._kern )
        self.expiresLink.linkText = _("Change")
        self.shareRequestBut.setTitle_forState_(_("Share request"), UIControlStateNormal)
        self.desc.placeholder = _("Description of the transaction (not mandatory).")
        

    @objc_method
    def refresh(self) -> None:
        if not self.viewIfLoaded or not parent().wallet: return
        # Placeholder for amount
        if self.isEditable():
            self.amt.placeholder = _("Input amount") 
            self.amtFiat.placeholder = _("Fiat amount") 

        if self.savedAmtSats:
            self.amt.setAmount_(self.savedAmtSats)
            self.savedAmtSats = None
        else:
            self.amt.setAmount_(self.amt.getAmount()) # redoes decimal point placement
        
        if not self.addrStr:
            # get an address
            a = parent().wallet.get_receiving_address()
            if a is None:
                parent().show_error(_("Unable to get a receiving address from your wallet!"))
            else:
                self.addrStr = a.to_ui_string()
        
        if self.addrStr:
            address = decodeAddress(self.addrStr)
            if address is not None:
                self.setReceiveAddress_(address.to_ui_string())
                            
        self.fxIsEnabled = parent().daemon.fx and parent().daemon.fx.is_enabled()
        self.csFiatLine.constant = 101.0 if self.fxIsEnabled else 15.0
        self.amtFiat.setHidden_(not self.fxIsEnabled)
        self.amtFiatTit.setHidden_(not self.fxIsEnabled)
            
   
        utils.uitf_redo_attrs(self.desc)
        utils.uitf_redo_attrs(self.amt)
        utils.uitf_redo_attrs(self.amtFiat)
        
        self.redoQR()
        self.updateFXFromAmt()
        
        self.kbas = utils.register_keyboard_autoscroll(self.sv)
        
        self.bottomView.setHidden_(utils.nspy_get_byname(self, 'payment_request') is None)
        
    @objc_method
    def viewWillAppear_(self, animated : bool) -> None:
        send_super(__class__, self, 'viewWillAppear:', animated, argtypes=[c_bool])
        self.refresh()
                   
    @objc_method
    def viewWillDisappear_(self, animated : bool) -> None:
        send_super(__class__, self, 'viewWillDisappear:', animated, argtypes=[c_bool])        
        if self.kbas:
            utils.unregister_keyboard_autoscroll(self.kbas)
            self.kbas = None
        if not self.addr: return
        self.addrStr = self.addr.linkText
        self.savedAmtSats = self.amt.getAmount()
    
    @objc_method
    def onAddressTap_(self, uigr : ObjCInstance) -> None:
        lbl = uigr.view
        def pickedAddress(entry) -> None:
            self.addrStr = str(entry.address)
            # refresh of view will be done as a result of viewWillAppear which will be called after this returns
        addresses.present_modal_address_picker(pickedAddress, vc = self, comboPreset = (1,2))

    @objc_method
    def onCopyBut_(self, sender) -> None:
        utils.boilerplate.vc_highlight_button_then_do(self, sender, lambda: parent().copy_to_clipboard(self.addrStr, 'Address'))
    
    @objc_method
    def setExpiresByIndex_(self, idx : int) -> None:
        if idx < 0 or idx >= len(self.expiresList): return
        self.expiresIdx = idx
        self.expires.text = _("This request expires: {}").format(_(self.expiresList[idx][0]))
        
    @objc_method
    def setExpiresByTS_(self, ts : float) -> None:
        if not ts or ts <= 0.001:
            self.expires.text = _("This request expires: {}").format(_("Never"))
            return
        secs = ts - time.time()
        if secs <= 0:
            self.expires.text = _("This request expires: {}").format(_("Already Expired"))
            return
        m = int( (secs / 60.0) % 60.0 )
        h = int( (secs / 60.0 / 60.0) % 24.0 )
        d = int( (secs / 60.0 / 60.0 / 24.0) )
        s = int( secs % 60.0 )
        txt = ""
        if d: txt += _('{} days').format(d) + ' '
        if h: txt += _('{} hours').format(h) + ' '
        if m: txt += _('{} mins').format(m) + ' '
        if s: txt += _("{} secs").format(s)
        self.expires.text = txt.strip()
        
    @objc_method
    def showExpiresMenu_(self, but : ObjCInstance) -> None:
        expiresList = self.expiresList
        def onSelect(idx : int) -> None:
            self.setExpiresByIndex_(idx)
        actions = list(map(lambda x,y: [ _(x[0]), onSelect, y ], expiresList, range(0,len(expiresList))))
        actions.append([_('Cancel')])
        vc = self
        ipadAnchor = None
        if utils.is_ipad():
            ipadAnchor = but.convertRect_toView_(but.bounds, vc.view)
            ipadAnchor.size = CGSizeMake(60,ipadAnchor.size.height)
        alertvc = utils.show_alert(vc = vc,
                                   title = self.expiresTit.text,
                                   message = _("Select when the payment request should expire"),
                                   actions = actions,
                                   cancel = _('Cancel'),
                                   style = UIAlertControllerStyleActionSheet,
                                   ipadAnchor = ipadAnchor
                                   )    
        
    @objc_method
    def updateFXFromAmt(self) -> None:
        if not self.fxIsEnabled:
            self.amtFiat.setAmount_(None)
            return
        amount = self.amt.getAmount()
        amountFiat = None
        if amount is not None:
            amount = Decimal(pow(10, -8)) * amount
            rate = parent().daemon.fx.exchange_rate()
            if rate:
                amountFiat = rate * amount * Decimal(100.0)
        amountFiatOld = self.amtFiat.getAmount()
        if amountFiat != amountFiatOld:
            self.amtFiat.setAmount_(amountFiat)

    @objc_method
    def updateAmtFromFX(self) -> None:
        if not self.fxIsEnabled: return
        amountFiat = self.amtFiat.getAmount()
        amount = None
        if amountFiat is not None:
            amountFiat = Decimal(amountFiat) / Decimal(100.0)
            rate = parent().daemon.fx.exchange_rate()
            if not rate:
                return
            amount = amountFiat/Decimal(rate) * Decimal(pow(10, 8))
        amountOld = self.amt.getAmount()
        if amount != amountOld:
            self.amt.setAmount_(amount)
    
    @objc_method
    def generatePrURI(self) -> ObjCInstance:
        amount = self.amt.getAmount()
        message = self.desc.text
        print("addr,amount,message=",self.addrStr,amount,message)
        uri = web.create_URI(decodeAddress(self.addrStr), amount, message)
        print("uri = ",uri)
        return uri        
        
    @objc_method
    def redoQR(self) -> None:
        uri = self.generatePrURI()
        qriv = self.qr
        amount = self.amt.getAmount()
        message = self.desc.text
        if self.saveBarBut: self.saveBarBut.setEnabled_((amount is not None) or (message != ""))
        if uri != self.lastQRData:
            qriv.image = utils.get_qrcode_image_for_data(uri)
            self.lastQRData = uri
            
    @objc_method
    def clear(self) -> None:
        self.lastQRData = None
        self.amt.setAmount_(None)
        self.amtFiat.setAmount_(None)
        self.desc.text = ""
        self.setExpiresByIndex_(0)
        self.redoQR()

    @objc_method
    def onSave(self) -> None:
        self.savedOk = False
        if not self.addrStr:
            parent().show_error(_('No receiving address'))
            return
        amount = self.amt.getAmount()
        message = self.desc.text
        if not message and not amount:
            parent().show_error(_('No message or amount'))
            return
        i = self.expiresIdx
        expiration = list(map(lambda x: x[1], self.expiresList))[i]
        if expiration <= 0: expiration = None
        theAddr = decodeAddress(self.addrStr)
        req = parent().wallet.make_payment_request(theAddr, amount, message, expiration)
        print(req)
        parent().wallet.add_payment_request(req, parent().config)
        utils.nspy_put_byname(self, req, 'payment_request')
        def OnDone() -> None:
            if not parent().wallet: return
            parent().wallet.storage.write() # commit it to disk
            parent().refresh_components('address','receive')
            self.savedOk = (amount is not None) or (message != "")
            # force disable save button
            if self.saveBarBut: self.saveBarBut.setEnabled_(self.savedOk)
            
        parent().sign_payment_request(addr = theAddr, onSuccess = OnDone, vc = self)
        

    @objc_method
    def onSaveDone_(self, sender) -> None:
        self.onSave()
        if self.savedOk:
            #if self.navigationItem.leftBarButtonItem:
            #    self.navigationItem.leftBarButtonItem.title = _("Close")
            self.setEditable_(False)
            pr = utils.nspy_get_byname(self, 'payment_request')
            cb = utils.get_callback(self, 'on_done')
            def ItIsDoneMyMaster() -> None:
                utils.show_notification(_("Payment request saved"))
                if callable(cb):
                    from inspect import signature
                    if len(signature(cb).parameters) > 0: cb(pr)
                    else: cb()
            ItIsDoneMyMaster()
            self.refresh() # side effect of this is it causes the "Share request" button to appear

    ## tf delegate methods
    @objc_method
    def textFieldShouldEndEditing_(self, tf : ObjCInstance) -> bool:
        #print('textFieldShouldEndEditing %d'%tf.tag)
        if tf.ptr.value == self.desc.ptr.value:
            tf.text = tf.text.strip()
            self.redoQR() # other tf's are handled by other callbacks
        return True
    
    @objc_method
    def textFieldDidEndEditing_(self, tf : ObjCInstance) -> None:
        if tf.ptr.value == self.desc.ptr.value:
            utils.uitf_redo_attrs(tf)
        
    @objc_method
    def textFieldShouldReturn_(self, tf : ObjCInstance) -> bool:
        #print('textFieldShouldReturn %d'%tf.tag)
        tf.resignFirstResponder()
        return True
    
    @objc_method
    def setReceiveAddress_(self, adr) -> None:
        self.addr.linkText = adr
        self.addrStr = adr
        
    @objc_method
    def getUnusedAddress(self) -> None:
        wallet = parent().wallet
        if not wallet: return
        # hide receive tab if no receive requests available
        b = len(wallet.receive_requests) > 0
        #self.setVisible(b)
        #self.parent.receive_requests_label.setVisible(b)
        #if not b:
        #    self.parent.expires_label.hide()
        #    self.parent.expires_combo.show()

        
        domain = wallet.get_addresses()
        if self.addrStr:
            # update the receive address if necessary
            current_address = Address.from_string(self.addrStr)
            addr = wallet.get_unused_address()
            if not current_address in domain and addr:
                self.setReceiveAddress_(addr.to_ui_string())
                current_address = addr.to_ui_string()        
            #TODO:
            #self.parent.new_request_button.setEnabled(addr != current_address)
            
    @objc_method
    def onShareRequestBut_(self, sender) -> None:
        ipadAnchor = sender.convertRect_toView_(sender.bounds, self.view) if isinstance(sender, UIView) else None
        def OnShareURI() -> None:
            uri = self.generatePrURI()
            url = NSURL.URLWithString_(uri)
            utils.show_share_actions(vc = self, url = url, ipadAnchor = ipadAnchor, objectName = _("Request URI"))
        def OnShareQR() -> None:
            if not self.qr.image: self.redoQR()
            if not self.qr.image: parent().show_error(vc = self, message = "Error Generating QR Image")
            else: utils.show_share_actions(vc = self, img = self.qr.image, ipadAnchor = ipadAnchor, objectName = _("Image"))
        
        actions = [
            [ _("Share as URI..."), OnShareURI ],
            [ _("Share as QR Image..."), OnShareQR ],
            [ _("Cancel") ]
        ]
        alert = utils.show_alert(vc = self,
                                 title = _("Share Request"),
                                 message = _("You may share this payment request as a 'bitcoincash:' style URI, or as a QR Code Image."),
                                 actions = actions,
                                 style = UIAlertControllerStyleActionSheet,
                                 cancel = _("Cancel"),
                                 ipadAnchor = ipadAnchor)

    @objc_method
    def onQRImgTap(self) -> None:
        if not self.qr.image: parent().show_error(vc = self, message = "Error, No QR Image")
        else:
            def ShowIt() -> None:
                utils.show_share_actions(vc = self, img = self.qr.image, ipadAnchor = self.qr.convertRect_toView_(self.qr.bounds, self.view), objectName = _("Image"))
            c1 = UIColor.clearColor
            c2 = UIColor.colorWithRed_green_blue_alpha_(0.0,0.0,0.0,0.3)
            self.qr.backgroundColorAnimationFromColor_toColor_duration_reverses_completion_(c1, c2, 0.2, True, ShowIt)


def _GetReqs() -> list:
    return parent().sigRequests.get(None)

def _DelReqAtIndex(index : int, refreshDelay : float = 0.45, showErrorBox : bool = True) -> bool:
    wasDeleted = False
    try:
        reqs = _GetReqs()
        if index < len(reqs):
            req = reqs[index]
            wasDeleted =  parent().delete_payment_request(req.addr, refreshDelay)
    except:
        utils.NSLog("Got exception deleting payment request: %s", str(sys.exc_info()[1]))
        traceback.print_exc(file=sys.stderr)
    if not wasDeleted and showErrorBox:
        parent().show_error("Unspecified error deleting payment request.")
    return wasDeleted

    
class RequestsMgr(utils.DataMgr):
    def doReloadForKey(self, ignored):
        t0 = time.time()
        wallet = parent().wallet
        daemon = parent().daemon
        if not wallet: return list() # wallet not open for whatever reason (can happen due to app backgrounding)
        
        domain = wallet.get_addresses()

        reqs = list()
        for req in wallet.get_sorted_requests(parent().config):
            address = req['address']
            if address not in domain:
                print("addr '%s' not in domain!"%str(address))
                continue
            timestamp = req.get('time', 0)
            amount = req.get('amount', None)
            expiration = req.get('exp', None)
            expirationStr = format_time(expiration) if expiration else ''
            message = req.get('memo', '')
            date = format_time(timestamp)
            status = req.get('status')
            signature = req.get('sig')
            requestor = req.get('name', '')
            amount_str = parent().format_amount(amount) if amount else ""
            signedBy = ''
            iconSign = ''
            iconStatus = ''
            fiatStr = ''
            fiat = None
            #item.setData(0, Qt.UserRole, address)
            if signature is not None:
                #item.setIcon(2, QIcon(":icons/seal.png"))
                #item.setToolTip(2, 'signed by '+ requestor)
                signedBy = 'signed by ' + requestor
                iconSign = "seal.png"
            if status is not PR_UNKNOWN:
                #item.setIcon(6, QIcon(pr_icons.get(status)))
                iconStatus = pr_icons.get(status,'')
            try:
                if daemon and daemon.fx.is_enabled() and amount:
                    fiatStr = daemon.fx.format_amount_and_units(amount)
                    try:
                        fiat = float(fiatStr.split()[0])
                    except:
                        pass
            except:
                utils.NSLog("ReqMgr: could not get fiat amount")
                fiatStr = ''
            #ReqItem = namedtuple("ReqItem", "dateStr addrStr signedBy message amountStr statusStr addr iconSign iconStatus fiatStr, timestamp expiration expirationStr amount fiat")
            item = ReqItem(date, address.to_ui_string(), signedBy, message, amount_str, pr_tooltips.get(status,''), address, iconSign, iconStatus, fiatStr, timestamp, expiration, expirationStr, amount, fiat)
            #print ("addr,amount,expiration = ",item.addrStr, item.amountStr, item.expiration, item.expirationStr)
            #self.addTopLevelItem(item)
            reqs.append(item)
            #print(item)
        reqs = sorted(reqs, key=lambda x: -x.timestamp)
        utils.NSLog("ReqMgr: fetched %d extant payment requests in %f ms",len(reqs),(time.time()-t0)*1e3)
        return reqs

class ReqTVD(ReqTVDBase):
    ''' Request TableView Datasource/Delegate -- generic handler to provide data and cells to the req table view '''
    didReg = objc_property()
    
    @objc_method
    def init(self) -> ObjCInstance:
        self = ObjCInstance(send_super(__class__, self, 'init'))
        if self:
            self.didReg = NSMutableSet.alloc().init().autorelease()
            def doRefresh() -> None:
                if self.tv:
                    self.tv.reloadData()
                    if self.tv.refreshControl: self.tv.refreshControl.endRefreshing()
            parent().sigRequests.connect(doRefresh, self)
        return self
    
    @objc_method
    def dealloc(self) -> None:
        parent().sigRequests.disconnect(self)
        self.didReg = None
        send_super(__class__, self, 'dealloc')
    
    ## TABLEVIEW related methods..
    @objc_method
    def numberOfSectionsInTableView_(self, tv) -> int:
        return 1
                
    @objc_method
    def tableView_numberOfRowsInSection_(self, tv : ObjCInstance, section : int) -> int:
        reqs = _GetReqs()
        return len(reqs) if reqs else 0
 
    @objc_method
    def tableView_cellForRowAtIndexPath_(self, tv, indexPath) -> ObjCInstance:
        try:
            reqs = _GetReqs()
            identifier = "RequestListCell"
            if not self.didReg.containsObject_(tv.ptr.value):
                nib = UINib.nibWithNibName_bundle_(identifier, None)
                tv.registerNib_forCellReuseIdentifier_(nib, identifier)
                self.didReg.addObject_(tv.ptr.value)
            if not reqs or indexPath.row < 0 or indexPath.row >= len(reqs):
                raise Exception('Bad index path row -- wallet closed and reopened?')
            cell = tv.dequeueReusableCellWithIdentifier_(identifier)
            #ReqItem = namedtuple("ReqItem", "date addrStr signedBy message amountStr statusStr addr iconSign iconStatus")
            item = reqs[indexPath.row]
            cell.addressTit.setText_withKerning_(_('Address'),utils._kern)
            cell.statusTit.setText_withKerning_(_('Status'),utils._kern)
            cell.amountTit.setText_withKerning_(_('Amount'),utils._kern)
            if item.fiatStr:
                cell.amount.attributedText = utils.hackyFiatAmtAttrStr(item.amountStr.strip(), item.fiatStr.strip(), '', 2.5, cell.amountTit.textColor)
            else:
                cell.amount.text = item.amountStr.strip() if item.amountStr else ''
            cell.address.text = item.addrStr.strip() if item.addrStr else ''
            if item.dateStr:
                cell.date.attributedText = utils.makeFancyDateAttrString(item.dateStr.strip())
            else:
                cell.date.text = ''
            if item.message:
                cell.desc.setText_withKerning_(item.message,utils._kern)
            else:
                cell.desc.text = ''
            cell.status.text = item.statusStr if item.statusStr else _('Unknown')
            cell.selectionStyle = UITableViewCellSelectionStyleNone if not self.vc or not self.vc.navigationController else UITableViewCellSelectionStyleDefault
            cell.chevron.setHidden_(cell.selectionStyle == UITableViewCellSelectionStyleNone)
        except:
            utils.NSLog("Exception in ReqTVD cellForRowAtIndexPath: %s", str(sys.exc_info()[1]))
            # this sometimes happens on app re-foregrounding.. so guard against it
            cell = UITableViewCell.alloc().initWithStyle_reuseIdentifier_(UITableViewCellStyleSubtitle, "Cell").autorelease()
            cell.selectionStyle = UITableViewCellSelectionStyleNone
        return cell

    # Below 3 methods conform to UITableViewDelegate protocol
    
    @objc_method
    def tableView_didSelectRowAtIndexPath_(self, tv, indexPath) -> None:
        tv.deselectRowAtIndexPath_animated_(indexPath,True)
        if not self.vc or not self.vc.navigationController:
            utils.NSLog("Cannot preset ReceiveVC because current view controller ReqTVD is embedded in is either undefined or lacks a navigationController!")
            return
        reqs = _GetReqs()
        try:
            item = reqs[indexPath.row]
            vc = ReceiveVC.new().autorelease()
            utils.nspy_put_byname(vc, item, 'payment_request')
            self.vc.navigationController.pushViewController_animated_(vc, True)
        except:
            utils.NSLog("Exception in ReqTVD didSelectRowAtIndexPath: %s", str(sys.exc_info()[1]))

    
    @objc_method
    def tableView_commitEditingStyle_forRowAtIndexPath_(self, tv : ObjCInstance, es : int, indexPath : ObjCInstance) -> None:
        ''' iOS 10 and below method for deleting table rows '''
        if es == UITableViewCellEditingStyleDelete:
            _DelReqAtIndex(indexPath.row, refreshDelay = 0.2)
     
    
    @objc_method
    def tableView_trailingSwipeActionsConfigurationForRowAtIndexPath_(self, tv, indexPath) -> ObjCInstance:
        ''' This method is called in iOS 11.0+ only .. so we only create this UISwipeActionsConfiguration ObjCClass
            here rather than in uikit_bindings.py
        '''
        try:
            row = int(indexPath.row) # save param outside objcinstance object and into python for 'handler' closure
            def handler(a : objc_id, v : objc_id, c : objc_id) -> None:
                result = False
                try:
                    result = _DelReqAtIndex(row)
                except:
                    traceback.print_exc(file=sys.stderr)
                ObjCBlock(c)(bool(result)) # inform UIKit if we deleted it or not by calling the block handler callback
            action = UIContextualAction.contextualActionWithStyle_title_handler_(UIContextualActionStyleDestructive,
                                                                                 _("Remove"),
                                                                                 Block(handler))
            action.image = UIImage.imageNamed_("trashcan_red.png")
            action.backgroundColor = utils.uicolor_custom('red')
            return UISwipeActionsConfiguration.configurationWithActions_([action])
        except:
            utils.NSLog("ReqTV.tableView_trailingSwipeActionsConfigurationForRowAtIndexPath_, got exception: %s", str(sys.exc_info()[1]))
            traceback.print_exc(file=sys.stderr)
        return None


class ReqTVDTiny(ReqTVD):
    @objc_method
    def tableView_titleForHeaderInSection_(self, tv : ObjCInstance,section : int) -> ObjCInstance:
        return _("Requests")

    @objc_method
    def tableView_cellForRowAtIndexPath_(self, tv, indexPath) -> ObjCInstance:
        reqs = _GetReqs()
        identifier = "%s_%s"%(str(__class__) , str(indexPath.section))
        cell = tv.dequeueReusableCellWithIdentifier_(identifier)
        if cell is None:
            cell = UITableViewCell.alloc().initWithStyle_reuseIdentifier_(UITableViewCellStyleSubtitle, identifier).autorelease()
        if not reqs or indexPath.row < 0 or indexPath.row >= len(reqs):
            return cell # can sometimes happen on app re-foregrounding
        item = reqs[indexPath.row]
        #ReqItem = namedtuple("ReqItem", "date addrStr signedBy message amountStr statusStr addr iconSign iconStatus")
        cell.textLabel.text = ((item.dateStr + " - ") if item.dateStr else "") + (item.message if item.message else "")
        cell.textLabel.numberOfLines = 1
        cell.textLabel.lineBreakMode = NSLineBreakByTruncatingMiddle
        cell.textLabel.adjustsFontSizeToFitWidth = True
        cell.textLabel.minimumScaleFactor = 0.3
        cell.detailTextLabel.text = ((item.addrStr + " ") if item.addrStr else "") + (item.amountStr if item.amountStr else "") + " - " + item.statusStr
        cell.detailTextLabel.numberOfLines = 1
        cell.detailTextLabel.lineBreakMode = NSLineBreakByTruncatingMiddle
        cell.detailTextLabel.adjustsFontSizeToFitWidth = True
        cell.detailTextLabel.minimumScaleFactor = 0.3
        cell.accessoryType = UITableViewCellAccessoryNone
        cell.selectionStyle = UITableViewCellSelectionStyleNone
        return cell
