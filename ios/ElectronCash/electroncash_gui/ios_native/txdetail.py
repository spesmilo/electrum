#
# This file is:
#     Copyright (C) 2018 Calin Culianu <calin.culianu@gmail.com>
#
# MIT License
#
from electroncash.i18n import _, language
from . import utils
from . import gui
from .custom_objc import TxDetailBase, TxInputsOutputsTVCBase, CustomNavController
from .uikit_bindings import *
from .history import HistoryEntry, StatusImages
from . import addresses
from electroncash.transaction import Transaction
from electroncash.address import Address, PublicKey, ScriptOutput
from electroncash.util import timestamp_to_datetime
import json, sys
from . import coins
from . import contacts

_TxInputsOutputsCellHeight = 85.0
_TxInputsOutputsHeaderHeight = 22.0

SCHNORR_SIGIL = "ⓢ"

# ViewController used for the TxDetail view's "Inputs" and "Outputs" tables.. not exposed.. managed internally
class TxInputsOutputsTVC(TxInputsOutputsTVCBase):

    tagin = objc_property()
    tagout = objc_property()
    ts = objc_property()
    # weak properties from Base:
    #  txDetailVC; // the TxDetail that is holding us
    @objc_method
    def initWithInputTV_outputTV_timestamp_(self, inputTV : ObjCInstance, outputTV : ObjCInstance, ts : float) -> ObjCInstance:
        self = ObjCInstance(send_super(__class__, self, 'init'))
        if self is not None:
            if not isinstance(utils.nspy_get(self), Transaction):
                raise ValueError('TxInputsOutputsTVC requires an nspy entry on self that is a Transaction subclass!')
            if inputTV.tag == 0:
                inputTV.tag = 9001
            self.tagin = inputTV.tag
            if outputTV.tag == 0:
                outputTV.tag = self.tagin + 1
            self.tagout = outputTV.tag
            self.ts = ts

            if self.tagin == self.tagout or inputTV.ptr.value == outputTV.ptr.value:
                raise ValueError("The input and output table views must be different and have different tags!")

            nib = UINib.nibWithNibName_bundle_("TxDetailInOutCell", None)
            inputTV.registerNib_forCellReuseIdentifier_(nib, "TxDetailInOutCell")
            outputTV.registerNib_forCellReuseIdentifier_(nib, "TxDetailInOutCell")

            inputTV.delegate = self
            outputTV.delegate = self
            inputTV.dataSource = self
            outputTV.dataSource = self

            from rubicon.objc.runtime import libobjc
            libobjc.objc_setAssociatedObject(inputTV.ptr, self.ptr, self.ptr, 0x301)
            libobjc.objc_setAssociatedObject(outputTV.ptr, self.ptr, self.ptr, 0x301)

            def refresh() -> None:
                inputTV.reloadData()
                outputTV.reloadData()

            gui.ElectrumGui.gui.cash_addr_sig.connect(lambda x: refresh(), self)
            gui.ElectrumGui.gui.sigContacts.connect(lambda: refresh(), self)

        return self

    @objc_method
    def dealloc(self) -> None:
        print("TxInputsOutputsTVC dealloc")
        gui.ElectrumGui.gui.sigContacts.disconnect(self)
        gui.ElectrumGui.gui.cash_addr_sig.disconnect(self)
        self.tagin = None
        self.tagout = None
        self.ts = None
        utils.nspy_pop(self)
        send_super(__class__, self, 'dealloc')


    @objc_method
    def numberOfSectionsInTableView_(self, tv) -> int:
        return 1

    @objc_method
    def tableView_viewForHeaderInSection_(self, tv : ObjCInstance, section : int) -> ObjCInstance:
        objs = NSBundle.mainBundle.loadNibNamed_owner_options_("TableHeaders", None, None)
        hdr = None
        for o in objs:
            if isinstance(o, UIView) and o.tag == 11000:
                hdr = o
                break
        if hdr:
            lbl = hdr.viewWithTag_(1)
            tx = utils.nspy_get(self)
            try:
                if tv.tag == self.tagin: lbl.text = _("Inputs") + (" (%d) "%len(tx.inputs()))
                elif tv.tag == self.tagout: lbl.text = _("Outputs") + (" (%d) "%len(tx.outputs()))
            except:
                utils.NSLog("Exception in viewForHeaderInSection in TX In/Out TVC: %s", str(sys.exc_info()[1]))
                lbl.text = "(In/Out)"
        else:
            hdr = UIView.alloc().initWithFrame_(CGRectMake(0,0,0,0)).autorelease()
        return hdr

    @objc_method
    def tableView_heightForRowAtIndexPath_(self, tv, indexPath) -> float:
        return _TxInputsOutputsCellHeight

    @objc_method
    def tableView_heightForHeaderInSection_(self, tv, section : int) -> float:
        return _TxInputsOutputsHeaderHeight

    @objc_method
    def tableView_numberOfRowsInSection_(self, tv : ObjCInstance, section : int) -> int:
        tx = utils.nspy_get(self)

        if tv.tag == self.tagin:
            return len(tx.inputs())
        elif tv.tag == self.tagout:
            return len(tx.outputs())

    @objc_method
    def tableView_cellForRowAtIndexPath_(self, tv, indexPath):
        #todo: - allow for label editing (popup menu?)
        identifier = "TxDetailInOutCell"
        cell = tv.dequeueReusableCellWithIdentifier_(identifier)
        parent = gui.ElectrumGui.gui
        wallet = parent.wallet

        def format_amount(amt):
            return parent.format_amount(amt, whitespaces = False)

        def fx():
            return parent.daemon.fx if parent.daemon and parent.daemon.fx and parent.daemon.fx.show_history() else None

        base_unit = parent.base_unit()

        try:
            tx = utils.nspy_get(self)

            isInput = None
            x = None
            if tv.tag == self.tagin:
                isInput = True
                x = tx.inputs()[indexPath.row]
            elif tv.tag == self.tagout:
                isInput = False
                x = tx.get_outputs()[indexPath.row]
            else:
                raise ValueError("tv tag %d is neither input (%d) or output (%d) tag!"%(int(tv.tag),int(self.tagin),int(self.tagout)))


            cell.address.text = ""
            cell.addressType.text = ""
            cell.detail.text = ""

            addr = None

            if isInput:
                if x['type'] == 'coinbase':
                    cell.addressType.text = "coinbase"
                    cell.address.text = "coinbase"
                else:
                    prevout_hash = x.get('prevout_hash')
                    prevout_n = x.get('prevout_n')
                    mytxt = ""
                    mytxt += prevout_hash[0:8] + '...'
                    mytxt += prevout_hash[-8:] + (":%-4d " % prevout_n)
                    addr = x['address']
                    if isinstance(addr, PublicKey):
                        addr = addr.toAddress()
                    if addr is None:
                        addr_text = _('unknown')
                    else:
                        addr_text = addr.to_ui_string()
                    cell.address.text = addr_text
                    if x.get('value') is not None:
                        v_in = x['value']
                        mytxt += format_amount(v_in) + ' ' + base_unit
                        if fx(): mytxt += ' (' + fx().historical_value_str(v_in,timestamp_to_datetime(self.ts)) + " " + fx().get_currency() + ')'
                    cell.detail.text = mytxt.strip()
            else:
                addr, v = x
                cell.address.text = addr.to_ui_string()
                if v is not None:
                    cell.detail.text = (format_amount(v) + " " + base_unit +  ((' (' + fx().historical_value_str(v,timestamp_to_datetime(self.ts)) + " " + fx().get_currency() + ')') if fx() else '')).strip()



            typ = ''
            if isinstance(addr, Address):
                if wallet.is_mine(addr):
                    if wallet.is_change(addr):
                        typ = _("My Change Address")
                    else:
                        typ = _("My Receiving Address")
                else:
                    typ = _("External Address")
                    contact = contacts.Find(addr)
                    if contact:
                        typ += ', ' + _('Contact') + ": " + contact.name
            cell.addressType.text = typ
            cell.accessoryType = UITableViewCellAccessoryNone #UITableViewCellAccessoryDisclosureIndicator#UITableViewCellAccessoryDetailDisclosureButton#UITableViewCellAccessoryDetailButton #
        except Exception as e:
            print("exception in %s: %s"%(__class__.name,str(e)))
            cell.addressType.text = ""
            cell.address.text = "Not found"
            cell.detail.text = ""
            cell.accessoryType = UITableViewCellAccessoryNone
        return cell

    # Below 2 methods conform to UITableViewDelegate protocol
    @objc_method
    def tableView_accessoryButtonTappedForRowWithIndexPath_(self, tv, indexPath):
        print("ACCESSORY TAPPED CALLED")
        pass

    @objc_method
    def tableView_didSelectRowAtIndexPath_(self, tv, indexPath):
        print("DID SELECT ROW CALLED FOR SECTION %s, ROW %s"%(str(indexPath.section),str(indexPath.row)))
        parent = gui.ElectrumGui.gui
        tv.deselectRowAtIndexPath_animated_(indexPath, True)
        tx = utils.nspy_get(self)
        isInput = tv.tag == self.tagin
        x = tx.inputs()[indexPath.row] if isInput else tx.get_outputs()[indexPath.row]
        if isInput and x.get('type', None) == 'coinbase':
            return
        vc = self.txDetailVC
        title = _("Options")
        message = _("Transaction Input {}").format(indexPath.row) if isInput else _("Transaction Output {}").format(indexPath.row)

        def getData(x, isAddr, isInput) -> str:
            data = ""
            if isAddr:
                if isInput:
                    addr = x['address']
                    if isinstance(addr, PublicKey):
                        addr = addr.toAddress()
                    if addr is None:
                        addr_text = _('unknown')
                    else:
                        addr_text = addr.to_ui_string()
                else:
                    addr, v = x
                    addr_text = addr.to_ui_string()
                data = addr_text
            elif isInput:
                prevout_hash = x.get('prevout_hash')
                prevout_n = x.get('prevout_n')
                data = prevout_hash[:] #+ ":%-4d" % prevout_n
            print("Data=%s"%str(data))
            return data

        def isScriptOutput(x) -> bool:
            if not isInput:
                try:
                    addr, v = x
                    if isinstance(addr, ScriptOutput): return True
                except:
                    pass
            return False

        def onCpy(isAddr : bool) -> None:
            print ("onCpy %s"%str(isAddr))
            parent.copy_to_clipboard(getData(x,isAddr,isInput))
        def onQR(isAddr : bool) -> None:
            print ("onQR %s"%str(isAddr))
            data = getData(x, isAddr, isInput)
            vc = self.txDetailVC
            qrvc = utils.present_qrcode_vc_for_data(vc, data)
            parent.add_navigation_bar_close_to_modal_vc(qrvc)

        def onBlkXplo(forceShowTx : bool = False) -> None:
            print ("onBlkXplo")
            if forceShowTx:
                tx = utils.nspy_get(self)
                txid = tx.txid()
                if tx and txid: parent.view_on_block_explorer(txid, 'tx')
                return
            if isInput:
                data = getData(x, False, True)
            else:
                data = getData(x, True, False)
                try:
                    data = Address.from_string(data)
                except:
                    parent.show_error(_('Invalid address') + ': ' + str(data))
                    return
            parent.view_on_block_explorer(data, "tx" if isInput else "addr")

        actions = [
            [ _("Copy Address"), onCpy, True ],
            [ _("Show Address QR"), onQR, True ],
            [ _("Copy input hash"), onCpy, False ],
            [ _("Show input hash QR"), onQR, False ],
            [ _("View on block explorer"), onBlkXplo ],
            [ _("Cancel") ],
        ]
        if not isInput:
            actions.pop(2)
            actions.pop(2)

            if isScriptOutput(x):
                # it's a script output, so indicate that in the messaging
                actions[0][0] = _('Copy Script')
                actions[1][0] = _('Show Script QR')
                actions[2].append(True) # force view block explorer to go to the TX since this isn't an output address
                message += " " + _("(Script Output)")

            # see if we have this output as a "Coin" in our wallet (UTXO)
            try:
                def get_name():
                    return str(tx.txid()) + (":%d"%indexPath.row)
                coin = coins.Find(get_name())
                if coin and self.txDetailVC.navigationController:
                    def onShowCoin(coin):
                        coins.PushCoinsDetailVC(coin, self.txDetailVC.navigationController)
                    actions.insert(0, [_("Show Coin Info"), onShowCoin, coin])
            except:
                print("Failed to get_name:",str(sys.exc_info()[1]))

        addy = getData(x, True, isInput)
        if addy and not isinstance(addy, Address):
            try:
                addy = Address.from_string(addy)
            except:
                addy = None
        if addy and parent.wallet:
            if parent.wallet.is_mine(addy):
                def onShowAddy(addy):
                    addresses.PushDetail(addy,self.txDetailVC.navigationController)

                actions.insert(0, [ _("Address Details"), onShowAddy, addy ] )
            else:
                entry = contacts.Find(addy)
                if not entry: # is not mine, isn't in contacts, offer user the option of adding
                    def doAddNewContact(addy):
                        contacts.show_new_edit_contact(addy, self.txDetailVC, onEdit=lambda x:utils.show_notification(_("Contact added")), title = _("New Contact"))
                    actions.insert(1, [ _("Add to Contacts"), doAddNewContact, addy ] )
                elif self.txDetailVC.navigationController: # is not mine but is in contacts, so offer them a chance to view the contact
                    actions.insert(1, [ _("Show Contact"), contacts.PushNewContactDetailVC, entry, self.txDetailVC.navigationController ] )


        utils.show_alert(vc = vc,
                         title = title,
                         message = message,
                         actions = actions,
                         cancel = _("Cancel"),
                         style = UIAlertControllerStyleActionSheet,
                         ipadAnchor = tv.convertRect_toView_(tv.rectForRowAtIndexPath_(indexPath), vc.view)
                         )



def CreateTxInputsOutputsTVC(txDetailVC : ObjCInstance, tx : Transaction, itv : ObjCInstance, otv : ObjCInstance, timestamp : float) -> ObjCInstance:
    tvc = TxInputsOutputsTVC.alloc()
    utils.nspy_put(tvc, tx)
    tvc = tvc.initWithInputTV_outputTV_timestamp_(itv,otv,timestamp).autorelease()
    tvc.txDetailVC = txDetailVC
    return tvc

# internal function to setup and/or refresh the TxDetail viewcontroller with data
def _setup_transaction_detail_view(vc : ObjCInstance) -> None:
    entry = utils.nspy_get_byname(vc, 'tx_entry')
    tx, tx_hash, status_str, label, v_str, balance_str, date, ts, conf, status, value, fiat_amount, fiat_balance, fiat_amount_str, fiat_balance_str, ccy, img, *dummy2 = entry
    parent = gui.ElectrumGui.gui
    wallet = parent.wallet
    base_unit = parent.base_unit()
    format_amount = parent.format_amount
    if not wallet:
        utils.NSLog("TxDetail: Wallet not open.. aborting early (tx_hash=%s)",tx_hash)
        return
    if tx is None:
        tx = wallet.transactions.get(tx_hash, None)
        if tx is not None and tx.raw:
            tx = Transaction(tx.raw, sign_schnorr=parent.prefs_use_schnorr)
            tx.deserialize()
    if tx is None:
        utils.NSLog("*** ERROR: Cannot find tx for hash: %s",tx_hash)
        return
    tx_hash, status_, label_, can_broadcast, amount, fee, height, conf, timestamp, exp_n = wallet.get_tx_info(tx)
    size = tx.estimated_size()
    can_sign = not tx.is_complete() and wallet and wallet.can_sign(tx) #and (wallet.can_sign(tx) # or bool(self.main_window.tx_external_keypairs))

    wasNew = False
    if not vc.viewIfLoaded:
        NSBundle.mainBundle.loadNibNamed_owner_options_("TxDetail",vc,None)
        wasNew = True
        if vc.maxTVHeight < 1.0:
            vc.maxTVHeight = vc.inputsTVHeightCS.constant

    # grab all the views
    # Transaction ID:
    txTit = vc.txTit
    txHash =  vc.txHash
    copyBut = vc.cpyBut
    qrBut =  vc.qrBut
    # Description:
    descTit = vc.descTit
    descTf = vc.descTf
    # Status:
    statusTit = vc.statusTit
    statusIV = vc.statusIV
    statusLbl = vc.statusLbl
    # Date:
    dateTit = vc.dateTit
    dateLbl = vc.dateLbl
    # Amount received/sent:
    amtTit = vc.amtTit
    amtLbl = vc.amtLbl
    # Size:
    sizeTit = vc.sizeTit
    sizeLbl = vc.sizeLbl
    # Fee:
    feeTit = vc.feeTit
    feeLbl = vc.feeLbl
    # Locktime:
    lockTit = vc.lockTit
    lockLbl = vc.lockLbl
    # ⓢ Schnorr Signed label
    schnorrLbl = vc.schnorrLbl
    # Inputs
    inputsTV = vc.inputsTV
    # Outputs
    outputsTV = vc.outputsTV

    # Setup data for all the stuff
    txTit.text = _("Transaction ID:").translate({ord(':') : None})
    tx_hash_str = tx_hash if tx_hash is not None and tx_hash != "None" and tx_hash != "Unknown" and tx_hash != _("Unknown") else _('Unknown')
    rbbs = []
    vc.bottomView.setHidden_(True)
    vc.bottomBut.handleControlEvent_withBlock_(UIControlEventPrimaryActionTriggered, None) # clear previous events
    if can_sign:
        vc.noBlkXplo = True
        vc.bottomView.setHidden_(False)
        def fun() -> None: vc.onSign()
        vc.bottomBut.handleControlEvent_withBlock_(UIControlEventPrimaryActionTriggered, fun)
        vc.bottomBut.setTitle_forState_(_('Sign'), UIControlStateNormal)
        if not img:
            img = StatusImages[-1]
    if can_broadcast:
        vc.noBlkXplo = True
        vc.bottomView.setHidden_(False)
        def fun() -> None: vc.onBroadcast()
        vc.bottomBut.handleControlEvent_withBlock_(UIControlEventPrimaryActionTriggered, None) # clear previous events
        vc.bottomBut.handleControlEvent_withBlock_(UIControlEventPrimaryActionTriggered, fun)
        vc.bottomBut.setTitle_forState_(_('Broadcast'), UIControlStateNormal)
        if not img:
            img = StatusImages[-2]

    if tx_hash_str == _("Unknown") or tx_hash is None: #unsigned tx
        copyBut.setHidden_(True)
        qrBut.setHidden_(True)
        txHash.setHidden_(True)
        txHash.userInteractionEnabled = False
        vc.noTxHashView.setHidden_(False)
        vc.noTxHashLbl.text = _("You need to sign this transaction in order for it to get a transaction ID.") if can_sign else _("This transaction is not signed and thus lacks a transaction ID.")
        vc.notsigned = True
        rbbs.append(UIBarButtonItem.alloc().initWithImage_style_target_action_(UIImage.imageNamed_("barbut_actions"), UIBarButtonItemStyleBordered, vc, SEL(b'onShareSave:')).autorelease())
    else:
        copyBut.setHidden_(False)
        qrBut.setHidden_(False)
        txHash.setHidden_(False)
        vc.noTxHashView.setHidden_(True)
        vc.notsigned = False
        txHash.linkText = tx_hash_str
        txHash.userInteractionEnabled = True

        def onTxLinkTap(ll : objc_id) -> None:
            vc.onTxLink_(ObjCInstance(ll).gr)
        txHash.linkTarget = Block(onTxLinkTap)
        rbbs.append(UIBarButtonItem.alloc().initWithImage_style_target_action_(UIImage.imageNamed_("barbut_actions"), UIBarButtonItemStyleBordered, vc, SEL(b'onTxLink:')).autorelease())

    if amount is None: # unrelated to this wallet.. hide the description textfield.. also affects messaging below.. see viewDidLayoutSubviews
        vc.unrelated = True
    else:
        vc.unrelated = False

    vc.navigationItem.rightBarButtonItems = rbbs

    descTit.text = _("Description")
    descTf.text = label
    descTf.placeholder = _("Tap to add a description")
    descTf.clearButtonMode = UITextFieldViewModeWhileEditing
    utils.uitf_redo_attrs(descTf)

    statusTit.setText_withKerning_(_("Status:").translate({ord(':') : None}), utils._kern)
    if not img:
        #try and auto-determine the appropriate image if it has some confirmations and img is still null
        try:
            c = min(int(conf), 6)
            if c >= 0: img = StatusImages[c+3]
        except:
            pass
        if not img: img = UIImage.imageNamed_("empty.png")
    ff = str(status_) #status_str
    vc.canRefresh = False
    try:
        if int(conf) > 0:
           ff = "%s %s"%(str(conf), _('confirmations'))
        vc.canRefresh = conf >= 0 # if we got here means refresh has meaning.. it's not an external tx or if it is, it now is on the network, so enable refreshing
    except:
        pass
    statusLbl.text = _(ff)
    if vc.canRefresh and conf >= 1: img = StatusImages[min(len(StatusImages)-1,3+min(6,conf))]
    statusIV.image = img


    if timestamp or exp_n:
        if timestamp:
            dateTit.setText_withKerning_(_("Date"), utils._kern)
            #dateLbl.text = str(date)
            dateLbl.attributedText = utils.makeFancyDateAttrString(str(date))
        elif exp_n:
            dateTit.setText_withKerning_(_("Expected conf."), utils._kern)
            dateLbl.text = '%d blocks'%(exp_n) if exp_n > 0 else _('unknown (low fee)')
        vc.noBlkXplo = False
        dateTit.alpha = 1.0
        dateLbl.alpha = 1.0
    else:
        # wtf? what to do here?
        dateTit.setText_withKerning_(_("Date"), utils._kern)
        dateLbl.text = ""
        dateTit.alpha = 0.5
        dateLbl.alpha = 0.5

    myAmtStr = ''
    if vc.unrelated:
        amtTit.setText_withKerning_(_("Amount"), utils._kern)
        amtLbl.text = _("Transaction unrelated to your wallet")
    elif amount > 0:
        amtTit.setText_withKerning_(_("Amount received:").translate({ord(':') : None}), utils._kern)
        myAmtStr = ('%s %s%s'%(format_amount(amount),base_unit,
                               (" " + fiat_amount_str + " " + ccy + "") if fiat_amount_str else '',
                               ))
    else:
        amtTit.setText_withKerning_( _("Amount sent:").translate({ord(':') : None}), utils._kern )
        myAmtStr = ('%s %s%s'%(format_amount(-amount),base_unit,
                               (" " + fiat_amount_str.replace('-','') + " " + ccy + "") if fiat_amount_str else '',
                               ))
    if myAmtStr:
        l = myAmtStr.split()
        am = l[0]
        unt = ' ' + l[1] if len(l) else ''
        rest = ' ' + ' '.join(l[2:]) if len(l) > 2 else ''
        ats = NSMutableAttributedString.alloc().initWithString_attributes_(am, {NSFontAttributeName : UIFont.systemFontOfSize_weight_(16.0, UIFontWeightBold)}).autorelease()
        if unt:
            ats.appendAttributedString_(NSAttributedString.alloc().initWithString_attributes_(unt, {NSFontAttributeName : UIFont.systemFontOfSize_weight_(16.0, UIFontWeightBold)}).autorelease())
        if rest:
            ats.appendAttributedString_(NSAttributedString.alloc().initWithString_attributes_(rest, {NSFontAttributeName : UIFont.systemFontOfSize_weight_(14.0, UIFontWeightRegular)}).autorelease())
        amtLbl.attributedText = ats

    sizeTit.setText_withKerning_( _("Size:").translate({ord(':') : None}), utils._kern )
    if size:
        sizeLbl.text = ('%d bytes' % (size))
    else:
        sizeLbl.text = _("Unknown")

    feeTit.setText_withKerning_( _("Fee"), utils._kern )
    fee_str = '%s' % (format_amount(fee) + ' ' + base_unit if fee is not None else _('unknown'))
    if fee is not None:
        fee_str += '  ( %s ) '%  parent.format_fee_rate(fee/size*1000)
    feeLbl.text = fee_str

    lockTit.setText_withKerning_(_("Locktime"), utils._kern)
    if tx.locktime > 0:
        lockLbl.text = str(tx.locktime)
        lockTit.setHidden_(False)
        lockLbl.setHidden_(False)
    else:
        lockTit.setHidden_(True)
        lockLbl.setHidden_(True)

    n_inp, n_outp = len(tx.inputs()), len(tx.outputs())
    # auto-adjust height of table views
    vc.inputsTVHeightCS.constant = min(_TxInputsOutputsHeaderHeight + _TxInputsOutputsCellHeight*n_inp, vc.maxTVHeight)
    vc.outputsTVHeightCS.constant = min(_TxInputsOutputsHeaderHeight + _TxInputsOutputsCellHeight*n_outp, vc.maxTVHeight)

    # refreshes the tableview with data
    if wasNew:
        if ts is None: ts = time.time()
        tvc = CreateTxInputsOutputsTVC(vc, tx, inputsTV, outputsTV, float(ts))
    else:
        inputsTV.reloadData()
        outputsTV.reloadData()

    if any(tx.is_schnorr_signed(i) for i in range(n_inp)):
        schnorrLbl.text = SCHNORR_SIGIL + " " + _('Schnorr Signed')
        schnorrLbl.setHidden_(False)
    else:
        schnorrLbl.setHidden_(True)


class TxDetail(TxDetailBase):
    notsigned = objc_property() # by default is false.. if true, offer different buttons/options
    unrelated = objc_property() # by default false, if set to true, hide the desc tf and other layout niceties
    noBlkXplo = objc_property()
    cbTimer = objc_property()
    canRefresh = objc_property()
    blockRefresh = objc_property()
    refreshNeeded = objc_property()
    # Various other properties, weak and strong, are in ViewsForIB.h in Obj-C declared for TxDetailbase

    @objc_method
    def init(self) -> ObjCInstance:
        self = ObjCInstance(send_super(__class__, self, 'init'))
        if self:
            self.title = _("Transaction") + " " + _("Details")
            bb = UIBarButtonItem.new().autorelease()
            bb.title = _("Back")
            self.navigationItem.backBarButtonItem = bb
            self.commonInit()
        return self

    @objc_method
    def initWithCoder_(self, coder : ObjCInstance) -> ObjCInstance:
        self = ObjCInstance(send_super(__class__, self, 'initWithCoder:', coder.ptr, argtypes=[objc_id]))
        if self:
            self.commonInit()
        return self

    @objc_method
    def commonInit(self) -> None:
        gui.ElectrumGui.gui.sigHistory.connect(lambda:self.refresh(), self)


    @objc_method
    def dealloc(self) -> None:
        print("TxDetail dealloc")
        gui.ElectrumGui.gui.sigHistory.disconnect(self)
        self.notsigned = None
        self.unrelated = None
        self.noBlkXplo = None
        self.canRefresh = None
        self.blockRefresh = None
        self.refreshNeeded = None
        if self.cbTimer: self.cbTimer.invalidate()
        self.cbTimer = None
        utils.nspy_pop(self)
        utils.remove_all_callbacks(self)
        send_super(__class__, self, 'dealloc')

    @objc_method
    def loadView(self) -> None:
        self.edgesForExtendedLayout = 0
        self.extendedLayoutIncludesOpaqueBars = False
        _setup_transaction_detail_view(self)

    @objc_method
    def refresh(self) -> None:
        if not self.viewIfLoaded: return
        if self.canRefresh:
            if self.blockRefresh:
                self.refreshNeeded = True
                utils.NSLog("TxDetail will refresh transaction later (user is editing)")
            else:
                _setup_transaction_detail_view(self)
                utils.NSLog("TxDetail refreshed transaction")
                self.refreshNeeded = False
        else:
            utils.NSLog("TxDetail will not refresh transaction (not refreshable)")
            self.refreshNeeded = False
            self.blockRefresh = False

    @objc_method
    def doRefreshIfNeeded(self) -> None:
        if self.refreshNeeded: self.refresh()

    @objc_method
    def viewWillAppear_(self, animated : bool) -> None:
        send_super(__class__, self, 'viewWillAppear:', animated, argtypes=[c_bool])
        entry = utils.nspy_get_byname(self, 'tx_entry')
        self.descTf.text = entry.label
        #todo update this stuff in realtime?

    @objc_method
    def viewDidAppear_(self, animated : bool) -> None:
        send_super(__class__, self, 'viewDidAppear:', animated, argtypes=[c_bool])
        utils.get_callback(self, "on_appear")()

    @objc_method
    def viewDidLayoutSubviews(self) -> None:
        send_super(__class__, self, 'viewDidLayoutSubviews')
        # mogrify layout depending on whether this tx is ours or not. if not ours, hide the descTit and descTf and move up the layout
        unrelated = bool(self.unrelated)
        self.statusTopCSRelated.setActive_(not unrelated)
        self.statusTopCSUnrelated.setActive_(unrelated)
        self.descTit.setHidden_(unrelated)
        self.descTf.setHidden_(unrelated)
        f = self.outputsTV.frame
        # peg layout size based on dynamic contents. Wish there was a way to do this with autolayout but my brain at the moment and this seems easier.
        self.contentViewHeightCS.constant = f.origin.y + f.size.height + 100
        self.contentView.layoutIfNeeded()

    @objc_method
    def textFieldShouldReturn_(self, tf : ObjCInstance) -> bool:
        tf.resignFirstResponder()
        return True

    @objc_method
    def textFieldDidBeginEditing_(self, tf) -> None:
        self.blockRefresh = True

    @objc_method
    def textFieldDidEndEditing_(self, tf : ObjCInstance) -> None:
        entry = utils.nspy_get_byname(self, 'tx_entry')
        tx_hash = entry.tx_hash
        tf.text = tf.text.strip()
        new_label = tf.text
        entry = utils.set_namedtuple_field(entry, 'label', new_label)
        utils.nspy_put_byname(self, entry, 'tx_entry')
        if tx_hash is not None:
            gui.ElectrumGui.gui.on_label_edited(tx_hash, new_label)
        utils.get_callback(self, 'on_label')(new_label)
        utils.uitf_redo_attrs(tf)
        self.blockRefresh = False
        self.doRefreshIfNeeded()

    @objc_method
    def onCpyBut_(self, but) -> None:
        entry = utils.nspy_get_byname(self, 'tx_entry')
        utils.boilerplate.vc_highlight_button_then_do(self, but, lambda:gui.ElectrumGui.gui.copy_to_clipboard(entry.tx_hash))

    @objc_method
    def onQRBut_(self, but) -> None:
        def DoIt() -> None:
            entry = utils.nspy_get_byname(self, 'tx_entry')
            if not entry: return

            qrvc = utils.present_qrcode_vc_for_data(vc=self,
                                                    data=entry.tx_hash,
                                                    title = _('QR code'))
            gui.ElectrumGui.gui.add_navigation_bar_close_to_modal_vc(qrvc)
        utils.boilerplate.vc_highlight_button_then_do(self, but, DoIt)

    @objc_method
    def onShareSave_(self, sender : ObjCInstance) -> None:
        parent = gui.ElectrumGui.gui
        ipadAnchor = sender.view.frame if isinstance(sender, UIGestureRecognizer) else sender # else clause means it's a UIBarButtonItem
        if not parent.wallet: return
        self.view.endEditing_(True)
        tx = utils.nspy_get_byname(self, 'tx_entry').tx
        waitDlg = None
        def Dismiss(compl, animated = True) -> None:
            nonlocal waitDlg
            if waitDlg:
                waitDlg.dismissViewControllerAnimated_completion_(animated, compl)
                waitDlg = None

        def DoIt() -> None:
            try:
                name = 'signed_%s.txt' % (tx.txid()[0:8]) if tx.is_complete() else 'unsigned.txt'
                fileName = utils.get_tmp_dir() + '/' + name
                text = None
                if fileName:
                    tx_dict = tx.as_dict()
                    input_values = [x.get('value') for x in tx.inputs()]
                    tx_dict['input_values'] = input_values
                    with open(fileName, "w+") as f:
                        text = json.dumps(tx_dict, indent=4) + '\n'
                        f.write(text)
                    utils.NSLog("wrote tx - %d bytes to file: %s",len(text),fileName)
                    text = None #No text..
                    def MyCompl() -> None:
                        utils.show_share_actions(vc = self, fileName = fileName, text = text, ipadAnchor = ipadAnchor)
                    Dismiss(MyCompl)
                else:
                    def MyCompl() -> None: parent.show_error("Could not save transaction temp file")
                    Dismiss(MyCompl, False)
            except:
                err = str(sys.exc_info()[1])
                def MyCompl() -> None: parent.show_error(err)
                Dismiss(MyCompl, False)
                utils.NSLog("Got exception generating TX text file: %s", err)
        waitDlg = utils.show_please_wait(vc = self, message = _("Calculating Tx Details..."), completion = DoIt)

    @objc_method
    def onTxLink_(self, sender : ObjCInstance) -> None:
        entry = utils.nspy_get_byname(self, 'tx_entry')
        parent = gui.ElectrumGui.gui

        ipadAnchor = sender.view.frame if isinstance(sender, UIGestureRecognizer) else sender # else clause means it's a UIBarButtonItem

        def on_block_explorer() -> None:
            parent.view_on_block_explorer(entry.tx_hash, 'tx')

        actions = [
            [ _('Cancel') ],
            [ _('Copy to clipboard'), self.onCpyBut_, None ],
            [ _('Show as QR code'), self.onQRBut_, None ],
        ]
        if not self.noBlkXplo:
            actions.append([ _("View on block explorer"), on_block_explorer ])


        actions.append([_("Share/Save..."), lambda: self.onShareSave_(sender)])

        utils.show_alert(
            vc = self,
            title = _("Options"),
            message = _("Transaction ID:") + " " + entry.tx_hash[:12] + "...",
            actions = actions,
            cancel = _('Cancel'),
            style = UIAlertControllerStyleActionSheet,
            ipadAnchor = ipadAnchor
        )

    @objc_method
    def onSign(self) -> None:
        password = None
        parent = gui.ElectrumGui.gui
        wallet = parent.wallet
        if not wallet: return
        self.view.endEditing_(True)
        entry = utils.nspy_get_byname(self, 'tx_entry')
        tx = entry.tx


        def DoSign(password : str) -> None:
            nonlocal entry
            def sign_done(success) -> None:
                nonlocal entry
                if success:
                    tx_hash, *dummy = wallet.get_tx_info(tx)
                    entry = utils.set_namedtuple_field(entry, 'tx_hash', tx_hash)
                    utils.nspy_put_byname(self, entry, 'tx_entry')
                    _setup_transaction_detail_view(self) # recreate ui
                #else:
                #    parent.show_error(_("An Unknown Error Occurred"))
            parent.sign_tx_with_password(tx, sign_done, password)


        parent.prompt_password_if_needed_asynch(callBack = DoSign, vc = self)


    @objc_method
    def onBroadcast(self) -> None:
        parent = gui.ElectrumGui.gui
        wallet = parent.wallet
        if not wallet: return
        self.view.endEditing_(True)
        entry = utils.nspy_get_byname(self, 'tx_entry')
        tx = entry.tx

        def broadcastDone():
            nonlocal entry
            if self.viewIfLoaded is None:
                self.cbTimer = None
                return
            # immediately hide the broadcast button
            self.bottomView.setHidden_(True)
            tx_hash, status_, label_, can_broadcast, amount, fee, height, conf, timestamp, exp_n = wallet.get_tx_info(tx)
            if conf is None:
                print("conf was none; calling broadcastDone again in 250 ms...")
                if self.cbTimer: self.cbTimer.invalidate()
                self.cbTimer = utils.call_later(0.250, broadcastDone)
                return
            else:
                print("conf was not none...refreshing TxDetail...")
            if self.cbTimer: self.cbTimer.invalidate()
            self.cbTimer = None
            status, status_str = wallet.get_tx_status(tx_hash, height, conf, timestamp)
            if status is not None and status >= 0 and status < len(StatusImages):
                entry = utils.set_namedtuple_field(entry, 'status_image', StatusImages[status])
                utils.nspy_put_byname(self, entry, 'tx_entry')
            _setup_transaction_detail_view(self) # nb: don't call refresh here, instead call this to re-evaluate everything, including 'canRefresh'

        parent.broadcast_transaction(tx, self.descTf.text, broadcastDone)


def CreateTxDetailWithEntry(entry : HistoryEntry, on_label = None, on_appear = None, tx = None, asModalNav = False) -> ObjCInstance:
    txvc = TxDetail.alloc()
    if not isinstance(entry.tx, Transaction) or isinstance(tx, Transaction):
        if isinstance(tx, Transaction):
            tx.deserialize()
            entry = utils.set_namedtuple_field(entry, 'tx', tx)
        else:
            raise ValueError('CreateWithEntry -- HistoryEntry provided must have an entry.tx that is a transaction!')
    utils.nspy_put_byname(txvc, entry, 'tx_entry')
    if callable(on_label): utils.add_callback(txvc, 'on_label', on_label)
    if callable(on_appear): utils.add_callback(txvc, 'on_appear', on_appear)
    txvc = txvc.init().autorelease()
    if asModalNav:
        gui.ElectrumGui.gui.add_navigation_bar_close_to_modal_vc(txvc,leftSide = True)
        return utils.tintify(CustomNavController.alloc().initWithRootViewController_(txvc).autorelease())
    return txvc

def CreateTxDetailWithTx(tx : Transaction, on_label = None, on_appear = None, asModalNav = False) -> ObjCInstance:
    parent = gui.ElectrumGui.gui
    wallet = parent.wallet
    import time

    tx_hash, status_, label_, can_broadcast, amount, fee, height, conf, timestamp, exp_n = wallet.get_tx_info(tx)
    size = tx.estimated_size()
    status_str = ""
    status = status_
    img = None
    if conf is not None:
        if tx_hash is not None and height is not None and timestamp is not None:
            status, status_str = wallet.get_tx_status(tx_hash, height, conf, timestamp)
            if status is not None and status >= 0 and status < len(StatusImages):
                img = StatusImages[status]
    else:
        conf = 0
    timestamp = time.time() if timestamp is None else timestamp
    doFX = False #fx() and fx().is_enabled()
    ccy = None #fx().get_currency() if doFX else None
    fiat_amount_str = None #str(self.fiat.text) if doFX else None
    #HistoryEntry = namedtuple("HistoryEntry", "extra_data tx_hash status_str label v_str balance_str date ts conf status value fiat_amount fiat_balance fiat_amount_str fiat_balance_str ccy status_image")
    entry = HistoryEntry(tx,tx_hash,status_str,label_,parent.format_amount(amount) if amount is not None else _("Transaction unrelated to your wallet"),
                         "",timestamp_to_datetime(time.time() if conf <= 0 else timestamp),
                         timestamp,conf,status,amount,None,None,fiat_amount_str,None,ccy,img)

    return CreateTxDetailWithEntry(entry, on_label = on_label, on_appear = on_appear, asModalNav = asModalNav)
