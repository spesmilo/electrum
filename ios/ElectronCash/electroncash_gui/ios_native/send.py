#
# This file is:
#     Copyright (C) 2018 Calin Culianu <calin.culianu@gmail.com>
#
# MIT License
#
from . import utils
from . import gui
from .history import HistoryEntry
from . import txdetail
from . import contacts
from electroncash import WalletStorage, Wallet
from electroncash.util import timestamp_to_datetime, NotEnoughFunds, ExcessiveFee
from electroncash.transaction import Transaction
from electroncash.i18n import _
from .custom_objc import *
from .uikit_bindings import *
from electroncash import networks
from electroncash.address import Address, ScriptOutput
from electroncash.paymentrequest import PaymentRequest
from electroncash import bitcoin
from .feeslider import FeeSlider
from .amountedit import BTCAmountEdit
from electroncash.plugins import run_hook
import time, html, re, sys, traceback
from decimal import Decimal

RE_ALIAS = '^(.*?)\s*\<([1-9A-Za-z]{26,})\>$'

def parent():
    return gui.ElectrumGui.gui

def config():
    return parent().config

def wallet():
    return parent().wallet

def fx():
    p = parent()
    if p and p.daemon and p.daemon.fx:
        return p.daemon.fx
    return None

_CellIdentifier = "SpendFromCell"
_TableHeaderHeight = 25
_TableCellHeight = 20
_TableHeightRows = 4.45

class SendVC(SendBase):
    qr = objc_property()
    qrvc = objc_property()
    qrScanErr = objc_property()
    amountSats = objc_property()
    feeSats = objc_property()
    isMax = objc_property()
    notEnoughFunds = objc_property()
    excessiveFee = objc_property()
    timer = objc_property()
    dismissOnAppear = objc_property()
    kbas = objc_property()
    queuedPayTo = objc_property()

    @objc_method
    def init(self):
        self = ObjCInstance(send_super(__class__, self, 'init'))
        self.title = _("Send")
        self.qrScanErr = False
        self.amountSats = None # None ok on this one
        self.feeSats = None  # None ok on this one too
        self.isMax = False # should always be defined
        self.notEnoughFunds = False
        self.excessiveFee = False
        self.timer = None
        self.dismissOnAppear = False
        self.kbas = None
        self.queuedPayTo = None

        self.navigationItem.leftItemsSupplementBackButton = True
        bb = UIBarButtonItem.new().autorelease()
        bb.title = _("Back")
        self.navigationItem.backBarButtonItem = bb

        return self

    @objc_method
    def dealloc(self) -> None:
        self.qrScanErr = None
        self.amountSats = None
        self.feeSats = None
        self.isMax = None
        self.notEnoughFunds = None
        self.qr = None
        self.qrvc = None
        self.dismissOnAppear = None
        if self.timer: self.timer.invalidate()  # kill a timer if it hasn't fired yet
        self.timer = None
        self.excessiveFee = None
        self.kbas = None
        self.queuedPayTo = None
        utils.nspy_pop(self)
        for e in [self.amt, self.fiat, self.payTo]:
            if e: utils.nspy_pop(e)
        send_super(__class__, self, 'dealloc')

    @objc_method
    def didRotateFromInterfaceOrientation_(self, o : int) -> None:
        pass

    @objc_method
    def reader_didScanResult_(self, reader, result) -> None:
        utils.NSLog("Reader data = '%s'",str(result))
        self.checkQRData_(result)
        if self.qrScanErr:
            if type(self.qrScanErr) is int and self.qrScanErr == 2:
                title = _("Unsupported QR Code")
                message = _("The QR code contains multiple outputs. At this time only a single output is supported.\nPlease try again.")
            else:
                title = _("Invalid QR Code")
                message = _("The QR code does not appear to be a valid BCH address or payment request.\nPlease try again.")
            reader.stopScanning()
            parent().show_error(
                title = title,
                message = message,
                onOk = lambda: reader.startScanning()
            )
            self.qrScanErr = False
        else:
            self.readerDidCancel_(reader)

    @objc_method
    def readerDidCancel_(self, reader) -> None:
        if reader is not None: reader.stopScanning()
        self.dismissViewControllerAnimated_completion_(True, None)
        self.qr = None
        self.qrvc = None

    @objc_method
    def loadView(self) -> None:
        objs = NSBundle.mainBundle.loadNibNamed_owner_options_("Send",self,None)
        assert objs is not None and len(objs)

        # Apply translations and other stuff to UI text...
        self.payToTit.setText_withKerning_(_("Pay to"), utils._kern)

        # Input amount text field
        btcedit = self.amt
        fiatedit = self.fiat
        def onAmount(t : ObjCInstance) -> None:
            #print("On Amount %s, %s satoshis"%(str(t.text),str(t.getAmount())))
            self.amountSats = t.getAmount()
            fiatModified = False
            if fx() and fx().is_enabled():
                rate = fx().exchange_rate()
                if rate:
                    amtfiat = int(round(float((Decimal(self.amountSats) * Decimal(100.0) * Decimal(rate)) / Decimal(1e8)))) if self.amountSats is not None else None
                    fiatModified = fiatedit.isModified()
                    fiatedit.setAmount_(amtfiat)
                    utils.uitf_redo_attrs(fiatedit)
            if fiatModified or t.isModified():
                #print ("updating fee...")
                self.updateFee()
            else: self.chkOk()
        utils.add_callback(btcedit, 'textChanged', onAmount)
        def onEdit(t : ObjCInstance) -> None:
            self.isMax = False
        utils.add_callback(btcedit, 'edited', onEdit)
        btcedit.setUseUnitLabel_(True)
        btcedit.fixedUnitLabelWidth = 50.0

        # Amount (Fiat) label
        # Input Fiat text field
        def onAmountFiat(t : ObjCInstance) -> None:
            #print("On Fiat Amount %s, %s %s"%(str(t.text),str(t.getAmount()),str(t.baseUnit())))
            if not t.isModified() or not fx() or not fx().is_enabled():
                return
            rate = fx().exchange_rate()
            if not rate: return
            amtSats = int(round(float( (Decimal(t.getAmount())*Decimal(1e6)) / Decimal(rate) ))) if t.getAmount() is not None else None
            btcedit.setAmount_(amtSats)
            utils.uitf_redo_attrs(btcedit)
        utils.add_callback(fiatedit, 'textChanged', onAmountFiat)
        def onEditFiat(t : ObjCInstance) -> None:
            self.isMax = False
        utils.add_callback(fiatedit, 'edited', onEditFiat)
        fiatedit.setUseUnitLabel_(True)
        fiatedit.fixedUnitLabelWidth = 50.0

        self.descTit.setText_withKerning_( _("Description"), utils._kern )

        but = self.maxBut
        but.setTitle_forState_(_("Max"), UIControlStateNormal)

        # Fee Label
        self.feeTit.setText_withKerning_( _("Fee"), utils._kern )

        tedit = self.feeTf
        fee_e = tedit
        tedit.placeholder = _("Fee manual edit")
        def onManualFee(t : ObjCInstance) -> None:
            #print("On Manual fee %s, %s satoshis"%(str(t.text),str(t.getAmount())))
            self.feeSats = t.getAmount()
            if t.isModified(): self.updateFee()
            else: self.chkOk()
        utils.add_callback(fee_e, 'textChanged', onManualFee)
        fee_e.setUseUnitLabel_(True)
        fee_e.fixedUnitLabelWidth = 50.0

        # Error Label
        self.message.text = ""

        self.descDel.placeholderFont = UIFont.italicSystemFontOfSize_(14.0)
        self.descDel.tv = self.desc
        self.descDel.text = ""
        self.descDel.placeholderText = _("Description of the transaction (not mandatory).")

        feelbl = self.feeLbl
        slider = self.feeSlider
        def sliderCB(dyn : bool, pos : int, fee_rate : int) -> None:
            txt = " ".join(str(slider.getToolTip(pos,fee_rate)).split("\n"))
            feelbl.text = txt
            fee_e.modified = False # force unfreeze fee
            if dyn:
                config().set_key('fee_level', pos, False)
            else:
                config().set_key('fee_per_kb', fee_rate, False)
            self.spendMax() if self.isMax else self.updateFee()
            #print("testcb: %d %d %d.. tt='%s'"%(int(dyn), pos, fee_rate,txt))
        utils.add_callback(slider, 'callback', sliderCB)

        utils.nspy_put_byname(self, 'dummy', '_last_spend_from') # trigger the clear

        # set up navigation bar items...
        self.clearBut.title = _("Clear")
        but = self.sendBut
        but.setTitle_forState_(_("Send"), UIControlStateNormal)
        barButPreview = self.previewBut
        barButPreview.title = _("Preview")

        self.navigationItem.rightBarButtonItems = [barButPreview]
        extra = self.navigationItem.leftBarButtonItems if self.navigationItem.leftBarButtonItems else []
        self.navigationItem.leftBarButtonItems = [*extra, self.clearBut]


    @objc_method
    def viewDidLoad(self) -> None:
        uinib = UINib.nibWithNibName_bundle_("SpendFromCell", None)
        self.tv.registerNib_forCellReuseIdentifier_(uinib, _CellIdentifier)
        self.clearAllExceptSpendFrom()

    @objc_method
    def viewWillAppear_(self, animated : bool) -> None:
        send_super(__class__, self, 'viewWillAppear:', animated, argtypes=[c_bool])

        if self.dismissOnAppear and self.presentingViewController and not self.isBeingDismissed():
            self.presentingViewController.dismissViewControllerAnimated_completion_(animated, None)
            return

        if self.queuedPayTo:
            try:
                qpt = list(self.queuedPayTo)
                self.queuedPayTo = None
                self.onPayTo_message_amount_(qpt[0],qpt[1],qpt[2])
            except:
                utils.NSLog("queuedPayTo.. failed with exception: %s",str(sys.exc_info()[1]))


        self.kbas = utils.register_keyboard_autoscroll(self.view.viewWithTag_(54321))

        # redo amount label if prefs changed
        lbl = self.amtTit
        tedit = self.amt
        lbl.setText_withKerning_( _("Amount") , utils._kern )
        # Placeholder for amount
        tedit.placeholder = _("Input amount")
        wasModified = tedit.isModified()
        tedit.setAmount_(self.amountSats) # in case unit changed in prefs
        tedit.modified = wasModified
        # fee amount label
        lbl = self.feeLbl
        lbl.text = self.feeSlider.getToolTip(-1,-1)
        # Manual edit .. re-set the amount in satoshis from our cached value, in case they changed units in the prefs screen
        tedit = self.feeTf
        wasModified = tedit.isModified()
        tedit.setAmount_(self.feeSats)
        tedit.modified = wasModified
        # set manual fee edit to be enabled/disabled based on prefs settings
        if parent().prefs_get_show_fee():
            tedit.userInteractionEnabled = True
            tedit.alpha = 1.0
        else:
            tedit.userInteractionEnabled = False
            tedit.alpha = .5

        # set fiat lbl/tedit based on prefs settings
        doFX = fx() and fx().is_enabled()
        ccy = fx().get_currency() if doFX else None
        fiatte = self.fiat
        fiatte.setHidden_(not doFX)
        if doFX:
            fiatte.placeholder = _("Fiat amount")
        feelbl = self.feeTit
        c = self.csFeeTop
        if c is not None:
            c.constant = 25.0 if doFX else -28.0

        parent().cash_addr_sig.connect(lambda: self.reformatSpendFrom(), self)
        self.reformatSpendFrom()

        pay_to = utils.nspy_get_byname(self, 'pay_to')
        if pay_to is not None:
            if isinstance(pay_to, str):
                self.payTo.text = pay_to
            utils.nspy_pop_byname(self, 'pay_to')

        utils.uitf_redo_attrs(self.payTo)
        utils.uitf_redo_attrs(self.amt)
        utils.uitf_redo_attrs(self.fiat)
        utils.uitf_redo_attrs(self.feeTf)
        self.chkOk()


    @objc_method
    def viewDidAppear_(self, animated : bool) -> None:
        send_super(__class__, self, 'viewDidAppear:', animated, argtypes=[c_bool])
        parent().show_warning_if_watching_only(vc = self,
                                               onOk = lambda: self.presentingViewController.dismissViewControllerAnimated_completion_(True, None))
        if not self.tv.isHidden(): self.tv.flashScrollIndicators()

    @objc_method
    def reformatSpendFrom(self) -> None:
        # Do the "spend from" stuff
        self.tv.reloadData()
        coins = utils.nspy_get_byname(self, 'spend_from')
        if utils.nspy_get_byname(self, '_last_spend_from') == coins:
            return
        utils.nspy_put_byname(self, coins, '_last_spend_from')
        self.updateFee()

    @objc_method
    def viewWillDisappear_(self, animated: bool) -> None:
        send_super(__class__, self, 'viewWillDisappear:', animated, argtypes=[c_bool])
        # Manual edit .. cache the feeSats in case they change stuff in prefs affecting this
        tedit = self.feeTf
        self.feeSats = tedit.getAmount()
        # Amount edit --  cache the amountSats in case they change stuff in the prefs affecting this
        tedit = self.amt
        self.amountSats = tedit.getAmount()
        parent().cash_addr_sig.disconnect(self)

        if self.kbas:
            utils.unregister_keyboard_autoscroll(int(self.kbas))
            self.kbas = None


    @objc_method
    def onQRBut_(self, but) -> None:
        def DoIt() -> None:
            if not QRCodeReader.isAvailable:
                utils.show_alert(self, _("QR Not Available"), _("The camera is not available for reading QR codes"))
            else:
                self.qr = QRCodeReader.new().autorelease()
                self.qrvc = QRCodeReaderViewController.readerWithCancelButtonTitle_codeReader_startScanningAtLoad_showSwitchCameraButton_showTorchButton_("Cancel",self.qr,True,False,False)
                self.qrvc.modalPresentationStyle = UIModalPresentationFormSheet
                self.qrvc.delegate = self
                self.presentViewController_animated_completion_(self.qrvc, True, None)
                self.qrScanErr = False
        utils.boilerplate.vc_highlight_button_then_do(self, but, DoIt)

    @objc_method
    def onContactBut_(self, but) -> None:
        def DoIt() -> None:
            def onPayTo(addys : list) -> None:
                if contacts.pay_to(addys):
                    self.dismissViewControllerAnimated_completion_(True, None)
            vc = contacts.ContactsVC.alloc().initWithMode_(contacts.ModePicker).autorelease()
            nav = utils.tintify(UINavigationController.alloc().initWithRootViewController_(vc).autorelease())
            utils.add_callback(vc, 'on_pay_to', onPayTo)
            if self.payTo and self.payTo.text:
                utils.nspy_put_byname(vc, self.payTo.text, 'preselected')
            self.presentViewController_animated_completion_(nav, True, None)
        utils.boilerplate.vc_highlight_button_then_do(self, but, DoIt)

    @objc_method
    def onMaxBut_(self, but) -> None:
        utils.boilerplate.vc_highlight_button_then_do(self, but, lambda:self.spendMax())

    @objc_method
    def textFieldShouldEndEditing_(self, tf : ObjCInstance) -> bool:
        #print('textFieldShouldEndEditing %d'%tf.tag)
        if tf.tag in [115,230]:
            tf.text = tf.text.strip() # strip leading/training spaces in description and address text fields
        if tf.tag in [115]: # the other ones auto-call chkOk anyway.. todo: make addr line edit be a special validating class
            self.chkOk()
        utils.uitf_redo_attrs(tf)
        return True

    @objc_method
    def textFieldShouldReturn_(self, tf : ObjCInstance) -> bool:
        #print('textFieldShouldReturn %d'%tf.tag)
        tf.resignFirstResponder()
        return True

    @objc_method
    def onPayTo_message_amount_(self, address, message, amount) -> None:
        # address
        if not self.viewIfLoaded:
            self.queuedPayTo = [address, message, amount]
            return
        tf = self.payTo
        pr = get_PR(self)
        if pr:
            # ignore passed-in values if using PRs
            address = pr.get_requestor()
            message = pr.get_memo()
            amount = pr.get_amount()
        tf.text = str(address) if address is not None else tf.text
        tf.resignFirstResponder() # just in case
        utils.uitf_redo_attrs(tf)
        # label
        self.descDel.text = str(message) if message is not None else ""
        self.desc.resignFirstResponder()
        # amount
        if amount == "!":
            if pr:
                # '!' max amount not supported for PRs!
                amount = 0
            else:
                self.spendMax()
        tf = self.amt
        self.amountSats = int(amount) if type(amount) in [int,float] else self.amountSats
        tf.setAmount_(self.amountSats)
        tf.resignFirstResponder()
        utils.uitf_redo_attrs(tf)
        utils.uitf_redo_attrs(self.fiat)

        self.qrScanErr = False
        self.chkOk()
        utils.NSLog("OnPayTo %s %s %s",str(address), str(message), str(amount))

    @objc_method
    def chkOk(self) -> bool:

        coins = utils.nspy_get_byname(self, 'spend_from')
        if coins:
            h = _TableCellHeight*min(len(coins),_TableHeightRows) + _TableHeaderHeight
            self.tv.setHidden_(False)
            self.csTvHeight.constant = h
            self.csPayToTop.constant = 25.0
        else:
            self.tv.setHidden_(True)
            self.csTvHeight.constant = 0
            self.csPayToTop.constant = 0

        f = self.desc.frame
        self.csContentHeight.constant = f.origin.y + f.size.height + 125

        retVal = False
        errLbl = self.message
        sendBut = self.sendBut
        previewBut = self.previewBut
        amountTf = self.amt
        errView = self.messageView

        sendBut.enabled = False
        utils.uiview_set_enabled(sendBut, False)
        previewBut.enabled = False
        errLbl.text = ""

        addy = ''

        #c, u, x = wallet().get_balance()
        #a = self.amountSats if self.amountSats is not None else 0
        #f = self.feeSats if self.feeSats is not None else 0

        try:
            #print("wallet balance: %f  amountSats: %f"%(float(c+u),float(self.amountSats)))
            if self.notEnoughFunds:
                errLbl.text = _("Insufficient funds")
                raise Exception("InsufficientFunds")
            if self.excessiveFee:
                errLbl.text = _("Max fee exceeded")
                raise Exception("ExcessiveFee")
            try:
                addy = py_from_ns(self.getPayToAddress())
                if len(addy): Parser().parse_address(addy) # raises exception on parse error
            except:
                errLbl.text = _("Invalid Address")
                raise Exception("InvalidAddress")
            if self.amountSats is None or self.feeSats is None or not len(addy): # or self.feeSats <= 0:
                errLbl.text = ""
                raise Exception("SilentException") # silent error when amount or fee isn't yet specified

            previewBut.enabled = True #False # for now, unimplemented.. #True
            en = True if parent().wallet is not None and not parent().wallet.is_watching_only() else False
            sendBut.enabled = en
            utils.uiview_set_enabled(sendBut, en)
            retVal = True
        except Exception as e:
            #print("Exception :" + str(e))
            pass

        errView.setHidden_(not bool(len(errLbl.text.strip())))

        return retVal


    @objc_method
    def spendMax(self) -> None:
        self.isMax = True
        self.updateFee()  # schedule update

    @objc_method
    def clearAllExceptSpendFrom(self) -> None:
        self.isMax = False
        self.notEnoughFunds = False
        self.excessiveFee = False
        set_PR(self, None) # implicitly clears nspy_byname attr 'payment_request'
        self.doChkPR()
        # address
        tf = self.payTo
        tf.text = ""
        # Amount
        tf = self.amt
        tf.setAmount_(None)
        # Fiat
        tf = self.fiat
        # label
        self.descDel.text = ""
        # slider
        slider = self.feeSlider
        slider.setValue_animated_(slider.minimumValue,True)
        slider.onMoved()
        # manual edit fee
        tf = self.feeTf
        tf.setAmount_(None)
        tf.setFrozen_(False)
        # self.amountSats set below..
        self.amountSats = None
        self.feeSats = None
        self.message.text = ""  # clear errors
        self.chkOk()

    @objc_method
    def clearSpendFrom(self) -> None:
        utils.nspy_pop_byname(self, 'spend_from')
        utils.nspy_put_byname(self, 'dummy', '_last_spend_from')
        self.reformatSpendFrom()

    @objc_method
    def clear(self) -> None:
        self.clearAllExceptSpendFrom()
        self.clearSpendFrom()

    @objc_method
    def doChkPR(self) -> None:
        if not self.viewIfLoaded:
            return
        b = bool(self.isPR()) # ensure bool
        for e in [self.payTo, self.amt, self.fiat]:
            e.setFrozen_(b)
            if b:
                utils.nspy_put_byname(e, 10.0, 'indent_override')
            else:
                utils.nspy_pop_byname(e, 'indent_override')
        for but in [self.maxBut, self.contactBut, self.qrBut]:
            but.userInteractionEnabled = not b
            but.alpha = 1.0 if not b else 0.3
        if b:
            self.isMax = False
            self.payTo.text = get_PR(self).get_requestor()
        else:
            self.payTo.backgroundColor = utils.uicolor_custom('ultralight')

    @objc_method
    def isPR(self) -> bool:
        return get_PR(self) is not None

    @objc_method
    def getPayToAddress(self) -> ObjCInstance:
        pr = get_PR(self)
        if pr:
            try:
                return ns_from_py(pr.get_address())
            except AttributeError as e:
                # invalid/expired payment requests sometimes have no outputs Attribute
                # See #1503.
                print("Invalid payment request:", repr(e))
        return ns_from_py(self.payTo.text)


    @objc_method
    def setPayToGreen(self) -> None:
        self.payTo.backgroundColor = utils.uicolor_custom('green')

    @objc_method
    def setPayToExpired(self) -> None:
        self.payTo.backgroundColor = utils.uicolor_custom('red')

    @objc_method
    def checkQRData_(self, text) -> None:
        self.qrScanErr = False
        parser = Parser()

        errors = []
        #if self.is_pr:
        #    return
        # filter out empty lines
        lines = text.split("\n")
        lines = [i for i in lines if i]
        outputs = []
        total = 0
        #self.payto_address = None
        payto_address = None

        if len(lines) == 1:
            data = lines[0]
            if data.lower().startswith(networks.net.CASHADDR_PREFIX + ":"):
                self.isMax = False
                if not parent().pay_to_URI(data, showErr = False):
                    self.qrScanErr = True
                    return
                self.updateFee() # schedule a fee update later after qr decode completes
                return
            try:
                #self.payto_address = self.parse_output(data)
                payto_address = parser.parse_output(data)
            except:
                pass
            #if self.payto_address:
            if payto_address and len(payto_address) and isinstance(payto_address[1], Address):
                #self.win.lock_amount(False)
                #print("LOCK AMOUNT = False")

                try:
                    #self.onPayTo_message_amount_(payto_address[1].to_ui_string(), None, None)
                    self.onPayTo_message_amount_(data, None, None)
                    return
                except Exception as e:
                    utils.NSLog("EXCEPTION -- %s",str(e))
                    pass

        is_max = False
        for i, line in enumerate(lines):
            try:
                _type, to_address, amount = parser.parse_address_and_amount(line)
            except:
                #self.errors.append((i, line.strip()))
                errors.append((i, line.strip()))
                continue

            outputs.append((_type, to_address, amount))
            if amount == '!':
                is_max = True
            else:
                total += amount

        #self.win.is_max = is_max
        #self.outputs = outputs
        #self.payto_address = None

        #if self.win.is_max:
        #    self.win.do_update_fee()
        #else:
        #    self.amount_edit.setAmount(total if outputs else None)
        #    self.win.lock_amount(total or len(lines)>1)
        if len(errors):
            self.qrScanErr = True
        elif len(outputs) != 1:
            self.qrScanErr = 2
        else:
            #print("onCheckPayToText.. last clause")
            self.isMax = is_max
            self.onPayTo_message_amount_(outputs[0][1].to_ui_string(),"",outputs[0][2])
            self.updateFee()  #schedule a fee update later
        utils.NSLog("onCheckPayToText_ result: is_max=%s outputs=%s total=%s errors=%s",str(is_max),str(outputs),str(total),str(errors))

    @objc_method
    def updateFee(self):
        # Enqueus a doUpdateFee() call for later -- this facility is provided for the fee slider so that it doesn't behave too slowly.
        def onTimer() -> None:
            self.timer = None
            # Note it is very unlikely but the timer can fire right after we kill the wallet instance
            # due to the user losing auth (a long phone sleep does this). Hence this check here.
            if wallet():
                self.doUpdateFee()
        if self.timer: self.timer.invalidate()
        self.timer = utils.call_later(0.1,onTimer)

    @objc_method
    def doUpdateFee(self) -> None:
        '''Recalculate the fee.  If the fee was manually input, retain it, but
        still build the TX to see if there are enough funds.
        '''
        fee_e = self.feeTf
        amount_e = self.amt
        payToAddr = py_from_ns(self.getPayToAddress())
        self.notEnoughFunds = False
        self.excessiveFee = False

        def get_outputs(is_max):
            outputs = []
            if payToAddr:
                if is_max:
                    amount = '!'
                else:
                    amount = amount_e.getAmount()

                try:
                    _type, addr = Parser().parse_output(payToAddr)
                    outputs = [(_type, addr, amount)]
                except Exception as e:
                    #print("Testing get_outputs Exception: %s"%str(e))
                    pass
            return outputs[:]
        def get_dummy():
            return (bitcoin.TYPE_ADDRESS, wallet().dummy_address())

        freeze_fee = (fee_e.isModified()
                      and (fee_e.text or fee_e.isFirstResponder))

        #print("freeze_fee=%s"%str(freeze_fee))
        amount = '!' if self.isMax else amount_e.getAmount()
        if amount is None:
            if not freeze_fee:
                fee_e.setAmount(None)
            # TODO
            #self.statusBar().showMessage('')
        else:
            fee = fee_e.getAmount() if freeze_fee else None
            outputs = get_outputs(self.isMax)
            if not outputs:
                _type, addr = get_dummy()
                outputs = [(_type, addr, amount)]
            try:
                tx = wallet().make_unsigned_transaction(get_coins(self), outputs, config(), fee, sign_schnorr=parent().prefs_use_schnorr)
                if tx and freeze_fee and fee and tx.estimated_size():
                    self.feeLbl.text = _("Manual fee") + ": " + parent().format_fee_rate((fee*1e3) / tx.estimated_size())
            except NotEnoughFunds:
                self.notEnoughFunds = True
                if not freeze_fee:
                    fee_e.setAmount_(None)
                self.chkOk()
                return
            except ExcessiveFee:
                self.excessiveFee = True
                self.chkOk()
                return
            except BaseException as e:
                print("BASE EXCEPTION %s"%str(e))
                self.chkOk()
                return

            if not freeze_fee:
                fee = None if self.notEnoughFunds else tx.get_fee()
                fee_e.setAmount_(fee)
                utils.uitf_redo_attrs(fee_e)

            if self.isMax:
                amount = tx.output_value()
                amount_e.setAmount_(amount)
                utils.uitf_redo_attrs(amount_e)
        self.chkOk()

    @objc_method
    def onPreviewSendBut_(self, but) -> None:
        self.view.endEditing_(True)
        isPreview = but.ptr.value == self.previewBut.ptr.value
        self.doSend_(isPreview)

    @objc_method
    def showTransaction_desc_(self, txraw, desc) -> None:
        tx = Transaction(txraw, sign_schnorr=parent().prefs_use_schnorr)
        tx.deserialize()
        tx_hash, status_, label_, can_broadcast, amount, fee, height, conf, timestamp, exp_n = wallet().get_tx_info(tx)
        #print("send: status_",status_,"label_",label_,"amount",amount,"conf",conf)
        size = tx.estimated_size()
        conf = 0 if conf is None else conf
        timestamp = time.time() if timestamp is None else timestamp
        status, status_str = (status_, _("Unsigned")) #wallet().get_tx_status(tx_hash, height, conf, timestamp)
        doFX = fx() and fx().is_enabled()
        ccy = fx().get_currency() if doFX else None
        fiat_amount_str = str(self.fiat.text) if doFX else None
        #HistoryEntry = namedtuple("HistoryEntry", "tx tx_hash status_str label v_str balance_str date ts conf status value fiat_amount fiat_balance fiat_amount_str fiat_balance_str ccy status_image")
        entry = HistoryEntry(tx,tx_hash,status_str,str(desc),self.amt.text,"",timestamp_to_datetime(time.time() if conf <= 0 else timestamp),timestamp,conf,status,amount,None,None,fiat_amount_str,None,ccy,None)
        def newLabel(l):
            self.descDel.text = l

        self.navigationController.pushViewController_animated_(txdetail.CreateTxDetailWithEntry(entry, on_label = newLabel), True)

    @objc_method
    def doSend_(self, preview : bool) -> None:
        #if run_hook('abort_send', self):
        #    return
        r = read_send_form(self)
        if not r:
            return
        outputs, fee, tx_desc, coins = r
        try:
            tx = wallet().make_unsigned_transaction(coins, outputs, config(), fee, sign_schnorr=parent().prefs_use_schnorr)
        except NotEnoughFunds:
            parent().show_error(_("Insufficient funds"))
            return
        except ExcessiveFee:
            parent().show_error(_("Your fee is too high.  Max is 50 sat/byte."))
            return
        except BaseException as e:
            traceback.print_exc(file=sys.stdout)
            parent().show_error(str(e))
            return

        amount = tx.output_value() if self.isMax else sum(map(lambda x:x[2], outputs))
        fee = tx.get_fee()

        #if fee < self.wallet.relayfee() * tx.estimated_size() / 1000 and tx.requires_fee(self.wallet):
            #parent().show_error(_("This transaction requires a higher fee, or it will not be propagated by the network"))
            #return

        if preview:
            self.showTransaction_desc_(tx.serialize(), tx_desc)
            return

        # confirmation dialog
        msg = [
            _("Amount to be sent") + ": " + parent().format_amount_and_units(amount),
            _("Mining fee") + ": " + parent().format_amount_and_units(fee),
        ]

        x_fee = run_hook('get_tx_extra_fee', wallet(), tx)
        if x_fee:
            x_fee_address, x_fee_amount = x_fee
            msg.append( _("Additional fees") + ": " + parent().format_amount_and_units(x_fee_amount) )

        confirm_rate = 2 * config().max_fee_rate()


        def DoSign(password : str) -> None:
            def sign_done(success) -> None:
                if success:
                    if not tx.is_complete():
                        self.showTransaction_desc_(tx.serialize(), tx_desc)
                        self.clear()
                    else:
                        parent().broadcast_transaction(tx, tx_desc)
                #else:
                #    parent().show_error(_("An Unknown Error Occurred"))
            parent().sign_tx_with_password(tx, sign_done, password)

        # IN THE FUTURE IF WE WANT TO APPEND SOMETHING IN THE MSG ABOUT THE FEE, CODE IS COMMENTED OUT:
        #if fee > confirm_rate * tx.estimated_size() / 1000:
        #    msg.append(_('Warning') + ': ' + _("The fee for this transaction seems unusually high."))
        password = None
        if wallet().has_password():
            parent().prompt_password_if_needed_asynch(callBack = DoSign, prompt = '\n'.join(msg), vc = self)
        else:
            msg.append(_('Proceed?'))
            parent().question(message = '\n'.join(msg), title = _("Confirm Send"), onOk = lambda: DoSign(None), vc = self)

    #### UITableView delegate/dataSource methods...
    @objc_method
    def numberOfSectionsInTableView_(self, tableView) -> int:
        return 1

    @objc_method
    def tableView_numberOfRowsInSection_(self, tableView, section : int) -> int:
        try:
            coins = utils.nspy_get_byname(self, 'spend_from') or list()
            return len(coins)
        except Exception as e:
            utils.NSLog("Error, exception retrieving spend_from coins: %s",str(e))
            return 0

    @objc_method
    def tableView_cellForRowAtIndexPath_(self, tableView, indexPath):
        cell = None
        try:
            coins = utils.nspy_get_byname(self, 'spend_from') or list()
            cell = tableView.dequeueReusableCellWithIdentifier_(_CellIdentifier)
            if cell is None: raise Exception("Dafuq UIKit?!")
            coin = coins[indexPath.row]
            cell.num.text = str(indexPath.row+1) + "."
            '''
            def fmt(x):
                h = x['prevout_hash']
                a = x['address'].to_ui_string()
                #maxlen = 18
                #if len(a) > maxlen:
                #    a = a[0:maxlen//2-1] + '...' + a[-(maxlen//2-1):]
                return '{}...{}:{:d}  {}'.format(h[0:5], h[-5:], x['prevout_n'], a)
            '''
            cell.input.text = coin['prevout_hash'] + ':' + str(coin['prevout_n'])
            cell.address.text = coin['address'].to_ui_string()
            cell.amount.text = parent().format_amount(coin['value']).strip()
        except:
            utils.NSLog("exception in Send tableView_cellForRowAtIndexPath_: %s",str(sys.exc_info()[1]))
            cell = UITableViewCell.alloc().initWithStyle_reuseIdentifier_(UITableViewCellStyleSubtitle, "ACell").autorelease()
            cell.textLabel.text = " "
        return cell

    @objc_method
    def tableView_heightForRowAtIndexPath_(self, tv, indexPath) -> float:
        return _TableCellHeight

    @objc_method
    def tableView_heightForHeaderInSection_(self, tableView, section) -> float:
        return _TableHeaderHeight

    @objc_method
    def tableView_viewForHeaderInSection_(self, tv : ObjCInstance, section : int) -> ObjCInstance:
        objs = NSBundle.mainBundle.loadNibNamed_owner_options_("TableHeaders", None, None)
        hdr = None
        for o in objs:
            if isinstance(o, UIView) and o.tag == 12000:
                hdr = o
                break
        if hdr:
            lbl = hdr.viewWithTag_(1)
            coins = utils.nspy_get_byname(self, 'spend_from') or list()
            lbl.setText_withKerning_( _("Spend From") + " (" + str(len(coins)) + ")" , utils._kern )
            but = hdr.viewWithTag_(2)
            def clearfun(but : objc_id) -> None:
                but = ObjCInstance(but)
                utils.boilerplate.vc_highlight_button_then_do(self, but, lambda: self.clearSpendFrom())
            but.handleControlEvent_withBlock_(UIControlEventPrimaryActionTriggered, clearfun)
        else:
            hdr = UIView.alloc().initWithFrame_(CGRectMake(0,0,0,0)).autorelease()
        return hdr


    @objc_method
    def tableView_editingStyleForRowAtIndexPath_(self, tv, indexPath) -> int:
        return UITableViewCellEditingStyleDelete

    @objc_method
    def removeSpendFromAtIndex_(self, index : int) -> None:
        coins = utils.nspy_get_byname(self, 'spend_from')
        try:
            coins.pop(index)
        except:
            utils.NSLog("Send: Failed to pop item at index %d", index)
        utils.nspy_put_byname(self, coins, 'spend_from')

    @objc_method
    def spendFromWasDeleted(self) -> None:
        self.tv.reloadData()
        self.updateFee()

    @objc_method
    def tableView_commitEditingStyle_forRowAtIndexPath_(self, tv, editingStyle : int, indexPath) -> None:
        if editingStyle == UITableViewCellEditingStyleDelete:
            self.removeSpendFromAtIndex_(indexPath.row)
            self.retain()
            utils.call_later(0.4, lambda: self.autorelease().spendFromWasDeleted())
            tv.deleteRowsAtIndexPaths_withRowAnimation_([indexPath],UITableViewRowAnimationFade)

    @objc_method
    def tableView_trailingSwipeActionsConfigurationForRowAtIndexPath_(self, tv, indexPath) -> ObjCInstance:
        ''' This method is called in iOS 11.0+ only .. so we only create this UISwipeActionsConfiguration ObjCClass
            here rather than in uikit_bindings.py
        '''

        try:
            row = int(indexPath.row) # save param outside objcinstance object and into python for 'handler' closure
            section = int(indexPath.section)
            def handler(a : objc_id, v : objc_id, c : objc_id) -> None:
                result = False
                try:
                    self.removeSpendFromAtIndex_(row)
                    self.retain()
                    utils.call_later(0.4, lambda: self.autorelease().spendFromWasDeleted())
                    result = True
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
            utils.NSLog("Send.tableView_trailingSwipeActionsConfigurationForRowAtIndexPath_, got exception: %s", str(sys.exc_info()[1]))
            traceback.print_exc(file=sys.stderr)
        return None
    ### end UITableView related methods


def get_coins(sendvc : ObjCInstance) -> list:
    coins = utils.nspy_get_byname(sendvc, 'spend_from')
    if coins: return coins
    return wallet().get_spendable_coins(None, config())

def read_send_form(send : ObjCInstance) -> tuple:
    label = send.descDel.text
    addr = py_from_ns(send.getPayToAddress())
    fee_e = send.feeTf
    outputs = []

    if False: #self.payment_request:
        #outputs = self.payment_request.get_outputs()
        pass
    else:
        errors = False #self.payto_e.get_errors()
        if errors:
            #self.show_warning(_("Invalid lines found:") + "\n\n" + '\n'.join([ _("Line #") + str(x[0]+1) + ": " + x[1] for x in errors]))
            #return
            pass
        amt_e = send.amt
        try:
            typ, addr = Parser().parse_output(addr)
        except:
            utils.show_alert(send, _("Error"), _("Invalid Address"))
            return None
        outputs = [(typ, addr, "!" if send.isMax else amt_e.getAmount())]

        #if self.payto_e.is_alias and self.payto_e.validated is False:
        #    alias = self.payto_e.toPlainText()
        #    msg = _('WARNING: the alias "{}" could not be validated via an additional '
        #            'security check, DNSSEC, and thus may not be correct.').format(alias) + '\n'
        #    msg += _('Do you wish to continue?')
        #    if not self.question(msg):
        #        return

    if not outputs:
        utils.show_alert(send, _("Error"), _('No outputs'))
        return None

    for _type, addr, amount in outputs:
        if amount is None:
            utils.show_alert(send, _("Error"), _('Invalid Amount'))
            return None

    freeze_fee = fee_e.isModified() and fee_e.getAmount()#self.fee_e.isVisible() and self.fee_e.isModified() and (self.fee_e.text() or self.fee_e.hasFocus())
    fee = fee_e.getAmount() if freeze_fee else None
    coins = get_coins(send)
    return outputs, fee, label, coins

def get_PR(sendVC):
    if sendVC:
        pr = utils.nspy_get_byname(sendVC, 'payment_request')
        if isinstance(pr, PaymentRequest):
            return pr
    return None

def set_PR(sendVC, pr):
    if sendVC:
        if isinstance(pr, PaymentRequest):
            utils.nspy_put_byname(sendVC, pr, 'payment_request')
        else:
            # Passed None to clear
            utils.nspy_pop_byname(sendVC, 'payment_request')

class Parser:
    def parse_address_and_amount(self, line):
        x, y = line.split(',')
        out_type, out = self.parse_output(x)
        amount = self.parse_amount(y)
        return out_type, out, amount

    def parse_output(self, x):
        try:
            address = self.parse_address(x)
            return bitcoin.TYPE_ADDRESS, address
        except:
            return bitcoin.TYPE_SCRIPT, ScriptOutput.from_string(x)

    def parse_address(self, line):
        r = line.strip()
        m = re.match(RE_ALIAS, r)
        address = m.group(2) if m else r
        return Address.from_string(address)

    def parse_amount(self, x):
        if x.strip() == '!':
            return '!'
        p = pow(10, parent().get_decimal_point())
        return int(p * Decimal(x.strip()))
