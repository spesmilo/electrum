#
# This file is:
#     Copyright (C) 2018 Calin Culianu <calin.culianu@gmail.com>
#
# MIT License
#
from . import utils
from . import gui
from electroncash.i18n import _, language
from electroncash import mnemonic
from electroncash.old_mnemonic import words as old_words
from typing import Any
from .uikit_bindings import *
from .custom_objc import *
import sys
from collections import namedtuple
import electroncash.bitcoin as bitcoin
import electroncash.keystore as keystore
from electroncash.address import Address, PublicKey

if False:
    # this is here for translate i18n to pick up these strings
    __DUMMY_FOR_TRANSLATION = (
        _("My Wallet"), _("Tap to enter a password"), _("Enter the same password again"),
        _("Wallet Password"), _("Confirm Wallet Password"),
        _("Please write your seed phrase down, as it's the only way to recover your funds if you forget your password or your device is stolen."),
        _("Reenter your seed phrase"),
        # On-Boarding text...
        _("Welcome to"), _("Electron Cash is an SPV wallet for Bitcoin Cash"),
        _("Control your own private keys"), _("Easily back up your wallet with a mnemonic seed phrase."),
        _("Enjoy high security"), _("without downloading the blockchain or running a full node."),
        _("Get Started"),
        _("Cancel"), _("Seed"), _("Next"), _("Back"),
        _("Import"), _("Master Key"), _("Save Wallet"),
    )


#################################################################################################
#    Use the below 2 functions to call up either the On-Boarding or the "New Wallet" wizards    #
#################################################################################################
def PresentAddWalletWizard(vc : ObjCInstance = None, animated : bool = True, completion : Block = None, dontPresentJustReturnIt = False) -> ObjCInstance:
    if not vc: vc = gui.ElectrumGui.gui.get_presented_viewcontroller()
    sb = UIStoryboard.storyboardWithName_bundle_("NewWallet", None)
    if not sb:
        utils.NSLog("ERROR: SB IS NULL")
        return None
    nav = sb.instantiateViewControllerWithIdentifier_("Add_A_Wallet")
    if nav:
        if not dontPresentJustReturnIt:
            vc.presentViewController_animated_completion_(nav, animated, completion)
    else:
        utils.NSLog("ERROR: Could not find the storyboard viewcontroller named 'Add_A_Wallet'!")
    return nav

def PresentOnBoardingWizard(vc : ObjCInstance = None, animated : bool = True, completion : Block = None, dontPresentJustReturnIt = False) -> ObjCInstance:
    if not vc: vc = gui.ElectrumGui.gui.get_presented_viewcontroller()
    sb = UIStoryboard.storyboardWithName_bundle_("NewWallet", None)
    if not sb:
        utils.NSLog("ERROR: SB IS NULL")
        return None
    wiz = sb.instantiateViewControllerWithIdentifier_("On_Boarding")
    if wiz:
        if not dontPresentJustReturnIt:
            vc.presentViewController_animated_completion_(wiz, animated, completion)
    else:
        utils.NSLog("ERROR: Could not find the storyboard viewcontroller named 'On_Boarding'!")
    return wiz
#################################################################################################

class NewWalletNav(NewWalletNavBase):
    @objc_method
    def dealloc(self) -> None:
        utils.nspy_pop(self)
        send_super(__class__, self, 'dealloc')

    @objc_method
    def pushViewController_animated_(self, vc : ObjCInstance, animated : bool) -> None:
        ''' This is here as a cheap hack to translate the top nav buttons to the native language '''
        send_super(__class__, self, 'pushViewController:animated:', vc.ptr, animated, argtypes=[objc_id, c_bool])
        if vc.navigationItem:
            if vc.navigationItem.backBarButtonItem:
                vc.navigationItem.backBarButtonItem.title = _(vc.navigationItem.backBarButtonItem.title or "Back")
            if vc.navigationItem.leftBarButtonItem:
                vc.navigationItem.leftBarButtonItem.title = _(vc.navigationItem.leftBarButtonItem.title or "Cancel")


class NewWalletVC(NewWalletVCBase):
    origPlaceholders = objc_property()
    origLabelTxts = objc_property()
    origPS = objc_property()

    @objc_method
    def dealloc(self) -> None:
        # cleanup code here
        self.origPlaceholders = None
        self.origLabelTxts = None
        self.origPS = None
        send_super(__class__, self, 'dealloc')


    @objc_method
    def viewDidLoad(self) -> None:
        send_super(__class__, self, 'viewDidLoad')
        self.setupNextButtonSmartLayoutMogrificationWhenKeyboardIsShown()
        if gui.ElectrumGui.gui.is_touchid_possible():
            self.touchIdTit.setHidden_(False)
            self.touchId.setHidden_(False)
            self.touchId.setOn_animated_(True, False)
            def Blk(sw : objc_id) -> None:
                sw = ObjCInstance(sw)
                gui.ElectrumGui.gui.check_touchid_for_gui(sw.isOn())
            self.touchId.handleControlEvent_withBlock_(UIControlEventValueChanged, Blk)
        else:
            self.touchIdTit.setHidden_(True)
            self.touchId.setHidden_(True)
            self.touchId.setOn_animated_(False, False)


    @objc_method
    def setupNextButtonSmartLayoutMogrificationWhenKeyboardIsShown(self) -> None:
        origButConstant = self.nextButBotCS.constant
        origHConstant = self.errHeightCS.constant
        origErrTopConstant = self.errTopCS.constant
        self.origPS = self.errMsg.attributedText.attribute_atIndex_effectiveRange_(NSParagraphStyleAttributeName, 0, None)

        def slideUpButton(rect : CGRect) -> None:
            # slide the 'next' button up so it's above the keyboard when the keyboard is shown
            self.nextButBotCS.constant = 5 + rect.size.height
            if utils.is_ipad():
                self.nextButBotCS.constant = origButConstant + rect.size.height
            else: #if utils.is_iphone()
                # on iPhone, things get cramped when we do this.. so..
                # on keyboard show, squeeze the layout (this includes the error message text line spacing)
                self.nextButBotCS.constant = 5 + rect.size.height
                self.errHeightCS.constant = origHConstant / 2.0
                self.errTopCS.constant = 10
                ats = NSMutableAttributedString.alloc().initWithAttributedString_(self.errMsg.attributedText).autorelease()
                ps = NSMutableParagraphStyle.new().autorelease()
                ps.setParagraphStyle_(self.origPS)
                ps.maximumLineHeight = 17.0
                ps.minimumLineHeight = 17.0
                ats.removeAttribute_range_(NSParagraphStyleAttributeName, NSRange(0, ats.length()))
                ats.addAttribute_value_range_(NSParagraphStyleAttributeName, ps, NSRange(0, ats.length()))
                self.errMsg.attributedText = ats
            self.view.layoutIfNeeded()
        def slideDownButton() -> None:
            # when keyboard hides, undo the damage done above
            self.nextButBotCS.constant = origButConstant
            if utils.is_iphone():
                self.errHeightCS.constant = origHConstant
                self.errTopCS.constant = origErrTopConstant
                ats = NSMutableAttributedString.alloc().initWithAttributedString_(self.errMsg.attributedText).autorelease()
                ats.removeAttribute_range_(NSParagraphStyleAttributeName, NSRange(0, ats.length()))
                ats.addAttribute_value_range_(NSParagraphStyleAttributeName, self.origPS, NSRange(0, ats.length()))
                self.errMsg.attributedText = ats
            self.view.layoutIfNeeded()

        # NB: this cleans itself up automatically due to objc associated object magic on self.view's deallocation
        utils.register_keyboard_callbacks(self.view, onWillShow=slideUpButton, onWillHide=slideDownButton)

    @objc_method
    def translateUI(self) -> None:
        self.title = _("Standard Wallet")

        for state in UIControlState_ALL_RELEVANT_TUPLE:
            self.nextBut.setTitle_forState_(_("Next"), state)

        lbls = [ self.walletNameTit, self.walletPw1Tit, self.walletPw2Tit, self.touchIdTit ]
        if not self.origLabelTxts:
            self.origLabelTxts = { lbl.ptr.value : lbl.text for lbl in lbls }
        d = self.origLabelTxts
        for lbl in lbls:
            lbl.setText_withKerning_(_(d[lbl.ptr.value]), utils._kern)

        tfs = [ self.walletName, self.walletPw1, self.walletPw2 ]
        if not self.origPlaceholders:
            self.origPlaceholders = { tf.ptr.value : tf.placeholder for tf in tfs }
        d = self.origPlaceholders
        for tf in tfs:
            tf.placeholder = _(d[tf.ptr.value])
            utils.uitf_redo_attrs(tf)
        if self.showHidePWBut:
            self.showHidePWBut.setTitle_forState_(" " + _("Show"), UIControlStateNormal)
            self.showHidePWBut.setTitle_forState_(" " + _("Show"), UIControlStateSelected)

    @objc_method
    def viewWillAppear_(self, animated : bool) -> None:
        send_super(__class__, self, 'viewWillAppear:', animated, argtypes=[c_bool])
        self.translateUI()

    @objc_method
    def viewWillDisappear_(self, animated : bool) -> None:
        send_super(__class__, self, 'viewWillDisappear:', animated, argtypes=[c_bool])
        self.view.endEditing_(True)


    @objc_method
    def textFieldShouldReturn_(self, tf) -> bool:
        tf.resignFirstResponder()
        return True

    @objc_method
    def textField_shouldChangeCharactersInRange_replacementString_(self, tf, r : NSRange, s : ObjCInstance) -> bool:
        if not self.errMsgView.isHidden():
            # hide the error message when they start typing
            self.errMsgView.setHidden_(True)
            self.touchIdView.setHidden_(not self.errMsgView.isHidden())
        return True

    @objc_method
    def textFieldDidEndEditing_(self, tf : ObjCInstance) -> None:
        if tf.ptr == self.walletName.ptr:
            tf.text = utils.pathsafeify(tf.text)[:30]
        utils.uitf_redo_attrs(tf)

    @objc_method
    def textFieldDidBeginEditing_(self, tf : ObjCInstance) -> None:
        pass

    @objc_method
    def toggleShowHidePW(self) -> None:
        sel = not self.showHidePWBut.isSelected()
        self.showHidePWBut.setSelected_(sel)
        self.walletPw1.setSecureTextEntry_(not sel)
        self.walletPw2.setSecureTextEntry_(not sel)

    @objc_method
    def doChkFormOk(self) -> bool:
        self.walletName.text = utils.pathsafeify(self.walletName.text)
        errMsg = ''
        if not self.walletName.text:
            errMsg = _("Wallet name is empty. Please enter a wallet name to proceed.")
        elif gui.ElectrumGui.gui.check_wallet_exists(self.walletName.text):
            errMsg = _("A wallet with that name already exists. Please enter a different wallet name to proceed.")
        elif not self.noPWCheck and not self.walletPw1.text:
            errMsg = _("Wallet password is empty. Please set a wallet password to proceed. You can disable wallet password protection later if you wish.")
        elif not self.noPWCheck and self.walletPw1.text != self.walletPw2.text:
            errMsg = _("Wallet passwords do not match. Please confirm the password you wish to set for your wallet by entering the same password twice.")

        if errMsg:
            utils.uilabel_replace_attributed_text(self.errMsg, errMsg, font = UIFont.italicSystemFontOfSize_(14.0))
        self.errMsgView.setHidden_(not errMsg)
        self.touchIdView.setHidden_(not self.errMsgView.isHidden())
        return not errMsg

    @objc_method
    def shouldPerformSegueWithIdentifier_sender_(self, identifier, sender) -> bool:
        # check passwords match, wallet name is unique
        return self.doChkFormOk()

    @objc_method
    def saveVars(self) -> None:
        _SetParam(self, 'WalletName', self.walletName.text)
        _SetParam(self, 'WalletPass', self.walletPw2.text)
        _SetParam(self, 'UseTouchID', bool((not self.touchId.isHidden()) and self.touchId.isOn()) )

    @objc_method
    def prepareForSegue_sender_(self, segue, sender) -> None:
        # pass along wallet name, password, etc..
        self.saveVars()

class NewWalletVCAtEnd(NewWalletVC):
    @objc_method
    def translateUI(self) -> None:
        send_super(__class__, self, 'translateUI')
        self.title = _("Save Wallet")
        for state in UIControlState_ALL_RELEVANT_TUPLE:
            self.nextBut.setTitle_forState_(_("Save"), state)


class NewWalletSeed1(NewWalletSeedBase):
    origLabelTxts = objc_property()
    seed = objc_property()

    @objc_method
    def dealloc(self) -> None:
        # cleanup code here
        self.origLabelTxts = None
        self.seed = None
        send_super(__class__, self, 'dealloc')

    @objc_method
    def viewDidLoad(self) -> None:
        send_super(__class__, self, 'viewDidLoad')
        utils.uilabel_replace_attributed_text(self.seedtv, " ", font = UIFont.systemFontOfSize_weight_(16.0, UIFontWeightBold))

    @objc_method
    def translateUI(self) -> None:
        self.title = _("Seed")
        for state in UIControlState_ALL_RELEVANT_TUPLE:
            self.nextBut.setTitle_forState_(_("Next"), state)
        lbls = [ self.seedTit, self.info ]
        if not self.origLabelTxts:
            self.origLabelTxts = { lbl.ptr.value : lbl.text for lbl in lbls }
        d = self.origLabelTxts
        for lbl in lbls:
            if lbl.ptr == self.info.ptr:
                utils.uilabel_replace_attributed_text(lbl, _(d[lbl.ptr.value]), font=UIFont.italicSystemFontOfSize_(14.0))
            else:
                lbl.setText_withKerning_(_(d[lbl.ptr.value]), utils._kern)

    @objc_method
    def viewWillAppear_(self, animated : bool) -> None:
        send_super(__class__, self, 'viewWillAppear:', animated, argtypes=[c_bool])
        self.translateUI()
        self.infoView.setHidden_(True)

    @objc_method
    def viewDidAppear_(self, animated : bool) -> None:
        send_super(__class__, self, 'viewDidAppear:', animated, argtypes=[c_bool])
        if not self.seed:
            self.infoView.setHidden_(True)
            def GenSeed() -> str:
                return _Mnem().make_seed()
            def OnError(exc) -> None:
                def onOk() -> None:
                    self.presentingViewController.dismissViewControllerAnimated_completion_(True, None)
                gui.ElectrumGui.gui.show_error(str(exc[1]), onOk = onOk, vc = self)
            def OnSuccess(result : str) -> None:
                self.infoView.setHidden_(False)
                self.seed = result
                utils.uilabel_replace_attributed_text(self.seedtv, self.seed)
            utils.WaitingDialog(self, _("Generating seed..."), GenSeed,  OnSuccess, OnError)
        else:
            self.infoView.setHidden_(False)
            utils.uilabel_replace_attributed_text(self.seedtv, self.seed)

    @objc_method
    def shouldPerformSegueWithIdentifier_sender_(self, identifier, sender) -> bool:
        return bool(self.seed)


    @objc_method
    def prepareForSegue_sender_(self, segue, sender) -> None:
        # pass along wallet seed
        s = py_from_ns(self.seed)
        sl = py_from_ns(self.seed).split()
        _SetParam(self, 'seed', s)
        _SetParam(self, 'seed_list', sl)
        print("FYI -- the seed is: ", s)
        if isinstance(segue.destinationViewController, NewWalletSeed2):
            segue.destinationViewController.seed = s
            segue.destinationViewController.seedList = sl
        #print("params=",_Params(self))

class NewWalletSeed2(NewWalletSeedBase):
    origLabelTxts = objc_property()
    seed = objc_property()
    seedList = objc_property()
    sugButs = objc_property()
    isDone = objc_property()
    restoreMode = objc_property()

    @objc_method
    def dealloc(self) -> None:
        # cleanup code here
        self.origLabelTxts = None
        self.seed = None
        self.seedList = None
        self.sugButs = None
        self.isDone = None
        self.restoreMode = None
        send_super(__class__, self, 'dealloc')

    @objc_method
    def viewDidLoad(self) -> None:
        send_super(__class__, self, 'viewDidLoad')
        self.sugButs = list()
        utils.uilabel_replace_attributed_text(self.seedtv, " ", font = UIFont.systemFontOfSize_weight_(16.0, UIFontWeightBold))
        self.seedtv.text = '' # now clear it again..
        if not self.kvc:
            vcs = self.childViewControllers
            for vc in vcs:
                if isinstance(vc, KeyboardVC):
                    self.kvc = vc
                    break
        if self.kvc:
            self.kvc.textInput = self.seedtv
            def callback() -> None: self.doSuggestions()
            self.kvc.textChanged = Block(callback)
            if self.kvcHeightCS and utils.is_iphone5():
                self.kvcHeightCS.constant = self.kvcHeightCS.constant - 70.0

        else:
            utils.NSLog("ERROR: NewWalletSeed2 cannot find the KeyboardVC! FIXME!")

    @objc_method
    def translateUI(self) -> None:
        self.title = _("Seed Entry")
        for state in UIControlState_ALL_RELEVANT_TUPLE:
            self.nextBut.setTitle_forState_(_("Next"), state)
        lbls = [ self.seedTit, self.info ]
        if self.seedExtTit: lbls.append(self.seedExtTit)
        if self.bip39Tit: lbls.append(self.bip39Tit)
        if not self.origLabelTxts:
            self.origLabelTxts = { lbl.ptr.value : lbl.text for lbl in lbls }
        d = self.origLabelTxts
        for lbl in lbls:
            if lbl.ptr == self.info.ptr:
                if not self.restoreMode:
                    txt = _('Your seed is important!') + ' ' + _('To make sure that you have properly saved your seed, please retype it here.') + ' ' + _('Use the quick suggestions to save time.')
                else:
                    txt = _('You can restore a wallet that was created by any version of Electron Cash.')
                utils.uilabel_replace_attributed_text(lbl, txt, font=UIFont.italicSystemFontOfSize_(14.0))
            else:
                lbl.setText_withKerning_(_(d[lbl.ptr.value]), utils._kern)

    @objc_method
    def viewWillAppear_(self, animated : bool) -> None:
        send_super(__class__, self, 'viewWillAppear:', animated, argtypes=[c_bool])
        self.translateUI()
        if not self.bip39 or not self.bip39.isOn():
            self.doSuggestions()

    @objc_method
    def viewDidAppear_(self, animated : bool) -> None:
        send_super(__class__, self, 'viewDidAppear:', animated, argtypes=[c_bool])
        if not self.bip39 or not self.bip39.isOn():
            self.seedtv.becomeFirstResponder()

    @objc_method
    def clearSugButs(self) -> None:
        # next, do suggestion buttons
        sugButs = py_from_ns(self.sugButs)
        for but in sugButs:
            but.removeFromSuperview()
        self.sugButs = list()


    @objc_method
    def doSuggestions(self) -> None:
        t = str(self.seedtv.text).lower()
        prefix = ''
        words = t.split()
        wordNum = len(words)
        if t and t[-1] != ' ':
            wordNum = wordNum - 1
            prefix = words[-1]

        suggestions = list(set(_Mnem().get_suggestions(prefix)) | _GetOldSuggestions(prefix))
        #print("wordnum=",wordNum,"prefix=","'"+prefix+"'","suggestions:",*suggestions)

        self.kvc.disableAllKeys()
        self.kvc.setKey_enabled_(self.kvc.backspace, True)
        validchars = set()
        for sug in suggestions:
            l = len(prefix)
            if len(sug) > l:
                validchars.add(sug[l].upper())
        for c in validchars:
            self.kvc.setKey_enabled_(c, True)

        # next, do suggestion buttons
        self.clearSugButs()
        sugButs = list()
        self.sugButs = list()

        currActualSeedWord = ''
        if not self.restoreMode:
            try:
                currActualSeedWord = self.seedList[wordNum]
            except:
                utils.NSLog("Error with seed word: %s",sys.exc_info()[1])
                currActualSeedWord = 'TOO MANY WORDS!' # this makes sure we continue even though they have too many words.

        #print("currActualSeedWord=",currActualSeedWord)

        if len(suggestions) < 10:
            import random
            sugSet = set()
            if currActualSeedWord in suggestions:
                sugSet.add(currActualSeedWord)
            elif prefix in suggestions: # this fixes issue #4
                sugSet.add(prefix)
            while len(sugSet) < len(suggestions) and len(sugSet) < 4:
                sugSet.add(suggestions[random.randint(0,len(suggestions)-1)])
            #print("sugSet=",*sugSet if sugSet else '')
            for sug in sugSet:
                def AddButWord(but : objc_id) -> None:
                    but = ObjCInstance(but)
                    word = but.titleForState_(UIControlStateNormal)
                    try:
                        self.seedtv.setText_((' '.join(words[:wordNum]) + (' ' if wordNum else '') + word + ' ').lower())
                    except:
                        utils.NSLog("Could not set textView: %s",sys.exc_info()[1])
                    self.doSuggestions()
                but = SuggestionButton.suggestionButtonWithText_handler_(sug, AddButWord)
                sugButs.append(but)

            # lay out buttons
            nButs = len(sugButs)
            if nButs:
                marg = 15.0
                pad = 5.0
                kvcY = self.kvcContainerView.frame.origin.y
                fw = self.view.frame.size.width
                insetWidth = fw - marg*2.0
                totalPad = pad * (nButs-1)
                w = min( (insetWidth - totalPad)/nButs, 200.0 )
                posX = (fw - (w*nButs + totalPad))/2.0
                for but in sugButs:
                    f = but.frame
                    f.size.width = w
                    f.origin.x = posX
                    posX += w + pad
                    f.origin.y = kvcY - f.size.height - marg
                    but.frame = f
                    self.view.addSubview_(but)

        self.sugButs = sugButs

        self.errMsgView.setHidden_(True)
        self.infoView.setHidden_(False)

    @objc_method
    def viewWillTransitionToSize_withTransitionCoordinator_(self, size : CGSize, coordinator : ObjCInstance) -> None:
        send_super(__class__, self, 'viewWillTransitionToSize:withTransitionCoordinator:', size, coordinator, argtypes=[CGSize,objc_id])
        # hack to handle rotaton correctly by laying out the buttons all over again
        def layoutButtons() -> None:
            self.doSuggestions()
            self.autorelease()
        if list(self.sugButs):
            self.retain()
            utils.call_later(0.400, layoutButtons)

    @objc_method
    def shouldPerformSegueWithIdentifier_sender_(self, identifier, sender) -> bool:
        if identifier in ('EMBEDDED_KVC'): return True
        return False

    @objc_method
    def onNext(self) -> None:
        ''' only calld from IB connections if not in restoreMode! '''

        if self.isDone:
            _DoDismiss(vc=self)
            return

        if list(self.seedList) != self.seedtv.text.strip().lower().split():
            err = _('The seed you entered does not match the generated seed. Go back to the previous screen and double-check it, then try again.')
            utils.uilabel_replace_attributed_text(self.errMsg, err, font=UIFont.italicSystemFontOfSize_(14.0))
            self.errMsgView.setHidden_(False)
            self.infoView.setHidden_(True)
            return

        try:
            wallet_name = _Params(self)['WalletName']
            wallet_pass = _Params(self)['WalletPass']
            wallet_seed = _Params(self)['seed']
            wants_touchid = _Params(self).get('UseTouchID', False)
        except:
            utils.NSLog("onNext in Seed2, got exception: %s", str(sys.exc_info()[1]))
            _ToErrIsHuman(self)
            return

        def Completion() -> None:
            self.isDone = True

        _WizardGenerateNewWallet(
            vc = self, completion = Completion,
            wallet_name = wallet_name,
            wallet_pass = wallet_pass,
            wallet_seed = wallet_seed,
            wants_touchid = wants_touchid)


    def prepareForSegue_sender_(self, segue, sender) -> None:
        #print("params=",_Params(self))
        pass

class RestoreWallet1(NewWalletSeed2):
    tvdel = objc_property()

    @objc_method
    def dealloc(self) -> None:
        self.tvdel = None
        send_super(__class__, self, 'dealloc')

    @objc_method
    def viewDidLoad(self) -> None:
        self.restoreMode = True
        self.seedTit.text = _('Enter your seed phrase') # override the text title to be appropriate to this screen

        def onBip39(b : objc_id) -> None:
            sw = ObjCInstance(b)
            if not sw.isOn():
                if self.tvdel:
                    self.tvdel.tv = None
                    self.tvdel = None
                self.seedtv.inputView = None
                self.seedtv.inputAccessoryView = None
                self.view.endEditing_(True)
                self.kvcContainerView.setHidden_(False)
                self.seedtv.selectedRange = NSRange(len(self.seedtv.text) if self.seedtv.text else 0, 0);
                self.kvc.textInput = self.seedtv
                utils.call_later(0.2, lambda:(self.seedtv.becomeFirstResponder(),self.doSuggestions()))
            else:
                self.clearSugButs()
                self.kvc.textInput = None
                self.seedtv.delegate = None
                self.seedtv.inputView = None
                self.kvcContainerView.setHidden_(True)
                self.view.endEditing_(True)
                self.tvdel = ECTextViewDelegate.new().autorelease()
                self.tvdel.tv = self.seedtv
                def undoErrMsgs() -> None:
                    self.errMsgView.setHidden_(True)
                    self.infoView.setHidden_(False)
                self.tvdel.didChange = undoErrMsgs
                utils.call_later(0.2, lambda:self.seedtv.becomeFirstResponder())
        self.bip39.handleControlEvent_withBlock_(UIControlEventPrimaryActionTriggered,onBip39)
        send_super(__class__, self, 'viewDidLoad')
        if self.kvc:
            self.kvc.blockPasting = False
            self.kvc.blockSelecting = False

    @objc_method
    def textFieldDidBeginEditing_(self, tf) -> None:
        if tf.ptr.value == self.seedExt.ptr.value:
            self.clearSugButs()
            self.kvcContainerView.setHidden_(True)
    @objc_method
    def textFieldDidEndEditing_(self, tf) -> None:
        if tf.ptr.value == self.seedExt.ptr.value:
            self.kvcContainerView.setHidden_(False or self.bip39.isOn())
    @objc_method
    def textFieldShouldReturn_(self, tf) -> None:
        if tf.ptr.value == self.seedExt.ptr.value:
            tf.resignFirstResponder()
            if not self.bip39.isOn():
                utils.call_later(0.2, lambda:self.seedtv.becomeFirstResponder())
            return True
        return False

    @objc_method
    def onNext(self) -> None:
        seed = ' '.join(self.seedtv.text.strip().split())
        is_bip39 = self.bip39.isOn()
        if not is_bip39: seed = seed.lower()

        if not seed or (not is_bip39 and not mnemonic.is_seed(seed)):
            err = _('The seed you entered does not appear to be a valid wallet seed.')
            utils.uilabel_replace_attributed_text(self.errMsg, err, font=UIFont.italicSystemFontOfSize_(14.0))
            self.errMsgView.setHidden_(False)
            self.infoView.setHidden_(True)
            return

        seedext = self.seedExt.text.strip() if self.seedExt.text else ''
        seed_type = 'bip39' if is_bip39 else mnemonic.seed_type_name(seed)
        print("seed type:", seed_type)

        def PushIt() -> None:
            _SetParam(self, 'seed', seed)
            _SetParam(self, 'seedext', seedext)
            _SetParam(self, 'is_bip39', is_bip39)
            _SetParam(self, 'seed_type', seed_type)
            _SetParam(self, 'wallet_type', 'standard')
            #print("params =", _Params(self))
            sb = UIStoryboard.storyboardWithName_bundle_("NewWallet", None)
            vc = sb.instantiateViewControllerWithIdentifier_("RESTORE_SEED_2")
            self.navigationController.pushViewController_animated_(vc, True)

        def ToErrIsHuman(title = "Oops!", message = "Something went wrong! Please email the developers!", onOk = None) -> None:
            gui.ElectrumGui.gui.show_error(vc = self, title = title, message = message, onOk = onOk)


        if seed_type == 'bip39':
            # do bip39 stuff
            default_derivation = keystore.bip44_derivation_145(0)
            test=bitcoin.is_bip32_derivation
            def onOk(text : str) -> None:
                der = text.strip()
                derOk = test(der)
                print('der=',der,'test results=',derOk)
                if not derOk:
                    ToErrIsHuman(title = _('Derivation Invalid'), message = _('It appears the derivation you specified is invalid. Please try again'), onOk=lambda:self.onNext())
                    return
                if self.doBip44Keystore(seed, seedext, der):
                    PushIt()
                else:
                    ToErrIsHuman() # NB: we may already have an alert up from called code above, in which case this is a no-op (hacky but works!)
            alert = utils.show_tf_alert(vc = self,
                                        title=_('Derivation'),
                                        message = ' '.join([_('Enter your wallet derivation here.'),
                                                             _('If you are not sure what this is, leave this field unchanged.'),
                                                             _("If you want the wallet to use legacy Bitcoin addresses use m/44'/0'/0'"),
                                                             _("If you want the wallet to use Bitcoin Cash addresses use m/44'/145'/0'")]),
                                        onOk = onOk, placeholder = _('Derivation') + '...', text = default_derivation
                                        )
        elif seed_type == 'old':
            print("old seed type")
            if self.doStandardKeystore(seed, ''):
                PushIt()
            else:
                ToErrIsHuman() # NB: we may already have an alert up from called code above, in which case this is a no-op (hacky but works!)

        elif seed_type in ('standard', 'electrum'):
            print("standard seed type")
            if self.doStandardKeystore(seed, seedext):
                PushIt()
            else:
                ToErrIsHuman() # NB: we may already have an alert up from called code above, in which case this is a no-op (hacky but works!)
        else:
            ToErrIsHuman()
            return

    @objc_method
    def doBip44Keystore(self, seed, passphrase, derivation) -> bool:
        seed, passphrase, derivation = py_from_ns(seed), py_from_ns(passphrase), py_from_ns(derivation)
        try:
            k = keystore.from_seed(seed, passphrase, derivation=derivation, seed_type='bip39')
            return _AddKeystore(self, k)
        except:
            utils.NSLog("Exception in doBip44Keystore: %s",sys.exc_info()[1])
        return False

    @objc_method
    def doStandardKeystore(self, seed, passphrase) -> bool:
        seed, passphrase = py_from_ns(seed), py_from_ns(passphrase)
        try:
            # not specifying a seed_type below triggers auto-detect, with
            # preference order: old, electrum, bip39
            k = keystore.from_seed(seed, passphrase)
            return _AddKeystore(self, k)
        except:
            utils.NSLog("Exception in doStandardKeystore: %s",sys.exc_info()[1])
        return False

def _AddKeystore(vc, k) -> bool:
    has_xpub = isinstance(k, keystore.Xpub)
    if has_xpub:
        t1 = bitcoin.xpub_type(k.xpub)
        if t1 not in ['standard']:
            gui.ElectrumGui.gui.show_error(message = _('Wrong key type') + ": '%s'"%t1, vc=vc)
            return False
    keystores = _Params(vc).get('keystores', list())
    keystores.append(k)
    _SetParam(vc, 'keystores', keystores)
    return True

class RestoreWallet2(NewWalletVCAtEnd):

    @objc_method
    def onRestoreModeSave(self) -> None:
        self.view.endEditing_(True)
        if self.doChkFormOk():
            self.saveVars()
            #print("params =",_Params(self))
            try:
                # create wallet, etc...
                wallet_name = _Params(self)['WalletName']
                wallet_pass = _Params(self)['WalletPass']
                seed = _Params(self)['seed']
                ks = _Params(self)['keystores'][0]
                seedext = _Params(self)['seedext']
                is_bip39 = _Params(self)['is_bip39']
                seed_type = _Params(self)['seed_type']
                wants_touchid = _Params(self).get('UseTouchID', False)

            except:
                utils.NSLog("onRestoreModeSave, got exception: %s", str(sys.exc_info()[1]))
                return

            _WizardGenerateNewWallet(
                vc = self,
                wallet_name = wallet_name,
                wallet_pass = wallet_pass,
                wallet_seed = seed,
                seed_ext = seedext,
                seed_type = seed_type,
                have_keystore = ks,
                wants_touchid = wants_touchid)


class NewWalletMenu(NewWalletMenuBase):
    lineHider = objc_property()
    noCancelBut = objc_property()

    @objc_method
    def dealloc(self) -> None:
        self.lineHider = None
        self.noCancelBut = None
        send_super(__class__, self, 'dealloc')

    @objc_method
    def viewDidLoad(self) -> None:
        send_super(__class__, self, 'viewDidLoad')
        if self.navigationItem:
            if self.navigationItem.leftBarButtonItem:
                self.navigationItem.leftBarButtonItem.title = _(self.navigationItem.leftBarButtonItem.title)
            if self.navigationItem.backBarButtonItem:
                self.navigationItem.backBarButtonItem.title = _(self.navigationItem.backBarButtonItem.title)

    @objc_method
    def viewWillAppear_(self, animated : bool) -> None:
        send_super(__class__, self, 'viewWillAppear:', animated, argtypes=[c_bool])
        _SetParams(self, dict()) # clear any params that may be present if they were forward then back again as they may pick a different path down the wizard tree

        if self.noCancelBut:
            self.navigationItem.leftBarButtonItem = None
            self.noCancelBut = None
        navBar = self.navigationController.navigationBar if self.navigationController else None
        if navBar:
            f = navBar.frame
            # This line hider is a hack/fix for a weirdness in iOS where there is a white line between the top nav bar and the bottom
            # main area.  This hopefully fixes that.
            self.lineHider = UIView.alloc().initWithFrame_(CGRectMake(0,f.size.height,f.size.width,1)).autorelease()
            self.lineHider.backgroundColor = navBar.barTintColor
            self.lineHider.autoresizingMask = (1<<6)-1
            navBar.addSubview_(self.lineHider)
        # translate UI
        self.navigationItem.title = _("New Wallet")
        utils.uilabel_replace_attributed_text(lbl = self.blurb,
                                              text = _("You can have as many wallets as you like! Choose from one of the options below:"),
                                              template = self.blurb.attributedText)
        for state in UIControlState_ALL_RELEVANT_TUPLE:
            self.std.setTitle_forState_(_("Create New Standard Wallet"), state)
            self.restore.setTitle_forState_(_("Restore from Seed"), state)
            self.imp.setTitle_forState_(_("Import Addresses or Private Keys"), state)
            self.master.setTitle_forState_(_("Use a Master Key"), state)

    @objc_method
    def viewWillDisappear_(self, animated : bool) -> None:
        send_super(__class__, self, 'viewWillDisappear:', animated, argtypes=[c_bool])
        if self.lineHider:
            self.lineHider.removeFromSuperview()
            self.lineHider = None

class Import1(Import1Base):

    @objc_method
    def viewDidLoad(self) -> None:
        send_super(__class__, self, 'viewDidLoad')
        for state in UIControlState_ALL_RELEVANT_TUPLE:
            self.nextBut.setTitle_forState_(_("Next"), state)
        self.tvDel.placeholderText = _("Tap to add text...")
        self.tvDel.placeholderFont = UIFont.italicSystemFontOfSize_(14.0)
        self.tvDel.font = UIFont.systemFontOfSize_weight_(14.0, UIFontWeightMedium)
        self.tvDel.paragraphStyle = self.tv.attributedText.attribute_atIndex_effectiveRange_(NSParagraphStyleAttributeName, 0, None)
        self.tvDel.tv = self.tv
        self.tvDel.text = ""
        def hideErrBox() -> None:
            if not self.errMsgView.isHidden():
                self.errMsgView.setHidden_(True)
                self.infoView.setHidden_(False)
        self.tvDel.didChange = Block(hideErrBox)
        if self.masterKeyMode:
            self.title = _("Master Key")
            titText = _("Create a wallet using a Master Key")
            infoText =  (_("Specify a master key to re-create a deterministic wallet.")
                         + " " + _("To create a watching-only wallet, please enter your master public key (xpub/ypub/zpub).")
                         + " " + _("To create a spending wallet, please enter a master private key (xprv/yprv/zprv).") )

        else:
            self.title = _("Import")
            titText = _("Import Bitcoin Cash Addresses or Private Keys")
            infoText = _("Enter a list of private keys to create a regular spending wallet. " +
                         "Alternatively, you can create a 'watching-only' wallet by " +
                         "entering a list of Bitcoin Cash addresses.")
        self.tit.setText_withKerning_(titText, utils._kern)
        utils.uilabel_replace_attributed_text(lbl=self.info, font = UIFont.italicSystemFontOfSize_(14.0),
                                              text = infoText)
        utils.uilabel_replace_attributed_text(lbl=self.errMsg, font = UIFont.italicSystemFontOfSize_(14.0), text = " ")

        self.setupNextButtonSmartLayoutMogrificationWhenKeyboardIsShown()

    @objc_method
    def setupNextButtonSmartLayoutMogrificationWhenKeyboardIsShown(self) -> None:
        origButConstant = self.nextButBotCS.constant

        def slideUpButton(rect : CGRect) -> None:
            # slide the 'next' button up so it's above the keyboard when the keyboard is shown
            self.nextButBotCS.constant = origButConstant + rect.size.height
            self.view.layoutIfNeeded()
        def slideDownButton() -> None:
            # when keyboard hides, undo the damage done above
            self.nextButBotCS.constant = origButConstant
            self.view.layoutIfNeeded()

        # NB: this cleans itself up automatically due to objc associated object magic on self.view's deallocation
        utils.register_keyboard_callbacks(self.view, onWillShow=slideUpButton, onWillHide=slideDownButton)

    @objc_method
    def onQRBut(self) -> None:
        #print("On QR...")
        if not QRCodeReader.isAvailable:
            utils.show_alert(self, _("QR Not Available"), _("The camera is not available for reading QR codes"))
        else:
            self.view.endEditing_(True)
            self.qr = QRCodeReader.new().autorelease()
            self.qrvc = QRCodeReaderViewController.readerWithCancelButtonTitle_codeReader_startScanningAtLoad_showSwitchCameraButton_showTorchButton_("Cancel",self.qr,True,False,False)
            self.qrvc.modalPresentationStyle = UIModalPresentationFormSheet
            self.qrvc.delegate = self
            self.presentViewController_animated_completion_(self.qrvc, True, None)

    @objc_method
    def reader_didScanResult_(self, reader, result) -> None:
        utils.NSLog("Reader data = '%s'",str(result))
        reader.stopScanning()
        if not self.masterKeyMode:
            from .contacts import cleanup_address_remove_colon
            result = cleanup_address_remove_colon(result)
            self.tvDel.text = str(self.tvDel.text).strip() + " " + result # append in this mode
        else:
            self.tvDel.text = result.strip() # overwrite in this mode
        self.readerDidCancel_(reader) # just close it once we get data

    @objc_method
    def readerDidCancel_(self, reader) -> None:
        if reader is not None: reader.stopScanning()
        self.dismissViewControllerAnimated_completion_(True, None)
        self.qr = None
        self.qrvc = None

    @objc_method
    def words(self) -> ObjCInstance:
        return ns_from_py(str(self.tvDel.text).split())

    @objc_method
    def doChkFormOk(self) -> bool:
        def ErrMsg(msg):
            utils.uilabel_replace_attributed_text(self.errMsg, msg)
            self.infoView.setHidden_(True)
            self.errMsgView.setHidden_(False)
        def ClearErrMsg():
            self.infoView.setHidden_(False)
            self.errMsgView.setHidden_(True)

        words = py_from_ns(self.words())
        if self.masterKeyMode:
            if len(words) > 1:
                ErrMsg(_("You appear to have entered more than one item. Each wallet can only have a single master key. To use multiple master keys, create a new wallet for each key."))
            elif not words:
                ErrMsg(_("Please specify a master key to continue. Valid keys are long strings starting with either xpub/ypub/zpub or xprv/yprv/zprv."))
            elif keystore.is_master_key(words[0]):
                ClearErrMsg()
                return True
            else:
                ErrMsg(_("The provided key does not appear to be a valid master key. Valid keys are long strings starting with either xpub/ypub/zpub or xprv/yprv/zprv. Please try again."))
        else:
            for w in words:
                if Address.is_valid(w) or bitcoin.is_private_key(w):
                    ClearErrMsg()
                    return True
            ErrMsg( _("You appear to have entered no valid Bitcoin Cash addresses or private keys.") )
        return False

    @objc_method
    def shouldPerformSegueWithIdentifier_sender_(self, identifier, sender) -> bool:
        # checks here that form is ok, etc
        self.view.endEditing_(True)
        return self.doChkFormOk()

    @objc_method
    def prepareForSegue_sender_(self, segue, sender) -> None:
        words = py_from_ns(self.words())
        if self.masterKeyMode:
            k = keystore.from_master_key(words[0])
            _SetParam(self, 'keystore', k)
        else:
            _SetParam(self, 'words', words)

class Import2(Import2Base):
    @objc_method
    def dealloc(self) -> None:
        utils.nspy_pop(self)
        send_super(__class__, self, 'dealloc')

    @objc_method
    def viewDidLoad(self) -> None:
        send_super(__class__, self, 'viewDidLoad')
        if self.title:
            self.title = _(self.title)
        for state in UIControlState_ALL_RELEVANT_TUPLE:
            self.nextBut.setTitle_forState_(_("Import"), state)
        utils.uilabel_replace_attributed_text(lbl=self.info, font = UIFont.italicSystemFontOfSize_(14.0),
                                              text = _("..."))
        utils.uilabel_replace_attributed_text(lbl=self.errMsg, font = UIFont.italicSystemFontOfSize_(14.0), text = "...")
        ats = NSMutableAttributedString.alloc().initWithAttributedString_(self.errMsg.attributedText).autorelease()
        ats.addAttribute_value_range_(NSKernAttributeName, utils._kern, NSRange(0, ats.length())) # make error msg be kerned a bit more to fit better
        self.errMsg.attributedText = ats

        if self.masterKeyMode:
            self.items = list()
        else:
            self.items = _Params(self).get('words', list())

        uinib = UINib.nibWithNibName_bundle_("ImportCell", None)
        self.tv.registerNib_forCellReuseIdentifier_(uinib, "ImportCell")

        ## Bar button item is optional in future but so far in the views we're using it's always there
        bb = self.navigationItem.rightBarButtonItem
        if bb:
            from .addresses import _GetBBTitle
            bb.possibleTitles = NSSet.setWithArray_(_GetBBTitle('*'))
            d = { NSFontAttributeName : UIFont.systemFontOfSize_weight_(14.0, UIFontWeightRegular) }
            bb.setTitleTextAttributes_forState_(d, UIControlStateNormal)
            d[NSFontAttributeName] = UIFont.systemFontOfSize_weight_(14.0, UIFontWeightRegular)
            bb.setTitleTextAttributes_forState_(d, UIControlStateHighlighted)
            bb.title = _GetBBTitle()

    @objc_method
    def viewWillAppear_(self, animated : bool) -> None:
        send_super(__class__, self, 'viewWillAppear:', animated, argtypes = [c_bool])
        self.refresh()

    @objc_method
    def viewDidAppear_(self, animated : bool) -> None:
        send_super(__class__, self, 'viewDidAppear:', animated, argtypes = [c_bool])
        if self.masterKeyMode and not self.items:
            k = _Params(self).get('keystore', None)
            if not k:
                utils.NSLog("Import2.viewDidAppear_: Oops! Can't find keystore in params! This shouldn't happen...")
                _ToErrIsHuman(self)
                return
            # pop up a waiting dialog here and generate some addresses to display...
            def Get20Addys() -> list():
                ret = list()
                for i in range(0,20):
                    addr = Address.from_pubkey(k.derive_pubkey(0, i))
                    ret.append(addr.to_ui_string())
                return ret
            def Err(excinf):
                utils.NSLog("Something went wrong! Got an exception when deriving addresses in Import2.viewDidAppear_: %s", str(excinf[1]))
                _ToErrIsHuman(self)
            def Success(l : list) -> None:
                self.items = l
                self.refresh()
            utils.WaitingDialog(vc = self, message = _("Deriving addresses..."), task=Get20Addys, on_success=Success, on_error=Err)

    @objc_method
    def toggleAddressFormat(self) -> None:
        bb = self.navigationItem.rightBarButtonItem
        if bb:
            from .addresses import _GetBBTitle
            gui.ElectrumGui.gui.toggle_cashaddr(not gui.ElectrumGui.gui.prefs_get_use_cashaddr())
            bb.title = _GetBBTitle()
            newitems = list()
            for it in self.items:
                if Address.is_valid(it):
                    it = Address.from_string(it).to_ui_string()
                newitems.append(it)
            self.items = newitems
            self.refresh()


    @objc_method
    def refresh(self) -> None:
        self.tv.reloadData()
        self.doChkFormOk()

    #### UITableView delegate/dataSource methods...
    @objc_method
    def numberOfSectionsInTableView_(self, tableView) -> int:
        return 1

    @objc_method
    def tableView_numberOfRowsInSection_(self, tableView, section : int) -> int:
        try:
            items = py_from_ns(self.items)
            return len(items) if items else 0
        except Exception as e:
            utils.NSLog("Error, exception retrieving items: %s",str(e))
            return 0

    @objc_method
    def tableView_cellForRowAtIndexPath_(self, tableView, indexPath):
        cell = None
        try:
            k = _Params(self).get('keystore', None)
            cell = tableView.dequeueReusableCellWithIdentifier_("ImportCell")
            if cell is None: raise Exception("Dafuq UIKit?!")
            item = str(self.items[indexPath.row])
            ii = _ImportItemify(item)
            cell.item.text = ii.item
            cell.num.text = str(indexPath.row + 1)
            if ii.typ == 1:
                cell.desc.text = "Bitcoin Cash Address" + (" (watching-only)" if k and k.is_watching_only() else "")
            elif ii.typ == 2:
                cell.desc.text = "Private Key - Address: " + ii.info.to_ui_string()
            else:
                cell.desc.text = ""
            # re-align 'title' to center or above center depending on whether we have a description or not
            if cell.desc.text:
                cell.centerYCS.constant = -8.0
            else:
                cell.centerYCS.constant = 0.0
            if ii.typ and (not self.forceType or int(self.forceType) == int(ii.typ)):
                cell.status.text = _("Valid")
                cell.status.textColor = utils.uicolor_custom('green')
            else:
                cell.status.text = _("Invalid")
                cell.status.textColor = utils.uicolor_custom('red')
        except:
            utils.NSLog("exception in Import2 tableView_cellForRowAtIndexPath_: %s",str(sys.exc_info()[1]))
            cell = UITableViewCell.alloc().initWithStyle_reuseIdentifier_(UITableViewCellStyleSubtitle, "ACell").autorelease()
            cell.textLabel.text = " "
        return cell

    @objc_method
    def tableView_heightForRowAtIndexPath_(self, tv, indexPath) -> float:
        return 65.0

    @objc_method
    def tableView_editingStyleForRowAtIndexPath_(self, tv, indexPath) -> int:
        return UITableViewCellEditingStyleDelete if not self.masterKeyMode else UITableViewCellEditingStyleNone

    @objc_method
    def removeItemAtIndex_(self, index : int) -> None:
        items = py_from_ns(self.items)
        try:
            items.pop(index)
        except:
            utils.NSLog("Failed to pop item at index %d", index)
        self.items = items

    @objc_method
    def tableView_commitEditingStyle_forRowAtIndexPath_(self, tv, editingStyle : int, indexPath) -> None:
        if editingStyle == UITableViewCellEditingStyleDelete:
            self.removeItemAtIndex_(indexPath.row)
            self.doChkFormOk()
            self.retain()
            utils.call_later(0.4, lambda: self.autorelease().refresh())
            tv.deleteRowsAtIndexPaths_withRowAnimation_([indexPath],UITableViewRowAnimationFade)

    @objc_method
    def tableView_trailingSwipeActionsConfigurationForRowAtIndexPath_(self, tv, indexPath) -> ObjCInstance:
        ''' This method is called in iOS 11.0+ only .. so we only create this UISwipeActionsConfiguration ObjCClass
            here rather than in uikit_bindings.py
        '''
        if self.masterKeyMode:
            return None

        try:
            row = int(indexPath.row) # save param outside objcinstance object and into python for 'handler' closure
            section = int(indexPath.section)
            def handler(a : objc_id, v : objc_id, c : objc_id) -> None:
                result = False
                try:
                    #ip = NSIndexPath.indexPathForRow_inSection_(row,section)
                    self.removeItemAtIndex_(row)
                    self.doChkFormOk()
                    self.retain()
                    utils.call_later(0.4, lambda: self.autorelease().refresh())
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
            utils.NSLog("Impoert2.tableView_trailingSwipeActionsConfigurationForRowAtIndexPath_, got exception: %s", str(sys.exc_info()[1]))
            traceback.print_exc(file=sys.stderr)
        return None
    ### end UITableView related methods

    @objc_method
    def doChkFormOk(self) -> bool:
        numvalid = 0
        numpk = 0
        numaddr = 0

        ret = True
        asError = False
        msg = ""

        if self.masterKeyMode:
            ret = True
            k = _Params(self).get('keystore', None)
            if k:
                if k.is_watching_only():
                    msg = _("A deterministic wallet will be created using the provided master public key. This wallet will be watching-only.")
                else:
                    msg = _("A deterministic wallet will be created using the provided master private key. This wallet will be able to freely send and receive Bitcoin Cash.")
            else:
                ret = False
                msg = _("An unknown error occurred. Cannot proceed.")
                asError = True
        else:
            # regular bitcoin address / private key import
            items = list(self.items)
            valid_items = list()
            for x in items:
                item = _ImportItemify(x)
                if item.typ == 1: numaddr += 1
                elif item.typ == 2: numpk += 1
                if item.typ:
                    if self.forceType == 2 and item.typ == 1:
                        pass
                    else:
                        numvalid += 1
                        valid_items.append(item)
            utils.nspy_put_byname(self, valid_items, 'valid_items')
            msg = ""
            if numvalid < len(items):
                msg += _("%d valid item(s)"%numvalid) + " (" + _("invalid items will be discarded") + ")."
            if self.forceType == 1 and numpk:
                msg += " " + _("This is a watching-only wallet, so the given private keys will be converted to watching addresses.")
            elif self.forceType == 2 and numaddr:
                msg =  _("To import addresses into a spending wallet, you must use their private key.")
                asError = True
                ret = False
            elif numpk and numaddr:
                msg = _("Cannot specify private keys and addresses in the same wallet. Addresses will result in a watching-only wallet, and private keys in a spending wallet. Remove incompatible items (by swiping them left).")
                ret = False
                asError = True
            elif numpk:
                if not self.forceType:
                    msg += " " + _("Importing these keys will create a fully capable spending wallet.")
                else:
                    msg += " " + _("Importing these keys will add addresses and keys to your spending wallet.")
            elif numaddr:
                if not self.forceType:
                    msg += " " + _("Importing these addresses will create a watching-only wallet.")
                else:
                    msg += " " + _("Importing these addresses will add them to your watching-only wallet.")
            elif not numvalid:
                msg = _("No valid items remain. Cannot proceed -- go back and try again.")
                asError = True
                ret = False
        if asError:
            utils.uilabel_replace_attributed_text(lbl=self.errMsg, text = msg)
            self.errMsgView.setHidden_(False)
            self.infoView.setHidden_(True)
        else:
            utils.uilabel_replace_attributed_text(lbl=self.info, text = msg)
            self.errMsgView.setHidden_(True)
            self.infoView.setHidden_(False)
        utils.uiview_set_enabled(self.nextBut, ret)
        return ret

    @objc_method
    def shouldPerformSegueWithIdentifier_sender_(self, identifier, sender) -> bool:
        # checks here that form is ok, etc
        return self.doChkFormOk()

    @objc_method
    def prepareForSegue_sender_(self, segue, sender) -> None:
        if not self.masterKeyMode:
            valids = utils.nspy_get_byname(self, 'valid_items')
            _SetParam(self, 'valid_items', valids)
            _SetParam(self, 'imported_keystore_type', valids[0].typ)
        else:
            _SetParam(self, 'imported_keystore_type', 1 if _Params(self)['keystore'].is_watching_only() else 2)

class ImportSaveWallet(NewWalletVCAtEnd):

    @objc_method
    def viewDidLoad(self) -> None:
        send_super(__class__, self, 'viewDidLoad')
        if _Params(self).get('imported_keystore_type', None) == 1:
            self.noPWCheck = True

    @objc_method
    def onSave(self) -> None:
        self.view.endEditing_(True)
        if self.doChkFormOk():
            try:
                self.saveVars()
                #print("params =", _Params(self))
                wallet_name = _Params(self)['WalletName']
                addys = []
                keys = []
                wallet_pass = None
                ks = _Params(self).get('keystore', None)
                wants_touchid = False
                if _Params(self)['imported_keystore_type'] == 2:
                    wallet_pass = _Params(self)['WalletPass']
                    wants_touchid = _Params(self).get('UseTouchID', False)
                    if not ks:
                        keys = [x.item for x in _Params(self)['valid_items']]
                elif _Params(self)['imported_keystore_type'] == 1:
                    if not ks:
                        addys = [x.item for x in _Params(self)['valid_items']]
                else:
                    raise Exception("Can't find imported_keystore_type in _Params!")

                _WizardGenerateNewWallet(vc = self, wallet_name = wallet_name, wallet_pass = wallet_pass,
                                         message = _("Generating your wallet..."),
                                         have_keystore = ks,
                                         watching_addresses = addys, private_keys = keys, encrypt = True,
                                         wants_touchid = wants_touchid)
            except:
                utils.NSLog("Exception in ImportSaveWallet onSave: %s", sys.exc_info()[1])
                _ToErrIsHuman(vc=self)

####################
# Useful Helpers   #
####################
ImportItem = namedtuple("ImportItem", "item typ info") # typ=0 is invalid, typ=1 is address typ=2 is private key. if valid, info is the Address object for the key and/or address
def _ImportItemify(item : str) -> ImportItem:
    item = item.strip()
    info = None
    typ = 0
    if Address.is_valid(item):
        typ = 1
        info = Address.from_string(item)
        item = item.split(':')[-1]
    elif bitcoin.is_private_key(item):
        typ = 2
        try:
            info = PublicKey.from_WIF_privkey(item).address
        except (ValueError, TypeError):
            # Not an address, not a PK
            info, typ = None, 0
    return ImportItem(item, typ, info)

def _ToErrIsHuman(vc : UIViewController, title = "Oops!", message = "Something went wrong! Please email the developers!", onOk = None) -> None:
    parent = gui.ElectrumGui.gui
    parent.show_error(vc = vc, title = title, message = message, onOk = onOk)

def _DoDismiss(vc : UIViewController) -> None:
    vc.presentingViewController.dismissViewControllerAnimated_completion_(True, None)

def _WizardGenerateNewWallet(vc : UIViewController, **kwargs) -> None:
    if kwargs.get('onSuccess', None) or kwargs.get('onFailure', None):
        raise ValueError('_WizardGenerateNewWallet cannot be passed an onFailure or onSuccess callback!')
    completion = kwargs.pop('completion', None)
    if not completion: completion = lambda: None
    wallet_name = kwargs.get('wallet_name', None)
    wallet_pass = kwargs.get('wallet_pass', None)
    if not wallet_name:
        raise ValueError('_WizardGenerateNewWallet: wallet_name kwarg missing!')
    parent = gui.ElectrumGui.gui

    def ToErrIsHuman() -> None:  _ToErrIsHuman(vc=vc)

    def onFailure(msg : str) -> None:
        utils.NSLog("Got error from generate_new_wallet: %s", msg)
        ToErrIsHuman()

    def doDismiss() -> None: _DoDismiss(vc)

    def openNew() -> None:
        parent.switch_wallets(wallet_name = wallet_name, wallet_pass = wallet_pass, vc = vc, onSuccess=doDismiss,
                              onFailure=onFailure, onCancel=doDismiss if not _IsOnBoarding(vc) else None)

    def onSuccess() -> None:
        completion()
        if not _IsOnBoarding(vc):
            parent.show_message(vc=vc, title=_('New Wallet Created'),
                                message = _('Your new imported wallet has been successfully created. Would you like to switch to it now?'),
                                hasCancel = True, cancelButTitle = _('No'), okButTitle=_('Open New Wallet'),
                                onOk = openNew, onCancel = doDismiss)
        else:
            openNew()

    parent.generate_new_wallet(vc = vc, onSuccess = onSuccess, onFailure = onFailure, **kwargs)


def _Params(vc : UIViewController) -> dict():
    nav = vc.navigationController
    p = utils.nspy_get(nav) if isinstance(nav, NewWalletNav) else dict()
    if not p: p = dict()
    return p

def _SetParams(vc : UIViewController, params : dict) -> None:
    nav = vc.navigationController
    if isinstance(nav, NewWalletNav):
        utils.nspy_put(nav, params)

def _SetParam(vc : UIViewController, paramName : str, paramValue : Any) -> None:
    d = _Params(vc)
    if paramValue is None:
        d.pop(paramName, None)
    else:
        d[paramName] = paramValue
    _SetParams(vc, d)

def _IsOnBoarding(vc : UIViewController) -> bool:
    nav = vc.navigationController
    if isinstance(nav, NewWalletNav):
        return nav.onBoardingWizard
    return False


_mnem = None
def _Mnem() -> None:
    global _mnem
    if not _mnem: _mnem = mnemonic.Mnemonic_Electrum()
    return _mnem

def _GetOldSuggestions(prefix) -> set:
    ret = set()
    for w in old_words:
        if w.startswith(prefix):
            ret.add(w)
    return ret

def _lowMemory(notificaton : objc_id) -> None:
    # low memory warning -- kill the _Mnem singleton which has 2048 words in it. Not much savings but it's something.
    ct = 0
    global _mnem
    if _mnem:
        _mnem = None
        ct += 1
    if ct:
        import os
        utils.NSLog("Low Memory: Flushed %d objects from %s static globals"%(ct,os.path.split(str(__file__))[-1]))

_notification_token = NSNotificationCenter.defaultCenter.addObserverForName_object_queue_usingBlock_(
    UIApplicationDidReceiveMemoryWarningNotification,
    UIApplication.sharedApplication,
    None,
    Block(_lowMemory)
).retain()


#############################################################################
# On-Boarding Wizard that comes up on first run when no wallets are present #
#############################################################################
class OnBoardingWizard(OnBoardingWizardBase):
    ''' On-Boarding Wizard that comes up on first run when no wallets are present'''
    pvc = objc_property()
    vcs = objc_property()


    @objc_method
    def dealloc(self) -> None:
        self.pvc = None
        self.vcs = None
        send_super(__class__, self, 'dealloc')

    @objc_method
    def viewDidLoad(self) -> None:
        send_super(__class__, self, 'viewDidLoad')
        if utils.is_iphone5() or utils.is_iphone4():
            self.bottomMarginCS.constant = 0
        vcs = self.childViewControllers
        for vc in vcs:
            if isinstance(vc, UIPageViewController):
                self.pvc = vc
        if self.pvc:
            self.pvc.dataSource = self
            sb = UIStoryboard.storyboardWithName_bundle_("NewWallet", None)
            if not sb:
                utils.NSLog("ERROR: SB IS NULL")
                return
            vcs = [ sb.instantiateViewControllerWithIdentifier_("On_Boarding_%d" % i) for i in range(1,4) ]
            vcs.append( sb.instantiateViewControllerWithIdentifier_("On_Boarding_Menu") )
            if not vcs or None in vcs:
                utils.NSLog("ERROR: Could not find a requisite viewcontroller in %s viewDidLoag method!",str(__class__))
                return
            for i,vc in enumerate(vcs):
                vc.parent = self
                vc.pageIndex = i
            self.vcs = ns_from_py(vcs)
            self.pvc.setViewControllers_direction_animated_completion_(NSArray.arrayWithObject_(vcs[0]),UIPageViewControllerNavigationDirectionForward,False,None)
        else:
            utils.NSLog("ERROR: Could not find the UIPageViewController in the %s viewDidLoad method!",str(__class__))

    @objc_method
    def preferredStatusBarStyle(self) -> int:
        return UIStatusBarStyleLightContent

    @objc_method
    def presentationCountForPageViewController_(self, pvc) -> int:
        return len(self.vcs) if self.vcs else 0

    @objc_method
    def presentationIndexForPageViewController_(self, pvc) -> int:
        return self.currentPageIndex

    @objc_method
    def pageViewController_viewControllerBeforeViewController_(self, pvc, vc) -> ObjCInstance:
        b4 = None
        vcs = py_from_ns(self.vcs)
        for i,v in enumerate(vcs):
            if v.ptr.value == vc.ptr.value and i > 0:
                b4 = vcs[i-1]
                break
        return b4


    @objc_method
    def pageViewController_viewControllerAfterViewController_(self, pvc, vc) -> ObjCInstance:
        aft = None
        vcs = py_from_ns(self.vcs)
        for i,v in enumerate(vcs):
            if v.ptr.value == vc.ptr.value and i+1 < len(vcs):
                aft = vcs[i+1]
                break
        return aft

    @objc_method
    def onNextButton_(self, curidx : int) -> None:
        nextidx = curidx + 1
        vcs = py_from_ns(self.vcs)
        if nextidx < len(vcs):
            self.currentPageIndex = nextidx
            self.pvc.setViewControllers_direction_animated_completion_(NSArray.arrayWithObject_(vcs[nextidx]),UIPageViewControllerNavigationDirectionForward,True,None)


class OnBoardingPage(OnBoardingPageBase):
    didTranslate = objc_property()

    @objc_method
    def dealloc(self) -> None:
        self.didTranslate = None
        send_super(__class__, self, 'dealloc')

    @objc_method
    def viewDidAppear_(self, animated : bool) -> None:
        send_super(__class__, self, 'viewDidAppear:', animated, argtypes=[c_bool])
        if self.parent: self.parent.currentPageIndex = self.pageIndex

    @objc_method
    def viewWillAppear_(self, animated : bool) -> None:
        send_super(__class__, self, 'viewWillAppear:', animated, argtypes=[c_bool])
        # translate UI
        if not self.didTranslate:
            self.tit.text = _(self.tit.text)
            s = self.blurb.attributedText.string
            utils.uilabel_replace_attributed_text(lbl = self.blurb,
                                                  text = _(s),
                                                  template = self.blurb.attributedText)
            s = _(self.nextBut.currentTitle)
            for state in UIControlState_ALL_RELEVANT_TUPLE:
                self.nextBut.setTitle_forState_(s, state)
            self.didTranslate = True

    @objc_method
    def onNext(self) -> None:
        if self.parent: self.parent.onNextButton_(self.pageIndex)


class OnBoardingMenu(OnBoardingMenuBase):
    @objc_method
    def viewDidAppear_(self, animated : bool) -> None:
        send_super(__class__, self, 'viewDidAppear:', animated, argtypes=[c_bool])
        if self.parent: self.parent.currentPageIndex = self.pageIndex

    @objc_method
    def viewWillAppear_(self, animated : bool) -> None:
        send_super(__class__, self, 'viewWillAppear:', animated, argtypes=[c_bool])
        # translate UI
        self.tit.text = _("Get started now")
        utils.uilabel_replace_attributed_text(lbl = self.blurb,
                                              text = _("and create your standard wallet or restore an existing one with any of the methods below"),
                                              template = self.blurb.attributedText)
        for state in UIControlState_ALL_RELEVANT_TUPLE:
            self.std.setTitle_forState_(_("Create New Standard Wallet"), state)
            self.restore.setTitle_forState_(_("Restore from Seed"), state)
            self.imp.setTitle_forState_(_("Import Addresses or Private Keys"), state)
            self.master.setTitle_forState_(_("Use a Master Key"), state)

    @objc_method
    def jumpToMenu_(self, vcToPushIdentifier) -> None:
        vc = PresentAddWalletWizard(dontPresentJustReturnIt = True)
        # hacky mechanism to get to the second viewcontroller in this storyboard.. it works but isn't 100% pretty
        if isinstance(vc, NewWalletNav) and vc.viewControllers and isinstance(vc.viewControllers[0], NewWalletMenu):
            vc.onBoardingWizard = True # tell the viewcontroller chain that we are on-boarding, so don't ask to open new wallets, just do it
            menu = vc.viewControllers[0]
            menu.noCancelBut = True
            menu.navigationItem.title = _("Get Started")
            sb = UIStoryboard.storyboardWithName_bundle_('NewWallet', None)
            if sb:
                vc2 = sb.instantiateViewControllerWithIdentifier_(vcToPushIdentifier) #NB: If you rename it in storyboard be SURE to update this!
                if vc2:
                    vc.pushViewController_animated_(vc2, False)
                    pvc = self.presentingViewController
                    if pvc:
                        pvc.dismissViewControllerAnimated_completion_(True, None)
                        pvc.presentViewController_animated_completion_(vc, True, None)
                        return
        # If this is reached, means the above failed
        gui.ElectrumGui.gui.show_error(vc = self, title = "Oops!", message = "Something went wrong! Please email the developers!")

    @objc_method
    def onNewStandardWallet(self) -> None:
        self.jumpToMenu_("NewStandardWallet")

    @objc_method
    def onRestoreSeed(self) -> None:
        self.jumpToMenu_("RESTORE_SEED_1")

    @objc_method
    def onImportAddysPks(self) -> None:
        self.jumpToMenu_("IMPORT_KEYS_1")

    @objc_method
    def onMasterKey(self) -> None:
        self.jumpToMenu_("MASTER_KEY_1")
