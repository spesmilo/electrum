#!/usr/bin/env python3
#
# Electron Cash - lightweight Bitcoin Cash client
# Copyright (C) 2012 thomasv@gitorious
#
# This file is:
#     Copyright (C) 2018 Calin Culianu <calin.culianu@gmail.com>
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
import math
import re
from typing import Callable, Any
from .uikit_bindings import *
from . import utils
from .custom_objc import *

from electroncash.i18n import _
from electroncash import WalletStorage, Wallet


def Create_PWChangeVC(msg : str, hasPW : bool, isEnc : bool, hasTouchId : bool,
                      callback : Callable[[str,str,bool,bool], None], # pass a callback that accepts oldPW, newPW, encrypt_wallet_bool
                      callbackChkTouchId : Callable[[bool],bool] # pass a callback that gets invoked whenever they try to enable touchid. if it can't be done, returns false. arg to callable is whether we want to use or not use touchid (UISwitch isOn())
                      ) -> ObjCInstance:
    ret = PWChangeVC.pwChangeVCWithMessage_hasPW_isEncrypted_hasTouchId_(ns_from_py(msg), hasPW, isEnc, hasTouchId)
    utils.add_callback(ret, 'okcallback', callback)
    utils.add_callback(ret, 'on_touchid', callbackChkTouchId)
    return ret

class PWChangeVC(UIViewController):
    okBut = objc_property()
    pw1 = objc_property()
    pw2 = objc_property()
    curPW = objc_property()
    hasPW = objc_property()
    isEnc = objc_property()
    hasTouchId = objc_property()
    msg = objc_property()
    colors = objc_property()
    encSW = objc_property()
    encTit = objc_property()
    tidSW = objc_property()
    tidTit = objc_property()
    kbas = objc_property()

    @objc_classmethod
    def pwChangeVCWithMessage_hasPW_isEncrypted_hasTouchId_(cls : ObjCInstance, msg : ObjCInstance, hasPW : bool, isEnc : bool, hasTouchId : bool) -> ObjCInstance:
        ret = PWChangeVC.new().autorelease()
        ret.hasPW = hasPW
        ret.isEnc = isEnc
        ret.hasTouchId = hasTouchId
        ret.msg = msg
        ret.modalPresentationStyle = UIModalPresentationOverFullScreen#UIModalPresentationOverCurrentContext
        ret.modalTransitionStyle = UIModalTransitionStyleCrossDissolve
        #ret.disablesAutomaticKeyboardDismissal = False #NB: this caused an app crash due to missing selector in some iOS! DO NOT USE!
        return ret

    @objc_method
    def dealloc(self) -> None:
        self.okBut = None
        self.hasPW = None
        self.isEnc = None
        self.hasTouchId = None
        self.curPW = None
        self.pw1 = None
        self.pw2 = None
        self.msg = None
        self.colors = None
        self.encSW = None
        self.encTit = None
        self.tidSW = None
        self.tidTit = None
        self.kbas = None
        utils.remove_all_callbacks(self)
        send_super(__class__, self, 'dealloc')

    @objc_method
    def doChkOkBut(self) -> None:
        is_en = bool( (not self.hasPW or self.curPW.text) and self.pw1.text == self.pw2.text )
#        for a in [self.okBut, self.encSW, self.encTit]:
        for a in [self.okBut]:
            if a: utils.uiview_set_enabled(a, is_en)


    @objc_method
    def textFieldDidBeginEditing_(self, tf : ObjCInstance) -> None:
        if not utils.is_iphone(): return

    @objc_method
    def textFieldDidEndEditing_(self, tf : ObjCInstance) -> None:
        #print("textFieldDidEndEditing", tf.tag, tf.text)
        self.doChkOkBut()
        return True

    @objc_method
    def textFieldShouldReturn_(self, tf: ObjCInstance) -> bool:
        #print("textFieldShouldReturn", tf.tag)
        nextTf = self.view.viewWithTag_(tf.tag+100) if self.viewIfLoaded else None
        if nextTf and isinstance(nextTf, UITextField):
            nextTf.becomeFirstResponder()
        else:
            tf.resignFirstResponder()
        return True

    @objc_method
    def viewWillAppear_(self, animated : bool) -> None:
        send_super(__class__, self, 'viewWillAppear:', animated, argtypes=[c_bool])
        self.kbas = utils.register_keyboard_autoscroll(self.view)

    @objc_method
    def viewWillDisappear_(self, animated : bool) -> None:
        send_super(__class__, self, 'viewWillDisappear:', animated, argtypes=[c_bool])
        if self.kbas:
            utils.unregister_keyboard_autoscroll(self.kbas)
            self.kbas = None


    @objc_method
    def loadView(self) -> None:
        is_encrypted = self.isEnc
        has_touchid = self.hasTouchId
        has_pw = self.hasPW
        msg = self.msg
        if msg is None:
            if not has_pw:
                msg = _('Your wallet is not protected.')
                msg += ' ' + _('Use this dialog to add a password to your wallet.')
            else:
                if not is_encrypted:
                    msg = _('Your bitcoins are password protected. However, your wallet file is not encrypted.')
                else:
                    msg = _('Your wallet is password protected and encrypted.')
                msg += ' ' + _('Use this dialog to change your password.')
        self.msg = msg
        objs = NSBundle.mainBundle.loadNibNamed_owner_options_("ChangePassword",None,None)
        v = objs[0]
        allviews = v.allSubviewsRecursively()
        for a in allviews:
            if isinstance(a, UILabel):
                # translate UI automatically since placeholder text has potential translations
                a.text = _(a.text)
            elif isinstance(a, UITextField):
                a.delegate = self
                old = a.placeholder
                new = _(old)
                newcolon = _(old + ':').replace(':','')
                a.placeholder = new if new != old else newcolon
            elif isinstance(a, UIButton):
                a.setTitle_forState_(_(a.titleForState_(UIControlStateNormal)), UIControlStateNormal)
                a.layer.borderColor = utils.uicolor_custom('nav').CGColor
        msgLbl = v.viewWithTag_(20)
        msgLbl.text = msg
        utils.uiview_set_enabled(v.viewWithTag_(100), has_pw)
        utils.uiview_set_enabled(v.viewWithTag_(110), has_pw)
        f = v.frame
        sv = UIScrollView.alloc().initWithFrame_(CGRectMake(0,0,f.size.width,f.size.height)).autorelease()
        sv.contentSize = CGSizeMake(f.size.width,f.size.height + 150)
        sv.backgroundColor = UIColor.colorWithRed_green_blue_alpha_(0.,0.,0.,0.3)
        sv.opaque = False
        sv.addSubview_(v)
        self.view = sv
        okBut = v.viewWithTag_(1000)
        self.okBut = okBut
        self.pw1 = v.viewWithTag_(210)
        self.pw2 = v.viewWithTag_(310)
        self.curPW = v.viewWithTag_(110)
        self.encSW = v.viewWithTag_(510)
        self.encSW.setOn_animated_(bool(is_encrypted or not has_pw), False)
        self.encTit = v.viewWithTag_(500)
        self.tidSW = v.viewWithTag_(610)
        self.tidTit = v.viewWithTag_(600)
        self.tidSW.setOn_animated_(bool(has_touchid), False)
        pwStrLbl = v.viewWithTag_(410)
        pwStrTitLbl = v.viewWithTag_(400)
        pwStrTitLbl.setText_withKerning_( _("Password Strength"), utils._kern)
        myGreen = UIColor.colorWithRed_green_blue_alpha_(0.0,0.75,0.0,1.0)
        self.colors =  {"Weak":utils.uicolor_custom('red'), "Medium":UIColor.blueColor, "Strong":myGreen, "Very Strong": myGreen}

        cancelBut = v.viewWithTag_(2000)
        def onCancel(but_in : objc_id) -> None:
            but = ObjCInstance(but_in)
            self.dismissViewControllerAnimated_completion_(True,None)
        def onOk(but_in : objc_id) -> None:
            but = ObjCInstance(but_in)
            #print("but tag = ",but.tag)
            cb=utils.get_callback(self, 'okcallback')
            oldpw = self.curPW.text
            newpw = self.pw1.text
            enc = bool(self.encSW.isOn() and newpw)
            tid = bool(self.tidSW.isOn())
            oldpw = oldpw if oldpw else None
            newpw = newpw if newpw else None
            def onCompletion() -> None:
                cb(oldpw, newpw, enc, tid)
            self.dismissViewControllerAnimated_completion_(True,onCompletion)
        def onChg(oid : objc_id) -> None:
            tf = ObjCInstance(oid)
            #print("value changed ", tf.tag,str(":"),tf.text)
            if tf.tag == self.pw1.tag:
                if len(tf.text):
                    s = check_password_strength(tf.text)
                    pwStrLbl.text = _(s)
                    pwStrLbl.textColor = self.colors.get(s,UIColor.blackColor)
                    utils.uiview_set_enabled(pwStrTitLbl,True)
                else:
                    pwStrLbl.text = ""
                    utils.uiview_set_enabled(pwStrTitLbl,False)
            self.doChkOkBut()
        def onTouchID(oid : objc_id) -> None:
            sw = ObjCInstance(oid)
            cb = utils.get_callback(self,'on_touchid')
            if cb: sw.setOn_animated_(cb(sw.isOn()),True)
        self.tidSW.handleControlEvent_withBlock_(UIControlEventValueChanged, onTouchID)
        cancelBut.handleControlEvent_withBlock_(UIControlEventPrimaryActionTriggered,onCancel)
        okBut.handleControlEvent_withBlock_(UIControlEventPrimaryActionTriggered,onOk)
        self.pw1.handleControlEvent_withBlock_(UIControlEventEditingChanged,onChg)
        self.pw2.handleControlEvent_withBlock_(UIControlEventEditingChanged,onChg)
        if has_pw: self.curPW.handleControlEvent_withBlock_(UIControlEventEditingChanged,onChg)
        #make sure Ok button is disabled, pw strength is disabled, etc
        onChg(self.pw1.ptr)

def check_password_strength(password):
    '''
    Check the strength of the password entered by the user and return back the same
    :param password: password entered by user in New Password
    :return: password strength 'Weak' or 'Medium' or 'Strong' or 'Very Strong'
    '''
    password = password
    n = math.log(len(set(password)))
    num = re.search("[0-9]", password) is not None and re.match("^[0-9]*$", password) is None
    caps = password != password.upper() and password != password.lower()
    extra = re.match("^[a-zA-Z0-9]*$", password) is None
    score = len(password)*( n + caps + num + extra)/20
    password_strength = {0:"Weak",1:"Medium",2:"Strong",3:"Very Strong"}
    strength = min(3, int(score))
    return password_strength[strength]


def prompt_password_local_runloop(vc : ObjCInstance, prompt : str = None, title : str = None) -> str:
    title =  _("Enter Password") if not title else title
    prompt = _("Enter your password to proceed") if not prompt else prompt
    tf = None
    retPW = None
    def tfConfigHandler(oid : objc_id) -> None:
        nonlocal tf
        tf = ObjCInstance(oid).retain()
        tf.adjustsFontSizeToFitWidth = True
        tf.minimumFontSize = 9
        tf.placeholder = _("Enter Password")
        tf.backgroundColor = utils.uicolor_custom('password')
        tf.borderStyle = UITextBorderStyleBezel
        tf.clearButtonMode = UITextFieldViewModeWhileEditing
        tf.secureTextEntry = True
    def onOK() -> None:
        nonlocal retPW
        nonlocal tf
        if tf:
            retPW = tf.text
            tf.release()
            tf = None
    def onCancel() -> None:
        nonlocal tf
        if tf:
            tf.release()
            tf = None
    utils.show_alert(
        vc = vc,
        title = title,
        message = prompt,
        actions = [ [ _("OK"), onOK ], [_("Cancel"), onCancel ] ],
        cancel = _("Cancel"),
        localRunLoop = True,
        uiTextFieldHandlers = [tfConfigHandler]
    )
    return retPW

_extant_pw_dialogs = list()
def kill_extant_asynch_pw_prompts() -> None:
    if _extant_pw_dialogs:
        #print("*** dlgs exist, len =",len(_extant_pw_dialogs))
        dlgs = _extant_pw_dialogs.copy()
        for tup in dlgs:
            tup[0].dismissViewControllerAnimated_completion_(False, Block(tup[1]))

def prompt_password_asynch(vc : ObjCInstance, onOk : Callable, prompt : str = None, title : str = None, onCancel : Callable = None,
                           onForcedDismissal : Callable = None) -> ObjCInstance:
    title =  _("Enter Password") if not title else title
    prompt = _("Enter your password to proceed") if not prompt else prompt
    tf = None
    retPW = None
    def tfConfigHandler(oid : objc_id) -> None:
        nonlocal tf
        tf = ObjCInstance(oid).retain()
        tf.adjustsFontSizeToFitWidth = True
        tf.minimumFontSize = 9
        tf.placeholder = _("Enter Password")
        tf.backgroundColor = utils.uicolor_custom('password')
        tf.borderStyle = UITextBorderStyleBezel
        tf.clearButtonMode = UITextFieldViewModeWhileEditing
        tf.secureTextEntry = True
    alert = None
    def Cleanup() -> None:
        nonlocal alert, tf
        for i, tup in enumerate(_extant_pw_dialogs):
            if tup[0].ptr.value == alert.ptr.value:
                _extant_pw_dialogs.pop(i)
                break
        tf.release()
        tf = None
        #print("*** alert cleaned up",alert.ptr.value, " dlgs len =", len(_extant_pw_dialogs))
        alert = None
    def MyOnOk() -> None:
        nonlocal tf
        txt = tf.text
        Cleanup()
        if callable(onOk): onOk(txt)
    def MyOnCancel() -> None:
        nonlocal tf
        Cleanup()
        if callable(onCancel): onCancel()
    def MyForcedKill() -> None:
        Cleanup()
        if callable(onForcedDismissal): onForcedDismissal()
    def MyCompletion(o : objc_id) -> None:
        _extant_pw_dialogs.append((ObjCInstance(o), MyForcedKill))

    kill_extant_asynch_pw_prompts()

    alert = utils.show_alert(
        vc = vc,
        title = title,
        message = prompt,
        actions = [ [ _("OK"), MyOnOk ], [_("Cancel"), MyOnCancel ] ],
        cancel = _("Cancel"),
        localRunLoop = False,
        uiTextFieldHandlers = [tfConfigHandler],
        completion = MyCompletion
    )

    return alert
