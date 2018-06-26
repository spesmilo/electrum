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
       

def Create_SeedDisplayVC(seed : str, passphrase : str) -> ObjCInstance:
    ret = SeedDisplayVC.seedDisplayVCWithSeed_passphrase_(ns_from_py(seed), ns_from_py(passphrase))
    #utils.add_callback(ret, 'okcallback', callback)
    return ret

class SeedDisplayVC(SeedDisplayBase):
    
    @objc_classmethod
    def seedDisplayVCWithSeed_passphrase_(cls : ObjCInstance, seed : ObjCInstance, passphrase : ObjCInstance) -> ObjCInstance:
        ret = SeedDisplayVC.new().autorelease()
        ret.seed = seed
        ret.passphrase = passphrase
        ret.modalPresentationStyle = UIModalPresentationOverFullScreen#UIModalPresentationOverCurrentContext
        ret.modalTransitionStyle = UIModalTransitionStyleCrossDissolve
        #ret.disablesAutomaticKeyboardDismissal = False #NB: this caused an app crash due to missing selector in some iOS! DO NOT USE!
        return ret
    
    @objc_method
    def dealloc(self) -> None:
        utils.remove_all_callbacks(self)
        send_super(__class__, self, 'dealloc')    
        
    @objc_method
    def loadView(self) -> None:
        NSBundle.mainBundle.loadNibNamed_owner_options_("SeedDialog",self,None)

        f = self.contentView.frame
        sv = UIScrollView.alloc().initWithFrame_(CGRectMake(0,0,f.size.width,f.size.height)).autorelease()
        sv.contentSize = CGSizeMake(f.size.width,f.size.height)
        sv.backgroundColor = UIColor.colorWithRed_green_blue_alpha_(0.,0.,0.,0.3)
        sv.opaque = False
        sv.addSubview_(self.contentView)
        self.view = sv

    @objc_method
    def viewWillAppear_(self, animated : bool) -> None:
        send_super(__class__, self, 'viewWillAppear:', animated, argtypes=[c_bool])
        seed = py_from_ns(self.seed)
        passphrase = py_from_ns(self.passphrase)
        self.seedTit.setText_withKerning_( _("Your wallet generation seed is:"), utils._kern )
        self.extTit.setText_withKerning_( _("Your seed extension is") + ":", utils._kern )
        f1 = UIFont.systemFontOfSize_weight_(16.0, UIFontWeightBold)
        utils.uilabel_replace_attributed_text(self.seedLbl, seed, font = f1)        
        utils.uilabel_replace_attributed_text(self.extLbl, passphrase or '', font = f1)
        utils.uilabel_replace_attributed_text(self.blurb,
                                              (_("Please save these %d words on paper (order is important). ") % (len(seed.split()) + (len(passphrase.split()) if passphrase else 0)))
                                              + _("This seed will allow you to recover your wallet in case of computer failure."),
                                              font = UIFont.italicSystemFontOfSize_(14.0))
        self.okBut.setTitle_forState_(_("OK"), UIControlStateNormal)
        self.warnTit.text = _("WARNING")
        self.warn1.text = _("Never disclose your seed.") 
        self.warn3.text = _("Never type it on a website.")
        self.warn2.text = _("Do not store it electronically.")
        if not passphrase:
            self.extTit.setHidden_(True)
            self.extLbl.setHidden_(True)
            self.csBlurbTop.constant = -40.0
            self.csBlurbHeight.constant = 80.0
            self.csBlurbBot.constant = 40.0
            self.csOkButHeight.constant = 40.0
            self.csTitTop.constant = 20.0
        else:
            self.extTit.setHidden_(False)
            self.extLbl.setHidden_(False)
            self.csBlurbTop.constant = 20.0
            self.csBlurbBot.constant = 20.0
            self.csBlurbHeight.constant = 60.0
            self.csOkButHeight.constant = 30.0
            self.csTitTop.constant = 10.0
            
        
    @objc_method
    def onCopyBut_(self, but) -> None:
        data = str(self.seed)
        if self.passphrase: data += " / " + str(self.passphrase)
        UIPasteboard.generalPasteboard.string = data
        utils.show_notification(message=_("Text copied to clipboard"))

    @objc_method
    def onOk_(self, sender) -> None:
        self.presentingViewController.dismissViewControllerAnimated_completion_(True,None)

    @objc_method
    def onQRBut_(self, but) -> None:
        data = self.seed
        if self.passphrase: data += " / " + self.passphrase
        qrvc = utils.present_qrcode_vc_for_data(vc=self,
                                                data=data,
                                                title = _('Wallet Seed'))

        closeButton = UIBarButtonItem.alloc().initWithBarButtonSystemItem_target_action_(UIBarButtonSystemItemStop, self, SEL(b'onModalClose:')).autorelease()
        qrvc.navigationItem.leftBarButtonItem = closeButton
    
    @objc_method
    def onModalClose_(self, but : ObjCInstance) -> None:
        self.dismissViewControllerAnimated_completion_(True, None)

    @objc_method
    def onSeedLblTap_(self, uigr : ObjCInstance) -> None:
        ipadAnchor = None
        if utils.is_ipad():
            ipadAnchor = self.seedLbl.bounds
            ipadAnchor = self.seedLbl.convertRect_toView_(ipadAnchor, self.view)
        utils.show_alert(
            vc = self,
            title = _("Options"),
            message = _("Wallet Seed"),
            actions = [
                [ _('Cancel') ],
                [ _('Copy to clipboard'), self.onCopyBut_, None ],
                [ _('Show as QR code'), self.onQRBut_, None ],
            ],
            cancel = _('Cancel'),
            style = UIAlertControllerStyleActionSheet,
            ipadAnchor = ipadAnchor
        )
'''
def seed_warning_msg(seed, passphrase):
    return ''.join([
        '<font face="Verdana, Arial, Helvetica" color=#414141>',
        "<p>",
        str(_("Your seed extension is") + ": <b>" + passphrase + "</b></p><p>") if passphrase else '',
        _("Please save these %d words on paper (order is important). "),
        _("This seed will allow you to recover your wallet in case "
          "of computer failure."),
        "</p>",
        '<p>',
        "<b>" + _("WARNING") + ":</b>",
        "<ul>",
        "<li>" + _("Never disclose your seed.") + "</li>",
        "<li>" + _("Never type it on a website.") + "</li>",
        "<li>" + _("Do not store it electronically.") + "</li>",
        "</ul>",
        '</p>',
        '</font>',
    ]) % len(seed.split())
'''