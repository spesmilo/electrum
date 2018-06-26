#
# This file is:
#     Copyright (C) 2018 Calin Culianu <calin.culianu@gmail.com>
#
# MIT License
#
from . import utils
from . import gui
from electroncash.i18n import _, language
from .uikit_bindings import *
from .custom_objc import *
from collections import namedtuple
from electroncash import bitcoin

def parent() -> object:
    return gui.ElectrumGui.gui

PrivateKeyEntry = namedtuple("PrivateKeyEntry", "address privkey is_frozen is_change")

class PrivateKeyDialog(PrivateKeyDialogBase):
        
    @objc_method
    def init(self) -> ObjCInstance:
        self = ObjCInstance(send_super(__class__, self, 'init'))
        self.title = _("Private Key")
        return self
    
    @objc_method
    def dealloc(self) -> None:
        utils.nspy_pop(self)
        send_super(__class__, self, 'dealloc')
    
    @objc_method
    def loadView(self) -> None:
        NSBundle.mainBundle.loadNibNamed_owner_options_("PrivateKeyDialog",self,None)
                
    @objc_method
    def viewWillAppear_(self, animated : bool) -> None:
        send_super(__class__, self, 'viewWillAppear:', animated, argtypes=[c_bool])
        self.refresh()
        parent().cash_addr_sig.connect(lambda: self.refresh(), self)
        
        
    @objc_method
    def viewWillDisappear_(self, animated : bool) -> None:
        send_super(__class__, self, 'viewWillDisappear:', animated, argtypes=[c_bool])
        parent().cash_addr_sig.disconnect(self)
        
    @objc_method
    def refresh(self) -> None:
        if not self.viewIfLoaded: return
        entry = utils.nspy_get_byname(self, 'entry')
 
        lbl = self.addressTit
        lbl.setText_withKerning_( _("Address"), utils._kern )
        lbl = self.address
        lbl.text = str(entry.address)
        if entry.is_frozen:
            lbl.textColor = utils.uicolor_custom('frozen address text')
        else:
            lbl.textColor = utils.uicolor_custom('dark')
   
        lbl = self.scriptTypeTit
        lbl.setText_withKerning_( _("Script type"), utils._kern )
        lbl = self.scriptType
        xtype = bitcoin.deserialize_privkey(entry.privkey)[0]
        lbl.text = xtype

        lbl = self.privKeyTit
        lbl.setText_withKerning_( _("Private key"), utils._kern )
        tv = self.privKey
        tv.text = str(entry.privkey)
        
        lbl = self.redeemScriptTit
        lbl.setText_withKerning_( _("Redeem Script"), utils._kern )
        tv = self.redeemScript
        tv.text = entry.address.to_script().hex()

        
    @objc_method
    def onCpyBut_(self, sender) -> None:
        entry = utils.nspy_get_byname(self, 'entry')
        data = ""
        if sender.tag == 120: data = str(entry.address)
        elif sender.tag == 320: data = str(entry.privkey)
        elif sender.tag == 420: data = entry.address.to_script().hex()        
        utils.boilerplate.vc_highlight_button_then_do(self, sender, lambda:parent().copy_to_clipboard(data))

    @objc_method
    def onQRBut_(self, sender) -> None:
        def DoIt() -> None:
            entry = utils.nspy_get_byname(self, 'entry')
            if not entry: return
            data = ""
            if sender.tag == 130: data = str(entry.address)
            elif sender.tag == 330: data = str(entry.privkey)
            elif sender.tag == 430: data = entry.address.to_script().hex()
            qrvc = utils.present_qrcode_vc_for_data(vc=self,
                                                    data=data,
                                                    title = _('QR code'))
            parent().add_navigation_bar_close_to_modal_vc(qrvc)
        utils.boilerplate.vc_highlight_button_then_do(self, sender, DoIt)

