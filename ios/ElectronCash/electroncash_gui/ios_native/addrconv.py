#
# This file is:
#     Copyright (C) 2018 Calin Culianu <calin.culianu@gmail.com>
#
# MIT License

from . import utils
from . import gui
from electroncash.i18n import _, language
from electroncash.address import Address

from .uikit_bindings import *
from .custom_objc import *


class AddrConvVC(AddrConvBase):
      
    @objc_method
    def init(self) -> ObjCInstance:
        self = ObjCInstance(send_super(__class__, self, 'init'))
        if self:
            self.title = _("Address Converter")
        return self
    
    @objc_method
    def dealloc(self) -> None:
        send_super(__class__, self, 'dealloc')
    
    @objc_method
    def loadView(self) -> None:
        NSBundle.mainBundle.loadNibNamed_owner_options_("AddressConverter",self,None)
        
    @objc_method
    def viewDidLoad(self) -> None:
        send_super(__class__, self, 'viewDidLoad')
        self.address.text = ""
        self.doConversion_("")  # disables copy buttons and show qr buttons before any data is present
        ats = NSMutableAttributedString.alloc().initWithAttributedString_(self.blurb.attributedText).autorelease()
        r = NSRange(0, ats.length())
        ats.addAttribute_value_range_(NSKernAttributeName, utils._kern, r)
        
    @objc_method
    def viewWillAppear_(self, animated : bool) -> None:
        send_super(__class__, self, 'viewWillAppear:', animated, argtypes=[c_bool])
        
        txt = _(
            "This tool helps convert between address formats for Bitcoin "
            "Cash addresses.\nYou are encouraged to use the 'Cash address' "
            "format."
            )
        
        utils.uilabel_replace_attributed_text(self.blurb, txt.replace('\n','\n\n'), font = UIFont.italicSystemFontOfSize_(14.0))
        
        self.address.attributedPlaceholder = NSAttributedString.alloc().initWithString_attributes_(
            _('Address to convert'),
            {
                NSFontAttributeName            : UIFont.italicSystemFontOfSize_(14.0),
                NSForegroundColorAttributeName : utils.uicolor_custom('light')
             }).autorelease()
        self.addressTit.setText_withKerning_(_('Address'), utils._kern)
        self.cashTit.setText_withKerning_(_('Cash address'), utils._kern)
        self.legacyTit.setText_withKerning_(_('Legacy address'), utils._kern)
        
        utils.uitf_redo_attrs(self.address)
        
    @objc_method
    def textFieldShouldReturn_(self, tf) -> bool:
        #print("tf should return")
        tf.resignFirstResponder()
        return True
    
    @objc_method
    def textFieldDidEndEditing_(self, tf) -> None:
        utils.uitf_redo_attrs(tf)
    
    @objc_method
    def onBut_(self, but) -> None:
        def DoIt() -> None:
            if but.ptr.value == self.cpyCashBut.ptr.value:
                gui.ElectrumGui.gui.copy_to_clipboard(self.cash.text, 'Address')
            elif but.ptr.value == self.cpyLegBut.ptr.value:
                gui.ElectrumGui.gui.copy_to_clipboard(self.legacy.text, 'Address')
            elif but.ptr.value == self.qrBut.ptr.value:
                if not QRCodeReader.isAvailable:
                    utils.show_alert(self, _("QR Not Avilable"), _("The camera is not available for reading QR codes"))
                else:
                    self.qr = QRCodeReader.new().autorelease() # self.qr is a weak property decalred in objc superclass.. it auto-zeros itself when the qr code reader disappears
                    self.qrvc = QRCodeReaderViewController.readerWithCancelButtonTitle_codeReader_startScanningAtLoad_showSwitchCameraButton_showTorchButton_("Cancel",self.qr,True,False,False)
                    self.qrvc.modalPresentationStyle = UIModalPresentationFormSheet
                    self.qrvc.delegate = self
                    self.presentViewController_animated_completion_(self.qrvc, True, None)
            elif but.ptr.value in (self.qrButShowLegacy.ptr.value, self.qrButShowCash.ptr.value):
                datum = self.cash.text if but.ptr.value == self.qrButShowCash.ptr.value else self.legacy.text
                print("qrcode datum =", datum)
                qrvc = utils.present_qrcode_vc_for_data(vc=self, data=datum, title = _('QR code'))
                gui.ElectrumGui.gui.add_navigation_bar_close_to_modal_vc(qrvc)
        utils.boilerplate.vc_highlight_button_then_do(self, but, DoIt)

    @objc_method
    def reader_didScanResult_(self, reader, result) -> None:
        utils.NSLog("Reader data = '%s'",str(result))
        result = str(result).strip()
        
        if not self.doConversion_(result):
            title = _("Invalid QR Code")
            message = _("The QR code does not appear to be a valid BCH address.\nPlease try again.")
            reader.stopScanning()
            gui.ElectrumGui.gui.show_error(
                title = title,
                message = message,
                onOk = lambda: reader.startScanning(),
                vc = self.qrvc
            )
        else:
            self.address.text = result
            self.readerDidCancel_(reader)
             
    @objc_method
    def readerDidCancel_(self, reader) -> None:
        if reader is not None: reader.stopScanning()
        if self.presentedViewController:
            self.dismissViewControllerAnimated_completion_(True, None)
        
    @objc_method
    def onAddress_(self, tf) -> None:
        print("onAddress:",tf.text)
        self.doConversion_(tf.text)
        
    @objc_method
    def doConversion_(self, text) -> bool:
        self.cash.text = ""
        self.legacy.text = ""
        self.cpyCashBut.enabled = False
        self.cpyLegBut.enabled = False
        self.qrButShowCash.enabled = False
        self.qrButShowLegacy.enabled = False
        text = text.strip()
        
        addy = None
        
        try:
            addy = Address.from_string(text)
        except:
            pass

        if addy:
            self.cash.text = addy.to_full_string(Address.FMT_CASHADDR)
            self.legacy.text = addy.to_full_string(Address.FMT_LEGACY)
            self.cpyCashBut.enabled = True
            self.cpyLegBut.enabled = True
            self.qrButShowCash.enabled = True
            self.qrButShowLegacy.enabled = True
            
            return True
        return False
