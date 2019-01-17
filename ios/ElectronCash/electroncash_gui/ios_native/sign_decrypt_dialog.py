#
# This file is:
#     Copyright (C) 2018 Calin Culianu <calin.culianu@gmail.com>
#
# MIT License
#
from .uikit_bindings import *
from .custom_objc import *
from . import utils
from . import gui
from . import addresses
from electroncash.i18n import _, language
from electroncash import bitcoin
from electroncash.address import Address
import sys, traceback, base64
from collections import namedtuple

def parent() -> object:
    return gui.ElectrumGui.gui

DialogData = namedtuple("DialogData", "address pubkey")

SignVerify = 0
EncryptDecrypt = 1

class SignDecryptVC(SignDecryptBase):
    
    mode = objc_property()
    kbas = objc_property()
    
    @objc_method
    def initWithMode_(self, mode : int) -> ObjCInstance:
        self = ObjCInstance(send_super(__class__, self, 'init'))
        if mode not in (SignVerify, EncryptDecrypt):
            utils.NSLog(" *** ERROR -- mode %d passed to SignDecryptVC.initWithMode is not valid! Defaulting to mode 'SignVerify'",mode)
            mode = 0
        self.title = _("Sign/Verify Message") if mode == SignVerify else _("Encrypt/Decrypt Message")
        self.mode = mode
        return self
    
    @objc_method
    def dealloc(self) -> None:
        #print("PrivateKeyDialog dealloc")
        utils.nspy_pop(self)
        self.mode = None
        self.kbas = None
        send_super(__class__, self, 'dealloc')
    
    @objc_method
    def loadView(self) -> None:
        NSBundle.mainBundle.loadNibNamed_owner_options_("SignVerify",self,None)

        data = utils.nspy_get_byname(self, 'data')
        
        # Can't set this property from IB, so we do it here programmatically to create the stroke around the button
        self.butRight.layer.borderColor = utils.uicolor_custom('nav').CGColor

        spacer = UIBarButtonItem.alloc().initWithBarButtonSystemItem_target_action_(UIBarButtonSystemItemFlexibleSpace, None, None).autorelease()
        item = UIBarButtonItem.alloc().initWithBarButtonSystemItem_target_action_(UIBarButtonSystemItemDone, self, SEL(b'onCloseKeyboard:')).autorelease()
        item.tag = self.tf.tag
        toolBar = UIToolbar.alloc().init().autorelease()
        toolBar.sizeToFit()
        toolBar.items = [spacer, item]
        self.tf.inputAccessoryView = toolBar
    
        self.tf.delegate = self
                
    @objc_method
    def textFieldDidEndEditing_(self, tf) -> None:
        utils.uitf_redo_attrs(tf)
        
    @objc_method
    def viewWillAppear_(self, animated : bool) -> None:
        send_super(__class__, self, 'viewWillAppear:', animated, argtypes=[c_bool])
        self.refresh()
        parent().cash_addr_sig.connect(lambda: self.refresh(), self)
        self.kbas = utils.register_keyboard_autoscroll(self.view)
        
        
    @objc_method
    def viewWillDisappear_(self, animated : bool) -> None:
        send_super(__class__, self, 'viewWillDisappear:', animated, argtypes=[c_bool])
        parent().cash_addr_sig.disconnect(self)
        data = utils.nspy_get_byname(self, 'data')
        if not data: data = DialogData(None,None)
        text = self.tf.text.strip()
        if self.mode == SignVerify:
            try:
                address = Address.from_string(text)
                data = utils.set_namedtuple_field(data, 'address', address)
            except:
                pass
        elif self.mode == EncryptDecrypt:
            data = utils.set_namedtuple_field(data, 'pubkey', text)
        utils.nspy_put_byname(self, data, 'data')
        if self.kbas:
            utils.unregister_keyboard_autoscroll(self.kbas)
            self.kbas = None
        
    @objc_method
    def refresh(self) -> None:
        if not self.viewIfLoaded or not parent().wallet: return
        data = utils.nspy_get_byname(self, 'data')
        
        strings = [
            [
                "Message",
                "Address",
                "Signature",
                "Sign",
                "Verify",
            ],
            [
                "Message",
                "Public key",
                "Encrypted",
                "Encrypt",
                "Decrypt",
            ],
        ]
  
        mode = self.mode
        watch_only = parent().wallet.is_watching_only()
        if watch_only:
            if mode == SignVerify:
                self.butLeft.enabled = False
                self.butRight.enabled = True
            elif mode == EncryptDecrypt:
                self.butLeft.enabled = True
                self.butLeft.enabled = False
        else:
            self.butLeft.enabled = True
            self.butRight.enabled = True
        utils.uiview_set_enabled(self.butLeft, self.butLeft.isEnabled())   
        utils.uiview_set_enabled(self.butRight, self.butRight.isEnabled())   

        
        lbl = self.midTit
        lbl.setText_withKerning_( _(strings[mode][1]), utils._kern )
        tf = self.tf
        if data.pubkey and not isinstance(data.pubkey, str):
            data = utils.set_namedtuple_field(data, 'pubkey', data.pubkey.to_ui_string())
            utils.nspy_put_byname(self,data,'data')
        tf.text = str(data.address.to_ui_string() if data.address else "") if mode == SignVerify else (str(data.pubkey) if data.pubkey else "")
        tf.placeholder = _("Enter or pick address") if mode == SignVerify else _("Choose address or enter a public key")
        utils.uitf_redo_attrs(tf)

        lbl = self.topTit
        lbl.setText_withKerning_( _(strings[mode][0]), utils._kern )
        tv = self.topTv
        tvDel = self.topTvDel
        tvDel.placeholderFont = UIFont.italicSystemFontOfSize_(14.0)
        tvDel.placeholderColor = utils.uicolor_custom('light')
        tvDel.placeholderText = _("Tap to enter text...")
        if not tvDel.text: tvDel.text = ''

        lbl = self.botTit
        lbl.setText_withKerning_( _(strings[mode][2]), utils._kern )
        tv = self.botTv
        tvDel = self.botTvDel
        tvDel.placeholderFont = UIFont.italicSystemFontOfSize_(14.0)
        tvDel.placeholderColor = utils.uicolor_custom('light')
        tvDel.placeholderText = _("Tap to enter text...")
        if not tvDel.text: tvDel.text = ''

        
        but = self.butLeft
        but.setTitle_forState_(_(strings[mode][3]),UIControlStateNormal)
        but = self.butRight
        but.setTitle_forState_(_(strings[mode][4]),UIControlStateNormal)

        
    @objc_method
    def onCpyBut_(self, sender : ObjCInstance) -> None:
        def DoIt() -> None:
            tvdel = None
            if sender.tag == 220: tvdel = self.topTvDel
            elif sender.tag == 320: tvdel = self.botTvDel
            if tvdel:
                data = tvdel.text
                if data:
                    parent().copy_to_clipboard(data)
        utils.boilerplate.vc_highlight_button_then_do(self, sender, DoIt)

        
    @objc_method
    def onPickAddress_(self, sender : ObjCInstance) -> None:
        def DoIt() -> None:
            def pickedAddress(entry) -> None:
                data = utils.nspy_get_byname(self, 'data')
                pubkey = None
                try:
                    pubkey =  parent().wallet.get_public_key(entry.address)
                except:
                    pass
                if pubkey is not None and not isinstance(pubkey,str):
                    pubkey = pubkey.to_ui_string()
                data = DialogData(entry.address, pubkey)
                utils.nspy_put_byname(self, data, 'data')
                # refresh will be auto-called as a result of viewWillAppear
            addresses.present_modal_address_picker(pickedAddress, self)
        utils.boilerplate.vc_highlight_button_then_do(self, sender, DoIt)

    @objc_method
    def onCloseKeyboard_(self, sender : ObjCInstance) -> None:
        self.view.endEditing_(True)

    @objc_method
    def onExecuteBut_(self, sender : ObjCInstance) -> None:
        def DoIt() -> None:
            if sender.tag == 1000:  # sign/encrypt
                if self.mode == SignVerify:
                    self.doSign()
                else:
                    self.doEncrypt()
            elif sender.tag == 2000: # verify/decrypt
                if self.mode == SignVerify:
                    self.doVerify()
                else:
                    self.doDecrypt()
        self.onCloseKeyboard_(None) # force close keyboard
        utils.boilerplate.vc_highlight_button_then_do(self, sender, DoIt)

    @objc_method
    def doSign(self) -> None:
        addrtf = self.tf
        address = str(addrtf.text).strip()
        message = str(self.topTvDel.text)
        signatureTvDel = self.botTvDel
        try:
            print ("address = ", address)
            addr = Address.from_string(address)
        except:
            parent().show_error(_('Invalid Bitcoin Cash address.'))
            return
        if addr.kind != addr.ADDR_P2PKH:
            msg_sign = _("Signing with an address actually means signing with the corresponding "
                        "private key, and verifying with the corresponding public key. The "
                        "address you have entered does not have a unique public key, so these "
                        "operations cannot be performed.") + '\n\n' + \
                       _('The operation is undefined. Not just in Electron Cash, but in general.')
            parent().show_message(_('Cannot sign messages with this type of address.') + '\n\n' + msg_sign)
            return
        if not parent().wallet:
            return
        if parent().wallet.is_watching_only():
            parent().show_message(_('This is a watching-only wallet.'))
            return
        if not parent().wallet.is_mine(addr):
            parent().show_message(_('Address not in wallet.'))
            return
        
        def onPw(password : str) -> None:
            try:
                signed = parent().wallet.sign_message(addr, message, password)
            except:
                parent().show_error(str(sys.exc_info()[1]))
                return
            signatureTvDel.text = base64.b64encode(signed).decode('ascii')
            parent().show_message(_("The signature for the provided message has been pasted into the signature text box."),title=_("Success"))

        parent().prompt_password_if_needed_asynch(onPw, vc = self)
    
    @objc_method
    def doVerify(self) -> None:
        addrtf = self.tf
        address_str = str(addrtf.text).strip()
        message = str(self.topTvDel.text)
        signature = str(self.botTvDel.text).strip()
        
        if not signature:
            parent().show_message(_("Please provide both a signature and a message to verify"))
            return
        
        try:
            address = Address.from_string(address_str)
        except:
            parent().show_error(_('Invalid Bitcoin Cash address.'))
            return
        message = message.encode('utf-8')
        try:
            # This can raise on invalid base64
            sig = base64.b64decode(signature)
            verified = bitcoin.verify_message(address, sig, message) # this raises too on failure
        except:
            verified = False

        if verified:
            parent().show_message(_("Signature verified"), title=_("Success"))
        else:
            parent().show_error(_("Wrong signature"))
    
    @objc_method
    def doEncrypt(self) -> None:
        message = self.topTvDel.text
        message = message.encode('utf-8')
        pubkey = self.tf.text.strip()
        encryptedTVDel = self.botTvDel
        
        if not pubkey:
            parent().show_message(_("Please provide a public key or select an address"))
            return
        
        try:
            encrypted = bitcoin.encrypt_message(message, pubkey)
            encryptedTVDel.text = str(encrypted.decode('ascii'))
        except BaseException as e:
            traceback.print_exc(file=sys.stdout)
            parent().show_error(str(e))

    
    @objc_method
    def doDecrypt(self) -> None:
        if not parent().wallet: return
        if parent().wallet.is_watching_only():
            parent().show_message(_('This is a watching-only wallet.'))
            return
        
        cyphertext = self.botTvDel.text
        pubkey = self.tf.text.strip()
        
        if not cyphertext:
            parent().show_message(_("Please provide cyphertext to decrypt"))
            return
        
        if not pubkey:
            parent().show_message(_("Please provide a public key to use for decryption"))
            return            
        
        def onPw(password: str) -> None:
            try:
                plaintext = parent().wallet.decrypt_message(pubkey, cyphertext, password)
                if plaintext is None:
                    raise BaseException('Unspecified failure in decoding cyphertext')
                plaintext = plaintext.decode('utf-8')
            except BaseException as e:
                err = str(e)
                if "Incorrect password" in err:
                    err = _("The specified public key cannot decrypt this cyphertext.\nPlease specify the correct key to decrypt.")
                parent().show_error(err)
                return
            self.topTvDel.text = plaintext
            parent().show_message(_("The message has been successfully decrypted"), title=_("Success"))
        parent().prompt_password_if_needed_asynch(onPw, vc = self) 

def Create_SignVerify_VC(address, pubkey = None) -> ObjCInstance:
    vc = SignDecryptVC.alloc()
    utils.nspy_put_byname(vc, DialogData(address, pubkey), 'data')
    vc.initWithMode_(SignVerify).autorelease()
    return vc

def Create_EncryptDecrypt_VC(address, pubkey) -> ObjCInstance:
    vc = SignDecryptVC.alloc()
    utils.nspy_put_byname(vc, DialogData(address, pubkey), 'data')
    vc.initWithMode_(EncryptDecrypt).autorelease()
    return vc
