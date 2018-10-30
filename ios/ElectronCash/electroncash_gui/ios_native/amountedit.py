#
# This file is:
#     Copyright (C) 2018 Calin Culianu <calin.culianu@gmail.com>
#
# MIT License
#
from electroncash.i18n import _
from .custom_objc import *
from .uikit_bindings import *
from . import utils
from . import gui

from decimal import Decimal
from electroncash.util import format_satoshis_plain, format_satoshis

def parent():
    return gui.ElectrumGui.gui

def config():
    return parent().config

# can use utils.register_callback() for this object.
# callbacks:
#   'textChanged' == func(amountEdit : BTCAmountEdit) -> None
#   'shortcut'    == func() -> None
#   'frozen'      == func() -> None
#   'edited'      == func(amountEdit : BTCAmountEdit) -> None

class BTCAmountEdit(UITextField):
    isInt = objc_property()
    isShortcut = objc_property()
    modified = objc_property()
    unitLabel = objc_property()
    fixedUnitLabelWidth = objc_property()

    @objc_method
    def init(self) -> ObjCInstance:
        self = ObjCInstance(send_super(__class__, self, 'init'))
        if self is not None:
            self.commonInit()
        return self

    @objc_method
    def initWithCoder_(self, coder : ObjCInstance) -> ObjCInstance:
        self = ObjCInstance(send_super(__class__, self, 'initWithCoder:', coder.ptr, argtypes=[objc_id]))
        if self is not None:
            self.commonInit()
        return self

    @objc_method
    def dealloc(self) -> None:
        # cleanup code here...
        self.isInt = None
        self.isShortcut = None
        self.modified = None
        self.unitLabel = None
        self.fixedUnitLabelWidth = None
        utils.remove_all_callbacks(self)
        send_super(__class__, self, 'dealloc')

    @objc_method
    def baseUnit(self) -> ObjCInstance:
        return ns_from_py(parent().base_unit())

    @objc_method
    def decimalPoint(self) -> int:
        return parent().get_decimal_point()

    @objc_method
    def commonInit(self):
        self.addTarget_action_forControlEvents_(self, SEL(b'numbify'), UIControlEventEditingDidEnd)
        self.addTarget_action_forControlEvents_(self, SEL(b'edited'), UIControlEventEditingChanged)        
        self.isInt = False
        self.isShortcut = False
        self.modified = False
        
    @objc_method
    def setUseUnitLabel_(self, b : bool) -> None:
        if b:
            f = CGRectMake(0,0,50,20)
            self.unitLabel = UILabel.alloc().initWithFrame_(f).autorelease()
            self.unitLabel.numberOfLines = 0
            self.unitLabel.adjustsFontSizeToFitWidth = True
            self.unitLabel.minimumScaleFactor = 0.1
            self.unitLabel.lineBreakMode = NSLineBreakByTruncatingTail
            self.unitLabel.textAlignment = NSTextAlignmentRight
            self.unitLabel.tag = 1
            spacer = UIView.alloc().initWithFrame_(CGRectMake(60,0,10,20)).autorelease()
            spacer.tag = 2
            sup = UIView.alloc().initWithFrame_(CGRectMake(0,0,60,20)).autorelease()
            sup.addSubview_(spacer)
            sup.addSubview_(self.unitLabel)
            sup.backgroundColor = UIColor.clearColor
            spacer.backgroundColor = UIColor.clearColor
            self.autosizeUnitLabel()
            self.leftView = sup
            self.leftViewMode = UITextFieldViewModeAlways
        else:
            self.unitLabel = None
            self.leftView = None
            self.leftViewMode = UITextFieldViewModeNever

    @objc_method
    def hasUnitLabel(self) -> bool:
        return bool(self.unitLabel)
    
    @objc_method
    def autosizeUnitLabel(self) -> None:
        if self.unitLabel:
            self.unitLabel.font = self.font
            self.unitLabel.text = self.baseUnit()
            self.unitLabel.textColor = self.textColor
            if not isinstance(self.fixedUnitLabelWidth, (float, int, NSNumber)):
                # unit label has dynamic size based on content, with a 10 pix padding
                f = self.unitLabel.frame
                f.size = self.unitLabel.attributedText.size()
                self.unitLabel.frame = f
                supf = f
                supf.size.width += 10.0 # 10 pix padding on right
                self.unitLabel.superview().frame = supf
                spacf = CGRectMake(f.size.width,0.0,10.0,f.size.height)
                self.unitLabel.superview().viewWithTag_(2).frame = spacf
            else:
                # unit label has a fixed size, with a 10 pix padding
                w = py_from_ns(self.fixedUnitLabelWidth)
                sup = self.unitLabel.superview()
                spac = sup.viewWithTag_(2)
                sz = self.unitLabel.attributedText.size()
                sz.width = w
                f = CGRectMake(0,0,w-10,sz.height)
                self.unitLabel.frame = f
                spac.frame = CGRectMake(f.size.width, 0, 10.0, sz.height)
                sup.frame = CGRectMake(0,0,w,sz.height)

    @objc_method
    def leftViewRectForBounds_(self, bounds : CGRect) -> CGRect:
        r = send_super(__class__, self, 'leftViewRectForBounds:', bounds, argtypes=[CGRect], restype=CGRect)
        if self.unitLabel:
            sz = self.unitLabel.superview().bounds.size
            return CGRectOffset(r, bounds.size.width - sz.width, 0)
        return r
    
    @objc_method
    def clearButtonRectForBounds_(self, bounds : CGRect) -> CGRect:
        r =  send_super(__class__, self, 'clearButtonRectForBounds:', bounds, argtypes=[CGRect], restype=CGRect)   
        if self.unitLabel:
            sz = self.unitLabel.superview().bounds.size
            return CGRectOffset(r, -sz.width, 0)
        return r

    @objc_method
    def editingRectForBounds_(self, bounds : CGRect) -> CGRect:
        r = bounds
        r.origin.x = 0
        if self.unitLabel:
            sz = self.unitLabel.superview().bounds.size
            r.size.width -= (20 + sz.width)
        return r
        
    @objc_method
    def textRectForBounds_(self, bounds : CGRect) -> CGRect:
        rect = bounds
        rect.origin.x = 0
        if self.unitLabel:
            sz = self.unitLabel.superview().bounds.size
            rect.size.width -= (20 + sz.width)
        return rect
    
    @objc_method
    def setFont_(self, font) -> None:
        send_super(__class__, self, 'setFont:', font.ptr, argtypes=[objc_id])
        self.autosizeUnitLabel()
        
    @objc_method
    def setText_(self, text : ObjCInstance) -> None:
        send_super(__class__, self, 'setText:', ns_from_py(text).ptr, argtypes=[objc_id])
        self.autosizeUnitLabel()
    
    @objc_method
    def setFrozen_(self, b : bool) -> None:
        # NB: we now implement this in ObjC in UIKitExtras.m
        send_super(__class__, self, 'setFrozen:', bool(b), argtypes=[c_bool])
        utils.get_callback(self, 'frozen')()

    @objc_method
    def numbify(self):
        text = str(self.text).strip()
        #if text == '!':
        #    #self.shortcut.emit()
        #    utils.get_callback(self, 'shortcut')()
        #    return
        #pos = self.cursorPosition()
        chars = '0123456789'
        if not self.isInt: chars +='.'
        s = ''.join([i for i in text if i in chars])
        if not self.isInt:
            if '.' in s:
                p = s.find('.')
                s = s.replace('.','')
                s = s[:p] + '.' + s[p:p+self.decimalPoint()]
        self.text = s
        utils.get_callback(self, 'textChanged')(self)
        # setText sets Modified to False.  Instead we want to remember
        # if updates were because of user modification.
        #self.setModified(self.hasFocus())
        #self.setCursorPosition(pos)

    @objc_method
    def formatPlain_(self, amount : ObjCInstance) -> ObjCInstance:
        amount = int(amount)
        return ns_from_py(format_satoshis_plain(amount, self.decimalPoint()))
        #return ns_from_py(format_satoshis(amount, False, parent().num_zeros, self.decimalPoint()))
        
    @objc_method
    def isModified(self) -> bool:
        return self.modified

    @objc_method
    def edited(self) -> None:
        self.modified = True
        utils.get_callback(self, 'edited')(self)

    @objc_method
    def getAmount(self) -> ObjCInstance:
        try:
            x = Decimal(str(self.text))
        except:
            return None
        p = pow(10, self.decimalPoint())
        return ns_from_py( int( p * x ) ) if x > 0 else None

    @objc_method
    def setAmount_(self, amount : ObjCInstance) -> None:
        self.modified = False
        if amount is None:
            self.text = ""  # Text(" ") # Space forces repaint in case units changed
        else:
            self.text = self.formatPlain_(amount)
        self.numbify()

class FiatAmountEdit(BTCAmountEdit):
    
    @objc_method
    def baseUnit(self) -> ObjCInstance:
        return ns_from_py(parent().daemon.fx.get_currency() if parent().daemon and parent().daemon.fx and parent().daemon.fx.is_enabled() else "USD")
    
    @objc_method
    def decimalPoint(self) -> int:
        return 2  # fiat always has precision of 2

    @objc_method
    def formatPlain_(self, amount : int) -> ObjCInstance:
        return ns_from_py(format_satoshis(amount, is_diff=False, num_zeros=2, decimal_point=self.decimalPoint()))

class BTCkBEdit(BTCAmountEdit):
    @objc_method
    def baseUnit(self) -> ObjCInstance:
        bu = ObjCInstance(send_super(__class__, self, 'baseUnit'))
        return ns_from_py(py_from_ns(bu) + '/kB')
