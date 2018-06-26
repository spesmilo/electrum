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
from typing import Callable

def parent():
    return gui.ElectrumGui.gui

def config():
    return parent().config

# uses utils.add_callback mechanism
# Callbacks: 'callback' ==  func(bool,int,int) -> None
class FeeSlider(UISlider):

    dyn = objc_property()
    feeStep = objc_property()
    feeRate = objc_property()

    @objc_method
    def init(self) -> ObjCInstance:
        #utils.NSLog("Fee Slider init!")
        self = ObjCInstance(send_super(__class__, self, 'init'))
        if self is not None: self.commonInit()
        return self
    
    @objc_method
    def commonInit(self) -> None:
        self.dyn = False
        self.addTarget_action_forControlEvents_(self, SEL(b'onMoved'), UIControlEventValueChanged)
        self.setMinimumTrackImage_forState_(UIImage.imageNamed_("slider_track_left").resizableImageWithCapInsets_resizingMode_(UIEdgeInsetsZero, UIImageResizingModeStretch),
                                            UIControlStateNormal)
        self.setMaximumTrackImage_forState_(UIImage.imageNamed_("slider_track_right").resizableImageWithCapInsets_resizingMode_(UIEdgeInsetsZero, UIImageResizingModeStretch),
                                            UIControlStateNormal)
        self.setThumbImage_forState_(UIImage.imageNamed_("slider_knob"), UIControlStateNormal)
        self.reset()
    
    @objc_method
    def initWithCoder_(self, coder : ObjCInstance) -> ObjCInstance:
        #utils.NSLog("Fee Slider initWithCoder!")
        self = ObjCInstance(send_super(__class__, self, 'initWithCoder:', coder.ptr, argtypes=[objc_id]))
        if self is not None: self.commonInit()
        return self
    
    @objc_method
    def dealloc(self) -> None:
        #utils.NSLog("Fee Slider dealloc!")
        utils.remove_all_callbacks(self)
        self.dyn = None
        self.feeStep = None
        send_super(__class__, self, 'dealloc')

    @objc_method
    def onMoved(self) -> None:
        pos = int(self.value)
        self.feeRate = int(config().dynfee(pos) if self.dyn else config().static_fee(pos))
        #tooltip = self.get_tooltip(pos, fee_rate)
        #QToolTip.showText(QCursor.pos(), tooltip, self)
        #self.setToolTip(tooltip)
        utils.get_callback(self,'callback')(self.dyn, pos, self.feeRate)
        #print("ToolTip: %s"%(str(self.getToolTip(pos, fee_rate))))

    @objc_method
    def getToolTip(self, pos : int, fee_rate : int) -> ObjCInstance:
        from electroncash.util import fee_levels
        pos = pos if pos is not None and pos >= 0 else int(self.value)
        fee_rate = fee_rate if fee_rate is not None and fee_rate >= 0 else int(self.feeRate)
        rate_str = parent().format_fee_rate(fee_rate) if fee_rate else _('unknown')
        if self.dyn:
            tooltip = fee_levels[pos] + '\n' + rate_str
        else:
            tooltip = 'Fixed rate: ' + rate_str
            if config().has_fee_estimates():
                i = config().reverse_dynfee(fee_rate)
                #tooltip += '\n' + (_('Low fee') if i < 0 else 'Within %d blocks'%i)
        return ns_from_py(tooltip)

    @objc_method
    def reset(self):
        self.feeStep = config().max_fee_rate() / 10
        self.feeRate = int(config().fee_per_kb())
        pos = int(min(self.feeRate / self.feeStep, 9.0))
        self.minimumValue = 0.0
        self.maximumValue = 9.0        
        self.value = float(pos)
        #print("ToolTip: %s"%(str(self.getToolTip(pos, fee_rate))))
