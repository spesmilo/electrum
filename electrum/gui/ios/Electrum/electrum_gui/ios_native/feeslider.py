# Copyright (C) 2018 Calin Culianu <calin.culianu@gmail.com>
# Copyright (C) 2018 Electrum Technologies GmbH
#
# This file is licensed under the MIT license. See LICENCE file for more information.
#
from electrum.i18n import _
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
        # utils.NSLog("Fee Slider init!")
        self = ObjCInstance(send_super(__class__, self, 'init'))
        if self is not None: self.commonInit()
        return self

    @objc_method
    def commonInit(self) -> None:
        self.dyn = False
        self.addTarget_action_forControlEvents_(self, SEL(b'onMoved'), UIControlEventValueChanged)
        self.setMinimumTrackImage_forState_(
            UIImage.imageNamed_("slider_track_left").resizableImageWithCapInsets_resizingMode_(UIEdgeInsetsZero,
                                                                                               UIImageResizingModeStretch),
            UIControlStateNormal)
        self.setMaximumTrackImage_forState_(
            UIImage.imageNamed_("slider_track_right").resizableImageWithCapInsets_resizingMode_(UIEdgeInsetsZero,
                                                                                                UIImageResizingModeStretch),
            UIControlStateNormal)
        self.setThumbImage_forState_(UIImage.imageNamed_("slider_knob"), UIControlStateNormal)
        self.reset()

    @objc_method
    def initWithCoder_(self, coder: ObjCInstance) -> ObjCInstance:
        # utils.NSLog("Fee Slider initWithCoder!")
        self = ObjCInstance(send_super(__class__, self, 'initWithCoder:', coder.ptr, argtypes=[objc_id]))
        if self is not None: self.commonInit()
        return self

    @objc_method
    def dealloc(self) -> None:
        # utils.NSLog("Fee Slider dealloc!")
        utils.remove_all_callbacks(self)
        self.dyn = None
        self.feeStep = None
        send_super(__class__, self, 'dealloc')

    @objc_method
    def onMoved(self) -> None:
        dyn = config().is_dynfee()
        mempool = config().use_mempool_fees()

        pos = int(self.value)
        print("dyn", dyn, "mempool", mempool, "pos", pos)
        if dyn:
            fee_rate = config().depth_to_fee(pos) if mempool else config().eta_to_fee(pos)
        else:
            fee_rate = config().static_fee(pos)

        self.feeRate = int(fee_rate or 0)
        cb = utils.get_callback(self, 'callback')
        cb(self.dyn, pos, self.feeRate)

    @objc_method
    def getToolTip(self, pos: int) -> ObjCInstance:
        dyn = config().is_dynfee()
        mempool = config().use_mempool_fees()
        target, estimate = config().get_fee_text(pos, dyn, mempool, self.feeRate)
        if dyn:
            tooltip = _('Target') + ': ' + target + '\n' + _('Current rate') + ': ' + estimate
        else:
            tooltip = _('Fixed rate') + ': ' + target + '\n' + _('Estimate') + ': ' + estimate
        return ns_from_py(tooltip)

    @objc_method
    def reset(self):
        mempool = config().use_mempool_fees()
        maxp, pos, fee_rate = config().get_fee_slider(self.dyn, mempool)
        self.dyn = config().is_dynfee()
        self.feeStep = 20 / 10
        self.feeRate = fee_rate
        self.minimumValue = 0.0
        self.maximumValue = maxp
        self.value = float(pos)
