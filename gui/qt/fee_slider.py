
from electroncash.i18n import _

from PyQt5.QtGui import *
from PyQt5.QtCore import *
from PyQt5.QtWidgets import QSlider, QToolTip

import threading

class FeeSlider(QSlider):

    def __init__(self, window, config, callback):
        QSlider.__init__(self, Qt.Horizontal)
        self.config = config
        self.window = window
        self.callback = callback
        self.dyn = False
        self.lock = threading.RLock()
        self.update()
        self.valueChanged.connect(self.moved)

    def moved(self, pos):
        with self.lock:
            fee_rate = self.config.dynfee(pos) if self.dyn else self.config.static_fee(pos)
            tooltip = self.get_tooltip(pos, fee_rate)
            QToolTip.showText(QCursor.pos(), tooltip, self)
            self.setToolTip(tooltip)
            self.callback(self.dyn, pos, fee_rate)

    def get_tooltip(self, pos, fee_rate):
        from electroncash.util import fee_levels
        rate_str = self.window.format_fee_rate(fee_rate) if fee_rate else _('unknown')
        if self.config.has_custom_fee_rate():
            tooltip = _('Custom rate: ') + rate_str
        elif self.dyn:
            tooltip = fee_levels[pos] + '\n' + rate_str
        else:
            tooltip = _('Fixed rate: ') + rate_str
            if self.config.has_fee_estimates():
                i = self.config.reverse_dynfee(fee_rate)
                #tooltip += '\n' + (_('Low fee') if i < 0 else 'Within %d blocks'%i)
        return tooltip

    def update(self):
        if self.config.has_custom_fee_rate():
            self.update_has_custom_fee_rate()
        else:
            self.update_no_custom_fee_rate()

    def update_no_custom_fee_rate(self):
        with self.lock:
            self.fee_step = self.config.max_fee_rate() / 10
            fee_rate = self.config.fee_per_kb()
            pos = min(fee_rate / self.fee_step, 10)
            self.setRange(0, 9)
            self.setValue(pos)
            self.setEnabled(True)
            tooltip = self.get_tooltip(pos, fee_rate)
            self.setToolTip(tooltip)

    # configuraing this as is done is here still required, can't just set range 0,0 to deactivate.
    # chose to make this a seperate function from update for easier code maintainence
    def update_has_custom_fee_rate(self):
        with self.lock:
            self.fee_step = self.config.max_fee_rate() / 10
            fee_rate = self.config.fee_per_kb()
            pos = max(0,min(fee_rate / self.fee_step, 1))
            self.setRange(0, 1)
            self.setValue(pos)
            self.setEnabled(False)
            tooltip = self.get_tooltip(pos, fee_rate)
            self.setToolTip(tooltip)
