from electrum.i18n import _

import PyQt4
from PyQt4.QtGui import *
from PyQt4.QtCore import *
import PyQt4.QtCore as QtCore

class FeeSlider(QSlider):

    def __init__(self, window, config, callback):
        QSlider.__init__(self, Qt.Horizontal)
        self.config = config
        self.fee_step = self.config.max_fee_rate() / 10
        self.window = window
        self.callback = callback
        self.setToolTip('')
        self.update()
        self.valueChanged.connect(self.moved)

    def moved(self, pos):
        from electrum.util import fee_levels
        dyn = self.config.is_dynfee()
        fee_rate = self.config.dynfee(pos) if dyn else pos * self.fee_step
        rate_str = self.window.format_amount(fee_rate) + ' ' + self.window.base_unit() + '/kB'
        if dyn:
            tooltip = fee_levels[pos] + '\n' + rate_str
        else:
            tooltip = rate_str
            if self.config.has_fee_estimates():
                i = self.config.reverse_dynfee(fee_rate)
                tooltip += '\n' + (_('low fee') if i < 0 else 'Within %d blocks'%i)
        QToolTip.showText(QCursor.pos(), tooltip, self)
        self.callback(dyn, pos, fee_rate)

    def update(self):
        if self.config.is_dynfee():
            self.setRange(0, 4)
            self.setValue(self.config.get('fee_level', 2))
        else:
            self.setRange(1, 10)
            fee_rate = self.config.fee_per_kb()
            pos = min(fee_rate / self.fee_step, 10)
            self.setValue(pos)
