
from electrum.i18n import _

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
        self._active = True

    def moved(self, pos):
        with self.lock:
            fee_rate = self.config.dynfee(pos) if self.dyn else self.config.static_fee(pos)
            tooltip = self.get_tooltip(pos, fee_rate)
            QToolTip.showText(QCursor.pos(), tooltip, self)
            self.setToolTip(tooltip)
            self.callback(self.dyn, pos, fee_rate)

    def get_tooltip(self, pos, fee_rate):
        from electrum.util import fee_levels
        rate_str = self.window.format_fee_rate(fee_rate) if fee_rate else _('unknown')
        if self.dyn:
            tooltip = fee_levels[pos] + '\n' + rate_str
        else:
            tooltip = 'Fixed rate: ' + rate_str
            if self.config.has_fee_estimates():
                i = self.config.reverse_dynfee(fee_rate)
                tooltip += '\n' + (_('Low fee') if i < 0 else 'Within %d blocks'%i)
        return tooltip

    def update(self):
        with self.lock:
            self.dyn = self.config.is_dynfee()
            if self.dyn:
                pos = self.config.get('fee_level', 2)
                fee_rate = self.config.dynfee(pos)
                self.setRange(0, 4)
                self.setValue(pos)
            else:
                fee_rate = self.config.fee_per_kb()
                pos = self.config.static_fee_index(fee_rate)
                self.setRange(0, 9)
                self.setValue(pos)
            tooltip = self.get_tooltip(pos, fee_rate)
            self.setToolTip(tooltip)

    def activate(self):
        self._active = True
        self.setStyleSheet('')

    def deactivate(self):
        self._active = False
        # TODO it would be nice to find a platform-independent solution
        # that makes the slider look as if it was disabled
        self.setStyleSheet(
            """
            QSlider::groove:horizontal {
                border: 1px solid #999999;
                height: 8px;
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #B1B1B1, stop:1 #B1B1B1);
                margin: 2px 0;
            }

            QSlider::handle:horizontal {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #b4b4b4, stop:1 #8f8f8f);
                border: 1px solid #5c5c5c;
                width: 12px;
                margin: -2px 0;
                border-radius: 3px;
            }
            """
        )

    def is_active(self):
        return self._active
