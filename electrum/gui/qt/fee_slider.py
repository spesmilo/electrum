import threading

from PyQt6.QtGui import QCursor
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QSlider, QToolTip, QComboBox

from electrum.i18n import _

class FeeComboBox(QComboBox):

    def __init__(self, fee_slider):
        QComboBox.__init__(self)
        self.config = fee_slider.config
        self.fee_slider = fee_slider
        self.addItems([_('Static'), _('ETA'), _('Mempool')])
        self.setCurrentIndex((2 if self.config.use_mempool_fees() else 1) if self.config.is_dynfee() else 0)
        self.currentIndexChanged.connect(self.on_fee_type)
        self.help_msg = '\n'.join([
            _('Static: the fee slider uses static values'),
            _('ETA: fee rate is based on average confirmation time estimates'),
            _('Mempool based: fee rate is targeting a depth in the memory pool')
            ]
        )

    def on_fee_type(self, x):
        self.config.FEE_EST_USE_MEMPOOL = (x == 2)
        self.config.FEE_EST_DYNAMIC = (x > 0)
        self.fee_slider.update()


class FeeSlider(QSlider):

    def __init__(self, window, config, callback):
        QSlider.__init__(self, Qt.Orientation.Horizontal)
        self.config = config
        self.window = window
        self.callback = callback
        self.dyn = False
        self.lock = threading.RLock()
        self.update()
        self.valueChanged.connect(self.moved)
        self._active = True

    def get_fee_rate(self, pos):
        if self.dyn:
            fee_rate = self.config.depth_to_fee(pos) if self.config.use_mempool_fees() else self.config.eta_to_fee(pos)
        else:
            fee_rate = self.config.static_fee(pos)
        return fee_rate

    def moved(self, pos):
        with self.lock:
            fee_rate = self.get_fee_rate(pos)
            tooltip = self.get_tooltip(pos, fee_rate)
            QToolTip.showText(QCursor.pos(), tooltip, self)
            self.setToolTip(tooltip)
            self.callback(self.dyn, pos, fee_rate)

    def get_tooltip(self, pos, fee_rate):
        mempool = self.config.use_mempool_fees()
        target, estimate = self.config.get_fee_text(pos, self.dyn, mempool, fee_rate)
        if self.dyn:
            return _('Target') + ': ' + target + '\n' + _('Current rate') + ': ' + estimate
        else:
            return _('Fixed rate') + ': ' + target + '\n' + _('Estimate') + ': ' + estimate

    def get_dynfee_target(self):
        if not self.dyn:
            return ''
        pos = self.value()
        fee_rate = self.get_fee_rate(pos)
        mempool = self.config.use_mempool_fees()
        target, estimate = self.config.get_fee_text(pos, True, mempool, fee_rate)
        return target

    def update(self):
        with self.lock:
            self.dyn = self.config.is_dynfee()
            mempool = self.config.use_mempool_fees()
            maxp, pos, fee_rate = self.config.get_fee_slider(self.dyn, mempool)
            self.setRange(0, maxp)
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
