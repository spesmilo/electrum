import threading

from PyQt6.QtGui import QCursor
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QSlider, QToolTip, QComboBox

from electrum.i18n import _
from electrum.fee_policy import FeeMethod


class FeeComboBox(QComboBox):

    def __init__(self, fee_slider):
        QComboBox.__init__(self)
        self.fee_slider = fee_slider
        self.addItems([_('Static'), _('ETA'), _('Mempool')])
        self.setCurrentIndex(int(self.fee_slider.fee_policy.method) - 1)
        self.currentIndexChanged.connect(self.on_fee_type)
        self.help_msg = '\n'.join([
            _('Static: the fee slider uses static values'),
            _('ETA: fee rate is based on average confirmation time estimates'),
            _('Mempool based: fee rate is targeting a depth in the memory pool')
            ]
        )

    def on_fee_type(self, x):
        method = [FeeMethod.STATIC, FeeMethod.ETA, FeeMethod.MEMPOOL][x]
        self.fee_slider.fee_policy.set_method(method)
        self.fee_slider.update()


class FeeSlider(QSlider):

    def __init__(self, window, fee_policy, callback):
        QSlider.__init__(self, Qt.Orientation.Horizontal)
        self.window = window
        self.network = window.network
        self.callback = callback
        self.fee_policy = fee_policy
        self.lock = threading.RLock()
        self.update()
        self.valueChanged.connect(self.moved)
        self._active = True

    @property
    def dyn(self):
        return self.fee_policy.use_dynamic_estimates

    def get_policy(self):
        return self.fee_policy

    def moved(self, pos):
        with self.lock:
            self.fee_policy.set_value_from_slider_pos(pos)
            fee_rate = self.fee_policy.fee_per_kb(self.network)
            tooltip = self.fee_policy.get_tooltip(self.network)
            QToolTip.showText(QCursor.pos(), tooltip, self)
            self.setToolTip(tooltip)
            self.callback(self.dyn, pos, fee_rate)

    def get_dynfee_target(self):
        if not self.dyn:
            return ''
        target = self.fee_policy.get_target_text()
        return target

    def update(self):
        with self.lock:
            maxp, pos = self.fee_policy.get_slider()
            self.setRange(0, maxp)
            self.setValue(pos)
            tooltip = self.fee_policy.get_tooltip(self.network)
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
