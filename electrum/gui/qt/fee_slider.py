import threading
from typing import Callable, Optional

from PyQt6.QtGui import QCursor
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QSlider, QToolTip, QComboBox, QWidget

from electrum.i18n import _
from electrum.fee_policy import FeeMethod, FeePolicy
from electrum.network import Network


class FeeComboBox(QComboBox):

    def __init__(self, fee_slider: 'FeeSlider'):
        QComboBox.__init__(self)
        self.fee_slider = fee_slider
        self.addItems([x.name_for_GUI() for x in FeeMethod.slider_values()])
        index = FeeMethod.slider_index_of_method(self.fee_slider.fee_policy.method)
        self.setCurrentIndex(index)
        self.currentIndexChanged.connect(self.on_fee_type)
        self.help_msg = '\n'.join([
            _('Feerate: the fee slider uses static feerate values'),
            _('ETA: fee rate is based on average confirmation time estimates'),
            _('Mempool based: fee rate is targeting a depth in the memory pool')
            ]
        )

    def on_fee_type(self, x):
        method = FeeMethod.slider_values()[x]
        self.fee_slider.fee_policy.set_method(method)
        self.fee_slider.update(is_initialized=True)


class FeeSlider(QSlider):

    def __init__(
        self,
        *,
        parent: Optional[QWidget],
        network: Network,
        fee_policy: FeePolicy,
        callback: Callable[[Optional[int]], None],
    ):
        QSlider.__init__(self, Qt.Orientation.Horizontal, parent=parent)
        self.network = network
        self.callback = callback
        self.fee_policy = fee_policy
        self.lock = threading.RLock()
        self.update(is_initialized=False)
        self.valueChanged.connect(self.moved)
        self._active = True

    @property
    def dyn(self) -> bool:
        return self.fee_policy.use_dynamic_estimates

    def get_policy(self) -> FeePolicy:
        return self.fee_policy

    def moved(self, pos):
        with self.lock:
            if self.fee_policy.method == FeeMethod.FIXED:
                return
            self.fee_policy.set_value_from_slider_pos(pos)
            fee_rate = self.fee_policy.fee_per_kb(self.network)
            tooltip = self.fee_policy.get_tooltip(self.network)
            QToolTip.showText(QCursor.pos(), tooltip, self)
            self.setToolTip(tooltip)
            self.callback(fee_rate)

    def update(self, *, is_initialized: bool = True):
        with self.lock:
            if self.fee_policy.method == FeeMethod.FIXED:
                return
            pos = self.fee_policy.get_slider_pos()
            maxp = self.fee_policy.get_slider_max()
            self.setRange(0, maxp)
            self.setValue(pos)
            if is_initialized:
                self.moved(pos)

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
