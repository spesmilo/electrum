from PyQt5.QtCore import pyqtProperty, pyqtSignal, pyqtSlot, QObject

from electrum.logging import get_logger
from electrum.i18n import _
from electrum.util import profiler

# container for satoshi amounts that can be passed around more
# easily between python, QML-property and QML-javascript contexts
# QML 'int' is 32 bit signed, so overflows on satoshi amounts
# QML 'quint64' and 'qint64' can be used, but this breaks
# down when passing through property bindings
# should also capture millisats amounts and MAX/'!' indicators
# and (unformatted) string representations

class QEAmount(QObject):
    _logger = get_logger(__name__)

    def __init__(self, *, amount_sat: int = 0, amount_msat: int = 0, is_max: bool = False, parent=None):
        super().__init__(parent)
        self._amount_sat = amount_sat
        self._amount_msat = amount_msat
        self._is_max = is_max

    valueChanged = pyqtSignal()

    @pyqtProperty('qint64', notify=valueChanged)
    def satsInt(self):
        return self._amount_sat

    @pyqtProperty('qint64', notify=valueChanged)
    def msatsInt(self):
        return self._amount_msat

    @pyqtProperty(str, notify=valueChanged)
    def satsStr(self):
        return str(self._amount_sat)

    @pyqtProperty(str, notify=valueChanged)
    def msatsStr(self):
        return str(self._amount_msat)

    @pyqtProperty(bool, notify=valueChanged)
    def isMax(self):
        return self._is_max

    def __eq__(self, other):
        if isinstance(other, QEAmount):
            return self._amount_sat == other._amount_sat and self._amount_msat == other._amount_msat and self._is_max == other._is_max
        elif isinstance(other, int):
            return self._amount_sat == other
        elif isinstance(other, str):
            return self.satsStr == other

        return False

    def __str__(self):
        s = _('Amount')
        if self._is_max:
            return '%s(MAX)' % s
        return '%s(sats=%d, msats=%d)' % (s, self._amount_sat, self._amount_msat)
