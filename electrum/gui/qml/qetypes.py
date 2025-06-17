from PyQt6.QtCore import pyqtProperty, pyqtSignal, pyqtSlot, QObject

from electrum.logging import get_logger
from electrum.i18n import _


class QEAmount(QObject):
    """Container for bitcoin amounts that can be passed around more
       easily between python, QML-property and QML-javascript contexts.
       Note: millisat and sat amounts are not synchronized!

       QML type 'int' in property definitions is 32 bit signed, so will overflow easily
       on (milli)satoshi amounts! 'int' in QML-javascript seems to be larger than 32 bit, and
       can be used to store q(u)int64 types.

       QML 'quint64' and 'qint64' can be used, but be aware these will in some cases be downcast
       by QML to 'int' (e.g. when using the property in a property binding, _even_ when a binding
       is done between two q(u)int64 properties (at least up until Qt6.4))
    """

    _logger = get_logger(__name__)

    def __init__(self, *, amount_sat: int = 0, amount_msat: int = 0, is_max: bool = False, from_invoice=None, parent=None):
        super().__init__(parent)
        self._amount_sat = int(amount_sat) if amount_sat is not None else None
        self._amount_msat = int(amount_msat) if amount_msat is not None else None
        self._is_max = is_max
        if from_invoice:
            inv_amt = from_invoice.get_amount_msat()
            if inv_amt == '!':
                self._is_max = True
            elif inv_amt is not None:
                self._amount_msat = int(inv_amt)
                self._amount_sat = int(from_invoice.get_amount_sat())

    valueChanged = pyqtSignal()

    @pyqtProperty('qint64', notify=valueChanged)
    def satsInt(self):
        if self._amount_sat is None:  # should normally be defined when accessing this property
            self._logger.warning('amount_sat is undefined, returning 0')
            return 0
        return self._amount_sat

    @satsInt.setter
    def satsInt(self, sats):
        if self._amount_sat != sats:
            self._amount_sat = sats
            self.valueChanged.emit()

    @pyqtProperty('qint64', notify=valueChanged)
    def msatsInt(self):
        if self._amount_msat is None:  # should normally be defined when accessing this property
            self._logger.warning('amount_msat is undefined, returning 0')
            return 0
        return self._amount_msat

    @msatsInt.setter
    def msatsInt(self, msats):
        if self._amount_msat != msats:
            self._amount_msat = msats
            self.valueChanged.emit()

    @pyqtProperty(str, notify=valueChanged)
    def satsStr(self):
        return str(self._amount_sat)

    @pyqtProperty(str, notify=valueChanged)
    def msatsStr(self):
        return str(self._amount_msat)

    @pyqtProperty(bool, notify=valueChanged)
    def isMax(self):
        return self._is_max

    @isMax.setter
    def isMax(self, ismax):
        if self._is_max != ismax:
            self._is_max = ismax
            self.valueChanged.emit()

    @pyqtProperty(bool, notify=valueChanged)
    def isEmpty(self):
        return not(self._is_max or self._amount_sat or self._amount_msat)

    @pyqtSlot()
    def clear(self):
        self._amount_sat = 0
        self._amount_msat = 0
        self._is_max = False
        self.valueChanged.emit()

    def copyFrom(self, amount):
        if not amount:
            self._logger.warning('copyFrom with None argument. assuming 0')  # TODO
            amount = QEAmount()
        self.satsInt = amount.satsInt
        self.msatsInt = amount.msatsInt
        self.isMax = amount.isMax

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

    def __repr__(self):
        return f"<QEAmount max={self._is_max} sats={self._amount_sat} msats={self._amount_msat} empty={self.isEmpty}>"
