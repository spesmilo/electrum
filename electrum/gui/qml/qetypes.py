from decimal import Decimal

from PyQt6.QtCore import pyqtProperty, pyqtSignal, pyqtSlot, QObject

from electrum.logging import get_logger
from electrum.i18n import _


class QEAmount(QObject):
    """Container for bitcoin amounts that can be passed around more
       easily between python, QML-property and QML-javascript contexts.

       QML type 'int' in property definitions is 32 bit signed, so will overflow easily
       on (milli)satoshi amounts! 'int' in QML-javascript seems to be larger than 32 bit, and
       can be used to store q(u)int64 types.

       QML 'quint64' and 'qint64' can be used, but be aware these will in some cases be downcast
       by QML to 'int' (e.g. when using the property in a property binding, _even_ when a binding
       is done between two q(u)int64 properties (at least up until Qt6.4))
    """

    _logger = get_logger(__name__)

    valueChanged = pyqtSignal()

    def __init__(self, *, amount_sat: int = None, amount_msat: int = None, is_max: bool = False, from_invoice=None, parent=None):
        super().__init__(parent)

        self._amount_msat = None
        if amount_sat is not None:
            assert isinstance(amount_sat, int)
            self._amount_msat = self._sat_to_msat(amount_sat)
        if amount_msat is not None:
            assert isinstance(amount_msat, int)
            if amount_sat is not None:
                assert amount_sat == self._msat_to_sat(amount_msat)  # if both defined, assert conversion is as expected
            self._amount_msat = amount_msat
        if is_max:
            assert amount_sat is None and amount_msat is None

        self._is_max = is_max
        if from_invoice:
            assert amount_sat is None and amount_msat is None, 'cannot combine from_invoice and amount_(m)sat'
            inv_amt = from_invoice.get_amount_msat()
            if inv_amt == '!':
                self._is_max = True
            elif inv_amt is not None:
                self._amount_msat = int(inv_amt)

    def _sat_to_msat(self, amount_sat: int | None) -> int | None:
        return amount_sat * 1000 if amount_sat is not None else None

    def _msat_to_sat(self, amount_msat: int | None) -> int | None:
        return int(Decimal(amount_msat) / 1000) if amount_msat is not None else None

    @pyqtProperty('qint64', notify=valueChanged)
    def satsInt(self):
        if self._amount_msat is None:  # should normally be defined when accessing this property
            self._logger.warning('amount_msat is undefined, returning 0')
            return 0
        return self._msat_to_sat(self._amount_msat)

    @satsInt.setter
    def satsInt(self, sats):
        msats = self._sat_to_msat(sats)
        if self._amount_msat != msats:
            self._amount_msat = msats
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
        return str(self._msat_to_sat(self._amount_msat))

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
        return not (self._is_max or self._amount_msat)

    @pyqtProperty(bool, notify=valueChanged)
    def hasMsatPrecision(self):
        return not (self._amount_msat == self._sat_to_msat(self._msat_to_sat(self._amount_msat)))

    @pyqtSlot()
    def clear(self):
        self._amount_msat = 0
        self._is_max = False
        self.valueChanged.emit()

    @pyqtSlot('QVariant')
    def copyFrom(self, amount):
        if not amount:
            self._logger.warning('copyFrom with None argument. assuming 0')  # TODO
            amount = QEAmount()

        changed = False
        if self._amount_msat != amount._amount_msat:
            self._amount_msat = amount._amount_msat
            changed = True
        if self._is_max != amount._is_max:
            self._is_max = amount._is_max
            changed = True
        if changed:
            self.valueChanged.emit()

    def __eq__(self, other):
        if isinstance(other, QEAmount):
            return self._amount_msat == other._amount_msat and self._is_max == other._is_max
        elif isinstance(other, int):
            return self._amount_msat == other

        return False

    def __str__(self):
        s = _('Amount')
        if self._is_max:
            return '%s(MAX)' % s
        return '%s(sats=%s, msats=%s)' % (s, str(self._msat_to_sat(self._amount_msat)), str(self._amount_msat))

    def __repr__(self):
        return f"<QEAmount max={self._is_max} sats={self._msat_to_sat(self._amount_msat)} msats={self._amount_msat} empty={self.isEmpty}>"


class QEBytes(QObject):
    def __init__(self, data: bytes = None, *, parent=None):
        super().__init__(parent)
        self.data = data

    @property
    def data(self):
        return self._data

    @data.setter
    def data(self, _data):
        self._data = _data

    @pyqtProperty(bool)
    def isEmpty(self):
        return self._data is None or self._data == bytes()

    def __str__(self):
        return f'{self._data}'

    def __repr__(self):
        return f"<QEBytes data={'None' if self._data is None else self._data.hex()}>"
