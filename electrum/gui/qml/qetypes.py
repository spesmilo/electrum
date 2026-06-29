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

       When passing QEAmount to QML scope using a pyqtProperty, avoid overwriting the returned
       instance with a new QEAmount. Use .copyFrom(..) instead, otherwise the old QEAmount will be
       gc'ed, resulting in amount property bindings being momentarily 'null' (until the property's
       notify signal gets processed)
    """

    _logger = get_logger(__name__)

    valueChanged = pyqtSignal()

    def __init__(self, parent=None, *, amount_sat: int = None, amount_msat: int = None, is_max: bool = False, from_invoice=None):
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
    def satsInt(self) -> int:
        if self._amount_msat is None:  # should normally be defined when accessing this property
            self._logger.warning('amount_msat is undefined, returning 0')
            return 0
        return self._msat_to_sat(self._amount_msat)

    @satsInt.setter
    def satsInt(self, sats: int):
        assert sats is None or isinstance(sats, int), 'sats must be int or None'
        msats = self._sat_to_msat(sats)
        if self._amount_msat != msats:
            self._amount_msat = msats
            self.valueChanged.emit()

    @pyqtProperty('qint64', notify=valueChanged)
    def msatsInt(self) -> int:
        if self._amount_msat is None:  # should normally be defined when accessing this property
            self._logger.warning('amount_msat is undefined, returning 0')
            return 0
        return self._amount_msat

    @msatsInt.setter
    def msatsInt(self, msats: int):
        assert msats is None or isinstance(msats, int), 'msats must be int or None'
        if self._amount_msat != msats:
            self._amount_msat = msats
            self.valueChanged.emit()

    @pyqtProperty(str, notify=valueChanged)
    def satsStr(self) -> str:
        return str(self._msat_to_sat(self._amount_msat))

    @pyqtProperty(str, notify=valueChanged)
    def msatsStr(self) -> str:
        return str(self._amount_msat)

    @pyqtProperty(bool, notify=valueChanged)
    def isMax(self) -> bool:
        return self._is_max

    @isMax.setter
    def isMax(self, ismax: bool):
        if self._is_max != ismax:
            self._is_max = ismax
            self.valueChanged.emit()

    @pyqtProperty(bool, notify=valueChanged)
    def isEmpty(self) -> bool:
        return not (self._is_max or self._amount_msat)

    @pyqtProperty(bool, notify=valueChanged)
    def hasMsatPrecision(self) -> bool:
        return not (self._amount_msat == self._sat_to_msat(self._msat_to_sat(self._amount_msat)))

    @pyqtProperty(bool, notify=valueChanged)
    def positive(self) -> bool:
        return self.isEmpty or self.isMax or self.msatsInt >= 0

    @pyqtSlot()
    def clear(self):
        self._amount_msat = 0
        self._is_max = False
        self.valueChanged.emit()

    @pyqtSlot('QVariant')
    def copyFrom(self, amount: 'QEAmount|None'):
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

    @pyqtSlot('QVariant', result=bool)
    def lt(self, other: 'QEAmount|None') -> bool:
        if other is None:
            other = QEAmount()
        assert isinstance(other, QEAmount)
        assert not (self.isMax or other.isMax), "'lt/lte' operator undefined for MAX amounts"
        if self.isEmpty and not other.isEmpty:
            return True
        return self.msatsInt < other.msatsInt

    @pyqtSlot('QVariant', result=bool)
    def lte(self, other: 'QEAmount|None') -> bool:
        return self.lt(other) or self == other

    @pyqtSlot('QVariant', result=bool)
    def gt(self, other: 'QEAmount|None') -> bool:
        if other is None:
            other = QEAmount()
        assert isinstance(other, QEAmount)
        assert not (self.isMax or other.isMax), "'gt/gte' operator undefined for MAX amounts"
        if self.isEmpty and not other.isEmpty:
            return False
        return self.msatsInt > other.msatsInt

    @pyqtSlot('QVariant', result=bool)
    def gte(self, other: 'QEAmount|None') -> bool:
        return self.gt(other) or self == other

    @pyqtSlot('QVariant', result=bool)
    def eq(self, other: 'QEAmount|None') -> bool:
        return self == other

    @pyqtSlot('QVariant', 'QVariant', result='QVariant')
    def max(self, one: 'QEAmount|None', two: 'QEAmount|None'):
        if one is None:
            one = QEAmount()
        if two is None:
            two = QEAmount()
        assert isinstance(one, QEAmount)
        assert isinstance(two, QEAmount)

        # TODO: as gt/lt is undefined for operands being isMax, we can either
        # - raise (let the GUI avoid comparisons against MAX)
        # - define MAX as always being larger than any value
        if one.isMax:
            return one
        if two.isMax:
            return two

        return one if one.gt(two) else two

    @pyqtSlot('QVariant', 'QVariant', result='QVariant')
    def min(self, one: 'QEAmount|None', two: 'QEAmount|None'):
        if one is None:
            one = QEAmount()
        if two is None:
            two = QEAmount()
        assert isinstance(one, QEAmount)
        assert isinstance(two, QEAmount)
        # TODO: as gt/lt is undefined for operands being isMax, we can either
        # - raise (let the GUI avoid comparisons against MAX)
        # - define MAX as always being larger than any value
        if one.isMax:
            return two
        if two.isMax:
            return one
        return one if one.lt(two) else two

    def __eq__(self, other: 'QEAmount') -> bool:
        assert True if other is None else isinstance(other, QEAmount)
        if other is None:
            return False
        return self._amount_msat == other._amount_msat and self._is_max == other._is_max

    def __str__(self) -> str:
        s = _('Amount')
        if self._is_max:
            return '%s(MAX)' % s
        return '%s(sats=%s, msats=%s)' % (s, str(self._msat_to_sat(self._amount_msat)), str(self._amount_msat))

    def __repr__(self) -> str:
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
