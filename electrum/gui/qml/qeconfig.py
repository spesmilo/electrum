from PyQt5.QtCore import pyqtProperty, pyqtSignal, pyqtSlot, QObject

from decimal import Decimal

from electrum.logging import get_logger
from electrum.util import DECIMAL_POINT_DEFAULT

class QEConfig(QObject):
    def __init__(self, config, parent=None):
        super().__init__(parent)
        self.config = config

    _logger = get_logger(__name__)

    autoConnectChanged = pyqtSignal()
    @pyqtProperty(bool, notify=autoConnectChanged)
    def autoConnect(self):
        return self.config.get('auto_connect')

    @autoConnect.setter
    def autoConnect(self, auto_connect):
        self.config.set_key('auto_connect', auto_connect, True)
        self.autoConnectChanged.emit()

    # auto_connect is actually a tri-state, expose the undefined case
    @pyqtProperty(bool, notify=autoConnectChanged)
    def autoConnectDefined(self):
        return self.config.get('auto_connect') is not None

    serverStringChanged = pyqtSignal()
    @pyqtProperty('QString', notify=serverStringChanged)
    def serverString(self):
        return self.config.get('server')

    @serverString.setter
    def serverString(self, server):
        self.config.set_key('server', server, True)
        self.serverStringChanged.emit()

    manualServerChanged = pyqtSignal()
    @pyqtProperty(bool, notify=manualServerChanged)
    def manualServer(self):
        return self.config.get('oneserver')

    @manualServer.setter
    def manualServer(self, oneserver):
        self.config.set_key('oneserver', oneserver, True)
        self.manualServerChanged.emit()

    baseUnitChanged = pyqtSignal()
    @pyqtProperty(str, notify=baseUnitChanged)
    def baseUnit(self):
        return self.config.get_base_unit()

    @baseUnit.setter
    def baseUnit(self, unit):
        self.config.set_base_unit(unit)
        self.baseUnitChanged.emit()

    thousandsSeparatorChanged = pyqtSignal()
    @pyqtProperty(bool, notify=thousandsSeparatorChanged)
    def thousandsSeparator(self):
        return self.config.get('amt_add_thousands_sep', False)

    @thousandsSeparator.setter
    def thousandsSeparator(self, checked):
        self.config.set_key('amt_add_thousands_sep', checked)
        self.config.amt_add_thousands_sep = checked
        self.thousandsSeparatorChanged.emit()


    @pyqtSlot(int, result=str)
    @pyqtSlot(int, bool, result=str)
    def formatSats(self, satoshis, with_unit=False):
        if with_unit:
            return self.config.format_amount_and_units(satoshis)
        else:
            return self.config.format_amount(satoshis)

    # TODO delegate all this to config.py/util.py
    def decimal_point(self):
        return self.config.get('decimal_point', DECIMAL_POINT_DEFAULT)

    def max_precision(self):
        return self.decimal_point() + 0 #self.extra_precision

    @pyqtSlot(str, result=int)
    def unitsToSats(self, unitAmount):
        # returns amt in satoshis
        try:
            x = Decimal(unitAmount)
        except:
            return 0
        # scale it to max allowed precision, make it an int
        max_prec_amount = int(pow(10, self.max_precision()) * x)
        # if the max precision is simply what unit conversion allows, just return
        if self.max_precision() == self.decimal_point():
            return max_prec_amount
        self._logger.debug('fallthrough')
        # otherwise, scale it back to the expected unit
        #amount = Decimal(max_prec_amount) / Decimal(pow(10, self.max_precision()-self.decimal_point()))
        #return int(amount) #Decimal(amount) if not self.is_int else int(amount)
        return 0
