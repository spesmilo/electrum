import copy
from decimal import Decimal
from typing import TYPE_CHECKING

from PyQt5.QtCore import pyqtProperty, pyqtSignal, pyqtSlot, QObject, QRegularExpression

from electrum.bitcoin import TOTAL_COIN_SUPPLY_LIMIT_IN_BTC
from electrum.i18n import set_language, languages
from electrum.logging import get_logger
from electrum.util import DECIMAL_POINT_DEFAULT, base_unit_name_to_decimal_point
from electrum.invoices import PR_DEFAULT_EXPIRATION_WHEN_CREATING

from .qetypes import QEAmount
from .auth import AuthMixin, auth_protect

if TYPE_CHECKING:
    from electrum.simple_config import SimpleConfig


class QEConfig(AuthMixin, QObject):
    _logger = get_logger(__name__)

    def __init__(self, config: 'SimpleConfig', parent=None):
        super().__init__(parent)
        self.config = config

    languageChanged = pyqtSignal()
    @pyqtProperty(str, notify=languageChanged)
    def language(self):
        return self.config.get('language')

    @language.setter
    def language(self, language):
        if language not in languages:
            return
        if self.config.get('language') != language:
            self.config.set_key('language', language)
            set_language(language)
            self.languageChanged.emit()

    languagesChanged = pyqtSignal()
    @pyqtProperty('QVariantList', notify=languagesChanged)
    def languagesAvailable(self):
        # sort on translated languages, then re-add Default on top
        langs = copy.deepcopy(languages)
        default = langs.pop('')
        langs_sorted = sorted(list(map(lambda x: {'value': x[0], 'text': x[1]}, langs.items())), key=lambda x: x['text'])
        langs_sorted.insert(0, {'value': '', 'text': default})
        return langs_sorted

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

    @pyqtProperty('QRegularExpression', notify=baseUnitChanged)
    def btcAmountRegex(self):
        decimal_point = base_unit_name_to_decimal_point(self.config.get_base_unit())
        max_digits_before_dp = (
            len(str(TOTAL_COIN_SUPPLY_LIMIT_IN_BTC))
            + (base_unit_name_to_decimal_point("BTC") - decimal_point))
        exp = '[0-9]{0,%d}' % max_digits_before_dp
        if decimal_point > 0:
            exp += '\\.'
            exp += '[0-9]{0,%d}' % decimal_point
        return QRegularExpression(exp)

    thousandsSeparatorChanged = pyqtSignal()
    @pyqtProperty(bool, notify=thousandsSeparatorChanged)
    def thousandsSeparator(self):
        return self.config.get('amt_add_thousands_sep', False)

    @thousandsSeparator.setter
    def thousandsSeparator(self, checked):
        self.config.set_key('amt_add_thousands_sep', checked)
        self.config.amt_add_thousands_sep = checked
        self.thousandsSeparatorChanged.emit()

    spendUnconfirmedChanged = pyqtSignal()
    @pyqtProperty(bool, notify=spendUnconfirmedChanged)
    def spendUnconfirmed(self):
        return not self.config.get('confirmed_only', False)

    @spendUnconfirmed.setter
    def spendUnconfirmed(self, checked):
        self.config.set_key('confirmed_only', not checked, True)
        self.spendUnconfirmedChanged.emit()

    requestExpiryChanged = pyqtSignal()
    @pyqtProperty(int, notify=requestExpiryChanged)
    def requestExpiry(self):
        return self.config.get('request_expiry', PR_DEFAULT_EXPIRATION_WHEN_CREATING)

    @requestExpiry.setter
    def requestExpiry(self, expiry):
        self.config.set_key('request_expiry', expiry)
        self.requestExpiryChanged.emit()

    pinCodeChanged = pyqtSignal()
    @pyqtProperty(str, notify=pinCodeChanged)
    def pinCode(self):
        return self.config.get('pin_code', '')

    @pinCode.setter
    def pinCode(self, pin_code):
        if pin_code == '':
            self.pinCodeRemoveAuth()
        else:
            self.config.set_key('pin_code', pin_code, True)
            self.pinCodeChanged.emit()

    # TODO: this allows disabling PIN unconditionally if wallet has no password
    # (which should never be the case however)
    @auth_protect(method='wallet_password')
    def pinCodeRemoveAuth(self, password=None):
        self.config.set_key('pin_code', '', True)
        self.pinCodeChanged.emit()

    useGossipChanged = pyqtSignal()
    @pyqtProperty(bool, notify=useGossipChanged)
    def useGossip(self):
        return self.config.get('use_gossip', False)

    @useGossip.setter
    def useGossip(self, gossip):
        self.config.set_key('use_gossip', gossip)
        self.useGossipChanged.emit()

    useFallbackAddressChanged = pyqtSignal()
    @pyqtProperty(bool, notify=useFallbackAddressChanged)
    def useFallbackAddress(self):
        return self.config.get('bolt11_fallback', True)

    @useFallbackAddress.setter
    def useFallbackAddress(self, use_fallback):
        self.config.set_key('bolt11_fallback', use_fallback)
        self.useFallbackAddressChanged.emit()

    enableDebugLogsChanged = pyqtSignal()
    @pyqtProperty(bool, notify=enableDebugLogsChanged)
    def enableDebugLogs(self):
        gui_setting = self.config.get('gui_enable_debug_logs', False)
        return gui_setting or bool(self.config.get('verbosity'))

    @pyqtProperty(bool, notify=enableDebugLogsChanged)
    def canToggleDebugLogs(self):
        gui_setting = self.config.get('gui_enable_debug_logs', False)
        return not self.config.get('verbosity') or gui_setting

    @enableDebugLogs.setter
    def enableDebugLogs(self, enable):
        self.config.set_key('gui_enable_debug_logs', enable)
        self.enableDebugLogsChanged.emit()

    useRecoverableChannelsChanged = pyqtSignal()
    @pyqtProperty(bool, notify=useRecoverableChannelsChanged)
    def useRecoverableChannels(self):
        return self.config.get('use_recoverable_channels', True)

    @useRecoverableChannels.setter
    def useRecoverableChannels(self, useRecoverableChannels):
        self.config.set_key('use_recoverable_channels', useRecoverableChannels)
        self.useRecoverableChannelsChanged.emit()

    trustedcoinPrepayChanged = pyqtSignal()
    @pyqtProperty(int, notify=trustedcoinPrepayChanged)
    def trustedcoinPrepay(self):
        return self.config.get('trustedcoin_prepay', 20)

    @trustedcoinPrepay.setter
    def trustedcoinPrepay(self, num_prepay):
        if num_prepay != self.config.get('trustedcoin_prepay', 20):
            self.config.set_key('trustedcoin_prepay', num_prepay)
            self.trustedcoinPrepayChanged.emit()

    preferredRequestTypeChanged = pyqtSignal()
    @pyqtProperty(str, notify=preferredRequestTypeChanged)
    def preferredRequestType(self):
        return self.config.get('preferred_request_type', 'bolt11')

    @preferredRequestType.setter
    def preferredRequestType(self, preferred_request_type):
        if preferred_request_type != self.config.get('preferred_request_type', 'bolt11'):
            self.config.set_key('preferred_request_type', preferred_request_type)
            self.preferredRequestTypeChanged.emit()

    userKnowsPressAndHoldChanged = pyqtSignal()
    @pyqtProperty(bool, notify=userKnowsPressAndHoldChanged)
    def userKnowsPressAndHold(self):
        return self.config.get('user_knows_press_and_hold', False)

    @userKnowsPressAndHold.setter
    def userKnowsPressAndHold(self, userKnowsPressAndHold):
        if userKnowsPressAndHold != self.config.get('user_knows_press_and_hold', False):
            self.config.set_key('user_knows_press_and_hold', userKnowsPressAndHold)
            self.userKnowsPressAndHoldChanged.emit()


    @pyqtSlot('qint64', result=str)
    @pyqtSlot('qint64', bool, result=str)
    @pyqtSlot(QEAmount, result=str)
    @pyqtSlot(QEAmount, bool, result=str)
    def formatSats(self, satoshis, with_unit=False):
        if isinstance(satoshis, QEAmount):
            satoshis = satoshis.satsInt
        if with_unit:
            return self.config.format_amount_and_units(satoshis)
        else:
            return self.config.format_amount(satoshis)

    @pyqtSlot(QEAmount, result=str)
    @pyqtSlot(QEAmount, bool, result=str)
    def formatMilliSats(self, amount, with_unit=False):
        if isinstance(amount, QEAmount):
            msats = amount.msatsInt
        else:
            return '---'
        precision = 3  # config.amt_precision_post_satoshi is not exposed in preferences
        if with_unit:
            return self.config.format_amount_and_units(msats/1000, precision=precision)
        else:
            return self.config.format_amount(msats/1000, precision=precision)

    # TODO delegate all this to config.py/util.py
    def decimal_point(self):
        return self.config.get('decimal_point', DECIMAL_POINT_DEFAULT)

    def max_precision(self):
        return self.decimal_point() + 0 #self.extra_precision

    @pyqtSlot(str, result=QEAmount)
    def unitsToSats(self, unitAmount):
        self._amount = QEAmount()
        try:
            x = Decimal(unitAmount)
        except Exception:
            return self._amount

        # scale it to max allowed precision, make it an int
        max_prec_amount = int(pow(10, self.max_precision()) * x)
        # if the max precision is simply what unit conversion allows, just return
        if self.max_precision() == self.decimal_point():
            self._amount = QEAmount(amount_sat=max_prec_amount)
            return self._amount
        self._logger.debug('fallthrough')
        # otherwise, scale it back to the expected unit
        #amount = Decimal(max_prec_amount) / Decimal(pow(10, self.max_precision()-self.decimal_point()))
        #return int(amount) #Decimal(amount) if not self.is_int else int(amount)
        return self._amount

    @pyqtSlot('quint64', result=float)
    def satsToUnits(self, satoshis):
        return satoshis / pow(10,self.config.decimal_point)
