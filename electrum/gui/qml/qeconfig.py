import copy
from decimal import Decimal
from typing import TYPE_CHECKING

from PyQt6.QtCore import pyqtProperty, pyqtSignal, pyqtSlot, QObject, QRegularExpression

from electrum.bitcoin import TOTAL_COIN_SUPPLY_LIMIT_IN_BTC
from electrum.i18n import set_language, languages
from electrum.logging import get_logger
from electrum.util import base_unit_name_to_decimal_point

from .qetypes import QEAmount
from .auth import AuthMixin, auth_protect

if TYPE_CHECKING:
    from electrum.simple_config import SimpleConfig


class QEConfig(AuthMixin, QObject):
    _logger = get_logger(__name__)

    def __init__(self, config: 'SimpleConfig', parent=None):
        super().__init__(parent)
        self.config = config

    @pyqtSlot(str, result=str)
    def shortDescFor(self, key) -> str:
        cv = getattr(self.config.cv, key)
        return cv.get_short_desc() if cv else ''

    @pyqtSlot(str, result=str)
    def longDescFor(self, key) -> str:
        cv = getattr(self.config.cv, key)
        return cv.get_long_desc() if cv else ''

    languageChanged = pyqtSignal()
    @pyqtProperty(str, notify=languageChanged)
    def language(self):
        return self.config.LOCALIZATION_LANGUAGE

    @language.setter
    def language(self, language):
        if language not in languages:
            return
        if self.config.LOCALIZATION_LANGUAGE != language:
            self.config.LOCALIZATION_LANGUAGE = language
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
        return self.config.NETWORK_AUTO_CONNECT

    @autoConnect.setter
    def autoConnect(self, auto_connect):
        self.config.NETWORK_AUTO_CONNECT = auto_connect
        self.autoConnectChanged.emit()

    # auto_connect is actually a tri-state, expose the undefined case
    @pyqtProperty(bool, notify=autoConnectChanged)
    def autoConnectDefined(self):
        return self.config.cv.NETWORK_AUTO_CONNECT.is_set()

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
        return self.config.BTC_AMOUNTS_ADD_THOUSANDS_SEP

    @thousandsSeparator.setter
    def thousandsSeparator(self, checked):
        self.config.BTC_AMOUNTS_ADD_THOUSANDS_SEP = checked
        self.config.amt_add_thousands_sep = checked
        self.thousandsSeparatorChanged.emit()

    spendUnconfirmedChanged = pyqtSignal()
    @pyqtProperty(bool, notify=spendUnconfirmedChanged)
    def spendUnconfirmed(self):
        return not self.config.WALLET_SPEND_CONFIRMED_ONLY

    @spendUnconfirmed.setter
    def spendUnconfirmed(self, checked):
        self.config.WALLET_SPEND_CONFIRMED_ONLY = not checked
        self.spendUnconfirmedChanged.emit()

    requestExpiryChanged = pyqtSignal()
    @pyqtProperty(int, notify=requestExpiryChanged)
    def requestExpiry(self):
        return self.config.WALLET_PAYREQ_EXPIRY_SECONDS

    @requestExpiry.setter
    def requestExpiry(self, expiry):
        self.config.WALLET_PAYREQ_EXPIRY_SECONDS = expiry
        self.requestExpiryChanged.emit()

    pinCodeChanged = pyqtSignal()
    @pyqtProperty(str, notify=pinCodeChanged)
    def pinCode(self):
        return self.config.CONFIG_PIN_CODE or ""

    @pinCode.setter
    def pinCode(self, pin_code):
        if pin_code == '':
            self.pinCodeRemoveAuth()
        else:
            self.config.CONFIG_PIN_CODE = pin_code
            self.pinCodeChanged.emit()

    @auth_protect(method='wallet_else_pin')
    def pinCodeRemoveAuth(self):
        self.config.CONFIG_PIN_CODE = ""
        self.pinCodeChanged.emit()

    useGossipChanged = pyqtSignal()
    @pyqtProperty(bool, notify=useGossipChanged)
    def useGossip(self):
        return self.config.LIGHTNING_USE_GOSSIP

    @useGossip.setter
    def useGossip(self, gossip):
        self.config.LIGHTNING_USE_GOSSIP = gossip
        self.useGossipChanged.emit()

    useFallbackAddressChanged = pyqtSignal()
    @pyqtProperty(bool, notify=useFallbackAddressChanged)
    def useFallbackAddress(self):
        return self.config.WALLET_BOLT11_FALLBACK

    @useFallbackAddress.setter
    def useFallbackAddress(self, use_fallback):
        self.config.WALLET_BOLT11_FALLBACK = use_fallback
        self.useFallbackAddressChanged.emit()

    enableDebugLogsChanged = pyqtSignal()
    @pyqtProperty(bool, notify=enableDebugLogsChanged)
    def enableDebugLogs(self):
        gui_setting = self.config.GUI_ENABLE_DEBUG_LOGS
        return gui_setting or bool(self.config.get('verbosity'))

    @pyqtProperty(bool, notify=enableDebugLogsChanged)
    def canToggleDebugLogs(self):
        gui_setting = self.config.GUI_ENABLE_DEBUG_LOGS
        return not self.config.get('verbosity') or gui_setting

    @enableDebugLogs.setter
    def enableDebugLogs(self, enable):
        self.config.GUI_ENABLE_DEBUG_LOGS = enable
        self.enableDebugLogsChanged.emit()

    alwaysAllowScreenshotsChanged = pyqtSignal()
    @pyqtProperty(bool, notify=alwaysAllowScreenshotsChanged)
    def alwaysAllowScreenshots(self):
        return self.config.GUI_QML_ALWAYS_ALLOW_SCREENSHOTS

    @alwaysAllowScreenshots.setter
    def alwaysAllowScreenshots(self, enable):
        self.config.GUI_QML_ALWAYS_ALLOW_SCREENSHOTS = enable
        self.alwaysAllowScreenshotsChanged.emit()

    useRecoverableChannelsChanged = pyqtSignal()
    @pyqtProperty(bool, notify=useRecoverableChannelsChanged)
    def useRecoverableChannels(self):
        return self.config.LIGHTNING_USE_RECOVERABLE_CHANNELS

    @useRecoverableChannels.setter
    def useRecoverableChannels(self, useRecoverableChannels):
        self.config.LIGHTNING_USE_RECOVERABLE_CHANNELS = useRecoverableChannels
        self.useRecoverableChannelsChanged.emit()

    trustedcoinPrepayChanged = pyqtSignal()
    @pyqtProperty(int, notify=trustedcoinPrepayChanged)
    def trustedcoinPrepay(self):
        return self.config.PLUGIN_TRUSTEDCOIN_NUM_PREPAY

    @trustedcoinPrepay.setter
    def trustedcoinPrepay(self, num_prepay):
        if num_prepay != self.config.PLUGIN_TRUSTEDCOIN_NUM_PREPAY:
            self.config.PLUGIN_TRUSTEDCOIN_NUM_PREPAY = num_prepay
            self.trustedcoinPrepayChanged.emit()

    preferredRequestTypeChanged = pyqtSignal()
    @pyqtProperty(str, notify=preferredRequestTypeChanged)
    def preferredRequestType(self):
        return self.config.GUI_QML_PREFERRED_REQUEST_TYPE

    @preferredRequestType.setter
    def preferredRequestType(self, preferred_request_type):
        if preferred_request_type != self.config.GUI_QML_PREFERRED_REQUEST_TYPE:
            self.config.GUI_QML_PREFERRED_REQUEST_TYPE = preferred_request_type
            self.preferredRequestTypeChanged.emit()

    userKnowsPressAndHoldChanged = pyqtSignal()
    @pyqtProperty(bool, notify=userKnowsPressAndHoldChanged)
    def userKnowsPressAndHold(self):
        return self.config.GUI_QML_USER_KNOWS_PRESS_AND_HOLD

    @userKnowsPressAndHold.setter
    def userKnowsPressAndHold(self, userKnowsPressAndHold):
        if userKnowsPressAndHold != self.config.GUI_QML_USER_KNOWS_PRESS_AND_HOLD:
            self.config.GUI_QML_USER_KNOWS_PRESS_AND_HOLD = userKnowsPressAndHold
            self.userKnowsPressAndHoldChanged.emit()

    addresslistShowTypeChanged = pyqtSignal()
    @pyqtProperty(int, notify=addresslistShowTypeChanged)
    def addresslistShowType(self):
        return self.config.GUI_QML_ADDRESS_LIST_SHOW_TYPE

    @addresslistShowType.setter
    def addresslistShowType(self, addresslistShowType):
        if addresslistShowType != self.config.GUI_QML_ADDRESS_LIST_SHOW_TYPE:
            self.config.GUI_QML_ADDRESS_LIST_SHOW_TYPE = addresslistShowType
            self.addresslistShowTypeChanged.emit()

    addresslistShowUsedChanged = pyqtSignal()
    @pyqtProperty(bool, notify=addresslistShowUsedChanged)
    def addresslistShowUsed(self):
        return self.config.GUI_QML_ADDRESS_LIST_SHOW_USED

    @addresslistShowUsed.setter
    def addresslistShowUsed(self, addresslistShowUsed):
        if addresslistShowUsed != self.config.GUI_QML_ADDRESS_LIST_SHOW_USED:
            self.config.GUI_QML_ADDRESS_LIST_SHOW_USED = addresslistShowUsed
            self.addresslistShowUsedChanged.emit()

    outputValueRoundingChanged = pyqtSignal()
    @pyqtProperty(bool, notify=outputValueRoundingChanged)
    def outputValueRounding(self):
        return self.config.WALLET_COIN_CHOOSER_OUTPUT_ROUNDING

    @outputValueRounding.setter
    def outputValueRounding(self, outputValueRounding):
        if outputValueRounding != self.config.WALLET_COIN_CHOOSER_OUTPUT_ROUNDING:
            self.config.WALLET_COIN_CHOOSER_OUTPUT_ROUNDING = outputValueRounding
            self.outputValueRoundingChanged.emit()

    lightningPaymentFeeMaxMillionthsChanged = pyqtSignal()
    @pyqtProperty(int, notify=lightningPaymentFeeMaxMillionthsChanged)
    def lightningPaymentFeeMaxMillionths(self):
        return self.config.LIGHTNING_PAYMENT_FEE_MAX_MILLIONTHS

    @lightningPaymentFeeMaxMillionths.setter
    def lightningPaymentFeeMaxMillionths(self, lightningPaymentFeeMaxMillionths):
        if lightningPaymentFeeMaxMillionths != self.config.LIGHTNING_PAYMENT_FEE_MAX_MILLIONTHS:
            self.config.LIGHTNING_PAYMENT_FEE_MAX_MILLIONTHS = lightningPaymentFeeMaxMillionths
            self.lightningPaymentFeeMaxMillionthsChanged.emit()

    @pyqtSlot('qint64', result=str)
    @pyqtSlot(QEAmount, result=str)
    def formatSatsForEditing(self, satoshis):
        if isinstance(satoshis, QEAmount):
            satoshis = satoshis.satsInt
        return self.config.format_amount(
            satoshis,
            add_thousands_sep=False,
        )

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
        return self.config.BTC_AMOUNTS_DECIMAL_POINT

    def max_precision(self):
        return self.decimal_point() + 0  # self.extra_precision

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
        return satoshis / pow(10, self.config.decimal_point)
