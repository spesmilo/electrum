from electrum.i18n import _
from .token import Token

class BalanceItem:
    def __init__(self, index, token: Token, value: float):
        self._index = index
        self._token = token
        self._value = value

    def label(self):
        return str(self._token)

    def name(self):
        return self._token['name']

    def index(self):
        return self._index

    def symbol(self):
        return self._token['symbol']

    def decimal(self):
        return self._token['decimal']

    def yesno(self, v: bool):
        return _('Yes') if v else _('No')

    def isDat(self):
        return self.yesno(self._token['isDAT'])

    def isLPS(self):
        return self.yesno(self._token['isLPS'])

    def isLoan(self):
        return self.yesno(self._token['isLoanToken'])

    def collateralAddress(self):
        return self._token['collateralAddress']

    def value(self):
        return self._value

    def add_value(self, v: float):
        self._value += v
