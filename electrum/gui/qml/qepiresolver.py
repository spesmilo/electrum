from enum import IntEnum
from typing import Optional

from PyQt6.QtCore import pyqtProperty, pyqtSignal, pyqtSlot, QObject, QTimer

from electrum.logging import get_logger
from electrum.i18n import _
from electrum.payment_identifier import PaymentIdentifier, PaymentIdentifierState, PaymentIdentifierType

from .qewallet import QEWallet


class QEPIResolver(QObject):
    """Intended to handle a user input Payment Identifier (PI), resolve it if necessary, then
    allow to distinguish between a Request/voucher/lnurlw and an Invoice (e.g. b11 or lnurlp)."""
    _logger = get_logger(__name__)

    busyChanged = pyqtSignal()
    resolveError = pyqtSignal([str, str], arguments=['code', 'message'])
    invoiceResolved = pyqtSignal(object)
    requestResolved = pyqtSignal(object)

    def __init__(self, parent=None):
        super().__init__(parent)

        self._wallet = None  # type: Optional[QEWallet]
        self._recipient = None
        self._pi = None
        self._busy = False

        self.clear()

    recipientChanged = pyqtSignal()
    @pyqtProperty(str, notify=recipientChanged)
    def recipient(self) -> Optional[str]:
        return self._recipient

    @recipient.setter
    def recipient(self, recipient: str) -> None:
        self.clear()
        if not recipient:
            return
        self._recipient = recipient
        self.recipientChanged.emit()
        self._pi = PaymentIdentifier(self._wallet.wallet, recipient)
        if self._pi.need_resolve():
            self.resolve_pi()
        else:
            # assuming if the PI is an invoice if it doesn't need resolving
            # as there are no request types that do not need resolving currently
            self.invoiceResolved.emit(self._pi)

    walletChanged = pyqtSignal()
    @pyqtProperty(QEWallet, notify=walletChanged)
    def wallet(self) -> Optional[QEWallet]:
        return self._wallet

    @wallet.setter
    def wallet(self, wallet: QEWallet) -> None:
        self._wallet = wallet

    @pyqtProperty(bool, notify=busyChanged)
    def busy(self):
        return self._busy

    def resolve_pi(self) -> None:
        assert self._pi is not None
        assert self._pi.need_resolve()

        def on_finished(pi: PaymentIdentifier):
            self._busy = False
            self.busyChanged.emit()

            if pi.is_error():
                if pi.type in [PaymentIdentifierType.EMAILLIKE, PaymentIdentifierType.DOMAINLIKE]:
                    msg = _('Could not resolve address')
                elif pi.type == PaymentIdentifierType.LNURL:
                    msg = _('Could not resolve LNURL') + "\n\n" + pi.get_error()
                elif pi.type == PaymentIdentifierType.BIP70:
                    msg = _('Could not resolve BIP70 payment request: {}').format(pi.error)
                else:
                    msg = _('Could not resolve')
                self.resolveError.emit('resolve', msg)
            else:
                if pi.type == PaymentIdentifierType.LNURLW:
                    self.requestResolved.emit(pi)
                else:
                    self.invoiceResolved.emit(pi)

        self._busy = True
        self.busyChanged.emit()

        self._pi.resolve(on_finished=on_finished)

    def clear(self) -> None:
        self._recipient = None
        self._pi = None
        self._busy = False
        self.busyChanged.emit()
        self.recipientChanged.emit()
