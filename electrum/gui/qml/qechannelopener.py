import threading
from concurrent.futures import CancelledError
from asyncio.exceptions import TimeoutError
from typing import Optional
import electrum_ecc as ecc

from PyQt6.QtCore import pyqtProperty, pyqtSignal, pyqtSlot, QObject

from electrum.i18n import _
from electrum.gui import messages
from electrum.util import bfh
from electrum.lnutil import MIN_FUNDING_SAT
from electrum.lntransport import extract_nodeid, ConnStringFormatError
from electrum.bitcoin import DummyAddress
from electrum.lnworker import hardcoded_trampoline_nodes
from electrum.logging import get_logger
from electrum.fee_policy import FeePolicy

from .auth import AuthMixin, auth_protect
from .qetxfinalizer import QETxFinalizer
from .qetxdetails import QETxDetails
from .qetypes import QEAmount
from .qewallet import QEWallet


class QEChannelOpener(QObject, AuthMixin):
    _logger = get_logger(__name__)

    validationError = pyqtSignal([str, str], arguments=['code', 'message'])
    conflictingBackup = pyqtSignal([str], arguments=['message'])
    channelOpening = pyqtSignal([str], arguments=['peer'])
    channelOpenError = pyqtSignal([str], arguments=['message'])
    channelOpenSuccess = pyqtSignal([str, bool, int, bool],
                                    arguments=['cid', 'has_onchain_backup', 'min_depth', 'tx_complete'])

    dataChanged = pyqtSignal()  # generic notify signal

    def __init__(self, parent=None):
        super().__init__(parent)

        self._wallet = None  # type: Optional[QEWallet]
        self._connect_str = None
        self._amount = QEAmount()
        self._valid = False
        self._opentx = None
        self._txdetails = None
        self._warning = ''
        self._determine_max_message = None

        self._finalizer = None
        self._node_pubkey = None
        self._connect_str_resolved = None

        self._updating_max = False

    walletChanged = pyqtSignal()
    @pyqtProperty(QEWallet, notify=walletChanged)
    def wallet(self):
        return self._wallet

    @wallet.setter
    def wallet(self, wallet: QEWallet):
        if self._wallet != wallet:
            self._wallet = wallet
            self.walletChanged.emit()

    connectStrChanged = pyqtSignal()
    @pyqtProperty(str, notify=connectStrChanged)
    def connectStr(self):
        return self._connect_str

    @connectStr.setter
    def connectStr(self, connect_str: str):
        if self._connect_str != connect_str:
            self._logger.debug('connectStr set -> %s' % connect_str)
            self._connect_str = connect_str
            self.connectStrChanged.emit()
            self.validate()

    amountChanged = pyqtSignal()
    @pyqtProperty(QEAmount, notify=amountChanged)
    def amount(self):
        return self._amount

    @amount.setter
    def amount(self, amount: QEAmount):
        if self._amount != amount:
            self._amount.copyFrom(amount)
            self.amountChanged.emit()
            self.validate()

    validChanged = pyqtSignal()
    @pyqtProperty(bool, notify=validChanged)
    def valid(self):
        return self._valid

    def setValid(self, is_valid):
        if self._valid != is_valid:
            self._valid = is_valid
            self.validChanged.emit()

    warningChanged = pyqtSignal()
    @pyqtProperty(str, notify=warningChanged)
    def warning(self):
        return self._warning

    def setWarning(self, warning):
        if self._warning != warning:
            self._warning = warning
            self.warningChanged.emit()

    finalizerChanged = pyqtSignal()
    @pyqtProperty(QETxFinalizer, notify=finalizerChanged)
    def finalizer(self):
        return self._finalizer

    txDetailsChanged = pyqtSignal()
    @pyqtProperty(QETxDetails, notify=txDetailsChanged)
    def txDetails(self):
        return self._txdetails

    @pyqtProperty(list, notify=dataChanged)
    def trampolineNodeNames(self):
        return list(hardcoded_trampoline_nodes().keys())

    # FIXME have requested funding amount
    def validate(self):
        """side-effects: sets self._node_pubkey, self._connect_str_resolved"""
        connect_str_valid = False
        if self._connect_str:
            self._logger.debug(f'checking if {self._connect_str=!r} is valid')
            if not self._wallet.wallet.config.LIGHTNING_USE_GOSSIP:
                # using trampoline: connect_str is the name of a trampoline node
                peer_addr = hardcoded_trampoline_nodes()[self._connect_str]
                self._node_pubkey = peer_addr.pubkey
                self._connect_str_resolved = str(peer_addr)
                connect_str_valid = True
            else:
                # using gossip: connect_str is anything extract_nodeid() can parse
                try:
                    self._node_pubkey, _rest = extract_nodeid(self._connect_str)
                except ConnStringFormatError:
                    pass
                else:
                    self._connect_str_resolved = self._connect_str
                    connect_str_valid = True

        self.setWarning('')

        if not connect_str_valid:
            self.setValid(False)
            return

        self._logger.debug(f'amount={self._amount}')
        if not self._amount or not (self._amount.satsInt > 0 or self._amount.isMax):
            self.setValid(False)
            return

        # for MAX, estimate is assumed to be calculated and set in self._amount.satsInt
        if self._amount.satsInt < MIN_FUNDING_SAT:
            message = _('Minimum required amount: {}').format(
                self._wallet.wallet.config.format_amount_and_units(MIN_FUNDING_SAT)
            )
            if self._amount.isMax and self._determine_max_message:
                message += '\n' + self._determine_max_message
            self.setWarning(message)
            self.setValid(False)
            return

        if self._amount.satsInt > self._wallet.wallet.config.LIGHTNING_MAX_FUNDING_SAT:
            self.setWarning(_('Amount is above maximum channel size: {}').format(
                self._wallet.wallet.config.format_amount_and_units(self._wallet.wallet.config.LIGHTNING_MAX_FUNDING_SAT)
            ))
            self.setValid(False)
            return

        self.setValid(True)

    @pyqtSlot(str, result=bool)
    def validateConnectString(self, connect_str):
        try:
            extract_nodeid(connect_str)
        except ConnStringFormatError as e:
            self._logger.debug(f'invalid connect_str. {e!r}')
            return False
        return True

    # FIXME "max" button in amount_dialog should enforce LIGHTNING_MAX_FUNDING_SAT
    @pyqtSlot()
    @pyqtSlot(bool)
    def openChannel(self, confirm_backup_conflict=False):
        if not self.valid:
            return

        self._logger.debug(f'Connect String: {self._connect_str!r}')

        lnworker = self._wallet.wallet.lnworker
        if lnworker.has_conflicting_backup_with(self._node_pubkey) and not confirm_backup_conflict:
            self.conflictingBackup.emit(messages.MSG_CONFLICTING_BACKUP_INSTANCE)
            return

        amount = '!' if self._amount.isMax else self._amount.satsInt
        self._logger.debug('amount = %s' % str(amount))

        coins = self._wallet.wallet.get_spendable_coins(None, nonlocal_only=True)

        mktx = lambda amt, fee_policy: lnworker.mktx_for_open_channel(
            coins=coins,
            funding_sat=amt,
            node_id=self._node_pubkey,
            fee_policy=fee_policy)

        acpt = lambda tx: self.do_open_channel(tx, self._connect_str_resolved, self._wallet.password)

        self._finalizer = QETxFinalizer(self, make_tx=mktx, accept=acpt)
        self._finalizer.canRbf = False
        self._finalizer.amount = self._amount
        self._finalizer.wallet = self._wallet
        self.finalizerChanged.emit()

    @auth_protect(message=_('Open Lightning channel?'))
    def do_open_channel(self, funding_tx, conn_str, password):
        """
        conn_str: a connection string that extract_nodeid can parse, i.e. cannot be a trampoline name
        """
        self._logger.debug('opening channel')
        # read funding_sat from tx; converts '!' to int value
        funding_sat = funding_tx.output_value_for_address(DummyAddress.CHANNEL)
        lnworker = self._wallet.wallet.lnworker

        def open_thread():
            error = None
            try:
                chan, _funding_tx = lnworker.open_channel(
                    connect_str=conn_str,
                    funding_tx=funding_tx,
                    funding_sat=funding_sat,
                    push_amt_sat=0,
                    password=password)
                self._logger.debug('opening channel succeeded')
                self.channelOpenSuccess.emit(chan.channel_id.hex(), chan.has_onchain_backup(),
                                             chan.constraints.funding_txn_minimum_depth, funding_tx.is_complete())

                # TODO: handle incomplete TX
                # if not funding_tx.is_complete():
                #     self._txdetails = QETxDetails(self)
                #     self._txdetails.rawTx = funding_tx
                #     self._txdetails.wallet = self._wallet
                #     self.txDetailsChanged.emit()

            except (CancelledError, TimeoutError):
                error = _('Could not connect to channel peer')
            except Exception as e:
                error = str(e)
                if not error:
                    error = repr(e)
            finally:
                if error:
                    self._logger.exception("Problem opening channel: %s", error)
                    self.channelOpenError.emit(error)

        self._logger.debug('starting open thread')
        self.channelOpening.emit(conn_str)
        threading.Thread(target=open_thread, daemon=True).start()

    @pyqtSlot(str, result=str)
    def channelBackup(self, cid):
        return self._wallet.wallet.lnworker.export_channel_backup(bfh(cid))

    @pyqtSlot()
    def updateMaxAmount(self):
        if self._updating_max:
            return

        self._updating_max = True

        def calc_max():
            try:
                coins = self._wallet.wallet.get_spendable_coins(None, nonlocal_only=True)
                dummy_nodeid = ecc.GENERATOR.get_public_key_bytes(compressed=True)
                make_tx = lambda fee_policy: self._wallet.wallet.lnworker.mktx_for_open_channel(
                    coins=coins,
                    funding_sat='!',
                    node_id=dummy_nodeid,
                    fee_policy=fee_policy)

                amount, self._determine_max_message = self._wallet.determine_max(mktx=make_tx)
                self._amount.satsInt = amount if amount else 0
            finally:
                self._updating_max = False
                self.validate()

        threading.Thread(target=calc_max, daemon=True).start()
