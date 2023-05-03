import threading
from concurrent.futures import CancelledError
from asyncio.exceptions import TimeoutError

from PyQt5.QtCore import pyqtProperty, pyqtSignal, pyqtSlot, QObject

from electrum.i18n import _
from electrum.gui import messages
from electrum.util import bfh
from electrum.lnutil import extract_nodeid, ln_dummy_address, ConnStringFormatError
from electrum.lnworker import hardcoded_trampoline_nodes
from electrum.logging import get_logger

from .auth import AuthMixin, auth_protect
from .qetxfinalizer import QETxFinalizer
from .qetxdetails import QETxDetails
from .qetypes import QEAmount
from .qewallet import QEWallet


class QEChannelOpener(QObject, AuthMixin):
    _logger = get_logger(__name__)

    validationError = pyqtSignal([str,str], arguments=['code','message'])
    conflictingBackup = pyqtSignal([str], arguments=['message'])
    channelOpening = pyqtSignal([str], arguments=['peer'])
    channelOpenError = pyqtSignal([str], arguments=['message'])
    channelOpenSuccess = pyqtSignal([str,bool,int,bool], arguments=['cid','has_onchain_backup','min_depth','tx_complete'])

    dataChanged = pyqtSignal() # generic notify signal

    def __init__(self, parent=None):
        super().__init__(parent)

        self._wallet = None
        self._connect_str = None
        self._amount = QEAmount()
        self._valid = False
        self._opentx = None
        self._txdetails = None

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

    # FIXME min channel funding amount
    # FIXME have requested funding amount
    def validate(self):
        """side-effects: sets self._valid, self._node_pubkey, self._connect_str_resolved"""
        connect_str_valid = False
        if self._connect_str:
            self._logger.debug(f'checking if {self._connect_str=!r} is valid')
            if not self._wallet.wallet.config.get('use_gossip', False):
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

        if not connect_str_valid:
            self._valid = False
            self.validChanged.emit()
            return

        self._logger.debug('amount=%s' % str(self._amount))
        if not self._amount or not (self._amount.satsInt > 0 or self._amount.isMax):
            self._valid = False
            self.validChanged.emit()
            return

        self._valid = True
        self.validChanged.emit()

    @pyqtSlot(str, result=bool)
    def validateConnectString(self, connect_str):
        try:
            node_id, rest = extract_nodeid(connect_str)
        except ConnStringFormatError as e:
            self._logger.debug(f"invalid connect_str. {e!r}")
            return False
        return True

    # FIXME "max" button in amount_dialog should enforce LN_MAX_FUNDING_SAT
    @pyqtSlot()
    @pyqtSlot(bool)
    def openChannel(self, confirm_backup_conflict=False):
        if not self.valid:
            return

        self._logger.debug(f'Connect String: {self._connect_str!r}')

        lnworker = self._wallet.wallet.lnworker
        if lnworker.has_conflicting_backup_with(self._node_pubkey) and not confirm_backup_conflict:
            self.conflictingBackup.emit(messages.MGS_CONFLICTING_BACKUP_INSTANCE)
            return

        amount = '!' if self._amount.isMax else self._amount.satsInt
        self._logger.debug('amount = %s' % str(amount))

        coins = self._wallet.wallet.get_spendable_coins(None, nonlocal_only=True)

        mktx = lambda amt: lnworker.mktx_for_open_channel(
            coins=coins,
            funding_sat=amt,
            node_id=self._node_pubkey,
            fee_est=None)

        acpt = lambda tx: self.do_open_channel(tx, self._connect_str_resolved)

        self._finalizer = QETxFinalizer(self, make_tx=mktx, accept=acpt)
        self._finalizer.canRbf = False
        self._finalizer.amount = self._amount
        self._finalizer.wallet = self._wallet
        self.finalizerChanged.emit()

    @auth_protect(method='keystore_else_pin', message=_('Open Lightning channel?'))
    def do_open_channel(self, funding_tx, conn_str, password=None):
        """
        conn_str: a connection string that extract_nodeid can parse, i.e. cannot be a trampoline name
        """
        self._logger.debug('opening channel')
        # read funding_sat from tx; converts '!' to int value
        funding_sat = funding_tx.output_value_for_address(ln_dummy_address())
        lnworker = self._wallet.wallet.lnworker

        if password is None:
            password = self._wallet.password

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
                #if not funding_tx.is_complete():
                    #self._txdetails = QETxDetails(self)
                    #self._txdetails.rawTx = funding_tx
                    #self._txdetails.wallet = self._wallet
                    #self.txDetailsChanged.emit()

            except (CancelledError,TimeoutError):
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
