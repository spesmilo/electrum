import threading
from concurrent.futures import CancelledError
from asyncio.exceptions import TimeoutError

from PyQt5.QtCore import pyqtProperty, pyqtSignal, pyqtSlot, QObject

from electrum.i18n import _
from electrum.gui import messages
from electrum.util import bfh
from electrum.lnutil import extract_nodeid, LNPeerAddr, ln_dummy_address
from electrum.lnworker import hardcoded_trampoline_nodes
from electrum.logging import get_logger

from .auth import AuthMixin, auth_protect
from .qetxfinalizer import QETxFinalizer
from .qetxdetails import QETxDetails
from .qetypes import QEAmount
from .qewallet import QEWallet


class QEChannelOpener(QObject, AuthMixin):
    def __init__(self, parent=None):
        super().__init__(parent)

    _logger = get_logger(__name__)

    _wallet = None
    _nodeid = None
    _amount = QEAmount()
    _valid = False
    _opentx = None
    _txdetails = None

    validationError = pyqtSignal([str,str], arguments=['code','message'])
    conflictingBackup = pyqtSignal([str], arguments=['message'])
    channelOpening = pyqtSignal([str], arguments=['peer'])
    channelOpenError = pyqtSignal([str], arguments=['message'])
    channelOpenSuccess = pyqtSignal([str,bool,int,bool], arguments=['cid','has_onchain_backup','min_depth','tx_complete'])

    dataChanged = pyqtSignal() # generic notify signal

    walletChanged = pyqtSignal()
    @pyqtProperty(QEWallet, notify=walletChanged)
    def wallet(self):
        return self._wallet

    @wallet.setter
    def wallet(self, wallet: QEWallet):
        if self._wallet != wallet:
            self._wallet = wallet
            self.walletChanged.emit()

    nodeidChanged = pyqtSignal()
    @pyqtProperty(str, notify=nodeidChanged)
    def nodeid(self):
        return self._nodeid

    @nodeid.setter
    def nodeid(self, nodeid: str):
        if self._nodeid != nodeid:
            self._logger.debug('nodeid set -> %s' % nodeid)
            self._nodeid = nodeid
            self.nodeidChanged.emit()
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
        nodeid_valid = False
        if self._nodeid:
            self._logger.debug(f'checking if {self._nodeid} is valid')
            if not self._wallet.wallet.config.get('use_gossip', False):
                self._peer = hardcoded_trampoline_nodes()[self._nodeid]
                nodeid_valid = True
            else:
                try:
                    self._peer = self.nodeid_to_lnpeer(self._nodeid)
                    nodeid_valid = True
                except:
                    pass

        if not nodeid_valid:
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
    def validate_nodeid(self, nodeid):
        try:
            self.nodeid_to_lnpeer(nodeid)
        except Exception as e:
            self._logger.debug(repr(e))
            return False
        return True

    def nodeid_to_lnpeer(self, nodeid):
        node_pubkey, host_port = extract_nodeid(nodeid)
        host, port = host_port.split(':',1)
        return LNPeerAddr(host, int(port), node_pubkey)

    # FIXME "max" button in amount_dialog should enforce LN_MAX_FUNDING_SAT
    @pyqtSlot()
    @pyqtSlot(bool)
    def open_channel(self, confirm_backup_conflict=False):
        if not self.valid:
            return

        self._logger.debug('Connect String: %s' % str(self._peer))

        lnworker = self._wallet.wallet.lnworker
        if lnworker.has_conflicting_backup_with(self._peer.pubkey) and not confirm_backup_conflict:
            self.conflictingBackup.emit(messages.MGS_CONFLICTING_BACKUP_INSTANCE)
            return

        amount = '!' if self._amount.isMax else self._amount.satsInt
        self._logger.debug('amount = %s' % str(amount))

        coins = self._wallet.wallet.get_spendable_coins(None, nonlocal_only=True)

        mktx = lambda amt: lnworker.mktx_for_open_channel(
            coins=coins,
            funding_sat=amt,
            node_id=self._peer.pubkey,
            fee_est=None)

        acpt = lambda tx: self.do_open_channel(tx, str(self._peer), self._wallet.password)

        self._finalizer = QETxFinalizer(self, make_tx=mktx, accept=acpt)
        self._finalizer.canRbf = False
        self._finalizer.amount = self._amount
        self._finalizer.wallet = self._wallet
        self.finalizerChanged.emit()

    @auth_protect
    def do_open_channel(self, funding_tx, conn_str, password):
        self._logger.debug('opening channel')
        # read funding_sat from tx; converts '!' to int value
        funding_sat = funding_tx.output_value_for_address(ln_dummy_address())
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
        threading.Thread(target=open_thread).start()

        # TODO: it would be nice to show this before broadcasting
        #if chan.has_onchain_backup():
            #self.maybe_show_funding_tx(chan, funding_tx)
        #else:
            #title = _('Save backup')
            #help_text = _(messages.MSG_CREATED_NON_RECOVERABLE_CHANNEL)
            #data = lnworker.export_channel_backup(chan.channel_id)
            #popup = QRDialog(
                #title, data,
                #show_text=False,
                #text_for_clipboard=data,
                #help_text=help_text,
                #close_button_text=_('OK'),
                #on_close=lambda: self.maybe_show_funding_tx(chan, funding_tx))
            #popup.open()


    #def maybe_show_funding_tx(self, chan, funding_tx):
        #n = chan.constraints.funding_txn_minimum_depth
        #message = '\n'.join([
            #_('Channel established.'),
            #_('Remote peer ID') + ':' + chan.node_id.hex(),
            #_('This channel will be usable after {} confirmations').format(n)
        #])
        #if not funding_tx.is_complete():
            #message += '\n\n' + _('Please sign and broadcast the funding transaction')
        #self.app.show_info(message)

        #if not funding_tx.is_complete():
            #self.app.tx_dialog(funding_tx)

    @pyqtSlot(str, result=str)
    def channelBackup(self, cid):
        return self._wallet.wallet.lnworker.export_channel_backup(bfh(cid))
