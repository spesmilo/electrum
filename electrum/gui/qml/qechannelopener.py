from PyQt5.QtCore import pyqtProperty, pyqtSignal, pyqtSlot, QObject

from electrum.logging import get_logger
from electrum.util import format_time
from electrum.lnutil import extract_nodeid, ConnStringFormatError
from electrum.gui import messages

from .qewallet import QEWallet
from .qetypes import QEAmount

class QEChannelOpener(QObject):
    def __init__(self, parent=None):
        super().__init__(parent)

    _logger = get_logger(__name__)

    _wallet = None
    _nodeid = None
    _amount = QEAmount()
    _valid = False
    _opentx = None

    validationError = pyqtSignal([str,str], arguments=['code','message'])
    conflictingBackup = pyqtSignal([str], arguments=['message'])

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
            self._amount = amount
            self.amountChanged.emit()
            self.validate()

    validChanged = pyqtSignal()
    @pyqtProperty(bool, notify=validChanged)
    def valid(self):
        return self._valid

    openTxChanged = pyqtSignal()
    @pyqtProperty(bool, notify=openTxChanged)
    def openTx(self):
        return self._opentx

    def validate(self):
        nodeid_valid = False
        if self._nodeid:
            try:
                self._node_pubkey, self._host_port = extract_nodeid(self._nodeid)
                nodeid_valid = True
            except ConnStringFormatError as e:
                self.validationError.emit('invalid_nodeid', repr(e))

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

    # FIXME "max" button in amount_dialog should enforce LN_MAX_FUNDING_SAT
    @pyqtSlot()
    @pyqtSlot(bool)
    def open_channel(self, confirm_backup_conflict=False):
        if not self.valid:
            return

        #if self.use_gossip:
            #conn_str = self.pubkey
            #if self.ipport:
                #conn_str += '@' + self.ipport.strip()
        #else:
            #conn_str = str(self.trampolines[self.pubkey])
        amount = '!' if self._amount.isMax else self._amount.satsInt

        lnworker = self._wallet.wallet.lnworker
        if lnworker.has_conflicting_backup_with(node_pubkey) and not confirm_backup_conflict:
            self.conflictingBackup.emit(messages.MGS_CONFLICTING_BACKUP_INSTANCE)
            return

        coins = self._wallet.wallet.get_spendable_coins(None, nonlocal_only=True)
        #node_id, rest = extract_nodeid(conn_str)
        make_tx = lambda rbf: lnworker.mktx_for_open_channel(
            coins=coins,
            funding_sat=amount,
            node_id=self._node_pubkey,
            fee_est=None)
        #on_pay = lambda tx: self.app.protected('Create a new channel?', self.do_open_channel, (tx, conn_str))
        #d = ConfirmTxDialog(
            #self.app,
            #amount = amount,
            #make_tx=make_tx,
            #on_pay=on_pay,
            #show_final=False)
        #d.open()

    #def do_open_channel(self, funding_tx, conn_str, password):
        ## read funding_sat from tx; converts '!' to int value
        #funding_sat = funding_tx.output_value_for_address(ln_dummy_address())
        #lnworker = self.app.wallet.lnworker
        #try:
            #chan, funding_tx = lnworker.open_channel(
                #connect_str=conn_str,
                #funding_tx=funding_tx,
                #funding_sat=funding_sat,
                #push_amt_sat=0,
                #password=password)
        #except Exception as e:
            #self.app.logger.exception("Problem opening channel")
            #self.app.show_error(_('Problem opening channel: ') + '\n' + repr(e))
            #return
        ## TODO: it would be nice to show this before broadcasting
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
