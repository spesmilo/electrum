from typing import TYPE_CHECKING

import PyQt5.QtGui as QtGui
import PyQt5.QtWidgets as QtWidgets
import PyQt5.QtCore as QtCore

from electrum.i18n import _
from electrum.util import bh2u, format_time
from electrum.lnutil import format_short_channel_id, LOCAL, REMOTE, UpdateAddHtlc, Direction
from electrum.lnchan import htlcsum
from electrum.lnaddr import LnAddr, lndecode
from electrum.bitcoin import COIN

if TYPE_CHECKING:
    from .main_window import ElectrumWindow

class HTLCItem(QtGui.QStandardItem):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.setEditable(False)

class SelectableLabel(QtWidgets.QLabel):
    def __init__(self, text=''):
        super().__init__(text)
        self.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse)

class LinkedLabel(QtWidgets.QLabel):
    def __init__(self, text, on_clicked):
        super().__init__(text)
        self.linkActivated.connect(on_clicked)

class ChannelDetailsDialog(QtWidgets.QDialog):
    def make_htlc_item(self, i: UpdateAddHtlc, direction: Direction) -> HTLCItem:
        it = HTLCItem(_('Sent HTLC with ID {}' if Direction.SENT == direction else 'Received HTLC with ID {}').format(i.htlc_id))
        it.appendRow([HTLCItem(_('Amount')),HTLCItem(self.format(i.amount_msat))])
        it.appendRow([HTLCItem(_('CLTV expiry')),HTLCItem(str(i.cltv_expiry))])
        it.appendRow([HTLCItem(_('Payment hash')),HTLCItem(bh2u(i.payment_hash))])
        return it

    def append_lnaddr(self, it: HTLCItem, lnaddr: LnAddr):
        invoice = HTLCItem(_('Invoice'))
        invoice.appendRow([HTLCItem(_('Remote node public key')), HTLCItem(bh2u(lnaddr.pubkey.serialize()))])
        invoice.appendRow([HTLCItem(_('Amount in sat')), HTLCItem(str(lnaddr.amount * COIN))]) # might have a comma because mSAT!
        invoice.appendRow([HTLCItem(_('Description')), HTLCItem(dict(lnaddr.tags).get('d', _('N/A')))])
        invoice.appendRow([HTLCItem(_('Date')), HTLCItem(format_time(lnaddr.date))])
        it.appendRow([invoice])

    def make_inflight(self, lnaddr, i: UpdateAddHtlc, direction: Direction) -> HTLCItem:
        it = self.make_htlc_item(i, direction)
        self.append_lnaddr(it, lnaddr)
        return it

    def make_model(self, htlcs) -> QtGui.QStandardItemModel:
        model = QtGui.QStandardItemModel(0, 2)
        model.setHorizontalHeaderLabels(['HTLC', 'Property value'])
        parentItem = model.invisibleRootItem()
        folder_types = {'settled': _('Fulfilled HTLCs'), 'inflight': _('HTLCs in current commitment transaction')}
        self.folders = {}

        self.keyname_rows = {}

        invoices = dict(self.window.wallet.lnworker.invoices)

        for keyname, i in folder_types.items():
            myFont=QtGui.QFont()
            myFont.setBold(True)
            folder = HTLCItem(i)
            folder.setFont(myFont)
            parentItem.appendRow(folder)
            self.folders[keyname] = folder
            mapping = {}
            num = 0
            if keyname == 'inflight':
                for lnaddr, i, direction in htlcs[keyname]:
                    it = self.make_inflight(lnaddr, i, direction)
                    self.folders[keyname].appendRow(it)
                    mapping[i.payment_hash] = num
                    num += 1
            elif keyname == 'settled':
                for date, direction, i, preimage in htlcs[keyname]:
                    it = self.make_htlc_item(i, direction)
                    hex_pay_hash = bh2u(i.payment_hash)
                    if hex_pay_hash in invoices:
                        # if we made the invoice and still have it, we can show more info
                        invoice = invoices[hex_pay_hash][1]
                        self.append_lnaddr(it, lndecode(invoice))
                    self.folders[keyname].appendRow(it)
                    mapping[i.payment_hash] = num
                    num += 1

            self.keyname_rows[keyname] = mapping
        return model

    def move(self, fro: str, to: str, payment_hash: bytes):
        assert fro != to
        row_idx = self.keyname_rows[fro].pop(payment_hash)
        row = self.folders[fro].takeRow(row_idx)
        self.folders[to].appendRow(row)
        dest_mapping = self.keyname_rows[to]
        dest_mapping[payment_hash] = len(dest_mapping)

    ln_payment_completed = QtCore.pyqtSignal(str, float, Direction, UpdateAddHtlc, bytes, bytes)
    htlc_added = QtCore.pyqtSignal(str, UpdateAddHtlc, LnAddr, Direction)

    @QtCore.pyqtSlot(str, UpdateAddHtlc, LnAddr, Direction)
    def do_htlc_added(self, evtname, htlc, lnaddr, direction):
        mapping = self.keyname_rows['inflight']
        mapping[htlc.payment_hash] = len(mapping)
        self.folders['inflight'].appendRow(self.make_inflight(lnaddr, htlc, direction))

    @QtCore.pyqtSlot(str, float, Direction, UpdateAddHtlc, bytes, bytes)
    def do_ln_payment_completed(self, evtname, date, direction, htlc, preimage, chan_id):
        self.move('inflight', 'settled', htlc.payment_hash)
        self.update_sent_received()

    def update_sent_received(self):
        self.sent_label.setText(str(htlcsum(self.chan.hm.settled_htlcs_by(LOCAL))))
        self.received_label.setText(str(htlcsum(self.chan.hm.settled_htlcs_by(REMOTE))))

    @QtCore.pyqtSlot(str)
    def show_tx(self, link_text: str):
        funding_tx = self.window.wallet.transactions[self.chan.funding_outpoint.txid]
        self.window.show_transaction(funding_tx, tx_desc=_('Funding Transaction'))

    def __init__(self, window: 'ElectrumWindow', chan_id: bytes):
        super().__init__(window)

        # initialize instance fields
        self.window = window
        chan = self.chan = window.wallet.lnworker.channels[chan_id]
        self.format = lambda msat: window.format_amount_and_units(msat / 1000)

        # connect signals with slots
        self.ln_payment_completed.connect(self.do_ln_payment_completed)
        self.htlc_added.connect(self.do_htlc_added)

        # register callbacks for updating
        window.network.register_callback(self.ln_payment_completed.emit, ['ln_payment_completed'])
        window.network.register_callback(self.htlc_added.emit, ['htlc_added'])

        # set attributes of QDialog
        self.setWindowTitle(_('Channel Details'))
        self.setMinimumSize(800, 400)

        # add layouts
        vbox = QtWidgets.QVBoxLayout(self)
        form_layout = QtWidgets.QFormLayout(None)
        vbox.addLayout(form_layout)

        # add form content
        form_layout.addRow(_('Node ID:'), SelectableLabel(bh2u(chan.node_id)))
        form_layout.addRow(_('Channel ID:'), SelectableLabel(bh2u(chan.channel_id)))
        funding_label_text = f'<a href=click_destination>{chan.funding_outpoint.txid}</a>:{chan.funding_outpoint.output_index}'
        form_layout.addRow(_('Funding Outpoint:'), LinkedLabel(funding_label_text, self.show_tx))
        form_layout.addRow(_('Short Channel ID:'), SelectableLabel(format_short_channel_id(chan.short_channel_id)))
        self.received_label = SelectableLabel()
        form_layout.addRow(_('Received (mSAT):'), self.received_label)
        self.sent_label = SelectableLabel()
        form_layout.addRow(_('Sent (mSAT):'), self.sent_label)

        # add htlc tree view to vbox (wouldn't scale correctly in QFormLayout)
        form_layout.addRow(_('Payments (HTLCs):'), None)
        w = QtWidgets.QTreeView(self)
        htlcs = window.wallet.lnworker._list_invoices(chan_id)
        w.setModel(self.make_model(htlcs))
        w.header().setSectionResizeMode(0, QtWidgets.QHeaderView.ResizeToContents)
        vbox.addWidget(w)

        # initialize sent/received fields
        self.update_sent_received()
