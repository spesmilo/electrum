from typing import Optional, TYPE_CHECKING

import PyQt5.QtGui as QtGui
import PyQt5.QtWidgets as QtWidgets
import PyQt5.QtCore as QtCore

from electrum.i18n import _
from electrum.lnchan import UpdateAddHtlc
from electrum.util import bh2u, format_time
from electrum.lnchan import HTLCOwner
from electrum.lnaddr import LnAddr, lndecode
if TYPE_CHECKING:
    from .main_window import ElectrumWindow

class HTLCItem(QtGui.QStandardItem):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.setEditable(False)

class ChannelDetailsDialog(QtWidgets.QDialog):

    def make_inflight(self, lnaddr, i: UpdateAddHtlc):
        it = HTLCItem(_('HTLC with ID ') + str(i.htlc_id))
        it.appendRow([HTLCItem(_('Amount')),HTLCItem(self.format(i.amount_msat))])
        it.appendRow([HTLCItem(_('CLTV expiry')),HTLCItem(str(i.cltv_expiry))])
        it.appendRow([HTLCItem(_('Payment hash')),HTLCItem(bh2u(i.payment_hash))])
        invoice = HTLCItem(_('Invoice'))
        invoice.appendRow([HTLCItem(_('Remote node public key')), HTLCItem(bh2u(lnaddr.pubkey.serialize()))])
        invoice.appendRow([HTLCItem(_('Amount in BTC')), HTLCItem(str(lnaddr.amount))])
        invoice.appendRow([HTLCItem(_('Description')), HTLCItem(dict(lnaddr.tags).get('d', _('N/A')))])
        invoice.appendRow([HTLCItem(_('Date')), HTLCItem(format_time(lnaddr.date))])
        it.appendRow([invoice])
        return it

    def make_model(self, htlcs):
        model = QtGui.QStandardItemModel(0, 2)
        model.setHorizontalHeaderLabels(['HTLC', 'Property value'])
        parentItem = model.invisibleRootItem()
        folder_types = {'settled': _('Fulfilled HTLCs'), 'inflight': _('HTLCs in current commitment transaction')}
        self.folders = {}

        self.keyname_rows = {}

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
                for lnaddr, i in htlcs[keyname]:
                    it = self.make_inflight(lnaddr, i)
                    self.folders[keyname].appendRow(it)
                    mapping[i.payment_hash] = num
                    num += 1
            elif keyname == 'settled':
                for date, direction, i, preimage in htlcs[keyname]:
                    it = HTLCItem(_('HTLC with ID ') + str(i.htlc_id))
                    it.appendRow([HTLCItem(_('Amount')),HTLCItem(self.format(i.amount_msat))])
                    it.appendRow([HTLCItem(_('CLTV expiry')),HTLCItem(str(i.cltv_expiry))])
                    it.appendRow([HTLCItem(_('Payment hash')),HTLCItem(bh2u(i.payment_hash))])
                    # NOTE no invoices because user can delete invoices after settlement
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

    ln_payment_completed = QtCore.pyqtSignal(str, float, HTLCOwner, UpdateAddHtlc, bytes, bytes)
    htlc_added = QtCore.pyqtSignal(str, UpdateAddHtlc, LnAddr, HTLCOwner)

    @QtCore.pyqtSlot(str, UpdateAddHtlc, LnAddr, HTLCOwner)
    def do_htlc_added(self, evtname, htlc, lnaddr, direction):
        mapping = self.keyname_rows['inflight']
        mapping[htlc.payment_hash] = len(mapping)
        self.folders['inflight'].appendRow(self.make_inflight(lnaddr, htlc))

    @QtCore.pyqtSlot(str, float, HTLCOwner, UpdateAddHtlc, bytes, bytes)
    def do_ln_payment_completed(self, evtname, date, direction, htlc, preimage, chan_id):
        self.move('inflight', 'settled', htlc.payment_hash)

    def __init__(self, window: Optional['ElectrumWindow'], chan_id: bytes):
        super().__init__(window)
        self.window = window
        assert type(window).__name__ in ['NoneType', 'ElectrumWindow']
        self.ln_payment_completed.connect(self.do_ln_payment_completed)
        self.htlc_added.connect(self.do_htlc_added)
        if not window:
            self.format = str
            htlcs = {
                    'settled':
                        [
                        ],
                    'inflight':
                        [
                            (lndecode("lnbcrt100n1pdl9c2vpp5z6ztyjy8an80te3u6l0fxuhjzt9pfa27a27uqap3xt8nv6dq47esdqgw3jhxapncqzy3rzjq2j0zgr9slpsefhaem0rq9w3kgjx6mjfd9tp7pe8yw23jqydcdtrsqqrc5qqqqgqqqqqqqlgqqqqqqgqjq5v97p0f0ftkwzmpxhjj6magd5ars465krljcp5z28j3nxl8d0kqjkzf6acjerxdu3yvtus75kakx3yvyus6c68hdwm2hpunusr47w3gpee4hgp"), UpdateAddHtlc(amount_msat=10001,  payment_hash=b"\x01"*32, cltv_expiry=500, htlc_id=1)),
                            (lndecode('lnbcrt22m1pdl9kc7pp5qw903tar0e3ar4mu4h8m3zratj0sddqhfftpsjgcx0jsekzk43dsdqqcqzy3a6ev4vh6lt62xrzlq5l23g59pv0g3tur6drnduhczqg8smqlm75nklwx8r0mm535e4x8uq6tzqw7j7tvy70qaapfnt3e9n6rltvcs7cppzmqys'), UpdateAddHtlc(amount_msat=10002,  payment_hash=b"\x02"*32, cltv_expiry=501, htlc_id=2)),
                            (lndecode('lnbcrt1u1pdl9k6tpp58la47qfxz6mvtgjmnmkl8xe8vcrkhluxrldlhv3dgdlla6tr3mvqdqgw3jhxapncqzy3rzjq2j0zgr9slpsefhaem0rq9w3kgjx6mjfd9tp7pe8yw23jqydcdtrsqqrc5qqqqgqqqqqqqlgqqqqqqgqjqavsdk9qdjwgfdywhlqtuzn5atkhzt9sgjz6tfll67wc34rh80mqzjme3meqyutrj0p7tvxczeuag956h6fv0356ezstgpfgqy47d7vsq7vhx6l'), UpdateAddHtlc(amount_msat=10003,  payment_hash=b"\x03"*32, cltv_expiry=502, htlc_id=3)),
                        ],
            }
        else:
            htlcs = self.window.wallet.lnworker._list_invoices(chan_id)
            self.format = lambda msat: self.window.format_amount_and_units(msat / 1000)
            self.window.network.register_callback(self.ln_payment_completed.emit, ['ln_payment_completed'])
            self.window.network.register_callback(self.htlc_added.emit, ['htlc_added'])
        self.setWindowTitle(_('Channel Details'))
        self.setMinimumSize(800, 400)
        vbox = QtWidgets.QVBoxLayout(self)
        w = QtWidgets.QTreeView(self)
        w.setModel(self.make_model(htlcs))
        #w.header().setStretchLastSection(False)
        w.header().setSectionResizeMode(0, QtWidgets.QHeaderView.ResizeToContents)
        vbox.addWidget(w)


if __name__ == '__main__':
    import sys
    app = QtWidgets.QApplication(sys.argv)
    d = ChannelDetailsDialog(None, b"\x01"*32)
    d.show()

    timer = QtCore.QTimer()
    timer.setSingleShot(True)
    def tick():
        d.move('inflight', 'settled', b'\x02' * 32)
    timer.timeout.connect(tick)
    timer.start(3000)

    sys.exit(app.exec_())
