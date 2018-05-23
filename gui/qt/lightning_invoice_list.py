# -*- coding: utf-8 -*-
import base64
import binascii
from PyQt5 import QtCore, QtWidgets
from collections import OrderedDict
import logging
from .qrcodewidget import QRDialog
from PyQt5.QtCore import pyqtSignal, pyqtSlot

mapping = {0: "r_hash", 1: "pay_req", 2: "settled"}
revMapp = {"r_hash": 0, "pay_req": 1, "settled": 2}
datatable = OrderedDict([])
idx = 0

class MyTableRow(QtWidgets.QTreeWidgetItem):
    def __init__(self, di):
        if "settled" not in di:
            di["settled"] = False
        strs = [str(di[mapping[key]]) for key in range(len(mapping))]
        print(strs)
        super(MyTableRow, self).__init__(strs)
        assert isinstance(di, dict)
        self.di = di
    def __getitem__(self, idx):
        return self.di[idx]
    def __setitem__(self, idx, val):
        self.di[idx] = val
        try:
            self.setData(revMapp[idx], QtCore.Qt.DisplayRole, '{0}'.format(val))
        except KeyError:
            logging.warning("Lightning Invoice field %s unknown", idx)
    def __str__(self):
        return str(self.di)

def addInvoiceRow(new):
    made = MyTableRow(new)
    datatable[new["r_hash"]] = made
    datatable.move_to_end(new["r_hash"], last=False)
    return made

class LightningInvoiceList(QtWidgets.QWidget):
    invoice_added_signal = QtCore.pyqtSignal(dict)

    @QtCore.pyqtSlot(dict)
    def invoice_added_handler(self, di):
        self._tv.insertTopLevelItem(0, addInvoiceRow(invoice))

    def clickHandler(self, numInput, treeView, lnworker):
        amt = numInput.value()
        if amt < 1:
            print("value too small")
            return
        print("creating invoice with value {}".format(amt))
        global idx
        #obj = {
        #    "r_hash": binascii.hexlify((int.from_bytes(bytearray.fromhex("9500edb0994b7bc23349193486b25c82097045db641f35fa988c0e849acdec29"), "big")+idx).to_bytes(byteorder="big", length=32)).decode("ascii"),
        #    "pay_req": "lntb81920n1pdf258s" + str(idx),
        #    "settled": False
        #}
        #treeView.insertTopLevelItem(0, addInvoiceRow(obj))
        idx += 1
        lnworker.add_invoice_from_other_thread(amt)

    def create_menu(self, position):
        menu = QtWidgets.QMenu()
        pay_req = self._tv.currentItem()["pay_req"]
        cb = QtWidgets.QApplication.instance().clipboard()
        def copy():
            print(pay_req)
            cb.setText(pay_req)
        def qr():
            d = QRDialog(pay_req, self, "Lightning invoice")
            d.exec_()
        menu.addAction("Copy payment request", copy)
        menu.addAction("Show payment request as QR code", qr)
        menu.exec_(self._tv.viewport().mapToGlobal(position))

    payment_received_signal = pyqtSignal(dict)

    @pyqtSlot(dict)
    def paymentReceived(self, new):
        try:
            obj = datatable[new["r_hash"]]
        except KeyError:
            print("lightning payment invoice r_hash {} unknown!".format(new["r_hash"]))
        else:
            for k, v in new.items():
                try:
                    if obj[k] != v: obj[k] = v
                except KeyError:
                    obj[k] = v

    def __init__(self, parent, lnworker):
        QtWidgets.QWidget.__init__(self, parent)

        self.payment_received_signal.connect(self.paymentReceived)
        self.invoice_added_signal.connect(self.invoice_added_handler)

        lnworker.subscribe_payment_received_from_other_thread(self.payment_received_signal.emit)
        lnworker.subscribe_invoice_added_from_other_thread(self.invoice_added_signal.emit)

        self._tv=QtWidgets.QTreeWidget(self)
        self._tv.setHeaderLabels([mapping[i] for i in range(len(mapping))])
        self._tv.setColumnCount(len(mapping))
        self._tv.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self._tv.customContextMenuRequested.connect(self.create_menu)

        class SatoshiCountSpinBox(QtWidgets.QSpinBox):
            def keyPressEvent(self2, e):
                super(SatoshiCountSpinBox, self2).keyPressEvent(e)
                if QtCore.Qt.Key_Return == e.key():
                    self.clickHandler(self2, self._tv, lnworker)

        numInput = SatoshiCountSpinBox(self)

        button = QtWidgets.QPushButton('Add invoice', self)
        button.clicked.connect(lambda: self.clickHandler(numInput, self._tv, lnworker))

        l=QtWidgets.QVBoxLayout(self)
        h=QtWidgets.QGridLayout(self)
        h.addWidget(numInput, 0, 0)
        h.addWidget(button, 0, 1)
        #h.addItem(QtWidgets.QSpacerItem(100, 200, QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Preferred), 0, 2)
        #h.setSizePolicy(
        h.setColumnStretch(0, 1)
        h.setColumnStretch(1, 1)
        h.setColumnStretch(2, 2)
        l.addLayout(h)
        l.addWidget(self._tv)

        self.resize(2500,1000)

def tick():
  key = "9500edb0994b7bc23349193486b25c82097045db641f35fa988c0e849acdec29"
  if not key in datatable:
      return
  row = datatable[key]
  row["settled"] = not row["settled"]
  print("data changed")

if __name__=="__main__":
    from sys import argv, exit

    a=QtWidgets.QApplication(argv)

    w=LightningInvoiceList()
    w.show()
    w.raise_()

    timer = QtCore.QTimer()
    timer.timeout.connect(tick)
    timer.start(1000)
    exit(a.exec_())
