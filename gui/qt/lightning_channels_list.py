# -*- coding: utf-8 -*-
import binascii, base64
from PyQt5 import QtCore, QtWidgets
from collections import OrderedDict
import logging
import traceback

# https://api.lightning.community/#listchannels
mapping = {0: "chan_id"}
revMapp = {"chan_id": 0}
datatable = OrderedDict([])

class MyTableRow(QtWidgets.QTreeWidgetItem):
    def __init__(self, di):
        strs = [str(di[mapping[key]]) for key in range(len(mapping))]
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
            logging.warning("Lightning Channel field %s unknown", idx)
    def __str__(self):
        return str(self.di)

def addChannelRow(new):
    made = MyTableRow(new)
    datatable[new["chan_id"]] = made
    datatable.move_to_end(new["chan_id"], last=False)
    return made


class LightningChannelsList(QtWidgets.QWidget):
    update_rows = QtCore.pyqtSignal(dict)
    update_single_row = QtCore.pyqtSignal(dict)

    def open_channel(self, nodeIdInput, local_amt_inp, push_amt_inp, password):
        node_id = str(nodeIdInput.text())
        print("creating channel with {}".format(node_id))
        local_amt = int(local_amt_inp.text())
        push_amt = int(push_amt_inp.text())
        assert local_amt >= 200000
        assert local_amt >= push_amt
        obj = self.lnworker.open_channel(node_id, local_amt, push_amt, password)

    @QtCore.pyqtSlot(dict)
    def do_update_single_row(self, new):
        try:
            obj = datatable[new["chan_id"]]
        except KeyError:
            print("lightning chan_id {} unknown!".format(new["chan_id"]))
        else:
            for k, v in new.items():
                try:
                    if obj[k] != v: obj[k] = v
                except KeyError:
                    obj[k] = v

    def create_menu(self, position):
        menu = QtWidgets.QMenu()
        cur = self._tv.currentItem()
        def close():
            print("closechannel result", lnworker.close_channel_from_other_thread(cur.di))
        menu.addAction("Close channel", close)
        menu.exec_(self._tv.viewport().mapToGlobal(position))

    @QtCore.pyqtSlot(dict)
    def do_update_rows(self, obj):
        self._tv.clear()
        for i in obj["channels"]:
            self._tv.insertTopLevelItem(0, addChannelRow(i))

    def __init__(self, parent, lnworker):
        QtWidgets.QWidget.__init__(self, parent)
        self.main_window = parent

        self.update_rows.connect(self.do_update_rows)
        self.update_single_row.connect(self.do_update_single_row)

        self.lnworker = lnworker

        #lnworker.subscribe_channel_list_updates_from_other_thread(self.update_rows.emit)
        #lnworker.subscribe_single_channel_update_from_other_thread(self.update_single_row.emit)

        self._tv=QtWidgets.QTreeWidget(self)
        self._tv.setHeaderLabels([mapping[i] for i in range(len(mapping))])
        self._tv.setColumnCount(len(mapping))
        self._tv.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self._tv.customContextMenuRequested.connect(self.create_menu)

        nodeid_inp = QtWidgets.QLineEdit(self)
        local_amt_inp = QtWidgets.QLineEdit(self, text='200000')
        push_amt_inp = QtWidgets.QLineEdit(self, text='0')
        button = QtWidgets.QPushButton('Open channel', self)
        button.clicked.connect(lambda: self.main_window.protect(self.open_channel, (nodeid_inp, local_amt_inp, push_amt_inp)))

        l=QtWidgets.QVBoxLayout(self)
        h=QtWidgets.QGridLayout(self)
        nodeid_label = QtWidgets.QLabel(self)
        nodeid_label.setText("Node ID")
        local_amt_label = QtWidgets.QLabel(self)
        local_amt_label.setText("Local amount (sat)")
        push_amt_label = QtWidgets.QLabel(self)
        push_amt_label.setText("Push amount (sat)")
        h.addWidget(nodeid_label, 0, 0)
        h.addWidget(local_amt_label, 0, 1)
        h.addWidget(push_amt_label, 0, 2)

        h.addWidget(nodeid_inp, 1, 0)
        h.addWidget(local_amt_inp, 1, 1)
        h.addWidget(push_amt_inp, 1, 2)
        h.addWidget(button, 1, 3)
        h.setColumnStretch(0, 3)
        h.setColumnStretch(1, 1)
        h.setColumnStretch(2, 1)
        h.setColumnStretch(3, 1)
        l.addLayout(h)
        l.addWidget(self._tv)

        self.resize(2500,1000)
