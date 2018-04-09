# -*- coding: utf-8 -*-
import binascii, base64
from PyQt5 import QtCore, QtWidgets
from collections import OrderedDict
import logging
from electrum.lightning import lightningCall

mapping = {0: "channel_point"}
revMapp = {"channel_point": 0}
datatable = OrderedDict([])

class MyTableRow(QtWidgets.QTreeWidgetItem):
    def __init__(self, di):
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
            logging.warning("Lightning Channel field %s unknown", idx)
    def __str__(self):
        return str(self.di)

def addChannelRow(new):
    made = MyTableRow(new)
    datatable[new["channel_point"]] = made
    datatable.move_to_end(new["channel_point"], last=False)
    return made

def clickHandler(nodeIdInput, local_amt_inp, push_amt_inp, lightningRpc):
    nodeId = nodeIdInput.text()
    print("creating channel with connstr {}".format(nodeId))
    lightningCall(lightningRpc, "openchannel")(str(nodeId), local_amt_inp.text(), push_amt_inp.text())

class LightningChannelsList(QtWidgets.QWidget):
    def create_menu(self, position):
        menu = QtWidgets.QMenu()
        cur = self._tv.currentItem()
        channel_point = cur["channel_point"]
        def close():
            params = [str(channel_point)] + (["--force"] if cur["active"] else [])
            lightningCall(lightningRpc, "closechannel")(*params)
        menu.addAction("Close channel", close)
        menu.exec_(self._tv.viewport().mapToGlobal(position))
    def lightningWorkerHandler(self, sourceClassName, obj):
        new = {}
        for k, v in obj.items():
            try:
                v = binascii.hexlify(base64.b64decode(v)).decode("ascii")
            except:
                pass
            new[k] = v
        try:
            obj = datatable[new["channel_point"]]
        except KeyError:
            print("lightning channel_point {} unknown!".format(new["channel_point"]))
        else:
            for k, v in new.items():
                try:
                    if obj[k] != v: obj[k] = v
                except KeyError:
                    obj[k] = v
    def lightningRpcHandler(self, methodName, obj):
        if methodName != "listchannels":
            print("channel list ignoring reply {} to {}".format(obj, methodName))
            return
        self._tv.clear()
        for i in obj["channels"]:
            self._tv.insertTopLevelItem(0, addChannelRow(i))

        
    def __init__(self, parent, lightningWorker, lightningRpc):
        QtWidgets.QWidget.__init__(self, parent)

        def tick():
            lightningCall(lightningRpc, "listchannels")()

        timer = QtCore.QTimer(self)
        timer.timeout.connect(tick)
        timer.start(20000)

        lightningWorker.subscribe(self.lightningWorkerHandler)
        lightningRpc.subscribe(self.lightningRpcHandler)

        self._tv=QtWidgets.QTreeWidget(self)
        self._tv.setHeaderLabels([mapping[i] for i in range(len(mapping))])
        self._tv.setColumnCount(len(mapping))
        self._tv.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self._tv.customContextMenuRequested.connect(self.create_menu)

        nodeid_inp = QtWidgets.QLineEdit(self)
        local_amt_inp = QtWidgets.QLineEdit(self)
        push_amt_inp = QtWidgets.QLineEdit(self)

        button = QtWidgets.QPushButton('Open channel', self)
        button.clicked.connect(lambda: clickHandler(nodeid_inp, local_amt_inp, push_amt_inp, lightningRpc))

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

if __name__=="__main__":
    from sys import argv, exit

    a=QtWidgets.QApplication(argv)

    w=LightningChannelsList()
    w.show()
    w.raise_()

    exit(a.exec_())
