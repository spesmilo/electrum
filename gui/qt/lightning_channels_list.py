# -*- coding: utf-8 -*-
import binascii, base64
from PyQt5 import QtCore, QtWidgets
from collections import OrderedDict
import logging
from electrum.lightning import lightningCall
import traceback

mapping = {0: "channel_point"}
revMapp = {"channel_point": 0}
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
    datatable[new["channel_point"]] = made
    datatable.move_to_end(new["channel_point"], last=False)
    return made

def clickHandler(nodeIdInput, local_amt_inp, push_amt_inp, lightningRpc):
    nodeId = nodeIdInput.text()
    print("creating channel with connstr {}".format(nodeId))
    lightningCall(lightningRpc, "openchannel")(str(nodeId), local_amt_inp.text(), push_amt_inp.text())

class LightningChannelsList(QtWidgets.QWidget):
    update_rows = QtCore.pyqtSignal(str, dict)

    def create_menu(self, position):
        menu = QtWidgets.QMenu()
        cur = self._tv.currentItem()
        channel_point = cur["channel_point"]
        def close():
            params = [str(channel_point)] + (["--force"] if not cur["active"] else []) # TODO test if force is being used correctly
            lightningCall(self.lightningRpc, "closechannel")(*params)
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
        if isinstance(obj, Exception):
            try:
                raise obj
            except:
                traceback.print_exc()
        else:
            self.update_rows.emit(methodName, obj)

    def do_update_rows(self, methodName, obj):
        if methodName != "listchannels":
            print("channel list ignoring reply {} to {}".format(obj, methodName))
            return
        self._tv.clear()
        for i in obj["channels"]:
            self._tv.insertTopLevelItem(0, addChannelRow(i))

        
    def __init__(self, parent, lightningWorker, lightningRpc):
        QtWidgets.QWidget.__init__(self, parent)

        self.update_rows.connect(self.do_update_rows)

        def tick():
            lightningCall(lightningRpc, "listchannels")()

        timer = QtCore.QTimer(self)
        timer.timeout.connect(tick)
        timer.start(5000)

        lightningWorker.subscribe(self.lightningWorkerHandler)
        lightningRpc.subscribe(self.lightningRpcHandler)
        self.lightningRpc = lightningRpc

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

class MockLightningWorker:
    def subscribe(self, handler):
        pass

if __name__=="__main__":
    import queue, threading, asyncio
    from sys import argv, exit
    import signal , traceback, os

    loop = asyncio.new_event_loop()

    async def loopstop():
        loop.stop()

    def signal_handler(signal, frame):
        asyncio.run_coroutine_threadsafe(loopstop(), loop)

    signal.signal(signal.SIGINT, signal_handler)

    a=QtWidgets.QApplication(argv)

    gotReplyHandlerLock = threading.Lock()
    gotReplyHandlerLock.acquire()
    replyHandler = None

    class MockLightningRPC:
        def __init__(self, q):
            self.queue = q
        def subscribe(self, handler):
            global replyHandler
            replyHandler = handler
            gotReplyHandlerLock.release()

    q = queue.Queue()
    w=LightningChannelsList(None, MockLightningWorker(), MockLightningRPC(q))
    w.show()
    w.raise_()

    async def the_job():
        try:
            acquired_once = False
            while loop.is_running():
                try:
                    cmd = q.get_nowait()
                except queue.Empty:
                    await asyncio.sleep(1)
                    continue
                if not acquired_once:
                    gotReplyHandlerLock.acquire()
                    acquired_once = True
                if cmd[0] == "listchannels":
                    #replyHandler("listchannels", Exception("Test exception"))
                    replyHandler("listchannels", {"channels": [{"channel_point": binascii.hexlify(os.urandom(32)).decode("ascii"), "active": True}]})
                elif cmd[0] == "openchannel":
                    replyHandler("openchannel", {})
                else:
                    print("mock rpc server ignoring", cmd[0])
        except:
            traceback.print_exc()

    def asyncioThread():
        loop.create_task(the_job())
        loop.run_forever()

    threading.Thread(target=asyncioThread).start()

    exit(a.exec_())
