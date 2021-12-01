from PyQt5.QtCore import pyqtProperty, pyqtSignal, pyqtSlot, QObject

from electrum.logging import get_logger

class QEConfig(QObject):
    def __init__(self, config, parent=None):
        super().__init__(parent)
        self.config = config

    _logger = get_logger(__name__)

    autoConnectChanged = pyqtSignal()
    serverStringChanged = pyqtSignal()
    manualServerChanged = pyqtSignal()

    @pyqtProperty(bool, notify=autoConnectChanged)
    def autoConnect(self):
        return self.config.get('auto_connect')

    @autoConnect.setter
    def autoConnect(self, auto_connect):
        self.config.set_key('auto_connect', auto_connect, True)
        self.autoConnectChanged.emit()

    # auto_connect is actually a tri-state, expose the undefined case
    @pyqtProperty(bool, notify=autoConnectChanged)
    def autoConnectDefined(self):
        return self.config.get('auto_connect') is not None

    @pyqtProperty('QString', notify=serverStringChanged)
    def serverString(self):
        return self.config.get('server')

    @serverString.setter
    def serverString(self, server):
        self.config.set_key('server', server, True)
        self.serverStringChanged.emit()

    @pyqtProperty(bool, notify=manualServerChanged)
    def manualServer(self):
        return self.config.get('oneserver')

    @manualServer.setter
    def manualServer(self, oneserver):
        self.config.set_key('oneserver', oneserver, True)
        self.manualServerChanged.emit()

