from PyQt5.QtCore import pyqtProperty, pyqtSignal, pyqtSlot, QObject

from electrum.logging import get_logger
from electrum import mnemonic

class QEBitcoin(QObject):
    def __init__(self, config, parent=None):
        super().__init__(parent)
        self.config = config

    _logger = get_logger(__name__)

    generatedSeedChanged = pyqtSignal()
    generatedSeed = ''

    seedValidChanged = pyqtSignal()
    seedValid = False

    @pyqtProperty('QString', notify=generatedSeedChanged)
    def generated_seed(self):
        return self.generatedSeed

    @pyqtSlot()
    @pyqtSlot(str)
    @pyqtSlot(str,str)
    def generate_seed(self, seed_type='segwit', language='en'):
        self._logger.debug('generating seed of type ' + str(seed_type))
        self.generatedSeed = mnemonic.Mnemonic(language).make_seed(seed_type=seed_type)
        self._logger.debug('seed generated')
        self.generatedSeedChanged.emit()

    @pyqtProperty(bool, notify=seedValidChanged)
    def seed_valid(self):
        return self.seedValid

    @pyqtSlot(str)
    @pyqtSlot(str,str)
    @pyqtSlot(str,str,str)
    @pyqtSlot(str,str,str,str)
    def verify_seed(self, seed, bip39=False, seed_type='segwit', language='en'):
        self._logger.debug('verify seed of type ' + str(seed_type))
        #TODO
        #self._logger.debug('seed verified')
        #self.seedValidChanged.emit()

