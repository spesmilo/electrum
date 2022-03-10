import asyncio

from PyQt5.QtCore import pyqtProperty, pyqtSignal, pyqtSlot, QObject

from electrum.logging import get_logger
from electrum.keystore import bip39_is_checksum_valid
from electrum.slip39 import decode_mnemonic, Slip39Error
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

    seedTypeChanged = pyqtSignal()
    seedType = ''

    validationMessageChanged = pyqtSignal()
    validationMessage = ''

    @pyqtProperty('QString', notify=generatedSeedChanged)
    def generated_seed(self):
        return self.generatedSeed

    @pyqtProperty(bool, notify=seedValidChanged)
    def seed_valid(self):
        return self.seedValid

    @pyqtProperty('QString', notify=seedTypeChanged)
    def seed_type(self):
        return self.seedType

    @pyqtProperty('QString', notify=validationMessageChanged)
    def validation_message(self):
        return self.validationMessage

    @pyqtSlot()
    @pyqtSlot(str)
    @pyqtSlot(str,str)
    def generate_seed(self, seed_type='segwit', language='en'):
        self._logger.debug('generating seed of type ' + str(seed_type))

        async def co_gen_seed(seed_type, language):
            self.generatedSeed = mnemonic.Mnemonic(language).make_seed(seed_type=seed_type)
            self._logger.debug('seed generated')
            self.generatedSeedChanged.emit()

        loop = asyncio.get_event_loop()
        asyncio.run_coroutine_threadsafe(co_gen_seed(seed_type, language), loop)

    @pyqtSlot(str)
    @pyqtSlot(str,bool,bool)
    @pyqtSlot(str,bool,bool,str,str,str)
    def verify_seed(self, seed, bip39=False, slip39=False, wallet_type='standard', language='en'):
        self._logger.debug('bip39 ' + str(bip39))
        self._logger.debug('slip39 ' + str(slip39))

        seed_type = ''
        seed_valid = False
        validation_message = ''

        if not (bip39 or slip39):
            seed_type = mnemonic.seed_type(seed)
            if seed_type != '':
                seed_valid = True
        elif bip39:
            is_checksum, is_wordlist = bip39_is_checksum_valid(seed)
            status = ('checksum: ' + ('ok' if is_checksum else 'failed')) if is_wordlist else 'unknown wordlist'
            validation_message = 'BIP39 (%s)' % status

            if is_checksum:
                seed_type = 'bip39'
                seed_valid = True
            seed_valid = False # for now

        elif slip39: # TODO: incomplete impl, this code only validates a single share.
            try:
                share = decode_mnemonic(seed)
                seed_type = 'slip39'
                validation_message = 'SLIP39: share #%d in %dof%d scheme' % (share.group_index, share.group_threshold, share.group_count)
            except Slip39Error as e:
                validation_message = 'SLIP39: %s' % str(e)
            seed_valid = False # for now

        # cosigning seed
        if wallet_type != 'standard' and seed_type not in ['standard', 'segwit']:
            seed_type = ''
            seed_valid = False

        self.seedType = seed_type
        self.seedTypeChanged.emit()

        if self.validationMessage != validation_message:
            self.validationMessage = validation_message
            self.validationMessageChanged.emit()

        if self.seedValid != seed_valid:
            self.seedValid = seed_valid
            self.seedValidChanged.emit()

        self._logger.debug('seed verified: ' + str(seed_valid))

