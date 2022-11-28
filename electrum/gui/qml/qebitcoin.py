import asyncio

from PyQt5.QtCore import pyqtProperty, pyqtSignal, pyqtSlot, QObject

from electrum import mnemonic
from electrum import keystore
from electrum.i18n import _
from electrum.bip32 import is_bip32_derivation, normalize_bip32_derivation, xpub_type
from electrum.logging import get_logger
from electrum.slip39 import decode_mnemonic, Slip39Error
from electrum.util import parse_URI, create_bip21_uri, InvalidBitcoinURI, get_asyncio_loop
from electrum.transaction import tx_from_any
from electrum.mnemonic import is_any_2fa_seed_type

from .qetypes import QEAmount

class QEBitcoin(QObject):
    def __init__(self, config, parent=None):
        super().__init__(parent)
        self.config = config

    _logger = get_logger(__name__)

    generatedSeedChanged = pyqtSignal()
    generatedSeed = ''

    seedTypeChanged = pyqtSignal()
    seedType = ''

    validationMessageChanged = pyqtSignal()
    _validationMessage = ''

    @pyqtProperty('QString', notify=generatedSeedChanged)
    def generated_seed(self):
        return self.generatedSeed

    @pyqtProperty('QString', notify=seedTypeChanged)
    def seed_type(self):
        return self.seedType

    @pyqtProperty('QString', notify=validationMessageChanged)
    def validationMessage(self):
        return self._validationMessage

    @validationMessage.setter
    def validationMessage(self, msg):
        if self._validationMessage != msg:
            self._validationMessage = msg
            self.validationMessageChanged.emit()

    @pyqtSlot()
    @pyqtSlot(str)
    @pyqtSlot(str,str)
    def generateSeed(self, seed_type='segwit', language='en'):
        self._logger.debug('generating seed of type ' + str(seed_type))

        async def co_gen_seed(seed_type, language):
            self.generatedSeed = mnemonic.Mnemonic(language).make_seed(seed_type=seed_type)
            self._logger.debug('seed generated')
            self.generatedSeedChanged.emit()

        asyncio.run_coroutine_threadsafe(co_gen_seed(seed_type, language), get_asyncio_loop())

    @pyqtSlot(str,str,str, result=bool)
    def verifySeed(self, seed, seed_variant, wallet_type='standard'):
        seed_type = ''
        seed_valid = False
        self.validationMessage = ''

        if seed_variant == 'electrum':
            seed_type = mnemonic.seed_type(seed)
            if seed_type != '':
                seed_valid = True
        elif seed_variant == 'bip39':
            is_checksum, is_wordlist = keystore.bip39_is_checksum_valid(seed)
            status = ('checksum: ' + ('ok' if is_checksum else 'failed')) if is_wordlist else 'unknown wordlist'
            self.validationMessage = 'BIP39 (%s)' % status

            if is_checksum:
                seed_type = 'bip39'
                seed_valid = True
        elif seed_variant == 'slip39': # TODO: incomplete impl, this code only validates a single share.
            try:
                share = decode_mnemonic(seed)
                seed_type = 'slip39'
                self.validationMessage = 'SLIP39: share #%d in %dof%d scheme' % (share.group_index, share.group_threshold, share.group_count)
            except Slip39Error as e:
                self.validationMessage = 'SLIP39: %s' % str(e)
            seed_valid = False # for now
        else:
            raise Exception(f'unknown seed variant {seed_variant}')

        # check if seed matches wallet type
        if wallet_type == '2fa' and not is_any_2fa_seed_type(seed_type):
            seed_valid = False
        elif wallet_type == 'standard' and seed_type not in ['old', 'standard', 'segwit', 'bip39']:
            seed_valid = False
        elif wallet_type == 'multisig' and seed_type not in ['standard', 'segwit', 'bip39']:
            seed_valid = False

        self.seedType = seed_type
        self.seedTypeChanged.emit()

        self._logger.debug('seed verified: ' + str(seed_valid))

        return seed_valid

    @pyqtSlot(str, str, result=bool)
    def verifyMasterKey(self, key, wallet_type='standard'):
        self.validationMessage = ''
        if not keystore.is_master_key(key):
            self.validationMessage = _('Not a master key')
            return False

        k = keystore.from_master_key(key)
        has_xpub = isinstance(k, keystore.Xpub)
        assert has_xpub
        t1 = xpub_type(k.xpub)

        if wallet_type == 'standard':
            if t1 not in ['standard', 'p2wpkh', 'p2wpkh-p2sh']:
                self.validationMessage = '%s: %s' % (_('Wrong key type'), t1)
                return False
            return True
        elif wallet_type == 'multisig':
            if t1 not in ['standard', 'p2wsh', 'p2wsh-p2sh']:
                self.validationMessage = '%s: %s' % (_('Wrong key type'), t1)
                return False
            return True

        raise Exception(f'Unsupported wallet type: {wallet_type}')

    @pyqtSlot(str, result=bool)
    def verifyDerivationPath(self, path):
        return is_bip32_derivation(path)

    @pyqtSlot(str, result='QVariantMap')
    def parse_uri(self, uri: str) -> dict:
        try:
            return parse_URI(uri)
        except InvalidBitcoinURI as e:
            return { 'error': str(e) }

    @pyqtSlot(str, QEAmount, str, int, int, result=str)
    def create_bip21_uri(self, address, satoshis, message, timestamp, expiry):
        extra_params = {}
        if expiry:
            extra_params['time'] = str(timestamp)
            extra_params['exp'] = str(expiry)

        return create_bip21_uri(address, satoshis.satsInt, message, extra_query_params=extra_params)

    @pyqtSlot(str, result=bool)
    def isRawTx(self, rawtx):
        try:
            tx_from_any(rawtx)
            return True
        except:
            return False

    @pyqtSlot(str, result=bool)
    def isAddressList(self, csv: str):
        return keystore.is_address_list(csv)

    @pyqtSlot(str, result=bool)
    def isPrivateKeyList(self, csv: str):
        return keystore.is_private_key_list(csv)
