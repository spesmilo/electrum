import asyncio

from PyQt6.QtCore import pyqtProperty, pyqtSignal, pyqtSlot, QObject

from electrum_grs import mnemonic
from electrum_grs import keystore
from electrum_grs.i18n import _
from electrum_grs.bip32 import is_bip32_derivation, xpub_type
from electrum_grs.logging import get_logger
from electrum_grs.util import get_asyncio_loop
from electrum_grs.transaction import tx_from_any
from electrum_grs.mnemonic import Mnemonic
from electrum_grs.old_mnemonic import wordlist as old_wordlist
from electrum_grs.bitcoin import is_address


class QEBitcoin(QObject):
    _logger = get_logger(__name__)

    generatedSeedChanged = pyqtSignal()
    seedTypeChanged = pyqtSignal()
    validationMessageChanged = pyqtSignal()

    def __init__(self, config, parent=None):
        super().__init__(parent)
        self.config = config
        self._seed_type = ''
        self._generated_seed = ''
        self._validationMessage = ''
        self._words = None

    @pyqtProperty(str, notify=generatedSeedChanged)
    def generatedSeed(self):
        return self._generated_seed

    @pyqtProperty(str, notify=seedTypeChanged)
    def seedType(self):
        return self._seed_type

    @pyqtProperty(str, notify=validationMessageChanged)
    def validationMessage(self):
        return self._validationMessage

    @validationMessage.setter
    def validationMessage(self, msg):
        if self._validationMessage != msg:
            self._validationMessage = msg
            self.validationMessageChanged.emit()

    @pyqtSlot()
    @pyqtSlot(str)
    @pyqtSlot(str, str)
    def generateSeed(self, seed_type='segwit', language='en'):
        self._logger.debug('generating seed of type ' + str(seed_type))

        async def co_gen_seed(seed_type, language):
            self._generated_seed = mnemonic.Mnemonic(language).make_seed(seed_type=seed_type)
            self._logger.debug('seed generated')
            self.generatedSeedChanged.emit()

        asyncio.run_coroutine_threadsafe(co_gen_seed(seed_type, language), get_asyncio_loop())

    @pyqtSlot(str, str, result=bool)
    def verifyMasterKey(self, key, wallet_type='standard'):
        self.validationMessage = ''
        if not keystore.is_master_key(key):
            self.validationMessage = _('Not a master key')
            return False

        k = keystore.from_master_key(key)
        if wallet_type == 'standard':
            if isinstance(k, keystore.Xpub):  # has bip32 xpub
                t1 = xpub_type(k.xpub)
                if t1 not in ['standard', 'p2wpkh', 'p2wpkh-p2sh']:  # disallow Ypub/Zpub
                    self.validationMessage = '%s: %s' % (_('Wrong key type'), t1)
                    return False
            elif isinstance(k, keystore.Old_KeyStore):
                pass
            else:
                self._logger.error(f"unexpected keystore type: {type(keystore)}")
                return False
        elif wallet_type == 'multisig':
            if not isinstance(k, keystore.Xpub):  # old mpk?
                self.validationMessage = '%s: %s' % (_('Wrong key type'), "not bip32")
                return False
            t1 = xpub_type(k.xpub)
            if t1 not in ['standard', 'p2wsh', 'p2wsh-p2sh']:  # disallow ypub/zpub
                self.validationMessage = '%s: %s' % (_('Wrong key type'), t1)
                return False
        else:
            self.validationMessage = '%s: %s' % (_('Unsupported wallet type'), wallet_type)
            self._logger.error(f'Unsupported wallet type: {wallet_type}')
            return False
        # looks okay
        return True

    @pyqtSlot(str, result=bool)
    def verifyDerivationPath(self, path):
        return is_bip32_derivation(path)

    @pyqtSlot(str, result=bool)
    def isRawTx(self, rawtx):
        try:
            tx_from_any(rawtx)
            return True
        except Exception:
            return False

    @pyqtSlot(str, result=bool)
    def isAddress(self, addr: str):
        return is_address(addr)

    @pyqtSlot(str, result=bool)
    def isAddressList(self, csv: str):
        return keystore.is_address_list(csv)

    @pyqtSlot(str, result=bool)
    def isPrivateKeyList(self, csv: str):
        return keystore.is_private_key_list(csv)

    @pyqtSlot(str, result='QVariantList')
    def mnemonicsFor(self, fragment):
        if not fragment:
            return []
        if not self._words:
            self._words = set(Mnemonic('en').wordlist).union(set(old_wordlist))
        return sorted(filter(lambda x: x.startswith(fragment), self._words))
