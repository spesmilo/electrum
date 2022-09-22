import os

from PyQt5.QtCore import pyqtProperty, pyqtSignal, pyqtSlot, QObject
from PyQt5.QtQml import QQmlApplicationEngine

from electrum.logging import get_logger
from electrum.gui.wizard import NewWalletWizard

from electrum.storage import WalletStorage, StorageEncryptionVersion
from electrum.wallet_db import WalletDB
from electrum.bip32 import normalize_bip32_derivation, xpub_type
from electrum import keystore

class QEAbstractWizard(QObject):
    _logger = get_logger(__name__)

    def __init__(self, parent = None):
        QObject.__init__(self, parent)

    @pyqtSlot(result=str)
    def start_wizard(self):
        self.start()
        return self._current.view

    @pyqtSlot(str, result=str)
    def viewToComponent(self, view):
        return self.navmap[view]['gui'] + '.qml'

    @pyqtSlot('QJSValue', result='QVariant')
    def submit(self, wizard_data):
        wdata = wizard_data.toVariant()
        self._logger.debug(str(wdata))
        view = self.resolve_next(self._current.view, wdata)
        return { 'view': view.view, 'wizard_data': view.wizard_data }

    @pyqtSlot(result='QVariant')
    def prev(self):
        viewstate = self.resolve_prev()
        return viewstate.wizard_data

    @pyqtSlot('QJSValue', result=bool)
    def isLast(self, wizard_data):
        wdata = wizard_data.toVariant()
        return self.is_last_view(self._current.view, wdata)


class QENewWalletWizard(NewWalletWizard, QEAbstractWizard):

    createError = pyqtSignal([str], arguments=["error"])
    createSuccess = pyqtSignal()

    def __init__(self, daemon, parent = None):
        NewWalletWizard.__init__(self, daemon)
        QEAbstractWizard.__init__(self, parent)
        self._daemon = daemon

        # attach view names
        self.navmap_merge({
            'wallet_name': { 'gui': 'WCWalletName' },
            'wallet_type': { 'gui': 'WCWalletType' },
            'keystore_type': { 'gui': 'WCKeystoreType' },
            'create_seed': { 'gui': 'WCCreateSeed' },
            'confirm_seed': { 'gui': 'WCConfirmSeed' },
            'have_seed': { 'gui': 'WCHaveSeed' },
            'bip39_refine': { 'gui': 'WCBIP39Refine' },
            'have_master_key': { 'gui': 'WCHaveMasterKey' },
            'wallet_password': { 'gui': 'WCWalletPassword' }
        })

    pathChanged = pyqtSignal()
    @pyqtProperty(str, notify=pathChanged)
    def path(self):
        return self._path

    @path.setter
    def path(self, path):
        self._path = path
        self.pathChanged.emit()

    def last_if_single_password(self, view, wizard_data):
        return self._daemon.singlePasswordEnabled

    @pyqtSlot('QJSValue',bool,str)
    def create_storage(self, js_data, single_password_enabled, single_password):
        self._logger.info('Creating wallet from wizard data')
        data = js_data.toVariant()
        self._logger.debug(str(data))

        # only standard and 2fa wallets for now
        assert data['wallet_type'] in ['standard', '2fa']

        if single_password_enabled and single_password:
            data['encrypt'] = True
            data['password'] = single_password

        try:
            path = os.path.join(os.path.dirname(self._daemon.daemon.config.get_wallet_path()), data['wallet_name'])
            if os.path.exists(path):
                raise Exception('file already exists at path')
            storage = WalletStorage(path)

            if data['keystore_type'] in ['createseed', 'haveseed']:
                if data['seed_type'] in ['old', 'standard', 'segwit']: #2fa, 2fa-segwit
                    self._logger.debug('creating keystore from electrum seed')
                    k = keystore.from_seed(data['seed'], data['seed_extra_words'], data['wallet_type'] == 'multisig')
                elif data['seed_type'] == 'bip39':
                    self._logger.debug('creating keystore from bip39 seed')
                    root_seed = keystore.bip39_to_seed(data['seed'], data['seed_extra_words'])
                    derivation = normalize_bip32_derivation(data['derivation_path'])
                    script = data['script_type'] if data['script_type'] != 'p2pkh' else 'standard'
                    k = keystore.from_bip43_rootseed(root_seed, derivation, xtype=script)
                elif data['seed_type'] == '2fa_segwit': # TODO: legacy 2fa
                    self._logger.debug('creating keystore from 2fa seed')
                    k = keystore.from_xprv(data['x1/']['xprv'])
                else:
                    raise Exception('unsupported/unknown seed_type %s' % data['seed_type'])
            elif data['keystore_type'] == 'masterkey':
                k = keystore.from_master_key(data['master_key'])
                has_xpub = isinstance(k, keystore.Xpub)
                assert has_xpub
                t1 = xpub_type(k.xpub)
                if t1 not in ['standard', 'p2wpkh', 'p2wpkh-p2sh']:
                    raise Exception('wrong key type %s' % t1)
            else:
                raise Exception('unsupported/unknown keystore_type %s' % data['keystore_type'])

            if data['encrypt']:
                if k.may_have_password():
                    k.update_password(None, data['password'])
                storage.set_password(data['password'], enc_version=StorageEncryptionVersion.USER_PASSWORD)

            db = WalletDB('', manual_upgrades=False)
            db.set_keystore_encryption(bool(data['password']) and data['encrypt'])

            db.put('wallet_type', data['wallet_type'])
            if 'seed_type' in data:
                db.put('seed_type', data['seed_type'])

            if data['wallet_type'] == 'standard':
                db.put('keystore', k.dump())
            elif data['wallet_type'] == '2fa':
                db.put('x1/', k.dump())
                db.put('x2/', data['x2/'])
                db.put('x3/', data['x3/'])
                db.put('use_trustedcoin', True)

            if k.can_have_deterministic_lightning_xprv():
                db.put('lightning_xprv', k.get_lightning_xprv(data['password'] if data['encrypt'] else None))

            db.load_plugins()
            db.write(storage)

            # minimally populate self after create
            self._password = data['password']
            self.path = path

            self.createSuccess.emit()
        except Exception as e:
            self._logger.error(repr(e))
            self.createError.emit(str(e))
