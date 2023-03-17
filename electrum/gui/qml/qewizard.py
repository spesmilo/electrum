import os

from PyQt5.QtCore import pyqtProperty, pyqtSignal, pyqtSlot, QObject
from PyQt5.QtQml import QQmlApplicationEngine

from electrum.logging import get_logger
from electrum.wizard import NewWalletWizard, ServerConnectWizard

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
        self.log_state(wdata)
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

        # attach view names and accept handlers
        self.navmap_merge({
            'wallet_name': { 'gui': 'WCWalletName' },
            'wallet_type': { 'gui': 'WCWalletType' },
            'keystore_type': { 'gui': 'WCKeystoreType' },
            'create_seed': { 'gui': 'WCCreateSeed' },
            'confirm_seed': { 'gui': 'WCConfirmSeed' },
            'have_seed': { 'gui': 'WCHaveSeed' },
            'bip39_refine': { 'gui': 'WCBIP39Refine' },
            'have_master_key': { 'gui': 'WCHaveMasterKey' },
            'multisig': { 'gui': 'WCMultisig' },
            # 'multisig_show_masterpubkey': { 'gui': 'WCShowMasterPubkey' },
            'multisig_cosigner_keystore': { 'gui': 'WCCosignerKeystore' },
            'multisig_cosigner_key': { 'gui': 'WCHaveMasterKey' },
            'multisig_cosigner_seed': { 'gui': 'WCHaveSeed' },
            'multisig_cosigner_bip39_refine': { 'gui': 'WCBIP39Refine' },
            'imported': { 'gui': 'WCImport' },
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

    def is_single_password(self):
        return self._daemon.singlePasswordEnabled

    @pyqtSlot('QJSValue', result=bool)
    def hasDuplicateKeys(self, js_data):
        self._logger.info('Checking for duplicate keys')
        data = js_data.toVariant()
        return self.has_duplicate_keys(data)

    @pyqtSlot('QJSValue', bool, str)
    def createStorage(self, js_data, single_password_enabled, single_password):
        self._logger.info('Creating wallet from wizard data')
        data = js_data.toVariant()

        if single_password_enabled and single_password:
            data['encrypt'] = True
            data['password'] = single_password

        path = os.path.join(os.path.dirname(self._daemon.daemon.config.get_wallet_path()), data['wallet_name'])

        try:
            self.create_storage(path, data)

            # minimally populate self after create
            self._password = data['password']
            self.path = path

            self.createSuccess.emit()
        except Exception as e:
            self._logger.error(repr(e))
            self.createError.emit(str(e))

class QEServerConnectWizard(ServerConnectWizard, QEAbstractWizard):

    def __init__(self, daemon, parent = None):
        ServerConnectWizard.__init__(self, daemon)
        QEAbstractWizard.__init__(self, parent)
        self._daemon = daemon

        # attach view names
        self.navmap_merge({
            'autoconnect': { 'gui': 'WCAutoConnect' },
            'proxy_ask': { 'gui': 'WCProxyAsk' },
            'proxy_config': { 'gui': 'WCProxyConfig' },
            'server_config': { 'gui': 'WCServerConfig' },
        })
