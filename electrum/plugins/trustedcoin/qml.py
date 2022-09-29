import threading
import socket

from PyQt5.QtCore import QObject, pyqtSignal, pyqtProperty, pyqtSlot

from electrum.i18n import _
from electrum.plugin import hook
from electrum.bip32 import xpub_type
from electrum.util import UserFacingException
from electrum import keystore

from electrum.gui.qml.qewallet import QEWallet
from electrum.gui.qml.plugins import PluginQObject

from .trustedcoin import (TrustedCoinPlugin, server, ErrorConnectingServer,
                          MOBILE_DISCLAIMER, get_user_id, get_signing_xpub,
                          TrustedCoinException, make_xpub)

class Plugin(TrustedCoinPlugin):

    class QSignalObject(PluginQObject):
        canSignWithoutServerChanged = pyqtSignal()
        _canSignWithoutServer = False
        termsAndConditionsChanged = pyqtSignal()
        _termsAndConditions = ''
        termsAndConditionsErrorChanged = pyqtSignal()
        _termsAndConditionsError = ''
        createRemoteKeyErrorChanged = pyqtSignal()
        _createRemoteKeyError = ''
        otpError = pyqtSignal()
        otpSuccess = pyqtSignal()
        disclaimerChanged = pyqtSignal()
        keystoreChanged = pyqtSignal()
        otpSecretChanged = pyqtSignal()
        _otpSecret = ''
        shortIdChanged = pyqtSignal()
        _shortId = ''

        requestOtp = pyqtSignal()

        def __init__(self, plugin, parent):
            super().__init__(plugin, parent)

        @pyqtSlot(result=str)
        def settingsComponent(self): return '../../../plugins/trustedcoin/qml/Settings.qml'

        @pyqtProperty(str, notify=disclaimerChanged)
        def disclaimer(self):
            return '\n\n'.join(MOBILE_DISCLAIMER)

        @pyqtProperty(bool, notify=canSignWithoutServerChanged)
        def canSignWithoutServer(self):
            return self._canSignWithoutServer

        @pyqtProperty('QVariantMap', notify=keystoreChanged)
        def keystore(self):
            return self._keystore

        @pyqtProperty(str, notify=otpSecretChanged)
        def otpSecret(self):
            return self._otpSecret

        @pyqtProperty(str, notify=shortIdChanged)
        def shortId(self):
            return self._shortId

        @pyqtSlot(str)
        def otpSubmit(self, otp):
            self._plugin.on_otp(otp)

        @pyqtProperty(str, notify=termsAndConditionsChanged)
        def termsAndConditions(self):
            return self._termsAndConditions

        @pyqtProperty(str, notify=termsAndConditionsErrorChanged)
        def termsAndConditionsError(self):
            return self._termsAndConditionsError

        @pyqtProperty(str, notify=createRemoteKeyErrorChanged)
        def createRemoteKeyError(self):
            return self._createRemoteKeyError

        @pyqtSlot()
        def fetchTermsAndConditions(self):
            def fetch_task():
                try:
                    self.plugin.logger.debug('TOS')
                    tos = server.get_terms_of_service()
                except ErrorConnectingServer as e:
                    self._termsAndConditionsError = _('Error connecting to server')
                    self.termsAndConditionsErrorChanged.emit()
                except Exception as e:
                    self._termsAndConditionsError = '%s: %s' % (_('Error'), repr(e))
                    self.termsAndConditionsErrorChanged.emit()
                else:
                    self._termsAndConditions = tos
                    self.termsAndConditionsChanged.emit()
                finally:
                    self._busy = False
                    self.busyChanged.emit()

            self._busy = True
            self.busyChanged.emit()
            t = threading.Thread(target=fetch_task)
            t.daemon = True
            t.start()

        @pyqtSlot(str)
        def createKeystore(self, email):
            xprv1, xpub1, xpub2, xpub3, short_id = self.plugin.create_keys()
            def create_remote_key_task():
                try:
                    self.plugin.logger.debug('create remote key')
                    r = server.create(xpub1, xpub2, email)

                    otp_secret = r['otp_secret']
                    _xpub3 = r['xpubkey_cosigner']
                    _id = r['id']
                except (socket.error, ErrorConnectingServer):
                    self._createRemoteKeyError = _('Error creating key')
                    self.createRemoteKeyErrorChanged.emit()
                except TrustedCoinException as e:
                    # if e.status_code == 409: TODO ?
                    #     r = None
                    self._createRemoteKeyError = str(e)
                    self.createRemoteKeyErrorChanged.emit()
                except (KeyError,TypeError) as e: # catch any assumptions
                    self._createRemoteKeyError = str(e)
                    self.createRemoteKeyErrorChanged.emit()
                else:
                    if short_id != _id:
                        self._createRemoteKeyError = "unexpected trustedcoin short_id: expected {}, received {}".format(short_id, _id)
                        self.createRemoteKeyErrorChanged.emit()
                        return
                    if xpub3 != _xpub3:
                        self._createRemoteKeyError = "unexpected trustedcoin xpub3: expected {}, received {}".format(xpub3, _xpub3)
                        self.createRemoteKeyErrorChanged.emit()
                        return
                    self._otpSecret = otp_secret
                    self.otpSecretChanged.emit()
                    self._shortId = short_id
                    self.shortIdChanged.emit()
                finally:
                    self._busy = False
                    self.busyChanged.emit()

            self._busy = True
            self.busyChanged.emit()
            t = threading.Thread(target=create_remote_key_task)
            t.daemon = True
            t.start()

        @pyqtSlot(str, int)
        def checkOtp(self, short_id, otp):
            def check_otp_task():
                try:
                    self.plugin.logger.debug(f'check OTP, shortId={short_id}, otp={otp}')
                    server.auth(short_id, otp)
                except TrustedCoinException as e:
                    if e.status_code == 400:  # invalid OTP
                        self.plugin.logger.debug('Invalid one-time password.')
                        self.otpError.emit()
                    else:
                        self.plugin.logger.error(str(e))
                        self._createRemoteKeyError = str(e)
                        self.createRemoteKeyErrorChanged.emit()
                except Exception as e:
                    self.plugin.logger.error(str(e))
                    self._createRemoteKeyError = str(e)
                    self.createRemoteKeyErrorChanged.emit()
                else:
                    self.plugin.logger.debug('OTP verify success')
                    self.otpSuccess.emit()
                finally:
                    self._busy = False
                    self.busyChanged.emit()

            self._busy = True
            self.busyChanged.emit()
            t = threading.Thread(target=check_otp_task)
            t.daemon = True
            t.start()


    def __init__(self, *args):
        super().__init__(*args)

    @hook
    def load_wallet(self, wallet: 'Abstract_Wallet'):
        if not isinstance(wallet, self.wallet_class):
            return
        self.logger.debug(f'plugin enabled for wallet "{str(wallet)}"')
        #wallet.handler_2fa = HandlerTwoFactor(self, window)
        if wallet.can_sign_without_server():
            self.so._canSignWithoutServer = True
            self.so.canSignWithoutServerChanged.emit()

            msg = ' '.join([
                _('This wallet was restored from seed, and it contains two master private keys.'),
                _('Therefore, two-factor authentication is disabled.')
            ])
            #action = lambda: window.show_message(msg)
        #else:
            #action = partial(self.settings_dialog, window)
        #button = StatusBarButton(read_QIcon("trustedcoin-status.png"),
                                 #_("TrustedCoin"), action)
        #window.statusBar().addPermanentWidget(button)
        self.start_request_thread(wallet)

    @hook
    def init_qml(self, gui: 'ElectrumGui'):
        self.logger.debug(f'init_qml hook called, gui={str(type(gui))}')
        self._app = gui.app
        # important: QSignalObject needs to be parented, as keeping a ref
        # in the plugin is not enough to avoid gc
        self.so = Plugin.QSignalObject(self, self._app)

        # extend wizard
        self.extend_wizard()

    def extend_wizard(self):
        wizard = self._app.daemon.newWalletWizard
        self.logger.debug(repr(wizard))
        views = {
            'trustedcoin_start': {
                'gui': '../../../../plugins/trustedcoin/qml/Disclaimer',
                'next': 'trustedcoin_choose_seed'
            },
            'trustedcoin_choose_seed': {
                'gui': '../../../../plugins/trustedcoin/qml/ChooseSeed',
                'next': self.on_choose_seed
            },
            'trustedcoin_create_seed': {
                'gui': 'WCCreateSeed',
                'next': 'trustedcoin_confirm_seed'
            },
            'trustedcoin_confirm_seed': {
                'gui': 'WCConfirmSeed',
                'next': 'trustedcoin_tos_email'
            },
            'trustedcoin_have_seed': {
                'gui': 'WCHaveSeed',
                'next': 'trustedcoin_tos_email'
            },
            'trustedcoin_tos_email': {
                'gui': '../../../../plugins/trustedcoin/qml/Terms',
                'next': 'trustedcoin_show_confirm_otp'
            },
            'trustedcoin_show_confirm_otp': {
                'gui': '../../../../plugins/trustedcoin/qml/ShowConfirmOTP',
                'accept': self.on_accept_otp_secret,
                'next': 'wallet_password',
                'last': wizard.last_if_single_password
            }
        }
        wizard.navmap_merge(views)

    def on_choose_seed(self, wizard_data):
        self.logger.debug('on_choose_seed')
        if wizard_data['keystore_type'] == 'createseed':
            return 'trustedcoin_create_seed'
        else:
            return 'trustedcoin_have_seed'

    # combined create_keystore and create_remote_key pre
    def create_keys(self):
        wizard = self._app.daemon.newWalletWizard
        wizard_data = wizard._current.wizard_data

        xprv1, xpub1, xprv2, xpub2 = self.xkeys_from_seed(wizard_data['seed'], wizard_data['seed_extra_words'])

        # NOTE: at this point, old style wizard creates a wallet file (w. password if set) and
        # stores the keystores and wizard state, in order to separate offline seed creation
        # and online retrieval of the OTP secret. For mobile, we don't do this, but
        # for desktop the wizard should support this usecase.

        data = {'x1/': {'xpub': xpub1}, 'x2/': {'xpub': xpub2}}

        # Generate third key deterministically.
        long_user_id, short_id = get_user_id(data)
        xtype = xpub_type(xpub1)
        xpub3 = make_xpub(get_signing_xpub(xtype), long_user_id)

        return (xprv1,xpub1,xpub2,xpub3,short_id)

    def on_accept_otp_secret(self, wizard_data):
        self.logger.debug('on accept otp: ' + repr(wizard_data))

        xprv1,xpub1,xpub2,xpub3,short_id = self.create_keys()

        k1 = keystore.from_xprv(xprv1)
        k2 = keystore.from_xpub(xpub2)
        k3 = keystore.from_xpub(xpub3)

        wizard_data['x1/'] = k1.dump()
        wizard_data['x2/'] = k2.dump()
        wizard_data['x3/'] = k3.dump()
        # wizard_data['use_trustedcoin'] = True



    # wizard
    def request_otp_dialog(self, wizard, short_id, otp_secret, xpub3):
        f = lambda otp, reset: self.check_otp(wizard, short_id, otp_secret, xpub3, otp, reset)
        wizard.otp_dialog(otp_secret=otp_secret, run_next=f)

    # regular wallet prompt function
    def prompt_user_for_otp(self, wallet, tx, on_success, on_failure):
        self.logger.debug('prompt_user_for_otp')
        self.on_success = on_success
        self.on_failure = on_failure if on_failure else lambda x: self.logger.error(x)
        self.wallet = wallet
        self.tx = tx
        qewallet = QEWallet.getInstanceFor(wallet)
        qewallet.request_otp(self.on_otp)

    def on_otp(self, otp):
        self.logger.debug(f'on_otp {otp} for tx {repr(self.tx)}')
        try:
            self.wallet.on_otp(self.tx, otp)
        except UserFacingException as e:
            self.on_failure(_('Invalid one-time password.'))
        except TrustedCoinException as e:
            if e.status_code == 400:  # invalid OTP
                self.on_failure(_('Invalid one-time password.'))
            else:
                self.on_failure(_('Error') + ':\n' + str(e))
        except Exception as e:
                self.on_failure(_('Error') + ':\n' + str(e))
        else:
            self.on_success(self.tx)
