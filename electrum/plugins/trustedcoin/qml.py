import threading
import socket
import base64
from typing import TYPE_CHECKING

from PyQt5.QtCore import QObject, pyqtSignal, pyqtProperty, pyqtSlot

from electrum.i18n import _
from electrum.plugin import hook
from electrum.bip32 import xpub_type, BIP32Node
from electrum.util import UserFacingException
from electrum import keystore

from electrum.gui.qml.qewallet import QEWallet
from electrum.gui.qml.plugins import PluginQObject

from .trustedcoin import (TrustedCoinPlugin, server, ErrorConnectingServer,
                          MOBILE_DISCLAIMER, get_user_id, get_signing_xpub,
                          TrustedCoinException, make_xpub)

if TYPE_CHECKING:
    from electrum.gui.qml import ElectrumGui
    from electrum.wallet import Abstract_Wallet

class Plugin(TrustedCoinPlugin):

    class QSignalObject(PluginQObject):
        canSignWithoutServerChanged = pyqtSignal()
        _canSignWithoutServer = False
        termsAndConditionsChanged = pyqtSignal()
        _termsAndConditions = ''
        termsAndConditionsErrorChanged = pyqtSignal()
        _termsAndConditionsError = ''
        otpError = pyqtSignal([str], arguments=['message'])
        otpSuccess = pyqtSignal()
        disclaimerChanged = pyqtSignal()
        keystoreChanged = pyqtSignal()
        otpSecretChanged = pyqtSignal()
        _otpSecret = ''
        shortIdChanged = pyqtSignal()
        _shortId = ''

        _remoteKeyState = ''
        remoteKeyStateChanged = pyqtSignal()
        remoteKeyError = pyqtSignal([str], arguments=['message'])

        requestOtp = pyqtSignal()

        def __init__(self, plugin, parent):
            super().__init__(plugin, parent)

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

        @pyqtProperty(str, notify=remoteKeyStateChanged)
        def remoteKeyState(self):
            return self._remoteKeyState

        @remoteKeyState.setter
        def remoteKeyState(self, new_state):
            if self._remoteKeyState != new_state:
                self._remoteKeyState = new_state
                self.remoteKeyStateChanged.emit()

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
            self.remoteKeyState = ''
            xprv1, xpub1, xprv2, xpub2, xpub3, short_id = self.plugin.create_keys()
            def create_remote_key_task():
                try:
                    self.plugin.logger.debug('create remote key')
                    r = server.create(xpub1, xpub2, email)

                    otp_secret = r['otp_secret']
                    _xpub3 = r['xpubkey_cosigner']
                    _id = r['id']
                except (socket.error, ErrorConnectingServer) as e:
                    self.remoteKeyState = 'error'
                    self.remoteKeyError.emit(f'Network error: {str(e)}')
                except TrustedCoinException as e:
                    if e.status_code == 409:
                        self.remoteKeyState = 'wallet_known'
                        self._shortId = short_id
                        self.shortIdChanged.emit()
                    else:
                        self.remoteKeyState = 'error'
                        self.logger.warning(str(e))
                        self.remoteKeyError.emit(f'Service error: {str(e)}')
                except (KeyError,TypeError) as e: # catch any assumptions
                    self.remoteKeyState = 'error'
                    self.remoteKeyError.emit(f'Error: {str(e)}')
                    self.logger.error(str(e))
                else:
                    if short_id != _id:
                        self.remoteKeyState = 'error'
                        self.logger.error("unexpected trustedcoin short_id: expected {}, received {}".format(short_id, _id))
                        self.remoteKeyError.emit('Unexpected short_id')
                        return
                    if xpub3 != _xpub3:
                        self.remoteKeyState = 'error'
                        self.logger.error("unexpected trustedcoin xpub3: expected {}, received {}".format(xpub3, _xpub3))
                        self.remoteKeyError.emit('Unexpected trustedcoin xpub3')
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

        @pyqtSlot()
        def resetOtpSecret(self):
            self.remoteKeyState = ''
            xprv1, xpub1, xprv2, xpub2, xpub3, short_id = self.plugin.create_keys()
            def reset_otp_task():
                try:
                    self.plugin.logger.debug('reset_otp')
                    r = server.get_challenge(short_id)
                    challenge = r.get('challenge')
                    message = 'TRUSTEDCOIN CHALLENGE: ' + challenge
                    def f(xprv):
                        rootnode = BIP32Node.from_xkey(xprv)
                        key = rootnode.subkey_at_private_derivation((0, 0)).eckey
                        sig = key.sign_message(message, True)
                        return base64.b64encode(sig).decode()

                    signatures = [f(x) for x in [xprv1, xprv2]]
                    r = server.reset_auth(short_id, challenge, signatures)
                    otp_secret = r.get('otp_secret')
                except (socket.error, ErrorConnectingServer) as e:
                    self.remoteKeyState = 'error'
                    self.remoteKeyError.emit(f'Network error: {str(e)}')
                except Exception as e:
                    self.remoteKeyState = 'error'
                    self.remoteKeyError.emit(f'Error: {str(e)}')
                else:
                    self._otpSecret = otp_secret
                    self.otpSecretChanged.emit()
                finally:
                    self._busy = False
                    self.busyChanged.emit()

            self._busy = True
            self.busyChanged.emit()

            t = threading.Thread(target=reset_otp_task, daemon=True)
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
                        self.otpError.emit(_('Invalid one-time password.'))
                    else:
                        self.plugin.logger.error(str(e))
                        self.otpError.emit(f'Service error: {str(e)}')
                except Exception as e:
                    self.plugin.logger.error(str(e))
                    self.otpError.emit(f'Error: {str(e)}')
                else:
                    self.plugin.logger.debug('OTP verify success')
                    self.otpSuccess.emit()
                finally:
                    self._busy = False
                    self.busyChanged.emit()

            self._busy = True
            self.busyChanged.emit()
            t = threading.Thread(target=check_otp_task, daemon=True)
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
            self.logger.info(msg)
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
                'next': lambda d: 'trustedcoin_create_seed' if d['keystore_type'] == 'createseed'
                        else 'trustedcoin_have_seed'
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
                'next': 'trustedcoin_keep_disable'
            },
            'trustedcoin_keep_disable': {
                'gui': '../../../../plugins/trustedcoin/qml/KeepDisable',
                'next': lambda d: 'trustedcoin_tos_email' if d['trustedcoin_keepordisable'] != 'disable'
                        else 'wallet_password',
                'accept': self.recovery_disable,
                'last': lambda v,d: wizard.last_if_single_password() and d['trustedcoin_keepordisable'] == 'disable'
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

        return (xprv1,xpub1,xprv2,xpub2,xpub3,short_id)

    def on_accept_otp_secret(self, wizard_data):
        self.logger.debug('OTP secret accepted, creating keystores')
        xprv1,xpub1,xprv2,xpub2,xpub3,short_id = self.create_keys()
        k1 = keystore.from_xprv(xprv1)
        k2 = keystore.from_xpub(xpub2)
        k3 = keystore.from_xpub(xpub3)

        wizard_data['x1/'] = k1.dump()
        wizard_data['x2/'] = k2.dump()
        wizard_data['x3/'] = k3.dump()

    def recovery_disable(self, wizard_data):
        if wizard_data['trustedcoin_keepordisable'] != 'disable':
            return

        self.logger.debug('2fa disabled, creating keystores')
        xprv1,xpub1,xprv2,xpub2,xpub3,short_id = self.create_keys()
        k1 = keystore.from_xprv(xprv1)
        k2 = keystore.from_xprv(xprv2)
        k3 = keystore.from_xpub(xpub3)

        wizard_data['x1/'] = k1.dump()
        wizard_data['x2/'] = k2.dump()
        wizard_data['x3/'] = k3.dump()


    # regular wallet prompt functions

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
