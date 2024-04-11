import threading
import socket
import base64
import sys
from typing import TYPE_CHECKING

from electrum.gui.common_qt import get_qt_major_version

if (qt_ver := get_qt_major_version()) == 5:
    from PyQt5.QtCore import pyqtSignal, pyqtProperty, pyqtSlot
elif qt_ver == 6:
    from PyQt6.QtCore import pyqtSignal, pyqtProperty, pyqtSlot
else:
    raise Exception(f"unexpected {qt_ver=}")

from electrum.i18n import _
from electrum.bip32 import BIP32Node

from .trustedcoin import (server, ErrorConnectingServer, MOBILE_DISCLAIMER, TrustedCoinException)
from electrum.gui.common_qt.plugins import PluginQObject

if TYPE_CHECKING:
    from electrum.wizard import NewWalletWizard


class TrustedcoinPluginQObject(PluginQObject):
    canSignWithoutServerChanged = pyqtSignal()
    termsAndConditionsRetrieved = pyqtSignal([str], arguments=['message'])
    termsAndConditionsError = pyqtSignal([str], arguments=['message'])
    otpError = pyqtSignal([str], arguments=['message'])
    otpSuccess = pyqtSignal()
    disclaimerChanged = pyqtSignal()
    keystoreChanged = pyqtSignal()
    otpSecretChanged = pyqtSignal()
    shortIdChanged = pyqtSignal()
    billingModelChanged = pyqtSignal()

    remoteKeyStateChanged = pyqtSignal()
    remoteKeyError = pyqtSignal([str], arguments=['message'])

    requestOtp = pyqtSignal()

    def __init__(self, plugin, wizard: 'NewWalletWizard', parent):
        super().__init__(plugin, parent)
        self.wizard = wizard
        self._canSignWithoutServer = False
        self._otpSecret = ''
        self._shortId = ''
        self._billingModel = []
        self._remoteKeyState = ''
        self._verifyingOtp = False

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

    @pyqtProperty(str, notify=remoteKeyStateChanged)
    def remoteKeyState(self):
        return self._remoteKeyState

    @remoteKeyState.setter
    def remoteKeyState(self, new_state):
        if self._remoteKeyState != new_state:
            self._remoteKeyState = new_state
            self.remoteKeyStateChanged.emit()

    @pyqtProperty('QVariantList', notify=billingModelChanged)
    def billingModel(self):
        return self._billingModel

    def updateBillingInfo(self, wallet):
        billingModel = []

        price_per_tx = wallet.price_per_tx
        for k, v in sorted(price_per_tx.items()):
            if k == 1:
                continue
            item = {
                'text': 'Pay every %d transactions' % k,
                'value': k,
                'sats_per_tx': v / k
            }
            billingModel.append(item)

        self._billingModel = billingModel
        self.billingModelChanged.emit()

    @pyqtSlot()
    def fetchTermsAndConditions(self):
        def fetch_task():
            try:
                self.plugin.logger.debug('TOS')
                tos = server.get_terms_of_service()
            except ErrorConnectingServer as e:
                self.termsAndConditionsError.emit(_('Error connecting to server'))
            except Exception as e:
                self.termsAndConditionsError.emit('%s: %s' % (_('Error'), repr(e)))
            else:
                self.termsAndConditionsRetrieved.emit(tos)
            finally:
                self._busy = False
                self.busyChanged.emit()

        self._busy = True
        self.busyChanged.emit()
        t = threading.Thread(target=fetch_task)
        t.daemon = True
        t.start()

    @pyqtSlot()
    def createKeystore(self):
        email = 'dummy@electrum.org'

        self.remoteKeyState = ''
        self._otpSecret = ''
        self.otpSecretChanged.emit()

        wizard_data = self.wizard.get_wizard_data()

        xprv1, xpub1, xprv2, xpub2, xpub3, short_id = self.plugin.create_keys(wizard_data)

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
            except (KeyError, TypeError) as e:  # catch any assumptions
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
                self.remoteKeyState = 'new'
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

        wizard_data = self.wizard.get_wizard_data()

        xprv1, xpub1, xprv2, xpub2, xpub3, short_id = self.plugin.create_keys(wizard_data)

        def reset_otp_task():
            try:
                self.plugin.logger.debug('reset_otp')
                r = server.get_challenge(short_id)
                challenge = r.get('challenge')
                message = 'TRUSTEDCOIN CHALLENGE: ' + challenge

                def f(xprv):
                    rootnode = BIP32Node.from_xkey(xprv)
                    key = rootnode.subkey_at_private_derivation((0, 0)).eckey
                    sig = key.ecdsa_sign_usermessage(message, is_compressed=True)
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
                self.remoteKeyState = 'reset'
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
        assert type(otp) is int  # make sure this doesn't fail subtly

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
                self._verifyingOtp = False

        self._verifyingOtp = True
        self._busy = True
        self.busyChanged.emit()
        t = threading.Thread(target=check_otp_task, daemon=True)
        t.start()
