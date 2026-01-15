import os
import secrets
from enum import Enum
from typing import Optional, TYPE_CHECKING

from PyQt6.QtCore import QObject, pyqtSignal, pyqtSlot, pyqtProperty

from electrum.i18n import _
from electrum.logging import get_logger
from electrum.base_crash_reporter import send_exception_to_crash_reporter
from electrum.crypto import aes_encrypt_with_iv, aes_decrypt_with_iv

from .auth import auth_protect, AuthMixin

if TYPE_CHECKING:
    from electrum.simple_config import SimpleConfig


_logger = get_logger(__name__)


jBiometricHelper = None
jBiometricActivity = None
jPythonActivity = None
jIntent = None
jString = None

if 'ANDROID_DATA' in os.environ:
    from jnius import autoclass
    from android import activity
    jPythonActivity = autoclass('org.kivy.android.PythonActivity').mActivity
    jBiometricHelper = autoclass('org.electrum.biometry.BiometricHelper')
    jBiometricActivity = autoclass('org.electrum.biometry.BiometricActivity')
    jIntent = autoclass('android.content.Intent')
    jString = autoclass('java.lang.String')


class BiometricAction(str, Enum):
    ENCRYPT = "ENCRYPT"
    DECRYPT = "DECRYPT"


class QEBiometrics(AuthMixin, QObject):
    REQUEST_CODE_BIOMETRIC_ACTIVITY = 24553  # random 16 bit int
    RESULT_CODE_SETUP_FAILED = 101  # codes duplicated from BiometricActivity.java
    RESULT_CODE_POPUP_CANCELLED = 102

    enablingFailed = pyqtSignal(str, arguments=['error'])
    unlockSuccess = pyqtSignal(str, arguments=['password'])
    unlockError = pyqtSignal(str, arguments=['error'])

    def __init__(self, *, config: 'SimpleConfig', parent=None):
        super().__init__(parent)
        self.config = config
        self._current_action: Optional[BiometricAction] = None

    @pyqtProperty(bool, constant=True)
    def isAvailable(self) -> bool:
        if 'ANDROID_DATA' not in os.environ:
            return False
        try:
            return jBiometricHelper.isAvailable(jPythonActivity)
        except Exception as e:
            send_exception_to_crash_reporter(e)
            return False

    isEnabledChanged = pyqtSignal()
    @pyqtProperty(bool, notify=isEnabledChanged)
    def isEnabled(self) -> bool:
        return self.config.WALLET_ANDROID_USE_BIOMETRIC_AUTHENTICATION

    @pyqtSlot(str)
    def enable(self, unified_wallet_password: str):
        """
        We encrypt (`wrap`) the wallet password with a random key 'wrap_key' and encrypt the random key
        with the AndroidKeyStore.
        Both the encrypted wrap_key and the encrypted wallet password are stored in the config.
        The encryption key for the wrap_key is stored in the AndroidKeyStore.
        This way the wallet password doesn't have to leave the process.
        """
        wrap_key, iv = secrets.token_bytes(32), secrets.token_bytes(16)
        wrapped_wallet_password = aes_encrypt_with_iv(
            key=wrap_key,
            iv=iv,
            data=unified_wallet_password.encode('utf-8'),
        )
        encrypted_password_bundle = f"{iv.hex()}:{wrapped_wallet_password.hex()}"
        self.config.WALLET_ANDROID_BIOMETRIC_AUTH_WRAPPED_WALLET_PASSWORD = encrypted_password_bundle
        self._start_activity(BiometricAction.ENCRYPT, data=wrap_key.hex())

    @pyqtSlot()
    def disable(self):
        self.config.WALLET_ANDROID_USE_BIOMETRIC_AUTHENTICATION = False
        self.config.WALLET_ANDROID_BIOMETRIC_AUTH_WRAPPED_WALLET_PASSWORD = ''
        self.config.WALLET_ANDROID_BIOMETRIC_AUTH_ENCRYPTED_WRAP_KEY = ''
        self.isEnabledChanged.emit()
        _logger.info("Android biometric authentication disabled")

    @pyqtSlot()
    @auth_protect(method='wallet_password_only', reject='_disable_protected_failed')
    def disableProtected(self):
        """
        Exists to ensure the user knows the wallet password when manually disabling
        biometric authentication. If they don't remember the password they can still do a seed
        backup or transactions if biometrics stay enabled. However, note it is still possible for
        biometrics to get disabled automatically on invalidation or error, so this cannot
        fully protect the user from forgetting their wallet password either.
        """
        self.disable()

    def _disable_protected_failed(self):
        self.isEnabledChanged.emit()

    @pyqtSlot()
    @pyqtSlot(str)
    def unlock(self, auth_message: str = None):
        """
        Called when the user needs to authenticate.
        Makes the AndroidKeyStore decrypt our encrypted wrap key, we then use the decrypted wrap key
        to decrypt the encrypted wallet password.
        auth_message is shown in the system auth popup and defaults to 'Confirm your identity'.
        """
        encrypted_wrap_key = self.config.WALLET_ANDROID_BIOMETRIC_AUTH_ENCRYPTED_WRAP_KEY
        assert encrypted_wrap_key, "shouldn't unlock if biometric auth is disabled"
        self._start_activity(BiometricAction.DECRYPT, data=encrypted_wrap_key, auth_message=auth_message)

    def _start_activity(self, action: BiometricAction, data: str, auth_message: str = None):
        self._current_action = action

        _logger.debug(f"_start_activity: {action.value}, {len(data)=}")
        intent = jIntent(jPythonActivity, jBiometricActivity)
        intent.putExtra(jString("action"), jString(action.value))
        intent.putExtra(jString("auth_message"), jString(auth_message or _("Confirm your identity")))
        if action == BiometricAction.ENCRYPT:
            intent.putExtra(jString("data"), jString(data))  # wrap_key
        elif action == BiometricAction.DECRYPT:
            assert ':' in data, f"malformed encrypted_bundle: {data=}"
            iv, encrypted_wrap_key = data.split(':')
            intent.putExtra(jString("iv"), jString(iv))
            intent.putExtra(jString("data"), jString(encrypted_wrap_key))
        else:
            raise ValueError(f"unsupported {action=}")

        activity.bind(on_activity_result=self._on_activity_result)
        jPythonActivity.startActivityForResult(intent, self.REQUEST_CODE_BIOMETRIC_ACTIVITY)

    def _on_activity_result(self, requestCode: int, resultCode: int, intent):
        if requestCode != self.REQUEST_CODE_BIOMETRIC_ACTIVITY:
            return

        action = self._current_action
        self._current_action = None

        try:
            activity.unbind(on_activity_result=self._on_activity_result)
            if resultCode == -1: # RESULT_OK
                data = intent.getStringExtra(jString("data"))
                if action == BiometricAction.ENCRYPT:
                    iv = intent.getStringExtra(jString("iv"))
                    encrypted_bundle = f"{iv}:{data}"
                    self._on_wrap_key_encrypted(encrypted_bundle=encrypted_bundle)
                else:
                    self._on_wrap_key_decrypted(wrap_key=data)
                return
        except Exception as e:  # prevent exc from getting lost
            send_exception_to_crash_reporter(e)

        # on qml side we act on specific errors, so these error strings shouldn't be changed
        if resultCode == self.RESULT_CODE_SETUP_FAILED and action == BiometricAction.DECRYPT:
            # setup failed, we need to delete the biometry data, it cannot be decrypted anymore
            _logger.debug(f"biometric decryption failed, probably invalidated key")
            error = 'INVALIDATED'
            self.disable()  # reset
        elif resultCode == self.RESULT_CODE_POPUP_CANCELLED:  # user clicked cancel on auth popup
            _logger.debug(f"biometric auth cancelled by user")
            error = 'CANCELLED'
        else:  # some other error
            _logger.error(f"biometric auth failed: {action=}, {resultCode=}")
            error = f"{resultCode=}"

        if action == BiometricAction.DECRYPT:
            self.unlockError.emit(error)
        else:
            self.disable()  # reset
            self.enablingFailed.emit(error)

    def _on_wrap_key_decrypted(self, *, wrap_key: str):
        encrypted_password_bundle = self.config.WALLET_ANDROID_BIOMETRIC_AUTH_WRAPPED_WALLET_PASSWORD
        assert encrypted_password_bundle and ':' in encrypted_password_bundle
        iv, encrypted_password = encrypted_password_bundle.split(':')
        decrypted_password = aes_decrypt_with_iv(
            key=bytes.fromhex(wrap_key),
            iv=bytes.fromhex(iv),
            data=bytes.fromhex(encrypted_password),
        )
        self.unlockSuccess.emit(decrypted_password.decode('utf-8'))

    def _on_wrap_key_encrypted(self, *, encrypted_bundle: str):
        self.config.WALLET_ANDROID_BIOMETRIC_AUTH_ENCRYPTED_WRAP_KEY = encrypted_bundle
        self.config.WALLET_ANDROID_USE_BIOMETRIC_AUTHENTICATION = True
        self.isEnabledChanged.emit()
