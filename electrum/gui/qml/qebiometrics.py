import os
from enum import Enum
from typing import Optional

from electrum.logging import get_logger
from electrum.base_crash_reporter import send_exception_to_crash_reporter

from PyQt6.QtCore import QObject, pyqtSignal, pyqtSlot, pyqtProperty


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


class QEBiometrics(QObject):
    REQUEST_CODE_BIOMETRIC_ACTIVITY = 24553
    RESULT_CODE_SETUP_FAILED = 101
    RESULT_CODE_POPUP_CANCELLED = 102

    encryptionSuccess = pyqtSignal(str, arguments=['encrypted_password'])
    encryptionError = pyqtSignal(str, arguments=['error'])
    decryptionSuccess = pyqtSignal(str, arguments=['password'])
    decryptionError = pyqtSignal(str, arguments=['error'])

    def __init__(self, parent=None):
        super().__init__(parent)
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

    @pyqtSlot(str)
    def encrypt(self, password: str):
        """
        This is done when enabling biometric authentication.
        Encrypts the password. We get the encrypted, base64 encoded password and have to store it.
        The encryption key is handled by the OS (secure element).
        """
        self._start_activity(BiometricAction.ENCRYPT, data=password)

    @pyqtSlot(str)
    def decrypt(self, encrypted_bundle: str):
        """
        Called when the user needs to authenticate. We pass the encrypted password, it will get
        decrypted on java side with the decryption key from the OS.
        encrypted_bundle format: "iv:ciphertext"
        """
        self._start_activity(BiometricAction.DECRYPT, data=encrypted_bundle)

    def _start_activity(self, action: BiometricAction, data: str):
        self._current_action = action

        _logger.debug(f"_start_activity: {action.value}, {len(data)=}")
        intent = jIntent(jPythonActivity, jBiometricActivity)
        intent.putExtra(jString("action"), jString(action.value))
        if action == BiometricAction.ENCRYPT:
            intent.putExtra(jString("data"), jString(data))  # password
        elif action == BiometricAction.DECRYPT:
            assert ':' in data, f"malformed encrypted_bundle: {data=}"
            iv, encrypted_password = data.split(':')
            intent.putExtra(jString("iv"), jString(iv))
            intent.putExtra(jString("data"), jString(encrypted_password))
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
                    self.encryptionSuccess.emit(encrypted_bundle)
                else:
                    self.decryptionSuccess.emit(data)  # password
                return
        except Exception as e:  # prevent exc from getting lost
            send_exception_to_crash_reporter(e)

        # on qml side we act on specific errors, so these error strings shouldn't be changed
        if resultCode == self.RESULT_CODE_SETUP_FAILED and action == BiometricAction.DECRYPT:
            # setup failed, we need to delete the encrypted password, it cannot be decrypted anymore
            _logger.debug(f"biometric decryption failed, probably invalidated key")
            error = 'INVALIDATE'
        elif resultCode == self.RESULT_CODE_POPUP_CANCELLED:  # user clicked cancel on auth popup
            _logger.debug(f"biometric auth cancelled by user")
            error = 'CANCELLED'
        else:  # some other error
            _logger.error(f"biometric auth failed: {action=}, {resultCode=}")
            error = f"{resultCode=}"

        if action == BiometricAction.DECRYPT:
            self.decryptionError.emit(error)
        else:
            self.encryptionError.emit(error)

