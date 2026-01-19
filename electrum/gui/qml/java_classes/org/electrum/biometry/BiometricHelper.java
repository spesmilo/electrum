package org.electrum.biometry;

import android.content.Context;
import android.content.pm.PackageManager;
import android.hardware.biometrics.BiometricManager;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;

public class BiometricHelper {
    public static boolean isAvailable(Context context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) { // API 30+
            BiometricManager biometricManager = context.getSystemService(BiometricManager.class);
            return biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG | BiometricManager.Authenticators.DEVICE_CREDENTIAL) == BiometricManager.BIOMETRIC_SUCCESS;
        }
        return false;
    }
}