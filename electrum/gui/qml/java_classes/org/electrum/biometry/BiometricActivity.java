package org.electrum.biometry;

import android.app.Activity;
import android.os.Build;
import android.os.Bundle;
import android.os.CancellationSignal;
import android.content.Intent;
import android.hardware.biometrics.BiometricPrompt;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;
import android.widget.Toast;

import java.nio.charset.Charset;
import java.security.KeyStore;
import java.util.concurrent.Executor;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.electrum.electrum.res.R;

public class BiometricActivity extends Activity {
    private static final String TAG = "BiometricActivity";
    private static final String KEY_NAME = "electrum_biometric_key";
    private static final int RESULT_SETUP_FAILED = 101;
    private static final int RESULT_POPUP_CANCELLED = 102;
    private CancellationSignal cancellationSignal;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            Log.e(TAG, "Biometrics not supported on this Android version (requires API 29+)");
            setResult(RESULT_CANCELED);
            finish();
            return;
        }

        handleIntent();
    }

    private void handleIntent() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return;

        Intent intent = getIntent();
        String action = intent.getStringExtra("action");

        Executor executor = getMainExecutor();
        BiometricPrompt biometricPrompt = new BiometricPrompt.Builder(this)
                .setTitle("Electrum Wallet")
                .setSubtitle("Confirm your identity")
                .setNegativeButton("Cancel", executor, (dialog, which) -> {
                    Log.d(TAG, "Authentication cancelled");
                    setResult(RESULT_POPUP_CANCELLED);
                    finish();
                })
                .build();

        cancellationSignal = new CancellationSignal();

        BiometricPrompt.AuthenticationCallback callback = new BiometricPrompt.AuthenticationCallback() {
            @Override
            public void onAuthenticationError(int errorCode, CharSequence errString) {
                super.onAuthenticationError(errorCode, errString);
                Log.e(TAG, "Authentication error: " + errString);
                setResult(RESULT_CANCELED);
                finish();
            }

            @Override
            public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {
                super.onAuthenticationSucceeded(result);
                Log.d(TAG, "Authentication succeeded!");
                handleAuthenticationSuccess(result);
            }

            @Override
            public void onAuthenticationFailed() {
                super.onAuthenticationFailed();
                Log.d(TAG, "Authentication failed");
            }
        };

        try {
            if ("ENCRYPT".equals(action)) {
                Cipher cipher = getCipher();
                SecretKey secretKey = genSecretKey();
                cipher.init(Cipher.ENCRYPT_MODE, secretKey);
                biometricPrompt.authenticate(new BiometricPrompt.CryptoObject(cipher), cancellationSignal, executor, callback);
            } else if ("DECRYPT".equals(action)) {
                String ivStr = intent.getStringExtra("iv");
                byte[] iv = Base64.decode(ivStr, Base64.NO_WRAP);
                Cipher cipher = getCipher();
                SecretKey secretKey = getSecretKey();
                cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
                biometricPrompt.authenticate(new BiometricPrompt.CryptoObject(cipher), cancellationSignal, executor, callback);
            } else {
                finish();
            }
        } catch (Exception e) {
            Log.e(TAG, "Setup error", e);
            Toast.makeText(this, "Biometric setup failed: " + e.getMessage(), Toast.LENGTH_SHORT).show();
            setResult(RESULT_SETUP_FAILED);
            finish();
        }
    }

    private void handleAuthenticationSuccess(BiometricPrompt.AuthenticationResult result) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return;
        try {
            BiometricPrompt.CryptoObject cryptoObject = result.getCryptoObject();
            Cipher cipher = cryptoObject.getCipher();
            Intent intent = getIntent();
            String action = intent.getStringExtra("action");
            Intent resultIntent = new Intent();
            resultIntent.putExtra("action", action);

            if ("ENCRYPT".equals(action)) {
                String data = intent.getStringExtra("data"); // Wallet password to encrypt
                byte[] encrypted = cipher.doFinal(data.getBytes(Charset.forName("UTF-8")));
                resultIntent.putExtra("data", Base64.encodeToString(encrypted, Base64.NO_WRAP));
                resultIntent.putExtra("iv", Base64.encodeToString(cipher.getIV(), Base64.NO_WRAP));
            } else {
                String dataStr = intent.getStringExtra("data"); // Encrypted blob
                byte[] encrypted = Base64.decode(dataStr, Base64.NO_WRAP);
                byte[] decrypted = cipher.doFinal(encrypted);
                resultIntent.putExtra("data", new String(decrypted, Charset.forName("UTF-8")));
            }
            setResult(RESULT_OK, resultIntent);
        } catch (Exception e) {
            Log.e(TAG, "Crypto error", e);
            setResult(RESULT_CANCELED);
        }
        finish();
    }

    private SecretKey getSecretKey() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        return (SecretKey) keyStore.getKey(KEY_NAME, null);
    }

    private SecretKey genSecretKey() throws Exception {
        // https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder?hl=en
        KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(KEY_NAME,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                .setUserAuthenticationRequired(true)
                .setInvalidatedByBiometricEnrollment(true);

        keyGenerator.init(builder.build());
        keyGenerator.generateKey();

        return getSecretKey();
    }

    private Cipher getCipher() throws Exception {
        return Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/"
                + KeyProperties.BLOCK_MODE_CBC + "/"
                + KeyProperties.ENCRYPTION_PADDING_PKCS7);
    }
}