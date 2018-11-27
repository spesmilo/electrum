package org.electrum.qr;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.content.Intent;
import android.support.v4.app.ActivityCompat;
import android.Manifest;
import android.content.pm.PackageManager;

import java.util.Arrays;

import me.dm7.barcodescanner.zxing.ZXingScannerView;

import com.google.zxing.Result;
import com.google.zxing.BarcodeFormat;

public class SimpleScannerActivity extends Activity implements ZXingScannerView.ResultHandler {
    private static final int MY_PERMISSIONS_CAMERA = 1002;

    private ZXingScannerView mScannerView = null;
    final String TAG = "org.electrum.SimpleScannerActivity";

    @Override
    public void onResume() {
        super.onResume();
        if (this.hasPermission()) {
            this.startCamera();
        } else {
            this.requestPermission();
        }
    }

    @Override
    public void onPause() {
        super.onPause();
        if (null != mScannerView) {
            mScannerView.stopCamera();           // Stop camera on pause
        }
    }

    private void startCamera() {
        mScannerView = new ZXingScannerView(this);   // Programmatically initialize the scanner view
        mScannerView.setFormats(Arrays.asList(BarcodeFormat.QR_CODE));
        setContentView(mScannerView);                // Set the scanner view as the content view
        mScannerView.setResultHandler(this);         // Register ourselves as a handler for scan results.
        mScannerView.startCamera();                  // Start camera on resume
    }

    @Override
    public void handleResult(Result rawResult) {
        Intent resultIntent = new Intent();
        resultIntent.putExtra("text", rawResult.getText());
        resultIntent.putExtra("format", rawResult.getBarcodeFormat().toString());
        setResult(Activity.RESULT_OK, resultIntent);
        this.finish();
    }

    private boolean hasPermission() {
        return (ActivityCompat.checkSelfPermission(this,
                                                   Manifest.permission.CAMERA)
                == PackageManager.PERMISSION_GRANTED);
    }

    private void requestPermission() {
        ActivityCompat.requestPermissions(this,
                    new String[]{Manifest.permission.CAMERA},
                    MY_PERMISSIONS_CAMERA);
    }

    @Override
    public void onRequestPermissionsResult(int requestCode,
            String permissions[], int[] grantResults) {
        switch (requestCode) {
            case MY_PERMISSIONS_CAMERA: {
                if (grantResults.length > 0
                    && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                    // permission was granted, yay!
                    this.startCamera();
                } else {
                    // permission denied
                    this.finish();
                }
                return;
            }
        }
    }

}
