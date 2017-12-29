package org.electrum.qr;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.content.Intent;

import java.util.Arrays;

import me.dm7.barcodescanner.zxing.ZXingScannerView;

import com.google.zxing.Result;
import com.google.zxing.BarcodeFormat;

public class SimpleScannerActivity extends Activity implements ZXingScannerView.ResultHandler {
    private ZXingScannerView mScannerView;
    final String TAG = "org.electrum.SimpleScannerActivity";

    @Override
    public void onCreate(Bundle state) {
        super.onCreate(state);
        mScannerView = new ZXingScannerView(this);   // Programmatically initialize the scanner view
        mScannerView.setFormats(Arrays.asList(BarcodeFormat.QR_CODE));
        setContentView(mScannerView);                // Set the scanner view as the content view
    }

    @Override
    public void onResume() {
        super.onResume();
        mScannerView.setResultHandler(this); // Register ourselves as a handler for scan results.
        mScannerView.startCamera();          // Start camera on resume
    }

    @Override
    public void onPause() {
        super.onPause();
        mScannerView.stopCamera();           // Stop camera on pause
    }

    @Override
    public void handleResult(Result rawResult) {
        Intent resultIntent = new Intent();
        resultIntent.putExtra("text", rawResult.getText());
        resultIntent.putExtra("format", rawResult.getBarcodeFormat().toString());
        setResult(Activity.RESULT_OK, resultIntent);
        this.finish();
    }
}
