package org.electrum.qr;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.content.Intent;
import android.Manifest;
import android.content.ClipData;
import android.content.ClipDescription;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.pm.PackageManager;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import androidx.core.app.ActivityCompat;

import java.util.Arrays;

import de.markusfisch.android.barcodescannerview.widget.BarcodeScannerView;


import org.electrum.electrum.res.R; // package set in build.gradle

public class SimpleScannerActivity extends Activity {
    private static final int MY_PERMISSIONS_CAMERA = 1002;

    private BarcodeScannerView mScannerView = null;
    final String TAG = "org.electrum.SimpleScannerActivity";

    private boolean mAlreadyRequestedPermissions = false;

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.scanner_layout);

        // change top text
        Intent intent = getIntent();
        String text = intent.getStringExtra(intent.EXTRA_TEXT);
        TextView hintTextView = (TextView) findViewById(R.id.hint);
        hintTextView.setText(text);

        // bind "paste" button
        Button btn = (Button) findViewById(R.id.paste_btn);
        btn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                ClipboardManager clipboard = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
                if (clipboard.hasPrimaryClip()
                        && (clipboard.getPrimaryClipDescription().hasMimeType(ClipDescription.MIMETYPE_TEXT_PLAIN)
                            || clipboard.getPrimaryClipDescription().hasMimeType(ClipDescription.MIMETYPE_TEXT_HTML))) {
                    ClipData.Item item = clipboard.getPrimaryClip().getItemAt(0);
                    String clipboardText = item.getText().toString();
                    // limit size of content. avoid https://developer.android.com/reference/android/os/TransactionTooLargeException.html
                    if (clipboardText.length() >  512 * 1024) {
                        Toast.makeText(SimpleScannerActivity.this, "Clipboard contents too large.", Toast.LENGTH_SHORT).show();
                        return;
                    }
                    SimpleScannerActivity.this.setResultAndClose(clipboardText);
                } else {
                    Toast.makeText(SimpleScannerActivity.this, "Clipboard is empty.", Toast.LENGTH_SHORT).show();
                }
            }
        });
    }

    @Override
    public void onResume() {
        super.onResume();
        if (this.hasPermission()) {
            this.startCamera();
        } else if (!mAlreadyRequestedPermissions) {
            mAlreadyRequestedPermissions = true;
            this.requestPermission();
        }
    }

    @Override
    public void onPause() {
        super.onPause();
        if (null != mScannerView) {
            mScannerView.close();  // Stop camera on pause
        }
    }

    private void startCamera() {
        mScannerView = new BarcodeScannerView(this);
        mScannerView.setCropRatio(0.75f); // Set crop ratio to 75% (this defines the square area shown in the scanner view)
        // by default only Format.QR_CODE is set
        ViewGroup contentFrame = (ViewGroup) findViewById(R.id.content_frame);
        contentFrame.addView(mScannerView);
        mScannerView.setOnBarcodeListener(result -> {
            // Handle the scan result
            this.setResultAndClose(result.getText());
            // Return false to stop scanning after first result
            return false;
        });
        mScannerView.openAsync();  // Start camera on resume
    }

    private void setResultAndClose(String resultText) {
        Intent resultIntent = new Intent();
        resultIntent.putExtra("text", resultText);
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
                    //this.finish();
                }
                return;
            }
        }
    }

}
