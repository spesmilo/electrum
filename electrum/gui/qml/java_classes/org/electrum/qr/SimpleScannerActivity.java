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

import me.dm7.barcodescanner.zxing.ZXingScannerView;

import com.google.zxing.Result;
import com.google.zxing.BarcodeFormat;

import org.electrum.electrum.res.R; // package set in build.gradle

public class SimpleScannerActivity extends Activity implements ZXingScannerView.ResultHandler {
    private static final int MY_PERMISSIONS_CAMERA = 1002;

    private ZXingScannerView mScannerView = null;
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
            mScannerView.stopCamera();           // Stop camera on pause
        }
    }

    private void startCamera() {
        mScannerView = new ZXingScannerView(this);
        mScannerView.setFormats(Arrays.asList(BarcodeFormat.QR_CODE));
        ViewGroup contentFrame = (ViewGroup) findViewById(R.id.content_frame);
        contentFrame.addView(mScannerView);
        mScannerView.setResultHandler(this);         // Register ourselves as a handler for scan results.
        mScannerView.startCamera();                  // Start camera on resume
    }

    @Override
    public void handleResult(Result rawResult) {
        //resultIntent.putExtra("format", rawResult.getBarcodeFormat().toString());
        this.setResultAndClose(rawResult.getText());
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
