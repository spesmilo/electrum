package org.electroncash.electroncash3

import android.content.ClipboardManager
import android.content.Intent
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import com.google.zxing.integration.android.IntentIntegrator
import kotlinx.android.synthetic.main.load.*


val libTransaction by lazy { libMod("transaction") }


// This provides a dialog to allow users to input a string, which is then broadcast
// on the bitcoin cash network. Strings are not validated,
// but broadcast_transaction should throw error which is toasted.
// Valid transaction quickly show up in transactions.

class ColdLoadDialog : AlertDialogFragment() {
    override fun onBuildDialog(builder: AlertDialog.Builder) {
        builder.setTitle(R.string.load_transaction)
                .setView(R.layout.load)
                .setNegativeButton(android.R.string.cancel, null)
                .setNeutralButton(R.string.qr_code, null)
                .setPositiveButton(R.string.send, null)
    }

    override fun onShowDialog() {
        super.onShowDialog()
        etTransaction.addAfterTextChangedListener{ updateUI() }
        updateUI()

        dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener { onOK() }
        dialog.getButton(AlertDialog.BUTTON_NEUTRAL).setOnClickListener { scanQR(this) }
        btnPaste.setOnClickListener {
            val clipdata = getSystemService(ClipboardManager::class).primaryClip
            if (clipdata != null && clipdata.getItemCount() > 0) {
                val cliptext = clipdata.getItemAt(0)
                etTransaction.setText(cliptext.text)
            }
        }
    }

    private fun updateUI() {
        val currenttext = etTransaction.text
        //checks if text is blank. further validations can be added here
        dialog.getButton(AlertDialog.BUTTON_POSITIVE).isEnabled = currenttext.isNotBlank()
    }

    // Receives the result of a QR scan.
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        val result = IntentIntegrator.parseActivityResult(requestCode, resultCode, data)
        if (result != null && result.contents != null) {
            etTransaction.setText(result.contents)
        } else {
            super.onActivityResult(requestCode, resultCode, data)
        }
    }

    fun onOK() {
        val tx = libTransaction.callAttr("Transaction", etTransaction.text.toString())
        try {
            if (!daemonModel.isConnected()) {
                throw ToastException(R.string.not_connected)
            }
            val result = daemonModel.network.callAttr("broadcast_transaction", tx)
            checkBroadcastResult(result)
            toast(R.string.the_string, Toast.LENGTH_LONG)
            dismiss()
        } catch (e: ToastException) { e.show() }
    }
}