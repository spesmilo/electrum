package org.electroncash.electroncash3

import android.content.ClipboardManager
import android.content.Intent
import android.os.Bundle
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import com.chaquo.python.PyException
import com.chaquo.python.PyObject
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
                .setPositiveButton(R.string.OK, null)
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
        val tx = libTransaction.callAttr("Transaction", etTransaction.text.toString())
        updateStatusText(tx)

        // Check hex transaction signing status
        if (canSign(tx)) {
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setText(R.string.sign)
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).isEnabled = true
        } else if (canBroadcast(tx)) {
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setText(R.string.send)
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).isEnabled = true
        } else {
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).isEnabled = false
        }
    }

    // Receives the result of a QR scan.
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        val result = IntentIntegrator.parseActivityResult(requestCode, resultCode, data)

        if (result != null && result.contents != null) {
            // Try to decode the QR content as Base43; if that fails, treat it as is
            val txHex: String = try {
                baseDecode(result.contents, 43)
            } catch (e: PyException) {
                result.contents
            }
            etTransaction.setText(txHex)
        } else {
            super.onActivityResult(requestCode, resultCode, data)
        }
    }

    fun onOK() {
        val tx = libTransaction.callAttr("Transaction", etTransaction.text.toString())

        // If transaction can be broadcasted, broadcast it.
        // Otherwise, prompt for signing. If the transaction hex is invalid,
        // the OK button will be disabled, regardless.
        try {
            if (canBroadcast(tx)) {
                broadcastSignedTransaction(tx)
            } else {
                signLoadedTransaction()
            }
        } catch (e: ToastException) {
            e.show()
        }
    }

    /**
     * Sign a loaded transaction.
     */
    private fun signLoadedTransaction() {
        val arguments = Bundle().apply {
            putString("txHex", etTransaction.text.toString())
            putBoolean("unbroadcasted", true)
        }
        val dialog = SendDialog()
        showDialog(this, dialog.apply { setArguments(arguments) })
    }

    /**
     * Broadcast a signed transaction.
     */
    private fun broadcastSignedTransaction(tx: PyObject) {
        try {
            if (!daemonModel.isConnected()) {
                throw ToastException(R.string.not_connected)
            }
            val result = daemonModel.network.callAttr("broadcast_transaction", tx)
            checkBroadcastResult(result)
            toast(R.string.the_transaction_has, Toast.LENGTH_LONG)
            dismiss()
        } catch (e: ToastException) { e.show() }
    }


    /**
     * Check if a loaded transaction is signed.
     * Displays the signing status below the raw TX field.
     * (signed, partially signed, empty or invalid)
     */
    private fun updateStatusText(tx: PyObject) {
        try {
            if (etTransaction.text.isBlank()) {
                idTxStatus.setText(R.string.empty)
            } else {
                // Check if the transaction can be processed by this wallet or not
                val txInfo = daemonModel.wallet!!.callAttr("get_tx_info", tx)

                if (txInfo["amount"] == null && !canBroadcast(tx)) {
                    idTxStatus.setText(R.string.transaction_unrelated)
                } else {
                    idTxStatus.setText(txInfo["status"].toString())
                }
            }
        } catch (e: PyException) {
            idTxStatus.setText(R.string.invalid)
        }
    }
}

/* Check if the wallet can sign the transaction */
fun canSign(tx: PyObject): Boolean {
    return try {
        !tx.callAttr("is_complete").toBoolean() and
                daemonModel.wallet!!.callAttr("can_sign", tx).toBoolean()
    } catch (e: PyException) {
        false
    }
}

/* Check if the transaction is ready to be broadcasted */
fun canBroadcast(tx: PyObject): Boolean {
    return try {
        tx.callAttr("is_complete").toBoolean()
    } catch (e: PyException) {
        false
    }
}
