package org.electroncash.electroncash3

import android.content.ClipboardManager
import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import com.chaquo.python.PyException
import com.chaquo.python.PyObject
import com.google.zxing.integration.android.IntentIntegrator
import kotlinx.android.synthetic.main.load.*
import java.lang.IllegalArgumentException


val libTransaction by lazy { libMod("transaction") }


// This provides a dialog to allow users to input a string, which is then broadcast
// on the bitcoin cash network. Strings are not validated,
// but broadcast_transaction should throw error which is toasted.
// Valid transaction quickly show up in transactions.

class ColdLoadDialog : AlertDialogFragment() {
    /* 1 = signed, 0 = partially signed, -1 = invalid */
    var txStatus: Int? = null

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
        val currenttext = etTransaction.text
        //checks if text is blank. further validations can be added here
        dialog.getButton(AlertDialog.BUTTON_POSITIVE).isEnabled = currenttext.isNotBlank()

        val tx: PyObject
        if (currenttext.isNotBlank()) {
            tx = libTransaction.callAttr("Transaction", etTransaction.text.toString())

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
    }

    // Receives the result of a QR scan.
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        val result = IntentIntegrator.parseActivityResult(requestCode, resultCode, data)

        // Try to decode the QR content as Base43; if that fails, treat it as is
        val txHex: String = try {
            Base43.decode(result.contents)
        } catch (e: IllegalArgumentException) {
            result.contents
        }

        if (result != null && result.contents != null) {
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
            return
        }
    }

    /**
     * Sign a loaded transaction.
     */
    private fun signLoadedTransaction() {
        val dialog = SignPasswordDialog()
        dialog.setArguments(Bundle().apply {
            putString("tx", etTransaction.text.toString())
        })
        showDialog(this, dialog)
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
            toast(R.string.the_string, Toast.LENGTH_LONG)
            dismiss()
        } catch (e: ToastException) { e.show() }
    }


    /**
     * Check if a loaded transaction is signed.
     * Displays the signing status below the raw TX field.
     * (signed, partially signed, or invisible label, if the transaction is invalid)
     */
    private fun updateStatusText(tx: PyObject) {
        try {
            val txInfo = daemonModel.wallet!!.callAttr("get_tx_info", tx)

            idStatusLabel.visibility = View.VISIBLE
            idTxStatus.visibility = View.VISIBLE

            // Check if the transaction can be processed by this wallet or not
            if (txInfo["amount"] == null) {
                idTxStatus.setText(R.string.transaction_unrelated)
            } else {
                idTxStatus.setText(txInfo["status"].toString())
            }
        } catch (e: PyException) {
            idStatusLabel.visibility = View.INVISIBLE
            idTxStatus.visibility = View.INVISIBLE
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

/**
 * Sign a loaded transaction dialog.
 */
class SignPasswordDialog : PasswordDialog<Unit>() {

    val coldLoadDialog by lazy { targetFragment as ColdLoadDialog }
    val signSchnorr = daemonModel.walletType == "standard" // sign with Schnorr in standard wallets

    val tx by lazy { libTransaction.callAttr("Transaction", arguments!!.getString("tx"), signSchnorr) }
    val wallet = daemonModel.wallet!!

    override fun onPassword(password: String) {
        wallet.callAttr("sign_transaction", tx, password)

        postToUiThread {
            coldLoadDialog.etTransaction.setText(tx.toString())
        }
    }

    override fun onPostExecute(result: Unit) {
        if (!canBroadcast(tx)) {
            coldLoadDialog.dismiss()
            copyToClipboard(tx.toString(), R.string.signed_transaction)
        }
    }
}