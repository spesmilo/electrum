package org.electroncash.electroncash3

import android.content.ClipboardManager
import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.fragment.app.DialogFragment
import com.chaquo.python.Kwarg
import com.chaquo.python.PyException
import com.chaquo.python.PyObject
import com.chaquo.python.PyObject.fromJava
import com.google.zxing.integration.android.IntentIntegrator
import kotlinx.android.synthetic.main.load.*
import kotlinx.android.synthetic.main.load.tvStatus
import kotlinx.android.synthetic.main.signed_transaction.*
import kotlinx.android.synthetic.main.sweep.*


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
                .setNeutralButton(R.string.scan_qr, null)
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
        val tx = txFromHex(etTransaction.text.toString())
        updateStatusText(tvStatus, tx)
        dialog.getButton(AlertDialog.BUTTON_POSITIVE).isEnabled =
            canSign(tx) || canBroadcast(tx)
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
        val txHex = etTransaction.text.toString()
        val tx = txFromHex(txHex)

        try {
            if (canBroadcast(tx)) {
                showDialog(this, SignedTransactionDialog().apply { arguments = Bundle().apply {
                    putString("txHex", txHex)
                }})
                dismiss()
            } else {
                signLoadedTransaction(txHex)
            }
        } catch (e: ToastException) {
            e.show()
        }
    }

    private fun signLoadedTransaction(txHex: String) {
        val arguments = Bundle().apply {
            putString("txHex", txHex)
            putBoolean("unbroadcasted", true)
        }
        val dialog = SendDialog()
        showDialog(this, dialog.apply { setArguments(arguments) })
    }
}

private fun updateStatusText(idTxStatus: TextView, tx: PyObject) {
    try {
        val txInfo = daemonModel.wallet!!.callAttr("get_tx_info", tx)
        if (txInfo["amount"] == null && !canBroadcast(tx)) {
            idTxStatus.setText(R.string.transaction_unrelated)
        } else {
            idTxStatus.setText(txInfo["status"].toString())
        }
    } catch (e: PyException) {
        idTxStatus.setText(R.string.invalid)
    }
}


class SignedTransactionDialog : TaskLauncherDialog<Unit>() {
    private val tx: PyObject by lazy {
        txFromHex(arguments!!.getString("txHex")!!)
    }
    private lateinit var description: String

    override fun onBuildDialog(builder: AlertDialog.Builder) {
        builder.setView(R.layout.signed_transaction)
               .setNegativeButton(R.string.close, null)
               .setPositiveButton(R.string.send, null)
    }

    override fun onShowDialog() {
        super.onShowDialog()

        fabCopy.setOnClickListener {
            copyToClipboard(tx.toString(), R.string.transaction)
        }
        showQR(imgQR, baseEncode(tx.toString(), 43))
        updateStatusText(tvStatus, tx)

        if (!canBroadcast(tx)) {
            hideDescription(this)
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).isEnabled = false
        }
    }

    override fun onPreExecute() {
        description = etDescription.text.toString()
    }

    override fun doInBackground() {
        broadcastTransaction(daemonModel.wallet!!, tx, description)
    }

    override fun onPostExecute(result: Unit) {
        toast(R.string.payment_sent, Toast.LENGTH_SHORT)
    }
}

fun hideDescription(dialog: DialogFragment) {
    for (view in listOf(dialog.tvDescriptionLabel, dialog.etDescription)) {
        view.visibility = View.GONE
    }
}


class SweepDialog : TaskLauncherDialog<PyObject>() {
    lateinit var input: String

    init {
        dismissAfterExecute = false
    }

    override fun onBuildDialog(builder: AlertDialog.Builder) {
        builder.setTitle(R.string.sweep_private)
            .setView(R.layout.sweep)
            .setNeutralButton(R.string.scan_qr, null)
            .setNegativeButton(android.R.string.cancel, null)
            .setPositiveButton(android.R.string.ok, null)
    }

    override fun onShowDialog() {
        super.onShowDialog()
        dialog.getButton(AlertDialog.BUTTON_NEUTRAL).setOnClickListener { scanQR(this) }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        val result = IntentIntegrator.parseActivityResult(requestCode, resultCode, data)
        if (result != null && result.contents != null) {
            appendLine(etInput, result.contents)
        } else {
            super.onActivityResult(requestCode, resultCode, data)
        }
    }

    override fun onPreExecute() {
        input = etInput.text.toString()
    }

    override fun doInBackground(): PyObject {
        daemonModel.assertConnected()
        val privkeys = input.split(Regex("\\s+")).filter { !it.isEmpty() }.toTypedArray()
        try {
            return libWallet.callAttr("sweep_preparations", privkeys, daemonModel.network)
        } catch (e: PyException) {
            throw ToastException(e)
        }
    }

    override fun onPostExecute(result: PyObject) {
        // Convert objects to serializable form so we can pass them in an argument.
        val inputs = result.asList()[0]
        for (i in inputs.asList()) {
            val iMap = i.asMap()
            iMap[fromJava("address")] = fromJava(iMap[fromJava("address")].toString())
        }

        val wallet = daemonModel.wallet!!
        try {
            showDialog(this, SendDialog().setArguments {
                putString("address", wallet.callAttr("get_receiving_address").toString())
                putString("inputs", inputs.repr())
                putString("sweepKeypairs", result.asList()[1].repr())
            })
        } catch (e: ToastException) { e.show() }
    }
}


fun txFromHex(hex: String) =
    libTransaction.callAttr("Transaction", hex, Kwarg("sign_schnorr", signSchnorr()))!!

fun canSign(tx: PyObject): Boolean {
    return try {
        !tx.callAttr("is_complete").toBoolean() &&
        daemonModel.wallet!!.callAttr("can_sign", tx).toBoolean()
    } catch (e: PyException) {
        false
    }
}

fun canBroadcast(tx: PyObject): Boolean {
    return try {
        tx.callAttr("is_complete").toBoolean()
    } catch (e: PyException) {
        false
    }
}
