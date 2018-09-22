package org.electroncash.electroncash3

import android.os.Bundle
import android.support.v7.app.AlertDialog
import android.text.Editable
import android.text.TextWatcher
import android.view.View
import android.widget.SeekBar
import kotlinx.android.synthetic.main.send.*
import org.json.JSONException
import org.json.JSONObject


val MIN_FEE = 1
val MAX_FEE = 10


class SendDialog : AlertDialogFragment(), View.OnClickListener {
    override fun onBuildDialog(builder: AlertDialog.Builder) {
        builder.setTitle(R.string.send)
            .setView(R.layout.send)
            .setNegativeButton(android.R.string.cancel, null)
            .setPositiveButton(android.R.string.ok, null)
    }

    override fun onShowDialog(dialog: AlertDialog) {
        dialog.etAmount.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: Editable?) { showFee() }
        })
        dialog.tvUnit.setText(unitName)
        with (dialog.sbFee) {
            // setMin is not available until API level 26, so values are offset by MIN_FEE.
            progress = (daemonModel.config.callAttr("fee_per_kb").toJava(Int::class.java) / 1000
                        - MIN_FEE)
            max = MAX_FEE - MIN_FEE
            setOnSeekBarChangeListener(object : SeekBar.OnSeekBarChangeListener {
                override fun onProgressChanged(seekBar: SeekBar, progress: Int, fromUser: Boolean) {
                    daemonModel.config.callAttr("set_key", "fee_per_kb", feeSpb * 1000)
                    showFee()
                }
                override fun onStartTrackingTouch(seekBar: SeekBar) {}
                override fun onStopTrackingTouch(seekBar: SeekBar) {}
            })
        }
        showFee()
        dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(this)
    }

    fun showFee() {
        var label = "$feeSpb sat/byte"
        try {
            val fee = makeUnsignedTx().callAttr("get_fee").toJava(Long::class.java)
            label += " (${formatSatoshis(fee)} $unitName)"
        } catch (e: ToastException) {}
        dialog.tvFeeLabel.setText(label)
    }

    override fun onClick(v: View) {
        try {
            makeUnsignedTx()
            showDialog(activity!!, SendPasswordDialog().apply { arguments = Bundle().apply {
                putString("address", address)
                putLong("amount", amount)
            }})
        } catch (e: ToastException) { e.show() }
        // Don't dismiss this dialog yet: the user might want to come back to it.
    }

    fun makeUnsignedTx() = daemonModel.makeTx(address, amount, unsigned=true)

    val address
        get() = dialog.etAddress.text.toString()

    val amount: Long
        get() {
            val amountStr = dialog.etAmount.text.toString()
            if (amountStr.isEmpty()) throw ToastException(R.string.enter_amount)
            val amount = toSatoshis(amountStr) ?: throw ToastException(R.string.invalid_amount)
            return amount
        }

    val feeSpb
        get() = MIN_FEE + dialog.sbFee.progress
}


class SendPasswordDialog : PasswordDialog() {
    override fun onPassword(password: String?) {
        val tx = daemonModel.makeTx(arguments!!.getString("address")!!,
                                    arguments!!.getLong("amount"), password)
        if (daemonModel.netStatus.value == null) {
            throw ToastException(getString(R.string.offline) + "\n" +
                                 getString(R.string.cannot_send))
        }
        val result = daemonModel.network.callAttr("broadcast_transaction", tx)
        if (result.callAttr("__getitem__", 0).toJava(Boolean::class.java)) {
            toast(R.string.payment_sent)
        } else {
            val err = ServerError(result.callAttr("__getitem__", 1).toString())
            if (err.isClean) {
                throw ToastException(err.message)
            } else {
                // We can't tell whether the transaction went through or not, so close all
                // dialogs and show a warning.
                showDialog(activity!!, MessageDialog(
                    getString(R.string.error),
                    err.message + "\n\n" + getString(R.string.the_app)))
            }
        }
        dismissDialog(activity!!, "SendDialog")
    }
}

class ServerError(input: String) {
    var message: String = input
    var isClean = false

    init {
        val reError = Regex("^error: (.*)")
        if (message.contains(reError)) {
            message = message.replace(reError, "$1")
            try {
                message = JSONObject(message).getString("message")
                isClean = true  // Server rejected the transaction.
                val reRules = Regex("^(the transaction was rejected by network rules).\n\n(.*)\n.*")
                if (message.contains(reRules)) {
                    // Remove the raw transaction dump (see electrumx/server/session.py).
                    message = message.replace(reRules, "$1: $2").capitalize()
                }
            } catch (e: JSONException) {}
        }
    }
}
