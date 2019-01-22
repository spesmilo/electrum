package org.electroncash.electroncash3

import android.arch.lifecycle.MutableLiveData
import android.arch.lifecycle.Observer
import android.arch.lifecycle.ViewModel
import android.arch.lifecycle.ViewModelProviders
import android.content.Intent
import android.os.Bundle
import android.support.v7.app.AlertDialog
import android.text.Editable
import android.text.TextWatcher
import android.widget.SeekBar
import com.chaquo.python.PyException
import com.chaquo.python.PyObject
import com.google.zxing.integration.android.IntentIntegrator
import kotlinx.android.synthetic.main.amount_box.*
import kotlinx.android.synthetic.main.send.*
import org.json.JSONException
import org.json.JSONObject


val MIN_FEE = 1
val MAX_FEE = 10


class SendDialog : AlertDialogFragment() {
    override fun onBuildDialog(builder: AlertDialog.Builder) {
        builder.setTitle(R.string.send)
            .setView(R.layout.send)
            .setNegativeButton(android.R.string.cancel, null)
            .setPositiveButton(android.R.string.ok, null)
            .setNeutralButton(R.string.scan_qr, null)
    }

    override fun onShowDialog(dialog: AlertDialog) {
        dialog.etAmount.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: Editable?) {
                if (!dialog.btnMax.isChecked) {  // Avoid infinite recursion.
                    updateUI()
                }
            }
        })
        dialog.tvUnit.setText(unitName)
        dialog.btnMax.setOnCheckedChangeListener { _, _ -> updateUI() }

        with (dialog.sbFee) {
            // setMin is not available until API level 26, so values are offset by MIN_FEE.
            progress = (daemonModel.config.callAttr("fee_per_kb").toInt() / 1000
                        - MIN_FEE)
            max = MAX_FEE - MIN_FEE
            setOnSeekBarChangeListener(object : SeekBar.OnSeekBarChangeListener {
                override fun onProgressChanged(seekBar: SeekBar, progress: Int, fromUser: Boolean) {
                    daemonModel.config.callAttr("set_key", "fee_per_kb", feeSpb * 1000)
                    updateUI()
                }
                override fun onStartTrackingTouch(seekBar: SeekBar) {}
                override fun onStopTrackingTouch(seekBar: SeekBar) {}
            })
        }
        fiatUpdate.observe(this, Observer { updateUI() })
        dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener { onOK() }
        dialog.getButton(AlertDialog.BUTTON_NEUTRAL).setOnClickListener { scanQR(this) }
    }

    fun updateUI() {
        var addrOrDummy: String
        try {
            daemonModel.makeAddress(address)
            addrOrDummy = address
        } catch (e: ToastException) {
            addrOrDummy = daemonModel.wallet!!.callAttr("dummy_address")
                            .callAttr("to_ui_string").toString()
        }

        var tx: PyObject? = null
        dialog.etAmount.isEnabled = !dialog.btnMax.isChecked
        if (dialog.btnMax.isChecked) {
            try {
                tx = daemonModel.makeTx(addrOrDummy, null, unsigned=true)
                dialog.etAmount.setText(formatSatoshis(tx.callAttr("output_value").toLong()))
            } catch (e: ToastException) {}
        }
        amountBoxUpdate(dialog)

        var feeLabel = getString(R.string.sat_byte, feeSpb)
        try {
            if (tx == null) {
                tx = daemonModel.makeTx(addrOrDummy, amountBoxGet(dialog), unsigned = true)
            }
            val fee = tx.callAttr("get_fee").toLong()
            feeLabel += " (${formatSatoshis(fee)} $unitName)"
        } catch (e: ToastException) {}
        dialog.tvFeeLabel.setText(feeLabel)
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        val result = IntentIntegrator.parseActivityResult(requestCode, resultCode, data)
        if (result != null && result.contents != null) {
            try {
                val parsed = libWeb.callAttr("parse_URI", result.contents)!!
                val address = parsed.callAttr("get", "address")
                if (address != null) {
                    dialog.etAddress.setText(address.toString())
                }
                val amount = parsed.callAttr("get", "amount")
                if (amount != null) {
                    dialog.etAmount.setText(formatSatoshis(amount.toLong()))
                }
            } catch (e: PyException) {
                dialog.etAddress.setText(result.contents)
            }
        } else {
            super.onActivityResult(requestCode, resultCode, data)
        }
    }

    fun onOK() {
        try {
            val amount = amountBoxGet(dialog)
            daemonModel.makeTx(address, amount, unsigned=true)
            showDialog(activity!!, SendPasswordDialog().apply { arguments = Bundle().apply {
                putString("address", address)
                putLong("amount", amount)
            }})
        } catch (e: ToastException) { e.show() }
        // Don't dismiss this dialog yet: the user might want to come back to it.
    }

    val address
        get() = dialog.etAddress.text.toString()

    val feeSpb
        get() = MIN_FEE + dialog.sbFee.progress
}


class SendPasswordDialog : PasswordDialog(runInBackground = true) {
    class Model : ViewModel() {
        val result = MutableLiveData<ServerError>()
    }
    private val model by lazy { ViewModelProviders.of(this).get(Model::class.java) }

    override fun onShowDialog(dialog: AlertDialog) {
        super.onShowDialog(dialog)
        model.result.observe(this, Observer { onResult(it) })
    }

    override fun onPassword(password: String) {
        val tx = daemonModel.makeTx(arguments!!.getString("address")!!,
                                    arguments!!.getLong("amount"), password)
        if (daemonModel.netStatus.value == null) {
            throw ToastException(R.string.not_connected)
        }
        val result = daemonModel.network.callAttr("broadcast_transaction", tx).asList()
        if (result.get(0).toBoolean()) {
            model.result.postValue(null)
        } else {
            val err = ServerError(result.get(1).toString())
            if (err.isClean) {
                throw ToastException(err.message)
            } else {
                model.result.postValue(err)
            }
        }
    }

    fun onResult(err: ServerError?) {
        dismissDialog(activity!!, SendDialog::class)
        if (err == null) {
            toast(R.string.payment_sent)
        } else {
            showDialog(activity!!, MessageDialog(
                getString(R.string.error),
                err.message + "\n\n" + getString(R.string.the_app)))
        }
    }
}

class ServerError(input: String) {
    var message: String = input

    // If isClean is true, the server rejected the transaction, so leave the dialog open and
    // give the user a chance to fix it. If isClean is false, we can't tell whether the
    // transaction went through or not, so close the dialog and show a warning.
    var isClean = false

    init {
        val reError = Regex("^error: (.*)")
        if (message.contains(reError)) {
            message = message.replace(reError, "$1")
            try {
                message = JSONObject(message).getString("message")
                isClean = true
                val reRules = Regex("^(the transaction was rejected by network rules).\n\n(.*)\n.*")
                if (message.contains(reRules)) {
                    // Remove the raw transaction dump (see electrumx/server/session.py).
                    message = message.replace(reRules, "$1: $2").capitalize()
                }
            } catch (e: JSONException) {}
        }
    }
}
