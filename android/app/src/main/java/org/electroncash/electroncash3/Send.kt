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
import android.view.Menu
import android.view.MenuItem
import android.widget.SeekBar
import android.widget.Toast
import com.chaquo.python.Kwarg
import com.chaquo.python.PyException
import com.chaquo.python.PyObject
import com.google.zxing.integration.android.IntentIntegrator
import kotlinx.android.synthetic.main.amount_box.*
import kotlinx.android.synthetic.main.send.*


val libPaymentRequest by lazy { libMod("paymentrequest") }

val MIN_FEE = 1  // sat/byte


class SendDialog : AlertDialogFragment() {
    class Model : ViewModel() {
        var paymentRequest: PyObject? = null
    }
    val model by lazy { ViewModelProviders.of(this).get(Model::class.java) }

    init {
        if (daemonModel.wallet!!.callAttr("is_watching_only").toBoolean()) {
            throw ToastException(R.string.this_wallet_is)
        } else if (daemonModel.wallet!!.callAttr("get_receiving_addresses")
                   .asList().isEmpty()) {
            // At least one receiving address is needed to call wallet.dummy_address.
            throw ToastException(
                R.string.electron_cash_is_generating_your_addresses__please_wait_)
        }
    }

    override fun onBuildDialog(builder: AlertDialog.Builder) {
        builder.setTitle(R.string.send)
            .setView(R.layout.send)
            .setNegativeButton(android.R.string.cancel, null)
            .setPositiveButton(android.R.string.ok, null)
            .setNeutralButton(R.string.qr_code, null)
    }

    override fun onShowDialog(dialog: AlertDialog) {
        if (arguments != null) {
            val address = arguments!!.getString("address")
            if (address != null) {
                dialog.etAddress.setText(address)
                dialog.etAmount.requestFocus()
            }
            val uri = arguments!!.getString("uri")
            if (uri != null) {
                onUri(uri)
            }
            arguments = null
        }
        setPaymentRequest(model.paymentRequest)

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
            progress = (daemonModel.config.callAttr("fee_per_kb").toInt() / 1000) - MIN_FEE
            max = (daemonModel.config.callAttr("max_fee_rate").toInt() / 1000) - MIN_FEE
            setOnSeekBarChangeListener(object : SeekBar.OnSeekBarChangeListener {
                override fun onProgressChanged(seekBar: SeekBar, progress: Int,
                                               fromUser: Boolean) {
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
        val feeSpb = MIN_FEE + dialog.sbFee.progress
        daemonModel.config.callAttr("set_key", "fee_per_kb", feeSpb * 1000)
        val tx: PyObject? = try {
            // If the user hasn't entered a valid address, use a dummy address in case we need
            // to calculate the max amount.
            makeUnsignedTransaction(allowDummy = true)
        } catch (e: ToastException) { null }

        dialog.etAmount.isEnabled = !dialog.btnMax.isChecked
        if (dialog.btnMax.isChecked && tx != null) {
            dialog.etAmount.setText(formatSatoshis(tx.callAttr("output_value").toLong()))
        }
        amountBoxUpdate(dialog)

        var feeLabel = getString(R.string.sat_byte, feeSpb)
        if (tx != null) {
            val fee = tx.callAttr("get_fee").toLong()
            feeLabel += " (${formatSatoshisAndUnit(fee)})"
        }
        dialog.tvFeeLabel.setText(feeLabel)
    }

    fun makeUnsignedTransaction(allowDummy: Boolean = false): PyObject {
        val outputs: PyObject
        val pr = model.paymentRequest
        if (pr != null) {
            outputs = pr.callAttr("get_outputs")
        } else {
            val addr = try {
                makeAddress(dialog.etAddress.text.toString())
            } catch (e: ToastException) {
                if (allowDummy) daemonModel.wallet!!.callAttr("dummy_address")
                else throw e
            }
            val output = py.builtins.callAttr(
                "tuple", arrayOf(libBitcoin.get("TYPE_ADDRESS"), addr,
                                 if (dialog.btnMax.isChecked) "!" else amountBoxGet(dialog)))
            outputs = py.builtins.callAttr("list", arrayOf(output))
        }

        val wallet = daemonModel.wallet!!
        val inputs = wallet.callAttr("get_spendable_coins", null, daemonModel.config,
                                     Kwarg("isInvoice", pr != null))
        try {
            return wallet.callAttr("make_unsigned_transaction", inputs, outputs,
                                   daemonModel.config)
        } catch (e: PyException) {
            throw if (e.message!!.startsWith("NotEnoughFunds"))
                ToastException(R.string.insufficient_funds) else e
        }
    }

    // Receives the result of a QR scan.
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        val result = IntentIntegrator.parseActivityResult(requestCode, resultCode, data)
        if (result != null && result.contents != null) {
            onUri(result.contents)
        } else {
            super.onActivityResult(requestCode, resultCode, data)
        }
    }

    fun onUri(uri: String) {
        try {
            val parsed: PyObject
            try {
                parsed = libWeb.callAttr("parse_URI", uri)!!
            } catch (e: PyException) {
                throw ToastException(e)
            }

            val r = parsed.callAttr("get", "r")
            if (r != null) {
                showDialog(activity!!, GetPaymentRequestDialog(this, r.toString()))
            } else {
                setPaymentRequest(null)
                dialog.etAddress.setText(parsed.callAttr("get", "address")?.toString() ?: "")
                val amount = parsed.callAttr("get", "amount")?.toLong()
                dialog.etAmount.setText(if (amount != null) formatSatoshis(amount) else "")
                dialog.btnMax.isChecked = false
                dialog.etDescription.setText(parsed.callAttr("get", "message")?.toString()
                                             ?: "")
            }
        } catch (e: ToastException) {
            e.show()
        }
    }

    fun setPaymentRequest(pr: PyObject?) {
        model.paymentRequest = pr
        with (dialog) {
            for (et in listOf(etAddress, etAmount, etDescription)) {
                if (pr == null) {
                    et.setFocusableInTouchMode(true)  // setFocusable(true) isn't good enough.
                } else {
                    et.setFocusable(false)
                }
            }
            if (pr != null) {
                etAddress.setText(pr.callAttr("get_requestor").toString())
                etAmount.setText(formatSatoshis(pr.callAttr("get_amount").toLong()))
                etDescription.setText(pr.callAttr("get_memo").toString())
            }

            btnContacts.setImageResource(if (pr == null) R.drawable.ic_person_24dp
                                         else R.drawable.ic_check_24dp)
            btnContacts.setOnClickListener {
                if (pr == null) {
                    showDialog(activity!!, SendContactsDialog())
                } else {
                    toast(pr.callAttr("get_verify_status").toString())
                }
            }
            btnMax.setEnabled(pr == null)
        }
    }

    fun onOK() {
        try {
            makeUnsignedTransaction()  // Validate input before asking for password.
            showDialog(activity!!, SendPasswordDialog(this))
        } catch (e: ToastException) { e.show() }
        // Don't dismiss this dialog yet: the user might want to come back to it.
    }
}


class GetPaymentRequestDialog() : ProgressDialogTask<PyObject?>() {
    constructor(sendDialog: SendDialog, url: String) : this() {
        setTargetFragment(sendDialog, 0)
        arguments = Bundle().apply { putString("url", url) }
    }

    override fun doInBackground(): PyObject? {
        val pr = libPaymentRequest.callAttr("get_payment_request",
                                            arguments!!.getString("url")!!)
        try {
            if (!pr.callAttr("verify", daemonModel.wallet!!.get("contacts")!!).toBoolean()) {
                throw ToastException(pr.get("error").toString())
            }
            checkExpired(pr)
            return pr
        } catch (e: ToastException) {
            e.show()
            return null
        }
    }

    override fun onPostExecute(result: PyObject?) {
        if (result != null) {
            (targetFragment as SendDialog).setPaymentRequest(result)
        }
    }
}


class SendContactsDialog : MenuDialog() {
    val contacts = listContacts()

    override fun onBuildDialog(builder: AlertDialog.Builder, menu: Menu) {
        builder.setTitle(R.string.contacts)
        contacts.forEachIndexed { i, contact ->
            menu.add(Menu.NONE, i, Menu.NONE, contact.name)
        }
    }

    override fun onShowDialog(dialog: AlertDialog) {
        if (contacts.isEmpty()) {
            toast(R.string.you_dont_have_any_contacts)
            dismiss()
        }
    }

    override fun onMenuItemSelected(item: MenuItem) {
        val address = contacts.get(item.itemId).addr.callAttr("to_ui_string").toString()
        with (findDialog(activity!!, SendDialog::class)!!) {
            dialog.etAddress.setText(address)
            dialog.etAmount.requestFocus()
        }
    }
}


class SendPasswordDialog() : PasswordDialog(runInBackground = true) {
    constructor(sendDialog: SendDialog) : this(){
        setTargetFragment(sendDialog, 0)
    }
    val sendDialog by lazy { super.getTargetFragment() as SendDialog }
    val tx by lazy { sendDialog.makeUnsignedTransaction() }

    class Model : ViewModel() {
        val result = MutableLiveData<List<PyObject>>()
    }
    private val model by lazy { ViewModelProviders.of(this).get(Model::class.java) }

    override fun onShowDialog(dialog: AlertDialog) {
        super.onShowDialog(dialog)
        model.result.observe(this, Observer { onResult(it!!) })
    }

    override fun onPassword(password: String) {
        val wallet = daemonModel.wallet!!
        wallet.callAttr("sign_transaction", tx, password)
        if (! daemonModel.isConnected()) {
            throw ToastException(R.string.not_connected)
        }
        val pr = sendDialog.model.paymentRequest
        val result = if (pr != null) {
            checkExpired(pr)
            val refundAddr = wallet.callAttr("get_receiving_addresses").asList().get(0)
            pr.callAttr("send_payment", tx.toString(), refundAddr)
        } else {
            daemonModel.network.callAttr("broadcast_transaction", tx)
        }
        model.result.postValue(result.asList())
    }

    fun onResult(result: List<PyObject>) {
        val success = result.get(0).toBoolean()
        if (success) {
            sendDialog.dismiss()
            toast(R.string.payment_sent, Toast.LENGTH_SHORT)
            setDescription(tx.callAttr("txid").toString(),
                           sendDialog.dialog.etDescription.text.toString())
            transactionsUpdate.setValue(Unit)
        } else {
            var message = result.get(1).toString()
            val reError = Regex("^error: (.*)")
            if (message.contains(reError)) {
                message = message.replace(reError, "$1")
            }
            toast(message)
        }
    }
}


private fun checkExpired(pr: PyObject) {
    if (pr.callAttr("has_expired").toBoolean()) {
        throw ToastException(R.string.payment_request_has)
    }
}
