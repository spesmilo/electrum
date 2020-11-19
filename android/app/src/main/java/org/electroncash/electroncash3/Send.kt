package org.electroncash.electroncash3

import android.content.Intent
import android.os.Bundle
import android.view.Menu
import android.view.MenuItem
import android.widget.SeekBar
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.fragment.app.viewModels
import androidx.lifecycle.ViewModel
import com.chaquo.python.Kwarg
import com.chaquo.python.PyException
import com.chaquo.python.PyObject
import com.google.zxing.integration.android.IntentIntegrator
import kotlinx.android.synthetic.main.send.*
import kotlin.properties.Delegates.notNull


val libPaymentRequest by lazy { libMod("paymentrequest") }

val MIN_FEE = 1  // sat/byte


class SendDialog : AlertDialogFragment() {
    class Model : ViewModel() {
        var paymentRequest: PyObject? = null
    }
    val model: Model by viewModels()

    val unbroadcasted by lazy {
        arguments?.getBoolean("unbroadcasted", false) ?: false
    }
    lateinit var amountBox: AmountBox
    var settingMax = false  // Prevent infinite recursion.

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
        if (!unbroadcasted) {
            builder.setTitle(R.string.send)
                .setPositiveButton(R.string.send, null)
        } else {
            builder.setTitle(R.string.sign_transaction)
                .setPositiveButton(R.string.sign, null)
        }
        builder.setView(R.layout.send)
            .setNegativeButton(android.R.string.cancel, null)
            .setNeutralButton(R.string.qr_code, null)
    }

    override fun onShowDialog() {
        amountBox = AmountBox(dialog)
        amountBox.listener = {
            if (!settingMax) {
                btnMax.isChecked = false
                updateUI()
            }
        }
        setPaymentRequest(model.paymentRequest)
        btnMax.setOnCheckedChangeListener { _, _ -> updateUI() }

        with (sbFee) {
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
        dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener { onOK() }
        dialog.getButton(AlertDialog.BUTTON_NEUTRAL).setOnClickListener { scanQR(this) }
        updateUI()
    }

    override fun onFirstShowDialog() {
        if (arguments != null) {
            val address = arguments!!.getString("address")
            if (address != null) {
                etAddress.setText(address)
                amountBox.requestFocus()
            }
        }
    }

    fun updateUI() {
        val feeSpb = MIN_FEE + sbFee.progress
        daemonModel.config.callAttr("set_key", "fee_per_kb", feeSpb * 1000)
        val tx: PyObject? = try {
            // If the user hasn't entered a valid address, use a dummy address in case we need
            // to calculate the max amount.
            makeUnsignedTransaction(allowDummy = true)
        } catch (e: ToastException) { null }

        if (btnMax.isChecked && tx != null) {
            try {
                settingMax = true
                amountBox.amount = tx.callAttr("output_value").toLong()
            } finally {
                settingMax = false
            }
        }

        var feeLabel = getString(R.string.sat_byte, feeSpb)
        if (tx != null) {
            val fee = tx.callAttr("get_fee").toLong()
            feeLabel += " (${ltr(formatSatoshisAndUnit(fee))})"
        }
        tvFeeLabel.setText(feeLabel)
    }

    fun makeUnsignedTransaction(allowDummy: Boolean = false): PyObject {
        val outputs: PyObject
        val pr = model.paymentRequest
        if (pr != null) {
            outputs = pr.callAttr("get_outputs")
        } else {
            val addr = try {
                makeAddress(etAddress.text.toString())
            } catch (e: ToastException) {
                if (allowDummy) daemonModel.wallet!!.callAttr("dummy_address")
                else throw e
            }
            val output = py.builtins.callAttr(
                "tuple", arrayOf(libBitcoin.get("TYPE_ADDRESS"), addr,
                                 if (btnMax.isChecked) "!" else amountBox.amount))
            outputs = py.builtins.callAttr("list", arrayOf(output))
        }

        val wallet = daemonModel.wallet!!
        val inputs = wallet.callAttr("get_spendable_coins", null, daemonModel.config,
                                     Kwarg("isInvoice", pr != null))
        try {
            return wallet.callAttr("make_unsigned_transaction", inputs, outputs,
                                   daemonModel.config, Kwarg("sign_schnorr", true))
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
                showDialog(this, GetPaymentRequestDialog(r.toString()))
            } else {
                setPaymentRequest(null)
                etAddress.setText(parsed.callAttr("get", "address")?.toString() ?: "")
                etDescription.setText(parsed.callAttr("get", "message")?.toString() ?: "")

                val amount = parsed.callAttr("get", "amount")?.toLong()
                if (amount != null) {
                    amountBox.amount = amount
                } else {
                    amountBox.clear()
                }
                amountBox.requestFocus()
                btnMax.isChecked = false
            }
        } catch (e: ToastException) {
            e.show()
        }
    }

    fun setPaymentRequest(pr: PyObject?) {
        model.paymentRequest = pr
        for (et in listOf(etAddress, etDescription)) {
            setEditable(et, (pr == null))
        }
        amountBox.isEditable = (pr == null)
        btnMax.isEnabled = (pr == null)

        if (pr != null) {
            etAddress.setText(pr.callAttr("get_requestor").toString())
            amountBox.amount = pr.callAttr("get_amount").toLong()
            btnMax.isChecked = false
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
    }

    fun onOK() {
        try {
            makeUnsignedTransaction()  // Validate input before asking for password.
            showDialog(this, SendPasswordDialog())
        } catch (e: ToastException) { e.show() }
        // Don't dismiss this dialog yet: the user might want to come back to it.
    }
}


class GetPaymentRequestDialog() : TaskDialog<PyObject>() {
    constructor(url: String) : this() {
        arguments = Bundle().apply { putString("url", url) }
    }

    override fun doInBackground(): PyObject {
        val pr = libPaymentRequest.callAttr("get_payment_request",
                                            arguments!!.getString("url")!!)!!
        if (!pr.callAttr("verify", daemonModel.wallet!!.get("contacts")!!).toBoolean()) {
            throw ToastException(pr.get("error").toString())
        }
        checkExpired(pr)
        return pr
    }

    override fun onPostExecute(result: PyObject) {
        (targetFragment as SendDialog).setPaymentRequest(result)
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

    override fun onShowDialog() {
        if (contacts.isEmpty()) {
            toast(R.string.you_dont_have_any_contacts)
            dismiss()
        }
    }

    override fun onMenuItemSelected(item: MenuItem) {
        val address = contacts.get(item.itemId).addr.callAttr("to_ui_string").toString()
        with (findDialog(activity!!, SendDialog::class)!!) {
            etAddress.setText(address)
            amountBox.requestFocus()
        }
    }
}


class SendPasswordDialog : PasswordDialog<Unit>() {
    val sendDialog by lazy { targetFragment as SendDialog }
    class Model : ViewModel() {
        var tx: PyObject by notNull()
        var description: String by notNull()
    }
    private val model: Model by viewModels()

    // We used to do this in onPreExecute, but it seems we can't rely on the SendDialog views
    // still existing by that time (#1701). I can't reproduce this, but my best guess is that
    // the screen was covered by a full-screen input method after a rotation or an app switch,
    // and the views below weren't re-created until they became visible.
    override fun onFirstShowDialog() {
        model.tx = sendDialog.makeUnsignedTransaction()
        model.description = sendDialog.etDescription.text.toString()
    }

    override fun onPassword(password: String) {
        val wallet = daemonModel.wallet!!
        wallet.callAttr("sign_transaction", model.tx, password)
        if (!sendDialog.unbroadcasted) {
            if (!daemonModel.isConnected()) {
                throw ToastException(R.string.not_connected)
            }
            val pr = sendDialog.model.paymentRequest
            val result = if (pr != null) {
                checkExpired(pr)
                val refundAddr = wallet.callAttr("get_receiving_addresses").asList().get(0)
                pr.callAttr("send_payment", model.tx.toString(), refundAddr)
            } else {
                daemonModel.network.callAttr("broadcast_transaction", model.tx)
            }
            checkBroadcastResult(result)
            setDescription(model.tx.callAttr("txid").toString(), model.description)
        }
    }

    override fun onPostExecute(result: Unit) {
        sendDialog.dismiss()
        if (!sendDialog.unbroadcasted) {
            toast(R.string.payment_sent, Toast.LENGTH_SHORT)
        } else {
            copyToClipboard(model.tx.toString(), R.string.signed_transaction)
        }
    }
}


private fun checkExpired(pr: PyObject) {
    if (pr.callAttr("has_expired").toBoolean()) {
        throw ToastException(R.string.payment_request_has)
    }
}


fun checkBroadcastResult(result: PyObject) {
    val success = result.asList().get(0).toBoolean()
    if (!success) {
        var message = result.asList().get(1).toString()
        message = message.replace(Regex("^error: (.*)"), "$1")
        throw ToastException(message)
    }
}
