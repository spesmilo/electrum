package org.electroncash.electroncash3

import android.os.Bundle
import android.view.View
import androidx.appcompat.app.AlertDialog
import com.chaquo.python.Kwarg
import com.chaquo.python.PyObject
import kotlinx.android.synthetic.main.main.*
import kotlinx.android.synthetic.main.request_detail.*
import kotlinx.android.synthetic.main.requests.*


class RequestsFragment : ListFragment(R.layout.requests, R.id.rvRequests) {

    override fun onListModelCreated(listModel: ListModel) {
        with (listModel) {
            trigger.addSource(daemonUpdate)
            trigger.addSource(settings.getString("base_unit"))
            data.function = { wallet.callAttr("get_sorted_requests", daemonModel.config)!! }
        }
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        btnAdd.setOnClickListener { showDialog(this, NewRequestDialog()) }
    }

    override fun onCreateAdapter() =
        ListAdapter(this, R.layout.request_list, ::RequestModel, ::RequestDialog)
}


class NewRequestDialog : TaskDialog<PyObject>() {
    val listFragment by lazy { targetFragment as ListFragment }

    override fun doInBackground(): PyObject {
        if (listFragment.wallet.callAttr("is_watching_only").toBoolean()) {
            throw ToastException(R.string.this_wallet_is)
        }
        return listFragment.wallet.callAttr("get_unused_address")
               ?: throw ToastException(R.string.no_more)
    }

    override fun onPostExecute(result: PyObject) {
        showDialog(listFragment, RequestDialog().apply { arguments = Bundle().apply {
           putString("address", result.callAttr("to_storage_string").toString())
        }})
    }
}


class RequestModel(wallet: PyObject, val request: PyObject) : ListItemModel(wallet) {
    val address by lazy { getField("address").toString() }
    val amount = getField("amount").toLong()
    val timestamp = formatTime(getField("time").toLong())
    val description = getField("memo").toString()
    val status = (app.resources.getStringArray(R.array.payment_status)
                  [getField("status").toInt()])!!

    private fun getField(key: String): PyObject {
        return request.callAttr("get", key)!!
    }

    override val dialogArguments by lazy {
        Bundle().apply { putString("address", address) }
    }
}


class RequestDialog : DetailDialog() {
    val address by lazy {
        clsAddress.callAttr("from_string", arguments!!.getString("address"))!!
    }
    val existingRequest: PyObject? by lazy {
        wallet.callAttr("get_payment_request", address, daemonModel.config)
    }
    lateinit var amountBox: AmountBox

    override fun onBuildDialog(builder: AlertDialog.Builder) {
        with (builder) {
            setView(R.layout.request_detail)
            setNegativeButton(android.R.string.cancel, null)
            setPositiveButton(android.R.string.ok, null)
            if (existingRequest != null) {
                setNeutralButton(R.string.delete, null)
            }
        }
    }

    override fun onShowDialog() {
        amountBox = AmountBox(dialog)
        amountBox.listener = { updateUI() }

        btnCopy.setOnClickListener {
            copyToClipboard(getUri(), R.string.request_uri)
        }
        tvAddress.text = address.callAttr("to_ui_string").toString()

        etDescription.addAfterTextChangedListener { updateUI() }
        dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener { onOK() }

        if (existingRequest != null) {
            dialog.getButton(AlertDialog.BUTTON_NEUTRAL).setOnClickListener {
                showDialog(this, RequestDeleteDialog(address))
            }
        }
        updateUI()
    }

    override fun onFirstShowDialog() {
        val request = existingRequest
        if (request != null) {
            val model = RequestModel(wallet, request)
            amountBox.amount = model.amount
            etDescription.setText(model.description)
        } else {
            amountBox.requestFocus()
        }
    }

    private fun updateUI() {
        showQR(imgQR, getUri())
    }

    private fun getUri(): String {
        return libWeb.callAttr("create_URI", address, amountBox.amount, description).toString()
    }

    private fun onOK() {
        val amount = amountBox.amount
        if (amount == null) {
            toast(R.string.Invalid_amount)
        } else {
            wallet.callAttr(
                "add_payment_request",
                wallet.callAttr("make_payment_request", address, amount, description),
                daemonModel.config, Kwarg("save", false))
            saveRequests(wallet)
            dismiss()

            // If the dialog was opened from the Transactions screen, we should now switch to
            // the Requests screen so the user can verify that the request has been saved.
            (activity as MainActivity).navBottom.selectedItemId = R.id.navRequests
        }
    }

    val description
        get() = etDescription.text.toString()
}


class RequestDeleteDialog() : AlertDialogFragment() {
    constructor(addr: PyObject) : this() {
        arguments = Bundle().apply {
            putString("address", addr.callAttr("to_storage_string").toString())
        }
    }

    override fun onBuildDialog(builder: AlertDialog.Builder) {
        val requestDialog = targetFragment as RequestDialog
        val wallet = requestDialog.wallet
        builder.setTitle(R.string.confirm_delete)
            .setMessage(R.string.are_you_sure_you_wish_to_proceed)
            .setPositiveButton(R.string.delete) { _, _ ->
                wallet.callAttr("remove_payment_request",
                                makeAddress(arguments!!.getString("address")!!),
                                daemonModel.config, Kwarg("save", false))
                saveRequests(wallet)
                requestDialog.dismiss()
            }
            .setNegativeButton(android.R.string.cancel, null)
    }
}


fun saveRequests(wallet: PyObject) {
    saveWallet(wallet) {
        wallet.callAttr("save_payment_requests", Kwarg("write", false))
    }
    daemonUpdate.setValue(Unit)
}