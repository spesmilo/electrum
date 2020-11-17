package org.electroncash.electroncash3

import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.view.View
import androidx.appcompat.app.AlertDialog
import androidx.fragment.app.Fragment
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.observe
import com.chaquo.python.PyObject
import kotlinx.android.synthetic.main.main.*
import kotlinx.android.synthetic.main.request_detail.*
import kotlinx.android.synthetic.main.requests.*


class RequestsFragment : Fragment(R.layout.requests), MainFragment {
    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        setupVerticalList(rvRequests)
        rvRequests.adapter = RequestsAdapter(activity!!)
        TriggerLiveData().apply {
            addSource(daemonUpdate)
            addSource(settings.getString("base_unit"))
        }.observe(viewLifecycleOwner, { refresh() })

        btnAdd.setOnClickListener { newRequest(activity!!) }
    }

    fun refresh() {
        val wallet = daemonModel.wallet
        (rvRequests.adapter as RequestsAdapter).submitList(
            if (wallet == null) null else RequestsList(wallet))
    }
}


fun newRequest(activity: FragmentActivity) {
    try {
        val address = daemonModel.wallet!!.callAttr("get_unused_address")
                      ?: throw ToastException(R.string.no_more)
        showDialog(activity, RequestDialog(address.callAttr("to_storage_string").toString()))
    } catch (e: ToastException) { e.show() }
}


class RequestsList(wallet: PyObject) : AbstractList<RequestModel>() {
    val requests = wallet.callAttr("get_sorted_requests", daemonModel.config).asList()

    override val size: Int
        get() = requests.size

    override fun get(index: Int) =
        RequestModel(requests.get(index))
}


class RequestsAdapter(val activity: FragmentActivity)
    : BoundAdapter<RequestModel>(R.layout.request_list) {

    override fun onBindViewHolder(holder: BoundViewHolder<RequestModel>, position: Int) {
        super.onBindViewHolder(holder, position)
        holder.itemView.setOnClickListener {
            showDialog(activity, RequestDialog(holder.item.address))
        }
    }
}

class RequestModel(val request: PyObject) {
    val address = getField("address").toString()
    val amount = getField("amount").toLong()
    val timestamp = libUtil.callAttr("format_time", getField("time")).toString()
    val description = getField("memo").toString()
    val status = (app.resources.getStringArray(R.array.payment_status)
                  [getField("status").toInt()])

    private fun getField(key: String): PyObject {
        return request.callAttr("get", key)!!
    }
}



class RequestDialog() : AlertDialogFragment() {
    val wallet by lazy { daemonModel.wallet!! }

    init {
        if (wallet.callAttr("is_watching_only").toBoolean()) {
            throw ToastException(R.string.this_wallet_is)
        }
    }

    val address by lazy {
        clsAddress.callAttr("from_string", arguments!!.getString("address"))
    }
    val existingRequest by lazy {
        wallet.callAttr("get_payment_request", address, daemonModel.config)
    }
    lateinit var amountBox: AmountBox

    constructor(address: String): this() {
        arguments = Bundle().apply { putString("address", address) }
    }

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

        etDescription.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: Editable?) { updateUI() }
        })
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
            val model = RequestModel(request)
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
        val amount = try {
            amountBox.amount
        } catch (e: ToastException) { null }
        return libWeb.callAttr("create_URI", address, amount, description).toString()
    }

    private fun onOK() {
        try {
            wallet.callAttr(
                "add_payment_request",
                wallet.callAttr("make_payment_request", address, amountBox.amount, description),
                daemonModel.config)
        } catch (e: ToastException) { e.show() }

        daemonUpdate.setValue(Unit)
        dismiss()

        // If the dialog was opened from the Transactions screen, we should now switch to
        // the Requests screen so the user can verify that the request has been saved.
        (activity as MainActivity).navBottom.selectedItemId = R.id.navRequests
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
        builder.setTitle(R.string.confirm_delete)
            .setMessage(R.string.are_you_sure_you_wish_to_proceed)
            .setPositiveButton(R.string.delete) { _, _ ->
                daemonModel.wallet!!.callAttr("remove_payment_request",
                                              makeAddress(arguments!!.getString("address")!!),
                                              daemonModel.config)
                daemonUpdate.setValue(Unit)
                (targetFragment as RequestDialog).dismiss()
            }
            .setNegativeButton(android.R.string.cancel, null)
    }
}
