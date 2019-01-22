package org.electroncash.electroncash3

import android.arch.lifecycle.MediatorLiveData
import android.arch.lifecycle.MutableLiveData
import android.arch.lifecycle.Observer
import android.os.Bundle
import android.support.v4.app.Fragment
import android.support.v4.app.FragmentActivity
import android.support.v7.app.AlertDialog
import android.text.Editable
import android.text.TextWatcher
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import com.chaquo.python.Kwarg
import com.chaquo.python.PyObject
import kotlinx.android.synthetic.main.amount_box.*
import kotlinx.android.synthetic.main.request_detail.*
import kotlinx.android.synthetic.main.requests.*


val requestsUpdate = MediatorLiveData<Unit>().apply { value = Unit }


class RequestsFragment : Fragment(), MainFragment {
    override val title = MutableLiveData<String>().apply {
        value = app.getString(R.string.requests)
    }
    override val subtitle = MutableLiveData<String>()

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?,
                              savedInstanceState: Bundle?): View? {
        return inflater.inflate(R.layout.requests, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        setupVerticalList(rvRequests)
        val wallet = daemonModel.wallet
        val observer = Observer<Unit> {
            if (wallet == null) {
                subtitle.value = getString(R.string.no_wallet)
                rvRequests.adapter = null
                btnAdd.hide()
            } else {
                subtitle.value = null
                rvRequests.adapter = RequestsAdapter(
                    activity!!,
                    wallet.callAttr("get_sorted_requests", daemonModel.config).asList())
                btnAdd.show()
            }
        }
        daemonUpdate.observe(viewLifecycleOwner, observer)
        requestsUpdate.observe(viewLifecycleOwner, observer)

        btnAdd.setOnClickListener {
            if (daemonModel.wallet!!.callAttr("is_watching_only").toBoolean()) {
                toast(R.string.this_wallet_is_watching_only_)
            } else {
                val address = wallet!!.callAttr("get_unused_address")
                if (address == null) {
                    toast(R.string.no_more, Toast.LENGTH_LONG)
                } else {
                    showDialog(activity!!,
                               RequestDialog(address.callAttr("to_ui_string").toString()))
                }
            }
        }
    }
}


class RequestsAdapter(val activity: FragmentActivity, val requests: List<PyObject>)
    : BoundAdapter<RequestModel>(R.layout.request_list) {

    override fun getItemCount(): Int {
        return requests.size
    }

    override fun getItem(position: Int): RequestModel {
        return RequestModel(requests.get(position))
    }

    override fun onBindViewHolder(holder: BoundViewHolder<RequestModel>, position: Int) {
        super.onBindViewHolder(holder, position)
        holder.itemView.setOnClickListener {
            showDialog(activity, RequestDialog(holder.item.address))
        }
    }
}

class RequestModel(val request: PyObject) {
    val address = getField("address").toString()
    val amount = formatSatoshis(getField("amount").toLong())
    val timestamp = libUtil.callAttr("format_time", getField("time")).toString()
    val description = getField("memo").toString()
    val status = formatStatus(getField("status").toInt())

    private fun formatStatus(status: Int): Any {
        return app.resources.getStringArray(R.array.payment_status)[status]
    }

    private fun getField(key: String): PyObject {
        return request.callAttr("get", key)!!
    }
}



class RequestDialog() : AlertDialogFragment() {
    var savedInstanceState: Bundle? = null
    val wallet by lazy { daemonModel.wallet!! }
    val address by lazy {
        clsAddress.callAttr("from_string", arguments!!.getString("address"))
    }
    val existingRequest by lazy {
        wallet.callAttr("get_payment_request", address, daemonModel.config)
    }

    constructor(address: String): this() {
        arguments = Bundle().apply { putString("address", address) }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        this.savedInstanceState = savedInstanceState
    }

    override fun onBuildDialog(builder: AlertDialog.Builder) {
        with (builder) {
            setView(R.layout.request_detail)
            setNegativeButton(android.R.string.cancel, null)
            setPositiveButton(android.R.string.ok, null)
            if (existingRequest != null) {
                setNeutralButton(R.string.delete, { _, _ -> onDelete() })
            }
        }
    }

    override fun onShowDialog(dialog: AlertDialog) {
        dialog.btnCopy.setOnClickListener { copyToClipboard(getUri()) }
        dialog.tvAddress.text = address.callAttr("to_ui_string").toString()
        dialog.tvUnit.text = unitName

        val tw = object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: Editable?) { updateUI() }
        }
        for (et in listOf(dialog.etAmount, dialog.etDescription)) {
            et.addTextChangedListener(tw)
        }
        fiatUpdate.observe(this, Observer { updateUI() })
        dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener { onOK() }

        if (existingRequest != null && savedInstanceState == null) {
            val model = RequestModel(existingRequest)
            dialog.etAmount.setText(model.amount)
            dialog.etDescription.setText(model.description)
        }
    }

    private fun updateUI() {
        showQR(dialog.imgQR, getUri())
        amountBoxUpdate(dialog)
    }

    private fun getUri(): String {
        var amount: Long? = null
        try {
            amount = amountBoxGet(dialog)
        } catch (e: ToastException) {}
        return libWeb.callAttr("create_URI", address, amount, description).toString()
    }

    private fun onOK() {
        try {
            val amount = amountBoxGet(dialog)
            wallet.callAttr(
                "add_payment_request",
                wallet.callAttr("make_payment_request", address, amount, description),
                daemonModel.config, Kwarg("set_address_label", false))
            requestsUpdate.setValue(Unit)
            dismiss()
        } catch (e: ToastException) { e.show() }
    }

    private fun onDelete() {
        wallet.callAttr("remove_payment_request", address, daemonModel.config)
        requestsUpdate.setValue(Unit)
        dismiss()
    }

    val description
        get() = dialog.etDescription.text.toString()
}