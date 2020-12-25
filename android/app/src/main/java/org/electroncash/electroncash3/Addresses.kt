package org.electroncash.electroncash3

import android.os.Bundle
import android.text.SpannableString
import android.text.SpannableStringBuilder
import android.text.Spanned
import android.text.method.LinkMovementMethod
import android.text.style.ClickableSpan
import android.view.Menu
import android.view.MenuInflater
import android.view.MenuItem
import android.view.View
import android.widget.Button
import androidx.appcompat.app.AlertDialog
import androidx.fragment.app.viewModels
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.Observer
import androidx.lifecycle.ViewModel
import com.chaquo.python.Kwarg
import com.chaquo.python.PyObject
import kotlinx.android.synthetic.main.address_detail.*
import kotlinx.android.synthetic.main.transactions.*


val guiAddresses by lazy { guiMod("addresses") }
val libAddress by lazy { libMod("address") }
val clsAddress by lazy { libAddress["Address"]!! }


class AddressesFragment : ListFragment(R.layout.addresses, R.id.rvAddresses) {

    class Model : ViewModel() {
        // This corresponds to the order of the arguments to get_addresses.
        val filters = listOf(R.menu.filter_type, R.menu.filter_status).map {
            it to MutableLiveData<Int>().apply { value = R.id.filterAll }
        }.toMap()
    }
    val model: Model by viewModels()

    override fun onListModelCreated(listModel: ListModel) {
        with (listModel) {
            trigger.addSource(daemonUpdate)
            trigger.addSource(settings.getBoolean("cashaddr_format"))
            trigger.addSource(settings.getString("base_unit"))
            for (filter in model.filters.values) {
                trigger.addSource(filter)
            }

            data.function = {
                guiAddresses.callAttr("get_addresses", wallet,
                                      *(model.filters.values.map { it.value }.toTypedArray()))
            }
        }
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        initFilter(R.id.btnType, R.string.type, R.menu.filter_type)
        initFilter(R.id.btnStatus, R.string.status, R.menu.filter_status)
    }

    override fun onCreateAdapter() =
        ListAdapter(this, R.layout.address_list, ::AddressModel, ::AddressDialog)

    private fun initFilter(btnId: Int, labelId: Int, menuId: Int) {
        val btn = view!!.findViewById<Button>(btnId)
        btn.setOnClickListener {
            showDialog(this, FilterDialog().apply { arguments = Bundle().apply {
                putInt("labelId", labelId)
                putInt("menuId", menuId)
            }})
        }

        val liveData = model.filters.getValue(menuId)
        val menu = inflateMenu(menuId)
        liveData.observe(viewLifecycleOwner, Observer {
            btn.setText("${getString(labelId)}: ${menu.findItem(liveData.value!!).title}")
        })
    }
}


class AddressModel(wallet: PyObject, val addr: PyObject) : ListItemModel(wallet) {
    fun toString(format: String) = addr.callAttr("to_${format}_string").toString()

    val status by lazy {
        app.getString(if (txCount == 0) R.string.unused
                      else if (balance != 0L) R.string.balance
                      else R.string.used)
    }
    val balance by lazy {
        // get_addr_balance returns the tuple (confirmed, unconfirmed, unmatured)
        wallet.callAttr("get_addr_balance", addr).asList().get(0).toLong()
    }
    val txCount by lazy {
        wallet.callAttr("get_address_history", addr).asList().size
    }
    val type by lazy {
        app.getString(if (wallet.callAttr("is_change", addr).toBoolean()) R.string.change
                      else R.string.receiving)
    }
    val description by lazy {
        getDescription(wallet, toString("storage"))
    }
    override val dialogArguments by lazy {
        Bundle().apply { putString("address", toString("storage")) }
    }
}


class AddressDialog : DetailDialog() {
    val addrModel by lazy {
        AddressModel(wallet, clsAddress.callAttr("from_string",
                                                 arguments!!.getString("address")!!))
    }

    override fun onBuildDialog(builder: AlertDialog.Builder) {
        with (builder) {
            setView(R.layout.address_detail)
            setNegativeButton(android.R.string.cancel, null)
            setPositiveButton(android.R.string.ok, { _, _  ->
                setDescription(wallet, addrModel.toString("storage"),
                               etDescription.text.toString())
            })
        }
    }

    override fun onShowDialog() {
        btnExplore.setOnClickListener {
            exploreAddress(activity!!, addrModel.addr)
        }
        btnCopy.setOnClickListener {
            copyToClipboard(addrModel.toString("full_ui"), R.string.address)
        }

        showQR(imgQR, addrModel.toString("full_ui"))
        tvAddress.text = addrModel.toString("ui")
        tvType.text = addrModel.type

        with (SpannableStringBuilder()) {
            append(addrModel.txCount.toString())
            if (addrModel.txCount > 0) {
                append(" (")
                val link = SpannableString(getString(R.string.show))
                link.setSpan(object : ClickableSpan() {
                    override fun onClick(widget: View) {
                        showDialog(this@AddressDialog,
                                   AddressTransactionsDialog(addrModel.toString("storage")))
                    }
                }, 0, link.length, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
                append(link)
                append(")")
            }
            tvTxCount.text = this
        }
        tvTxCount.movementMethod = LinkMovementMethod.getInstance()

        tvBalance.text = ltr(formatSatoshisAndFiat(addrModel.balance))
    }

    override fun onFirstShowDialog() {
        etDescription.setText(addrModel.description)
    }
}


class AddressTransactionsDialog() : AlertDialogFragment() {
    constructor(address: String) : this() {
        arguments = Bundle().apply { putString("address", address) }
    }

    override fun onBuildDialog(builder: AlertDialog.Builder) {
        with (builder) {
            setTitle(R.string.transactions)
            setView(R.layout.transactions)
        }
    }

    override fun onShowDialog() {
        // Remove buttons and bottom padding.
        btnSend.hide()
        btnRequest.hide()
        rvTransactions.setPadding(0, 0, 0, 0)

        setupVerticalList(rvTransactions)
        val addressDialog = targetFragment as AddressDialog
        val adapter = TransactionsAdapter(addressDialog.listFragment)
        rvTransactions.adapter = adapter
        val addr = clsAddress.callAttr("from_string", arguments!!.getString("address")!!)
        val wallet = addressDialog.wallet

        // The list needs to auto-update in case the user sets a transaction description.
        daemonUpdate.observe(this, Observer {
            adapter.submitPyList(wallet, wallet.callAttr("get_history",
                                                         Kwarg("domain", arrayOf(addr))))
        })
    }
}


class FilterDialog : MenuDialog() {

    val menuId by lazy { arguments!!.getInt("menuId") }
    val liveData by lazy {
        (targetFragment as AddressesFragment).model.filters.getValue(menuId)
    }

    override fun onBuildDialog(builder: AlertDialog.Builder, menu: Menu) {
        builder.setTitle(arguments!!.getInt("labelId"))
        MenuInflater(app).inflate(menuId, menu)
        menu.findItem(liveData.value!!).isChecked = true
    }

    override fun onMenuItemSelected(item: MenuItem) {
        liveData.value = item.itemId
        dismiss()
    }
}
