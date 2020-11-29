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
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel
import com.chaquo.python.Kwarg
import com.chaquo.python.PyObject
import kotlinx.android.synthetic.main.address_detail.*
import kotlinx.android.synthetic.main.addresses.*
import kotlinx.android.synthetic.main.transactions.*
import kotlin.reflect.KClass


val guiAddresses by lazy { guiMod("addresses") }
val libAddress by lazy { libMod("address") }
val clsAddress by lazy { libAddress["Address"]!! }


class AddressesFragment : ListFragment(R.layout.addresses, R.id.rvAddresses) {

    class Model : ViewModel() {
        val filterType = MutableLiveData<Int>().apply { value = R.id.filterAll }
        val filterStatus = MutableLiveData<Int>().apply { value = R.id.filterAll }
    }
    val model: Model by viewModels()

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        btnType.setOnClickListener { showFilterDialog(FilterTypeDialog::class) }
        btnStatus.setOnClickListener { showFilterDialog(FilterStatusDialog::class) }

        addSource(daemonUpdate)
        addSource(model.filterType)
        addSource(model.filterStatus)
        addSource(settings.getBoolean("cashaddr_format"))
        addSource(settings.getString("base_unit"))
    }

    override fun onCreateAdapter() =
        ListAdapter(this, R.layout.address_list, { AddressModel(daemonModel.wallet!!, it) },
                    ::AddressDialog)

    override fun refresh() {
        super.refresh()
        setFilterLabel(btnType, R.string.type, R.menu.filter_type, model.filterType)
        setFilterLabel(btnStatus, R.string.status, R.menu.filter_status, model.filterStatus)
    }

    override fun onRefresh(wallet: PyObject) =
        guiAddresses.callAttr("get_addresses", wallet,
                              model.filterType.value, model.filterStatus.value)!!

    fun setFilterLabel(btn: Button, prefix: Int, menuId: Int, liveData: LiveData<Int>) {
        val menu = inflateMenu(menuId)
        btn.setText("${getString(prefix)}: ${menu.findItem(liveData.value!!).title}")
    }

    fun <T: FilterDialog> showFilterDialog(cls: KClass<T>) {
        val frag = cls.java.newInstance()
        frag.setTargetFragment(this, 0)
        showDialog(activity!!, frag)
    }
}


class AddressModel(val wallet: PyObject, val addr: PyObject) : ListModel {
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
        getDescription(toString("storage"))
    }
    override val dialogArguments by lazy {
        Bundle().apply { putString("address", toString("storage")) }
    }
}


class AddressDialog : AlertDialogFragment() {

    val addrModel by lazy {
        AddressModel(daemonModel.wallet!!,
                     clsAddress.callAttr("from_string",
                                         arguments!!.getString("address")!!))
    }

    override fun onBuildDialog(builder: AlertDialog.Builder) {
        with (builder) {
            setView(R.layout.address_detail)
            setNegativeButton(android.R.string.cancel, null)
            setPositiveButton(android.R.string.ok, { _, _  ->
                setDescription(addrModel.toString("storage"),
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
                        showDialog(activity!!,
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

    private val adapter = TransactionsAdapter(this)

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
        rvTransactions.adapter = adapter
        val addr = clsAddress.callAttr("from_string", arguments!!.getString("address")!!)
        adapter.submitPyList(
            daemonModel.wallet!!.callAttr("get_history", Kwarg("domain", arrayOf(addr))))
    }
}


abstract class FilterDialog : MenuDialog() {
    val model by lazy { (targetFragment as AddressesFragment).model }
    lateinit var liveData: MutableLiveData<Int>

    fun onBuildDialog(builder: AlertDialog.Builder, menu: Menu, titleId: Int, menuId: Int,
                      liveData: MutableLiveData<Int>) {
        this.liveData = liveData
        builder.setTitle(titleId)
        MenuInflater(app).inflate(menuId, menu)
        menu.findItem(liveData.value!!).isChecked = true
    }

    override fun onMenuItemSelected(item: MenuItem) {
        liveData.value = item.itemId
        dismiss()
    }
}

class FilterTypeDialog : FilterDialog() {
    override fun onBuildDialog(builder: AlertDialog.Builder, menu: Menu) {
        onBuildDialog(builder, menu, R.string.type, R.menu.filter_type, model.filterType)
    }
}

class FilterStatusDialog : FilterDialog() {
    override fun onBuildDialog(builder: AlertDialog.Builder, menu: Menu) {
        onBuildDialog(builder, menu, R.string.status, R.menu.filter_status,
                      model.filterStatus)
    }
}
