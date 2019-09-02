package org.electroncash.electroncash3

import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.Observer
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProviders
import android.os.Bundle
import androidx.fragment.app.Fragment
import androidx.fragment.app.FragmentActivity
import androidx.appcompat.app.AlertDialog
import android.text.SpannableString
import android.text.SpannableStringBuilder
import android.text.Spanned
import android.text.method.LinkMovementMethod
import android.text.style.ClickableSpan
import android.view.LayoutInflater
import android.view.Menu
import android.view.MenuInflater
import android.view.MenuItem
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import com.chaquo.python.PyObject
import kotlinx.android.synthetic.main.address_detail.*
import kotlinx.android.synthetic.main.addresses.*
import kotlinx.android.synthetic.main.transactions.*
import kotlin.reflect.KClass


val libAddress by lazy { libMod("address") }
val clsAddress by lazy { libAddress["Address"]!! }

val addressLabelUpdate = MutableLiveData<Unit>().apply { value = Unit }


class AddressesFragment : Fragment(), MainFragment {
    
    class Model : ViewModel() {
        val filterType = MutableLiveData<Int>().apply { value = R.id.filterAll }
        val filterStatus = MutableLiveData<Int>().apply { value = R.id.filterAll }
    }
    val model by lazy { ViewModelProviders.of(this).get(Model::class.java) }
    
    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?,
                              savedInstanceState: Bundle?): View? {
        return inflater.inflate(R.layout.addresses, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        btnType.setOnClickListener { showFilterDialog(FilterTypeDialog::class) }
        btnStatus.setOnClickListener { showFilterDialog(FilterStatusDialog::class) }

        setupVerticalList(rvAddresses)
        rvAddresses.adapter = AddressesAdapter(activity!!)
        daemonUpdate.observe(viewLifecycleOwner, Observer { refresh() })
        for (filter in listOf(model.filterType, model.filterStatus)) {
            filter.observe(viewLifecycleOwner, Observer { refresh() })
        }

        addressLabelUpdate.observe(viewLifecycleOwner, Observer { rebind() })
        settings.getBoolean("cashaddr_format").observe(viewLifecycleOwner, Observer { rebind() })
        settings.getString("base_unit").observe(viewLifecycleOwner, Observer { rebind() })
    }

    fun refresh() {
        setFilterLabel(btnType, R.string.type, R.menu.filter_type, model.filterType)
        setFilterLabel(btnStatus, R.string.status, R.menu.filter_status, model.filterStatus)

        val wallet = daemonModel.wallet
        (rvAddresses.adapter as AddressesAdapter).submitList(
            if (wallet == null) null
            else wallet.callAttr("get_addresses").asList()
                .map { AddressModel(wallet, it) }
                .filter { passesFilter(it) })
    }

    fun setFilterLabel(btn: Button, prefix: Int, menuId: Int, liveData: LiveData<Int>) {
        val menu = inflateMenu(menuId)
        btn.setText("${getString(prefix)}: ${menu.findItem(liveData.value!!).title}")
    }

    fun <T: FilterDialog> showFilterDialog(cls: KClass<T>) {
        val frag = cls.java.newInstance()
        frag.setTargetFragment(this, 0)
        showDialog(activity!!, frag)
    }

    fun rebind() {
        rvAddresses.adapter?.notifyDataSetChanged()
    }

    fun passesFilter(am: AddressModel): Boolean {
        when (model.filterType.value) {
            R.id.filterReceiving -> { if (am.isChange) return false }
            R.id.filterChange -> { if (!am.isChange) return false }
        }
        when (model.filterStatus.value) {
            R.id.filterUnused -> { if (!am.history.isEmpty()) return false }
            R.id.filterFunded -> { if (am.balance == 0L) return false }
            R.id.filterUsed -> {
                if (am.history.isEmpty() || am.balance != 0L) return false
            }
        }
        return true
    }
}


class AddressesAdapter(val activity: FragmentActivity)
    : BoundAdapter<AddressModel>(R.layout.address_list) {

    override fun onBindViewHolder(holder: BoundViewHolder<AddressModel>, position: Int) {
        super.onBindViewHolder(holder, position)
        holder.itemView.setOnClickListener {
            showDialog(activity, AddressDialog(holder.item.toString("storage")))
        }
    }
}


class AddressModel(val wallet: PyObject, val addr: PyObject) {
    fun toString(format: String) = addr.callAttr("to_${format}_string").toString()

    val status
        get() = app.getString(if (history.isEmpty()) R.string.unused
                              else if (balance != 0L) R.string.balance
                              else R.string.used)

    // get_addr_balance returns the tuple (confirmed, unconfirmed, unmatured)
    val balance
        get() = wallet.callAttr("get_addr_balance", addr).asList().get(0).toLong()

    val history by lazy {
        wallet.callAttr("get_address_history", addr).asList()
    }

    val type
        get() = app.getString(if (isChange) R.string.change else R.string.receiving)

    val isChange
        get() = wallet.callAttr("is_change", addr).toBoolean()

    val description
        get() = wallet.callAttr("get_label", toString("storage")).toString()
}


class AddressDialog() : AlertDialogFragment() {
    constructor(address: String) : this() {
        arguments = Bundle().apply { putString("address", address) }
    }
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
                addressLabelUpdate.setValue(Unit)
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
            append(addrModel.history.size.toString())
            if (!addrModel.history.isEmpty()) {
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

        tvBalance.text = formatSatoshisAndFiat(addrModel.balance)
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
        rvTransactions.adapter = TransactionsAdapter(activity!!)
        transactionsUpdate.observe(this, Observer { refresh() })
    }

    fun refresh() {
        val addr = clsAddress.callAttr("from_string", arguments!!.getString("address")!!)
        (rvTransactions.adapter as TransactionsAdapter).submitList(
            TransactionsList(daemonModel.wallet!!, addr))
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
