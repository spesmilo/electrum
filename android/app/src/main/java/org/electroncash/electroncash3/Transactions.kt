package org.electroncash.electroncash3

import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.Observer
import android.graphics.drawable.Drawable
import android.os.Bundle
import androidx.fragment.app.Fragment
import androidx.fragment.app.FragmentActivity
import androidx.core.content.ContextCompat
import androidx.appcompat.app.AlertDialog
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import com.chaquo.python.Kwarg
import com.chaquo.python.PyObject
import kotlinx.android.synthetic.main.transaction_detail.*
import kotlinx.android.synthetic.main.transactions.*
import kotlin.math.roundToInt


val transactionsUpdate = MutableLiveData<Unit>().apply { value = Unit }


class TransactionsFragment : Fragment(), MainFragment {
    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?,
                              savedInstanceState: Bundle?): View? {
        return inflater.inflate(R.layout.transactions, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        setupVerticalList(rvTransactions)
        rvTransactions.adapter = TransactionsAdapter(activity!!)

        daemonUpdate.observe(viewLifecycleOwner, Observer { refresh() })
        transactionsUpdate.observe(viewLifecycleOwner, Observer { refresh() })
        settings.getString("base_unit").observe(viewLifecycleOwner, Observer { refresh() })

        btnSend.setOnClickListener {
            try {
                showDialog(activity!!, SendDialog())
            } catch (e: ToastException) { e.show() }
        }
        btnRequest.setOnClickListener { newRequest(activity!!) }
    }

    fun refresh() {
        val wallet = daemonModel.wallet
        (rvTransactions.adapter as TransactionsAdapter).submitList(
            if (wallet == null) null else TransactionsList(wallet))
    }
}


class TransactionsList(wallet: PyObject, addr: PyObject? = null)
    : AbstractList<TransactionModel>() {

    val history = wallet.callAttr("export_history",
                                  Kwarg("domain", if (addr == null) null else arrayOf(addr)),
                                  Kwarg("decimal_point", unitPlaces)).asList()

    override val size
        get() = history.size

    override fun get(index: Int) =
        TransactionModel(history.get(index).asMap())
}


class TransactionsAdapter(val activity: FragmentActivity)
    : BoundAdapter<TransactionModel>(R.layout.transaction_list) {

    override fun onBindViewHolder(holder: BoundViewHolder<TransactionModel>, position: Int) {
        super.onBindViewHolder(holder, position)
        holder.itemView.setOnClickListener {
            val txid = holder.item.get("txid")
            val tx = daemonModel.wallet!!.get("transactions")!!.callAttr("get", txid)
            if (tx == null) {  // Can happen during wallet sync.
                toast(R.string.Transaction_not, Toast.LENGTH_SHORT)
            } else {
                showDialog(activity, TransactionDialog(txid))
            }
        }
    }
}

class TransactionModel(val txExport: Map<PyObject, PyObject>) {
    fun get(key: String) = txExport.get(PyObject.fromJava(key))!!.toString()

    fun getIcon(): Drawable {
        return ContextCompat.getDrawable(
            app,
            if (get("value")[0] == '+') R.drawable.ic_add_24dp
            else R.drawable.ic_remove_24dp)!!
    }

    fun getConfirmationsStr(): String {
        val confirmations = Integer.parseInt(get("confirmations"))
        return when {
            confirmations <= 0 -> ""
            else -> app.resources.getQuantityString(R.plurals.confirmation,
                                                    confirmations, confirmations)
        }
    }
}


class TransactionDialog() : AlertDialogFragment() {
    constructor(txid: String) : this() {
        arguments = Bundle().apply { putString("txid", txid) }
    }

    val wallet by lazy { daemonModel.wallet!! }
    val txid by lazy { arguments!!.getString("txid")!! }
    val tx by lazy { wallet.get("transactions")!!.callAttr("get", txid)!! }
    val txInfo by lazy { wallet.callAttr("get_tx_info", tx).asList() }

    override fun onBuildDialog(builder: AlertDialog.Builder) {
        builder.setView(R.layout.transaction_detail)
            .setNegativeButton(android.R.string.cancel, null)
            .setPositiveButton(android.R.string.ok, {_, _ ->
                setDescription(txid, etDescription.text.toString())
                transactionsUpdate.setValue(Unit)
            })
    }

    override fun onShowDialog() {
        btnExplore.setOnClickListener { exploreTransaction(activity!!, txid) }
        btnCopy.setOnClickListener { copyToClipboard(txid, R.string.transaction_id) }

        tvTxid.text = txid

        val timestamp = txInfo.get(8).toLong()
        tvTimestamp.text = if (timestamp == 0L) getString(R.string.Unknown)
                                  else libUtil.callAttr("format_time", timestamp).toString()

        tvStatus.text = txInfo.get(1)!!.toString()

        val size = tx.callAttr("estimated_size").toInt()
        tvSize.text = getString(R.string.bytes, size)

        val fee = txInfo.get(5)?.toLong()
        if (fee == null) {
            tvFee.text = getString(R.string.Unknown)
        } else {
            val feeSpb = (fee.toDouble() / size.toDouble()).roundToInt()
            tvFee.text = String.format("%s (%s)",
                                              getString(R.string.sat_byte, feeSpb),
                                              formatSatoshisAndUnit(fee))
        }
    }

    override fun onFirstShowDialog() {
        etDescription.setText(txInfo.get(2)!!.toString())
    }
}