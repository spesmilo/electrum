package org.electroncash.electroncash3

import android.graphics.drawable.Drawable
import android.os.Bundle
import android.view.View
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.content.res.AppCompatResources
import androidx.fragment.app.Fragment
import com.chaquo.python.PyObject
import kotlinx.android.synthetic.main.transaction_detail.*
import kotlinx.android.synthetic.main.transactions.*
import kotlin.math.roundToInt


class TransactionsFragment : ListFragment(R.layout.transactions, R.id.rvTransactions) {

    override fun onListModelCreated(listModel: ListModel) {
        with (listModel) {
            trigger.addSource(daemonUpdate)
            trigger.addSource(settings.getString("base_unit"))
            data.function = { wallet.callAttr("get_history")!! }
        }
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        btnSend.setOnClickListener {
            try {
                showDialog(this, SendDialog())
            } catch (e: ToastException) { e.show() }
        }
        btnRequest.setOnClickListener { showDialog(this, NewRequestDialog()) }
    }

    override fun onCreateAdapter() = TransactionsAdapter(this)
}


// Also used in AddressesTransactionsDialog.
fun TransactionsAdapter(listFragment: ListFragment) =
    ListAdapter(listFragment, R.layout.transaction_list, ::TransactionModel,
                ::TransactionDialog)
        .apply { reversed = true }


class TransactionModel(wallet: PyObject, val txHistory: PyObject) : ListItemModel(wallet) {
    private fun get(key: String) = txHistory.get(key)

    val txid by lazy { get("tx_hash")!!.toString() }
    val amount by lazy { get("amount")?.toLong() ?: 0 }
    val balance by lazy { get("balance")?.toLong() ?: 0 }
    val timestamp by lazy { formatTime(get("timestamp")?.toLong()) }
    val label by lazy { getDescription(wallet, txid) }

    val icon: Drawable by lazy {
        // Support inflation of vector images before API level 21.
        AppCompatResources.getDrawable(
            app,
            if (amount >= 0) R.drawable.ic_add_24dp
            else R.drawable.ic_remove_24dp)!!
    }

    val status: String  by lazy {
        val confirmations = get("conf")!!.toInt()
        when {
            confirmations <= 0 -> app.getString(R.string.Unconfirmed)
            else -> app.resources.getQuantityString(R.plurals.confirmation,
                                                    confirmations, confirmations)
        }
    }

    override val dialogArguments by lazy {
        Bundle().apply { putString("txid", txid) }
    }
}


class TransactionDialog : DetailDialog() {
    val txid by lazy { arguments!!.getString("txid")!! }
    val tx by lazy {
        // Transaction lookup sometimes fails during sync.
        wallet.get("transactions")!!.callAttr("get", txid)
            ?: throw ToastException(R.string.Transaction_not)
    }
    val txInfo by lazy { wallet.callAttr("get_tx_info", tx)!! }

    override fun onBuildDialog(builder: AlertDialog.Builder) {
        builder.setView(R.layout.transaction_detail)
            .setNegativeButton(android.R.string.cancel, null)
            .setPositiveButton(android.R.string.ok, {_, _ ->
                setDescription(wallet, txid, etDescription.text.toString())
            })
    }

    override fun onShowDialog() {
        btnExplore.setOnClickListener { exploreTransaction(activity!!, txid) }
        btnCopy.setOnClickListener { copyToClipboard(txid, R.string.transaction_id) }

        tvTxid.text = txid

        // For outgoing transactions, the list view includes the fee in the amount, but the
        // detail view does not.
        tvAmount.text = ltr(formatSatoshisAndUnit(txInfo.get("amount")?.toLong(), signed=true))
        tvTimestamp.text = ltr(formatTime(txInfo.get("timestamp")?.toLong()))
        tvStatus.text = txInfo.get("status")!!.toString()

        val size = tx.callAttr("estimated_size").toInt()
        tvSize.text = getString(R.string.bytes, size)

        val fee = txInfo.get("fee")?.toLong()
        if (fee == null) {
            tvFee.text = getString(R.string.Unknown)
        } else {
            val feeSpb = (fee.toDouble() / size.toDouble()).roundToInt()
            tvFee.text = String.format("%s (%s)",
                                       getString(R.string.sat_byte, feeSpb),
                                       ltr(formatSatoshisAndUnit(fee)))
        }
    }

    override fun onFirstShowDialog() {
        etDescription.setText(txInfo.get("label")!!.toString())
    }
}