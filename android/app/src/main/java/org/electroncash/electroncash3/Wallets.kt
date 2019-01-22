package org.electroncash.electroncash3

import android.annotation.SuppressLint
import android.app.Dialog
import android.arch.lifecycle.MutableLiveData
import android.arch.lifecycle.Observer
import android.arch.lifecycle.ViewModel
import android.arch.lifecycle.ViewModelProviders
import android.content.DialogInterface
import android.content.Intent
import android.graphics.drawable.Drawable
import android.os.Bundle
import android.support.v4.app.DialogFragment
import android.support.v4.app.Fragment
import android.support.v4.app.FragmentActivity
import android.support.v7.app.AlertDialog
import android.text.Selection
import android.view.LayoutInflater
import android.view.Menu
import android.view.MenuInflater
import android.view.MenuItem
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import android.widget.Toast
import com.chaquo.python.PyException
import com.chaquo.python.PyObject
import com.google.zxing.integration.android.IntentIntegrator
import kotlinx.android.synthetic.main.new_wallet.*
import kotlinx.android.synthetic.main.text_input.*
import kotlinx.android.synthetic.main.transaction_detail.*
import kotlinx.android.synthetic.main.wallets.*
import org.electroncash.electroncash3.databinding.WalletsBinding
import kotlin.math.roundToInt


class WalletsFragment : Fragment(), MainFragment {
    override val title = MutableLiveData<String>()
    override val subtitle = MutableLiveData<String>()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setHasOptionsMenu(true)
        daemonModel.netStatus.observe(this, Observer { status ->
            if (status != null) {
                title.value = getString(R.string.online)
                subtitle.value = if (status.localHeight < status.serverHeight) {
                    "${getString(R.string.synchronizing)} ${status.localHeight} / ${status.serverHeight}"
                } else {
                    "${getString(R.string.height)} ${status.localHeight}"
                }
            } else {
                title.value = getString(R.string.offline)
                subtitle.value = getString(R.string.cannot_send)
            }
        })
    }

    override fun onCreateOptionsMenu(menu: Menu, inflater: MenuInflater) {
        inflater.inflate(R.menu.wallets, menu)
    }

    override fun onPrepareOptionsMenu(menu: Menu) {
        if (daemonModel.walletName.value == null) {
            menu.clear()
        }
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        when (item.itemId) {
            R.id.menuShowSeed-> {
                if (daemonModel.wallet!!.containsKey("get_seed")) {
                    showDialog(activity!!, ShowSeedPasswordDialog())
                } else {
                    toast(R.string.this_wallet_has_no_seed)
                }
            }
            R.id.menuDelete -> showDialog(activity!!, DeleteWalletDialog())
            R.id.menuClose -> showDialog(activity!!, CloseWalletDialog())
            else -> throw Exception("Unknown item $item")
        }
        return true
    }

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?,
                              savedInstanceState: Bundle?): View? {
        val binding = WalletsBinding.inflate(inflater, container, false)
        binding.setLifecycleOwner(this)
        binding.model = daemonModel
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        walletPanel.setOnClickListener {
            showDialog(activity!!, SelectWalletDialog())
        }
        daemonModel.walletBalance.observe(viewLifecycleOwner, Observer { balance ->
            tvBalance.text = if (balance == null) "" else formatSatoshis(balance)
            tvBalanceUnit.text = when {
                daemonModel.wallet == null -> getString(R.string.touch_to_load)
                balance == null -> getString(R.string.synchronizing)
                else -> unitName
            }
            updateFiat()
        })
        fiatUpdate.observe(viewLifecycleOwner, Observer { updateFiat() })

        setupVerticalList(rvTransactions)
        daemonModel.transactions.observe(viewLifecycleOwner, Observer {
            rvTransactions.adapter = if (it == null) null
                                     else TransactionsAdapter(activity!!, it.asList())
        })

        daemonModel.walletName.observe(viewLifecycleOwner, Observer {
            activity!!.invalidateOptionsMenu()
            if (it == null) {
                btnSend.hide()
            } else {
                btnSend.show()
            }
        })
        btnSend.setOnClickListener {
            if (daemonModel.wallet!!.callAttr("is_watching_only").toBoolean()) {
                toast(R.string.this_wallet_is_watching_only_)
            } else if (daemonModel.wallet!!.callAttr("get_receiving_addresses")
                       .asList().isEmpty()) {
                // At least one receiving address is needed to call wallet.dummy_address.
                toast(R.string.electron_cash_is_generating_your_addresses__please_wait_)
            } else {
                showDialog(activity!!, SendDialog())
            }
        }
    }

    fun updateFiat() {
        val balance = daemonModel.walletBalance.value
        val fiat = if (balance == null) null else formatFiatAmountAndUnit(balance)
        tvFiat.text = if (fiat == null) "" else "($fiat)"
    }
}


class SelectWalletDialog : AlertDialogFragment(), DialogInterface.OnClickListener {
    val items = ArrayList<String>()

    override fun onBuildDialog(builder: AlertDialog.Builder) {
        items.addAll(daemonModel.listWallets())
        items.add(getString(R.string.new_wallet))
        builder.setTitle(R.string.wallets)
            .setSingleChoiceItems(items.toTypedArray(),
                                  items.indexOf(daemonModel.walletName.value), this)
    }

    override fun onResume() {
        super.onResume()
        if (items.size == 1) {
            onClick(dialog, 0)
        }
    }

    override fun onClick(dialog: DialogInterface, which: Int) {
        dismiss()
        if (which < items.size - 1) {
            showDialog(activity!!, OpenWalletDialog().apply { arguments = Bundle().apply {
                putString("walletName", items[which])
            }})
        } else {
            showDialog(activity!!, NewWalletDialog1())
        }
    }
}


class NewWalletDialog1 : AlertDialogFragment() {
    override fun onBuildDialog(builder: AlertDialog.Builder) {
        builder.setTitle(R.string.new_wallet)
            .setView(R.layout.new_wallet)
            .setPositiveButton(R.string.next, null)
            .setNegativeButton(R.string.cancel, null)
    }

    override fun onShowDialog(dialog: AlertDialog) {
        dialog.spnType.adapter = MenuAdapter(context!!, R.menu.wallet_type)

        dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
            try {
                val name = dialog.etName.text.toString()
                if (name.isEmpty()) throw ToastException(R.string.name_is)
                if (name.contains("/")) throw ToastException(R.string.invalid_name)
                if (daemonModel.listWallets().contains(name)) {
                    throw ToastException(R.string.a_wallet_with_that_name_already_exists_please)
                }

                val password = dialog.etPassword.text.toString()
                if (password.isEmpty()) throw ToastException(R.string.enter_password)
                if (password != dialog.etConfirmPassword.text.toString()) {
                    throw ToastException(R.string.wallet_passwords)
                }

                val nextDialog: DialogFragment
                val arguments = Bundle().apply {
                    putString("name", name)
                    putString("password", password)
                }

                val walletType = dialog.spnType.selectedItemId.toInt()
                if (walletType in listOf(R.id.menuCreateSeed, R.id.menuRestoreSeed)) {
                    nextDialog = NewWalletSeedDialog()
                    val seed = if (walletType == R.id.menuCreateSeed)
                                   daemonModel.commands.callAttr("make_seed").toString()
                               else null
                    arguments.putString("seed", seed)
                } else if (walletType == R.id.menuImport) {
                    nextDialog = NewWalletImportDialog()
                } else {
                    throw Exception("Unknown item: ${dialog.spnType.selectedItem}")
                }
                showDialog(activity!!, nextDialog.apply { setArguments(arguments) })
                dismiss()
            } catch (e: ToastException) { e.show() }
        }
    }
}


abstract class NewWalletDialog2 : AlertDialogFragment() {
    class Model : ViewModel() {
        val result = MutableLiveData<Boolean>()
    }
    private val model by lazy { ViewModelProviders.of(this).get(Model::class.java) }

    override fun onBuildDialog(builder: AlertDialog.Builder) {
        builder.setTitle(R.string.new_wallet)
            .setView(R.layout.text_input)
            .setPositiveButton(android.R.string.ok, null)
            .setNegativeButton(R.string.cancel, null)
    }

    override fun onShowDialog(dialog: AlertDialog) {
        super.onShowDialog(dialog)
        dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
            model.result.value = null
            showDialog(activity!!, ProgressDialogFragment())
            Thread {
                try {
                    val name = arguments!!.getString("name")!!
                    val password = arguments!!.getString("password")!!
                    onCreateWallet(name, password, dialog.etInput.text.toString())
                    daemonModel.loadWallet(name, password)
                    model.result.postValue(true)
                } catch (e: ToastException) {
                    e.show()
                    model.result.postValue(false)
                }
            }.start()
        }
        model.result.observe(this, Observer { onResult(it) })
    }

    abstract fun onCreateWallet(name: String, password: String, input: String)

    fun onResult(success: Boolean?) {
        if (success == null) return
        dismissDialog(activity!!, ProgressDialogFragment::class)
        if (success) {
            dismiss()
        }
    }
}


class NewWalletSeedDialog : NewWalletDialog2() {
    override fun onShowDialog(dialog: AlertDialog) {
        super.onShowDialog(dialog)
        setupSeedDialog(this)
    }

    override fun onCreateWallet(name: String, password: String, input: String) {
        try {
            daemonModel.createWallet(name, password, "seed", input)
        } catch (e: PyException) {
            if (e.message!!.startsWith("InvalidSeed")) {
                throw ToastException(R.string.the_seed_you_entered_does_not_appear)
            }
            throw e
        }
    }
}


class NewWalletImportDialog : NewWalletDialog2() {
    override fun onBuildDialog(builder: AlertDialog.Builder) {
        super.onBuildDialog(builder)
        builder.setNeutralButton(R.string.scan_qr, null)
    }

    override fun onShowDialog(dialog: AlertDialog) {
        super.onShowDialog(dialog)
        dialog.tvPrompt.setText(R.string.enter_a_list_of_bitcoin)
        dialog.getButton(AlertDialog.BUTTON_NEUTRAL).setOnClickListener { scanQR(this) }
    }

    override fun onCreateWallet(name: String, password: String, input: String) {
        var foundAddress = false
        var foundPrivkey = false
        for (word in input.split(Regex("\\s+"))) {
            if (word.isEmpty()) {
                // Can happen at start or end of list.
            } else if (clsAddress.callAttr("is_valid", word).toBoolean()) {
                foundAddress = true
            } else if (libBitcoin.callAttr("is_private_key", word).toBoolean()) {
                foundPrivkey = true
            } else {
                throw ToastException(getString(R.string.not_a_valid, word))
            }
        }

        if (foundAddress) {
            if (foundPrivkey) {
                throw ToastException(R.string.cannot_specify_short)
            }
            daemonModel.createWallet(name, password, "addresses", input)
        } else if (foundPrivkey) {
            daemonModel.createWallet(name, password, "privkeys", input)
        } else {
            throw ToastException(R.string.you_appear_to_have_entered_no)
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        val result = IntentIntegrator.parseActivityResult(requestCode, resultCode, data)
        if (result != null && result.contents != null) {
            val text = dialog.etInput.text
            if (!text.isEmpty() && !text.endsWith("\n")) {
                text.append("\n")
            }
            text.append(result.contents)
            Selection.setSelection(text, text.length)
        } else {
            super.onActivityResult(requestCode, resultCode, data)
        }
    }
}


class DeleteWalletDialog : AlertDialogFragment() {
    override fun onBuildDialog(builder: AlertDialog.Builder) {
        val walletName = daemonModel.walletName.value
        val message = getString(R.string.do_you_want_to_delete, walletName) + "\n\n" +
                      getString(R.string.if_your_wallet)
        builder.setTitle(R.string.delete_wallet)
            .setMessage(message)
            .setPositiveButton(android.R.string.ok) { _, _ ->
                daemonModel.commands.callAttr("delete_wallet", walletName)
            }
            .setNegativeButton(android.R.string.cancel, null)
    }
}


abstract class PasswordDialog(val runInBackground: Boolean = false) : AlertDialogFragment() {
    class Model : ViewModel() {
        val result = MutableLiveData<Boolean>()
    }
    private val model by lazy { ViewModelProviders.of(this).get(Model::class.java) }

    override fun onBuildDialog(builder: AlertDialog.Builder) {
        builder.setTitle(R.string.password_required)
            .setView(R.layout.password)
            .setPositiveButton(android.R.string.ok, null)
            .setNegativeButton(android.R.string.cancel, null)
    }

    override fun onCreateDialog(savedInstanceState: Bundle?): Dialog {
        val dialog = super.onCreateDialog(savedInstanceState)
        dialog.window!!.setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_VISIBLE)
        return dialog
    }

    override fun onShowDialog(dialog: AlertDialog) {
        val posButton = dialog.getButton(AlertDialog.BUTTON_POSITIVE)
        posButton.setOnClickListener {
            tryPassword(dialog.etPassword.text.toString())
        }
        dialog.etPassword.setOnEditorActionListener { _, _, _ ->
            posButton.performClick()
        }
        model.result.observe(this, Observer { onResult(it) })
    }

    fun tryPassword(password: String) {
        model.result.value = null
        val r = Runnable {
            try {
                try {
                    onPassword(password)
                    model.result.postValue(true)
                } catch (e: PyException) {
                    throw if (e.message!!.startsWith("InvalidPassword"))
                        ToastException(R.string.password_incorrect, Toast.LENGTH_SHORT) else e
                }
            } catch (e: ToastException) {
                e.show()
                model.result.postValue(false)
            }
        }
        if (runInBackground) {
            showDialog(activity!!, ProgressDialogFragment())
            Thread(r).start()
        } else {
            r.run()
        }
    }

    /** Attempt to perform the operation with the given password. If the operation fails, this
     * method should throw either a ToastException, or an InvalidPassword PyException (most
     * lib functions that take passwords will do this automatically). */
    abstract fun onPassword(password: String)

    private fun onResult(success: Boolean?) {
        if (success == null) return
        dismissDialog(activity!!, ProgressDialogFragment::class)
        if (success) {
            dismiss()
        }
    }
}


class OpenWalletDialog : PasswordDialog(runInBackground = true) {
    override fun onPassword(password: String) {
        daemonModel.loadWallet(arguments!!.getString("walletName")!!, password)
    }
}


class CloseWalletDialog : ProgressDialogTask() {
    override fun doInBackground() {
        daemonModel.commands.callAttr("close_wallet")
    }
}


class ShowSeedPasswordDialog : PasswordDialog() {
    override fun onPassword(password: String) {
        val seed = daemonModel.wallet!!.callAttr("get_seed", password).toString()
        if (! seed.contains(" ")) {
            // get_seed(None) doesn't throw an exception, but returns the encrypted base64 seed.
            throw PyException("InvalidPassword")
        }
        showDialog(activity!!, SeedDialog().apply { arguments = Bundle().apply {
            putString("seed", seed)
        }})
    }
}

open class SeedDialog : AlertDialogFragment() {
    override fun onBuildDialog(builder: AlertDialog.Builder) {
        builder.setTitle(R.string.wallet_seed)
            .setView(R.layout.text_input)
            .setPositiveButton(android.R.string.ok, null)
    }

    override fun onShowDialog(dialog: AlertDialog) {
        setupSeedDialog(this)
    }
}


fun setupSeedDialog(fragment: DialogFragment) {
    val tvPrompt = fragment.dialog.tvPrompt
    val etInput = fragment.dialog.etInput
    val seed = fragment.arguments!!.getString("seed")
    if (seed == null) {
        tvPrompt.setText(R.string.please_enter_your_seed_phrase)
    } else {
        tvPrompt.setText(seedAdvice(seed))
        etInput.setText(seed)
        etInput.setFocusable(false)
    }
}


fun seedAdvice(seed: String): String {
    return app.getString(R.string.please_save, seed.split(" ").size) + " " +
           app.getString(R.string.this_seed) + " " +
           app.getString(R.string.never_disclose)
}


class TransactionsAdapter(val activity: FragmentActivity, val transactions: List<PyObject>)
    : BoundAdapter<TransactionModel>(R.layout.transaction_list) {

    override fun getItem(position: Int): TransactionModel {
        return TransactionModel(transactions.get(itemCount - position - 1)  // Newest first
                                .asMap())
    }

    override fun getItemCount(): Int {
        return transactions.size
    }

    override fun onBindViewHolder(holder: BoundViewHolder<TransactionModel>, position: Int) {
        super.onBindViewHolder(holder, position)
        holder.itemView.setOnClickListener {
            val txid = holder.item.get("txid").toString()
            val tx = daemonModel.wallet!!.get("transactions")!!.callAttr("get", txid)
            if (tx == null) {  // Can happen during wallet sync.
                toast(R.string.transaction_not)
            } else {
                showDialog(activity, TransactionDialog(txid))
            }
        }
    }
}

class TransactionModel(val txExport: Map<PyObject, PyObject>) {
    fun get(key: String) = txExport.get(PyObject.fromJava(key))!!

    fun getIcon(): Drawable {
        return app.resources.getDrawable(
            if (get("value").toString()[0] == '+') R.drawable.ic_add_24dp
            else R.drawable.ic_remove_24dp)!!
    }

    @SuppressLint("StringFormatMatches")
    fun getConfirmationsStr(): String {
        val confirmations = get("confirmations").toInt()
        return when {
            confirmations <= 0 -> ""
            confirmations > 6 -> app.getString(R.string.confirmed)
            else -> app.getString(R.string.___confirmations, confirmations)
        }
    }
}


class TransactionDialog() : AlertDialogFragment() {
    constructor(txid: String) : this() {
        arguments = Bundle().apply { putString("txid", txid) }
    }
    val txid by lazy { arguments!!.getString("txid")!! }
    val wallet by lazy { daemonModel.wallet!! }

    override fun onBuildDialog(builder: AlertDialog.Builder) {
        builder.setView(R.layout.transaction_detail)
            .setPositiveButton(R.string.ok, null)
    }

    override fun onShowDialog(dialog: AlertDialog) {
        dialog.btnExplore.setOnClickListener { exploreTransaction(activity!!, txid) }
        dialog.btnCopy.setOnClickListener { copyToClipboard(txid) }

        val tx = wallet.get("transactions")!!.callAttr("get", txid)!!
        val txInfo = wallet.callAttr("get_tx_info", tx).asList()
        dialog.tvTxid.text = txid

        val timestamp = txInfo.get(8).toLong()
        dialog.tvTimestamp.text = if (timestamp == 0L) getString(R.string.Unknown)
                                  else libUtil.callAttr("format_time", timestamp).toString()

        dialog.tvStatus.text = txInfo.get(1).toString()

        val size = tx.callAttr("estimated_size").toInt()
        dialog.tvSize.text = getString(R.string.bytes, size)

        val fee = txInfo.get(5)?.toLong()
        if (fee == null) {
            dialog.tvFee.text = getString(R.string.Unknown)
        } else {
            val feeSpb = (fee.toDouble() / size.toDouble()).roundToInt()
            dialog.tvFee.text = String.format("%s (%s %s)",
                                              getString(R.string.sat_byte, feeSpb),
                                              formatSatoshis(fee), unitName)
        }
    }
}