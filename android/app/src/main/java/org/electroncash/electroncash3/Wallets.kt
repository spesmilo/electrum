package org.electroncash.electroncash3

import android.arch.lifecycle.Observer
import android.content.DialogInterface
import android.os.Bundle
import android.support.v7.app.AlertDialog
import android.support.v7.widget.DividerItemDecoration
import android.support.v7.widget.LinearLayoutManager
import android.view.*
import android.view.inputmethod.InputMethodManager
import android.widget.Toast
import com.chaquo.python.PyException
import com.chaquo.python.PyObject
import kotlinx.android.synthetic.main.main.*
import kotlinx.android.synthetic.main.new_wallet.*
import kotlinx.android.synthetic.main.seed.*
import kotlinx.android.synthetic.main.wallets.*
import org.electroncash.electroncash3.databinding.WalletsBinding


class WalletsFragment : MainFragment() {
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
        daemonModel.walletName.observe(this, Observer {
            activity!!.invalidateOptionsMenu()
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
            R.id.menuShowSeed-> showDialog(activity!!, ShowSeedPasswordDialog())
            R.id.menuDelete -> showDialog(activity!!, DeleteWalletDialog())
            R.id.menuClose -> daemonModel.commands.callAttr("close_wallet")
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
        daemonModel.walletBalance.observe(this, Observer { balance ->
            tvBalance.text = if (balance == null) "" else formatSatoshis(balance)
            tvBalanceUnit.text = when {
                daemonModel.wallet == null -> getString(R.string.touch_to_load)
                balance == null -> getString(R.string.synchronizing)
                else -> unitName
            }
        })

        with (rvTransactions) {
            layoutManager = LinearLayoutManager(activity)
            addItemDecoration(DividerItemDecoration(context, DividerItemDecoration.VERTICAL))
        }
        daemonModel.walletTransactions.observe(this, Observer {
            rvTransactions.adapter = if (it == null) null else TransactionsAdapter(it)
        })

        btnSend.setOnClickListener { showDialog(activity!!, SendDialog()) }
        btnReceive.setOnClickListener {
            mainActivity.navigation.selectedItemId = R.id.navAddresses
        }
    }
}


// TODO integrate into Wallets screen like in the iOS app.
class SelectWalletDialog : AlertDialogFragment(), DialogInterface.OnClickListener {
    lateinit var items: MutableList<String>

    override fun onBuildDialog(builder: AlertDialog.Builder) {
        items = daemonModel.listWallets()
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
            showDialog(activity!!, NewWalletDialog())
        }
    }
}


class NewWalletDialog : AlertDialogFragment(), DialogInterface.OnClickListener {
    override fun onBuildDialog(builder: AlertDialog.Builder) {
        builder.setTitle(R.string.new_wallet)
            .setView(R.layout.new_wallet)
            .setNegativeButton(R.string.create, null)
            .setPositiveButton(R.string.restore, null)
    }
    override fun onShowDialog(dialog: AlertDialog) {
        for (which in listOf(AlertDialog.BUTTON_NEGATIVE, AlertDialog.BUTTON_POSITIVE)) {
            dialog.getButton(which).setOnClickListener { onClick(dialog, which) }
        }
    }

    override fun onClick(di: DialogInterface, which: Int) {
        try {
            val name = dialog.etName.text.toString()
            if (name.isEmpty()) throw ToastException(R.string.name_is)
            if (name.contains("/")) throw ToastException(R.string.invalid_name)
            if (daemonModel.listWallets().contains(name)) throw ToastException(R.string.a_wallet)

            val password = dialog.etPassword.text.toString()
            if (password.isEmpty()) throw ToastException(R.string.password_required)
            if (password != dialog.etConfirmPassword.text.toString()) {
                throw ToastException(R.string.wallet_passwords)
            }

            // Can't put this within the lambda or daemonModel will be found in NewSeedDialog
            // and return null.
            // TODO: select seed language.
            val seed = if (which == AlertDialog.BUTTON_NEGATIVE)
                       daemonModel.commands.callAttr("make_seed").toString()
                       else null
            showDialog(activity!!, NewSeedDialog().apply { arguments = Bundle().apply {
                putString("name", name)
                putString("password", password)
                putString("seed", seed)
            }})
            dismiss()
        } catch (e: ToastException) { e.show() }
    }
}

class NewSeedDialog : SeedDialog() {
    override fun onShowDialog(dialog: AlertDialog) {
        super.onShowDialog(dialog)
        dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
            try {
                val name = arguments!!.getString("name")
                val password = arguments!!.getString("password")
                val seed = dialog.etSeed.text.toString()
                try {
                    daemonModel.commands.callAttr("create", name, password, seed)
                } catch (e: PyException) {
                    if (e.message!!.startsWith("BaseException")) {  // See keystore.from_seed
                        throw ToastException(R.string.the_seed)
                    }
                    throw e
                }
                dismiss()
                daemonModel.loadWallet(name, password)
            } catch (e: ToastException) { e.show() }
        }
    }
}


class DeleteWalletDialog : AlertDialogFragment() {
    override fun onBuildDialog(builder: AlertDialog.Builder) {
        val walletName = daemonModel.walletName.value
        builder.setTitle(R.string.delete_wallet)
            .setMessage(getString(R.string.you_are, walletName))
            .setPositiveButton(android.R.string.ok) { _, _ ->
                daemonModel.commands.callAttr("delete_wallet", walletName)
            }
            .setNegativeButton(android.R.string.cancel, null)
    }
}


abstract class PasswordDialog : AlertDialogFragment() {
    override fun onBuildDialog(builder: AlertDialog.Builder) {
        builder.setTitle(R.string.password_required)
            .setView(R.layout.password)
            .setPositiveButton(android.R.string.ok, null)
            .setNegativeButton(android.R.string.cancel, null)
    }

    override fun onShowDialog(dialog: AlertDialog) {
        getSystemService(InputMethodManager::class)
            .showSoftInput(dialog.etPassword, InputMethodManager.SHOW_IMPLICIT)
        dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
            try {
                tryPassword(dialog.etPassword.text.toString())
            } catch (e: ToastException) {
                e.show()
            }
        }
    }

    override fun onResume() {
        super.onResume()
        try {
            tryPassword(null)
        } catch (e: ToastException) {}
    }

    fun tryPassword(password: String?) {
        try {
            onPassword(password)
            dismiss()
        } catch (e: PyException) {
            throw if (e.message!!.startsWith("InvalidPassword"))
                ToastException(R.string.password_incorrect, Toast.LENGTH_SHORT) else e
        }
    }

    /** Attempt to perform the operation with the given password. `null` means to try with no
     * password, which will automatically be attempted when the dialog first opens. If the
     * operation fails, this method should throw either a ToastException, or an InvalidPassword
     * PyException (most lib functions that take passwords will do this automatically). */
    abstract fun onPassword(password: String?)
}


class OpenWalletDialog: PasswordDialog() {
    override fun onPassword(password: String?) {
        daemonModel.loadWallet(arguments!!.getString("walletName"), password)
    }
}


class ShowSeedPasswordDialog : PasswordDialog() {
    override fun onPassword(password: String?) {
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
            .setView(R.layout.seed)
            .setPositiveButton(android.R.string.ok, null)
    }

    override fun onShowDialog(dialog: AlertDialog) {
        val seed = arguments!!.getString("seed")
        if (seed == null) {
            dialog.tvSeedLabel.setText(R.string.please_enter)
        } else {
            dialog.tvSeedLabel.setText(seedAdvice(seed))
            dialog.etSeed.setText(seed)
            dialog.etSeed.setFocusable(false)
        }
    }
}


fun seedAdvice(seed: String): String {
    return app.getString(R.string.please_save, seed.split(" ").size) + " " +
           app.getString(R.string.this_seed) + " " +
           app.getString(R.string.never_disclose)
}


class TransactionsAdapter(val transactions: PyObject)
    : BoundAdapter<TransactionModel>(R.layout.transaction) {

    override fun getItem(position: Int): TransactionModel {
        val t = transactions.callAttr("__getitem__", itemCount - position - 1)
        return TransactionModel(
            t.callAttr("__getitem__", "value").toString(),
            t.callAttr("__getitem__", "balance").toString(),
            t.callAttr("__getitem__", "date").toString())
    }

    override fun getItemCount(): Int {
        return transactions.callAttr("__len__").toJava(Int::class.java)
    }
}

// TODO: eliminate this once Chaquopy provides better syntax for dict access.
class TransactionModel(
    val value: String,
    val balance: String,
    val date: String)
