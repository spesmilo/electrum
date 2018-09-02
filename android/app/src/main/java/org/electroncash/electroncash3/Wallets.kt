package org.electroncash.electroncash3

import android.app.Dialog
import android.arch.lifecycle.Observer
import android.content.DialogInterface
import android.os.Bundle
import android.support.v7.app.AlertDialog
import android.support.v7.widget.DividerItemDecoration
import android.support.v7.widget.LinearLayoutManager
import android.view.*
import android.widget.Toast
import com.chaquo.python.PyException
import com.chaquo.python.PyObject
import kotlinx.android.synthetic.main.main.*
import kotlinx.android.synthetic.main.wallets.*
import kotlinx.android.synthetic.main.password.*
import org.electroncash.electroncash3.databinding.WalletsBinding


class WalletsFragment : MainFragment() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setHasOptionsMenu(true)
        daemonModel.height.observe(this, Observer { height ->
            if (height != null) {
                title.value = getString(R.string.online)
                subtitle.value = "${getString(R.string.height)} $height"
            } else {
                title.value = getString(R.string.offline)
                subtitle.value = getString(R.string.cannot_send)
            }
        })
        daemonModel.walletName.observe(this, Observer {
            activity.invalidateOptionsMenu()
        })
    }

    override fun onPrepareOptionsMenu(menu: Menu) {
        menu.clear()
        if (daemonModel.walletName.value != null) {
            activity.menuInflater.inflate(R.menu.wallets, menu)
        }
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        when (item.itemId) {
            R.id.menuShowSeed-> showDialog(activity, ShowSeedPasswordDialog())
            R.id.menuDelete -> showDialog(activity, DeleteWalletDialog())
            R.id.menuClose -> daemonModel.commands.callAttr("close_wallet")
            else -> return false
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

    override fun onViewCreated(view: View?, savedInstanceState: Bundle?) {
        walletPanel.setOnClickListener {
            showDialog(activity, SelectWalletDialog())
        }

        with (rvTransactions) {
            layoutManager = LinearLayoutManager(activity)
            addItemDecoration(DividerItemDecoration(context, DividerItemDecoration.VERTICAL))
        }
        daemonModel.walletTransactions.observe(this, Observer {
            rvTransactions.adapter = if (it == null) null else TransactionsAdapter(it)
        })

        btnSend.setOnClickListener {
            // TODO
        }

        btnReceive.setOnClickListener {
            // TODO
            toast(R.string.touch_to_copy, Toast.LENGTH_LONG)
            mainActivity.navigation.selectedItemId = R.id.navAddresses
        }
    }
}


// TODO integrate into Wallets screen like in the iOS app.
class SelectWalletDialog : MainDialogFragment(), DialogInterface.OnClickListener {
    val items = ArrayList<String>()

    override fun onCreateDialog(savedInstanceState: Bundle?): Dialog {
        var checkedItem = -1
        val walletNames = daemonModel.commands.callAttr("list_wallets")
        for (i in 0 until walletNames.callAttr("__len__").toJava(Int::class.java)) {
            val name = walletNames.callAttr("__getitem__", i).toString()
            items.add(name)
            if (name == daemonModel.walletName.value) {
                checkedItem = i
            }
        }
        items.add(getString(R.string.new_restore))

        return AlertDialog.Builder(context)
            .setTitle(R.string.wallets)
            .setSingleChoiceItems(items.toTypedArray(), checkedItem, this)
            .create()
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
            showDialog(activity, OpenWalletDialog().apply { arguments = Bundle().apply {
                putString("walletName", items[which])
            }})
        } else {
            // TODO showDialog(activity, NewWalletDialog())
        }
    }
}


class DeleteWalletDialog : AlertDialogFragment() {
    override fun onBuildDialog(builder: AlertDialog.Builder) {
        val walletName = daemonModel.walletName.value
        builder.setTitle(R.string.delete_wallet)
            .setMessage(getString(R.string.you_are, walletName))
            .setPositiveButton(android.R.string.ok) { dialog, which ->
                daemonModel.commands.callAttr("delete_wallet", walletName)
            }
            .setNegativeButton(android.R.string.cancel, null)
    }
}


// TODO: keyboard should open automatically
abstract class PasswordDialog : AlertDialogFragment() {
    override fun onBuildDialog(builder: AlertDialog.Builder) {
        builder.setTitle(R.string.password_required)
            .setView(R.layout.password)
            .setPositiveButton(android.R.string.ok, null)
            .setNegativeButton(android.R.string.cancel, null)
    }

    override fun onPrepareDialog(dialog: AlertDialog) {
        dialog.setOnShowListener {
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                if (!tryPassword(dialog.etPassword.text.toString())) {
                    toast(R.string.password_incorrect, Toast.LENGTH_SHORT)
                } else {
                    dismiss()
                }
            }
        }
    }

    override fun onResume() {
        super.onResume()
        if (tryPassword(null)) {
            dismiss()
        }
    }

    fun tryPassword(password: String?): Boolean {
        try {
            onPassword(password)
            return true
        } catch (e: PyException) {
            if (e.message!!.startsWith("InvalidPassword")) {
                return false
            }
            throw e
        }
    }

    /** Attempt to perform the operation with the given password. `null` means to try with no
     * password, which will automatically be attempted when the dialog first opens. If the
     * password is wrong, overrides should throw PyException with the type InvalidPassword.
     * Most back-end functions that take passwords will do this automatically. */
    abstract fun onPassword(password: String?)
}


class OpenWalletDialog: PasswordDialog() {
    override fun onPassword(password: String?) {
        val name = arguments.getString("walletName")
        val prevName = daemonModel.walletName.value
        daemonModel.commands.callAttr("load_wallet", name, password)
        if (prevName != null && prevName != name) {
            daemonModel.commands.callAttr("close_wallet", prevName)
        }
    }
}


class ShowSeedPasswordDialog : PasswordDialog() {
    override fun onPassword(password: String?) {
        val seed = daemonModel.wallet!!.callAttr("get_seed", password).toString()
        if (! seed.contains(" ")) {
            // get_seed(None) doesn't throw an exception, but returns the encrypted base64 seed.
            throw PyException("InvalidPassword")
        }
        showDialog(activity, ShowSeedDialog().apply { arguments = Bundle().apply {
            putString("seed", seed)
        }})
    }
}

class ShowSeedDialog : AlertDialogFragment() {
    override fun onBuildDialog(builder: AlertDialog.Builder) {
        val seed = arguments.getString("seed")
        builder.setTitle(R.string.wallet_seed)
            .setMessage(seedAdvice(seed) + "\n\n" + seed)
            .setPositiveButton(android.R.string.ok, null)
    }
}


fun seedAdvice(seed: String): String {
    return App.context.getString(R.string.please_save, seed.split(" ").size) + " " +
           App.context.getString(R.string.this_seed) + " " +
           App.context.getString(R.string.never_disclose)
}


class TransactionsAdapter(val transactions: PyObject)
    : BoundAdapter(R.layout.transaction) {

    override fun getItem(position: Int): Any {
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
