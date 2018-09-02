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
            R.id.menuClose -> {
                daemonModel.commands.callAttr("close_wallet")
            }
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
            showDialog(mainActivity, SelectWalletDialog())
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

    override fun onClick(dialog: DialogInterface, which: Int) {
        dialog.dismiss()
        if (which < items.size - 1) {
            val walletName = items[which]
            if (!daemonModel.loadWallet(walletName)) {
                showDialog(activity, PasswordDialog().apply { arguments = Bundle().apply {
                    putString("walletName", walletName)
                }})
            }
        } else {
            // TODO showDialog(activity, NewWalletDialog())
        }
    }
}


class PasswordDialog : MainDialogFragment() {
    override fun onCreateDialog(savedInstanceState: Bundle?): Dialog {
        val dialog = AlertDialog.Builder(context)
            .setTitle(R.string.password_required)
            .setView(R.layout.password)
            .setPositiveButton(android.R.string.ok, null)
            .setNegativeButton(android.R.string.cancel, null)
            .create()

        dialog.setOnShowListener {
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                if (!daemonModel.loadWallet(arguments.getString("walletName"),
                                            dialog.etPassword.text.toString())) {
                    toast(R.string.password_incorrect, Toast.LENGTH_SHORT)
                } else {
                    dialog.dismiss()
                }
            }
        }
        return dialog
    }
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
