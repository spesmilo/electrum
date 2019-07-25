package org.electroncash.electroncash3

import android.app.Dialog
import android.arch.lifecycle.MutableLiveData
import android.arch.lifecycle.Observer
import android.arch.lifecycle.ViewModel
import android.arch.lifecycle.ViewModelProviders
import android.content.Intent
import android.os.Bundle
import android.support.v4.app.DialogFragment
import android.support.v7.app.AlertDialog
import android.text.Selection
import android.view.View
import android.widget.Toast
import com.chaquo.python.Kwarg
import com.chaquo.python.PyException
import com.google.zxing.integration.android.IntentIntegrator
import kotlinx.android.synthetic.main.new_wallet.*
import kotlinx.android.synthetic.main.new_wallet_2.*


val libKeystore by lazy { libMod("keystore") }
val libWallet by lazy { libMod("wallet") }


class NewWalletDialog1 : AlertDialogFragment() {
    override fun onBuildDialog(builder: AlertDialog.Builder) {
        builder.setTitle(R.string.New_wallet)
            .setView(R.layout.new_wallet)
            .setPositiveButton(R.string.next, null)
            .setNegativeButton(R.string.cancel, null)
    }

    override fun onShowDialog(dialog: AlertDialog) {
        dialog.spnType.adapter = MenuAdapter(context!!, R.menu.wallet_type)

        dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
            try {
                val name = dialog.etName.text.toString()
                if (name.isEmpty()) throw ToastException(R.string.name_is, Toast.LENGTH_SHORT)
                if (name.contains("/")) throw ToastException(R.string.invalid_name)
                if (daemonModel.listWallets().contains(name)) {
                    throw ToastException(R.string.a_wallet_with_that_name_already_exists_please)
                }
                val password = confirmPassword(dialog)

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
                } else if (walletType == R.id.menuImportMaster) {
                    nextDialog = NewWalletImportMasterDialog()
                } else {
                    throw Exception("Unknown item: ${dialog.spnType.selectedItem}")
                }
                showDialog(activity!!, nextDialog.apply { setArguments(arguments) })
            } catch (e: ToastException) { e.show() }
        }
    }
}


fun confirmPassword(dialog: Dialog): String {
    val password = dialog.etPassword.text.toString()
    if (password.isEmpty()) throw ToastException(R.string.Enter_password, Toast.LENGTH_SHORT)
    if (password != dialog.etConfirmPassword.text.toString()) {
        throw ToastException(R.string.wallet_passwords)
    }
    return password
}


abstract class NewWalletDialog2 : AlertDialogFragment() {
    class Model : ViewModel() {
        val result = MutableLiveData<Boolean>()
    }
    private val model by lazy { ViewModelProviders.of(this).get(Model::class.java) }

    override fun onBuildDialog(builder: AlertDialog.Builder) {
        builder.setTitle(R.string.New_wallet)
            .setView(R.layout.new_wallet_2)
            .setPositiveButton(android.R.string.ok, null)
            .setNegativeButton(R.string.back, null)
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
            dismissDialog(activity!!, NewWalletDialog1::class)
        }
    }
}


class NewWalletSeedDialog : NewWalletDialog2() {
    override fun onShowDialog(dialog: AlertDialog) {
        super.onShowDialog(dialog)
        setupSeedDialog(this)
        if (arguments!!.getString("seed") == null) {  // Restore from seed
            dialog.bip39Panel.visibility = View.VISIBLE
            dialog.swBip39.setOnCheckedChangeListener { _, isChecked ->
                dialog.etDerivation.isEnabled = isChecked
            }
        }
    }

    override fun onCreateWallet(name: String, password: String, input: String) {
        try {
            val derivation: String?
            if (dialog.swBip39.isChecked) {
                derivation = dialog.etDerivation.text.toString()
                if (!libBitcoin.callAttr("is_bip32_derivation", derivation).toBoolean()) {
                    throw ToastException(R.string.derivation_invalid)
                }
            } else {
                derivation = null
            }

            daemonModel.commands.callAttr(
                "create", name, password,
                Kwarg("seed", input),
                Kwarg("passphrase", dialog.etPassphrase.text.toString()),
                Kwarg("bip39_derivation", derivation))
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
        builder.setNeutralButton(R.string.qr_code, null)
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
                throw ToastException(
                    R.string.cannot_specify_private_keys_and_addresses_in_the_same_wallet)
            }
            daemonModel.commands.callAttr("create", name, password, Kwarg("addresses", input))
        } else if (foundPrivkey) {
            daemonModel.commands.callAttr("create", name, password, Kwarg("privkeys", input))
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


class NewWalletImportMasterDialog : NewWalletDialog2() {
    override fun onBuildDialog(builder: AlertDialog.Builder) {
        super.onBuildDialog(builder)
        builder.setNeutralButton(R.string.qr_code, null)
    }

    override fun onShowDialog(dialog: AlertDialog) {
        super.onShowDialog(dialog)
        dialog.tvPrompt.setText(getString(R.string.to_create_a_watching) + " " +
                                getString(R.string.to_create_a_spending))
        dialog.getButton(AlertDialog.BUTTON_NEUTRAL).setOnClickListener { scanQR(this) }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        val result = IntentIntegrator.parseActivityResult(requestCode, resultCode, data)
        if (result != null && result.contents != null) {
            dialog.etInput.setText(result.contents)
            dialog.etInput.setSelection(result.contents.length)
        } else {
            super.onActivityResult(requestCode, resultCode, data)
        }
    }

    override fun onCreateWallet(name: String, password: String, input: String) {
        val key = input.trim()
        if (libKeystore.callAttr("is_bip32_key", key).toBoolean()) {
            daemonModel.commands.callAttr("create", name, password, Kwarg("master", key))
        } else {
            throw ToastException(R.string.please_specify)
        }
    }
}


fun setupSeedDialog(fragment: DialogFragment) {
    with (fragment.dialog) {
        val seed = fragment.arguments!!.getString("seed")
        if (seed == null) {
            // Import
            tvPrompt.setText(R.string.please_enter_your_seed_phrase)
        } else {
            // Generate or display
            tvPrompt.setText(seedAdvice(seed))
            etInput.setText(seed)
            etInput.setFocusable(false)
        }

        val passphrase = fragment.arguments!!.getString("passphrase")
        if (passphrase == null) {
            // Import or generate
            passphrasePanel.visibility = View.VISIBLE
            tvPassphrasePrompt.setText(R.string.please_enter_your_seed_derivation)
        } else {
            // Display
            if (passphrase.isNotEmpty()) {
                passphrasePanel.visibility = View.VISIBLE
                tvPassphrasePrompt.setText(R.string.passphrase)
                etPassphrase.setText(passphrase)
                etPassphrase.setFocusable(false)
            }
        }
    }
}


fun seedAdvice(seed: String): String {
    return app.getString(R.string.please_save, seed.split(" ").size) + " " +
           app.getString(R.string.this_seed) + " " +
           app.getString(R.string.never_disclose)
}
