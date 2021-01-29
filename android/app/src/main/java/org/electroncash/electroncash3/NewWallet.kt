package org.electroncash.electroncash3

import android.app.Dialog
import android.content.Intent
import android.os.Bundle
import android.text.Selection
import android.view.View
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.fragment.app.DialogFragment
import com.chaquo.python.Kwarg
import com.chaquo.python.PyException
import com.google.zxing.integration.android.IntentIntegrator
import kotlinx.android.synthetic.main.wallet_new.*
import kotlinx.android.synthetic.main.wallet_new_2.*
import kotlin.properties.Delegates.notNull


val libKeystore by lazy { libMod("keystore") }
val libWallet by lazy { libMod("wallet") }


class NewWalletDialog1 : AlertDialogFragment() {
    override fun onBuildDialog(builder: AlertDialog.Builder) {
        builder.setTitle(R.string.New_wallet)
            .setView(R.layout.wallet_new)
            .setPositiveButton(R.string.next, null)
            .setNegativeButton(R.string.cancel, null)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        spnType.adapter = MenuAdapter(context!!, R.menu.wallet_type)
    }

    override fun onShowDialog() {
        dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
            try {
                val name = etName.text.toString()
                validateWalletName(name)
                val password = confirmPassword(dialog)
                val nextDialog: DialogFragment
                val arguments = Bundle().apply {
                    putString("name", name)
                    putString("password", password)
                }

                val walletType = spnType.selectedItemId.toInt()
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
                    throw Exception("Unknown item: ${spnType.selectedItem}")
                }
                showDialog(this, nextDialog.apply { setArguments(arguments) })
            } catch (e: ToastException) { e.show() }
        }
    }
}


fun validateWalletName(name: String) {
    if (name.isEmpty()) {
        throw ToastException(R.string.name_is)
    }
    if (name.contains("/")) {
        throw ToastException(R.string.wallet_names)
    }
    if (name.toByteArray().size > 200) {
        // The filesystem limit is probably 255, but we need to leave room for the temporary
        // filename suffix.
        throw ToastException(R.string.wallet_name_is_too)
    }
    if (daemonModel.listWallets().contains(name)) {
        throw ToastException(R.string.a_wallet_with_that_name_already_exists_please_enter)
    }
}


// Also called from PasswordChangeDialog.
fun confirmPassword(dialog: Dialog): String {
    val password = dialog.etNewPassword.text.toString()
    if (password.isEmpty()) throw ToastException(R.string.Enter_password, Toast.LENGTH_SHORT)
    if (password != dialog.etConfirmPassword.text.toString()) {
        throw ToastException(R.string.wallet_passwords)
    }
    return password
}


abstract class NewWalletDialog2 : TaskLauncherDialog<String>() {
    var input: String by notNull()

    override fun onBuildDialog(builder: AlertDialog.Builder) {
        builder.setTitle(R.string.New_wallet)
            .setView(R.layout.wallet_new_2)
            .setPositiveButton(android.R.string.ok, null)
            .setNegativeButton(R.string.back, null)
    }

    override fun onPreExecute() {
        input = etInput.text.toString()
    }

    override fun doInBackground(): String {
        val name = arguments!!.getString("name")!!
        val password = arguments!!.getString("password")!!
        onCreateWallet(name, password)
        daemonModel.loadWallet(name, password)
        return name
    }

    abstract fun onCreateWallet(name: String, password: String)

    override fun onPostExecute(result: String) {
        (targetFragment as NewWalletDialog1).dismiss()
        daemonModel.commands.callAttr("select_wallet", result)
        (activity as MainActivity).updateDrawer()
    }
}


class NewWalletSeedDialog : NewWalletDialog2() {
    var passphrase: String by notNull()
    var bip39: Boolean by notNull()
    var derivation: String? = null

    override fun onShowDialog() {
        super.onShowDialog()
        setupSeedDialog(this)
        if (arguments!!.getString("seed") == null) {  // Restore from seed
            bip39Panel.visibility = View.VISIBLE
            val bip39Listener = { etDerivation.isEnabled = swBip39.isChecked }
            swBip39.setOnCheckedChangeListener { _, _ -> bip39Listener() }
            bip39Listener()
        }
    }

    override fun onPreExecute() {
        super.onPreExecute()
        passphrase = etPassphrase.text.toString()
        bip39 = swBip39.isChecked
        if (bip39) {
            derivation = etDerivation.text.toString()
        }
    }

    override fun onCreateWallet(name: String, password: String) {
        try {
            if (derivation != null &&
                !libBitcoin.callAttr("is_bip32_derivation", derivation).toBoolean()) {
                throw ToastException(R.string.Derivation_invalid)
            }
            daemonModel.commands.callAttr(
                "create", name, password,
                Kwarg("seed", input),
                Kwarg("passphrase", passphrase),
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

    override fun onShowDialog() {
        super.onShowDialog()
        tvPrompt.setText(R.string.enter_a_list_of_bitcoin)
        dialog.getButton(AlertDialog.BUTTON_NEUTRAL).setOnClickListener { scanQR(this) }
    }

    override fun onCreateWallet(name: String, password: String) {
        var foundAddress = false
        var foundPrivkey = false
        for (word in input.split(Regex("\\s+"))) {
            if (word.isEmpty()) {
                // Can happen at start or end of list.
            } else if (clsAddress.callAttr("is_valid", word).toBoolean()) {
                foundAddress = true
            } else {
                try {
                    // Use the same function as the wallet creation process (#2133).
                    libAddress.get("PublicKey")!!.callAttr("from_WIF_privkey", word)
                    foundPrivkey = true
                } catch (e: PyException) {
                    throw ToastException(getString(R.string.not_a_valid, word))
                }
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
            val text = etInput.text
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

    override fun onShowDialog() {
        super.onShowDialog()
        tvPrompt.setText(getString(R.string.to_create_a_watching) + " " +
                                getString(R.string.to_create_a_spending))
        dialog.getButton(AlertDialog.BUTTON_NEUTRAL).setOnClickListener { scanQR(this) }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        val result = IntentIntegrator.parseActivityResult(requestCode, resultCode, data)
        if (result != null && result.contents != null) {
            etInput.setText(result.contents)
            etInput.setSelection(result.contents.length)
        } else {
            super.onActivityResult(requestCode, resultCode, data)
        }
    }

    override fun onCreateWallet(name: String, password: String) {
        val key = input.trim()
        if (libKeystore.callAttr("is_bip32_key", key).toBoolean()) {
            daemonModel.commands.callAttr("create", name, password, Kwarg("master", key))
        } else {
            throw ToastException(R.string.please_specify)
        }
    }
}


fun setupSeedDialog(fragment: AlertDialogFragment) {
    with (fragment) {
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
            tvPassphrasePrompt.setText(app.getString(R.string.you_may_extend) + " " +
                                       app.getString(R.string.if_you_are))
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
           app.getString(R.string.this_seed_will) + " " +
           app.getString(R.string.never_disclose)
}
