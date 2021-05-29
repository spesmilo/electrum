package org.electroncash.electroncash3

import android.app.Dialog
import android.content.*
import android.os.Bundle
import android.text.Selection
import android.view.View
import android.widget.SeekBar
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.fragment.app.DialogFragment
import androidx.fragment.app.Fragment
import com.chaquo.python.Kwarg
import com.chaquo.python.PyException
import com.chaquo.python.PyObject
import com.google.zxing.integration.android.IntentIntegrator
import kotlinx.android.synthetic.main.choose_keystore.*
import kotlinx.android.synthetic.main.multisig_cosigners.*
import kotlinx.android.synthetic.main.show_master_key.*
import kotlinx.android.synthetic.main.wallet_new.*
import kotlinx.android.synthetic.main.wallet_new_2.*
import kotlin.properties.Delegates.notNull


val libKeystore by lazy { libMod("keystore") }
val libWallet by lazy { libMod("wallet") }

val keystores by lazy { ArrayList<PyObject>() }

val MAX_COSIGNERS = 15
val COSIGNER_OFFSET = 2 // min. number of multisig cosigners = 2
val SIGNATURE_OFFSET = 1 // min. number of req. multisig signatures = 1

class NewWalletDialog1 : AlertDialogFragment() {
    override fun onBuildDialog(builder: AlertDialog.Builder) {
        builder.setTitle(R.string.New_wallet)
            .setView(R.layout.wallet_new)
            .setPositiveButton(R.string.next, null)
            .setNegativeButton(R.string.cancel, null)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        spnWalletType.adapter = MenuAdapter(context!!, R.menu.wallet_kind)
    }

    override fun onShowDialog() {
        dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
            try {
                val name = etName.text.toString()
                validateWalletName(name)
                val password = confirmPassword(dialog)
                val arguments = Bundle().apply {
                    putString("name", name)
                    putString("password", password)
                }

                val nextDialog: DialogFragment = when (spnWalletType.selectedItemId.toInt()) {
                    R.id.menuStandardWallet -> {
                        KeystoreDialog()
                    }
                    R.id.menuMultisigWallet -> {
                        CosignerDialog()
                    }
                    R.id.menuImport -> {
                        NewWalletImportDialog()
                    }
                    else -> {
                        throw Exception("Unknown item: ${spnWalletType.selectedItem}")
                    }
                }
                showDialog(this, nextDialog.apply { setArguments(arguments) })
            } catch (e: ToastException) { e.show() }
        }
    }

    override fun onDismiss(dialog: DialogInterface) {
        super.onDismiss(dialog)
        keystores.clear()
    }
}

fun closeDialogs(targetFragment: Fragment) {
    (targetFragment as DialogFragment).dismiss()
    if (targetFragment.targetFragment != null) {
        closeDialogs(targetFragment.targetFragment!!)
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

// Choose the way of generating the wallet (new seed, import seed, etc.)
class KeystoreDialog : AlertDialogFragment() {
    override fun onBuildDialog(builder: AlertDialog.Builder) {
        builder.setTitle(R.string.keystore)
                .setView(R.layout.choose_keystore)
                .setPositiveButton(android.R.string.ok, null)
                .setNegativeButton(R.string.back, null)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        /* Choose the appropriate keystore dropdown, based on wallet type */
        val multisig = arguments!!.getBoolean("multisig")
        val currentCosigner = arguments!!.getInt("i_signer") //
        val numOfCosigners = arguments!!.getInt("cosigners")

        /* Handle dialog title for cosigners */
        if (multisig) {
            dialog.setTitle(getString(R.string.Add_cosigner) + " " +
                getString(R.string.__d_of, currentCosigner, numOfCosigners))
        }

        val keystoreMenu: Int
        if (multisig && currentCosigner != 1) {
            keystoreMenu = R.menu.cosigner_type
            keystoreDesc.setText(R.string.add_a)
        } else {
            keystoreMenu = R.menu.wallet_type
        }

        spnType.adapter = MenuAdapter(context!!, keystoreMenu)
    }

    override fun onShowDialog() {
        dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
            try {
                val nextDialog: DialogFragment
                val keystoreType = spnType.selectedItemId.toInt()
                if (keystoreType in listOf(R.id.menuCreateSeed, R.id.menuRestoreSeed)) {
                    nextDialog = NewWalletSeedDialog()
                    val seed = if (keystoreType == R.id.menuCreateSeed)
                        daemonModel.commands.callAttr("make_seed").toString()
                    else null
                    arguments!!.putString("seed", seed)
                } else if (keystoreType in listOf(R.id.menuImportMaster)) {
                    nextDialog = NewWalletImportMasterDialog()
                } else {
                    throw Exception("Unknown item: ${spnType.selectedItem}")
                }
                nextDialog.setArguments(arguments)
                showDialog(this, nextDialog)
            } catch (e: ToastException) { e.show() }
        }
    }
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

        val multisig = arguments!!.getBoolean("multisig")

        /**
         * For multisig wallets, wait until all cosigners have been added,
         * and then create and load the multisig wallet.
         *
         * Otherwise, load the created wallet.
         */
        if (multisig) {
            val currentCosigner = arguments!!.getInt("i_signer")
            val numCosigners = arguments!!.getInt("cosigners")
            val numSignatures = arguments!!.getInt("signatures")

            // Close the previous cosigner's keystore dialog.
            // TODO: Consider a better solution for closing dialogs?
            (targetFragment as KeystoreDialog).dismiss()

            if (currentCosigner == numCosigners) {
                daemonModel.commands.callAttr(
                        "create_multisig", name, password,
                        Kwarg("keystores", keystores.toArray()),
                        Kwarg("cosigners", numCosigners),
                        Kwarg("signatures", numSignatures)
                )
                daemonModel.loadWallet(name, password)
                closeDialogs(targetFragment!!)
            }
        } else {
            daemonModel.loadWallet(name, password)
        }

        return name
    }

    abstract fun onCreateWallet(name: String, password: String)

    override fun onPostExecute(result: String) {
        val multisig = arguments!!.getBoolean("multisig")

        /**
         * For multisig wallets, we need to first show the master key to the 1st cosigner, and
         * then prompt for data for all other cosigners by calling the KeystoreDialog again.
         */
        if (multisig) {
            val currentCosigner = arguments!!.getInt("i_signer")
            val numCosigners = arguments!!.getInt("cosigners")

            if (currentCosigner < numCosigners) {
                // The first cosigner sees their master public key; others are prompted for data
                val nextDialog: DialogFragment = if (currentCosigner == 1) {
                    MasterPublicKeyDialog()
                } else {
                    KeystoreDialog()
                }

                arguments!!.putInt("i_signer", currentCosigner + 1)

                nextDialog.setArguments(arguments)
                showDialog(this, nextDialog)
            } else { // last cosigner done; finalize wallet
                daemonModel.commands.callAttr("select_wallet", result)
                (activity as MainActivity).updateDrawer()
            }
        } else {
            // In a standard wallet, close the dialogs and open the newly created wallet.
            closeDialogs(targetFragment!!)
            daemonModel.commands.callAttr("select_wallet", result)
            (activity as MainActivity).updateDrawer()
        }
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

            val multisig = arguments!!.getBoolean("multisig")
            val ks = daemonModel.commands.callAttr(
                "create", name, password,
                Kwarg("seed", input),
                Kwarg("passphrase", passphrase),
                Kwarg("multisig", multisig),
                Kwarg("bip39_derivation", derivation))

            if (multisig) {
                keystores.add(ks)

                val masterKey = ks.callAttr("get_master_public_key").toString()
                arguments!!.putString("masterKey", masterKey)
            }

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

        val multisig = arguments!!.getBoolean("multisig")
        val currentCosigner = arguments!!.getInt("i_signer")

        val keyPrompt = if (multisig && currentCosigner != 1) {
            getString(R.string.please_enter_the_master_public_key_xpub) + " " +
            getString(R.string.enter_their)
        } else {
            getString(R.string.to_create_a_watching) + " " +
            getString(R.string.to_create_a_spending)
        }
        tvPrompt.setText(keyPrompt)

        if (multisig && currentCosigner != 1) {
            dialog.setTitle(getString(R.string.Add_cosigner) + " $currentCosigner")
        }

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
            val multisig = arguments!!.getBoolean("multisig")
            val ks = daemonModel.commands.callAttr(
                    "create", name, password,
                    Kwarg("master", key),
                    Kwarg("multisig", multisig)
            )

            if (multisig) {
                val masterKey = ks.callAttr("get_master_public_key").toString()
                arguments!!.putString("masterKey", masterKey)
                keystores.add(ks)
            }
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

// Choose the number of multi-sig wallet cosigners
class CosignerDialog : AlertDialogFragment() {
    override fun onBuildDialog(builder: AlertDialog.Builder) {
        builder.setTitle(R.string.Multi_signature)
                .setView(R.layout.multisig_cosigners)
                .setPositiveButton(R.string.next, null)
                .setNegativeButton(R.string.cancel, null)
    }

    val numCosigners: Int
        get() = sbCosigners.progress + COSIGNER_OFFSET

    val numSignatures: Int
        get() = sbSignatures.progress + SIGNATURE_OFFSET

    override fun onShowDialog() {
        super.onShowDialog()

        tvCosigners.text = getString(R.string.from_cosigners, 2)
        tvSignatures.text = getString(R.string.require_signatures, 2)

        // Handle the total number of cosigners
        with (sbCosigners) {
            progress = 0
            max = MAX_COSIGNERS - COSIGNER_OFFSET

            setOnSeekBarChangeListener(object : SeekBar.OnSeekBarChangeListener {
                override fun onProgressChanged(seekBar: SeekBar?, progress: Int, fromUser: Boolean) {
                    tvCosigners.text = getString(R.string.from_cosigners, numCosigners)
                    sbSignatures.max = numCosigners - 1
                }

                override fun onStartTrackingTouch(seekBar: SeekBar?) {}
                override fun onStopTrackingTouch(seekBar: SeekBar) {}
            })
        }

        // Handle the number of required signatures
        with (sbSignatures) {
            progress = numCosigners
            max = SIGNATURE_OFFSET

            setOnSeekBarChangeListener(object: SeekBar.OnSeekBarChangeListener {
                override fun onProgressChanged(seekBar: SeekBar?, progress: Int, fromUser: Boolean) {
                    tvSignatures.text = getString(R.string.require_signatures, numSignatures)
                }

                override fun onStartTrackingTouch(seekBar: SeekBar?) {}
                override fun onStopTrackingTouch(seekBar: SeekBar?) {}
            })
        }

        dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
            try {
                val nextDialog: DialogFragment = KeystoreDialog()

                arguments!!.putBoolean("multisig", true)
                arguments!!.putInt("i_signer", 1) // current co-signer; will update
                arguments!!.putInt("cosigners", numCosigners)
                arguments!!.putInt("signatures", numSignatures)

                nextDialog.setArguments(arguments)
                showDialog(this, nextDialog)
            } catch (e: ToastException) {
                e.show()
            }
        }
    }
}

/**
 * View and copy the master public key of the (multisig) wallet.
 */
class MasterPublicKeyDialog : AlertDialogFragment() {
    override fun onBuildDialog(builder: AlertDialog.Builder) {
        builder.setView(R.layout.show_master_key)
                .setPositiveButton(R.string.next, null)
                .setNegativeButton(R.string.back, null)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        fabCopyMasterKey.setOnClickListener {
            copyToClipboard(walletMasterKey.text, R.string.Master_public)
        }
    }

    override fun onShowDialog() {
        super.onShowDialog()

        walletMasterKey.setText(arguments!!.getString("masterKey"))
        walletMasterKey.setFocusable(false)

        dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
            try {
                val nextDialog: DialogFragment = KeystoreDialog()

                nextDialog.setArguments(arguments)
                showDialog(this, nextDialog)
            } catch (e: ToastException) {
                e.show()
            }
        }
    }
}

fun seedAdvice(seed: String): String {
    return app.getString(R.string.please_save, seed.split(" ").size) + " " +
           app.getString(R.string.this_seed_will) + " " +
           app.getString(R.string.never_disclose)
}
