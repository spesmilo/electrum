@file:Suppress("PARAMETER_NAME_CHANGED_ON_OVERRIDE")

package org.electroncash.electroncash3

import android.annotation.SuppressLint
import android.app.Activity
import android.content.DialogInterface
import android.content.Intent
import android.content.res.Configuration
import android.net.Uri
import android.os.Bundle
import android.text.Html
import android.text.SpannableStringBuilder
import android.text.method.LinkMovementMethod
import android.view.LayoutInflater
import android.view.Menu
import android.view.MenuItem
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import android.widget.AdapterView
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.FileProvider
import androidx.core.view.MenuCompat
import androidx.drawerlayout.widget.DrawerLayout
import androidx.fragment.app.Fragment
import androidx.lifecycle.observe
import com.chaquo.python.Kwarg
import com.chaquo.python.PyException
import com.chaquo.python.PyObject
import kotlinx.android.synthetic.main.main.*
import kotlinx.android.synthetic.main.show_master_key.walletMasterKey
import kotlinx.android.synthetic.main.wallet_export.*
import kotlinx.android.synthetic.main.wallet_information.*
import kotlinx.android.synthetic.main.wallet_open.*
import kotlinx.android.synthetic.main.wallet_rename.*
import java.io.File
import kotlin.reflect.KClass


// Drawer navigation
val ACTIVITIES = HashMap<Int, KClass<out Activity>>().apply {
    put(R.id.navSettings, SettingsActivity::class)
    put(R.id.navNetwork, NetworkActivity::class)
    put(R.id.navConsole, ECConsoleActivity::class)
}

// Bottom navigation
val FRAGMENTS = HashMap<Int, KClass<out Fragment>>().apply {
    put(R.id.navNoWallet, WalletNotOpenFragment::class)
    put(R.id.navTransactions, TransactionsFragment::class)
    put(R.id.navRequests, RequestsFragment::class)
    put(R.id.navAddresses, AddressesFragment::class)
    put(R.id.navContacts, ContactsFragment::class)
}

interface MainFragment


class MainActivity : AppCompatActivity(R.layout.main) {
    var cleanStart = true
    var newIntent = true
    var walletName: String? = null
    var viewStateRestored = false
    var pendingDrawerItem: MenuItem? = null

    override fun onCreate(state: Bundle?) {
        // Remove splash screen: doesn't work if called after super.onCreate.
        setTheme(R.style.AppTheme_NoActionBar)

        // If the system language changes while the app is running, the activity will be
        // restarted, but not the process.
        setLocale(this)

        // If the wallet name doesn't match, the process has probably been restarted, so
        // ignore the UI state, including all dialogs.
        if (state != null) {
            walletName = state.getString("walletName")
            cleanStart = (walletName != daemonModel.walletName)
        }
        super.onCreate(if (!cleanStart) state else null)

        setSupportActionBar(toolbar)
        supportActionBar!!.apply {
            setDisplayHomeAsUpEnabled(true)
            setHomeAsUpIndicator(R.drawable.ic_menu_24dp)
        }

        navDrawer.setNavigationItemSelectedListener { item ->
            // Running two transitions at a time can cause flashing or jank, so delay the
            // action until the drawer close animation completes,
            closeDrawer()
            pendingDrawerItem = item
            false
        }
        drawer.addDrawerListener(object : DrawerLayout.SimpleDrawerListener() {
            override fun onDrawerClosed(drawerView: View) {
                if (pendingDrawerItem != null) {
                    onDrawerItemSelected(pendingDrawerItem!!)
                    pendingDrawerItem = null
                }
            }
        })
        updateDrawer()

        navBottom.setOnNavigationItemSelectedListener {
            showFragment(it.itemId)
            true
        }

        daemonUpdate.observe(this, { refresh() })
        caption.observe(this, ::onCaption)

        // LiveData observers are activated after onStart returns. But this means that if an
        // observer modifies a view, the modification could be undone by
        // onRestoreInstanceState. This isn't a problem in the Fragment lifecycle because it
        // restores view state before calling onStart. So we do the same at the activity level.
        //
        // I considered fixing this by delaying the lifecycle start event until onPostCreate,
        // but this was more awkward because of the way lifecycle events are driven by
        // ReportFragment. Also, this would require overriding ComponentActivity.getLifecycle,
        // whose documentation says it will be made final in a future version.
        if (state != null) {
            onRestoreInstanceState(state)
        }
    }

    fun refresh() {
        val newWalletName = daemonModel.walletName
        if (cleanStart || (newWalletName != walletName)) {
            walletName = newWalletName
            invalidateOptionsMenu()
            clearFragments()
            navBottom.selectedItemId = if (walletName == null) R.id.navNoWallet
                                       else R.id.navTransactions
        }
    }

    override fun onBackPressed() {
        if (drawer.isDrawerOpen(navDrawer)) {
            closeDrawer()
        } else if (daemonModel.wallet != null) {
            // We allow the wallet to be closed using the Back button because the Close command
            // in the top right menu isn't very obvious. However, we require confirmation so
            // the user doesn't close it accidentally by pressing Back too many times.
            showDialog(this, WalletCloseConfirmDialog())
        } else {
            super.onBackPressed()
        }
    }

    fun onCaption(caption: Caption) {
        val walletName = caption.walletName ?: app.getString(R.string.No_wallet)
        if (resources.configuration.orientation == Configuration.ORIENTATION_PORTRAIT) {
            setTitle(walletName)
            supportActionBar!!.setSubtitle(caption.subtitle)
        } else {
            // Landscape subtitle is too small, so combine it with the title.
            setTitle("$walletName | ${caption.subtitle}")
        }
    }

    fun openDrawer() {
        drawer.openDrawer(navDrawer)
    }

    fun closeDrawer() {
        drawer.closeDrawer(navDrawer)
    }

    fun updateDrawer() {
        val loadedWalletName = daemonModel.walletName
        val menu = navDrawer.menu
        menu.clear()

        // New menu items are added at the bottom regardless of their group ID, so we inflate
        // the fixed items in two parts.
        navDrawer.inflateMenu(R.menu.nav_drawer_1)
        for (walletName in daemonModel.listWallets()) {
            val item = menu.add(R.id.navWallets, Menu.NONE, Menu.NONE, walletName)
            item.setIcon(R.drawable.ic_wallet_24dp)
            if (walletName == loadedWalletName) {
                item.setCheckable(true)
                item.setChecked(true)
            }
        }
        navDrawer.inflateMenu(R.menu.nav_drawer_2)
    }

    fun onDrawerItemSelected(item: MenuItem): Boolean {
        val activityCls = ACTIVITIES[item.itemId]
        if (activityCls != null) {
            startActivity(Intent(this, activityCls.java))
        } else if (item.itemId == R.id.navNewWallet) {
            showDialog(this, NewWalletDialog1())
        } else if (item.itemId == Menu.NONE) {
            val walletName = item.title.toString()
            if (walletName != daemonModel.walletName) {
                showDialog(this, WalletOpenDialog().apply { arguments = Bundle().apply {
                    putString("walletName", walletName)
                }})
            }
        } else if (item.itemId == R.id.navAbout) {
            showDialog(this, AboutDialog())
        } else {
            throw Exception("Unknown item $item")
        }
        return false
    }

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        val wallet = daemonModel.wallet
        if (wallet != null) {
            menuInflater.inflate(R.menu.wallet, menu)
            MenuCompat.setGroupDividerEnabled(menu, true)
            menu.findItem(R.id.menuUseChange)!!.isChecked =
                wallet.get("use_change")!!.toBoolean()
        }
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        when (item.itemId) {
            android.R.id.home -> openDrawer()
            R.id.menuUseChange -> {
                item.isChecked = !item.isChecked
                val useChange = item.isChecked  // Save thread shouldn't access UI object `item`.
                val wallet = daemonModel.wallet!!
                wallet.put("use_change", useChange)
                saveWallet(wallet) {
                    wallet.get("storage")!!.callAttr("put", "use_change", useChange)
                }
            }
            R.id.menuChangePassword -> showDialog(this, PasswordChangeDialog())
            R.id.menuWalletInformation -> { showDialog(this, WalletInformationDialog()) }
            R.id.menuSignTx -> {
                try {
                    showDialog(this, SendDialog().apply {
                        arguments = Bundle().apply { putBoolean("unbroadcasted", true) }
                    })
                } catch (e: ToastException) { e.show() }
            }
            R.id.menuLoadTx -> { showDialog(this, ColdLoadDialog()) }
            R.id.menuSweep -> showDialog(this, SweepDialog())
            R.id.menuExport -> showDialog(this, WalletExportDialog().apply {
                arguments = Bundle().apply { putString("walletName", daemonModel.walletName) }
            })
            R.id.menuClose -> showDialog(this, WalletCloseDialog())
            else -> throw Exception("Unknown item $item")
        }
        return true
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putBoolean("newIntent", newIntent)
        outState.putString("walletName", walletName)
    }

    override fun onRestoreInstanceState(state: Bundle) {
        if (viewStateRestored) return
        viewStateRestored = true

        if (!cleanStart) {
            super.onRestoreInstanceState(state)
        }
        newIntent = state.getBoolean("newIntent")
    }

    override fun onPostCreate(state: Bundle?) {
        super.onPostCreate(if (!cleanStart) state else null)
    }

    // setIntent only takes effect on the current instance of the activity: after a rotation,
    // the original intent will be restored.
    override fun onNewIntent(intent: Intent?) {
        super.onNewIntent(intent)
        setIntent(intent)
        newIntent = true
    }

    override fun onResume() {
        super.onResume()
        if (newIntent) {
            newIntent = false
            val uri = intent?.data
            if (uri != null) {
                if (daemonModel.wallet == null) {
                    toast(R.string.no_wallet_is_open_)
                    openDrawer()
                } else {
                    try {
                        var dialog = findDialog(this, SendDialog::class)
                        if (dialog == null) {
                            dialog = SendDialog()
                            showDialog(this, dialog)
                        }
                        dialog.onUri(uri.toString())
                    } catch (e: ToastException) { e.show() }
                }
            }
        }
    }

    override fun onResumeFragments() {
        super.onResumeFragments()
        showFragment(navBottom.selectedItemId)
        if (cleanStart) {
            cleanStart = false
            if (daemonModel.wallet == null) {
                openDrawer()
            }
        }
    }

    fun showFragment(id: Int) {
        val ft = supportFragmentManager.beginTransaction()
        val newFrag = getOrCreateFragment(id)
        for (frag in supportFragmentManager.fragments) {
            if (frag is MainFragment && frag !== newFrag) {
                ft.detach(frag)
            }
        }
        ft.attach(newFrag)
        ft.commitNow()

        navBottom.visibility = if (newFrag is WalletNotOpenFragment) View.GONE else View.VISIBLE
    }

    fun getFragment(id: Int): Fragment? {
        return supportFragmentManager.findFragmentByTag(fragTag(id))
    }

    fun getOrCreateFragment(id: Int): Fragment {
        var frag = getFragment(id)
        if (frag != null) {
            return frag
        } else {
            frag = FRAGMENTS[id]!!.java.newInstance()
            supportFragmentManager.beginTransaction()
                .add(flContent.id, frag, fragTag(id))
                .commitNow()
            return frag
        }
    }

    fun clearFragments() {
        val ft = supportFragmentManager.beginTransaction()
        for (id in FRAGMENTS.keys) {
            val frag = getFragment(id)
            if (frag != null) {
                ft.remove(frag)
            }
        }
        ft.commitNow()
    }

    fun fragTag(id: Int) = "MainFragment:$id"
}


class WalletNotOpenFragment : Fragment(), MainFragment {
    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?,
                              savedInstanceState: Bundle?): View? {
        return inflater.inflate(R.layout.wallet_not_open, container, false)
    }
}


class AboutDialog : AlertDialogFragment() {
    override fun onBuildDialog(builder: AlertDialog.Builder) {
        with (builder) {
            val version = app.packageManager.getPackageInfo(app.packageName, 0).versionName
            setTitle(getString(R.string.app_name) + " " + version)
            val message = SpannableStringBuilder()
            listOf(R.string.copyright_2017, R.string.made_with, R.string.for_support)
                .forEachIndexed { i, stringId ->
                    if (i != 0) {
                        message.append("\n\n")
                    }
                    @Suppress("DEPRECATION")
                    message.append(Html.fromHtml(getString(stringId)))
                }
            setMessage(message)
        }
    }

    override fun onShowDialog() {
        dialog.findViewById<TextView>(android.R.id.message)!!.movementMethod =
            LinkMovementMethod.getInstance()
    }
}


class WalletOpenDialog : PasswordDialog<String>() {
    val walletName by lazy { arguments!!.getString("walletName")!! }

    override fun onPassword(password: String): String {
        try {
            daemonModel.loadWallet(walletName, password)
        } catch (e: PyException) {
            throw if (e.message!!.startsWith("OSError"))  // Probably a corrupt file (#2232)
                ToastException(e) else e
        }
        return walletName
    }

    override fun onPostExecute(result: String) {
        daemonModel.commands.callAttr("select_wallet", result)
        (activity as MainActivity).updateDrawer()
    }

    override fun onBuildDialog(builder: AlertDialog.Builder) {
        super.onBuildDialog(builder)
        builder.setView(R.layout.wallet_open)
                .setNeutralButton(R.string.Delete, null)
                .setTitle("")
    }

    override fun onShowDialog() {
        super.onShowDialog()
        tvTitle.text = walletName
        btnRename.setOnClickListener {
            showDialog(this, WalletRenameDialog().apply {
                arguments = Bundle().apply { putString("walletName", walletName) }
            })
            dismiss()
        }
        btnExport.setOnClickListener {
            showDialog(this, WalletExportDialog().apply {
                arguments = Bundle().apply { putString("walletName", walletName) }
            })
            dismiss()
        }
        dialog.getButton(AlertDialog.BUTTON_NEUTRAL).setOnClickListener {
            showDialog(activity!!, WalletDeleteConfirmDialog().apply {
                arguments = Bundle().apply { putString("walletName", walletName) }
            })
            dismiss()
        }
    }
}


class WalletDeleteConfirmDialog : AlertDialogFragment() {
    override fun onBuildDialog(builder: AlertDialog.Builder) {
        val walletName = arguments!!.getString("walletName")!!
        val message = getString(R.string.are_you_sure_you_want_to_delete, walletName) +
                      "\n\n" + getString(R.string.if_your)
        builder.setTitle(R.string.confirm_delete)
            .setMessage(message)
            .setPositiveButton(R.string.delete, { _, _ ->
                showDialog(activity!!, WalletDeleteDialog().apply {
                    arguments = Bundle().apply { putString("walletName", walletName) }
                })
            })
            .setNegativeButton(android.R.string.cancel, null)
    }
}


class WalletDeleteDialog : WalletCloseDialog() {
    override fun onPreExecute() {
        walletName = arguments!!.getString("walletName")!!
        if (walletName == daemonModel.walletName) {
            daemonModel.commands.callAttr("select_wallet", null)
        }
    }

    override fun doInBackground() {
        super.doInBackground()
        daemonModel.commands.callAttr("delete_wallet", walletName)
    }
}


class WalletCloseConfirmDialog : AlertDialogFragment() {
    override fun onBuildDialog(builder: AlertDialog.Builder) {
        builder.setTitle(daemonModel.walletName!!)
            .setMessage(R.string.do_you_want_to_close)
            .setPositiveButton(R.string.close_wallet, { _, _ ->
                showDialog(activity!!, WalletCloseDialog())
            })
            .setNegativeButton(android.R.string.cancel, null)
    }
}


open class WalletCloseDialog : TaskDialog<Unit>() {
    var walletName: String? = null

    override fun onPreExecute() {
        walletName = daemonModel.walletName
        daemonModel.commands.callAttr("select_wallet", null)
    }

    override fun doInBackground() {
        // It should be impossible for this to be null, but it looks like there's still a race
        // condition somewhere (#1872).
        if (walletName != null) {
            waitForSave()
            daemonModel.commands.callAttr("close_wallet", walletName)
        }
    }

    override fun onPostExecute(result: Unit) {
        with (activity as MainActivity) {
            updateDrawer()
            openDrawer()
        }
    }
}


class PasswordChangeDialog : PasswordDialog<Unit>() {
    lateinit var newPassword: String

    override fun onBuildDialog(builder: AlertDialog.Builder) {
        builder.setTitle(R.string.Change_password)
            .setView(R.layout.password_change)
            .setPositiveButton(android.R.string.ok, null)
            .setNegativeButton(android.R.string.cancel, null)
    }

    override fun onPreExecute() {
        super.onPreExecute()
        newPassword = confirmPassword(dialog)
    }

    override fun onPassword(password: String) {
        val wallet = daemonModel.wallet!!
        wallet.callAttr("update_password", password, newPassword, Kwarg("encrypt", true))
        toast(R.string.password_was, Toast.LENGTH_SHORT)
    }
}


class WalletRenameDialog : TaskLauncherDialog<String?>() {
    private val walletName by lazy { arguments!!.getString("walletName")!! }
    private lateinit var newWalletName: String

    override fun onBuildDialog(builder: AlertDialog.Builder) {
        builder.setTitle(R.string.Rename_wallet)
                .setView(R.layout.wallet_rename)
                .setPositiveButton(android.R.string.ok, null)
                .setNegativeButton(android.R.string.cancel, null)
    }

    override fun onCreateDialog(savedInstanceState: Bundle?): AlertDialog {
        val dialog = super.onCreateDialog(savedInstanceState)
        dialog.window!!.setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_VISIBLE)
        return dialog
    }

    override fun onFirstShowDialog() {
        etWalletName.setText(walletName)
        etWalletName.setSelection(0, etWalletName.getText().length)
    }

    override fun onPreExecute() {
        newWalletName = etWalletName.text.toString()
    }

    override fun doInBackground(): String? {
        if (newWalletName == walletName) {
            return null
        } else {
            validateWalletName(newWalletName)
            waitForSave()
            daemonModel.commands.callAttr("rename_wallet", walletName, newWalletName)
            toast(R.string.wallet_renamed, Toast.LENGTH_SHORT)
            return newWalletName
        }
    }

    override fun onPostExecute(newWalletName: String?) {
        if (newWalletName != null) {
            showDialog((activity as MainActivity), WalletOpenDialog().apply {
                arguments = Bundle().apply { putString("walletName", newWalletName) }
            })
        }
        (activity as MainActivity).updateDrawer()
    }
}

class WalletExportDialog : TaskLauncherDialog<Uri>() {
    private val walletName by lazy { arguments!!.getString("walletName")!! }
    private lateinit var exportFileName: String

    override fun onBuildDialog(builder: AlertDialog.Builder) {
        builder.setTitle(R.string.export_wallet)
                .setView(R.layout.wallet_export)
                .setPositiveButton(android.R.string.ok, null)
                .setNegativeButton(android.R.string.cancel, null)
    }

    override fun onCreateDialog(savedInstanceState: Bundle?): AlertDialog {
        val dialog = super.onCreateDialog(savedInstanceState)
        dialog.window!!.setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_VISIBLE)
        return dialog
    }

    @SuppressLint("SetTextI18n")
    override fun onFirstShowDialog() {
        val walletName = arguments!!.getString("walletName")!!
        etExportFileName.setText(walletName)
        etExportFileName.setSelection(0, etExportFileName.getText().length)
    }

    override fun onPreExecute() {
        exportFileName = etExportFileName.text.toString()
        validateFilename(exportFileName)
    }

    override fun doInBackground(): Uri {
        val exportDir = File(activity!!.cacheDir, "wallet_exports")
        exportDir.deleteRecursively() // To ensure no more than one temp file lingers
        val exportFilePath = "$exportDir/$exportFileName"
        waitForSave()
        val exportFile = File(exportFilePath)
        val exportFileUri: Uri = FileProvider.getUriForFile(app,
            "org.electroncash.wallet.wallet_exports", exportFile)
        daemonModel.commands.callAttr("copy_wallet", walletName, exportFilePath)
        return exportFileUri
    }

    override fun onPostExecute(exportFileUri: Uri) {
        val sendIntent = Intent()
        sendIntent.type = "application/octet-stream"
        sendIntent.action = Intent.ACTION_SEND
        sendIntent.putExtra(Intent.EXTRA_STREAM, exportFileUri)
        startActivity(Intent.createChooser(sendIntent, "SHARE"))
    }
}


data class SeedResult(val seed: String, val passphrase: String)


class SeedPasswordDialog : PasswordDialog<SeedResult>() {
    override fun onPassword(password: String): SeedResult {
        val keystore = daemonModel.wallet!!.callAttr("get_keystore")!!
        return SeedResult(keystore.callAttr("get_seed", password).toString(),
                              keystore.callAttr("get_passphrase", password).toString())
    }

    override fun onPostExecute(result: SeedResult) {
        showDialog(activity!!, SeedDialog().apply { arguments = Bundle().apply {
            putString("seed", result.seed)
            putString("passphrase", result.passphrase)
        }})
    }
}

class SeedDialog : AlertDialogFragment() {
    override fun onBuildDialog(builder: AlertDialog.Builder) {
        builder.setTitle(R.string.Wallet_seed)
                .setView(R.layout.wallet_new_2)
                .setPositiveButton(android.R.string.ok, null)
    }

    override fun onShowDialog() {
        setupSeedDialog(this)
    }
}

class WalletInformationDialog : AlertDialogFragment() {
    override fun onBuildDialog(builder: AlertDialog.Builder) {
        builder.setView(R.layout.wallet_information)
            .setPositiveButton(android.R.string.ok, null)

        if (daemonModel.wallet!!.callAttr("has_seed").toBoolean()) {
            builder.setNeutralButton(R.string.show_seed, null)
        }
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        idWalletName.setText(daemonModel.walletName)
        idWalletType.setText(daemonModel.walletType)
        idScriptType.setText(daemonModel.scriptType)

        val mpks = daemonModel.wallet!!.callAttr("get_master_public_keys")?.asList()
        if (mpks != null && mpks.size != 0) {
            setupMasterKeys(mpks)
        } else {
            // Imported wallets do not have a master public key.
            tvMasterPublicKey.setVisibility(View.GONE)
            spnCosigners.setVisibility(View.GONE)
            walletMasterKey.setVisibility(View.GONE)
            // Using View.INVISIBLE on the 'Copy' button to preserve layout.
            (fabCopyMasterKey as View).setVisibility(View.INVISIBLE)
        }

        dialog.getButton(DialogInterface.BUTTON_NEUTRAL)?.setOnClickListener {
            showDialog(this, SeedPasswordDialog())
        }
    }

    private fun setupMasterKeys(mpks: List<PyObject>) {
        fabCopyMasterKey.setOnClickListener {
            val textToCopy = walletMasterKey.text
            copyToClipboard(textToCopy, R.string.Master_public_key)
        }
        walletMasterKey.setFocusable(false)

        // For multisig wallets, display a spinner with selectable cosigners.
        if (mpks.size > 1) {
            tvMasterPublicKey.setText(R.string.Master_public_keys)

            val captions = List(mpks.size, { getString(R.string.cosigner__d, it + 1) })
            spnCosigners.adapter = SimpleArrayAdapter(context!!, captions)
            spnCosigners.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
                override fun onItemSelected(parent: AdapterView<*>?, view: View?,
                                            position: Int, id: Long) {
                    walletMasterKey.setText(mpks[position].toString())
                }
                override fun onNothingSelected(parent: AdapterView<*>?) {}
            }
        } else {
            // For a standard wallet, display the single master public key.
            walletMasterKey.setText(mpks[0].toString())
            spnCosigners.setVisibility(View.GONE)
        }
    }
}
