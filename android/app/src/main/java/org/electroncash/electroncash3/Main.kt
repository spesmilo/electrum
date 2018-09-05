package org.electroncash.electroncash3

import android.app.Dialog
import android.arch.lifecycle.MutableLiveData
import android.arch.lifecycle.Observer
import android.arch.lifecycle.ViewModelProviders
import android.content.Intent
import android.os.Bundle
import android.support.v4.app.DialogFragment
import android.support.v4.app.Fragment
import android.support.v7.app.AlertDialog
import android.support.v7.app.AppCompatActivity
import kotlinx.android.synthetic.main.main.*


class MainActivity : AppCompatActivity() {
    // TODO: integrate console into MainActivity and remove this.
    companion object {
        var instance: MainActivity? = null
    }

    val FRAGMENTS = mapOf(
        R.id.navWallets to WalletsFragment::class,
        R.id.navAddresses to AddressesFragment::class
    )

    val daemonModel by lazy { ViewModelProviders.of(this).get(DaemonModel::class.java) }

    override fun onCreate(savedInstanceState: Bundle?) {
        instance = this
        super.onCreate(savedInstanceState)
        setContentView(R.layout.main)
        navigation.setOnNavigationItemSelectedListener {
            when (it.itemId) {
                R.id.navConsole -> {
                    startActivity(Intent(this, ECConsoleActivity::class.java))
                    false
                }
                else -> {
                    showFragment(it.itemId)
                    true
                }
            }
        }
    }

    override fun onResume() {
        super.onResume()
        showFragment(navigation.selectedItemId)
    }

    override fun onDestroy() {
        instance = null
        super.onDestroy()
    }

    fun showFragment(id: Int) {
        val ft = supportFragmentManager.beginTransaction()
        for (frag in supportFragmentManager.fragments) {
            if (frag is MainFragment) {
                ft.detach(frag)
                frag.title.removeObservers(this)
                frag.subtitle.removeObservers(this)
            }
        }
        val newFrag = getFragment(id)
        ft.attach(newFrag)
        newFrag.title.observe(this, Observer { setTitle(it ?: "") })
        newFrag.subtitle.observe(this, Observer { supportActionBar!!.setSubtitle(it) })
        ft.commit()
    }

    private fun getFragment(id: Int): MainFragment {
        val tag = "MainFragment:$id"
        var frag = supportFragmentManager.findFragmentByTag(tag)
        if (frag == null) {
            frag = FRAGMENTS[id]!!.java.newInstance()
            supportFragmentManager.beginTransaction()
                .add(flContent.id, frag, tag).commit()
        }
        return frag as MainFragment
    }
}


open class MainFragment : Fragment() {
    val mainActivity by lazy { activity as MainActivity }
    val daemonModel by lazy { mainActivity.daemonModel }

    val title = MutableLiveData<String>().apply { value = "" }
    val subtitle = MutableLiveData<String>().apply { value = null }
}

open class AlertDialogFragment : DialogFragment() {
    // TODO remove duplication
    val mainActivity by lazy {
        activity as MainActivity
    }
    val daemonModel by lazy { mainActivity.daemonModel }

    override fun onCreateDialog(savedInstanceState: Bundle?): Dialog {
        val builder = AlertDialog.Builder(context)
        onBuildDialog(builder)
        val dialog = builder.create()
        dialog.setOnShowListener { onShowDialog(dialog) }
        return dialog
    }

    open fun onBuildDialog(builder: AlertDialog.Builder) {}

    /** Can be used to do things like configure custom views, or attach listeners to buttons so
     *  they don't always close the dialog. */
    open fun onShowDialog(dialog: AlertDialog) {}
}

open class MessageDialog() : AlertDialogFragment() {
    constructor(title: String, message: String) : this() {
        arguments = Bundle().apply {
            putString("title", title)
            putString("message", message)
        }
    }
    override fun onBuildDialog(builder: AlertDialog.Builder) {
        builder.setTitle(arguments.getString("title"))
            .setMessage(arguments.getString("message"))
            .setPositiveButton(android.R.string.ok, null)
    }
}