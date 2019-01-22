package org.electroncash.electroncash3

import android.arch.lifecycle.LiveData
import android.arch.lifecycle.MutableLiveData
import android.arch.lifecycle.Observer
import android.os.Bundle
import android.support.v4.app.Fragment
import android.support.v7.app.AppCompatActivity
import kotlinx.android.synthetic.main.main.*
import kotlin.properties.Delegates.notNull
import kotlin.reflect.KClass


val FRAGMENTS = HashMap<Int, KClass<out Fragment>>().apply {
    put(R.id.navWallets, WalletsFragment::class)
    put(R.id.navRequests, RequestsFragment::class)
    put(R.id.navAddresses, AddressesFragment::class)
    put(R.id.navNetwork, NetworkFragment::class)
    put(R.id.navSettings, SettingsFragment::class)
}


class MainActivity : AppCompatActivity() {
    var stateValid: Boolean by notNull()
    var cleanStart = true

    override fun onCreate(state: Bundle?) {
        // Remove splash screen: doesn't work if called after super.onCreate.
        setTheme(R.style.AppTheme)

        // If the wallet name doesn't match, the process has probably been restarted, so
        // ignore the UI state, including all dialogs.
        stateValid = (state != null &&
                      (state.getString("walletName") == daemonModel.walletName.value))
        super.onCreate(if (stateValid) state else null)

        setContentView(R.layout.main)
        navigation.setOnNavigationItemSelectedListener {
            showFragment(it.itemId)
            true
        }
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putBoolean("cleanStart", cleanStart)
        outState.putString("walletName", daemonModel.walletName.value)
    }

    override fun onRestoreInstanceState(state: Bundle) {
        if (stateValid) {
            super.onRestoreInstanceState(state)
            cleanStart = state.getBoolean("cleanStart", true)
        }
    }

    override fun onPostCreate(state: Bundle?) {
        super.onPostCreate(if (stateValid) state else null)
    }

    override fun onResumeFragments() {
        super.onResumeFragments()
        showFragment(navigation.selectedItemId)
        if (cleanStart) {
            cleanStart = false
            if (daemonModel.wallet == null) {
                showDialog(this, SelectWalletDialog())
            }
        }
    }

    fun showFragment(id: Int) {
        val ft = supportFragmentManager.beginTransaction()
        val newFrag = getFragment(id)
        for (frag in supportFragmentManager.fragments) {
            if (frag is MainFragment && frag !== newFrag) {
                ft.detach(frag)
                frag.title.removeObservers(this)
                frag.subtitle.removeObservers(this)
            }
        }
        ft.attach(newFrag)
        if (newFrag is MainFragment) {
            newFrag.title.observe(this, Observer { setTitle(it ?: "") })
            newFrag.subtitle.observe(this, Observer { supportActionBar!!.setSubtitle(it) })
        }

        // BottomNavigationView onClick is sometimes triggered after state has been saved
        // (https://github.com/Electron-Cash/Electron-Cash/issues/1091).
        ft.commitNowAllowingStateLoss()
    }

    private fun getFragment(id: Int): Fragment {
        val tag = "MainFragment:$id"
        var frag = supportFragmentManager.findFragmentByTag(tag)
        if (frag != null) {
            return frag
        } else {
            frag = FRAGMENTS[id]!!.java.newInstance()
            supportFragmentManager.beginTransaction()
                .add(flContent.id, frag, tag).commitNowAllowingStateLoss()
            return frag
        }
    }
}


interface MainFragment {
    // To control the title or subtitle, override these with a MutableLiveData.
    val title: LiveData<String>
        get() = MutableLiveData<String>().apply { value = "" }
    val subtitle: LiveData<String>
        get() = MutableLiveData<String>().apply { value = null }
}

