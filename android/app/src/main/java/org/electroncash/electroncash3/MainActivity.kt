package org.electroncash.electroncash3

import android.os.Bundle
import android.support.v4.app.Fragment
import android.support.v7.app.AppCompatActivity
import kotlinx.android.synthetic.main.activity_main.*

class MainActivity : AppCompatActivity() {

    val fragWallets = WalletsFragment()
    val fragAddresses = AddressesFragment()
    val fragConsole = ConsoleFragment()
    var currentFrag: Fragment? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val ft = supportFragmentManager.beginTransaction()
        for (frag in listOf(fragWallets, fragAddresses, fragConsole)) {
            ft.add(flContent.id, frag, null)
            ft.detach(frag)
        }
        ft.commit()
        setFragment(fragWallets)

        navigation.setOnNavigationItemSelectedListener {
            setFragment(when (it.itemId) {
                R.id.navWallets -> fragWallets
                R.id.navAddresses -> fragAddresses
                R.id.navConsole-> fragConsole
                else -> throw IllegalArgumentException(it.toString())
            })
            true
        }
    }

    private fun setFragment(newFrag: Fragment) {
        val ft = supportFragmentManager.beginTransaction()
        if (currentFrag != null) {
            ft.detach(currentFrag)
        }
        ft.attach(newFrag).commit()
        currentFrag = newFrag
    }
}
