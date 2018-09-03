package org.electroncash.electroncash3

import android.app.Application
import android.arch.lifecycle.AndroidViewModel
import android.arch.lifecycle.MutableLiveData
import android.os.Handler
import com.chaquo.python.PyObject
import com.chaquo.python.Python


val WATCHDOG_INTERVAL = 1000L
val py = Python.getInstance()
val daemonMod =  py.getModule("electroncash_gui.android.daemon")


class DaemonModel(val app: Application) : AndroidViewModel(app) {
    val handler = Handler()

    val commands: PyObject
    val daemon: PyObject
        get() = commands.get("daemon")!!
    val network: PyObject
        get() = commands.get("network")!!
    val wallet: PyObject?
        get() = commands.get("wallet")

    lateinit var watchdog: Runnable

    val height = MutableLiveData<Int>()
    val walletName = MutableLiveData<String>()
    val walletBalance = MutableLiveData<String>()
    val walletTransactions = MutableLiveData<PyObject>()

    init {
        val consoleMod = py.getModule("electroncash_gui.android.ec_console")
        commands = consoleMod.callAttr("AllCommands")
        network.callAttr("register_callback", daemonMod.callAttr("make_callback", this),
                         consoleMod.get("CALLBACKS"))
        commands.callAttr("start")
        watchdog = Runnable {
            for (thread in listOf(daemon, network)) {
                if (! thread.callAttr("is_alive").toJava(Boolean::class.java)) {
                    throw RuntimeException("$thread unexpectedly stopped")
                }
            }
            handler.postDelayed(watchdog, WATCHDOG_INTERVAL)
        }
        watchdog.run()
    }

    fun onCallback(event: String) {
        if (network.callAttr("is_connected").toJava(Boolean::class.java)) {
            height.postValue (network.callAttr("get_local_height").toJava(Int::class.java))
        } else {
            height.postValue(null)
        }

        val wallet = this.wallet
        if (wallet != null) {
            walletName.postValue(wallet.callAttr("basename").toString())
            walletBalance.postValue(commands.callAttr("getbalance")  // TODO make unit configurable
                                    .callAttr("__getitem__", "confirmed").toString())
            walletTransactions.postValue(wallet.callAttr("export_history"))
        } else {
            for (ld in listOf(walletName, walletBalance, walletTransactions)) {
                ld.postValue(null)
            }
        }
    }

    override fun onCleared() {
        handler.removeCallbacks(watchdog)
        commands.callAttr("stop")
    }

    // TODO remove once Chaquopy provides better syntax.
    fun listWallets(): MutableList<String> {
        val pyNames = commands.callAttr("list_wallets")
        val names = ArrayList<String>()
        for (i in 0 until pyNames.callAttr("__len__").toJava(Int::class.java)) {
            val name = pyNames.callAttr("__getitem__", i).toString()
            names.add(name)
        }
        return names
    }

    /** If the password is wrong, throws PyException with the type InvalidPassword. */
    fun loadWallet(name: String, password: String?) {
        val prevName = walletName.value
        commands.callAttr("load_wallet", name, password)
        if (prevName != null && prevName != name) {
            commands.callAttr("close_wallet", prevName)
        }
    }
}