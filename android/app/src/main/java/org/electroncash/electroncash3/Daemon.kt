package org.electroncash.electroncash3

import android.app.Application
import android.arch.lifecycle.AndroidViewModel
import android.arch.lifecycle.MutableLiveData
import com.chaquo.python.Kwarg
import com.chaquo.python.PyException
import com.chaquo.python.PyObject
import com.chaquo.python.Python
import com.chaquo.python.android.AndroidPlatform


val py by lazy {
    Python.start(AndroidPlatform(app))
    Python.getInstance()
}
val libMod by lazy { py.getModule("electroncash")!! }
val daemonMod by lazy {
    val mod =  py.getModule("electroncash_gui.android.daemon")!!
    mod.callAttr("set_excepthook", mainHandler)
    mod
}

val WATCHDOG_INTERVAL = 1000L


class DaemonModel(val app: Application) : AndroidViewModel(app) {
    val consoleMod = py.getModule("electroncash_gui.android.ec_console")

    val commands = consoleMod.callAttr("AllCommands")!!
    val config = commands.get("config")!!
    val daemon = commands.get("daemon")!!
    val network = commands.get("network")!!
    val wallet: PyObject?
        get() = commands.get("wallet")

    lateinit var callback: Runnable
    lateinit var watchdog: Runnable

    val netStatus = MutableLiveData<NetworkStatus>()
    val walletName = MutableLiveData<String>()
    val walletBalance = MutableLiveData<Long>()
    val walletTransactions = MutableLiveData<PyObject>()

    init {
        checkAcra()
        initCallback()
        network.callAttr("register_callback", daemonMod.callAttr("make_callback", this),
                         consoleMod.get("CALLBACKS"))
        commands.callAttr("start")

        // This is still necessary even with the excepthook, in case a thread exits
        // non-exceptionally.
        watchdog = Runnable {
            for (thread in listOf(daemon, network)) {
                if (! thread.callAttr("is_alive").toJava(Boolean::class.java)) {
                    throw RuntimeException("$thread unexpectedly stopped")
                }
            }
            mainHandler.postDelayed(watchdog, WATCHDOG_INTERVAL)
        }
        watchdog.run()
    }

    fun initCallback() {
        callback = Runnable {
            if (network.callAttr("is_connected").toJava(Boolean::class.java)) {
                netStatus.value = NetworkStatus(
                    network.callAttr("get_local_height").toJava(Int::class.java),
                    network.callAttr("get_server_height").toJava(Int::class.java))
            } else {
                netStatus.value = null
            }

            val wallet = this.wallet
            if (wallet != null) {
                walletName.value = wallet.callAttr("basename").toString()
                if (wallet.callAttr("is_up_to_date").toJava(Boolean::class.java)) {
                    val balances = wallet.callAttr("get_balance")  // Returns (confirmed, unconfirmed, unmatured)
                    walletBalance.value = balances.callAttr("__getitem__", 0).toJava(Long::class.java)
                } else {
                    walletBalance.value = null
                }
                walletTransactions.value = wallet.callAttr("export_history")
            } else {
                for (ld in listOf(walletName, walletBalance, walletTransactions)) {
                    ld.value = null
                }
            }
        }
        onCallback("ui_create")  // Set initial LiveData values.
    }

    // This will sometimes be called on the main thread and sometimes on the network thread.
    fun onCallback(event: String) {
        mainHandler.removeCallbacks(callback)  // Mitigate callback floods.
        mainHandler.post(callback)
    }

    // TODO: when the app is off-screen, the device is rotated, and the app is resumed, all
    // ViewModels are incorrectly recreated. This is said to be fixed in support library version
    // 28 (https://stackoverflow.com/a/51475630), but we're not using that yet because the
    // current pre-release breaks the layout editor in Android Studio 3.1.
    override fun onCleared() {
        mainHandler.removeCallbacks(watchdog)
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

    fun makeTx(address: String, amount: Long, password: String? = null,
               unsigned: Boolean = false): PyObject {
        if (address.isEmpty()) {
            throw ToastException(R.string.enter_or)
        }
        try {
            libMod["address"]!!["Address"]!!.callAttr("from_string", address)
        } catch (e: PyException) {
            throw if (e.message!!.startsWith("AddressError"))
                ToastException(R.string.invalid_address) else e
        }
        if (amount <= 0) throw ToastException(R.string.invalid_amount)

        val outputs = arrayOf(arrayOf(address, formatSatoshis(amount, UNIT_BCH)))
        try {
            return commands.callAttr("_mktx", outputs, Kwarg("password", password),
                                     Kwarg("unsigned", unsigned))
        } catch (e: PyException) {
            throw if (e.message!!.startsWith("NotEnoughFunds"))
                ToastException(R.string.insufficient_funds) else e
        }
    }
}


data class NetworkStatus(val localHeight: Int, val serverHeight: Int)