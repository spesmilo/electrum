package org.electroncash.electroncash3

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
fun libMod(name: String) = py.getModule("electroncash.$name")!!
fun guiMod(name: String) = py.getModule("electroncash_gui.android.$name")!!

val guiDaemon by lazy { guiMod("daemon") }

val WATCHDOG_INTERVAL = 1000L

lateinit var daemonModel: DaemonModel
val daemonUpdate = MutableLiveData<Unit>().apply { value = Unit }


fun initDaemon() {
    guiDaemon.callAttr("set_excepthook", mainHandler)
    daemonModel = DaemonModel()
}


class DaemonModel {
    val commands = guiConsole.callAttr("AndroidCommands", app)!!
    val config = commands.get("config")!!
    val daemon = commands.get("daemon")!!
    val network = commands.get("network")!!
    val wallet: PyObject?
        get() = commands.get("wallet")

    lateinit var callback: Runnable
    lateinit var watchdog: Runnable

    // TODO get rid of these: see onCallback.
    val netStatus = MutableLiveData<NetworkStatus>()
    val walletName = MutableLiveData<String>()
    val walletBalance = MutableLiveData<Long>()
    val transactions = MutableLiveData<PyObject>()
    val addresses = MutableLiveData<PyObject>()

    init {
        initCallback()
        network.callAttr("register_callback", guiDaemon.callAttr("make_callback", this),
                         guiConsole.get("CALLBACKS"))
        commands.callAttr("start")

        // This is still necessary even with the excepthook, in case a thread exits
        // non-exceptionally.
        watchdog = Runnable {
            for (thread in listOf(daemon, network)) {
                if (! thread.callAttr("is_alive").toBoolean()) {
                    throw RuntimeException("$thread unexpectedly stopped")
                }
            }
            mainHandler.postDelayed(watchdog, WATCHDOG_INTERVAL)
        }
        watchdog.run()
    }

    fun initCallback() {
        callback = Runnable {
            if (network.callAttr("is_connected").toBoolean()) {
                netStatus.value = NetworkStatus(
                    network.callAttr("get_local_height").toInt(),
                    network.callAttr("get_server_height").toInt())
            } else {
                netStatus.value = null
            }

            val wallet = this.wallet
            if (wallet != null) {
                walletName.value = wallet.callAttr("basename").toString()
                if (wallet.callAttr("is_up_to_date").toBoolean()) {
                    // get_balance returns the tuple (confirmed, unconfirmed, unmatured)
                    val balances = wallet.callAttr("get_balance").asList()
                    walletBalance.value = balances.get(0).toLong()
                } else {
                    walletBalance.value = null
                }
                transactions.value = wallet.callAttr("export_history")
                addresses.value = guiAddresses.callAttr("get_addresses", wallet)
            } else {
                for (ld in listOf(walletName, walletBalance, transactions, addresses)) {
                    ld.value = null
                }
            }
        }
        onCallback("ui_create")  // Set initial LiveData values.
    }

    // TODO: migrate everything to daemonUpdate (no need to distinguish between callback types
    // yet). Then get rid of the other LiveDatas above, and distribute the content of
    // initCallback to the places which actually use the data. Callback floods will be
    // mitigated automatically, and only the on-screen data will be queried.
    //
    // This will sometimes be called on the main thread and sometimes on the network thread.
    fun onCallback(event: String) {
        if (EXCHANGE_CALLBACKS.contains(event)) {
            fiatUpdate.postValue(Unit)
        } else {
            daemonUpdate.postValue(Unit)
            mainHandler.removeCallbacks(callback)  // Mitigate callback floods.
            mainHandler.post(callback)
        }
    }

    fun listWallets(): List<String> {
        return commands.callAttr("list_wallets").asList().map { it.toString() }
    }

    fun createWallet(name: String, password: String, kwargName: String, kwargValue: String) {
        commands.callAttr("create", name, password, Kwarg(kwargName, kwargValue))
    }

    /** If the password is wrong, throws PyException with the type InvalidPassword. */
    fun loadWallet(name: String, password: String) {
        val prevName = walletName.value
        commands.callAttr("load_wallet", name, password)
        if (prevName != null && prevName != name) {
            commands.callAttr("close_wallet", prevName)
        }
    }

    fun makeTx(address: String, amount: Long?, password: String? = null,
               unsigned: Boolean = false): PyObject {
        makeAddress(address)

        val amountStr: String
        if (amount == null) {
            amountStr = "!"
        } else {
            if (amount <= 0) throw ToastException(R.string.Invalid_amount)
            amountStr = formatSatoshis(amount, UNIT_BCH)
        }

        val outputs = arrayOf(arrayOf(address, amountStr))
        try {
            return commands.callAttr("_mktx", outputs, Kwarg("password", password),
                                     Kwarg("unsigned", unsigned))
        } catch (e: PyException) {
            throw if (e.message!!.startsWith("NotEnoughFunds"))
                ToastException(R.string.insufficient_funds) else e
        }
    }

    fun makeAddress(addrStr: String): PyObject {
        if (addrStr.isEmpty()) {
            throw ToastException(R.string.enter_or)
        }
        try {
            return clsAddress.callAttr("from_string", addrStr)
        } catch (e: PyException) {
            throw if (e.message!!.startsWith("AddressError"))
                ToastException(R.string.invalid_address) else e
        }
    }
}


data class NetworkStatus(val localHeight: Int, val serverHeight: Int)