package org.electroncash.electroncash3

import android.app.Application
import android.arch.lifecycle.AndroidViewModel
import android.arch.lifecycle.MutableLiveData
import android.os.Handler
import com.chaquo.python.Kwarg
import com.chaquo.python.PyException
import com.chaquo.python.PyObject
import com.chaquo.python.Python


val WATCHDOG_INTERVAL = 1000L
val py = Python.getInstance()
val libMod = py.getModule("electroncash")!!


class DaemonModel(val app: Application) : AndroidViewModel(app) {
    val handler = Handler()
    val consoleMod = py.getModule("electroncash_gui.android.ec_console")

    val commands = consoleMod.callAttr("AllCommands")!!
    val config = commands.get("config")!!
    val daemon = commands.get("daemon")!!
    val network = commands.get("network")!!
    val wallet: PyObject?
        get() = commands.get("wallet")

    lateinit var watchdog: Runnable

    val height = MutableLiveData<Int>()
    val walletName = MutableLiveData<String>()
    val walletBalance = MutableLiveData<String>()
    val walletTransactions = MutableLiveData<PyObject>()

    init {
        network.callAttr("register_callback",
                         py.getModule("electroncash_gui.android.daemon")
                             .callAttr("make_callback", this),
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