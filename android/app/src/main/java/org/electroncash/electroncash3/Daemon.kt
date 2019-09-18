package org.electroncash.electroncash3

import androidx.lifecycle.MutableLiveData
import android.widget.Toast
import com.chaquo.python.PyException
import com.chaquo.python.PyObject


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
    val walletName: String?
        get() {
            val wallet = this.wallet
            return if (wallet == null) null else wallet.callAttr("basename").toString()
        }

    lateinit var watchdog: Runnable

    init {
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

    // This function is called from src/main/python/electroncash_gui/android/daemon.py.
    // It will sometimes be called on the main thread and sometimes on the network thread.
    @Suppress("unused")
    fun onCallback(event: String) {
        if (EXCHANGE_CALLBACKS.contains(event)) {
            fiatUpdate.postValue(Unit)
        } else {
            daemonUpdate.postValue(Unit)
        }
    }

    fun isConnected() = network.callAttr("is_connected").toBoolean()

    fun listWallets(): List<String> {
        return commands.callAttr("list_wallets").asList().map { it.toString() }
    }

    /** If the password is wrong, throws PyException with the type InvalidPassword. */
    fun loadWallet(name: String, password: String) {
        val prevName = walletName
        commands.callAttr("load_wallet", name, password)
        if (prevName != null && prevName != name) {
            commands.callAttr("close_wallet", prevName)
        }
    }
}


fun makeAddress(addrStr: String): PyObject {
    try {
        return clsAddress.callAttr("from_string", addrStr)
    } catch (e: PyException) {
        throw if (e.message!!.startsWith("AddressError"))
            ToastException(R.string.Invalid_address, Toast.LENGTH_SHORT)
            else e
    }
}


fun setDescription(key: String, description: String) {
    val wallet = daemonModel.wallet!!
    wallet.callAttr("set_label", key, description)
    wallet.get("storage")!!.callAttr("write")
    daemonUpdate.postValue(Unit)
}
