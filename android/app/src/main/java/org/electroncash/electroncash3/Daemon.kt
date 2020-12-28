package org.electroncash.electroncash3

import android.widget.Toast
import androidx.lifecycle.MutableLiveData
import com.chaquo.python.PyException
import com.chaquo.python.PyObject
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit


val guiDaemon by lazy { guiMod("daemon") }

val WATCHDOG_INTERVAL = 1000L

lateinit var daemonModel: DaemonModel
val daemonUpdate = MutableLiveData<Unit>().apply { value = Unit }


fun initDaemon(config: PyObject) {
    guiDaemon.callAttr("initialize", mainHandler)
    daemonModel = DaemonModel(config)
}


class DaemonModel(val config: PyObject) {
    val commands = guiConsole.callAttr("AndroidCommands", config)!!
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
        commands.put("gui_callback", ::onCallback)
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
            waitForSave()
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


fun getDescription(wallet: PyObject, key: String) =
    wallet.callAttr("get_label", key).toString()

fun setDescription(wallet: PyObject, key: String, description: String) {
    if (wallet.callAttr("set_label", key, description).toBoolean()) {
        saveWallet(wallet) { wallet.callAttr("save_labels") }
    }
    daemonUpdate.postValue(Unit)
}


private var saveThread = newSaveThread()

private fun newSaveThread() =
    ThreadPoolExecutor(1, 1, 0L, TimeUnit.MILLISECONDS, LinkedBlockingQueue<Runnable>())

// Both saving to storage and writing storage to disk should be done on a background thread.
// Even if the save to storage is usually fast, it may be blocked by a storage.write on the
// network thread.
fun saveWallet(wallet: PyObject, saveToStorage: () -> Unit) {
    saveThread.execute {
        saveToStorage()
        if (saveThread.queue.isEmpty()) {
            wallet.get("storage")!!.callAttr("write")
        }
    }
}

fun waitForSave() {
    saveThread.shutdown()
    while (!saveThread.isTerminated()) {
        saveThread.awaitTermination(1, TimeUnit.SECONDS)
    }
    saveThread = newSaveThread()
}