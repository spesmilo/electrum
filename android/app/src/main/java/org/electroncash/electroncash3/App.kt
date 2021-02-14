package org.electroncash.electroncash3

import android.app.Application
import android.content.Context
import android.os.Handler
import com.chaquo.python.Python
import com.chaquo.python.android.AndroidPlatform
import org.acra.ACRA
import org.acra.annotation.AcraCore
import org.acra.annotation.AcraDialog


lateinit var app: App
lateinit var mainHandler: Handler


val py by lazy {
    Python.start(AndroidPlatform(app))
    Python.getInstance()
}
fun libMod(name: String) = py.getModule("electroncash.$name")
fun guiMod(name: String) = py.getModule("electroncash_gui.android.$name")
val libNetworks by lazy { libMod("networks") }


// Not using reportFields: it doesn't noticably reduce response time.
@AcraCore(buildConfigClass = BuildConfig::class,
          reportSenderFactoryClasses = [CrashhubSenderFactory::class])
@AcraDialog(reportDialogClass = CrashhubDialog::class, resTitle = R.string.sorry,
            resCommentPrompt = R.string.please_briefly, resPositiveButtonText = R.string.send)
class App : Application() {

    override fun attachBaseContext(base: Context?) {
        // Set these variables as early as possible, in case ACRA.init tries to send a
        // saved crash report.
        app = this
        mainHandler = Handler()

        super.attachBaseContext(base)
        ACRA.init(this)
    }

    override fun onCreate() {
        super.onCreate()

        // The rest of this method should run in the main process only.
        if (ACRA.isACRASenderServiceProcess()) return

        if (BuildConfig.testnet) {
            libNetworks.callAttr("set_testnet")
        }

        val config = initSettings()
        initDaemon(config)
        initNetwork()
        initExchange()
        initCaption()
    }

}


fun runOnUiThread(r: () -> Unit) { runOnUiThread(Runnable { r() }, false) }
fun postToUiThread(r: () -> Unit) { runOnUiThread(Runnable { r() }, true) }

fun runOnUiThread(r: Runnable, post: Boolean) {
    if (onUiThread() && !post) {
        r.run()
    } else {
        mainHandler.post(r)
    }
}

fun onUiThread() = Thread.currentThread() == mainHandler.looper.thread