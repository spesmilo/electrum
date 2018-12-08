package org.electroncash.electroncash3

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.os.Build
import android.os.Handler
import org.acra.ACRA
import org.acra.annotation.AcraCore
import org.acra.annotation.AcraDialog


val DEFAULT_CHANNEL = "default"

lateinit var app: App
lateinit var mainHandler: Handler


// Not using reportFields: it doesn't noticably reduce response time.
@AcraCore(reportSenderFactoryClasses = [CrashhubSenderFactory::class])
@AcraDialog(reportDialogClass = CrashhubDialog::class, resTitle = R.string.sorry,
            resCommentPrompt = R.string.please_briefly, resPositiveButtonText = R.string.send)
class App : Application() {

    override fun attachBaseContext(base: Context?) {
        super.attachBaseContext(base)
        ACRA.init(this)
    }

    override fun onCreate() {
        super.onCreate()
        app = this
        mainHandler = Handler()

        if (Build.VERSION.SDK_INT >= 26) {
            getSystemService(NotificationManager::class).createNotificationChannel(
                NotificationChannel(DEFAULT_CHANNEL, "Default",
                                    NotificationManager.IMPORTANCE_DEFAULT))
        }

        if (!ACRA.isACRASenderServiceProcess()) {
            initSettings()
            initDaemon()
            initNetwork()
            initExchange()
        }
    }

}


fun runOnUiThread(r: () -> Unit) { runOnUiThread(Runnable { r() }) }

fun runOnUiThread(r: Runnable) {
    if (onUiThread()) {
        r.run()
    } else {
        mainHandler.post(r)
    }
}

fun onUiThread() = Thread.currentThread() == mainHandler.looper.thread