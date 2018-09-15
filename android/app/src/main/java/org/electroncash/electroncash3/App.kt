package org.electroncash.electroncash3

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import android.os.Handler
import android.preference.PreferenceManager
import org.acra.annotation.AcraCore
import org.acra.annotation.AcraDialog


val DEFAULT_CHANNEL = "default"

lateinit var app: App
lateinit var prefs: SharedPreferences
lateinit var mainHandler: Handler


// Not using reportFields: it doesn't noticably reduce response time.
@AcraCore(reportSenderFactoryClasses = [CrashhubSenderFactory::class])
@AcraDialog(reportDialogClass = CrashhubDialog::class, resTitle = R.string.sorry,
            resCommentPrompt = R.string.please_briefly, resPositiveButtonText = R.string.send)
class App : Application() {

    override fun attachBaseContext(base: Context?) {
        super.attachBaseContext(base)
        initAcra(this)
    }

    override fun onCreate() {
        super.onCreate()
        app = this
        prefs = PreferenceManager.getDefaultSharedPreferences(this)
        mainHandler = Handler()

        if (Build.VERSION.SDK_INT >= 26) {
            val channel = NotificationChannel(DEFAULT_CHANNEL, "Default", NotificationManager.IMPORTANCE_DEFAULT)
            (getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager)
                .createNotificationChannel(channel)
        }
    }

}