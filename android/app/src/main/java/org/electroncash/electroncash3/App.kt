package org.electroncash.electroncash3

import android.app.*
import android.content.*
import android.os.*
import android.preference.*
import com.chaquo.python.android.*


val DEFAULT_CHANNEL = "default"

lateinit var app: App
lateinit var prefs: SharedPreferences


class App : PyApplication() {

    override fun onCreate() {
        super.onCreate()
        app = this
        prefs = PreferenceManager.getDefaultSharedPreferences(this)

        if (Build.VERSION.SDK_INT >= 26) {
            val channel = NotificationChannel(DEFAULT_CHANNEL, "Default", NotificationManager.IMPORTANCE_DEFAULT)
            (getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager)
                .createNotificationChannel(channel)
        }
    }

}