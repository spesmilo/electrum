package org.electroncash.electroncash3

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat


private val EXTRA_TITLE = "title"
private val EXTRA_SUBTITLE = "subtitle"
private val NOTIFICATION_CHANNEL = "wallet"
private val NOTIFICATION_ID = 1


class Caption(val walletName: String?, val subtitle: String)

val caption = BackgroundLiveData<Unit, Caption>().apply {
    function = { getCaption() }
    minInterval = MIN_REFRESH_INTERVAL
}
val captionTrigger = TriggerLiveData()


fun initCaption() {
    captionTrigger.apply {
        addSource(daemonUpdate)
        addSource(fiatUpdate)
        addSource(settings.getString("base_unit"))
        observeForever { caption.refresh(Unit) }
    }
    caption.observeForever {
        val intent = Intent(app, CaptionService::class.java)
        if (it.walletName != null) {
            intent.putExtra(EXTRA_TITLE, it.walletName)
            intent.putExtra(EXTRA_SUBTITLE, it.subtitle)
            if (Build.VERSION.SDK_INT >= 26) {
                app.startForegroundService(intent)
            } else {
                app.startService(intent)
            }
        } else {
            app.stopService(intent)
        }
    }
}

private fun getCaption(): Caption {
    val wallet = daemonModel.wallet
    val subtitle: String
    if (! daemonModel.isConnected()) {
        subtitle = app.getString(R.string.offline)
    } else {
        val localHeight = daemonModel.network.callAttr("get_local_height").toInt()
        val serverHeight = daemonModel.network.callAttr("get_server_height").toInt()
        if (localHeight < serverHeight) {
            subtitle = "$localHeight / $serverHeight ${app.getString(R.string.blocks)}"
        } else if (wallet == null) {
            subtitle = app.getString(R.string.online)
        } else {
            if (wallet.callAttr("is_fully_settled_down").toBoolean()) {
                // get_balance returns the tuple (confirmed, unconfirmed, unmatured)
                val balance = wallet.callAttr("get_balance").asList().get(0).toLong()
                subtitle = ltr(formatSatoshisAndFiat(balance))
            } else {
                // get_addresses copies the list, which may be very large.
                val addrCount = wallet.callAttr("get_receiving_addresses").asList().size +
                                wallet.callAttr("get_change_addresses").asList().size
                subtitle =
                    app.getQuantityString1(R.plurals._d_address, addrCount) + " | " +
                    app.getString(R.string.tx_unverified,
                                  wallet.get("transactions")!!.asList().size,
                                  wallet.callAttr("get_unverified_tx_pending_count").toInt())
            }
        }
    }
    return Caption(wallet?.toString(), subtitle)
}


/** This service displays the caption as a foreground notification whenever a wallet is open,
 * which makes the OS much less likely to kill the process. */
class CaptionService : Service() {

    override fun onCreate() {
        if (Build.VERSION.SDK_INT >= 26) {
            getSystemService(NotificationManager::class).createNotificationChannel(
                NotificationChannel(NOTIFICATION_CHANNEL, getString(R.string.wallet),
                                    NotificationManager.IMPORTANCE_LOW))
        }
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent, flags: Int, startId: Int): Int {
        val builder = NotificationCompat.Builder(this, NOTIFICATION_CHANNEL)
            // Priority is ignored from API level 26 in favor of the channel importance.
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setOngoing(true)
            .setShowWhen(false)
            .setSmallIcon(R.drawable.ic_notification)
            .setColor(ContextCompat.getColor(this, R.color.colorPrimaryDark))
            .setContentTitle(intent.extras!!.getString(EXTRA_TITLE))
            .setContentText(intent.extras!!.getString(EXTRA_SUBTITLE))
            .setContentIntent(PendingIntent.getActivity(
                this, 0, Intent(this, MainActivity::class.java), 0))
        startForeground(NOTIFICATION_ID, builder.build())
        return START_NOT_STICKY
    }
}
