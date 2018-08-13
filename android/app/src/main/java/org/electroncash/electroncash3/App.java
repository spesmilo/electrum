package org.electroncash.electroncash3;

import android.app.*;
import android.content.*;
import android.os.*;
import android.preference.*;
import com.chaquo.python.android.*;


public class App extends PyApplication {

    public static final String DEFAULT_CHANNEL = "default";

    public static App context;
    public static SharedPreferences prefs;

    @Override
    public void onCreate() {
        super.onCreate();
        context = this;
        prefs = PreferenceManager.getDefaultSharedPreferences(this);

        if (Build.VERSION.SDK_INT >= 26) {
            NotificationChannel channel = new NotificationChannel
                (DEFAULT_CHANNEL, "Default", NotificationManager.IMPORTANCE_DEFAULT);
            ((NotificationManager) getSystemService(NOTIFICATION_SERVICE))
                .createNotificationChannel(channel);
        }
    }

}