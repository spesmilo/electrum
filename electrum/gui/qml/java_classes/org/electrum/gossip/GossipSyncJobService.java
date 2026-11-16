package org.electrum.gossip;

import android.app.Activity;
import android.app.ActivityManager;
import android.app.job.JobInfo;
import android.app.job.JobParameters;
import android.app.job.JobScheduler;
import android.app.job.JobService;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.PersistableBundle;
import android.os.PowerManager;
import android.provider.Settings;
import android.util.Log;

import java.util.List;

/**
 * Brings the Lightning gossip db up to date while the app is not in use.
 *
 * The OS suspends or kills the app shortly after the user leaves it, so the gossip gets stale, and
 * the payments made right after coming back run into outdated fees and channels that are gone.
 * If the user allows it, the app schedules this job, and the OS runs it from time to time:
 *  - if the app is not running, the job runs python in a separate process (GossipSyncService),
 *    which only fetches gossip (see electrum/gossip_catch_up.py), and waits for it to exit;
 *  - if the app is running, suspended in the background, the job only keeps it awake until
 *    it says that its gossip has caught up.
 */
public class GossipSyncJobService extends JobService {
    private static final String TAG = "GossipSyncJob";
    private static final int JOB_ID = 7614;  // arbitrary, unique within the app

    private static final String EXTRA_APK_UPDATE_TIME = "apk_update_time";
    private static final String EXTRA_INTERVAL_MINUTES = "interval_minutes";
    private static final String EXTRA_FLEX_MILLIS = "flex_millis";
    private static final String EXTRA_UNMETERED_ONLY = "unmetered_only";
    private static final String EXTRA_CHARGING_ONLY = "charging_only";

    // The OS stops a job after about ten minutes. Python stops by itself before this,
    // which is better, as only then it records how far it got.
    private static final long MAX_RUN_MILLIS = 8 * 60 * 1000;

    private static final Handler mainHandler = new Handler(Looper.getMainLooper());

    // whether the app (its python side) runs in this process. It tells us when it starts.
    private static volatile boolean appRunning = false;
    // the job that is running, if any. Only used on the main thread.
    private static GossipSyncJobService runningJob = null;
    private static volatile boolean jobRunningInApp = false;

    private JobParameters params;
    private ServiceConnection connection;  // set while we are bound to GossipSyncService
    private final Runnable timeout = () -> finish("time is up");

    /**
     * Asks the OS to run the job about every intervalMinutes (15 at least), also after a reboot.
     * Returns whether that worked.
     */
    public static boolean schedule(Context context, long intervalMinutes, boolean unmeteredOnly, boolean chargingOnly) {
        JobScheduler scheduler = (JobScheduler) context.getSystemService(Context.JOB_SCHEDULER_SERVICE);
        long apkUpdateTime = getApkUpdateTime(context);
        long intervalMillis = intervalMinutes * 60 * 1000;
        // The OS runs the job at some time within the last flexMillis of each interval. Without a flex
        // it is the whole interval: the job can then run twice in a row, at the end of an interval and at
        // the start of the next, or not for almost two intervals, and after a run that the OS deferred
        // past its interval (doze, no wifi) the next one is due at once.
        long flexMillis = Math.max(intervalMillis / 4, JobInfo.getMinFlexMillis());
        JobInfo pending = scheduler.getPendingJob(JOB_ID);
        if (pending != null) {
            PersistableBundle extras = pending.getExtras();
            if (extras.getLong(EXTRA_APK_UPDATE_TIME, -1) == apkUpdateTime
                    && extras.getLong(EXTRA_INTERVAL_MINUTES, -1) == intervalMinutes
                    && extras.getLong(EXTRA_FLEX_MILLIS, -1) == flexMillis
                    && extras.getInt(EXTRA_UNMETERED_ONLY, -1) == (unmeteredOnly ? 1 : 0)
                    && extras.getInt(EXTRA_CHARGING_ONLY, -1) == (chargingOnly ? 1 : 0)) {
                return true;  // scheduling again would restart the interval, every time the app starts
            }
        }
        PersistableBundle extras = new PersistableBundle();
        extras.putLong(EXTRA_APK_UPDATE_TIME, apkUpdateTime);
        extras.putLong(EXTRA_INTERVAL_MINUTES, intervalMinutes);
        extras.putLong(EXTRA_FLEX_MILLIS, flexMillis);
        extras.putInt(EXTRA_UNMETERED_ONLY, unmeteredOnly ? 1 : 0);
        extras.putInt(EXTRA_CHARGING_ONLY, chargingOnly ? 1 : 0);
        JobInfo.Builder builder = new JobInfo.Builder(JOB_ID, new ComponentName(context, GossipSyncJobService.class))
                .setPeriodic(intervalMillis, flexMillis)
                .setRequiredNetworkType(unmeteredOnly ? JobInfo.NETWORK_TYPE_UNMETERED : JobInfo.NETWORK_TYPE_ANY)
                .setRequiresCharging(chargingOnly)
                .setRequiresBatteryNotLow(true)
                .setExtras(extras);
        try {
            builder.setPersisted(true);  // needs the permission RECEIVE_BOOT_COMPLETED
            return scheduler.schedule(builder.build()) == JobScheduler.RESULT_SUCCESS;
        } catch (RuntimeException e) {
            Log.w(TAG, "could not schedule the job", e);
            return false;
        }
    }

    public static void cancel(Context context) {
        JobScheduler scheduler = (JobScheduler) context.getSystemService(Context.JOB_SCHEDULER_SERVICE);
        scheduler.cancel(JOB_ID);
    }

    public static boolean isScheduled(Context context) {
        JobScheduler scheduler = (JobScheduler) context.getSystemService(Context.JOB_SCHEDULER_SERVICE);
        return scheduler.getPendingJob(JOB_ID) != null;
    }

    /**
     * Whether the user exempted the app from battery optimizations. If not, the OS may delay
     * the job by hours, or even a day, once the app has not been used for a while.
     */
    public static boolean isIgnoringBatteryOptimizations(Context context) {
        PowerManager powerManager = (PowerManager) context.getSystemService(Context.POWER_SERVICE);
        return powerManager.isIgnoringBatteryOptimizations(context.getPackageName());
    }

    /**
     * Lets the user exempt the app from battery optimizations: with the dialog of the OS if the
     * build declares the permission for that (app stores restrict it), else with the list
     * in the settings of the OS, where the user has to find the app.
     */
    public static boolean requestIgnoreBatteryOptimizations(Context context) {
        boolean canAskDirectly = context.checkSelfPermission(
                "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS") == PackageManager.PERMISSION_GRANTED;
        if (canAskDirectly && tryStartActivity(context, new Intent(
                Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS,
                Uri.parse("package:" + context.getPackageName())))) {
            return true;
        }
        return tryStartActivity(context, new Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS));
    }

    private static boolean tryStartActivity(Context context, Intent intent) {
        if (!(context instanceof Activity)) {
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        }
        try {
            context.startActivity(intent);
            return true;
        } catch (RuntimeException e) {  // some devices lack these screens
            Log.w(TAG, "could not open " + intent.getAction(), e);
            return false;
        }
    }

    /**
     * To be called by the app when it starts, before it uses its files.
     * Stops the background process if one is running.
     */
    public static void onAppStarted(Context context) {
        appRunning = true;
        // The OS would kill the process once the job unbinds, but that happens later, on the
        // main thread, and the app is about to open the gossip db.
        killBackgroundProcess(context);
        mainHandler.post(() -> {
            if (runningJob != null && runningJob.connection != null) {
                runningJob.finish("the app got started");
            }
        });
    }

    private static void killBackgroundProcess(Context context) {
        ActivityManager activityManager = (ActivityManager) context.getSystemService(Context.ACTIVITY_SERVICE);
        // (the OS only tells an app about its own processes)
        List<ActivityManager.RunningAppProcessInfo> processes = activityManager.getRunningAppProcesses();
        if (processes == null) {
            return;
        }
        String processName = context.getPackageName() + GossipSyncService.PROCESS_NAME_SUFFIX;
        for (ActivityManager.RunningAppProcessInfo process : processes) {
            if (processName.equals(process.processName)) {
                Log.i(TAG, "killing the background process, as the app got started");
                android.os.Process.killProcess(process.pid);
            }
        }
    }

    /** Whether a job is keeping the app awake, waiting for finishJobInApp(). */
    public static boolean isJobRunningInApp() {
        return jobRunningInApp;
    }

    /** To be called by the app once its gossip has caught up, or if it does not use gossip. */
    public static void finishJobInApp() {
        mainHandler.post(() -> {
            if (runningJob != null && runningJob.connection == null) {
                runningJob.finish("the app caught up");
            }
        });
    }

    private static long getApkUpdateTime(Context context) {
        try {
            return context.getPackageManager().getPackageInfo(context.getPackageName(), 0).lastUpdateTime;
        } catch (PackageManager.NameNotFoundException e) {
            return 0;
        }
    }

    @Override
    public boolean onStartJob(JobParameters params) {
        this.params = params;
        if (params.getExtras().getLong(EXTRA_APK_UPDATE_TIME, -1) != getApkUpdateTime(this)) {
            // The app got updated and was not started since. Its python files are unpacked
            // when it starts, so the ones on disk are not the ones of this apk.
            Log.i(TAG, "the app got updated. it will schedule the job again when it gets started");
            cancel(this);
            return false;
        }
        if (runningJob != null) {
            return false;
        }
        if (appRunning) {
            Log.i(TAG, "keeping the app awake until its gossip has caught up");
        } else {
            Log.i(TAG, "starting the background process");
            Intent intent = new Intent(this, GossipSyncService.class);
            ServiceConnection connection = new ServiceConnection() {
                @Override
                public void onServiceConnected(ComponentName name, IBinder service) {
                }

                @Override
                public void onServiceDisconnected(ComponentName name) {
                    // python is done and its process exited. (unbind, or the OS starts it again)
                    finish("the background process exited");
                }

                @Override
                public void onBindingDied(ComponentName name) {
                    finish("the binding died");
                }
            };
            if (!bindService(intent, connection, Context.BIND_AUTO_CREATE)) {
                Log.w(TAG, "could not start the background process");
                try {
                    unbindService(connection);
                } catch (RuntimeException e) {
                    // it was not bound
                }
                return false;
            }
            this.connection = connection;
        }
        runningJob = this;
        jobRunningInApp = (connection == null);
        mainHandler.postDelayed(timeout, MAX_RUN_MILLIS);
        return true;
    }

    @Override
    public boolean onStopJob(JobParameters params) {
        // the OS wants us to stop: e.g. the device left the wifi, or we took too long
        Log.i(TAG, "the job got stopped");
        cleanUp();
        return false;  // no need to run again before the next time
    }

    private void finish(String reason) {
        if (runningJob != this) {
            return;
        }
        Log.i(TAG, "the job is done: " + reason);
        cleanUp();
        jobFinished(params, false);
    }

    private void cleanUp() {
        mainHandler.removeCallbacks(timeout);
        if (runningJob == this) {
            runningJob = null;
            jobRunningInApp = false;
        }
        if (connection != null) {
            try {
                unbindService(connection);
            } catch (RuntimeException e) {
                Log.w(TAG, "could not unbind", e);
            }
            connection = null;
        }
    }
}
