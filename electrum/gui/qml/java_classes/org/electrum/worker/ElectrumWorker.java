package org.electrum.worker;

import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.work.Worker;
import androidx.work.WorkerParameters;

import p4a.services.ServiceChainwatch;

/**
 * Periodic worker that wakes up on WorkManager's schedule (see the enqueue in
 * chainwatch.py) and hands off to the p4a Python service ServiceChainwatch.
 */
public class ElectrumWorker extends Worker {
    private static final String TAG = "ElectrumWorker";

    public ElectrumWorker(@NonNull Context ctx, @NonNull WorkerParameters params) {
        super(ctx, params);
        Log.i(TAG, "constructed: id=" + params.getId()
                + " runAttempt=" + params.getRunAttemptCount()
                + " tags=" + params.getTags());
    }

    @Override
    public @NonNull Result doWork() {
        Log.i(TAG, "doWork() ENTER"
                + " id=" + getId()
                + " runAttempt=" + getRunAttemptCount()
                + " isStopped=" + isStopped()
                + " thread=" + Thread.currentThread().getName()
                + " process.pid=" + android.os.Process.myPid());

        Context ctx = getApplicationContext();
        Intent intent;
        try {
            // Reuse p4a's fully-populated intent: it sets serviceEntrypoint,
            // pythonHome/pythonPath, serviceStartAsForeground and the
            // pythonServiceArgument extra.
            intent = ServiceChainwatch.getDefaultIntent(
                    ctx, "", "Electrum", "Chainwatch", "hourly-peek");
        } catch (Throwable t) {
            Log.e(TAG, "failed to build ServiceChainwatch intent", t);
            return Result.failure();
        }

        try {
            // The generated ServiceChainwatch.start() uses plain startService(),
            // which throws IllegalStateException from the background; call
            // startForegroundService() ourselves. Requires the service to
            // be declared `:foreground` so it calls startForeground()
            // within ~5s (else ForegroundServiceDidNotStartInTimeException).
            Log.i(TAG, "startForegroundService(ServiceChainwatch)...");
            ctx.startForegroundService(intent);
            Log.i(TAG, "service start dispatched OK");
        } catch (Throwable t) {
            Log.e(TAG, "failed to start ServiceChainwatch; will retry", t);
            return Result.retry();
        }

        Log.i(TAG, "doWork() EXIT -> success");
        return Result.success();
    }

    @Override
    public void onStopped() {
        super.onStopped();
        Log.w(TAG, "onStopped(): worker was cancelled/preempted"
                + " id=" + getId() + " runAttempt=" + getRunAttemptCount());
    }
}
