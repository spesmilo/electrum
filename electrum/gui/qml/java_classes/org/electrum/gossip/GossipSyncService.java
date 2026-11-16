package org.electrum.gossip;

import android.content.Intent;
import android.os.Binder;
import android.os.IBinder;

import org.kivy.android.PythonService;

/**
 * Runs python in a process of its own, to bring the Lightning gossip db up to date while the app
 * is not running. See GossipSyncJobService, which binds to this service.
 *
 * Python sees PYTHON_ARGUMENT in the environment variable PYTHON_SERVICE_ARGUMENT, and exits when
 * it is done. If the job unbinds before that, the OS destroys the service, and PythonService kills
 * the process.
 */
public class GossipSyncService extends PythonService {
    public static final String PYTHON_ARGUMENT = "gossip_catch_up";
    // as declared for this service in the manifest, see contrib/android/p4a_hook.py
    public static final String PROCESS_NAME_SUFFIX = ":gossipsync";

    private final IBinder binder = new Binder();

    @Override
    public IBinder onBind(Intent intent) {
        // PythonService starts python when the service gets started, which the OS does not allow
        // an app in the background to do. Binding is allowed. PythonService takes what it needs
        // from the extras of the intent, and the extras of an intent used for binding do not
        // reliably get here, so we make them up here.
        String appRoot = getFilesDir().getAbsolutePath() + "/app";
        Intent start = new Intent(this, GossipSyncService.class);
        start.putExtra("androidPrivate", getFilesDir().getAbsolutePath());
        start.putExtra("androidArgument", appRoot);
        start.putExtra("serviceEntrypoint", "main.py");
        start.putExtra("pythonName", "gossipsync");
        start.putExtra("pythonHome", appRoot);
        start.putExtra("pythonPath", appRoot + ":" + appRoot + "/lib");
        start.putExtra("pythonServiceArgument", PYTHON_ARGUMENT);
        start.putExtra("serviceStartAsForeground", "false");
        onStartCommand(start, 0, 0);
        return binder;
    }
}
