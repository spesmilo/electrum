#!/usr/bin/env python3
# p4a service entry point for "Chainwatch". Launched by org.electrum.worker.ElectrumWorker
# once per period.
#
# Declared in contrib/android/buildozer_qml.spec as:
#   services = Chainwatch:electrum/gui/qml/service/chainwatch_service.py:foreground
#
# Runs in a separate process with its own interpreter.
# must exit / stopSelf() when done so the foreground notification clears.

import os
import sys


def _bootstrap_syspath():
    """Put the app bundle root and its packages/ dir on sys.path.

    This entrypoint does NOT go through run_electrum, which is what normally
    adds the top-level packages/ dir to sys.path.

    TODO: collects using two strategies, probably one is sufficient
    1. ask the Android service context for filesDir; typically /data/user/0/<pkg>/files/app.
    2. resolve electrum's on-disk location via find_spec; typically /data/data/<pkg>/files/app.
    """
    roots = []
    try:
        from jnius import autoclass
        svc = autoclass('org.kivy.android.PythonService').mService
        roots.append(os.path.join(svc.getFilesDir().getPath(), 'app'))
    except Exception:
        pass
    try:
        import importlib.util
        spec = importlib.util.find_spec('electrum')
        if spec and spec.origin:  # .../app/electrum/__init__.py
            roots.append(os.path.dirname(os.path.dirname(spec.origin)))
    except Exception:
        pass

    for root in roots:
        for p in (root, os.path.join(root, 'packages')):
            if os.path.isdir(p) and p not in sys.path:
                sys.path.insert(0, p)


def _repair_ctypes_pythonapi():
    """Repoint ctypes.pythonapi at libpython opened by name.

    In a p4a *service* process ctypes.pythonapi (PyDLL(None) -> dlopen(NULL) ->
    RTLD_DEFAULT) cannot resolve libpython's C-API symbols, because Android's
    default/global symbol scope does not include the System.loadLibrary'd
    libpython. Code that calls the Python C-API via ctypes.pythonapi then dies,
    e.g. pycryptodome's buffer handling (Cryptodome/Util/_raw_api.py:
    `ctypes.pythonapi.PyObject_GetBuffer`) raises
    'AttributeError: undefined symbol: PyObject_GetBuffer', which surfaces as
    crypto.py's "at least one of ('pycryptodomex', 'cryptography')".

    libpython opened by name resolves those symbols fine (dlsym on its own
    handle), so we swap pythonapi's handle for that one. Must run before the
    first user of ctypes.pythonapi (i.e. before importing electrum).
    """
    import ctypes
    try:
        ver = f"{sys.version_info.major}.{sys.version_info.minor}"
        libpy = ctypes.CDLL(f"libpython{ver}.so")
        ctypes.cast(libpy.PyObject_GetBuffer, ctypes.c_void_p)  # sanity check
        ctypes.pythonapi._handle = libpy._handle
    except Exception:
        pass


_bootstrap_syspath()
_repair_ctypes_pythonapi()

CHANNEL_ID = "electrum_chainwatch"
CHANNEL_NAME = "Chainwatch"
NOTIFICATION_ID = 4711


def _stop_self():
    """Stop the Android foreground service so its notification is dismissed."""
    try:
        from jnius import autoclass
        PythonService = autoclass('org.kivy.android.PythonService')
        PythonService.mService.stopSelf()
    except Exception:
        pass


def _notify(title, text):
    """Post a notification whose tap target opens the app.

    The activity is launched by the OS when the user taps (via the
    PendingIntent), so it sidesteps the Background-Activity-Launch restriction.
    Extras are readable from the QML side after PythonActivity is (re)started.
    """
    from jnius import autoclass, cast
    PythonService = autoclass('org.kivy.android.PythonService')
    PythonActivity = autoclass('org.kivy.android.PythonActivity')
    Context = autoclass('android.content.Context')
    Intent = autoclass('android.content.Intent')
    PendingIntent = autoclass('android.app.PendingIntent')
    NotificationBuilder = autoclass('android.app.Notification$Builder')
    NotificationManager = autoclass('android.app.NotificationManager')
    NotificationChannel = autoclass('android.app.NotificationChannel')
    String = autoclass('java.lang.String')

    service = PythonService.mService
    nm = cast('android.app.NotificationManager',
              service.getSystemService(Context.NOTIFICATION_SERVICE))

    channel = NotificationChannel(
        CHANNEL_ID, cast('java.lang.CharSequence', String(CHANNEL_NAME)),
        NotificationManager.IMPORTANCE_DEFAULT)
    nm.createNotificationChannel(channel)

    # Tap target: (re)open the app.
    intent = Intent(service, PythonActivity)
    intent.setFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP | Intent.FLAG_ACTIVITY_NEW_TASK)
    intent.putExtra("chainwatch", String(text))
    pi = PendingIntent.getActivity(
        service, 0, intent,
        PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE)

    builder = NotificationBuilder(service, CHANNEL_ID)
    builder.setContentTitle(cast('java.lang.CharSequence', String(title)))
    builder.setContentText(cast('java.lang.CharSequence', String(text)))
    builder.setContentIntent(pi)
    builder.setAutoCancel(True)

    # electrum_light_icon.png is packaged into res/drawable via
    # `android.add_resources` in buildozer_qml.spec; resolve its id by name so
    # we don't need a generated R reference. Note: the system renders the small
    # icon as a tinted alpha silhouette, not the full-color image.
    icon_id = service.getResources().getIdentifier(
        "electrum_light_icon", "drawable", service.getPackageName())
    if icon_id == 0:  # not packaged/renamed as expected: fall back to app icon
        icon_id = service.getApplicationInfo().icon
    builder.setSmallIcon(icon_id)

    nm.notify(NOTIFICATION_ID, builder.build())


def _build_config():
    """Build the SimpleConfig for this service process and select the chain.
    """
    from jnius import autoclass
    from electrum import constants
    from electrum.simple_config import SimpleConfig

    service = autoclass('org.kivy.android.PythonService').mService
    pkgname = str(service.getPackageName())
    data_dir = service.getFilesDir().getPath() + '/data'

    # electrum_path pins the same data dir the GUI uses (avoids android_data_dir).
    options = {'electrum_path': data_dir}
    # mirror SimpleConfig.set_chain_config_opt_based_on_android_packagename(),
    # which we can't call directly (it reads mActivity).
    for chain in constants.NETS_LIST:
        if pkgname == f"org.electrum.{chain.cli_flag()}.electrum":
            options[chain.cli_flag()] = True

    # reads the same user config the GUI uses, incl. server + proxy settings.
    config = SimpleConfig(options)
    # set the global constants.net (ports, genesis, default servers).
    config.get_selected_chain().set_as_network()
    return config


def _fetch_chain_tip(config, timeout=45):
    """Connect to the configured server and return the current chain-tip height.

    Starts a private asyncio loop + Network and returns the height, or None on
    failure/timeout. Bounded by `timeout` seconds.
    """
    import time
    import asyncio
    from electrum.network import Network
    from electrum.util import create_and_start_event_loop

    loop, stopping_fut, loop_thread = create_and_start_event_loop()
    network = Network(config)
    network.start()
    try:
        waited = 0.0
        while not network.is_connected() and waited < timeout:
            time.sleep(1.0)
            waited += 1.0
        if not network.is_connected():
            return None
        # server's claimed tip; fall back to the POW-verified local height
        return network.get_server_height() or network.get_local_height()
    finally:
        # set_result must run on the loop thread; stop the network first so its
        # tasks unwind cleanly before the loop is torn down.
        try:
            asyncio.run_coroutine_threadsafe(
                network.stop(full_shutdown=True), loop).result(10)
        except Exception:
            pass
        loop.call_soon_threadsafe(stopping_fut.set_result, 1)
        while loop_thread.is_alive():
            loop_thread.join(1)


def main():
    try:
        config = _build_config()
        height = _fetch_chain_tip(config)
        if height:
            _notify("Electrum", f"Current block height: {height:,}")
        else:
            _notify("Electrum", "Could not reach the Electrum server")
    except Exception as e:
        # p4a redirects stdout/stderr to logcat, so this makes failures of this
        # otherwise-invisible background service debuggable.
        import traceback
        traceback.print_exc()
        _notify("Electrum", f"Chainwatch failed: {e}")
    finally:
        # shortService: must stop well within ~3 min or the OS kills us
        _stop_self()


if __name__ == '__main__':
    main()
