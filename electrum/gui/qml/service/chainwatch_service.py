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
import time
import asyncio
from contextlib import contextmanager
from typing import List


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

# electrum imports only AFTER the two calls above: _bootstrap_syspath() puts the
# bundled packages/ dir (aiohttp etc.) on sys.path, and _repair_ctypes_pythonapi()
# must run before electrum's crypto code first touches ctypes.pythonapi.
from electrum.util import create_and_start_event_loop, read_json_file, write_json_file
from electrum.bitcoin import address_to_scripthash, script_to_scripthash
from electrum.transaction import Transaction
from electrum.network import Network
from electrum import constants
from electrum.simple_config import SimpleConfig

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


def _notify(title, text: str, wallets: List[str] = None):
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
    ArrayList = autoclass('java.util.ArrayList')

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
    jWallets = ArrayList()
    wallets = [] if wallets is None else wallets
    for wallet in wallets:
        jWallets.add(String(wallet))
    intent.putStringArrayListExtra("chainwatch_wallets", jWallets)
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


@contextmanager
def _network_session(config, timeout=45):
    """Start a private asyncio loop + Network and yield the connected Network.

    Honors the config's server and proxy settings. Waits up to `timeout` seconds
    for the initial connection; the yielded Network may still be disconnected if
    the timeout elapsed, so callers should check `network.is_connected()`.
    Guarantees the network is stopped and the loop torn down on exit, keeping the
    service well under the shortService ~3-minute cap.
    """
    loop, stopping_fut, loop_thread = create_and_start_event_loop()
    network = Network(config)
    network.start()
    try:
        waited = 0.0
        while not network.is_connected() and waited < timeout:
            time.sleep(1.0)
            waited += 1.0
        yield network
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


def _fetch_chain_tip(network):
    """Return the current chain-tip height for a connected Network.
    """
    # server's claimed tip
    return network.get_server_height()


def _confirmations_for_height(height: int, tip: int) -> int:
    """Actual confirmation depth of a tx given its server history height.

    0 means unconfirmed/in mempool (also when our tip is unknown or behind, so
    we never over-report). Server heights: >0 confirmed at that block; 0 or -1
    unconfirmed (in mempool, possibly with an unconfirmed parent).
    """
    if height <= 0 or not tip:
        return 0
    return max(0, tip - height + 1)


def _query_watched_items(network, config, tip, timeout=30):
    """Read watched_items.json and query the server for the relevant event.

    The GUI process exports the addresses/outpoints it wants watched to
    <data_dir>/watched_items.json (see QEDaemon.export_watched_items), keyed by
    wallet name. Detection differs by how the item is watched:

    - address: *arrival* -- any tx paying the address' scripthash.
    - outpoint: *spend* -- a tx whose input spends the specific outpoint

    `txids` holds the tx(s) that constitute the event (the incoming payment(s),
    or the single spending tx); it is empty when the event has not happened yet.
    `confirmations` is the actual confirmation depth of that event (deepest
    incoming tx for an address; the spending tx for an outpoint), 0 when
    unconfirmed or nothing qualifies. The caller triggers once it is >= the
    item's required depth.

    Returns {wallet_name: [{'item': item, 'txids': [...], 'confirmations': n}, ...]}.
    """

    path = os.path.join(config.path, 'watched_items.json')
    if not os.path.exists(path):
        return {}
    data = read_json_file(path)

    def _get_tx(txid):
        raw = network.run_from_another_thread(
            network.get_transaction(txid), timeout=timeout)
        return Transaction(raw)

    def _history(sh):
        return network.run_from_another_thread(
            network.get_history_for_scripthash(sh), timeout=timeout)

    def _query_address(address):
        """Arrival detection: any history on the address' scripthash counts.
        confirmations is the deepest incoming tx (max)."""
        history = _history(address_to_scripthash(address))
        txids = [h['tx_hash'] for h in history]
        confirmations = max(
            (_confirmations_for_height(h['height'], tip) for h in history),
            default=0)
        return txids, confirmations

    def _query_outpoint(outpoint):
        """Spend detection: find the tx that spends this specific outpoint.

        The funding tx gives us the watched output's scriptpubkey -> scripthash;
        its history contains the funder plus anything spending from that script.
        A history tx spends our outpoint iff one of its inputs' prevout equals
        txid:idx. An outpoint is spent at most once, so we stop at the first hit
        and report that tx and its confirmations."""
        fund_txid, idx = outpoint.split(':')
        spk = _get_tx(fund_txid).outputs()[int(idx)].scriptpubkey
        for h in _history(script_to_scripthash(spk)):
            if h['tx_hash'] == fund_txid:
                continue  # the funder itself cannot spend its own output
            spender = _get_tx(h['tx_hash'])
            if any(txin.prevout.to_str() == outpoint for txin in spender.inputs()):
                return [h['tx_hash']], _confirmations_for_height(h['height'], tip)
        return [], 0

    result = {}
    for wallet_name, items in data.items():
        found = []
        for item in items:
            try:
                if address := item.get('address'):
                    txids, confirmations = _query_address(address)
                elif outpoint := item.get('outpoint'):
                    txids, confirmations = _query_outpoint(outpoint)
                else:
                    continue
                found.append({
                    'item': item,
                    'txids': txids,
                    'confirmations': confirmations,
                })
            except Exception:
                import traceback
                traceback.print_exc()
        if found:
            result[wallet_name] = found
    return result


def _describe_events(entries):
    """Human-readable notification text summarizing the fired events by type.

    Phrasing reflects what each WatchedItemType actually observed: a REQUEST
    address received a payment, while a SWAP/LIGHTNING lockup outpoint was spent
    (swap claim/refund, or channel close)."""
    counts = {}
    for e in entries:
        t = e['item'].get('type') or 'unknown'
        counts[t] = counts.get(t, 0) + 1
    phrasing = {
        'request': lambda n: f"{n} payment(s) received",
        'swap': lambda n: f"{n} swap lockup(s) spent",
        'lightning': lambda n: f"{n} channel(s) closed on-chain",
    }
    parts = [
        phrasing.get(t, lambda n: f"{n} {t} event(s)")(n)
        for t, n in counts.items()
    ]
    return "; ".join(parts)


def _mark_notified(config, entries):
    """Persist a `notified` flag onto the given watched items in watched_items.json.

    We reuse the existing export file as our notify-once state store (no extra
    file): the flag survives across the repeated background runs that happen
    while the GUI is closed. When the GUI later re-exports a loaded wallet it
    recomputes the list from scratch, dropping the flag -- which is harmless, as
    a paid request drops out entirely and an app that's open won't spam anyway.

    Best-effort: never raises.
    """
    try:
        path = os.path.join(config.path, 'watched_items.json')
        if not os.path.exists(path):
            return
        data = read_json_file(path)
        keys = {(e['item'].get('address'), e['item'].get('outpoint')) for e in entries}
        changed = False
        for items in data.values():
            for item in items:
                if (item.get('address'), item.get('outpoint')) in keys and not item.get('notified'):
                    item['notified'] = True
                    changed = True
        if changed:
            write_json_file(path, data)
    except Exception:
        import traceback
        traceback.print_exc()


def main():
    try:
        config = _build_config()
        with _network_session(config) as network:
            if not network.is_connected():
                return
            height = _fetch_chain_tip(network)
            watched = _query_watched_items(network, config, height)
            n_items = sum(len(items) for items in watched.values())
            n_txids = sum(len(entry['txids']) for items in watched.values() for entry in items)
            print(f"chainwatch: queried {n_items} watched item(s) across "
                  f"{len(watched)} wallet(s); {n_txids} relevant tx(s) at {height=}")
            # Every watched item is notified exactly once, and only once its tx
            # has reached the item's required depth, i.e. its actual confirmation
            # count is >= the item's `depth` (0 = trigger as soon as seen, even in
            # mempool). An empty txids means the event (arrival / spend) has not
            # happened yet.
            def _required_depth(item):
                try:
                    return int(item.get('depth', 0))
                except (TypeError, ValueError):
                    return 0
            fresh = [
                entry
                for items in watched.values() for entry in items
                if entry['txids']
                and entry['confirmations'] >= _required_depth(entry['item'])
                and not entry['item'].get('notified')
            ]
            if fresh:
                wallets = sorted({
                    name for name, items in watched.items()
                    if any(e in fresh for e in items)
                })
                _notify("Electrum", _describe_events(fresh), wallets)
                _mark_notified(config, fresh)
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
