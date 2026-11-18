# Copyright (C) 2026 The Electrum developers
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://www.opensource.org/licenses/mit-license.php
"""Brings the Lightning gossip db up to date, without running the rest of the wallet.

A mobile OS suspends or kills the app shortly after the user leaves it. When they come back hours
or days later the gossip db is stale, and the payments they make right away run into outdated fees
and into channels that are gone. To avoid that, the Android app lets the OS run it in the
background from time to time (see GossipSyncJobService.java). This module is what runs then: it
connects to a few Lightning nodes, receives the gossip since the last time, and stops.
No wallet is opened and no Electrum server is contacted.
"""
import asyncio
import json
import os
import time
from typing import TYPE_CHECKING, List, Optional, Tuple

from aiorpcx import ignore_after

from .logging import get_logger
from .util import get_headers_dir

if TYPE_CHECKING:
    from .network import Network
    from .simple_config import SimpleConfig


_logger = get_logger(__name__)

LOCK_FILE_NAME = 'gossip_db.lock'
HISTORY_FILE_NAME = 'gossip_catch_up_history'
NUM_HISTORY_ENTRIES_KEEP = 50
# Android stops a background job after about ten minutes. We want to stop by ourselves before
# that, to write everything to disk. (GossipSyncJobService.java waits a bit longer than this)
DEFAULT_TIMEOUT = 7 * 60  # seconds
# If we are not connected to any node for this long (counted from when the db got loaded), e.g. as
# the network blocks us, we do not wait any longer.
NO_PEERS_TIMEOUT = 60  # seconds
# what GossipSyncService.java passes to python, to tell that it should only catch up on gossip
ANDROID_SERVICE_ARGUMENT = 'gossip_catch_up'
CMD_NAME = 'gossip_catch_up'


class GossipDbLock:
    """Held by the process that uses the gossip db: either the app, or a catch-up in the background.

    The OS releases the lock when the process that holds it exits, however it exits.
    """

    def __init__(self, config: 'SimpleConfig'):
        self.path = os.path.join(get_headers_dir(config), LOCK_FILE_NAME)
        self._fd = None  # type: Optional[int]

    def acquire(self, *, timeout: float = 0) -> bool:
        """Returns whether we got the lock, waiting for it up to `timeout` seconds."""
        import fcntl  # not available on Windows
        if self._fd is not None:
            return True
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
        deadline = time.monotonic() + timeout
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                if time.monotonic() >= deadline:
                    os.close(fd)
                    return False
                time.sleep(0.1)
            else:
                self._fd = fd
                return True

    def release(self) -> None:
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None


def _history_path(config: 'SimpleConfig') -> str:
    return os.path.join(config.path, HISTORY_FILE_NAME)


def read_history(config: 'SimpleConfig') -> List[dict]:
    """Returns what the last catch-ups in the background did, oldest first.

    An entry without 'finished' is a catch-up that the OS killed, or one that is running.
    """
    entries = []
    try:
        with open(_history_path(config), encoding='utf-8') as f:
            for line in f:
                try:
                    entry = json.loads(line)
                except ValueError:
                    continue
                if isinstance(entry, dict) and isinstance(entry.get('started'), int):
                    entries.append(entry)
    except OSError:
        pass
    return entries


def _save_history_entry(config: 'SimpleConfig', entry: dict) -> None:
    """Adds the entry, or replaces the one of the same catch-up."""
    entries = [e for e in read_history(config) if e['started'] != entry['started']] + [entry]
    entries = entries[-NUM_HISTORY_ENTRIES_KEEP:]
    path = _history_path(config)
    tmp_path = path + '.tmp'
    with open(tmp_path, 'w', encoding='utf-8') as f:
        for e in entries:
            f.write(json.dumps(e, sort_keys=True) + '\n')
    os.replace(tmp_path, path)


def _android_traffic() -> Optional[List[int]]:
    """Returns the bytes received and sent by the app so far, if the OS tells."""
    if 'ANDROID_DATA' not in os.environ:
        return None
    try:
        import jnius
        traffic_stats = jnius.autoclass('android.net.TrafficStats')
        uid = jnius.autoclass('android.os.Process').myUid()
        rx, tx = traffic_stats.getUidRxBytes(uid), traffic_stats.getUidTxBytes(uid)
    except Exception as e:
        _logger.info(f"could not read the traffic counters: {e!r}")
        return None
    if rx < 0 or tx < 0:  # TrafficStats.UNSUPPORTED
        return None
    return [rx, tx]


async def catch_up(network: 'Network', *, timeout: float = DEFAULT_TIMEOUT) -> dict:
    """Runs only the gossip, until it has caught up or the time is up. Returns some numbers about it."""
    network.start_gossip()
    lngossip = network.lngossip
    if lngossip is None:
        raise Exception("gossip is disabled")
    # We run often, so traffic matters more than a second opinion: peers resend the same gossip.
    lngossip.GOSSIP_BACKLOG_NUM_PEERS = 1
    result = {}
    try:
        async with ignore_after(timeout):
            # loading the db takes a while on a phone, and we only connect to nodes after that
            await network.channel_db.data_loaded.wait()
            no_peers_since = time.monotonic()
            while not lngossip.is_caught_up():
                await asyncio.sleep(1)
                if lngossip.lnpeermgr.num_peers() > 0:
                    no_peers_since = None
                elif no_peers_since is None:
                    no_peers_since = time.monotonic()
                elif time.monotonic() - no_peers_since > NO_PEERS_TIMEOUT:
                    _logger.info("no node can be reached. giving up")
                    break
    finally:
        channel_db = network.channel_db
        result.update({
            'caught_up': lngossip.is_caught_up(),
            'synced_until': lngossip.get_gossip_synced_until(),
            'peers': lngossip.lnpeermgr.num_peers(),
            'channel_announcements': lngossip._num_chan_ann,
            'channel_updates': lngossip._num_chan_upd,
            'channel_updates_good': lngossip._num_chan_upd_good,
            'peers_resending_pruned_channels': lngossip._num_peers_resending_pruned_chans,
            'node_announcements': lngossip._num_node_ann,
            'channels': channel_db.num_channels,
            'policies': channel_db.num_policies,
        })
        # waits until the db has written everything to disk
        await network.stop_gossip(full_shutdown=True)
    return result


def set_config_options_for_android_service(config_options: dict) -> bool:
    """If the OS started us as the background service (see GossipSyncService.java), sets the
    options for that, and returns True."""
    if os.environ.get('PYTHON_SERVICE_ARGUMENT') != ANDROID_SERVICE_ARGUMENT:
        return False
    from .simple_config import SimpleConfig
    config_options['cmd'] = CMD_NAME
    # The config file belongs to the app. The app can start at any moment, which gets us killed,
    # and a write that is cut short would leave a broken file.
    config_options[SimpleConfig.CONFIG_FORGET_CHANGES.key()] = True
    return True


def run(config: 'SimpleConfig', *, timeout: float = DEFAULT_TIMEOUT) -> bool:
    """Catches up on gossip once and records the outcome. To be called with the event loop running,
    in a process that does nothing else. Returns whether we caught up.
    """
    from .network import Network
    lock = GossipDbLock(config)
    if not lock.acquire():
        _logger.info("the gossip db is in use: the app is running. nothing to do")
        return False
    entry = {'started': int(time.time())}
    try:
        if not config.LIGHTNING_USE_GOSSIP or not config.LIGHTNING_GOSSIP_BACKGROUND_SYNC:
            # (the app cancels the job when the user changes these settings)
            _logger.info("gossip, or updating it in the background, is disabled. nothing to do")
            return False
        _save_history_entry(config, entry)
        traffic_before = _android_traffic()
        t0 = time.monotonic()
        try:
            network = Network(config)
            entry.update(Network.run_from_another_thread(catch_up(network, timeout=timeout)))
        except Exception as e:
            _logger.exception("catching up on gossip failed")
            entry['error'] = repr(e)
        traffic_after = _android_traffic()
        if traffic_before and traffic_after:
            entry['rx_bytes'] = traffic_after[0] - traffic_before[0]
            entry['tx_bytes'] = traffic_after[1] - traffic_before[1]
        entry['seconds'] = round(time.monotonic() - t0)
        entry['finished'] = int(time.time())
        _save_history_entry(config, entry)
        _logger.info(f"done: {entry}")
        return bool(entry.get('caught_up'))
    finally:
        lock.release()


class BackgroundCatchUpManager:
    """The app's side of the catch-ups in the background, on Android.

    `job_service` is the java class GossipSyncJobService, which has the details.
    """

    LOCK_TIMEOUT = 10  # seconds
    MIN_INTERVAL = 15  # minutes. the OS does not run periodic jobs more often
    NUM_HISTORY_ENTRIES_TO_LOG = 30
    POLL_INTERVAL = 5  # seconds
    # Some systems suspend an app soon after the user leaves it, others let it run for hours (e.g. if the
    # user exempted it from battery optimizations). So that the gossip does not go on arriving for as long,
    # also on a metered network, we pause it ourselves once the app has been in the background for this
    # long. The catch-ups the OS wakes us up for, and the user coming back, resume it.
    BACKGROUND_GRACE = 5 * 60  # seconds

    _android_app_instance = None  # type: Optional[BackgroundCatchUpManager]

    def __init__(self, config: 'SimpleConfig', *, job_service, context):
        self.config = config
        self.job_service = job_service
        self.context = context
        self.lock = GossipDbLock(config)
        self.is_started = False
        self.last_catch_up = None  # type: Optional[dict]
        # about the job that is keeping the app awake, if any: whether we saw it, and since when we have no peers
        self._job_seen = False
        self._job_no_peers_since = None  # type: Optional[float]
        self._job_entry = None  # type: Optional[dict]  # what goes to the history about it
        # since when (time.monotonic) the app is in the background, if it is. set by the GUI thread
        self._background_since = None  # type: Optional[float]
        # (time.monotonic, bytes received and sent by the app) when we last looked at the traffic counters
        self._traffic_mark = None  # type: Optional[Tuple[float, List[int]]]

    @classmethod
    def for_android_app(cls, config: 'SimpleConfig') -> 'BackgroundCatchUpManager':
        """Returns the manager of the running app, creating it the first time."""
        if cls._android_app_instance is None:
            from jnius import autoclass
            cls._android_app_instance = cls(
                config,
                job_service=autoclass('org.electrum.gossip.GossipSyncJobService'),
                context=autoclass('org.kivy.android.PythonActivity').mActivity)
        return cls._android_app_instance

    def on_app_start(self) -> None:
        """To be called when the app starts, before it uses its files: the background process
        uses the gossip db, and looks at the block headers."""
        self.is_started = True
        # Stops the background process if it is running. The OS releases its lock when it is gone.
        self.job_service.onAppStarted(self.context)
        if not self.lock.acquire(timeout=self.LOCK_TIMEOUT):
            # Should not happen. Two processes writing to the gossip db do not corrupt it (it is
            # sqlite), but writes can fail, and then gossip stops working until the next start.
            _logger.warning("could not get the lock of the gossip db: is another process using it?")
        try:
            history = read_history(self.config)
            for entry in history[-self.NUM_HISTORY_ENTRIES_TO_LOG:]:
                _logger.info(f"catch-up on gossip in the background: {json.dumps(entry, sort_keys=True)}")
            self.last_catch_up = history[-1] if history else None
        except Exception as e:
            _logger.warning(f"could not read the history of the catch-ups in the background: {e!r}")
        self._traffic_since_mark(time.monotonic())  # from here on we count what the app uses
        self.update_schedule()

    def update_schedule(self) -> None:
        """To be called when a setting it depends on changes."""
        config = self.config
        if config.LIGHTNING_USE_GOSSIP and config.LIGHTNING_GOSSIP_BACKGROUND_SYNC:
            interval = max(self.MIN_INTERVAL, config.LIGHTNING_GOSSIP_BACKGROUND_SYNC_INTERVAL)
            unmetered_only = config.LIGHTNING_GOSSIP_BACKGROUND_SYNC_UNMETERED_ONLY
            charging_only = config.LIGHTNING_GOSSIP_BACKGROUND_SYNC_CHARGING_ONLY
            is_scheduled = self.job_service.schedule(self.context, interval, unmetered_only, charging_only)
            _logger.info(f"catch-up on gossip in the background every {interval} minutes. "
                         f"{unmetered_only=}, {charging_only=}, {is_scheduled=}, "
                         f"restricted_by_the_os={self.is_restricted_by_the_os()}")
        else:
            self.job_service.cancel(self.context)

    def is_restricted_by_the_os(self) -> bool:
        """Whether the catch-ups are on, but the OS optimizes the battery use of the app: it then
        delays background work, by hours or a day once the app has not been used for a while."""
        config = self.config
        if not (config.LIGHTNING_USE_GOSSIP and config.LIGHTNING_GOSSIP_BACKGROUND_SYNC):
            return False
        return not self.job_service.isIgnoringBatteryOptimizations(self.context)

    def request_to_lift_restriction(self) -> bool:
        """Shows what the OS has for the user to exempt the app. Returns whether that got shown."""
        return bool(self.job_service.requestIgnoreBatteryOptimizations(self.context))

    def set_app_in_background(self, in_background: bool) -> None:
        """To be called, from any thread, when the user leaves the app or comes back to it."""
        if not in_background:
            self._background_since = None
        elif self._background_since is None:
            self._background_since = time.monotonic()

    def _traffic_since_mark(self, now: float) -> Optional[Tuple[int, int, int]]:
        """Returns the seconds passed, and the bytes the app received and sent, since we last looked,
        if the OS tells. The counters are those of the app as a whole, not only of the gossip."""
        traffic = _android_traffic()
        mark = self._traffic_mark
        self._traffic_mark = (now, traffic) if traffic else None
        if not traffic or not mark:
            return None
        then, traffic_then = mark
        return round(now - then), traffic[0] - traffic_then[0], traffic[1] - traffic_then[1]

    def poll(self, network: Optional['Network']) -> None:
        """Pauses the gossip while the app is in the background, and resumes it for the user, and for the
        OS when it wakes the app up to catch up on gossip: this then tells it when that is done, so that
        it can suspend the app again."""
        now = time.monotonic()
        lngossip = network.lngossip if network else None
        is_job_running = self.job_service.isJobRunningInApp()
        background_since = self._background_since
        if lngossip is not None:
            if is_job_running or background_since is None:
                from .lnworker import LNGossip
                # Woken up by the OS only to catch up, we save traffic as the background process does:
                # peers resend the same gossip, so a second source is of little use.
                lngossip.GOSSIP_BACKLOG_NUM_PEERS = 1 if background_since is not None else LNGossip.GOSSIP_BACKLOG_NUM_PEERS
                if lngossip.is_paused():
                    lngossip.resume()
            elif now - background_since >= self.BACKGROUND_GRACE and not lngossip.is_paused():
                lngossip.pause()
        if not is_job_running:
            self._job_seen = False
            return
        if not self._job_seen:
            self._job_entry = {'started': int(time.time()), 'in_app': True}
            if idle := self._traffic_since_mark(now):
                # what the app used since the previous catch-up, or since it started
                self._job_entry['idle_seconds'], self._job_entry['idle_rx_bytes'], self._job_entry['idle_tx_bytes'] = idle
        if lngossip is not None and lngossip.lnpeermgr.num_peers() > 0:
            self._job_no_peers_since = None
        elif not self._job_seen or self._job_no_peers_since is None:
            self._job_no_peers_since = now
        self._job_seen = True
        if lngossip is None:
            reason = "there is no gossip to catch up on"
        elif lngossip.is_caught_up():
            reason = "gossip has caught up"
        elif self._job_no_peers_since is not None and now - self._job_no_peers_since > NO_PEERS_TIMEOUT:
            # (connections from before the OS suspended us still count as peers at first)
            reason = "no node can be reached"
        else:
            return
        entry, self._job_entry = self._job_entry or {}, None
        try:
            entry['finished'] = int(time.time())
            entry['caught_up'] = lngossip is not None and lngossip.is_caught_up()
            if lngossip is not None:
                entry['synced_until'] = lngossip.get_gossip_synced_until()
            if used := self._traffic_since_mark(now):
                entry['seconds'], entry['rx_bytes'], entry['tx_bytes'] = used
            if 'started' in entry and lngossip is not None:  # else there was nothing to do, e.g. at startup
                _save_history_entry(self.config, entry)
                self.last_catch_up = entry
        except Exception as e:
            _logger.warning(f"could not record the catch-up in the background: {e!r}")
        _logger.info(f"woken up in the background: {reason}. {json.dumps(entry, sort_keys=True, default=repr)}")
        self._job_seen = False
        self.job_service.finishJobInApp()

    async def poll_loop(self, network: Optional['Network']) -> None:
        """To be run on the event loop of the network, not by the GUI: the GUI does not run
        while the app is in the background."""
        while True:
            await asyncio.sleep(self.POLL_INTERVAL)
            self.poll_safely(network)

    def poll_safely(self, network: Optional['Network']) -> None:
        try:
            self.poll(network)
        except Exception as e:
            _logger.warning(f"poll failed: {e!r}")
