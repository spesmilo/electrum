import asyncio
import json
import os
import re
import sys
from unittest import mock

from electrum import gossip_catch_up, util
from electrum.gossip_catch_up import GossipDbLock
from electrum.network import Network
from electrum.simple_config import SimpleConfig

from . import ElectrumTestCase


class _FakeLNGossip:

    def __init__(self, *, caught_up_after_checks):
        self._checks_left = caught_up_after_checks
        self.lnpeermgr = mock.Mock(num_peers=lambda: 3)
        self._num_chan_ann, self._num_chan_upd, self._num_chan_upd_good, self._num_node_ann = 1, 20, 15, 4

    def is_caught_up(self):
        self._checks_left -= 1
        return self._checks_left < 0

    GOSSIP_BACKLOG_NUM_PEERS = 2

    def get_gossip_synced_until(self):
        return 1_700_000_000


class _FakeNetwork:
    """what gossip_catch_up needs of a Network"""

    instances = []
    lngossip_factory = None
    db_load_time = 0  # seconds
    run_from_another_thread = Network.run_from_another_thread

    def __init__(self, config):
        self.config = config
        self.lngossip = None
        self.channel_db = None
        self.stopped_gossip = []
        self.instances.append(self)

    def start_gossip(self):
        if not self.config.LIGHTNING_USE_GOSSIP:
            return
        self.lngossip = self.lngossip_factory()
        self.channel_db = mock.Mock(num_channels=30_000, num_policies=50_000, data_loaded=asyncio.Event())
        util.get_asyncio_loop().call_later(self.db_load_time, self.channel_db.data_loaded.set)

    async def stop_gossip(self, *, full_shutdown=False):
        self.stopped_gossip.append(full_shutdown)
        self.lngossip = self.channel_db = None


class TestGossipCatchUp(ElectrumTestCase):

    def setUp(self):
        super().setUp()
        self.config = SimpleConfig({'electrum_path': self.electrum_path})
        self.config.LIGHTNING_USE_GOSSIP = True
        _FakeNetwork.instances = []
        _FakeNetwork.db_load_time = 0
        _FakeNetwork.lngossip_factory = lambda _: _FakeLNGossip(caught_up_after_checks=2)
        patcher = mock.patch('electrum.network.Network', _FakeNetwork)
        patcher.start()
        self.addCleanup(patcher.stop)
        sleep = asyncio.sleep
        patcher = mock.patch.object(gossip_catch_up.asyncio, 'sleep', lambda delay: sleep(delay / 1000))
        patcher.start()
        self.addCleanup(patcher.stop)

    async def _run(self, **kwargs) -> bool:
        # as in the background process: not on the thread of the event loop
        return await asyncio.to_thread(gossip_catch_up.run, self.config, **kwargs)

    def test_lock_is_exclusive_until_released(self):
        lock1, lock2 = GossipDbLock(self.config), GossipDbLock(self.config)
        self.assertEqual(os.path.join(self.electrum_path, 'gossip_db.lock'), lock1.path)
        self.assertTrue(lock1.acquire())
        self.assertTrue(lock1.acquire())  # we have it already
        self.assertFalse(lock2.acquire())
        self.assertFalse(lock2.acquire(timeout=0.3))
        lock1.release()
        lock1.release()
        self.assertTrue(lock2.acquire())
        self.assertFalse(lock1.acquire())
        lock2.release()

    async def test_lock_can_be_waited_for(self):
        lock1, lock2 = GossipDbLock(self.config), GossipDbLock(self.config)
        self.assertTrue(lock1.acquire())
        waiter = asyncio.create_task(asyncio.to_thread(lock2.acquire, timeout=10))
        await asyncio.sleep(0.3)
        self.assertFalse(waiter.done())
        lock1.release()
        self.assertTrue(await asyncio.wait_for(waiter, 5))
        lock2.release()

    async def test_catch_up_runs_the_gossip_until_caught_up_and_stops_it(self):
        self.assertTrue(await self._run())
        network, = _FakeNetwork.instances
        self.assertEqual([True], network.stopped_gossip)  # waits for the db to be written
        entry, = gossip_catch_up.read_history(self.config)
        entry_started = entry.pop('started')
        self.assertGreaterEqual(entry.pop('finished'), entry_started)
        self.assertGreaterEqual(entry.pop('seconds'), 0)
        self.assertEqual({
            'caught_up': True, 'synced_until': 1_700_000_000, 'peers': 3,
            'channel_announcements': 1, 'channel_updates': 20, 'channel_updates_good': 15, 'node_announcements': 4,
            'channels': 30_000, 'policies': 50_000}, entry)
        # the lock got released
        with mock.patch.object(gossip_catch_up.time, 'time', return_value=entry_started + 3600):
            self.assertTrue(await self._run())
        self.assertEqual([entry_started, entry_started + 3600],
                         [entry['started'] for entry in gossip_catch_up.read_history(self.config)])

    async def test_catch_up_asks_a_single_peer_for_the_backlog(self):
        lngossips = []
        def lngossip_factory(_):
            lngossips.append(_FakeLNGossip(caught_up_after_checks=1))
            return lngossips[-1]
        _FakeNetwork.lngossip_factory = lngossip_factory
        await self._run()
        self.assertEqual(1, lngossips[0].GOSSIP_BACKLOG_NUM_PEERS)
        self.assertEqual(2, _FakeLNGossip.GOSSIP_BACKLOG_NUM_PEERS)

    async def test_catch_up_gives_up_when_the_time_is_up(self):
        _FakeNetwork.lngossip_factory = lambda _: _FakeLNGossip(caught_up_after_checks=10 ** 9)
        self.assertFalse(await self._run(timeout=0.2))
        network, = _FakeNetwork.instances
        self.assertEqual([True], network.stopped_gossip)
        entry, = gossip_catch_up.read_history(self.config)
        self.assertFalse(entry['caught_up'])
        self.assertIn('finished', entry)

    async def test_catch_up_gives_up_early_without_peers(self):
        lngossip = _FakeLNGossip(caught_up_after_checks=10 ** 9)
        lngossip.lnpeermgr.num_peers = lambda: 0
        _FakeNetwork.lngossip_factory = lambda _: lngossip
        with mock.patch.object(gossip_catch_up, 'NO_PEERS_TIMEOUT', 0.05):
            self.assertFalse(await asyncio.wait_for(self._run(timeout=3600), 10))
        entry, = gossip_catch_up.read_history(self.config)
        self.assertEqual((False, 0), (entry['caught_up'], entry['peers']))
        self.assertIn('finished', entry)

    async def test_time_to_load_the_db_does_not_count_as_time_without_peers(self):
        # on a phone the db takes about as long to load as we are willing to wait for peers
        _FakeNetwork.db_load_time = 0.5
        peers = []
        lngossip = _FakeLNGossip(caught_up_after_checks=3)
        def num_peers():
            # we only connect to nodes once the db is loaded
            if _FakeNetwork.instances[0].channel_db.data_loaded.is_set():
                peers.append(1)
            return len(peers)
        lngossip.lnpeermgr.num_peers = num_peers
        _FakeNetwork.lngossip_factory = lambda _: lngossip
        with mock.patch.object(gossip_catch_up, 'NO_PEERS_TIMEOUT', 0.1):
            self.assertTrue(await asyncio.wait_for(self._run(timeout=3600), 10))
        self.assertTrue(peers)

    async def test_losing_the_peers_for_a_moment_is_not_a_reason_to_give_up(self):
        num_peers = iter([1, 0, 1, 0, 1, 0, 1, 1, 1, 1])  # e.g. the wifi reconnects
        lngossip = _FakeLNGossip(caught_up_after_checks=6)
        lngossip.lnpeermgr.num_peers = lambda: next(num_peers)
        _FakeNetwork.lngossip_factory = lambda _: lngossip
        with mock.patch.object(gossip_catch_up, 'NO_PEERS_TIMEOUT', 0.05):
            self.assertTrue(await asyncio.wait_for(self._run(timeout=3600), 10))

    async def test_catch_up_gives_up_if_the_peers_are_lost_for_good(self):
        num_peers = iter([1, 1] + [0] * 10 ** 6)
        lngossip = _FakeLNGossip(caught_up_after_checks=10 ** 9)
        lngossip.lnpeermgr.num_peers = lambda: next(num_peers)
        _FakeNetwork.lngossip_factory = lambda _: lngossip
        with mock.patch.object(gossip_catch_up, 'NO_PEERS_TIMEOUT', 0.05):
            self.assertFalse(await asyncio.wait_for(self._run(timeout=3600), 10))
        entry, = gossip_catch_up.read_history(self.config)
        self.assertFalse(entry['caught_up'])

    async def test_db_that_does_not_load_in_time_is_not_waited_for_forever(self):
        _FakeNetwork.db_load_time = 3600
        self.assertFalse(await asyncio.wait_for(self._run(timeout=0.2), 10))
        network, = _FakeNetwork.instances
        self.assertEqual([True], network.stopped_gossip)

    async def test_lock_is_held_while_the_gossip_runs(self):
        seen = []
        def is_lock_free():
            other = GossipDbLock(self.config)
            try:
                return other.acquire()
            finally:
                other.release()
        class LNGossip(_FakeLNGossip):
            def is_caught_up(self):
                seen.append(is_lock_free())
                return super().is_caught_up()
        _FakeNetwork.lngossip_factory = lambda _: LNGossip(caught_up_after_checks=2)
        stop_gossip = _FakeNetwork.stop_gossip
        async def stop_gossip_and_check(network, **kwargs):
            seen.append(is_lock_free())  # the db is still being written when the gossip gets stopped
            await stop_gossip(network, **kwargs)
        with mock.patch.object(_FakeNetwork, 'stop_gossip', stop_gossip_and_check):
            self.assertTrue(await self._run())
        self.assertGreaterEqual(len(seen), 4)
        self.assertEqual({False}, set(seen))
        self.assertTrue(is_lock_free())

    def test_android_service_gets_its_command_and_does_not_write_the_config(self):
        self.assertEqual('gossip_catch_up', gossip_catch_up.ANDROID_SERVICE_ARGUMENT)
        for argument in (None, '', 'something else'):
            env = {} if argument is None else {'PYTHON_SERVICE_ARGUMENT': argument}
            with mock.patch.dict(os.environ, env):
                os.environ.pop('PYTHON_SERVICE_ARGUMENT', None) if argument is None else None
                config_options = {'cmd': 'gui'}
                self.assertFalse(gossip_catch_up.set_config_options_for_android_service(config_options))
                self.assertEqual({'cmd': 'gui'}, config_options)
        with mock.patch.dict(os.environ, {'PYTHON_SERVICE_ARGUMENT': 'gossip_catch_up'}):
            config_options = {'cmd': 'gui', 'electrum_path': self.electrum_path}
            self.assertTrue(gossip_catch_up.set_config_options_for_android_service(config_options))
        self.assertEqual(gossip_catch_up.CMD_NAME, config_options['cmd'])
        # the config file belongs to the app: a config made from these options does not write it
        config_path = os.path.join(self.electrum_path, 'config')
        with open(config_path, 'w', encoding='utf-8') as f:
            f.write('{"use_gossip": true}')  # no config_version: opening it upgrades it
        config = SimpleConfig(config_options)
        self.assertTrue(config.LIGHTNING_USE_GOSSIP)
        config.LIGHTNING_GOSSIP_BACKGROUND_SYNC_INTERVAL = 240
        with open(config_path, encoding='utf-8') as f:
            self.assertEqual('{"use_gossip": true}', f.read())
        # the same without that option does write it
        del config_options[SimpleConfig.CONFIG_FORGET_CHANGES.key()]
        SimpleConfig(config_options)
        with open(config_path, encoding='utf-8') as f:
            self.assertIn('config_version', f.read())

    def test_app_stops_the_background_process_before_it_creates_the_daemon(self):
        # The daemon creates the network, which looks at the block headers, as the background process does.
        # (run_electrum is a script, so this only reads it. The order was also checked on an emulator.)
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, 'run_electrum'), encoding='utf-8') as f:
            source = f.read()
        gui_branch = source[source.index("    if cmdname == 'gui':\n        configure_logging(config)"):]
        gui_branch = gui_branch[:gui_branch.index("    elif cmdname == 'daemon':")]
        app_start = gui_branch.index('BackgroundCatchUpManager.for_android_app(config).on_app_start()')
        self.assertLess(app_start, gui_branch.index('daemon.get_file_descriptor(config)'))
        self.assertLess(app_start, gui_branch.index('daemon.Daemon('))
        self.assertIn('gossip_catch_up.set_config_options_for_android_service(config_options)', source)
        self.assertIn('if cmdname == gossip_catch_up.CMD_NAME:', source)

    def test_constants_shared_with_the_java_side(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        java_dir = os.path.join(root, 'electrum', 'gui', 'qml', 'java_classes', 'org', 'electrum', 'gossip')
        with open(os.path.join(java_dir, 'GossipSyncService.java'), encoding='utf-8') as f:
            service = f.read()
        with open(os.path.join(java_dir, 'GossipSyncJobService.java'), encoding='utf-8') as f:
            job_service = f.read()
        with open(os.path.join(root, 'contrib', 'android', 'p4a_hook.py'), encoding='utf-8') as f:
            hook = f.read()
        argument, = re.findall(r'PYTHON_ARGUMENT = "(\w+)";', service)
        self.assertEqual(gossip_catch_up.ANDROID_SERVICE_ARGUMENT, argument)
        process_suffix, = re.findall(r'PROCESS_NAME_SUFFIX = "(:\w+)";', service)
        self.assertIn(f'android:process="{process_suffix}"', hook)
        # python stops by itself, to write everything to disk, before the job gives up on it
        max_run_minutes, = re.findall(r'MAX_RUN_MILLIS = (\d+) \* 60 \* 1000;', job_service)
        self.assertLessEqual(gossip_catch_up.DEFAULT_TIMEOUT + 30, int(max_run_minutes) * 60)
        self.assertLessEqual(int(max_run_minutes), 9)  # the OS stops a job after about ten minutes
        for name in ('GossipSyncJobService', 'GossipSyncService'):
            self.assertIn(f'android:name="org.electrum.gossip.{name}"', hook)
            self.assertTrue(os.path.exists(os.path.join(java_dir, name + '.java')))
        # the job runs about every interval: with a flex, see GossipSyncJobService.schedule
        # (a text guard only: the java code does not run in these tests)
        self.assertIn('.setPeriodic(intervalMillis, flexMillis)', job_service)
        self.assertIn('long flexMillis = Math.max(intervalMillis / 4, JobInfo.getMinFlexMillis());', job_service)
        # what python calls on the job service
        for signature in ('boolean isIgnoringBatteryOptimizations(Context context)',
                          'boolean requestIgnoreBatteryOptimizations(Context context)'):
            self.assertIn('public static ' + signature, job_service)

    async def test_nothing_is_done_while_the_app_uses_the_gossip_db(self):
        app_lock = GossipDbLock(self.config)
        self.assertTrue(app_lock.acquire())
        self.assertFalse(await self._run())
        self.assertEqual([], _FakeNetwork.instances)
        self.assertEqual([], gossip_catch_up.read_history(self.config))
        app_lock.release()

    async def test_nothing_is_done_if_gossip_is_disabled(self):
        self.config.LIGHTNING_USE_GOSSIP = False
        self.assertFalse(await self._run())
        self.assertEqual([], _FakeNetwork.instances)
        self.assertEqual([], gossip_catch_up.read_history(self.config))
        self.assertTrue(GossipDbLock(self.config).acquire())  # the lock got released

    async def test_nothing_is_done_if_updating_in_the_background_is_disabled(self):
        self.config.LIGHTNING_GOSSIP_BACKGROUND_SYNC = False
        self.assertFalse(await self._run())
        self.assertEqual([], _FakeNetwork.instances)
        self.assertEqual([], gossip_catch_up.read_history(self.config))

    async def test_failure_is_recorded(self):
        def lngossip_factory(_):
            raise Exception("no db")
        _FakeNetwork.lngossip_factory = lngossip_factory
        self.assertFalse(await self._run())
        entry, = gossip_catch_up.read_history(self.config)
        self.assertEqual("Exception('no db')", entry['error'])
        self.assertIn('finished', entry)
        self.assertTrue(GossipDbLock(self.config).acquire())

    async def test_catch_up_that_is_running_or_got_killed_has_an_entry_that_is_not_finished(self):
        started = []
        def lngossip_factory(_):
            started.extend(gossip_catch_up.read_history(self.config))
            return _FakeLNGossip(caught_up_after_checks=0)
        _FakeNetwork.lngossip_factory = lngossip_factory
        await self._run()
        entry, = started
        self.assertEqual(['started'], list(entry))

    def test_history_keeps_the_last_entries_and_skips_garbage(self):
        num_keep = gossip_catch_up.NUM_HISTORY_ENTRIES_KEEP
        for i in range(num_keep + 5):
            gossip_catch_up._save_history_entry(self.config, {'started': i})
        history = gossip_catch_up.read_history(self.config)
        self.assertEqual(list(range(5, num_keep + 5)), [entry['started'] for entry in history])
        # the entry of a catch-up gets replaced when it finishes
        gossip_catch_up._save_history_entry(self.config, {'started': num_keep + 4, 'finished': num_keep + 9})
        history = gossip_catch_up.read_history(self.config)
        self.assertEqual(num_keep, len(history))
        self.assertEqual({'started': num_keep + 4, 'finished': num_keep + 9}, history[-1])
        path = os.path.join(self.electrum_path, gossip_catch_up.HISTORY_FILE_NAME)
        with open(path, 'a', encoding='utf-8') as f:
            f.write('{"started": 1\n[]\n{"finished": 3}\n{"started": "x"}\n' + json.dumps({'started': 10 ** 6}) + '\n')
        history = gossip_catch_up.read_history(self.config)
        self.assertEqual(num_keep + 1, len(history))
        self.assertEqual({'started': 10 ** 6}, history[-1])

    def test_history_of_a_new_datadir_is_empty(self):
        self.assertEqual([], gossip_catch_up.read_history(self.config))

    async def test_catch_up_fails_if_gossip_is_disabled(self):
        self.config.LIGHTNING_USE_GOSSIP = False
        with self.assertRaisesRegex(Exception, "gossip is disabled"):
            await gossip_catch_up.catch_up(_FakeNetwork(self.config), timeout=1)


class TestBackgroundCatchUpManager(ElectrumTestCase):

    def setUp(self):
        super().setUp()
        self.config = SimpleConfig({'electrum_path': self.electrum_path})
        self.config.LIGHTNING_USE_GOSSIP = True
        self.job_service = mock.Mock()
        self.job_service.schedule.return_value = True
        self.context = object()
        self.manager = gossip_catch_up.BackgroundCatchUpManager(
            self.config, job_service=self.job_service, context=self.context)
        self.manager.LOCK_TIMEOUT = 0.3

    def test_app_start_stops_the_background_process_then_takes_the_lock_and_schedules(self):
        calls = []
        def is_lock_free():
            other = GossipDbLock(self.config)
            try:
                return other.acquire()
            finally:
                other.release()
        self.job_service.onAppStarted.side_effect = lambda context: calls.append(('onAppStarted', is_lock_free()))
        self.job_service.schedule.side_effect = lambda *args: calls.append(('schedule', is_lock_free())) or True
        self.manager.on_app_start()
        # the lock is not taken before the background process is told to stop, and is held afterwards
        self.assertEqual([('onAppStarted', True), ('schedule', False)], calls)
        self.assertFalse(is_lock_free())
        self.job_service.onAppStarted.assert_called_once_with(self.context)
        self.assertTrue(self.manager.is_started)

    def test_app_starts_also_if_the_lock_cannot_be_taken(self):
        other = GossipDbLock(self.config)
        self.assertTrue(other.acquire())
        self.manager.on_app_start()
        self.job_service.schedule.assert_called_once()

    def test_schedule_follows_the_settings(self):
        self.assertTrue(self.config.LIGHTNING_GOSSIP_BACKGROUND_SYNC)
        self.manager.update_schedule()
        self.job_service.schedule.assert_called_once_with(self.context, 120, True, False)
        self.job_service.cancel.assert_not_called()
        self.config.LIGHTNING_GOSSIP_BACKGROUND_SYNC_INTERVAL = 5  # the OS does not go below 15 minutes
        self.config.LIGHTNING_GOSSIP_BACKGROUND_SYNC_UNMETERED_ONLY = False
        self.config.LIGHTNING_GOSSIP_BACKGROUND_SYNC_CHARGING_ONLY = True
        self.manager.update_schedule()
        self.job_service.schedule.assert_called_with(self.context, 15, False, True)
        self.config.LIGHTNING_GOSSIP_BACKGROUND_SYNC = False
        self.manager.update_schedule()
        self.job_service.cancel.assert_called_once_with(self.context)
        self.assertEqual(2, self.job_service.schedule.call_count)

    def test_nothing_is_scheduled_with_trampoline(self):
        self.config.LIGHTNING_USE_GOSSIP = False
        self.manager.on_app_start()
        self.job_service.schedule.assert_not_called()
        self.job_service.cancel.assert_called_once_with(self.context)

    def test_app_start_remembers_the_last_catch_up(self):
        self.manager.on_app_start()
        self.assertIsNone(self.manager.last_catch_up)
        gossip_catch_up._save_history_entry(self.config, {'started': 1, 'finished': 2, 'caught_up': True})
        gossip_catch_up._save_history_entry(self.config, {'started': 5})
        manager = gossip_catch_up.BackgroundCatchUpManager(self.config, job_service=self.job_service, context=self.context)
        manager.lock = self.manager.lock
        manager.on_app_start()
        self.assertEqual({'started': 5}, manager.last_catch_up)

    @staticmethod
    def _lngossip(*, num_peers: int = 4, is_caught_up: bool = False, is_paused: bool = False) -> mock.Mock:
        lngossip = mock.Mock()
        lngossip.lnpeermgr.num_peers.return_value = num_peers
        lngossip.is_caught_up.return_value = is_caught_up
        lngossip.is_paused.return_value = is_paused
        lngossip.get_gossip_synced_until.return_value = 1_800_000_000
        lngossip.pause.side_effect = lambda: setattr(lngossip.is_paused, 'return_value', True)
        lngossip.resume.side_effect = lambda: setattr(lngossip.is_paused, 'return_value', False)
        return lngossip

    def test_gossip_is_paused_once_the_app_has_been_in_the_background_for_a_while(self):
        lngossip = self._lngossip(is_caught_up=True)
        network = mock.Mock(lngossip=lngossip)
        self.job_service.isJobRunningInApp.return_value = False
        grace = self.manager.BACKGROUND_GRACE
        self.assertEqual(5 * 60, grace)
        now = [1000.]
        with mock.patch.object(gossip_catch_up.time, 'monotonic', lambda: now[0]):
            # in use: never
            now[0] += 10 * grace
            self.manager.poll(network)
            lngossip.pause.assert_not_called()
            # the user leaves: first the app gets inactive, then suspended
            self.manager.set_app_in_background(True)
            now[0] += 10
            self.manager.set_app_in_background(True)
            now[0] += grace - 11
            self.manager.poll(network)
            lngossip.pause.assert_not_called()
            now[0] += 1
            self.manager.poll(network)
            lngossip.pause.assert_called_once_with()
            now[0] += 3600
            self.manager.poll(network)
            lngossip.pause.assert_called_once_with()
            lngossip.resume.assert_not_called()
            # the user comes back
            self.manager.set_app_in_background(False)
            self.manager.poll(network)
            lngossip.resume.assert_called_once_with()
            self.manager.poll(network)
            lngossip.resume.assert_called_once_with()
            # leaving for a moment, e.g. to copy an invoice from another app, does not pause it
            for _ in range(5):
                self.manager.set_app_in_background(True)
                now[0] += grace - 1
                self.manager.poll(network)
                self.manager.set_app_in_background(False)
                now[0] += 5
                self.manager.poll(network)
            lngossip.pause.assert_called_once_with()
        self.job_service.finishJobInApp.assert_not_called()

    def test_catch_up_for_the_job_asks_a_single_peer_for_the_backlog_as_the_background_process_does(self):
        from electrum.lnworker import LNGossip
        self.assertEqual(2, LNGossip.GOSSIP_BACKLOG_NUM_PEERS)
        lngossip = self._lngossip(is_paused=True)
        network = mock.Mock(lngossip=lngossip)
        self.manager.set_app_in_background(True)
        self.job_service.isJobRunningInApp.return_value = True
        self.manager.poll(network)
        self.assertEqual(1, lngossip.GOSSIP_BACKLOG_NUM_PEERS)
        # the user comes back: the usual second source
        self.job_service.isJobRunningInApp.return_value = False
        self.manager.set_app_in_background(False)
        self.manager.poll(network)
        self.assertEqual(2, lngossip.GOSSIP_BACKLOG_NUM_PEERS)
        # also while the job is still running
        self.manager.set_app_in_background(True)
        self.job_service.isJobRunningInApp.return_value = True
        self.manager.poll(network)
        self.assertEqual(1, lngossip.GOSSIP_BACKLOG_NUM_PEERS)
        self.manager.set_app_in_background(False)
        self.manager.poll(network)
        self.assertEqual(2, lngossip.GOSSIP_BACKLOG_NUM_PEERS)

    def test_gossip_is_resumed_for_the_job_and_paused_again_after_it(self):
        lngossip = self._lngossip(is_paused=True)
        network = mock.Mock(lngossip=lngossip)
        now = [1000.]
        with mock.patch.object(gossip_catch_up.time, 'monotonic', lambda: now[0]):
            self.manager.set_app_in_background(True)
            now[0] += 2 * 3600
            self.job_service.isJobRunningInApp.return_value = True
            self.manager.poll(network)
            lngossip.resume.assert_called_once_with()
            lngossip.pause.assert_not_called()
            self.job_service.finishJobInApp.assert_not_called()
            now[0] += 90
            lngossip.is_caught_up.return_value = True
            self.manager.poll(network)
            self.job_service.finishJobInApp.assert_called_once_with()
            lngossip.pause.assert_not_called()
            self.job_service.isJobRunningInApp.return_value = False
            now[0] += 5
            self.manager.poll(network)
            lngossip.pause.assert_called_once_with()
            lngossip.resume.assert_called_once_with()

    def test_job_in_the_app_is_recorded_with_the_traffic_of_the_app(self):
        lngossip = self._lngossip(is_paused=True)
        network = mock.Mock(lngossip=lngossip)
        now = [1000.]
        traffic = [5_000_000, 100_000]
        with mock.patch.object(gossip_catch_up.time, 'monotonic', lambda: now[0]), \
                mock.patch.object(gossip_catch_up, '_android_traffic', lambda: list(traffic)):
            self.manager.on_app_start()  # from here on the traffic is counted
            self.manager.set_app_in_background(True)
            now[0] += 7200
            traffic[0] += 40_000
            traffic[1] += 9_000
            self.job_service.isJobRunningInApp.return_value = True
            self.manager.poll(network)
            now[0] += 95
            traffic[0] += 4_000_000
            traffic[1] += 60_000
            lngossip.is_caught_up.return_value = True
            with self.assertLogs('electrum', level='INFO') as logs:
                self.manager.poll(network)
        entry, = gossip_catch_up.read_history(self.config)
        self.assertEqual(
            {'in_app': True, 'caught_up': True, 'synced_until': 1_800_000_000,
             'idle_seconds': 7200, 'idle_rx_bytes': 40_000, 'idle_tx_bytes': 9_000,
             'seconds': 95, 'rx_bytes': 4_000_000, 'tx_bytes': 60_000},
            {k: v for k, v in entry.items() if k not in ('started', 'finished')})
        self.assertLessEqual(entry['started'], entry['finished'])
        self.assertEqual(entry, self.manager.last_catch_up)
        self.assertIn('woken up in the background: gossip has caught up. {', '\n'.join(logs.output))
        self.assertIn('"rx_bytes": 4000000', '\n'.join(logs.output))

    def test_job_is_let_go_even_if_it_cannot_be_recorded(self):
        lngossip = self._lngossip(is_caught_up=True)
        self.job_service.isJobRunningInApp.return_value = True
        with mock.patch.object(gossip_catch_up, '_save_history_entry', side_effect=OSError("disk full")):
            self.manager.poll(mock.Mock(lngossip=lngossip))
        self.job_service.finishJobInApp.assert_called_once_with()

    def test_poll_lets_the_job_go_once_gossip_has_caught_up(self):
        lngossip = self._lngossip()
        network = mock.Mock(lngossip=lngossip)
        self.job_service.isJobRunningInApp.return_value = False
        lngossip.is_caught_up.return_value = True
        self.manager.poll(network)
        self.job_service.finishJobInApp.assert_not_called()  # no job is keeping us awake
        self.job_service.isJobRunningInApp.return_value = True
        lngossip.is_caught_up.return_value = False
        self.manager.poll(network)
        self.job_service.finishJobInApp.assert_not_called()
        lngossip.is_caught_up.return_value = True
        self.manager.poll(network)
        self.job_service.finishJobInApp.assert_called_once_with()

    def test_poll_lets_the_job_go_if_no_node_can_be_reached(self):
        lngossip = self._lngossip()
        network = mock.Mock(lngossip=lngossip)
        self.job_service.isJobRunningInApp.return_value = True
        now = [1000.]
        with mock.patch.object(gossip_catch_up.time, 'monotonic', lambda: now[0]):
            lngossip.lnpeermgr.num_peers.return_value = 0
            self.manager.poll(network)
            now[0] += gossip_catch_up.NO_PEERS_TIMEOUT
            self.manager.poll(network)
            self.job_service.finishJobInApp.assert_not_called()  # not yet
            now[0] += 1
            self.manager.poll(network)
            self.job_service.finishJobInApp.assert_called_once_with()
            # the next job gets its own time
            self.job_service.isJobRunningInApp.return_value = False
            self.manager.poll(network)
            self.job_service.isJobRunningInApp.return_value = True
            now[0] += 10 * gossip_catch_up.NO_PEERS_TIMEOUT
            self.manager.poll(network)
            self.job_service.finishJobInApp.assert_called_once_with()

    def test_poll_keeps_the_job_if_the_peers_are_lost_for_a_moment(self):
        lngossip = self._lngossip()
        network = mock.Mock(lngossip=lngossip)
        self.job_service.isJobRunningInApp.return_value = True
        now = [1000.]
        with mock.patch.object(gossip_catch_up.time, 'monotonic', lambda: now[0]):
            for num_peers in [1, 0, 0, 1, 0, 0, 1]:  # e.g. the wifi reconnects
                lngossip.lnpeermgr.num_peers.return_value = num_peers
                self.manager.poll(network)
                now[0] += gossip_catch_up.NO_PEERS_TIMEOUT / 2
            self.job_service.finishJobInApp.assert_not_called()

    def test_poll_lets_the_job_go_if_the_peers_it_had_are_gone_for_good(self):
        # the connections from before the OS suspended us still count as peers at first
        lngossip = self._lngossip()
        network = mock.Mock(lngossip=lngossip)
        self.job_service.isJobRunningInApp.return_value = True
        now = [1000.]
        with mock.patch.object(gossip_catch_up.time, 'monotonic', lambda: now[0]):
            lngossip.lnpeermgr.num_peers.return_value = 4
            self.manager.poll(network)
            lngossip.lnpeermgr.num_peers.return_value = 0  # they were dead, and no node can be reached
            now[0] += 5
            self.manager.poll(network)
            now[0] += gossip_catch_up.NO_PEERS_TIMEOUT
            self.manager.poll(network)
            self.job_service.finishJobInApp.assert_not_called()
            now[0] += 1
            self.manager.poll(network)
            self.job_service.finishJobInApp.assert_called_once_with()

    def test_history_that_cannot_be_read_does_not_stop_the_app_from_scheduling(self):
        with mock.patch.object(gossip_catch_up, 'read_history', side_effect=Exception("broken")):
            self.manager.on_app_start()
        self.job_service.schedule.assert_called_once()
        self.assertIsNone(self.manager.last_catch_up)

    def test_manager_of_the_android_app_is_created_once(self):
        job_service_class, activity_class = mock.Mock(), mock.Mock()
        jnius = mock.Mock(autoclass={'org.electrum.gossip.GossipSyncJobService': job_service_class,
                                     'org.kivy.android.PythonActivity': activity_class}.__getitem__)
        cls = gossip_catch_up.BackgroundCatchUpManager
        self.addCleanup(setattr, cls, '_android_app_instance', None)
        with mock.patch.dict(sys.modules, {'jnius': jnius}):
            manager = cls.for_android_app(self.config)
            self.assertIs(manager, cls.for_android_app(self.config))
        self.assertIs(job_service_class, manager.job_service)
        self.assertIs(activity_class.mActivity, manager.context)
        self.assertFalse(manager.is_started)

    def test_app_is_restricted_while_the_os_optimizes_its_battery_use(self):
        self.job_service.isIgnoringBatteryOptimizations.return_value = False
        self.assertTrue(self.manager.is_restricted_by_the_os())
        self.job_service.isIgnoringBatteryOptimizations.assert_called_with(self.context)
        self.job_service.isIgnoringBatteryOptimizations.return_value = True  # the user exempted the app
        self.assertFalse(self.manager.is_restricted_by_the_os())

    def test_restriction_does_not_matter_if_nothing_is_to_run_in_the_background(self):
        self.job_service.isIgnoringBatteryOptimizations.return_value = False
        self.config.LIGHTNING_GOSSIP_BACKGROUND_SYNC = False
        self.assertFalse(self.manager.is_restricted_by_the_os())
        self.config.LIGHTNING_GOSSIP_BACKGROUND_SYNC = True
        self.assertTrue(self.manager.is_restricted_by_the_os())
        self.config.LIGHTNING_USE_GOSSIP = False  # trampoline
        self.assertFalse(self.manager.is_restricted_by_the_os())
        self.job_service.requestIgnoreBatteryOptimizations.assert_not_called()

    def test_request_to_lift_the_restriction_tells_if_the_os_showed_something(self):
        self.job_service.requestIgnoreBatteryOptimizations.return_value = True
        self.assertIs(True, self.manager.request_to_lift_restriction())
        self.job_service.requestIgnoreBatteryOptimizations.assert_called_once_with(self.context)
        self.job_service.requestIgnoreBatteryOptimizations.return_value = False  # the device has no such screen
        self.assertIs(False, self.manager.request_to_lift_restriction())

    def test_poll_lets_the_job_go_if_there_is_no_gossip_to_wait_for(self):
        self.job_service.isJobRunningInApp.return_value = True
        self.manager.poll(mock.Mock(lngossip=None))  # trampoline, or the gossip has not been started yet
        self.manager.poll(None)  # offline
        self.assertEqual(2, self.job_service.finishJobInApp.call_count)
        # that is not a catch-up to remember
        self.assertEqual([], gossip_catch_up.read_history(self.config))
        self.assertIsNone(self.manager.last_catch_up)

    async def test_poll_loop_keeps_polling_after_a_failure(self):
        polled = []
        def poll(network):
            polled.append(network)
            if len(polled) == 1:
                raise Exception("jni")
        self.manager.poll = poll
        self.manager.POLL_INTERVAL = 0.01
        network = object()
        task = asyncio.create_task(self.manager.poll_loop(network))
        await asyncio.sleep(0.2)
        task.cancel()
        self.assertGreater(len(polled), 2)
        self.assertIs(network, polled[0])
