import asyncio
import weakref

from electrum import util
from electrum.util import EventListener, event_listener, trigger_callback
from electrum.utils.memory_leak import count_objects_in_memory, wait_until_obj_is_garbage_collected
from electrum.simple_config import SimpleConfig

from . import ElectrumTestCase, restore_wallet_from_text__for_unittest


class MyEventListener(EventListener):
    def __init__(self, *, autostart: bool = False):
        self._satoshi_cnt = 0
        self._hal_cnt = 0
        if autostart:
            self.start()

    def start(self):
        self.register_callbacks()

    def stop(self):
        self.unregister_callbacks()

    @event_listener
    async def on_event_satoshi_moves_his_coins(self, arg1, arg2):
        self._satoshi_cnt += 1

    @event_listener
    def on_event_hal_moves_his_coins(self, arg1, arg2):  # non-async
        self._hal_cnt += 1


_count_all_callbacks = util.callback_mgr.count_all_callbacks


async def fast_sleep():
    # sleep a few event loop iterations
    for i in range(5):
        await asyncio.sleep(0)


class TestCallbackMgr(ElectrumTestCase):

    def test_multiple_calls_to_register_callbacks(self):
        self.assertEqual(0, _count_all_callbacks())
        el1 = MyEventListener()
        el2 = MyEventListener()
        self.assertEqual(0, _count_all_callbacks())
        el1.start()
        self.assertEqual(2, _count_all_callbacks())
        el2.start()
        self.assertEqual(4, _count_all_callbacks())
        el1.start()
        self.assertEqual(4, _count_all_callbacks())
        el1.stop()
        self.assertEqual(2, _count_all_callbacks())
        el1.stop()
        self.assertEqual(2, _count_all_callbacks())
        el1.stop()
        self.assertEqual(2, _count_all_callbacks())
        el2.stop()
        self.assertEqual(0, _count_all_callbacks())

    async def test_trigger_callback(self):
        el1 = MyEventListener()
        el1.start()
        el2 = MyEventListener()
        el2.start()
        # trigger some cbs
        self.assertEqual(el1._satoshi_cnt, 0)
        self.assertEqual(el1._hal_cnt, 0)
        trigger_callback('satoshi_moves_his_coins', 0, 0)
        trigger_callback('satoshi_moves_his_coins', 0, 0)
        trigger_callback('satoshi_moves_his_coins', 0, 0)
        trigger_callback('hal_moves_his_coins', 0, 0)
        await fast_sleep()
        self.assertEqual(el1._satoshi_cnt, 3)
        self.assertEqual(el2._satoshi_cnt, 3)
        self.assertEqual(el1._hal_cnt, 1)
        self.assertEqual(el2._hal_cnt, 1)
        # stop one listener, see new triggers are only seen by other one still running
        el1.stop()
        trigger_callback('satoshi_moves_his_coins', 0, 0)
        trigger_callback('hal_moves_his_coins', 0, 0)
        await fast_sleep()
        self.assertEqual(el1._satoshi_cnt, 3)
        self.assertEqual(el2._satoshi_cnt, 4)
        self.assertEqual(el1._hal_cnt, 1)
        self.assertEqual(el2._hal_cnt, 2)

    async def test_gc(self):
        objmap = count_objects_in_memory([MyEventListener])
        self.assertEqual(len(objmap[MyEventListener]), 0)
        self.assertEqual(_count_all_callbacks(), 0)
        el1 = MyEventListener()
        el1.start()
        el2 = MyEventListener()
        el2.start()
        objmap = count_objects_in_memory([MyEventListener])
        self.assertEqual(len(objmap[MyEventListener]), 2)
        self.assertEqual(_count_all_callbacks(), 4)
        # test if we can get GC-ed if we explicitly unregister cbs:
        el1.stop()  # calls unregister_callbacks
        del el1
        objmap = count_objects_in_memory([MyEventListener])
        self.assertEqual(len(objmap[MyEventListener]), 1)
        self.assertEqual(_count_all_callbacks(), 2)
        # test if we can get GC-ed even without unregistering cbs:
        del el2
        objmap = count_objects_in_memory([MyEventListener])
        self.assertEqual(len(objmap[MyEventListener]), 0)
        self.assertEqual(_count_all_callbacks(), 0)

    async def test_gc2(self):
        def func():
            el1 = MyEventListener(autostart=True)
            el1.el2 = MyEventListener(autostart=True)
            el1.el2.el3 = MyEventListener(autostart=True)
            self.assertEqual(_count_all_callbacks(), 6)
        func()
        self.assertEqual(_count_all_callbacks(), 0)

    async def test_gc_complex_using_wallet(self):
        """This test showcases why EventListener uses WeakMethodProper instead of weakref.WeakMethod.
        We need the custom __eq__ for some reason.
        """
        self.assertEqual(_count_all_callbacks(), 0)
        config = SimpleConfig({'electrum_path': self.electrum_path})
        wallet = restore_wallet_from_text__for_unittest(
            "9dk", path=None, config=config,
        )["wallet"]
        assert wallet.lnworker is not None
        # now delete the wallet, and wait for it to get GC-ed
        # note: need to wait for cyclic GC. example: wallet.lnworker.wallet
        wr = weakref.ref(wallet)
        del wallet
        async with util.async_timeout(5):
            await wait_until_obj_is_garbage_collected(wr)
        # by now, all callbacks must have been cleaned up:
        self.assertEqual(_count_all_callbacks(), 0)
