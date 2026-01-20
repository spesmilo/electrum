import asyncio

from electrum import util
from electrum.util import EventListener, event_listener, trigger_callback
from electrum.utils.memory_leak import count_objects_in_memory

from . import ElectrumTestCase


class MyEventListener(EventListener):
    def __init__(self):
        self._satoshi_cnt = 0
        self._hal_cnt = 0

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


def _count_all_callbacks() -> int:
    return sum(len(cbs) for cbs in util.callback_mgr.callbacks.values())


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
        el1 = MyEventListener()
        el1.start()
        el2 = MyEventListener()
        el2.start()
        objmap = count_objects_in_memory([MyEventListener])
        self.assertEqual(len(objmap[MyEventListener]), 2)
        el1.stop()
        del el1
        objmap = count_objects_in_memory([MyEventListener])
        self.assertEqual(len(objmap[MyEventListener]), 1)
