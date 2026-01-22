import asyncio
from collections import defaultdict
import datetime
import os
import time
from typing import Sequence, Mapping, TypeVar, Optional
import weakref

from electrum import util
from electrum.util import ThreadJob


_U = TypeVar('_U')

def count_objects_in_memory(mclasses: Sequence[type[_U]]) -> Mapping[type[_U], Sequence[weakref.ref[_U]]]:
    import gc
    gc.collect()
    objmap = defaultdict(list)
    for obj in gc.get_objects():
        for class_ in mclasses:
            try:
                _isinstance = isinstance(obj, class_)
            except AttributeError:
                _isinstance = False
            if _isinstance:
                objmap[class_].append(weakref.ref(obj))
    return objmap


class DebugMem(ThreadJob):
    '''A handy class for debugging GC memory leaks

    In Qt console:
    >>> from electrum.utils.memory_leak import DebugMem
    >>> from electrum.wallet import Abstract_Wallet
    >>> plugins.add_jobs([DebugMem([Abstract_Wallet,], interval=5)])
    '''
    def __init__(self, classes, interval=30):
        ThreadJob.__init__(self)
        self.next_time = 0
        self.classes = classes
        self.interval = interval

    def mem_stats(self):
        self.logger.info("Start memscan")
        objmap = count_objects_in_memory(self.classes)
        for class_, objs in objmap.items():
            self.logger.info(f"{class_.__name__}: {len(objs)}")
        self.logger.info("Finish memscan")

    def run(self):
        if time.time() > self.next_time:
            self.mem_stats()
            self.next_time = time.time() + self.interval


async def wait_until_obj_is_garbage_collected(wr: weakref.ref) -> None:
    """Async wait until the object referenced by `wr` is GC-ed."""
    obj = wr()
    if obj is None:
        return
    evt_gc = asyncio.Event()  # set when obj is finally GC-ed.
    wr2 = weakref.ref(obj, lambda _x: util.run_sync_function_on_asyncio_thread(evt_gc.set, block=False))
    del obj
    while True:
        try:
            async with util.async_timeout(0.01):
                await evt_gc.wait()
        except asyncio.TimeoutError:
            import gc
            gc.collect()
        else:
            break
    assert evt_gc.is_set()


def debug_memusage_list_all_objects(limit: int = 50) -> list[tuple[str, int]]:
    """Return a string listing the most common types in memory."""
    import objgraph  # 3rd-party dependency
    return objgraph.most_common_types(
        limit=limit,
        shortnames=False,
    )


def debug_memusage_dump_random_backref_chain(objtype: str) -> Optional[str]:
    """Writes a dotfile to cwd, containing the backref chain
    for a randomly selected object of type objtype.

    Warning: very slow!

    In Qt console:
    >>> debug_memusage_dump_random_backref_chain("Standard_Wallet")

    To convert to image:
    $ dot -Tps filename.dot -o outfile.ps
    """
    import objgraph  # 3rd-party dependency
    import random
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    fpath = os.path.abspath(f"electrum_backref_chain_{timestamp}.dot")
    objects = objgraph.by_type(objtype)
    if not objects:
        return None
    random_obj = random.choice(objects)
    with open(fpath, "w") as f:
        objgraph.show_chain(
            objgraph.find_backref_chain(
                random_obj,
                objgraph.is_proper_module),
            output=f)
    return fpath
