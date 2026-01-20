from collections import defaultdict
import datetime
import os
import time

from electrum.util import ThreadJob


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
        import gc
        self.logger.info("Start memscan")
        gc.collect()
        objmap = defaultdict(list)
        for obj in gc.get_objects():
            for class_ in self.classes:
                try:
                    _isinstance = isinstance(obj, class_)
                except AttributeError:
                    _isinstance = False
                if _isinstance:
                    objmap[class_].append(obj)
        for class_, objs in objmap.items():
            self.logger.info(f"{class_.__name__}: {len(objs)}")
        self.logger.info("Finish memscan")

    def run(self):
        if time.time() > self.next_time:
            self.mem_stats()
            self.next_time = time.time() + self.interval


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
