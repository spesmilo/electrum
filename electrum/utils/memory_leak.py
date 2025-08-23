from collections import defaultdict
import time

from electrum.util import ThreadJob


class DebugMem(ThreadJob):
    '''A handy class for debugging GC memory leaks

    In console:
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
