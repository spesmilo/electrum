#!/usr/bin/env python3
#
# Electron Cash - A Bitcoin Cash SPV Wallet
#
# This file Copyright (C) 2019 Calin Culianu <calin.culianu@gmail.com>
# License: MIT License
#
import time
import threading
import queue
import weakref
import math
from collections import defaultdict
from .util import PrintError, print_error

class ExpiringCache:
    ''' A fast cache useful for storing tens of thousands of lightweight items.

    Use this class to cache the results of functions or other computations
    when:

        1. Many identical items are repetitively created (or many duplicate
           computations are repetitively performed) during normal app
           execution, and it makes sense to cache them.
        2. The creation of said items is more computationally expensive than
           accessing this cache.
        3. The memory tradeoff is acceptable. (As with all caches, you are
           trading CPU cost for memory cost).

    An example of this is UI code or string formatting code that refreshes the
    display with (mostly) the same output over and over again. In that case it
    may make more sense to just cache the output items (such as the formatted
    amount results from format_satoshis), rather than regenerate them, as a
    performance tweak.

    ExpiringCache automatically has old items expire if `maxlen' is exceeded.

    Or, alternatively, if `timeout' is not None (and a positive nonzero number)
    items are auto-removed if they are older than `timeout' seconds (even if
    `maxlen' was otherwise not exceeded).  Note that the actual timeout used
    may be rounded up to match the tick granularity of the cache manager (see
    below).

    Items are timestamped with a 'tick count' (granularity of 10 seconds per
    tick). Their timestamp is updated each time they are accessed via `get' (so
    that only the oldest items that are least useful are the first to expire on
    cache overflow).

    get() and put() are fast. A background thread is used to safely
    expire items when the cache overflows (so that get and put never stall
    to manage the cache's size and/or to flush old items).  This background
    thread runs every 10 seconds -- so caches may temporarily overflow past
    their maxlen for up to 10 seconds. '''
    def __init__(self, *, maxlen=10000, name="An Unnamed Cache", timeout=None):
        assert maxlen > 0
        timeout = (isinstance(timeout, (float, int)) and timeout > 0.0 and timeout) or None
        self.timeout_ticks = timeout and math.ceil(timeout/_ExpiringCacheMgr.tick_interval)
        self.maxlen = maxlen
        self.name = name
        self.d = dict()
        _ExpiringCacheMgr.add_cache(self)
    def get(self, key, default=None):
        res = self.d.get(key)
        if res is not None:
            # cache hit
            res[0] = _ExpiringCacheMgr.tick  # update tick access time for this cache hit
            return res[1]
        # cache miss
        return default
    def put(self, key, value):
        self.d[key] = [_ExpiringCacheMgr.tick, value]
    def size_bytes(self):
        ''' Returns the cache's memory usage in bytes. This is done by doing a
        deep, recursive examination of the cache contents. '''
        return get_object_size(
            self.d.copy()  # prevent iterating over a mutating dict.
        )
    def copy_dict(self):
        ''' Returns a copy of the cache contents. Useful for seriliazing
        or otherwise examining the cache. The returned dict format is:
        d[item_key] -> [tick, item_value]'''
        return self.d.copy()
    def __len__(self):
        return len(self.d)
    def __repr__(self):
        name, address, length, maxlen, timeout = (
            self.name, '0x{:x}'.format(id(self)), len(self), self.maxlen,
            ('{:1.1f}'.format(float(self.timeout_ticks * _ExpiringCacheMgr.tick_interval))
                if self.timeout_ticks
                else self.timeout_ticks)
        )
        return (f'<{__class__.__name__} "{name}" at {address}, {length} item{"s" if length != 1 else ""} (maxlen={maxlen} timeout={timeout})>')

class _ExpiringCacheMgr(PrintError):
    '''Do not use this class directly. Instead just create ExpiringCache
    instances and that will handle the creation of this object automatically
    and its lifecycle.

    This is a singleton that manages the ExpiringCaches. It creates a thread
    that wakes up every tick_interval seconds and expires old items from
    overflowing extant caches.

    Note that after the last cache is gc'd the manager thread will exit and
    this singleton object also will expire and clean itself up automatically.'''

    # This lock is used to lock _instance and self.caches.
    # NOTE: This lock *must* be a recursive lock as the gc callback function
    # may end up executing in the same thread as our add_cache() method,
    # due to the way Python GC works!
    _lock = threading.RLock()
    _instance = None
    tick = 0
    tick_interval = 10.0  # seconds; we wake up this often to update 'tick' and also to expire old items for overflowing caches
    debug = False  # If true we print to console when caches expire and go away

    def __init__(self, add_iter=None):
        cls = type(self)
        assert not cls._instance, "_ExpiringCacheMgr is a singleton"
        super().__init__()
        cls._instance = self
        self.q = queue.Queue()
        self.caches = weakref.WeakSet()
        if add_iter:
            self.caches.update(add_iter)
        self.livect = len(self.caches)  # this is updated by add_cache and on_cache_gc below.
        self.thread = threading.Thread(target=self.mgr_thread, daemon=True)
        self.thread.start()

    @classmethod
    def add_cache(cls, *caches):
        assert caches
        new_caches = caches
        with cls._lock:
            slf = cls._instance
            if not slf:
                slf = cls(caches)
                assert slf == cls._instance
            else:
                new_caches = [c for c in caches if c not in slf.caches]
                slf.caches.update(new_caches)
            for cache in new_caches:
                # add finalizer for each new cache
                weakref.finalize(cache, cls.on_cache_gc, cache.name)
            slf.livect = len(slf.caches)

    @classmethod
    def on_cache_gc(cls, name):
        assert cls._instance
        thread2join = None
        with cls._lock:
            slf = cls._instance
            slf.livect -= 1 # we need to keep this counter because the weak set doesn't have the correct length at this point yet.
            if cls.debug:
                slf.print_error("Cache '{}' has been gc'd, {} still alive".format(name, slf.livect))
            if not slf.livect:  # all caches have been gc'd, kill the thread
                if cls.debug:
                    slf.print_error("No more caches, stopping manager thread and removing singleton")
                need2join = slf.thread.is_alive()
                slf.q.put(None)  # signal thread to stop
                if need2join:
                    thread2join = slf.thread
                elif cls.debug:
                    slf.print_error("Warning: Cache thread was stoppped before we had a chance to kill it")
                cls._instance = None  # kill self.
        if thread2join and thread2join is not threading.current_thread():
            # we do this here as defensive programming to avoid deadlocks in case
            # thread ends up taking locks in some future implementation.
            thread2join.join()

    def mgr_thread(self):
        cls = type(self)
        #self.print_error("thread started")
        try:
            while True:
                try:
                    x = self.q.get(timeout=self.tick_interval)
                    return # we got a stop signal
                except queue.Empty:
                    # normal condition, we slept with nothing to do
                    pass
                cls.tick += 1
                for c in tuple(self.caches):  # prevent cache from dying while we iterate
                    # 1. timeout check (off by default unless client code specified a timeout)
                    if c.timeout_ticks and len(c.d) and 0 == (cls.tick % c.timeout_ticks):
                        # expire timed-out items first, if any. This check only runs every timeout_ticks ticks.
                        t0 = time.time()
                        num = cls._remove_timed_out_items(c.d, cls.tick - c.timeout_ticks)
                        tf = time.time()
                        if num:
                            self.print_error("{}: flushed {} timed-out items in {:.02f} msec".format(c.name, num, (tf-t0)*1e3))
                    # 2. maxlen check (always on)
                    len_c = len(c.d)  # capture length here as c.d may mutate and grow while this code executes.
                    if len_c > c.maxlen:
                        t0 = time.time()
                        num = cls._try_to_expire_old_items(c.d, len_c - c.maxlen)
                        tf = time.time()
                        self.print_error("{}: flushed {} items in {:.02f} msec".format(c.name, num, (tf-t0)*1e3))
        finally:
            if cls.debug:
                self.print_error("thread exit")

    @classmethod
    def _try_to_expire_old_items(cls, d_orig, num):
        d = d_orig.copy()  # yes, this is slow but this makes it so we don't need locks.
        if len(d) < num or num <= 0:
            # cache modified from underneath our feet. We abort gracefully and complain.
            print_error(f'[{__class__.__name__}] Cache data may have been removed by another thread. Aborting flush operation and will try again later...')
            return 0

        # bin the cache.dict items by 'tick' (when they were last accessed)
        bins = defaultdict(list)
        for k,v in d.items():
            tick = v[0]
            bins[tick].append(k)
        del d

        # Now, expire the old items starting with the oldest until we
        # expire num items. Note that during this loop it's possible
        # for items to get their timestamp updated by ExpiringCache.get().
        # This loop will not detect that situation and will expire them anyway.
        # This is fine, because it's a corner case and in the interests of
        # keeping this code as simple as possible, we don't bother to guard
        # against that.
        ct = 0
        sorted_bin_keys = sorted(bins.keys())
        while ct < num and bins:
            tick = sorted_bin_keys[0]
            for key in bins[tick]:
                # KeyError here should never happen in normal use, but it
                # may if client code is messing with the .d dict.
                try: del d_orig[key]  # despite appearances, this is atomic (thread-safe)
                except KeyError: pass
                ct += 1
                if ct >= num:
                    break
            else:
                del bins[tick]
                del sorted_bin_keys[0]
        return ct

    @classmethod
    def _remove_timed_out_items(cls, d_orig, tick_cutoff):
        d = d_orig.copy()  # yes, this is slow but this makes it so we don't need locks.
        if not len(d) or tick_cutoff < 0:
            # cache modified from underneath our feet. We abort gracefully and complain.
            print_error(f'[{__class__.__name__}] Cache data may have been removed by another thread. Aborting flush operation and will try again later...')
            return 0

        # scan the cache.dict for items whose 'tick' is older than tick_cutoff
        ct = 0
        for k,v in d.items():
            tick = v[0]
            if tick < tick_cutoff:
                try: del d_orig[k]  # despite appearances, this is atomic (thread-safe)
                except KeyError: pass
                ct += 1
        return ct


def get_object_size(obj_0):
    ''' Debug tool -- returns the amount of memory taken by an object in bytes
    by deeply examining its contents recursively (more accurate than
    sys.getsizeof as a result). '''
    import sys
    import warnings
    from numbers import Number
    from collections import Set, Mapping, deque

    try: # Python 2
        zero_depth_bases = (basestring, Number, xrange, bytearray)
        iteritems = 'iteritems'
    except NameError: # Python 3
        zero_depth_bases = (str, bytes, Number, range, bytearray)
        iteritems = 'items'

    def getsize(obj_0):
        """Recursively iterate to sum size of object & members."""
        _seen_ids = set()
        def inner(obj):
            obj_id = id(obj)
            if obj_id in _seen_ids:
                return 0
            _seen_ids.add(obj_id)
            size = sys.getsizeof(obj)
            if isinstance(obj, zero_depth_bases):
                pass # bypass remaining control flow and return
            elif isinstance(obj, (tuple, list, Set, deque)):
                size += sum(inner(i) for i in obj)
            elif isinstance(obj, Mapping) or hasattr(obj, iteritems):
                try:
                    size += sum(inner(k) + inner(v) for k, v in getattr(obj, iteritems)())
                except Exception as e:
                    warnings.warn(f"warning: unable to process object '{obj}' due to exception: {repr(e)}", RuntimeWarning, stacklevel=2)
            # Check for custom object instances - may subclass above too
            if hasattr(obj, '__dict__'):
                size += inner(vars(obj))
            if hasattr(obj, '__slots__'): # can have __slots__ with __dict__
                size += sum(inner(getattr(obj, s)) for s in obj.__slots__ if hasattr(obj, s))
            return size
        return inner(obj_0)
    return getsize(obj_0)
