# Copyright (c) 2019 Calin Culianu <calin.culianu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://www.opensource.org/licenses/mit-license.php

from functools import wraps
import threading
import time
import weakref

from PyQt5.QtCore import QObject, QTimer

from electrum.logging import Logger, get_logger


_logger = get_logger(__name__)


class RateLimiter(Logger):
    ''' Manages the state of a @rate_limited decorated function, collating
    multiple invocations. This class is not intended to be used directly. Instead,
    use the @rate_limited decorator (for instance methods).
    This state instance gets inserted into the instance attributes of the target
    object wherever a @rate_limited decorator appears.
    The inserted attribute is named "__FUNCNAME__RateLimiter". '''
    # some defaults
    last_ts = 0.0
    timer = None
    saved_args = (tuple(),dict())
    ctr = 0

    def __init__(self, rate, ts_after, obj, func):
        self.n = func.__name__
        self.qn = func.__qualname__
        self.rate = rate
        self.ts_after = ts_after
        self.obj = weakref.ref(obj) # keep a weak reference to the object to prevent cycles
        self.func = func
        Logger.__init__(self)
        #self.logger.debug(f"*** Created: {func=},{obj=},{rate=}")

    def diagnostic_name(self):
        return "{}:{}".format("rate_limited",self.qn)

    def kill_timer(self):
        if self.timer:
            #self.logger.debug("deleting timer")
            try:
                self.timer.stop()
                self.timer.deleteLater()
            except RuntimeError as e:
                if 'c++ object' in str(e).lower():
                    # This can happen if the attached object which actually owns
                    # QTimer is deleted by Qt before this call path executes.
                    # This call path may be executed from a queued connection in
                    # some circumstances, hence the crazyness (I think).
                    self.logger.debug("advisory: QTimer was already deleted by Qt, ignoring...")
                else:
                    raise
            finally:
                self.timer = None

    @classmethod
    def attr_name(cls, func): return "__{}__{}".format(func.__name__, cls.__name__)

    @classmethod
    def invoke(cls, rate, ts_after, func, args, kwargs):
        ''' Calls _invoke() on an existing RateLimiter object (or creates a new
        one for the given function on first run per target object instance). '''
        assert args and isinstance(args[0], object), "@rate_limited decorator may only be used with object instance methods"
        assert threading.current_thread() is threading.main_thread(), "@rate_limited decorator may only be used with functions called in the main thread"
        obj = args[0]
        a_name = cls.attr_name(func)
        #_logger.debug(f"*** {a_name=}, {obj=}")
        rl = getattr(obj, a_name, None) # we hide the RateLimiter state object in an attribute (name based on the wrapped function name) in the target object
        if rl is None:
            # must be the first invocation, create a new RateLimiter state instance.
            rl = cls(rate, ts_after, obj, func)
            setattr(obj, a_name, rl)
        return rl._invoke(args, kwargs)

    def _invoke(self, args, kwargs):
        self._push_args(args, kwargs)  # since we're collating, save latest invocation's args unconditionally. any future invocation will use the latest saved args.
        self.ctr += 1 # increment call counter
        #self.logger.debug(f"args_saved={args}, kwarg_saved={kwargs}")
        if not self.timer: # check if there's a pending invocation already
            now = time.time()
            diff = float(self.rate) - (now - self.last_ts)
            if diff <= 0:
                # Time since last invocation was greater than self.rate, so call the function directly now.
                #self.logger.debug("calling directly")
                return self._doIt()
            else:
                # Time since last invocation was less than self.rate, so defer to the future with a timer.
                self.timer = QTimer(self.obj() if isinstance(self.obj(), QObject) else None)
                self.timer.timeout.connect(self._doIt)
                #self.timer.destroyed.connect(lambda x=None,qn=self.qn: print(qn,"Timer deallocated"))
                self.timer.setSingleShot(True)
                self.timer.start(int(diff*1e3))
                #self.logger.debug("deferring")
        else:
            # We had a timer active, which means as future call will occur. So return early and let that call happen in the future.
            # Note that a side-effect of this aborted invocation was to update self.saved_args.
            pass
            #self.logger.debug("ignoring (already scheduled)")

    def _pop_args(self):
        args, kwargs = self.saved_args # grab the latest collated invocation's args. this attribute is always defined.
        self.saved_args = (tuple(),dict()) # clear saved args immediately
        return args, kwargs

    def _push_args(self, args, kwargs):
        self.saved_args = (args, kwargs)

    def _doIt(self):
        #self.logger.debug("called!")
        t0 = time.time()
        args, kwargs = self._pop_args()
        #self.logger.debug(f"args_actually_used={args}, kwarg_actually_used={kwargs}")
        ctr0 = self.ctr # read back current call counter to compare later for reentrancy detection
        retval = self.func(*args, **kwargs) # and.. call the function. use latest invocation's args
        was_reentrant = self.ctr != ctr0 # if ctr is not the same, func() led to a call this function!
        del args, kwargs # deref args right away (allow them to get gc'd)
        tf = time.time()
        time_taken = tf-t0
        if self.ts_after:
            self.last_ts = tf
        else:
            if time_taken > float(self.rate):
                self.logger.debug(f"method took too long: {time_taken} > {self.rate}. Fudging timestamps to compensate.")
                self.last_ts = tf # Hmm. This function takes longer than its rate to complete. so mark its last run time as 'now'. This breaks the rate but at least prevents this function from starving the CPU (benforces a delay).
            else:
                self.last_ts = t0 # Function takes less than rate to complete, so mark its t0 as when we entered to keep the rate constant.

        if self.timer: # timer is not None if and only if we were a delayed (collated) invocation.
            if was_reentrant:
                # we got a reentrant call to this function as a result of calling func() above! re-schedule the timer.
                self.logger.debug("*** detected a re-entrant call, re-starting timer")
                time_left = float(self.rate) - (tf - self.last_ts)
                self.timer.start(time_left*1e3)
            else:
                # We did not get a reentrant call, so kill the timer so subsequent calls can schedule the timer and/or call func() immediately.
                self.kill_timer()
        elif was_reentrant:
            self.logger.debug("*** detected a re-entrant call")

        return retval


class RateLimiterClassLvl(RateLimiter):
    ''' This RateLimiter object is used if classlevel=True is specified to the
    @rate_limited decorator.  It inserts the __RateLimiterClassLvl state object
    on the class level and collates calls for all instances to not exceed rate.
    Each instance is guaranteed to receive at least 1 call and to have multiple
    calls updated with the latest args for the final call. So for instance:
    a.foo(1)
    a.foo(2)
    b.foo(10)
    b.foo(3)
    Would collate to a single 'class-level' call using 'rate':
    a.foo(2) # latest arg taken, collapsed to 1 call
    b.foo(3) # latest arg taken, collapsed to 1 call
    '''

    @classmethod
    def invoke(cls, rate, ts_after, func, args, kwargs):
        assert args and not isinstance(args[0], type), "@rate_limited decorator may not be used with static or class methods"
        obj = args[0]
        objcls = obj.__class__
        args = list(args)
        args.insert(0, objcls) # prepend obj class to trick super.invoke() into making this state object be class-level.
        return super(RateLimiterClassLvl, cls).invoke(rate, ts_after, func, args, kwargs)

    def _push_args(self, args, kwargs):
        objcls, obj = args[0:2]
        args = args[2:]
        self.saved_args[obj] = (args, kwargs)

    def _pop_args(self):
        weak_dict = self.saved_args
        self.saved_args = weakref.WeakKeyDictionary()
        return (weak_dict,),dict()

    def _call_func_for_all(self, weak_dict):
        for ref in weak_dict.keyrefs():
            obj = ref()
            if obj:
                args,kwargs = weak_dict[obj]
                obj_name = obj.diagnostic_name() if hasattr(obj, "diagnostic_name") else obj
                #self.logger.debug(f"calling for {obj_name}, timer={bool(self.timer)}")
                self.func_target(obj, *args, **kwargs)

    def __init__(self, rate, ts_after, obj, func):
        # note: obj here is really the __class__ of the obj because we prepended the class in our custom invoke() above.
        super().__init__(rate, ts_after, obj, func)
        self.func_target = func
        self.func = self._call_func_for_all
        self.saved_args = weakref.WeakKeyDictionary() # we don't use a simple arg tuple, but instead an instance -> args,kwargs dictionary to store collated calls, per instance collated


def rate_limited(rate, *, classlevel=False, ts_after=False):
    """ A Function decorator for rate-limiting GUI event callbacks. Argument
        rate in seconds is the minimum allowed time between subsequent calls of
        this instance of the function. Calls that arrive more frequently than
        rate seconds will be collated into a single call that is deferred onto
        a QTimer. It is preferable to use this decorator on QObject subclass
        instance methods. This decorator is particularly useful in limiting
        frequent calls to GUI update functions.
        params:
            rate - calls are collated to not exceed rate (in seconds)
            classlevel - if True, specify that the calls should be collated at
                1 per `rate` secs. for *all* instances of a class, otherwise
                calls will be collated on a per-instance basis.
            ts_after - if True, mark the timestamp of the 'last call' AFTER the
                target method completes.  That is, the collation of calls will
                ensure at least `rate` seconds will always elapse between
                subsequent calls. If False, the timestamp is taken right before
                the collated calls execute (thus ensuring a fixed period for
                collated calls).
                TL;DR: ts_after=True : `rate` defines the time interval you want
                                        from last call's exit to entry into next
                                        call.
                       ts_adter=False: `rate` defines the time between each
                                        call's entry.
        (See on_fx_quotes & on_fx_history in main_window.py for example usages
        of this decorator). """
    def wrapper0(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if classlevel:
                return RateLimiterClassLvl.invoke(rate, ts_after, func, args, kwargs)
            return RateLimiter.invoke(rate, ts_after, func, args, kwargs)
        return wrapper
    return wrapper0

