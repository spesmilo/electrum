# The code below is mostly my own but based on the interfaces of the
# curio library by David Beazley.  I'm considering switching to using
# curio.  In the mean-time this is an attempt to provide a similar
# clean, pure-async interface and move away from direct
# framework-specific dependencies.  As asyncio differs in its design
# it is not possible to provide identical semantics.
#
# The curio library is distributed under the following licence:
#
# Copyright (C) 2015-2017
# David Beazley (Dabeaz LLC)
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
# * Redistributions of source code must retain the above copyright notice,
#   this list of conditions and the following disclaimer.
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
# * Neither the name of the David Beazley or Dabeaz LLC may be used to
#   endorse or promote products derived from this software without
#   specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

from asyncio import (
    CancelledError, get_event_loop, Queue, Event, Lock, Semaphore, sleep, current_task
)
from collections import deque

from aiorpcx.util import instantiate_coroutine


__all__ = (
    'Queue', 'Event', 'Lock', 'Semaphore', 'sleep', 'CancelledError',
    'run_in_thread', 'spawn', 'spawn_sync', 'TaskGroup', 'NoRemainingTasksError',
    'TaskTimeout', 'TimeoutCancellationError', 'UncaughtTimeoutError',
    'timeout_after', 'timeout_at', 'ignore_after', 'ignore_at',
)


async def run_in_thread(func, *args):
    '''Run a function in a separate thread, and await its completion.'''
    return await get_event_loop().run_in_executor(None, func, *args)


async def spawn(coro, *args, loop=None, daemon=False):
    return spawn_sync(coro, *args, loop=loop, daemon=daemon)


def spawn_sync(coro, *args, loop=None, daemon=False):
    coro = instantiate_coroutine(coro, args)
    loop = loop or get_event_loop()
    task = loop.create_task(coro)
    task._daemon = daemon
    return task


def safe_exception(task):
    try:
        return task.exception()
    except CancelledError as e:
        return e


class NoRemainingTasksError(RuntimeError):
    pass


class TaskGroup:
    '''A class representing a group of executing tasks. tasks is an optional set of existing
    tasks to put into the group. New tasks can later be added using the spawn() method
    below.

    wait specifies the policy used for waiting for tasks by the join() method.  If wait is
    all then wait for all tasks to complete.  If wait is any then wait for any task to
    complete and then cancel tasks that are still running.  If wait is object then wait
    for the first task to return a non-None result and cancel tasks that are still
    runnning.  None means wait for no tasks and cancel all still running.

    Completed tasks are normally dropped, but if retain is True, then a reference is kept
    so that the `results` and `exceptions` properties can be examined.  To avoid runaway
    memory use, this should only be done for groups with a limited number of tasks.

    When join() is called, if any of the tasks in the group raises an exception or is
    cancelled then all tasks in the group, including daemon tasks, are cancelled.  If the
    join() operation itself is cancelled then all running tasks in the group are also
    cancelled.  Once join() returns all tasks have completed and new tasks may not be
    added.  Tasks can be added while join() is waiting.

    A TaskGroup is often used as a context manager, which calls the join() method on
    context-exit.  Each TaskGroup is an independent entity. Task groups do not form a
    hierarchy or any kind of relationship to other previously created task groups or
    tasks. Moreover, Tasks created by the top level spawn() function are not placed into
    any task group. To create a task in a group, it should be created using
    TaskGroup.spawn() or explicitly added using TaskGroup.add_task().

    A task group has the following public attributes:

    completed: initially None, and set by join() to the first task in the group that
    finished.  Tasks removed from the group by calls to next_done() (and if wait is object
    tasks returning None) do not count.
    joined: true if the task group join() operation has completed

    daemons: a set of all running daemonic tasks in the group.
    tasks: a set of all non-daemonic tasks in the group.
    '''

    def __init__(self, tasks=(), *, wait=all, retain=False):
        if wait not in (any, all, object, None):
            raise ValueError('invalid wait argument')
        # Tasks that have not yet finished
        self._pending = set()
        # All non-daemonic tasks tracked by the group
        self.tasks = set()
        # All running deamonic tasks in the group
        self.daemons = set()
        # Non-daemonic tasks that have completed
        self._done = deque()
        self._wait = wait
        self._retain = retain
        self.joined = False
        self._semaphore = Semaphore(0)
        self.completed = None
        for task in tasks:
            self._add_task(task)

    def _on_done(self, task):
        task._task_group = None
        if getattr(task, '_daemon', False):
            self.daemons.discard(task)
        else:
            if not self._retain:
                self.tasks.remove(task)
            self._pending.discard(task)
            self._done.append(task)
            self._semaphore.release()

    def _add_task(self, task):
        '''Add an already existing task to the task group.'''
        if hasattr(task, '_task_group'):
            raise RuntimeError('task is already part of a group')
        if self.joined:
            raise RuntimeError('task group terminated')
        task._task_group = self
        daemon = getattr(task, '_daemon', False)
        if not daemon:
            self.tasks.add(task)
        if task.done():
            self._on_done(task)
        elif daemon:
            self.daemons.add(task)
        else:
            self._pending.add(task)
            task.add_done_callback(self._on_done)

    @property
    def result(self):
        ''' The result of the first completed task.  Should only be called after join()
        has returned.'''
        if not self.joined:
            raise RuntimeError('task group not yet terminated')
        if not self.completed:
            raise RuntimeError('no task successfully completed')
        return self.completed.result()

    @property
    def exception(self):
        ''' The exception of the first completed task.  Should only be called after join()
        has returned.'''
        if not self.joined:
            raise RuntimeError('task group not yet terminated')
        return safe_exception(self.completed) if self.completed else None

    @property
    def results(self):
        '''A list of all results collected by join() in no particular order.

        If a task raised an exception or was cancelled then that exception will be raised.
        '''
        if not self.joined:
            raise RuntimeError('task group not yet terminated')
        return [task.result() for task in self.tasks]

    @property
    def exceptions(self):
        '''A list of all exceptions collected by join() in no particular order.'''
        if not self.joined:
            raise RuntimeError('task group not yet terminated')
        return [safe_exception(task) for task in self.tasks]

    async def spawn(self, coro, *args, daemon=False):
        '''Create a new task and put it in the group. Returns a Task instance.

        Daemonic tasks are both ignored and cancelled by join().
        '''
        task = await spawn(coro, *args, daemon=daemon)
        self._add_task(task)
        return task

    async def add_task(self, task):
        '''Add an already existing task to the task group.'''
        self._add_task(task)

    async def next_done(self):
        '''Return the next completed task and remove it from the group.  Return None if no more
        tasks remain. A TaskGroup may also be used as an asynchronous iterator.
        '''
        if self._done or self._pending:
            await self._semaphore.acquire()
        if self._done:
            return self._done.popleft()
        return None

    async def next_result(self):
        '''Return the result of the next completed task and remove it from the group. If the task
        failed with an exception, that exception is raised. A RuntimeError exception is
        raised if no tasks remain.
        '''
        task = await self.next_done()
        if not task:
            raise NoRemainingTasksError('no tasks remain')
        return task.result()

    async def join(self):
        '''Wait for tasks in the group to terminate according to the wait policy for the group.
        '''
        try:
            # Wait for no-one; all tasks are cancelled
            if self._wait is None:
                return

            while True:
                task = await self.next_done()
                if task is None:
                    return

                # Set self.completed if not yet set; unless wait is object and
                if self.completed is None:
                    if not (self._wait is object and not safe_exception(task)
                            and task.result() is None):
                        self.completed = task

                if (safe_exception(task) or self._wait is any or (self._wait is object
                                                                  and self.completed)):
                    return
        finally:
            # Cancel everything including daemons
            await self._cancel_tasks(self._pending.union(self.daemons))
            self.joined = True

    async def _cancel_tasks(self, tasks):
        '''Cancel the passed set of tasks.  Wait for them to complete.'''
        for task in tasks:
            task.cancel()

        if tasks:
            def pop_task(task):
                unfinished.remove(task)
                if not unfinished:
                    all_done.set()

            unfinished = set(tasks)
            all_done = Event()
            for task in tasks:
                task.add_done_callback(pop_task)
            await all_done.wait()

    async def cancel_remaining(self):
        '''Cancel all remaining non-daemonic tasks and wait for them to complete.

        If any task blocks cancellation this routine will not return.
        '''
        await self._cancel_tasks(self._pending)

    def __aiter__(self):
        return self

    async def __anext__(self):
        task = await self.next_done()
        if task:
            return task
        raise StopAsyncIteration

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        if exc_type:
            await self.cancel_remaining()
        await self.join()


class TaskTimeout(Exception):

    def __init__(self, secs, *args):
        super().__init__(*args)
        self.secs = secs

    def __str__(self):
        return f'task timed out after {self.secs}s'


class TimeoutCancellationError(CancelledError):
    pass


class UncaughtTimeoutError(Exception):
    pass


def _set_new_deadline(task, deadline):
    def timeout_task():
        # Unfortunately task.cancel is all we can do with asyncio
        task.cancel()
        task._timed_out = deadline
    task._deadline_handle = task._loop.call_at(deadline, timeout_task)


def _set_task_deadline(task, deadline):
    deadlines = getattr(task, '_deadlines', [])
    if deadlines:
        if deadline < min(deadlines):
            task._deadline_handle.cancel()
            _set_new_deadline(task, deadline)
    else:
        _set_new_deadline(task, deadline)
    deadlines.append(deadline)
    task._deadlines = deadlines
    task._timed_out = None


def _unset_task_deadline(task):
    deadlines = task._deadlines
    timed_out_deadline = task._timed_out
    uncaught = timed_out_deadline not in deadlines
    task._deadline_handle.cancel()
    deadlines.pop()
    if deadlines:
        _set_new_deadline(task, min(deadlines))
    return timed_out_deadline, uncaught


class TimeoutAfter:

    def __init__(self, deadline, *, ignore=False, absolute=False):
        self._deadline = deadline
        self._ignore = ignore
        self._absolute = absolute
        self._secs = None
        self._task = None
        self.expired = False

    async def __aenter__(self):
        task = current_task()
        loop_time = task._loop.time()
        if self._absolute:
            self._secs = self._deadline - loop_time
        else:
            self._secs = self._deadline
            self._deadline += loop_time
        _set_task_deadline(task, self._deadline)
        self.expired = False
        self._task = task
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        timed_out_deadline, uncaught = _unset_task_deadline(self._task)
        if exc_type not in (CancelledError, TaskTimeout,
                            TimeoutCancellationError):
            return False
        if timed_out_deadline == self._deadline:
            self.expired = True
            if self._ignore:
                return True
            raise TaskTimeout(self._secs) from None
        if timed_out_deadline is None:
            return False
        if uncaught:
            raise UncaughtTimeoutError('uncaught timeout received')
        if exc_type is TimeoutCancellationError:
            return False
        raise TimeoutCancellationError(timed_out_deadline) from None


async def _timeout_after_func(seconds, absolute, coro, args):
    coro = instantiate_coroutine(coro, args)
    async with TimeoutAfter(seconds, absolute=absolute):
        return await coro


def timeout_after(seconds, coro=None, *args):
    '''Execute the specified coroutine and return its result. However,
    issue a cancellation request to the calling task after seconds
    have elapsed.  When this happens, a TaskTimeout exception is
    raised.  If coro is None, the result of this function serves
    as an asynchronous context manager that applies a timeout to a
    block of statements.

    timeout_after() may be composed with other timeout_after()
    operations (i.e., nested timeouts).  If an outer timeout expires
    first, then TimeoutCancellationError is raised instead of
    TaskTimeout.  If an inner timeout expires and fails to properly
    TaskTimeout, a UncaughtTimeoutError is raised in the outer
    timeout.

    '''
    if coro:
        return _timeout_after_func(seconds, False, coro, args)

    return TimeoutAfter(seconds)


def timeout_at(clock, coro=None, *args):
    '''Execute the specified coroutine and return its result. However,
    issue a cancellation request to the calling task after seconds
    have elapsed.  When this happens, a TaskTimeout exception is
    raised.  If coro is None, the result of this function serves
    as an asynchronous context manager that applies a timeout to a
    block of statements.

    timeout_after() may be composed with other timeout_after()
    operations (i.e., nested timeouts).  If an outer timeout expires
    first, then TimeoutCancellationError is raised instead of
    TaskTimeout.  If an inner timeout expires and fails to properly
    TaskTimeout, a UncaughtTimeoutError is raised in the outer
    timeout.

    '''
    if coro:
        return _timeout_after_func(clock, True, coro, args)

    return TimeoutAfter(clock, absolute=True)


async def _ignore_after_func(seconds, absolute, coro, args, timeout_result):
    coro = instantiate_coroutine(coro, args)
    async with TimeoutAfter(seconds, absolute=absolute, ignore=True):
        return await coro

    return timeout_result


def ignore_after(seconds, coro=None, *args, timeout_result=None):
    '''Execute the specified coroutine and return its result. Issue a
    cancellation request after seconds have elapsed. When a timeout
    occurs, no exception is raised. Instead, timeout_result is
    returned.

    If coro is None, the result is an asynchronous context manager
    that applies a timeout to a block of statements. For the context
    manager case, the resulting context manager object has an expired
    attribute set to True if time expired.

    Note: ignore_after() may also be composed with other timeout
    operations. TimeoutCancellationError and UncaughtTimeoutError
    exceptions might be raised according to the same rules as for
    timeout_after().
    '''
    if coro:
        return _ignore_after_func(seconds, False, coro, args, timeout_result)

    return TimeoutAfter(seconds, ignore=True)


def ignore_at(clock, coro=None, *args, timeout_result=None):
    '''
    Stop the enclosed task or block of code at an absolute
    clock value. Same usage as ignore_after().
    '''
    if coro:
        return _ignore_after_func(clock, True, coro, args, timeout_result)

    return TimeoutAfter(clock, absolute=True, ignore=True)
