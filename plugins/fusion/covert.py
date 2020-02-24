#!/usr/bin/env python3
#
# Electron Cash - a lightweight Bitcoin Cash client
# CashFusion - an advanced coin anonymizer
#
# Copyright (C) 2020 Mark B. Lundeberg
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
"""
Covert submission mechanism

- Open numerous connections at random times.
- Send data (component) at random times on random connections.
- Send more data (signature) at a later random time, but on the same connection.
- Close the connections at random times.
- Keep some spare connections in case of problems.

Each connection gets its own thread.
"""

import math
import random
import secrets
import socket
import socks
import threading
import time
from collections import deque

from electroncash.util import PrintError
from .comms import send_pb, recv_pb, pb, FusionError
from .connection import open_connection

# how long to remember attempting Tor connections
TOR_COOLDOWN_TIME = 660  # seconds

# how long a covert connection is allowed to stay alive without anything happening (as a sanity check measure)
TIMEOUT_INACTIVE_CONNECTION = 120

# Used internally
class Unrecoverable(FusionError):
    pass

def is_tor_port(host, port):
    if not 0 <= port < 65536:
        return False
    try:
        socketclass = socket.socket
        try:
            # socket.socket could be monkeypatched (see lib/network.py),
            # in which case we need to get the real one.
            socketclass = socket._socketobject
        except AttributeError:
            pass
        s = socketclass(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.1)
        s.connect((host, port))
        # Tor responds uniquely to HTTP-like requests
        s.send(b"GET\n")
        if b"Tor is not an HTTP Proxy" in s.recv(1024):
            return True
    except socket.error:
        pass
    return False

class TorLimiter:
    # Holds a log of the times of connections during the last `lifetime`
    # seconds. At any time you can query `.count` to see how many.
    def __init__(self, lifetime):
        self.deque = deque()
        self.lifetime = lifetime
        self.lock = threading.Lock()
        self._count = 0

    def cleanup(self,):
        with self.lock:
            tnow = time.monotonic()
            while True:
                try:
                    item = self.deque[0]
                except IndexError:
                    return
                if item > tnow:
                    return
                self.deque.popleft()
                self._count -= 1

    @property
    def count(self,):
        self.cleanup()
        return self._count

    def bump(self,):
        t = time.monotonic() + self.lifetime
        with self.lock:
            self.deque.append(t)
            self._count += 1

limiter = TorLimiter(TOR_COOLDOWN_TIME)

def rand_trap(rng):
    """ Random number between 0 and 1 according to trapezoid distribution.
    a = 0
    b = 1/4
    c = 3/4
    d = 1
    Peak density is 1.333.
    """
    sixth = 1./6
    f = rng.random()
    fc = 1. - f
    if f < sixth:
        return math.sqrt(0.375 * f)
    elif fc < sixth:
        return 1. - math.sqrt(0.375 * fc)
    else:
        return 0.75*f + 0.125

class CovertConnection:
    connection = None
    slotnum = None
    t_ping = None
    conn_number = None
    def __init__(self):
        self.wakeup = threading.Event()
    def wait_wakeup_or_time(self, t):
        remtime = max(0., t - time.monotonic())
        was_set = self.wakeup.wait(remtime)
        self.wakeup.clear()
        return was_set
    def ping(self):
        send_pb(self.connection, pb.CovertMessage, pb.Ping(), 1)
        self.t_ping = None
    def inactive(self):
        raise Unrecoverable("timed out from inactivity (this is a bug!)")

class CovertSlot:
    def __init__(self, submit_timeout):
        self.submit_timeout = submit_timeout
        self.t_submit = None # The requested start time of work.
        self.submsg = None # The work to be done.
        self.done = True # Whether last work requested is done.
        self.covconn = None # which CovertConnection is assigned to work on this slot
    def submit(self):
        connection = self.covconn.connection
        send_pb(connection, pb.CovertMessage, self.submsg, timeout=self.submit_timeout)
        resmsg, mtype = recv_pb(connection, pb.CovertResponse, 'ok', 'error', timeout=self.submit_timeout)
        if mtype == 'error':
            raise Unrecoverable('error from server: ' + repr(resmsg.message))
        self.done = True
        self.t_submit = None
        self.covconn.t_ping = None # if a submission is done, no ping is needed.

class CovertSubmitter(PrintError):
    stopping = False

    def __init__(self, dest_addr, dest_port, ssl, tor_host, tor_port, num_slots, randspan, submit_timeout):
        self.dest_addr = dest_addr
        self.dest_port = dest_port
        self.ssl = ssl

        if tor_host is None or tor_port is None:
            self.proxy_opts = None
        else:
            self.proxy_opts = dict(proxy_type = socks.SOCKS5, proxy_addr=tor_host, proxy_port = tor_port, proxy_rdns = True)

        # The timespan (in s) used for randomizing action times on established
        # connections. Each connection chooses a delay between 0 and randspan,
        # and every action (submitting data, pinging, or closing) on that
        # connection gets performed with the same delay relative to the scheduled
        # timeframe. The connection establishment itself happens with an
        # unrelated random time.
        self.randspan = randspan
        # We don't let submissions take too long, in order to make sure a spare can still be tried.
        self.submit_timeout = submit_timeout

        # If .stop() is called, it will use this timeframe (settable with .set_stop_time)
        # to randomize the disconnection times. Note that .stop() may be internally
        # invoked at any time in case of a failure where there are no more spare
        # connections left.
        self.stop_tstart = time.monotonic() - randspan

        # Our internal logic is as follows:
        #  - Each connection is its own thread, which starts with opening the socket and ends once the socket is dead.
        #  - Pending connections are also connections.
        #  - There are N slots and M connections, N <= M in normal operation. Each slot has a connection, but some connections are spare.
        #  - Sending of data happens on a "slot". That way, related data (with same slot number) gets sent on the same connection whenever possible.
        #  - Each connection has its own random offset parameter, which it uses to offset its actions during each covert phase.
        #    In other words, each channel leaks minimal information about the actual timeframe it belongs to, even after many actions.
        #  - When a connection dies / times out and it was assigned to a slot, it immediately reassigns the slot to another connection.
        #    If reassignment is not possible, then the entire covert submission mechanism stops itself.

        self.slots  = [CovertSlot(self.submit_timeout) for _ in range(num_slots)]

        self.spare_connections = []

        # This will be set to the exception that caused a stoppage:
        # - the first connection error where a spare was not available
        # - the first unrecoverable error from server
        self.failure_exception = None

        self.randtag = secrets.token_urlsafe(12) # for proxy login
        self.rng = random.Random(secrets.token_bytes(32)) # for timings

        self.count_attempted = 0 # how many connections have been attempted (or are being attempted)
        self.count_established = 0 # how many connections were made successfully
        self.count_failed = 0 # how many connections could not be made

        self.lock = threading.RLock()

    def wake_all(self,):
        with self.lock:
            for s in self.slots:
                if s.covconn:
                    s.covconn.wakeup.set()
            for c in self.spare_connections:
                c.wakeup.set()

    def set_stop_time(self, tstart):
        self.stop_tstart = tstart
        if self.stopping:
            self.wake_all()

    def stop(self, _exception=None):
        """ Schedule any established connections to close at random times, and
        stop any pending connections and pending work.
        """
        with self.lock:
            if self.stopping:
                # already requested!
                return
            self.failure_exception = _exception
            self.stopping = True
            self.print_error(f"stopping; connections will close in ~{self.stop_tstart - time.monotonic():.3f}s")
            self.wake_all()

    def schedule_connections(self, tstart, tspan, num_spares = 0, connect_timeout = 10):
        """ Schedule connections to start. For any slots without a connection,
        they will have one allocated. Additionally, new spare connections will
        be started until the number of remaining spares is >= num_spares.

        This gets called after instance creation, but can be called again
        later on, if new spares are needed.
        """
        with self.lock:
            newconns = []
            for snum, s in enumerate(self.slots):
                if s.covconn is None:
                    s.covconn = CovertConnection()
                    s.covconn.slotnum = snum
                    newconns.append(s.covconn)

            num_new_spares = max(0, num_spares - len(self.spare_connections))
            new_spares = [CovertConnection() for _ in range(num_new_spares)]
            self.spare_connections = new_spares + self.spare_connections

            newconns.extend(new_spares)
            for covconn in newconns:
                covconn.conn_number = self.count_attempted
                self.count_attempted += 1
                conn_time = tstart + tspan * rand_trap(self.rng)
                rand_delay = self.randspan * rand_trap(self.rng)
                thread = threading.Thread(name=f'CovertSubmitter-{covconn.conn_number}',
                                          target=self.run_connection,
                                          args=(covconn, conn_time, rand_delay, connect_timeout,),
                                          )
                thread.daemon = True
                thread.start()
                # GC note - no reference is kept to the thread. When it dies,
                # the target bound method dies. If all threads die and the
                # CovertSubmitter has no external references, then refcounts
                # should all drop to 0.

    def schedule_submit(self, slot_num, tstart, submsg):
        """ Schedule a submission on a specific slot. """
        slot = self.slots[slot_num]
        assert slot.done, "tried to set new work when prior work not done"
        slot.submsg = submsg
        slot.done = False
        slot.t_submit = tstart
        covconn = slot.covconn
        if covconn is not None:
            covconn.wakeup.set()

    def schedule_submissions(self, tstart, slot_messages):
        """ Schedule submissions on all slots. For connections without a message,
        optionally send them a ping."""
        slot_messages = tuple(slot_messages)
        assert len(slot_messages) == len(self.slots)

        # note we don't take a lock; because of this we step carefully by
        # first touching spares, then slots.

        # first we tell the spare connections that they will need to make a ping.
        for c in tuple(self.spare_connections): # copy in case of mutation mid-iteration
            c.t_ping = tstart
            c.wakeup.set()

        # then we tell the slots that there is a message to submit.
        for slot, submsg in zip(self.slots, slot_messages):
            covconn = slot.covconn
            if submsg is None:
                covconn.t_ping = tstart
            else:
                slot.submsg = submsg
                slot.done = False
                slot.t_submit = tstart
            covconn.wakeup.set()

    def run_connection(self, covconn, conn_time, rand_delay, connect_timeout):
        # Main loop for connection thread

        while covconn.wait_wakeup_or_time(conn_time):
            # if we are woken up before connection and stopping is happening, then just don't make a connection at all
            if self.stopping:
                return
        tbegin = time.monotonic()
        try:
            # STATE 1 - connecting
            if self.proxy_opts is None:
                proxy_opts = None
            else:
                unique = f'CF{self.randtag}_{covconn.conn_number}'
                proxy_opts = dict(proxy_username = unique, proxy_password = unique)
                proxy_opts.update(self.proxy_opts)
            limiter.bump()
            try:
                connection = open_connection(self.dest_addr, self.dest_port, conn_timeout=connect_timeout, ssl=self.ssl, socks_opts = proxy_opts)
                covconn.connection = connection
            except Exception as e:
                with self.lock:
                    self.count_failed += 1
                tend = time.monotonic()
                self.print_error(f"could not establish connection (after {(tend-tbegin):.3f}s): {e}")
                raise
            with self.lock:
                self.count_established += 1
            tend = time.monotonic()
            self.print_error(f"[{covconn.conn_number}] connection established after {(tend-tbegin):.3f}s")

            covconn.delay = rand_trap(self.rng) * self.randspan
            last_action_time = time.monotonic()

            # STATE 2 - working
            while not self.stopping:
                # (First preference: stop)
                nexttime = None
                slotnum = covconn.slotnum
                # Second preference: submit something
                if slotnum is not None:
                    slot = self.slots[slotnum]
                    nexttime = slot.t_submit
                    action = slot.submit
                # Third preference: send a ping
                if nexttime is None and covconn.t_ping is not None:
                    nexttime = covconn.t_ping
                    action = covconn.ping
                # Last preference: wait doing nothing
                if nexttime is None:
                    nexttime = last_action_time + TIMEOUT_INACTIVE_CONNECTION
                    action = covconn.inactive

                nexttime += rand_delay

                if covconn.wait_wakeup_or_time(nexttime):
                    # got woken up ... let's go back and reevaluate what to do
                    continue

                # reached action time, time to do it
                label = f"[{covconn.conn_number}-{slotnum}-{action.__name__}]"
                try:
                    action()
                except Unrecoverable as e:
                    self.print_error(f"{label} unrecoverable {e}")
                    self.stop(_exception=e)
                    raise
                except Exception as e:
                    self.print_error(f"{label} error {e}")
                    raise
                else:
                    self.print_error(f"{label} done")
                last_action_time = time.monotonic()

            # STATE 3 - stopping
            while True:
                stoptime = self.stop_tstart + rand_delay
                if not covconn.wait_wakeup_or_time(stoptime):
                    break
            self.print_error(f"[{covconn.conn_number}] closing from stop")
        except Exception as e:
            # in case of any problem, record the exception and if we have a slot, reassign it.
            exception = e
            with self.lock:
                slotnum = covconn.slotnum
                if slotnum is not None:
                    try:
                        spare = self.spare_connections.pop()
                    except IndexError:
                        # We failed, and there are no spares. Party is over!
                        self.stop(_exception = exception)
                    else:
                        # Found a spare.
                        self.slots[slotnum].covconn = spare
                        spare.slotnum = slotnum
                        spare.wakeup.set()
                        covconn.slotnum = None
        finally:
            if covconn.connection:
                covconn.connection.close()

    def check_ok(self):
        """ Make sure that an error hasn't occurred yet. """
        e = self.failure_exception
        if e is not None:
            raise FusionError('Covert connections failed: {} {}'.format(type(e).__name__, e)) from e

    def check_connected(self):
        """ Make sure that condition is good, and all slots have an active connection. """
        self.check_ok()
        num_missing = sum(1 for s in self.slots if s.covconn.connection is None)
        if num_missing > 0:
            raise FusionError(f"Covert connections were too slow ({num_missing} incomplete out of {len(self.slots)}).")

    def check_done(self):
        """ Make sure that condition is good, and all slots have completed the work. """
        self.check_ok()
        num_missing = sum(1 for s in self.slots if not s.done)
        if num_missing > 0:
            raise FusionError(f"Covert submissions were too slow ({num_missing} incomplete out of {len(self.slots)}).")
