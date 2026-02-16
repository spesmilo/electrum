# Copyright (c) 2018-2019, Neil Booth
#
# All rights reserved.
#
# The MIT License (MIT)
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.


__all__ = ('RPCSession', 'MessageSession', 'ExcessiveSessionCostError',
           'BatchError', 'Concurrency', 'ReplyAndDisconnect', 'SessionKind')


import asyncio
from enum import Enum
import logging
from math import ceil
import time

from aiorpcx.curio import (
    TaskGroup, TaskTimeout, timeout_after, sleep
)
from aiorpcx.framing import (
    NewlineFramer, BitcoinFramer, BadMagicError, BadChecksumError, OversizedPayloadError
)
from aiorpcx.jsonrpc import (
    Request, Batch, Notification, ProtocolError, RPCError,
    JSONRPC, JSONRPCv2, JSONRPCConnection
)


class ReplyAndDisconnect(Exception):
    '''Force a session disconnect after sending result (a Python object or an RPCError).
    '''


class ExcessiveSessionCostError(RuntimeError):
    pass


class Concurrency:

    def __init__(self, target):
        self._target = int(target)
        self._semaphore = asyncio.Semaphore(self._target)
        self._sem_value = self._target

    async def _retarget_semaphore(self):
        if self._target <= 0:
            raise ExcessiveSessionCostError
        while self._sem_value < self._target:
            self._sem_value += 1
            self._semaphore.release()

    @property
    def max_concurrent(self):
        return self._target

    def set_target(self, target):
        self._target = int(target)

    async def __aenter__(self):
        await self._semaphore.acquire()
        await self._retarget_semaphore()

    async def __aexit__(self, exc_type, exc_value, traceback):
        if self._sem_value > self._target:
            self._sem_value -= 1
        else:
            self._semaphore.release()


class SessionKind(Enum):
    CLIENT = 'client'
    SERVER = 'server'


class SessionBase:
    '''Base class of networking sessions.

    There is no client / server distinction other than who initiated
    the connection.
    '''

    # Multiply this by bandwidth bytes used to get resource usage cost
    bw_cost_per_byte = 1 / 100000
    # If cost is over this requests begin to get delayed and concurrency is reduced
    cost_soft_limit = 2000
    # If cost is over this the session is closed
    cost_hard_limit = 10000
    # Resource usage is reduced by this every second
    cost_decay_per_sec = cost_hard_limit / 3600
    # Request delay ranges from 0 to this between cost_soft_limit and cost_hard_limit
    cost_sleep = 2.0
    # Base cost of an error.  Errors that took resources to discover incur additional costs
    error_base_cost = 100.0
    # Initial number of requests that can be concurrently processed
    initial_concurrent = 20
    # Send a "server busy" error if processing a request takes longer than this seconds
    processing_timeout = 30.0
    # Force-close a connection if its socket send buffer stays full this long
    max_send_delay = 20.0

    def __init__(self, transport, *, loop=None):
        self.transport = transport
        self.loop = loop or asyncio.get_event_loop()
        self.logger = logging.getLogger(self.__class__.__name__)
        # For logger.debug messsages
        self.verbosity = 0
        self._group = TaskGroup()
        # Statistics.  The RPC object also keeps its own statistics.
        self.start_time = time.time()
        self.errors = 0
        self.send_count = 0
        self.send_size = 0
        self.last_send = self.start_time
        self.recv_count = 0
        self.recv_size = 0
        self.last_recv = self.start_time
        # Resource usage
        self.cost = 0.0
        self._cost_last = 0.0
        self._cost_time = self.start_time
        self._cost_fraction = 0.0
        # Concurrency control for incoming request handling
        self._incoming_concurrency = Concurrency(self.initial_concurrent)
        # By default, do not limit outgoing connections
        if self.session_kind == SessionKind.CLIENT:
            self.cost_hard_limit = 0

    async def _send_message(self, message):
        if self.verbosity >= 4:
            self.logger.debug(f'sending message {message}')
        try:
            async with timeout_after(self.max_send_delay):
                await self.transport.write(message)
        except TaskTimeout:
            await self.abort()
            raise
        self.send_size += len(message)
        self.bump_cost(len(message) * self.bw_cost_per_byte)
        self.send_count += 1
        self.last_send = time.time()
        return self.last_send

    def _bump_errors(self, exception=None):
        self.errors += 1
        self.bump_cost(self.error_base_cost + getattr(exception, 'cost', 0.0))

    @property
    def session_kind(self):
        '''Either client or server.'''
        return self.transport.kind

    async def connection_lost(self):
        pass

    def data_received(self, data):
        if self.verbosity >= 2:
            self.logger.debug(f'received data {data}')
        self.recv_size += len(data)
        self.bump_cost(len(data) * self.bw_cost_per_byte)

    def bump_cost(self, delta):
        # Delta can be positive or negative
        self.cost = max(0, self.cost + delta)
        if abs(self.cost - self._cost_last) > 100:
            self.recalc_concurrency()

    def on_disconnect_due_to_excessive_session_cost(self):
        '''Called just before disconnecting from the session, if it was consuming too
        much resources.
        '''

    def recalc_concurrency(self):
        '''Call to recalculate sleeps and concurrency for the session.  Called automatically if
        cost has drifted significantly.  Otherwise can be called at regular intervals if
        desired.
        '''
        # Refund resource usage proportionally to elapsed time; the bump passed is negative
        now = time.time()
        self.cost = max(0, self.cost - (now - self._cost_time) * self.cost_decay_per_sec)
        self._cost_time = now
        self._cost_last = self.cost

        # Setting cost_hard_limit <= 0 means to not limit concurrency
        value = self._incoming_concurrency.max_concurrent
        cost_soft_range = self.cost_hard_limit - self.cost_soft_limit
        if cost_soft_range <= 0:
            return

        cost = self.cost + self.extra_cost()
        self._cost_fraction = max(0.0, (cost - self.cost_soft_limit) / cost_soft_range)

        target = max(0, ceil((1.0 - self._cost_fraction) * self.initial_concurrent))
        if abs(target - value) > 1:
            self.logger.info(f'changing task concurrency from {value} to {target}')
        self._incoming_concurrency.set_target(target)

    async def _process_messages(self, recv_message):
        try:
            await self._process_messages_loop(recv_message)
        finally:
            # Call the hook provided for derived classes
            await self.connection_lost()

    async def process_messages(self, recv_message):
        async with self._group as group:
            await group.spawn(self._process_messages, recv_message)

            # Remove tasks
            async for task in group:
                task.result()

    def unanswered_request_count(self):
        '''The number of requests received but not yet answered.'''
        # Max with zero in case the message processing task hasn't yet spawned
        return max(0, len(self._group._pending) - 1)

    def extra_cost(self):
        '''A dynamic value added to this session's cost when deciding how much to throttle
        requests.  Can be negative.
        '''
        return 0.0

    def default_framer(self):
        '''Return a default framer.'''
        raise NotImplementedError

    def proxy(self):
        '''Returns the proxy used, or None.'''
        return self.transport.proxy()

    def remote_address(self):
        '''Returns a NetAddress or None if not connected.'''
        return self.transport.remote_address()

    def is_closing(self):
        '''Return True if the connection is closing.'''
        return self.transport.is_closing()

    async def abort(self):
        '''Forcefully close the connection.'''
        await self.transport.abort()

    async def close(self, *, force_after=30):
        '''Close the connection and return when closed.'''
        await self.transport.close(force_after)


class MessageSession(SessionBase):
    '''Session class for protocols where messages are not tied to responses,
    such as the Bitcoin protocol.
    '''
    async def _process_messages_loop(self, recv_message):
        while True:
            try:
                message = await recv_message()
            except BadMagicError as e:
                magic, expected = e.args
                self.logger.error(
                    f'bad network magic: got {magic} expected {expected}, '
                    f'disconnecting'
                )
                self._bump_errors(e)
                await self._group.spawn(self.close)
                await sleep(0.001)
            except OversizedPayloadError as e:
                command, payload_len = e.args
                self.logger.error(
                    f'oversized payload of {payload_len:,d} bytes to command '
                    f'{command}, disconnecting'
                )
                self._bump_errors(e)
                await self._group.spawn(self.close)
                await sleep(0.001)
            except BadChecksumError as e:
                payload_checksum, claimed_checksum = e.args
                self.logger.warning(
                    f'checksum mismatch: actual {payload_checksum.hex()} '
                    f'vs claimed {claimed_checksum.hex()}'
                )
                self._bump_errors(e)
            else:
                self.last_recv = time.time()
                self.recv_count += 1
                await self._group.spawn(self._throttled_message(message))

    async def _throttled_message(self, message):
        '''Process a single request, respecting the concurrency limit.'''
        try:
            timeout = self.processing_timeout
            async with timeout_after(timeout):
                async with self._incoming_concurrency:
                    if self._cost_fraction:
                        await sleep(self._cost_fraction * self.cost_sleep)
                    await self.handle_message(message)
        except ProtocolError as e:
            self.logger.error(f'{e}')
            self._bump_errors(e)
        except TaskTimeout:
            self.logger.info(f'incoming request timed out after {timeout} secs')
            self._bump_errors()
        except ExcessiveSessionCostError:
            self.on_disconnect_due_to_excessive_session_cost()
            await self.close()
        except Exception:
            self.logger.exception(f'exception handling {message}')
            self._bump_errors()

    def default_framer(self):
        '''Return a bitcoin framer.'''
        return BitcoinFramer()

    async def handle_message(self, message):
        '''message is a (command, payload) pair.'''

    async def send_message(self, message):
        '''Send a message (command, payload) over the network.'''
        await self._send_message(message)


class BatchError(Exception):

    def __init__(self, request):
        super().__init__(request)
        self.request = request   # BatchRequest object


class BatchRequest:
    '''Used to build a batch request to send to the server.  Stores
    the

    Attributes batch and results are initially None.

    Adding an invalid request or notification immediately raises a
    ProtocolError.

    On exiting the with clause, it will:

    1) create a Batch object for the requests in the order they were
       added.  If the batch is empty this raises a ProtocolError.

    2) set the "batch" attribute to be that batch

    3) send the batch request and wait for a response

    4) raise a ProtocolError if the protocol was violated by the
       server.  Currently this only happens if it gave more than one
       response to any request

    5) otherwise there is precisely one response to each Request.  Set
       the "results" attribute to the tuple of results; the responses
       are ordered to match the Requests in the batch.  Notifications
       do not get a response.

    6) if raise_errors is True and any individual response was a JSON
       RPC error response, or violated the protocol in some way, a
       BatchError exception is raised.  Otherwise the caller can be
       certain each request returned a standard result.
    '''

    def __init__(self, session, raise_errors):
        self._session = session
        self._raise_errors = raise_errors
        self._requests = []
        self.batch = None
        self.results = None

    def add_request(self, method, args=()):
        self._requests.append(Request(method, args))

    def add_notification(self, method, args=()):
        self._requests.append(Notification(method, args))

    def __len__(self):
        return len(self._requests)

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        if exc_type is None:
            self.batch = Batch(self._requests)
            message, future = self._session.connection.send_batch(self.batch)
            self.results = await self._session._send_concurrent(message, future, len(self.batch))
            if self._raise_errors:
                if any(isinstance(item, Exception) for item in self.results):
                    raise BatchError(self)


class RPCSession(SessionBase):
    '''Base class for protocols where a message can lead to a response,
    for example JSON RPC.'''

    # Adjust outgoing request concurrency to target a round trip response time of
    # this many seconds, recalibrating every recalibrate_count requests
    target_response_time = 3.0
    recalibrate_count = 30
    # Raise a TaskTimeout if getting a response takes longer than this
    sent_request_timeout = 30.0
    log_me = False

    def __init__(self, transport, *, loop=None, connection=None):
        super().__init__(transport, loop=loop)
        self.connection = connection or self.default_connection()
        # Concurrency control for outgoing request sending
        self._outgoing_concurrency = Concurrency(50)
        self._req_times = []

    def _recalc_concurrency(self):
        req_times = self._req_times
        avg = sum(req_times) / len(req_times)
        req_times.clear()
        current = self._outgoing_concurrency.max_concurrent
        cap = min(current + max(3, current * 0.1), 250)
        floor = max(1, min(current * 0.8, current - 1))
        if avg != 0:
            target = max(floor, min(cap, current * self.target_response_time / avg))
        else:
            target = cap
        target = int(0.5 + target)
        if target != current:
            self.logger.info(f'changing outgoing request concurrency to {target} from {current}')
            self._outgoing_concurrency.set_target(target)

    async def _process_messages_loop(self, recv_message):
        # The loop will exit when recv_message raises a ConnectionLost error; which is also
        # arranged when close() is called.
        while True:
            try:
                message = await recv_message()
            except MemoryError as e:
                self.logger.warning(f'{e!r}')
                continue

            self.last_recv = time.time()
            self.recv_count += 1
            if self.log_me:
                self.logger.info(f'processing {message}')

            try:
                requests = self.connection.receive_message(message)
            except ProtocolError as e:
                self.logger.debug(str(e))
                if e.code == JSONRPC.PARSE_ERROR:
                    e.cost = self.error_base_cost * 10
                self._bump_errors(e)
                if e.error_message:
                    await self._send_message(e.error_message)
            else:
                for request in requests:
                    await self._group.spawn(self._throttled_request(request))

    async def _throttled_request(self, request):
        '''Process a single request, respecting the concurrency limit.'''
        disconnect = False
        try:
            timeout = self.processing_timeout
            async with timeout_after(timeout):
                async with self._incoming_concurrency:
                    if self._cost_fraction:
                        await sleep(self._cost_fraction * self.cost_sleep)
                    result = await self.handle_request(request)
        except (ProtocolError, RPCError) as e:
            result = e
        except TaskTimeout:
            self.logger.info(f'incoming request {request} timed out after {timeout} secs')
            result = RPCError(JSONRPC.SERVER_BUSY, 'server busy - request timed out')
        except ReplyAndDisconnect as e:
            result = e.args[0]
            disconnect = True
        except ExcessiveSessionCostError:
            self.on_disconnect_due_to_excessive_session_cost()
            result = RPCError(JSONRPC.EXCESSIVE_RESOURCE_USAGE, 'excessive resource usage')
            disconnect = True
        except Exception:
            self.logger.exception(f'exception handling {request}')
            result = RPCError(JSONRPC.INTERNAL_ERROR, 'internal server error')

        if isinstance(request, Request):
            message = request.send_result(result)
            if message:
                await self._send_message(message)
        if isinstance(result, Exception):
            self._bump_errors(result)
        if disconnect:
            await self.close()

    async def _send_concurrent(self, message, future, request_count):
        async with self._outgoing_concurrency:
            send_time = await self._send_message(message)
            try:
                async with timeout_after(self.sent_request_timeout):
                    return await future
            finally:
                time_taken = max(0, time.time() - send_time)
                if request_count == 1:
                    self._req_times.append(time_taken)
                else:
                    self._req_times.extend([time_taken / request_count] * request_count)
                if len(self._req_times) >= self.recalibrate_count:
                    self._recalc_concurrency()

    # External API
    async def connection_lost(self):
        self.connection.cancel_pending_requests()

    def default_connection(self):
        '''Return a default connection if the user provides none.'''
        return JSONRPCConnection(JSONRPCv2)

    def default_framer(self):
        '''Return a default framer.'''
        return NewlineFramer()

    async def handle_request(self, request):
        pass

    async def send_request(self, method, args=()):
        '''Send an RPC request over the network.'''
        message, future = self.connection.send_request(Request(method, args))
        return await self._send_concurrent(message, future, 1)

    async def send_notification(self, method, args=()):
        '''Send an RPC notification over the network.'''
        message = self.connection.send_notification(Notification(method, args))
        await self._send_message(message)

    def send_batch(self, raise_errors=False):
        '''Return a BatchRequest.  Intended to be used like so:

           async with session.send_batch() as batch:
               batch.add_request("method1")
               batch.add_request("sum", (x, y))
               batch.add_notification("updated")

           for result in batch.results:
              ...

        Note that in some circumstances exceptions can be raised; see
        BatchRequest doc string.
        '''
        return BatchRequest(self, raise_errors)
