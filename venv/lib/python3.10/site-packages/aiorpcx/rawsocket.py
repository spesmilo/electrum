# Copyright (c) 2019, Neil Booth
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

'''Asyncio protocol abstraction.'''

__all__ = ('connect_rs', 'serve_rs')


import asyncio
from functools import partial

from aiorpcx.curio import Event, timeout_after, TaskTimeout
from aiorpcx.session import RPCSession, SessionBase, SessionKind
from aiorpcx.util import NetAddress


class ConnectionLostError(Exception):
    pass


class RSTransport(asyncio.Protocol):

    def __init__(self, session_factory, framer, kind):
        self.session_factory = session_factory
        self.loop = asyncio.get_event_loop()
        self.session = None
        self.kind = kind
        self._proxy = None
        self._asyncio_transport = None
        self._remote_address = None
        self._framer = framer
        # Cleared when the send socket is full
        self._can_send = Event()
        self._can_send.set()
        self._closed_event = Event()
        self._process_messages_task = None

    async def process_messages(self):
        try:
            await self.session.process_messages(self.receive_message)
        except ConnectionLostError:
            pass
        finally:
            self._closed_event.set()

    async def receive_message(self):
        return await self._framer.receive_message()

    def connection_made(self, transport):
        '''Called by asyncio when a connection is established.'''
        self._asyncio_transport = transport
        # If the Socks proxy was used then _proxy and _remote_address are already set
        if self._proxy is None:
            # This would throw if called on a closed SSL transport.  Fixed in asyncio in
            # Python 3.6.1 and 3.5.4
            peername = transport.get_extra_info('peername')
            if peername:
                self._remote_address = NetAddress(peername[0], peername[1])
        self.session = self.session_factory(self)
        self._framer = self._framer or self.session.default_framer()
        self._process_messages_task = self.loop.create_task(self.process_messages())

    def connection_lost(self, exc):
        '''Called by asyncio when the connection closes.

        Tear down things done in connection_made.'''
        # Release waiting tasks
        self._can_send.set()
        self._framer.fail(ConnectionLostError())

    def data_received(self, data):
        '''Called by asyncio when a message comes in.'''
        self.session.data_received(data)
        self._framer.received_bytes(data)

    def pause_writing(self):
        '''Called by asyncio the send buffer is full.'''
        if not self.is_closing():
            self._can_send.clear()
            self._asyncio_transport.pause_reading()

    def resume_writing(self):
        '''Called by asyncio the send buffer has room.'''
        if not self._can_send.is_set():
            self._can_send.set()
            self._asyncio_transport.resume_reading()

    # API exposed to session
    async def write(self, message):
        await self._can_send.wait()
        if not self.is_closing():
            framed_message = self._framer.frame(message)
            self._asyncio_transport.write(framed_message)

    async def close(self, force_after):
        '''Close the connection and return when closed.'''
        if self._asyncio_transport:
            self._asyncio_transport.close()
            try:
                async with timeout_after(force_after):
                    await self._closed_event.wait()
            except TaskTimeout:
                await self.abort()
                await self._closed_event.wait()

    async def abort(self):
        if self._asyncio_transport:
            self._asyncio_transport.abort()

    def is_closing(self):
        '''Return True if the connection is closing.'''
        return self._closed_event.is_set() or self._asyncio_transport.is_closing()

    def proxy(self):
        return self._proxy

    def remote_address(self):
        return self._remote_address


class RSClient:

    def __init__(
        self, host=None, port=None, proxy=None, *, framer=None, transport=None, **kwargs,
    ):
        session_factory = kwargs.pop('session_factory', RPCSession)
        if transport is None:
            transport = RSTransport
        self.protocol_factory = partial(transport, session_factory, framer,
                                        SessionKind.CLIENT)
        self.host = host
        self.port = port
        self.proxy = proxy
        self.session = None
        self.loop = kwargs.get('loop', asyncio.get_event_loop())
        self.kwargs = kwargs

    async def create_connection(self):
        '''Initiate a connection.'''
        connector = self.proxy or self.loop
        return await connector.create_connection(
            self.protocol_factory, self.host, self.port, **self.kwargs)

    async def __aenter__(self):
        _transport, protocol = await self.create_connection()
        self.session = protocol.session
        assert isinstance(self.session, SessionBase)
        return self.session

    async def __aexit__(self, exc_type, exc_value, traceback):
        await self.session.close()


async def serve_rs(
    session_factory, host=None, port=None, *, framer=None, transport=None, loop=None, **kwargs,
):
    loop = loop or asyncio.get_event_loop()
    if transport is None:
        transport = RSTransport
    protocol_factory = partial(transport, session_factory, framer, SessionKind.SERVER)
    return await loop.create_server(protocol_factory, host, port, **kwargs)


connect_rs = RSClient
