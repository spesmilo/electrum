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


from functools import partial

try:
    from websockets import connect, serve
    from websockets.exceptions import ConnectionClosed
except ImportError:
    websockets = None

from aiorpcx.curio import spawn
from aiorpcx.session import RPCSession, SessionKind
from aiorpcx.util import NetAddress


__all__ = ('serve_ws', 'connect_ws')


class WSTransport:
    '''Implementation of a websocket transport for session.py.'''

    def __init__(self, websocket, session_factory, kind):
        self.websocket = websocket
        self.kind = kind
        self.session = session_factory(self)
        self.closing = False

    @classmethod
    async def ws_server(cls, session_factory, websocket):
        transport = cls(websocket, session_factory, SessionKind.SERVER)
        await transport.process_messages()

    @classmethod
    async def ws_client(cls, uri, **kwargs):
        session_factory = kwargs.pop('session_factory', RPCSession)
        websocket = await connect(uri, **kwargs)
        return cls(websocket, session_factory, SessionKind.CLIENT)

    async def recv_message(self):
        message = await self.websocket.recv()
        # It might be nice to avoid the redundant conversions
        if isinstance(message, str):
            message = message.encode()
        self.session.data_received(message)
        return message

    async def process_messages(self):
        try:
            await self.session.process_messages(self.recv_message)
        except ConnectionClosed:
            pass

    # API exposed to session
    async def write(self, framed_message):
        # Prefer to send as text
        try:
            framed_message = framed_message.decode()
        except UnicodeDecodeError:
            pass
        await self.websocket.send(framed_message)

    async def close(self, _force_after=0):
        '''Close the connection and return when closed.'''
        self.closing = True
        await self.websocket.close()

    async def abort(self):
        '''Abort the connection.  For now this just calls close().'''
        self.closing = True
        await self.close()

    def is_closing(self):
        '''Return True if the connection is closing.'''
        return self.closing

    def proxy(self):
        return None

    def remote_address(self):
        result = self.websocket.remote_address
        if result:
            result = NetAddress(*result[:2])
        return result


class WSClient:

    def __init__(self, uri, **kwargs):
        self.uri = uri
        self.session_factory = kwargs.pop('session_factory', RPCSession)
        self.kwargs = kwargs
        self.transport = None
        self.process_messages_task = None

    async def __aenter__(self):
        self.transport = await WSTransport.ws_client(self.uri, **self.kwargs)
        self.process_messages_task = await spawn(self.transport.process_messages())
        return self.transport.session

    async def __aexit__(self, exc_type, exc_value, traceback):
        await self.transport.close()
        # Disabled this as loop might not have processed the event, and don't want to sleep here
        # assert self.process_messages_task.done()


def serve_ws(session_factory, *args, **kwargs):
    ws_handler = partial(WSTransport.ws_server, session_factory)
    return serve(ws_handler, *args, **kwargs)


connect_ws = WSClient
