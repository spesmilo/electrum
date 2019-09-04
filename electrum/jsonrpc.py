#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2019 Thomas Voegtlin
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

import time
from aiohttp import web
from base64 import b64decode

import jsonrpcserver

from .util import to_bytes, to_string, constant_time_compare
from .logging import Logger


class AuthenticationError(Exception):
    pass


class JsonRpcServer(Logger):
    """General JSON-RPC server as used in Electrum

    This implements some common code to build a JSON-RPC server listening
    on HTTP, optionally with authentication.  That is then used both for
    implementing the WatchTowerServer and the general Daemon JSON-RPC
    interface."""

    def __init__ (self):
        Logger.__init__(self)

    def authenticate(self, headers):
        if self.rpcauth is None:
            # RPC authentication is disabled
            return
        user, password = self.rpcauth
        auth_string = headers.get('Authorization', None)
        if auth_string is None:
            raise AuthenticationError('CredentialsMissing')
        basic, _, encoded = auth_string.partition(' ')
        if basic != 'Basic':
            raise AuthenticationError('UnsupportedType')
        encoded = to_bytes(encoded, 'utf8')
        credentials = to_string(b64decode(encoded), 'utf8')
        username, _, password = credentials.partition(':')
        if not (constant_time_compare(username, user)
                and constant_time_compare(password, password)):
            time.sleep(0.050)
            raise AuthenticationError('Invalid Credentials')

    async def handle(self, request):
        try:
            self.authenticate(request.headers)
        except AuthenticationError:
            return web.Response(text='Forbidden', status=403)
        request = await request.text()
        #self.logger.info(f'handling request: {request}')
        response = await jsonrpcserver.async_dispatch(request, methods=self.methods)
        if isinstance(response, jsonrpcserver.response.ExceptionResponse):
            self.logger.error(f"error handling request: {request}", exc_info=response.exc)
        if response.wanted:
            return web.json_response(response.deserialized(), status=response.http_status)
        else:
            return web.Response()

    async def start_jsonrpc(self, methods, host_port, rpcauth=None):
        """Starts the JSON-RPC server

        host_port should be a pair of (host, port) for the desired
        server.  methods must be the set of methods as jsonrpcserver
        Method instance, and rpcauth should be None to disable authentication
        or a pair (user, password) to use authentication.

        The method returns the created TCPSite instance to the caller."""

        self.rpcauth = rpcauth
        self.methods = methods

        self.app = web.Application()
        self.app.router.add_post("/", self.handle)

        self.runner = web.AppRunner(self.app)
        await self.runner.setup()

        host, port = host_port
        site = web.TCPSite(self.runner, host, port)
        await site.start()

        return site
