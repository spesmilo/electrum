# Copyright (c) 2018, Neil Booth
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

'''SOCKS proxying.'''

import asyncio
import collections
from ipaddress import IPv4Address, IPv6Address
import secrets
import socket
import struct
from functools import partial

from aiorpcx.util import NetAddress


__all__ = ('SOCKSUserAuth', 'SOCKSRandomAuth', 'SOCKS4', 'SOCKS4a', 'SOCKS5', 'SOCKSProxy',
           'SOCKSError', 'SOCKSProtocolError', 'SOCKSFailure')


SOCKSUserAuth = collections.namedtuple("SOCKSUserAuth", "username password")


# Random authentication is useful when used with Tor for stream isolation.
class SOCKSRandomAuth(SOCKSUserAuth):
    def __getattribute__(self, key):
        return secrets.token_hex(32)


SOCKSRandomAuth.__new__.__defaults__ = (None, None)


class SOCKSError(Exception):
    '''Base class for SOCKS exceptions.  Each raised exception will be
    an instance of a derived class.'''


class SOCKSProtocolError(SOCKSError):
    '''Raised when the proxy does not follow the SOCKS protocol'''


class SOCKSFailure(SOCKSError):
    '''Raised when the proxy refuses or fails to make a connection'''


class NeedData(Exception):
    pass


class SOCKSBase:
    '''Stateful as written so good for a single connection only.'''

    @classmethod
    def name(cls):
        return cls.__name__

    def __init__(self):
        self._buffer = bytes()
        self._state = self._start

    def _read(self, size):
        if len(self._buffer) < size:
            raise NeedData(size - len(self._buffer))
        result = self._buffer[:size]
        self._buffer = self._buffer[size:]
        return result

    def receive_data(self, data):
        self._buffer += data

    def next_message(self):
        return self._state()


class SOCKS4(SOCKSBase):
    '''SOCKS4 protocol wrapper.'''

    # See http://ftp.icm.edu.pl/packages/socks/socks4/SOCKS4.protocol
    REPLY_CODES = {
        90: 'request granted',
        91: 'request rejected or failed',
        92: ('request rejected because SOCKS server cannot connect '
             'to identd on the client'),
        93: ('request rejected because the client program and identd '
             'report different user-ids')
    }

    def __init__(self, remote_address, auth):
        super().__init__()
        self._remote_host = remote_address.host
        self._remote_port = remote_address.port
        self._auth = auth
        self._check_remote_host()

    def _check_remote_host(self):
        if not isinstance(self._remote_host, IPv4Address):
            raise SOCKSProtocolError(f'SOCKS4 requires an IPv4 address: {self._remote_host}')

    def _start(self):
        self._state = self._first_response

        if isinstance(self._remote_host, IPv4Address):
            # SOCKS4
            dst_ip_packed = self._remote_host.packed
            host_bytes = b''
        else:
            # SOCKS4a
            dst_ip_packed = b'\0\0\0\1'
            host_bytes = self._remote_host.encode() + b'\0'

        if isinstance(self._auth, SOCKSUserAuth):
            user_id = self._auth.username.encode()
        else:
            user_id = b''

        # Send TCP/IP stream CONNECT request
        return b''.join([b'\4\1', struct.pack('>H', self._remote_port),
                         dst_ip_packed, user_id, b'\0', host_bytes])

    def _first_response(self):
        # Wait for 8-byte response
        data = self._read(8)
        if data[0] != 0:
            raise SOCKSProtocolError(f'invalid {self.name()} proxy '
                                     f'response: {data}')
        reply_code = data[1]
        if reply_code != 90:
            msg = self.REPLY_CODES.get(
                reply_code, f'unknown {self.name()} reply code {reply_code}')
            raise SOCKSFailure(f'{self.name()} proxy request failed: {msg}')

        # Other fields ignored
        return None


class SOCKS4a(SOCKS4):

    def _check_remote_host(self):
        if not isinstance(self._remote_host, (str, IPv4Address)):
            raise SOCKSProtocolError(
                f'SOCKS4a requires an IPv4 address or host name: {self._remote_host}')


class SOCKS5(SOCKSBase):
    '''SOCKS protocol wrapper.'''

    # See https://tools.ietf.org/html/rfc1928
    ERROR_CODES = {
        1: 'general SOCKS server failure',
        2: 'connection not allowed by ruleset',
        3: 'network unreachable',
        4: 'host unreachable',
        5: 'connection refused',
        6: 'TTL expired',
        7: 'command not supported',
        8: 'address type not supported',
    }

    def __init__(self, remote_address, auth):
        super().__init__()
        self._dst_bytes = SOCKS5._destination_bytes(remote_address.host, remote_address.port)
        self._auth_bytes, self._auth_methods = SOCKS5._authentication(auth)

    @staticmethod
    def _destination_bytes(host, port):
        if isinstance(host, IPv4Address):
            addr_bytes = b'\1' + host.packed
        elif isinstance(host, IPv6Address):
            addr_bytes = b'\4' + host.packed
        else:
            assert isinstance(host, str)
            host = host.encode()
            assert len(host) <= 255
            addr_bytes = b'\3' + bytes([len(host)]) + host
        return addr_bytes + struct.pack('>H', port)

    @staticmethod
    def _authentication(auth):
        if isinstance(auth, SOCKSUserAuth):
            user_bytes = auth.username.encode()
            if not 0 < len(user_bytes) < 256:
                raise SOCKSProtocolError(f'username {auth.username} has '
                                         f'invalid length {len(user_bytes)}')
            pwd_bytes = auth.password.encode()
            if not 0 < len(pwd_bytes) < 256:
                raise SOCKSProtocolError(f'password has invalid length '
                                         f'{len(pwd_bytes)}')
            return b''.join([bytes([1, len(user_bytes)]), user_bytes,
                             bytes([len(pwd_bytes)]), pwd_bytes]), [0, 2]
        return b'', [0]

    def _start(self):
        self._state = self._first_response
        return (b'\5' + bytes([len(self._auth_methods)])
                + bytes(m for m in self._auth_methods))

    def _first_response(self):
        # Wait for 2-byte response
        data = self._read(2)
        if data[0] != 5:
            raise SOCKSProtocolError(f'invalid SOCKS5 proxy response: {data}')
        if data[1] not in self._auth_methods:
            raise SOCKSFailure('SOCKS5 proxy rejected authentication methods')

        # Authenticate if user-password authentication
        if data[1] == 2:
            self._state = self._auth_response
            return self._auth_bytes
        return self._request_connection()

    def _auth_response(self):
        data = self._read(2)
        if data[0] != 1:
            raise SOCKSProtocolError(f'invalid SOCKS5 proxy auth '
                                     f'response: {data}')
        if data[1] != 0:
            raise SOCKSFailure(f'SOCKS5 proxy auth failure code: '
                               f'{data[1]}')

        return self._request_connection()

    def _request_connection(self):
        # Send connection request
        self._state = self._connect_response
        return b'\5\1\0' + self._dst_bytes

    def _connect_response(self):
        data = self._read(5)
        if data[0] != 5 or data[2] != 0 or data[3] not in (1, 3, 4):
            raise SOCKSProtocolError(f'invalid SOCKS5 proxy response: {data}')
        if data[1] != 0:
            raise SOCKSFailure(self.ERROR_CODES.get(
                data[1], f'unknown SOCKS5 error code: {data[1]}'))

        if data[3] == 1:
            addr_len = 3   # IPv4
        elif data[3] == 3:
            addr_len = data[4]  # Hostname
        else:
            addr_len = 15  # IPv6

        self._state = partial(self._connect_response_rest, addr_len)
        return self.next_message()

    def _connect_response_rest(self, addr_len):
        self._read(addr_len + 2)
        return None


class SOCKSProxy:

    def __init__(self, address, protocol, auth):
        '''A SOCKS proxy at a NetAddress following a SOCKS protocol.

        auth is an authentication method to use when connecting, or None.
        '''
        if not isinstance(address, NetAddress):
            address = NetAddress.from_string(address)
        self.address = address
        self.protocol = protocol
        self.auth = auth
        # Set on each successful connection via the proxy to the
        # result of socket.getpeername()
        self.peername = None

    def __str__(self):
        auth = 'username' if self.auth else 'none'
        return f'{self.protocol.name()} proxy at {self.address}, auth: {auth}'

    async def _handshake(self, client, sock, loop):
        while True:
            count = 0
            try:
                message = client.next_message()
            except NeedData as e:
                count = e.args[0]
            else:
                if message is None:
                    return
                await loop.sock_sendall(sock, message)

            if count:
                data = await loop.sock_recv(sock, count)
                if not data:
                    raise SOCKSProtocolError("EOF received")
                client.receive_data(data)

    async def _connect_one(self, remote_address):
        '''Connect to the proxy and perform a handshake requesting a connection.

        Return the open socket on success, or the exception on failure.
        '''
        loop = asyncio.get_event_loop()

        for info in await loop.getaddrinfo(str(self.address.host), self.address.port,
                                           type=socket.SOCK_STREAM):
            # This object has state so is only good for one connection
            client = self.protocol(remote_address, self.auth)
            sock = socket.socket(family=info[0])
            try:
                # A non-blocking socket is required by loop socket methods
                sock.setblocking(False)
                await loop.sock_connect(sock, info[4])
                await self._handshake(client, sock, loop)
                self.peername = sock.getpeername()
                return sock
            except (OSError, SOCKSError) as e:
                exception = e
                # Don't close the socket because of an asyncio bug
                # see https://github.com/kyuupichan/aiorpcX/issues/8
        return exception

    async def _connect(self, remote_addresses):
        '''Connect to the proxy and perform a handshake requesting a connection to each address in
        addresses.

        Return an (open_socket, remote_address) pair on success.
        '''
        assert remote_addresses

        exceptions = []
        for remote_address in remote_addresses:
            sock = await self._connect_one(remote_address)
            if isinstance(sock, socket.socket):
                return sock, remote_address
            exceptions.append(sock)

        strings = set(f'{exc!r}' for exc in exceptions)
        raise (exceptions[0] if len(strings) == 1 else
               OSError(f'multiple exceptions: {", ".join(strings)}'))

    async def _detect_proxy(self):
        '''Return True if it appears we can connect to a SOCKS proxy,
        otherwise False.
        '''
        if self.protocol is SOCKS4a:
            remote_address = NetAddress('www.apple.com', 80)
        else:
            remote_address = NetAddress('8.8.8.8', 53)

        sock = await self._connect_one(remote_address)
        if isinstance(sock, socket.socket):
            sock.close()
            return True

        # SOCKSFailure indicates something failed, but that we are likely talking to a
        # proxy
        return isinstance(sock, SOCKSFailure)

    @classmethod
    async def auto_detect_at_address(cls, address, auth):
        '''Try to detect a SOCKS proxy at address using the authentication method (or None).
        SOCKS5, SOCKS4a and SOCKS are tried in order.  If a SOCKS proxy is detected a
        SOCKSProxy object is returned.

        Returning a SOCKSProxy does not mean it is functioning - for example, it may have
        no network connectivity.

        If no proxy is detected return None.
        '''
        for protocol in (SOCKS5, SOCKS4a, SOCKS4):
            proxy = cls(address, protocol, auth)
            if await proxy._detect_proxy():
                return proxy
        return None

    @classmethod
    async def auto_detect_at_host(cls, host, ports, auth):
        '''Try to detect a SOCKS proxy on a host on one of the ports.

        Calls auto_detect_address for the ports in order.  Returning a SOCKSProxy does not
        mean it is functioning - for example, it may have no network connectivity.

        If no proxy is detected return None.
        '''
        for port in ports:
            proxy = await cls.auto_detect_at_address(NetAddress(host, port), auth)
            if proxy:
                return proxy

        return None

    async def create_connection(self, protocol_factory, host, port, *,
                                resolve=False, ssl=None,
                                family=0, proto=0, flags=0):
        '''Set up a connection to (host, port) through the proxy.

        If resolve is True then host is resolved locally with
        getaddrinfo using family, proto and flags, otherwise the proxy
        is asked to resolve host.

        The function signature is similar to loop.create_connection()
        with the same result.  The attribute _address is set on the
        protocol to the address of the successful remote connection.
        Additionally raises SOCKSError if something goes wrong with
        the proxy handshake.
        '''
        loop = asyncio.get_event_loop()
        if resolve:
            remote_addresses = [NetAddress(info[4][0], info[4][1]) for info in
                                await loop.getaddrinfo(host, port, family=family, proto=proto,
                                                       type=socket.SOCK_STREAM, flags=flags)]
        else:
            remote_addresses = [NetAddress(host, port)]

        sock, remote_address = await self._connect(remote_addresses)

        def set_address():
            protocol = protocol_factory()
            protocol._proxy = self
            protocol._remote_address = remote_address
            return protocol

        return await loop.create_connection(set_address, sock=sock, ssl=ssl,
                                            server_hostname=host if ssl else None)
