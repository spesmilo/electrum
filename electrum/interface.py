#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2011 thomasv@gitorious
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
import os
import re
import ssl
import sys
import traceback
import asyncio
import socket
from typing import Tuple, Union, List, TYPE_CHECKING, Optional, Set, NamedTuple, Any, Sequence, Dict
from collections import defaultdict
from ipaddress import IPv4Network, IPv6Network, ip_address, IPv6Address, IPv4Address
import itertools
import logging
import hashlib
import functools

import aiorpcx
from aiorpcx import RPCSession, Notification, NetAddress, NewlineFramer
from aiorpcx.curio import timeout_after, TaskTimeout
from aiorpcx.jsonrpc import JSONRPC, CodeMessageError
from aiorpcx.rawsocket import RSClient
import certifi

from .util import (ignore_exceptions, log_exceptions, bfh, MySocksProxy,
                   is_integer, is_non_negative_integer, is_hash256_str, is_hex_str,
                   is_int_or_float, is_non_negative_int_or_float, OldTaskGroup)
from . import util
from . import x509
from . import pem
from . import version
from . import blockchain
from .blockchain import Blockchain, HEADER_SIZE
from . import bitcoin
from . import constants
from .i18n import _
from .logging import Logger
from .transaction import Transaction

if TYPE_CHECKING:
    from .network import Network
    from .simple_config import SimpleConfig


ca_path = certifi.where()

BUCKET_NAME_OF_ONION_SERVERS = 'onion'

_KNOWN_NETWORK_PROTOCOLS = {'t', 's'}
PREFERRED_NETWORK_PROTOCOL = 's'
assert PREFERRED_NETWORK_PROTOCOL in _KNOWN_NETWORK_PROTOCOLS


class NetworkTimeout:
    # seconds
    class Generic:
        NORMAL = 30
        RELAXED = 45
        MOST_RELAXED = 600

    class Urgent(Generic):
        NORMAL = 10
        RELAXED = 20
        MOST_RELAXED = 60


def assert_non_negative_integer(val: Any) -> None:
    if not is_non_negative_integer(val):
        raise RequestCorrupted(f'{val!r} should be a non-negative integer')


def assert_integer(val: Any) -> None:
    if not is_integer(val):
        raise RequestCorrupted(f'{val!r} should be an integer')


def assert_int_or_float(val: Any) -> None:
    if not is_int_or_float(val):
        raise RequestCorrupted(f'{val!r} should be int or float')


def assert_non_negative_int_or_float(val: Any) -> None:
    if not is_non_negative_int_or_float(val):
        raise RequestCorrupted(f'{val!r} should be a non-negative int or float')


def assert_hash256_str(val: Any) -> None:
    if not is_hash256_str(val):
        raise RequestCorrupted(f'{val!r} should be a hash256 str')


def assert_hex_str(val: Any) -> None:
    if not is_hex_str(val):
        raise RequestCorrupted(f'{val!r} should be a hex str')


def assert_dict_contains_field(d: Any, *, field_name: str) -> Any:
    if not isinstance(d, dict):
        raise RequestCorrupted(f'{d!r} should be a dict')
    if field_name not in d:
        raise RequestCorrupted(f'required field {field_name!r} missing from dict')
    return d[field_name]


def assert_list_or_tuple(val: Any) -> None:
    if not isinstance(val, (list, tuple)):
        raise RequestCorrupted(f'{val!r} should be a list or tuple')


class NotificationSession(RPCSession):

    def __init__(self, *args, interface: 'Interface', **kwargs):
        super(NotificationSession, self).__init__(*args, **kwargs)
        self.subscriptions = defaultdict(list)
        self.cache = {}
        self._msg_counter = itertools.count(start=1)
        self.interface = interface
        self.cost_hard_limit = 0  # disable aiorpcx resource limits

    async def handle_request(self, request):
        self.maybe_log(f"--> {request}")
        try:
            if isinstance(request, Notification):
                params, result = request.args[:-1], request.args[-1]
                key = self.get_hashable_key_for_rpc_call(request.method, params)
                if key in self.subscriptions:
                    self.cache[key] = result
                    for queue in self.subscriptions[key]:
                        await queue.put(request.args)
                else:
                    raise Exception(f'unexpected notification')
            else:
                raise Exception(f'unexpected request. not a notification')
        except Exception as e:
            self.interface.logger.info(f"error handling request {request}. exc: {repr(e)}")
            await self.close()

    async def send_request(self, *args, timeout=None, **kwargs):
        # note: semaphores/timeouts/backpressure etc are handled by
        # aiorpcx. the timeout arg here in most cases should not be set
        msg_id = next(self._msg_counter)
        self.maybe_log(f"<-- {args} {kwargs} (id: {msg_id})")
        try:
            # note: RPCSession.send_request raises TaskTimeout in case of a timeout.
            # TaskTimeout is a subclass of CancelledError, which is *suppressed* in TaskGroups
            response = await util.wait_for2(
                super().send_request(*args, **kwargs),
                timeout)
        except (TaskTimeout, asyncio.TimeoutError) as e:
            self.maybe_log(f"--> request timed out: {args} (id: {msg_id})")
            raise RequestTimedOut(f'request timed out: {args} (id: {msg_id})') from e
        except CodeMessageError as e:
            self.maybe_log(f"--> {repr(e)} (id: {msg_id})")
            raise
        except BaseException as e:  # cancellations, etc. are useful for debugging
            self.maybe_log(f"--> {repr(e)} (id: {msg_id})")
            raise
        else:
            self.maybe_log(f"--> {response} (id: {msg_id})")
            return response

    def set_default_timeout(self, timeout):
        assert hasattr(self, "sent_request_timeout")  # in base class
        self.sent_request_timeout = timeout
        assert hasattr(self, "max_send_delay")        # in base class
        self.max_send_delay = timeout

    async def subscribe(self, method: str, params: List, queue: asyncio.Queue):
        # note: until the cache is written for the first time,
        # each 'subscribe' call might make a request on the network.
        key = self.get_hashable_key_for_rpc_call(method, params)
        self.subscriptions[key].append(queue)
        if key in self.cache:
            result = self.cache[key]
        else:
            result = await self.send_request(method, params)
            self.cache[key] = result
        await queue.put(params + [result])

    def unsubscribe(self, queue):
        """Unsubscribe a callback to free object references to enable GC."""
        # note: we can't unsubscribe from the server, so we keep receiving
        # subsequent notifications
        for v in self.subscriptions.values():
            if queue in v:
                v.remove(queue)

    @classmethod
    def get_hashable_key_for_rpc_call(cls, method, params):
        """Hashable index for subscriptions and cache"""
        return str(method) + repr(params)

    def maybe_log(self, msg: str) -> None:
        if not self.interface: return
        if self.interface.debug or self.interface.network.debug:
            self.interface.logger.debug(msg)

    def default_framer(self):
        # overridden so that max_size can be customized
        max_size = self.interface.network.config.NETWORK_MAX_INCOMING_MSG_SIZE
        assert max_size > 500_000, f"{max_size=} (< 500_000) is too small"
        return NewlineFramer(max_size=max_size)

    async def close(self, *, force_after: int = None):
        """Closes the connection and waits for it to be closed.
        We try to flush buffered data to the wire, which can take some time.
        """
        if force_after is None:
            # We give up after a while and just abort the connection.
            # Note: specifically if the server is running Fulcrum, waiting seems hopeless,
            #       the connection must be aborted (see https://github.com/cculianu/Fulcrum/issues/76)
            # Note: if the ethernet cable was pulled or wifi disconnected, that too might
            #       wait until this timeout is triggered
            force_after = 1  # seconds
        await super().close(force_after=force_after)


class NetworkException(Exception): pass


class GracefulDisconnect(NetworkException):
    log_level = logging.INFO

    def __init__(self, *args, log_level=None, **kwargs):
        Exception.__init__(self, *args, **kwargs)
        if log_level is not None:
            self.log_level = log_level


class RequestTimedOut(GracefulDisconnect):
    def __str__(self):
        return _("Network request timed out.")


class RequestCorrupted(Exception): pass

class ErrorParsingSSLCert(Exception): pass
class ErrorGettingSSLCertFromServer(Exception): pass
class ErrorSSLCertFingerprintMismatch(Exception): pass
class InvalidOptionCombination(Exception): pass
class ConnectError(NetworkException): pass


class _RSClient(RSClient):
    async def create_connection(self):
        try:
            return await super().create_connection()
        except OSError as e:
            # note: using "from e" here will set __cause__ of ConnectError
            raise ConnectError(e) from e


class ServerAddr:

    def __init__(self, host: str, port: Union[int, str], *, protocol: str = None):
        assert isinstance(host, str), repr(host)
        if protocol is None:
            protocol = 's'
        if not host:
            raise ValueError('host must not be empty')
        if host[0] == '[' and host[-1] == ']':  # IPv6
            host = host[1:-1]
        try:
            net_addr = NetAddress(host, port)  # this validates host and port
        except Exception as e:
            raise ValueError(f"cannot construct ServerAddr: invalid host or port (host={host}, port={port})") from e
        if protocol not in _KNOWN_NETWORK_PROTOCOLS:
            raise ValueError(f"invalid network protocol: {protocol}")
        self.host = str(net_addr.host)  # canonical form (if e.g. IPv6 address)
        self.port = int(net_addr.port)
        self.protocol = protocol
        self._net_addr_str = str(net_addr)

    @classmethod
    def from_str(cls, s: str) -> 'ServerAddr':
        """Constructs a ServerAddr or raises ValueError."""
        # host might be IPv6 address, hence do rsplit:
        host, port, protocol = str(s).rsplit(':', 2)
        return ServerAddr(host=host, port=port, protocol=protocol)

    @classmethod
    def from_str_with_inference(cls, s: str) -> Optional['ServerAddr']:
        """Construct ServerAddr from str, guessing missing details.
        Does not raise - just returns None if guessing failed.
        Ongoing compatibility not guaranteed.
        """
        if not s:
            return None
        host = ""
        if s[0] == "[" and "]" in s:  # IPv6 address
            host_end = s.index("]")
            host = s[1:host_end]
            s = s[host_end+1:]
        items = str(s).rsplit(':', 2)
        if len(items) < 2:
            return None  # although maybe we could guess the port too?
        host = host or items[0]
        port = items[1]
        if len(items) >= 3:
            protocol = items[2]
        else:
            protocol = PREFERRED_NETWORK_PROTOCOL
        try:
            return ServerAddr(host=host, port=port, protocol=protocol)
        except ValueError:
            return None

    def to_friendly_name(self) -> str:
        # note: this method is closely linked to from_str_with_inference
        if self.protocol == 's':  # hide trailing ":s"
            return self.net_addr_str()
        return str(self)

    def __str__(self):
        return '{}:{}'.format(self.net_addr_str(), self.protocol)

    def to_json(self) -> str:
        return str(self)

    def __repr__(self):
        return f'<ServerAddr host={self.host} port={self.port} protocol={self.protocol}>'

    def net_addr_str(self) -> str:
        return self._net_addr_str

    def __eq__(self, other):
        if not isinstance(other, ServerAddr):
            return False
        return (self.host == other.host
                and self.port == other.port
                and self.protocol == other.protocol)

    def __ne__(self, other):
        return not (self == other)

    def __hash__(self):
        return hash((self.host, self.port, self.protocol))


def _get_cert_path_for_host(*, config: 'SimpleConfig', host: str) -> str:
    filename = host
    try:
        ip = ip_address(host)
    except ValueError:
        pass
    else:
        if isinstance(ip, IPv6Address):
            filename = f"ipv6_{ip.packed.hex()}"
    return os.path.join(config.path, 'certs', filename)


class Interface(Logger):

    LOGGING_SHORTCUT = 'i'

    def __init__(self, *, network: 'Network', server: ServerAddr, proxy: Optional[dict]):
        self.ready = network.asyncio_loop.create_future()
        self.got_disconnected = asyncio.Event()
        self.server = server
        Logger.__init__(self)
        assert network.config.path
        self.cert_path = _get_cert_path_for_host(config=network.config, host=self.host)
        self.blockchain = None  # type: Optional[Blockchain]
        self._requested_chunks = set()  # type: Set[int]
        self.network = network
        self.session = None  # type: Optional[NotificationSession]
        self._ipaddr_bucket = None
        # Set up proxy.
        # - for servers running on localhost, the proxy is not used. If user runs their own server
        #   on same machine, this lets them enable the proxy (which is used for e.g. FX rates).
        #   note: we could maybe relax this further and bypass the proxy for all private
        #         addresses...? e.g. 192.168.x.x
        if util.is_localhost(server.host):
            self.logger.info(f"looks like localhost: not using proxy for this server")
            proxy = None
        self.proxy = MySocksProxy.from_proxy_dict(proxy)

        # Latest block header and corresponding height, as claimed by the server.
        # Note that these values are updated before they are verified.
        # Especially during initial header sync, verification can take a long time.
        # Failing verification will get the interface closed.
        self.tip_header = None
        self.tip = 0

        self.fee_estimates_eta = {}  # type: Dict[int, int]

        # Dump network messages (only for this interface).  Set at runtime from the console.
        self.debug = False

        self.taskgroup = OldTaskGroup()

        async def spawn_task():
            task = await self.network.taskgroup.spawn(self.run())
            task.set_name(f"interface::{str(server)}")
        asyncio.run_coroutine_threadsafe(spawn_task(), self.network.asyncio_loop)

    @property
    def host(self):
        return self.server.host

    @property
    def port(self):
        return self.server.port

    @property
    def protocol(self):
        return self.server.protocol

    def diagnostic_name(self):
        return self.server.net_addr_str()

    def __str__(self):
        return f"<Interface {self.diagnostic_name()}>"

    async def is_server_ca_signed(self, ca_ssl_context):
        """Given a CA enforcing SSL context, returns True if the connection
        can be established. Returns False if the server has a self-signed
        certificate but otherwise is okay. Any other failures raise.
        """
        try:
            await self.open_session(ca_ssl_context, exit_early=True)
        except ConnectError as e:
            cause = e.__cause__
            if (isinstance(cause, ssl.SSLCertVerificationError)
                    and cause.reason == 'CERTIFICATE_VERIFY_FAILED'
                    and cause.verify_code == 18):  # "self signed certificate"
                # Good. We will use this server as self-signed.
                return False
            # Not good. Cannot use this server.
            raise
        # Good. We will use this server as CA-signed.
        return True

    async def _try_saving_ssl_cert_for_first_time(self, ca_ssl_context):
        ca_signed = await self.is_server_ca_signed(ca_ssl_context)
        if ca_signed:
            if self._get_expected_fingerprint():
                raise InvalidOptionCombination("cannot use --serverfingerprint with CA signed servers")
            with open(self.cert_path, 'w') as f:
                # empty file means this is CA signed, not self-signed
                f.write('')
        else:
            await self._save_certificate()

    def _is_saved_ssl_cert_available(self):
        if not os.path.exists(self.cert_path):
            return False
        with open(self.cert_path, 'r') as f:
            contents = f.read()
        if contents == '':  # CA signed
            if self._get_expected_fingerprint():
                raise InvalidOptionCombination("cannot use --serverfingerprint with CA signed servers")
            return True
        # pinned self-signed cert
        try:
            b = pem.dePem(contents, 'CERTIFICATE')
        except SyntaxError as e:
            self.logger.info(f"error parsing already saved cert: {e}")
            raise ErrorParsingSSLCert(e) from e
        try:
            x = x509.X509(b)
        except Exception as e:
            self.logger.info(f"error parsing already saved cert: {e}")
            raise ErrorParsingSSLCert(e) from e
        try:
            x.check_date()
        except x509.CertificateError as e:
            self.logger.info(f"certificate has expired: {e}")
            os.unlink(self.cert_path)  # delete pinned cert only in this case
            return False
        self._verify_certificate_fingerprint(bytearray(b))
        return True

    async def _get_ssl_context(self):
        if self.protocol != 's':
            # using plaintext TCP
            return None

        # see if we already have cert for this server; or get it for the first time
        ca_sslc = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH, cafile=ca_path)
        if not self._is_saved_ssl_cert_available():
            try:
                await self._try_saving_ssl_cert_for_first_time(ca_sslc)
            except (OSError, ConnectError, aiorpcx.socks.SOCKSError) as e:
                raise ErrorGettingSSLCertFromServer(e) from e
        # now we have a file saved in our certificate store
        siz = os.stat(self.cert_path).st_size
        if siz == 0:
            # CA signed cert
            sslc = ca_sslc
        else:
            # pinned self-signed cert
            sslc = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH, cafile=self.cert_path)
            sslc.check_hostname = False
        return sslc

    def handle_disconnect(func):
        @functools.wraps(func)
        async def wrapper_func(self: 'Interface', *args, **kwargs):
            try:
                return await func(self, *args, **kwargs)
            except GracefulDisconnect as e:
                self.logger.log(e.log_level, f"disconnecting due to {repr(e)}")
            except aiorpcx.jsonrpc.RPCError as e:
                self.logger.warning(f"disconnecting due to {repr(e)}")
                self.logger.debug(f"(disconnect) trace for {repr(e)}", exc_info=True)
            finally:
                self.got_disconnected.set()
                await self.network.connection_down(self)
                # if was not 'ready' yet, schedule waiting coroutines:
                self.ready.cancel()
        return wrapper_func

    @ignore_exceptions  # do not kill network.taskgroup
    @log_exceptions
    @handle_disconnect
    async def run(self):
        try:
            ssl_context = await self._get_ssl_context()
        except (ErrorParsingSSLCert, ErrorGettingSSLCertFromServer) as e:
            self.logger.info(f'disconnecting due to: {repr(e)}')
            return
        try:
            await self.open_session(ssl_context)
        except (asyncio.CancelledError, ConnectError, aiorpcx.socks.SOCKSError) as e:
            # make SSL errors for main interface more visible (to help servers ops debug cert pinning issues)
            if (isinstance(e, ConnectError) and isinstance(e.__cause__, ssl.SSLError)
                    and self.is_main_server() and not self.network.auto_connect):
                self.logger.warning(f'Cannot connect to main server due to SSL error '
                                    f'(maybe cert changed compared to "{self.cert_path}"). Exc: {repr(e)}')
            else:
                self.logger.info(f'disconnecting due to: {repr(e)}')
            return

    def _mark_ready(self) -> None:
        if self.ready.cancelled():
            raise GracefulDisconnect('conn establishment was too slow; *ready* future was cancelled')
        if self.ready.done():
            return

        assert self.tip_header
        chain = blockchain.check_header(self.tip_header)
        if not chain:
            self.blockchain = blockchain.get_best_chain()
        else:
            self.blockchain = chain
        assert self.blockchain is not None

        self.logger.info(f"set blockchain with height {self.blockchain.height()}")

        self.ready.set_result(1)

    def is_connected_and_ready(self) -> bool:
        return self.ready.done() and not self.got_disconnected.is_set()

    async def _save_certificate(self) -> None:
        if not os.path.exists(self.cert_path):
            # we may need to retry this a few times, in case the handshake hasn't completed
            for _ in range(10):
                dercert = await self._fetch_certificate()
                if dercert:
                    self.logger.info("succeeded in getting cert")
                    self._verify_certificate_fingerprint(dercert)
                    with open(self.cert_path, 'w') as f:
                        cert = ssl.DER_cert_to_PEM_cert(dercert)
                        # workaround android bug
                        cert = re.sub("([^\n])-----END CERTIFICATE-----","\\1\n-----END CERTIFICATE-----",cert)
                        f.write(cert)
                        # even though close flushes, we can't fsync when closed.
                        # and we must flush before fsyncing, cause flush flushes to OS buffer
                        # fsync writes to OS buffer to disk
                        f.flush()
                        os.fsync(f.fileno())
                    break
                await asyncio.sleep(1)
            else:
                raise GracefulDisconnect("could not get certificate after 10 tries")

    async def _fetch_certificate(self) -> bytes:
        sslc = ssl.SSLContext(protocol=ssl.PROTOCOL_TLS_CLIENT)
        sslc.check_hostname = False
        sslc.verify_mode = ssl.CERT_NONE
        async with _RSClient(session_factory=RPCSession,
                             host=self.host, port=self.port,
                             ssl=sslc, proxy=self.proxy) as session:
            asyncio_transport = session.transport._asyncio_transport  # type: asyncio.BaseTransport
            ssl_object = asyncio_transport.get_extra_info("ssl_object")  # type: ssl.SSLObject
            return ssl_object.getpeercert(binary_form=True)

    def _get_expected_fingerprint(self) -> Optional[str]:
        if self.is_main_server():
            return self.network.config.NETWORK_SERVERFINGERPRINT

    def _verify_certificate_fingerprint(self, certificate):
        expected_fingerprint = self._get_expected_fingerprint()
        if not expected_fingerprint:
            return
        fingerprint = hashlib.sha256(certificate).hexdigest()
        fingerprints_match = fingerprint.lower() == expected_fingerprint.lower()
        if not fingerprints_match:
            util.trigger_callback('cert_mismatch')
            raise ErrorSSLCertFingerprintMismatch('Refusing to connect to server due to cert fingerprint mismatch')
        self.logger.info("cert fingerprint verification passed")

    async def get_block_header(self, height, assert_mode):
        if not is_non_negative_integer(height):
            raise Exception(f"{repr(height)} is not a block height")
        self.logger.info(f'requesting block header {height} in mode {assert_mode}')
        # use lower timeout as we usually have network.bhi_lock here
        timeout = self.network.get_network_timeout_seconds(NetworkTimeout.Urgent)
        res = await self.session.send_request('blockchain.block.header', [height], timeout=timeout)
        return blockchain.deserialize_header(bytes.fromhex(res), height)

    async def request_chunk(self, height: int, tip=None, *, can_return_early=False):
        if not is_non_negative_integer(height):
            raise Exception(f"{repr(height)} is not a block height")
        index = height // 2016
        if can_return_early and index in self._requested_chunks:
            return
        self.logger.info(f"requesting chunk from height {height}")
        size = 2016
        if tip is not None:
            size = min(size, tip - index * 2016 + 1)
            size = max(size, 0)
        try:
            self._requested_chunks.add(index)
            res = await self.session.send_request('blockchain.block.headers', [index * 2016, size])
        finally:
            self._requested_chunks.discard(index)
        assert_dict_contains_field(res, field_name='count')
        assert_dict_contains_field(res, field_name='hex')
        assert_dict_contains_field(res, field_name='max')
        assert_non_negative_integer(res['count'])
        assert_non_negative_integer(res['max'])
        assert_hex_str(res['hex'])
        if len(res['hex']) != HEADER_SIZE * 2 * res['count']:
            raise RequestCorrupted('inconsistent chunk hex and count')
        # we never request more than 2016 headers, but we enforce those fit in a single response
        if res['max'] < 2016:
            raise RequestCorrupted(f"server uses too low 'max' count for block.headers: {res['max']} < 2016")
        if res['count'] != size:
            raise RequestCorrupted(f"expected {size} headers but only got {res['count']}")
        conn = self.blockchain.connect_chunk(index, res['hex'])
        if not conn:
            return conn, 0
        return conn, res['count']

    def is_main_server(self) -> bool:
        return (self.network.interface == self or
                self.network.interface is None and self.network.default_server == self.server)

    async def open_session(self, sslc, exit_early=False):
        session_factory = lambda *args, iface=self, **kwargs: NotificationSession(*args, **kwargs, interface=iface)
        async with _RSClient(session_factory=session_factory,
                             host=self.host, port=self.port,
                             ssl=sslc, proxy=self.proxy) as session:
            self.session = session  # type: NotificationSession
            self.session.set_default_timeout(self.network.get_network_timeout_seconds(NetworkTimeout.Generic))
            try:
                ver = await session.send_request('server.version', [self.client_name(), version.PROTOCOL_VERSION])
            except aiorpcx.jsonrpc.RPCError as e:
                raise GracefulDisconnect(e)  # probably 'unsupported protocol version'
            if exit_early:
                return
            if ver[1] != version.PROTOCOL_VERSION:
                raise GracefulDisconnect(f'server violated protocol-version-negotiation. '
                                         f'we asked for {version.PROTOCOL_VERSION!r}, they sent {ver[1]!r}')
            if not self.network.check_interface_against_healthy_spread_of_connected_servers(self):
                raise GracefulDisconnect(f'too many connected servers already '
                                         f'in bucket {self.bucket_based_on_ipaddress()}')
            self.logger.info(f"connection established. version: {ver}")

            try:
                async with self.taskgroup as group:
                    await group.spawn(self.ping)
                    await group.spawn(self.request_fee_estimates)
                    await group.spawn(self.run_fetch_blocks)
                    await group.spawn(self.monitor_connection)
            except aiorpcx.jsonrpc.RPCError as e:
                if e.code in (
                    JSONRPC.EXCESSIVE_RESOURCE_USAGE,
                    JSONRPC.SERVER_BUSY,
                    JSONRPC.METHOD_NOT_FOUND,
                    JSONRPC.INTERNAL_ERROR,
                ):
                    log_level = logging.WARNING if self.is_main_server() else logging.INFO
                    raise GracefulDisconnect(e, log_level=log_level) from e
                raise
            finally:
                self.got_disconnected.set()  # set this ASAP, ideally before any awaits

    async def monitor_connection(self):
        while True:
            await asyncio.sleep(1)
            # If the session/transport is no longer open, we disconnect.
            # e.g. if the remote cleanly sends EOF, we would handle that here.
            # note: If the user pulls the ethernet cable or disconnects wifi,
            #       ideally we would detect that here, so that the GUI/etc can reflect that.
            #       - On Android, this seems to work reliably , where asyncio.BaseProtocol.connection_lost()
            #         gets called with e.g. ConnectionAbortedError(103, 'Software caused connection abort').
            #       - On desktop Linux/Win, it seems BaseProtocol.connection_lost() is not called in such cases.
            #         Hence, in practice the connection issue will only be detected the next time we try
            #         to send a message (plus timeout), which can take minutes...
            if not self.session or self.session.is_closing():
                raise GracefulDisconnect('session was closed')

    async def ping(self):
        while True:
            await asyncio.sleep(300)
            await self.session.send_request('server.ping')

    async def request_fee_estimates(self):
        from .simple_config import FEE_ETA_TARGETS
        while True:
            async with OldTaskGroup() as group:
                fee_tasks = []
                for i in FEE_ETA_TARGETS:
                    fee_tasks.append((i, await group.spawn(self.get_estimatefee(i))))
            for nblock_target, task in fee_tasks:
                fee = task.result()
                if fee < 0: continue
                assert isinstance(fee, int)
                self.fee_estimates_eta[nblock_target] = fee
            self.network.update_fee_estimates()
            await asyncio.sleep(60)

    async def close(self, *, force_after: int = None):
        """Closes the connection and waits for it to be closed.
        We try to flush buffered data to the wire, which can take some time.
        """
        if self.session:
            await self.session.close(force_after=force_after)
        # monitor_connection will cancel tasks

    async def run_fetch_blocks(self):
        header_queue = asyncio.Queue()
        await self.session.subscribe('blockchain.headers.subscribe', [], header_queue)
        while True:
            item = await header_queue.get()
            raw_header = item[0]
            height = raw_header['height']
            header = blockchain.deserialize_header(bfh(raw_header['hex']), height)
            self.tip_header = header
            self.tip = height
            if self.tip < constants.net.max_checkpoint():
                raise GracefulDisconnect('server tip below max checkpoint')
            self._mark_ready()
            blockchain_updated = await self._process_header_at_tip()
            # header processing done
            if blockchain_updated:
                util.trigger_callback('blockchain_updated')
            util.trigger_callback('network_updated')
            await self.network.switch_unwanted_fork_interface()
            await self.network.switch_lagging_interface()

    async def _process_header_at_tip(self) -> bool:
        """Returns:
        False - boring fast-forward: we already have this header as part of this blockchain from another interface,
        True - new header we didn't have, or reorg
        """
        height, header = self.tip, self.tip_header
        async with self.network.bhi_lock:
            if self.blockchain.height() >= height and self.blockchain.check_header(header):
                # another interface amended the blockchain
                self.logger.info(f"skipping header {height}")
                return False
            _, height = await self.step(height, header)
            # in the simple case, height == self.tip+1
            if height <= self.tip:
                await self.sync_until(height)
            return True

    async def sync_until(self, height, next_height=None):
        if next_height is None:
            next_height = self.tip
        last = None
        while last is None or height <= next_height:
            prev_last, prev_height = last, height
            if next_height > height + 10:
                could_connect, num_headers = await self.request_chunk(height, next_height)
                if not could_connect:
                    if height <= constants.net.max_checkpoint():
                        raise GracefulDisconnect('server chain conflicts with checkpoints or genesis')
                    last, height = await self.step(height)
                    continue
                util.trigger_callback('blockchain_updated')
                util.trigger_callback('network_updated')
                height = (height // 2016 * 2016) + num_headers
                assert height <= next_height+1, (height, self.tip)
                last = 'catchup'
            else:
                last, height = await self.step(height)
            assert (prev_last, prev_height) != (last, height), 'had to prevent infinite loop in interface.sync_until'
        return last, height

    async def step(self, height, header=None):
        assert 0 <= height <= self.tip, (height, self.tip)
        if header is None:
            header = await self.get_block_header(height, 'catchup')

        chain = blockchain.check_header(header) if 'mock' not in header else header['mock']['check'](header)
        if chain:
            self.blockchain = chain if isinstance(chain, Blockchain) else self.blockchain
            # note: there is an edge case here that is not handled.
            # we might know the blockhash (enough for check_header) but
            # not have the header itself. e.g. regtest chain with only genesis.
            # this situation resolves itself on the next block
            return 'catchup', height+1

        can_connect = blockchain.can_connect(header) if 'mock' not in header else header['mock']['connect'](height)
        if not can_connect:
            self.logger.info(f"can't connect {height}")
            height, header, bad, bad_header = await self._search_headers_backwards(height, header)
            chain = blockchain.check_header(header) if 'mock' not in header else header['mock']['check'](header)
            can_connect = blockchain.can_connect(header) if 'mock' not in header else header['mock']['connect'](height)
            assert chain or can_connect
        if can_connect:
            self.logger.info(f"could connect {height}")
            height += 1
            if isinstance(can_connect, Blockchain):  # not when mocking
                self.blockchain = can_connect
                self.blockchain.save_header(header)
            return 'catchup', height

        good, bad, bad_header = await self._search_headers_binary(height, bad, bad_header, chain)
        return await self._resolve_potential_chain_fork_given_forkpoint(good, bad, bad_header)

    async def _search_headers_binary(self, height, bad, bad_header, chain):
        assert bad == bad_header['block_height']
        _assert_header_does_not_check_against_any_chain(bad_header)

        self.blockchain = chain if isinstance(chain, Blockchain) else self.blockchain
        good = height
        while True:
            assert good < bad, (good, bad)
            height = (good + bad) // 2
            self.logger.info(f"binary step. good {good}, bad {bad}, height {height}")
            header = await self.get_block_header(height, 'binary')
            chain = blockchain.check_header(header) if 'mock' not in header else header['mock']['check'](header)
            if chain:
                self.blockchain = chain if isinstance(chain, Blockchain) else self.blockchain
                good = height
            else:
                bad = height
                bad_header = header
            if good + 1 == bad:
                break

        mock = 'mock' in bad_header and bad_header['mock']['connect'](height)
        real = not mock and self.blockchain.can_connect(bad_header, check_height=False)
        if not real and not mock:
            raise Exception('unexpected bad header during binary: {}'.format(bad_header))
        _assert_header_does_not_check_against_any_chain(bad_header)

        self.logger.info(f"binary search exited. good {good}, bad {bad}")
        return good, bad, bad_header

    async def _resolve_potential_chain_fork_given_forkpoint(self, good, bad, bad_header):
        assert good + 1 == bad
        assert bad == bad_header['block_height']
        _assert_header_does_not_check_against_any_chain(bad_header)
        # 'good' is the height of a block 'good_header', somewhere in self.blockchain.
        # bad_header connects to good_header; bad_header itself is NOT in self.blockchain.

        bh = self.blockchain.height()
        assert bh >= good, (bh, good)
        if bh == good:
            height = good + 1
            self.logger.info(f"catching up from {height}")
            return 'no_fork', height

        # this is a new fork we don't yet have
        height = bad + 1
        self.logger.info(f"new fork at bad height {bad}")
        forkfun = self.blockchain.fork if 'mock' not in bad_header else bad_header['mock']['fork']
        b = forkfun(bad_header)  # type: Blockchain
        self.blockchain = b
        assert b.forkpoint == bad
        return 'fork', height

    async def _search_headers_backwards(self, height, header):
        async def iterate():
            nonlocal height, header
            checkp = False
            if height <= constants.net.max_checkpoint():
                height = constants.net.max_checkpoint()
                checkp = True
            header = await self.get_block_header(height, 'backward')
            chain = blockchain.check_header(header) if 'mock' not in header else header['mock']['check'](header)
            can_connect = blockchain.can_connect(header) if 'mock' not in header else header['mock']['connect'](height)
            if chain or can_connect:
                return False
            if checkp:
                raise GracefulDisconnect("server chain conflicts with checkpoints")
            return True

        bad, bad_header = height, header
        _assert_header_does_not_check_against_any_chain(bad_header)
        with blockchain.blockchains_lock: chains = list(blockchain.blockchains.values())
        local_max = max([0] + [x.height() for x in chains]) if 'mock' not in header else float('inf')
        height = min(local_max + 1, height - 1)
        while await iterate():
            bad, bad_header = height, header
            delta = self.tip - height
            height = self.tip - 2 * delta

        _assert_header_does_not_check_against_any_chain(bad_header)
        self.logger.info(f"exiting backward mode at {height}")
        return height, header, bad, bad_header

    @classmethod
    def client_name(cls) -> str:
        return f'electrum/{version.ELECTRUM_VERSION}'

    def is_tor(self):
        return self.host.endswith('.onion')

    def ip_addr(self) -> Optional[str]:
        session = self.session
        if not session: return None
        peer_addr = session.remote_address()
        if not peer_addr: return None
        return str(peer_addr.host)

    def bucket_based_on_ipaddress(self) -> str:
        def do_bucket():
            if self.is_tor():
                return BUCKET_NAME_OF_ONION_SERVERS
            try:
                ip_addr = ip_address(self.ip_addr())  # type: Union[IPv4Address, IPv6Address]
            except ValueError:
                return ''
            if not ip_addr:
                return ''
            if ip_addr.is_loopback:  # localhost is exempt
                return ''
            if ip_addr.version == 4:
                slash16 = IPv4Network(ip_addr).supernet(prefixlen_diff=32-16)
                return str(slash16)
            elif ip_addr.version == 6:
                slash48 = IPv6Network(ip_addr).supernet(prefixlen_diff=128-48)
                return str(slash48)
            return ''

        if not self._ipaddr_bucket:
            self._ipaddr_bucket = do_bucket()
        return self._ipaddr_bucket

    async def get_merkle_for_transaction(self, tx_hash: str, tx_height: int) -> dict:
        if not is_hash256_str(tx_hash):
            raise Exception(f"{repr(tx_hash)} is not a txid")
        if not is_non_negative_integer(tx_height):
            raise Exception(f"{repr(tx_height)} is not a block height")
        # do request
        res = await self.session.send_request('blockchain.transaction.get_merkle', [tx_hash, tx_height])
        # check response
        block_height = assert_dict_contains_field(res, field_name='block_height')
        merkle = assert_dict_contains_field(res, field_name='merkle')
        pos = assert_dict_contains_field(res, field_name='pos')
        # note: tx_height was just a hint to the server, don't enforce the response to match it
        assert_non_negative_integer(block_height)
        assert_non_negative_integer(pos)
        assert_list_or_tuple(merkle)
        for item in merkle:
            assert_hash256_str(item)
        return res

    async def get_transaction(self, tx_hash: str, *, timeout=None) -> str:
        if not is_hash256_str(tx_hash):
            raise Exception(f"{repr(tx_hash)} is not a txid")
        raw = await self.session.send_request('blockchain.transaction.get', [tx_hash], timeout=timeout)
        # validate response
        if not is_hex_str(raw):
            raise RequestCorrupted(f"received garbage (non-hex) as tx data (txid {tx_hash}): {raw!r}")
        tx = Transaction(raw)
        try:
            tx.deserialize()  # see if raises
        except Exception as e:
            raise RequestCorrupted(f"cannot deserialize received transaction (txid {tx_hash})") from e
        if tx.txid() != tx_hash:
            raise RequestCorrupted(f"received tx does not match expected txid {tx_hash} (got {tx.txid()})")
        return raw

    async def get_history_for_scripthash(self, sh: str) -> List[dict]:
        if not is_hash256_str(sh):
            raise Exception(f"{repr(sh)} is not a scripthash")
        # do request
        res = await self.session.send_request('blockchain.scripthash.get_history', [sh])
        # check response
        assert_list_or_tuple(res)
        prev_height = 1
        for tx_item in res:
            height = assert_dict_contains_field(tx_item, field_name='height')
            assert_dict_contains_field(tx_item, field_name='tx_hash')
            assert_integer(height)
            assert_hash256_str(tx_item['tx_hash'])
            if height in (-1, 0):
                assert_dict_contains_field(tx_item, field_name='fee')
                assert_non_negative_integer(tx_item['fee'])
                prev_height = float("inf")  # this ensures confirmed txs can't follow mempool txs
            else:
                # check monotonicity of heights
                if height < prev_height:
                    raise RequestCorrupted(f'heights of confirmed txs must be in increasing order')
                prev_height = height
        hashes = set(map(lambda item: item['tx_hash'], res))
        if len(hashes) != len(res):
            # Either server is sending garbage... or maybe if server is race-prone
            # a recently mined tx could be included in both last block and mempool?
            # Still, it's simplest to just disregard the response.
            raise RequestCorrupted(f"server history has non-unique txids for sh={sh}")
        return res

    async def listunspent_for_scripthash(self, sh: str) -> List[dict]:
        if not is_hash256_str(sh):
            raise Exception(f"{repr(sh)} is not a scripthash")
        # do request
        res = await self.session.send_request('blockchain.scripthash.listunspent', [sh])
        # check response
        assert_list_or_tuple(res)
        for utxo_item in res:
            assert_dict_contains_field(utxo_item, field_name='tx_pos')
            assert_dict_contains_field(utxo_item, field_name='value')
            assert_dict_contains_field(utxo_item, field_name='tx_hash')
            assert_dict_contains_field(utxo_item, field_name='height')
            assert_non_negative_integer(utxo_item['tx_pos'])
            assert_non_negative_integer(utxo_item['value'])
            assert_non_negative_integer(utxo_item['height'])
            assert_hash256_str(utxo_item['tx_hash'])
        return res

    async def get_balance_for_scripthash(self, sh: str) -> dict:
        if not is_hash256_str(sh):
            raise Exception(f"{repr(sh)} is not a scripthash")
        # do request
        res = await self.session.send_request('blockchain.scripthash.get_balance', [sh])
        # check response
        assert_dict_contains_field(res, field_name='confirmed')
        assert_dict_contains_field(res, field_name='unconfirmed')
        assert_non_negative_integer(res['confirmed'])
        assert_integer(res['unconfirmed'])
        return res

    async def get_txid_from_txpos(self, tx_height: int, tx_pos: int, merkle: bool):
        if not is_non_negative_integer(tx_height):
            raise Exception(f"{repr(tx_height)} is not a block height")
        if not is_non_negative_integer(tx_pos):
            raise Exception(f"{repr(tx_pos)} should be non-negative integer")
        # do request
        res = await self.session.send_request(
            'blockchain.transaction.id_from_pos',
            [tx_height, tx_pos, merkle],
        )
        # check response
        if merkle:
            assert_dict_contains_field(res, field_name='tx_hash')
            assert_dict_contains_field(res, field_name='merkle')
            assert_hash256_str(res['tx_hash'])
            assert_list_or_tuple(res['merkle'])
            for node_hash in res['merkle']:
                assert_hash256_str(node_hash)
        else:
            assert_hash256_str(res)
        return res

    async def get_fee_histogram(self) -> Sequence[Tuple[Union[float, int], int]]:
        # do request
        res = await self.session.send_request('mempool.get_fee_histogram')
        # check response
        assert_list_or_tuple(res)
        prev_fee = float('inf')
        for fee, s in res:
            assert_non_negative_int_or_float(fee)
            assert_non_negative_integer(s)
            if fee >= prev_fee:  # check monotonicity
                raise RequestCorrupted(f'fees must be in decreasing order')
            prev_fee = fee
        return res

    async def get_server_banner(self) -> str:
        # do request
        res = await self.session.send_request('server.banner')
        # check response
        if not isinstance(res, str):
            raise RequestCorrupted(f'{res!r} should be a str')
        return res

    async def get_donation_address(self) -> str:
        # do request
        res = await self.session.send_request('server.donation_address')
        # check response
        if not res:  # ignore empty string
            return ''
        if not bitcoin.is_address(res):
            # note: do not hard-fail -- allow server to use future-type
            #       bitcoin address we do not recognize
            self.logger.info(f"invalid donation address from server: {repr(res)}")
            res = ''
        return res

    async def get_relay_fee(self) -> int:
        """Returns the min relay feerate in sat/kbyte."""
        # do request
        res = await self.session.send_request('blockchain.relayfee')
        # check response
        assert_non_negative_int_or_float(res)
        relayfee = int(res * bitcoin.COIN)
        relayfee = max(0, relayfee)
        return relayfee

    async def get_estimatefee(self, num_blocks: int) -> int:
        """Returns a feerate estimate for getting confirmed within
        num_blocks blocks, in sat/kbyte.
        Returns -1 if the server could not provide an estimate.
        """
        if not is_non_negative_integer(num_blocks):
            raise Exception(f"{repr(num_blocks)} is not a num_blocks")
        # do request
        try:
            res = await self.session.send_request('blockchain.estimatefee', [num_blocks])
        except aiorpcx.jsonrpc.ProtocolError as e:
            # The protocol spec says the server itself should already have returned -1
            # if it cannot provide an estimate, however apparently "electrs" does not conform
            # and sends an error instead. Convert it here:
            if "cannot estimate fee" in e.message:
                res = -1
            else:
                raise
        except aiorpcx.jsonrpc.RPCError as e:
            # The protocol spec says the server itself should already have returned -1
            # if it cannot provide an estimate. "Fulcrum" often sends:
            #   aiorpcx.jsonrpc.RPCError: (-32603, 'internal error: bitcoind request timed out')
            if e.code == JSONRPC.INTERNAL_ERROR:
                res = -1
            else:
                raise
        # check response
        if res != -1:
            assert_non_negative_int_or_float(res)
            res = int(res * bitcoin.COIN)
        return res


def _assert_header_does_not_check_against_any_chain(header: dict) -> None:
    chain_bad = blockchain.check_header(header) if 'mock' not in header else header['mock']['check'](header)
    if chain_bad:
        raise Exception('bad_header must not check!')


def check_cert(host, cert):
    try:
        b = pem.dePem(cert, 'CERTIFICATE')
        x = x509.X509(b)
    except Exception:
        traceback.print_exc(file=sys.stdout)
        return

    try:
        x.check_date()
        expired = False
    except Exception:
        expired = True

    m = "host: %s\n"%host
    m += "has_expired: %s\n"% expired
    util.print_msg(m)


# Used by tests
def _match_hostname(name, val):
    if val == name:
        return True

    return val.startswith('*.') and name.endswith(val[1:])


def test_certificates():
    from .simple_config import SimpleConfig
    config = SimpleConfig()
    mydir = os.path.join(config.path, "certs")
    certs = os.listdir(mydir)
    for c in certs:
        p = os.path.join(mydir,c)
        with open(p, encoding='utf-8') as f:
            cert = f.read()
        check_cert(c, cert)

if __name__ == "__main__":
    test_certificates()
