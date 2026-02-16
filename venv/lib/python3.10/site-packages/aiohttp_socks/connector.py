import asyncio
import socket
from ssl import SSLContext
from typing import Any, Iterable, NamedTuple, Optional, List, Tuple

from aiohttp import ClientConnectorError, TCPConnector
from aiohttp.abc import AbstractResolver, ResolveResult
from aiohttp.client_proto import ResponseHandler

import python_socks
from python_socks import ProxyType, parse_proxy_url
from python_socks.async_.asyncio.v2 import Proxy

from ._errors import ProxyConnectionError, ProxyTimeoutError, ProxyError


class NoResolver(AbstractResolver):
    async def resolve(
        self,
        host: str,
        port: int = 0,
        family: socket.AddressFamily = socket.AF_INET,  # pylint: disable=no-member
    ) -> List[ResolveResult]:
        return [
            {
                'hostname': host,
                'host': host,
                'port': port,
                'family': family,
                'proto': 0,
                'flags': 0,
            }
        ]

    async def close(self):
        pass  # pragma: no cover


class _ResponseHandler(ResponseHandler):
    """
    To fix issue https://github.com/romis2012/aiohttp-socks/issues/27
    In Python>=3.11.5 we need to keep a reference to the StreamWriter
    so that the underlying transport is not closed during garbage collection.
    See StreamWriter.__del__ method (was added in Python 3.11.5)
    """

    def __init__(
        self, loop: asyncio.AbstractEventLoop, writer: asyncio.StreamWriter
    ) -> None:
        super().__init__(loop)
        self._writer = writer


class _BaseProxyConnector(TCPConnector):
    async def _wrap_create_connection(
        self,
        *args,
        addr_infos,
        req,
        timeout,
        client_error=ClientConnectorError,
        **kwargs,
    ) -> Tuple[asyncio.Transport, ResponseHandler]:
        try:
            host: str = addr_infos[0][4][0]
            port: int = addr_infos[0][4][1]
        except IndexError as e:  # pragma: no cover
            raise ValueError('Invalid arg: `addr_infos`') from e

        ssl: Optional[SSLContext] = kwargs.get('ssl')  # type: ignore
        try:
            return await self._connect_via_proxy(
                host=host,
                port=port,
                ssl=ssl,
                timeout=timeout.sock_connect,
            )
        except python_socks.ProxyConnectionError as e:
            raise ProxyConnectionError(str(e)) from e
        except python_socks.ProxyTimeoutError as e:
            raise ProxyTimeoutError(str(e)) from e
        except python_socks.ProxyError as e:
            raise ProxyError(str(e), error_code=e.error_code) from e

    async def _connect_via_proxy(
        self,
        host: str,
        port: int,
        ssl: Optional[SSLContext] = None,
        timeout: Optional[float] = None,
    ) -> Tuple[asyncio.Transport, ResponseHandler]:
        raise NotImplementedError


class ProxyConnector(_BaseProxyConnector):
    def __init__(
        self,
        host: str,
        port: int,
        proxy_type: ProxyType = ProxyType.SOCKS5,
        username: Optional[str] = None,
        password: Optional[str] = None,
        rdns: Optional[bool] = None,
        proxy_ssl: Optional[SSLContext] = None,
        **kwargs: Any,
    ) -> None:
        kwargs['resolver'] = NoResolver()
        super().__init__(**kwargs)

        self._proxy_type = proxy_type
        self._proxy_host = host
        self._proxy_port = port
        self._proxy_username = username
        self._proxy_password = password
        self._rdns = rdns
        self._proxy_ssl = proxy_ssl

    async def _connect_via_proxy(
        self,
        host: str,
        port: int,
        ssl: Optional[SSLContext] = None,
        timeout: Optional[float] = None,
    ) -> Tuple[asyncio.Transport, ResponseHandler]:
        proxy = Proxy(
            proxy_type=self._proxy_type,
            host=self._proxy_host,
            port=self._proxy_port,
            username=self._proxy_username,
            password=self._proxy_password,
            rdns=self._rdns,
            proxy_ssl=self._proxy_ssl,
        )

        stream = await proxy.connect(
            dest_host=host,
            dest_port=port,
            dest_ssl=ssl,
            timeout=timeout,
        )

        transport: asyncio.Transport = stream.writer.transport
        protocol: ResponseHandler = _ResponseHandler(
            loop=self._loop,
            writer=stream.writer,
        )

        transport.set_protocol(protocol)
        protocol.connection_made(transport)

        return transport, protocol

    @classmethod
    def from_url(cls, url: str, **kwargs: Any) -> 'ProxyConnector':
        proxy_type, host, port, username, password = parse_proxy_url(url)
        return cls(
            proxy_type=proxy_type,
            host=host,
            port=port,
            username=username,
            password=password,
            **kwargs,
        )


class ProxyInfo(NamedTuple):
    proxy_type: ProxyType
    host: str
    port: int
    username: Optional[str] = None
    password: Optional[str] = None
    rdns: Optional[bool] = None


class ChainProxyConnector(_BaseProxyConnector):
    def __init__(self, proxy_infos: Iterable[ProxyInfo], **kwargs):
        kwargs['resolver'] = NoResolver()
        super().__init__(**kwargs)

        self._proxy_infos = proxy_infos

    async def _connect_via_proxy(
        self,
        host: str,
        port: int,
        ssl: Optional[SSLContext] = None,
        timeout: Optional[float] = None,
    ) -> Tuple[asyncio.Transport, ResponseHandler]:
        forward = None
        proxy = None
        for info in self._proxy_infos:
            proxy = Proxy(
                proxy_type=info.proxy_type,
                host=info.host,
                port=info.port,
                username=info.username,
                password=info.password,
                rdns=info.rdns,
                forward=forward,
            )
            forward = proxy

        assert proxy is not None

        stream = await proxy.connect(
            dest_host=host,
            dest_port=port,
            dest_ssl=ssl,
            timeout=timeout,
        )

        transport: asyncio.Transport = stream.writer.transport
        protocol: ResponseHandler = _ResponseHandler(
            loop=self._loop,
            writer=stream.writer,
        )

        transport.set_protocol(protocol)
        protocol.connection_made(transport)

        return transport, protocol

    @classmethod
    def from_urls(cls, urls: Iterable[str], **kwargs: Any) -> 'ChainProxyConnector':
        infos = []
        for url in urls:
            proxy_type, host, port, username, password = parse_proxy_url(url)
            proxy_info = ProxyInfo(
                proxy_type=proxy_type,
                host=host,
                port=port,
                username=username,
                password=password,
            )
            infos.append(proxy_info)

        return cls(infos, **kwargs)
