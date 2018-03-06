import traceback
import ssl
from asyncio.sslproto import SSLProtocol
import aiosocks
import asyncio
from . import interface

class AppProto(asyncio.Protocol):
    def __init__(self, receivedQueue, connUpLock):
        self.buf = bytearray()
        self.receivedQueue = receivedQueue
        self.connUpLock = connUpLock
    def connection_made(self, transport):
        self.connUpLock.release()
    def data_received(self, data):
        self.buf.extend(data)
        NEWLINE = b"\n"[0]
        for idx, val in enumerate(self.buf):
            if NEWLINE == val:
                asyncio.ensure_future(self.receivedQueue.put(bytes(self.buf[:idx+1])))
                self.buf = self.buf[idx+1:]

def makeProtocolFactory(receivedQueue, connUpLock, ca_certs):
    class MySSLProtocol(SSLProtocol):
        def __init__(self):
            context = interface.get_ssl_context(\
                    cert_reqs=ssl.CERT_REQUIRED if ca_certs is not None else ssl.CERT_NONE,\
                    ca_certs=ca_certs)
            proto = AppProto(receivedQueue, connUpLock)
            super().__init__(asyncio.get_event_loop(), proto, context, None)
    return MySSLProtocol

class ReaderEmulator:
    def __init__(self, receivedQueue):
        self.receivedQueue = receivedQueue
    async def read(self, _bufferSize):
        return await self.receivedQueue.get()

class WriterEmulator:
    def __init__(self, transport):
        self.transport = transport
    def write(self, data):
        self.transport.write(data)
    async def drain(self):
        pass
    def close(self):
        self.transport.close()

async def sslInSocksReaderWriter(socksAddr, socksAuth, host, port, ca_certs):
    receivedQueue = asyncio.Queue()
    connUpLock = asyncio.Lock()
    await connUpLock.acquire()
    transport, protocol = await aiosocks.create_connection(\
            makeProtocolFactory(receivedQueue, connUpLock, ca_certs),\
            proxy=socksAddr,\
            proxy_auth=socksAuth, dst=(host, port))
    await connUpLock.acquire()
    return ReaderEmulator(receivedQueue), WriterEmulator(protocol._app_transport)

if __name__ == "__main__":
    async def l(fut):
        try:
            # aiosocks.Socks4Addr("127.0.0.1", 9050), None, "songbird.bauerj.eu", 50002, None)
            args = aiosocks.Socks4Addr("127.0.0.1", 9050), None, "electrum.akinbo.org", 51002, None
            reader, writer = await sslInSocksReaderWriter(*args)
            writer.write(b'{"id":0,"method":"server.version","args":["3.0.2", "1.1"]}\n')
            await writer.drain()
            print(await reader.read(4096))
            writer.write(b'{"id":0,"method":"server.version","args":["3.0.2", "1.1"]}\n')
            await writer.drain()
            print(await reader.read(4096))
            writer.close()
            fut.set_result("finished")
        except BaseException as e:
            fut.set_exception(e)

    def f():
        loop = asyncio.get_event_loop()
        fut = asyncio.Future()
        asyncio.ensure_future(l(fut))
        loop.run_until_complete(fut)
        print(fut.result())
        loop.close()

    f()
