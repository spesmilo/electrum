"""
iroh_transport.py — Iroh P2P transport for Electrum
"""
import asyncio
import logging
import os
from pathlib import Path
from typing import Optional
import iroh

_logger = logging.getLogger(__name__)
ALPN = b"electrs/electrum/0"
_iroh_node = None
_endpoint = None
_endpoint_lock = asyncio.Lock()

def _load_or_create_secret_key():
    key_path = Path.home() / ".electrum" / "iroh_secret_key.bin"
    key_path.parent.mkdir(parents=True, exist_ok=True)
    if key_path.exists():
        key_bytes = key_path.read_bytes()
        if len(key_bytes) == 32:
            return key_bytes
    key_bytes = os.urandom(32)
    key_path.write_bytes(key_bytes)
    _logger.info(f"New Iroh secret key saved to {key_path}")
    return key_bytes

async def get_shared_endpoint():
    global _iroh_node, _endpoint
    async with _endpoint_lock:
        if _endpoint is None:
            iroh.iroh_ffi.uniffi_set_event_loop(asyncio.get_event_loop())
            secret_key = _load_or_create_secret_key()
            options = iroh.NodeOptions(secret_key=secret_key)
            _iroh_node = await iroh.Iroh.memory_with_options(options)
            _endpoint = _iroh_node.node().endpoint()
            _logger.info(f"Iroh endpoint ready. Node ID: {_endpoint.node_id()}")
            await asyncio.sleep(3)
        return _endpoint

class IrohTransport(asyncio.Transport):
    def __init__(self, send_stream, recv_stream, node_id, loop):
        super().__init__()
        self._send = send_stream
        self._recv = recv_stream
        self._node_id = node_id
        self._loop = loop
        self._closing = False
        self._protocol = None
        self._reader_task = None
        self._write_lock = asyncio.Lock()

    def set_protocol(self, protocol):
        self._protocol = protocol

    def get_protocol(self):
        return self._protocol

    def start_reader(self):
        self._reader_task = self._loop.create_task(
            self._reader_loop(), name=f"iroh-reader-{self._node_id[:12]}"
        )

    async def _reader_loop(self):
        try:
            while not self._closing:
                data = await self._recv.read(65536)
                if not data:
                    break
                if self._protocol is not None:
                    self._protocol.data_received(data)
        except asyncio.CancelledError:
            pass
        except Exception as e:
            if not self._closing:
                _logger.warning(f"Iroh reader error ({self._node_id[:12]}): {e}")
        finally:
            if not self._closing:
                self._closing = True
                if self._protocol is not None:
                    self._protocol.connection_lost(None)

    def write(self, data):
        if self._closing:
            return
        self._loop.create_task(self._write_async(data))

    async def _write_async(self, data):
        async with self._write_lock:
            try:
                await self._send.write_all(data)
            except Exception as e:
                if not self._closing:
                    _logger.warning(f"Iroh write error: {e}")
                    self.close()

    def close(self):
        if self._closing:
            return
        self._closing = True
        if self._reader_task and not self._reader_task.done():
            self._reader_task.cancel()
        self._loop.create_task(self._close_streams())

    async def _close_streams(self):
        try:
            await self._send.finish()
        except Exception:
            pass

    def is_closing(self):
        return self._closing

    def get_extra_info(self, name, default=None):
        if name == 'peername':
            return (self._node_id, 0)
        if name == 'sockname':
            return ('iroh-local', 0)
        return default

async def open_iroh_connection(node_id_str):
    _logger.info(f"Iroh: connecting to {node_id_str[:12]}...")
    endpoint = await get_shared_endpoint()
    try:
        public_key = iroh.PublicKey.from_string(node_id_str)
    except Exception as e:
        raise Exception(f"Invalid Iroh Node ID '{node_id_str}': {e}") from e
    node_addr = iroh.NodeAddr(node_id=public_key, derp_url="https://use1-1.relay.iroh.network./", addresses=[])
    conn = await endpoint.connect(node_addr, alpn=ALPN)
    bistream = await conn.open_bi()
    loop = asyncio.get_event_loop()
    transport = IrohTransport(
        send_stream=bistream.send(),
        recv_stream=bistream.recv(),
        node_id=node_id_str,
        loop=loop,
    )
    _logger.info(f"Iroh: connected to {node_id_str[:12]}")
    return transport
