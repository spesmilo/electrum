import asyncio

from electrum import util
from electrum.ecc import ECPrivkey
from electrum.lnutil import LNPeerAddr
from electrum.lntransport import LNResponderTransport, LNTransport
from electrum.util import OldTaskGroup

from . import ElectrumTestCase
from .test_bitcoin import needs_test_with_all_chacha20_implementations


class TestLNTransport(ElectrumTestCase):

    @needs_test_with_all_chacha20_implementations
    async def test_responder(self):
        # local static
        ls_priv=bytes.fromhex('2121212121212121212121212121212121212121212121212121212121212121')
        # ephemeral
        e_priv=bytes.fromhex('2222222222222222222222222222222222222222222222222222222222222222')

        class Writer:
            def __init__(self):
                self.state = 0
            def write(self, data):
                assert self.state == 0
                self.state += 1
                assert len(data) == 50
        class Reader:
            def __init__(self):
                self.state = 0
            async def read(self, num_bytes):
                assert self.state in (0, 1)
                self.state += 1
                if self.state-1 == 0:
                    assert num_bytes == 50
                    return bytes.fromhex('00036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c6a')
                elif self.state-1 == 1:
                    assert num_bytes == 66
                    return bytes.fromhex('00b9e3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa22355361aa02e55a8fc28fef5bd6d71ad0c38228dc68b1c466263b47fdf31e560e139ba')
        transport = LNResponderTransport(ls_priv, Reader(), Writer())
        await transport.handshake(epriv=e_priv)

    @needs_test_with_all_chacha20_implementations
    async def test_loop(self):
        responder_shaked = asyncio.Event()
        server_shaked = asyncio.Event()
        responder_key = ECPrivkey.generate_random_key()
        initiator_key = ECPrivkey.generate_random_key()
        messages_sent_by_client = [
            b'hello from client',
            b'long data from client ' + bytes(range(256)) * 100 + b'... client done',
            b'client is running out of things to say',
        ]
        messages_sent_by_server = [
            b'hello from server',
            b'hello2 from server',
            b'long data from server ' + bytes(range(256)) * 100 + b'... server done',
        ]
        async def read_messages(transport, expected_messages):
            ctr = 0
            async for msg in transport.read_messages():
                self.assertEqual(expected_messages[ctr], msg)
                ctr += 1
                if ctr == len(expected_messages):
                    return
        async def write_messages(transport, expected_messages):
            for msg in expected_messages:
                transport.send_bytes(msg)
                await asyncio.sleep(0.01)

        async def cb(reader, writer):
            t = LNResponderTransport(responder_key.get_secret_bytes(), reader, writer)
            self.assertEqual(await t.handshake(), initiator_key.get_public_key_bytes())
            async with OldTaskGroup() as group:
                await group.spawn(read_messages(t, messages_sent_by_client))
                await group.spawn(write_messages(t, messages_sent_by_server))
            responder_shaked.set()
        async def connect(port: int):
            peer_addr = LNPeerAddr('127.0.0.1', port, responder_key.get_public_key_bytes())
            t = LNTransport(initiator_key.get_secret_bytes(), peer_addr, proxy=None)
            await t.handshake()
            async with OldTaskGroup() as group:
                await group.spawn(read_messages(t, messages_sent_by_server))
                await group.spawn(write_messages(t, messages_sent_by_client))
            server_shaked.set()

        async def f():
            server = await asyncio.start_server(cb, '127.0.0.1', port=None)
            server_port = server.sockets[0].getsockname()[1]
            try:
                async with OldTaskGroup() as group:
                    await group.spawn(connect(port=server_port))
                    await group.spawn(responder_shaked.wait())
                    await group.spawn(server_shaked.wait())
            finally:
                server.close()
                await server.wait_closed()

        await f()
