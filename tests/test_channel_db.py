from unittest import mock

from electrum_ecc import ECPrivkey

from electrum import util
from electrum.channel_db import ChannelDB, ChannelInfo
from electrum.constants import BitcoinTestnet
from electrum.lnmsg import encode_msg, decode_msg
from electrum.lnutil import ShortChannelID, InvalidGossipMsg
from electrum.simple_config import SimpleConfig
from electrum.util import bfh

from . import ElectrumTestCase


def channel(number: int) -> ShortChannelID:
    return ShortChannelID(bfh(format(number, '016x')))


# sorted, so that node('a') < node('b') < node('c')
NODE_IDS = dict(zip('abc', sorted(ECPrivkey.from_secret_scalar(i).get_public_key_bytes() for i in (1, 2, 3))))


def node(character: str) -> bytes:
    return NODE_IDS[character]


def chan_ann(scid: ShortChannelID, node_id_1: bytes, node_id_2: bytes) -> dict:
    raw = encode_msg(
        'channel_announcement',
        node_signature_1=bytes(64),
        node_signature_2=bytes(64),
        bitcoin_signature_1=bytes(64),
        bitcoin_signature_2=bytes(64),
        len=0,
        features=b'',
        chain_hash=BitcoinTestnet.rev_genesis_bytes(),
        short_channel_id=scid,
        node_id_1=node_id_1,
        node_id_2=node_id_2,
        bitcoin_key_1=node_id_1,
        bitcoin_key_2=node_id_2,
    )
    payload = decode_msg(raw)[1]
    payload['raw'] = raw
    return payload


class TestChannelDB(ElectrumTestCase):
    TESTNET = True

    def setUp(self):
        super().setUp()
        self.config = SimpleConfig({'electrum_path': self.electrum_path})
        self.cdbs = []

    async def asyncTearDown(self):
        for cdb in list(self.cdbs):
            await self._stop_cdb(cdb)
        await super().asyncTearDown()

    def _new_cdb(self) -> ChannelDB:
        class fake_network:
            config = self.config
            asyncio_loop = util.get_asyncio_loop()
            trigger_callback = lambda *args: None
            register_callback = lambda *args: None
            interface = None
        cdb = ChannelDB(fake_network())
        self.cdbs.append(cdb)
        return cdb

    async def _stop_cdb(self, cdb: ChannelDB):
        cdb.stop()
        await cdb.stopped_event.wait()
        self.cdbs.remove(cdb)

    async def test_add_channel_announcements_ignores_same_node_ids(self):
        cdb = self._new_cdb()
        cdb.add_channel_announcements(chan_ann(channel(1), node('a'), node('a')))
        self.assertNotIn(channel(1), cdb._channels)
        self.assertNotIn(node('a'), cdb._channels_for_node)
        self.assertEqual(0, cdb.num_channels)

    async def test_add_channel_announcements_ignores_unsorted_node_ids(self):
        cdb = self._new_cdb()
        cdb.add_channel_announcements([
            chan_ann(channel(1), node('a'), node('b')),
            chan_ann(channel(2), node('c'), node('b')),
            chan_ann(channel(3), node('b'), node('c')),
        ])
        self.assertIn(channel(1), cdb._channels)
        self.assertNotIn(channel(2), cdb._channels)
        self.assertIn(channel(3), cdb._channels)
        self.assertEqual(2, cdb.num_channels)

    async def test_load_data_skips_invalid_channel_announcement(self):
        # a gossip_db written by an older version may contain announcements
        # that fail validation added later
        cdb = self._new_cdb()
        for ann in [chan_ann(channel(1), node('a'), node('b')),
                    chan_ann(channel(2), node('b'), node('c'))]:
            await cdb._db_save_channel(ann['short_channel_id'], ann['raw'])
        await self._stop_cdb(cdb)

        from_msg = ChannelInfo.from_msg
        def from_msg_rejecting_channel_1(payload):
            if payload['short_channel_id'] == channel(1):
                raise InvalidGossipMsg('rejected by test')
            return from_msg(payload)

        cdb = self._new_cdb()
        with mock.patch.object(ChannelInfo, 'from_msg', side_effect=from_msg_rejecting_channel_1):
            await cdb.load_data()
        self.assertTrue(cdb.data_loaded.is_set())
        self.assertNotIn(channel(1), cdb._channels)
        self.assertIn(channel(2), cdb._channels)
