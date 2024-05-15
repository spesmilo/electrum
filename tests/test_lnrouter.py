from math import inf
import unittest
import tempfile
import shutil
import asyncio
from typing import Optional

from electrum import util
from electrum.channel_db import NodeInfo
from electrum.onion_message import is_onion_message_node
from electrum.util import bfh
from electrum.lnutil import ShortChannelID, LnFeatures
from electrum.lnonion import (OnionHopsDataSingle, new_onion_packet,
                              process_onion_packet, _decode_onion_error, decode_onion_error,
                              OnionFailureCode, OnionPacket)
from electrum import bitcoin, lnrouter
from electrum.constants import BitcoinTestnet
from electrum.simple_config import SimpleConfig
from electrum.lnrouter import PathEdge, LiquidityHintMgr, DEFAULT_PENALTY_PROPORTIONAL_MILLIONTH, DEFAULT_PENALTY_BASE_MSAT, fee_for_edge_msat

from . import ElectrumTestCase
from .test_bitcoin import needs_test_with_all_chacha20_implementations


def channel(number: int) -> ShortChannelID:
    return ShortChannelID(bfh(format(number, '016x')))


def node(character: str) -> bytes:
    return b'\x02' + f'{character}'.encode() * 32


def alias(character: str) -> bytes:
    return (character * 8).encode('utf-8')


def node_features(extra: LnFeatures = None) -> bytes:
    lnf = LnFeatures(0) | LnFeatures.VAR_ONION_OPT
    if extra:
        lnf |= extra
    return lnf.to_bytes(8, 'big')


class Test_LNRouter(ElectrumTestCase):
    TESTNET = True

    cdb = None  # type: Optional[lnrouter.ChannelDB]

    def setUp(self):
        super().setUp()
        self.config = SimpleConfig({'electrum_path': self.electrum_path})
        self.assertIsNone(self.cdb)  # sanity-check side effects from previous tests

    async def asyncTearDown(self):
        # if the test called prepare_graph(), channeldb needs to be cleaned up
        if self.cdb:
            self.cdb.stop()
            await self.cdb.stopped_event.wait()
        await super().asyncTearDown()

    def prepare_graph(self):
        """
        Network topology with channel ids:
                3
            A  ---  B
            |    2/ |
          6 |   E   | 1
            | /5 \7 |
            D  ---  C
                4
        valid routes from A -> E:
        A -3-> B -2-> E
        A -6-> D -5-> E
        A -6-> D -4-> C -7-> E
        A -3-> B -1-> C -7-> E
        A -6-> D -4-> C -1-> B -2-> E
        A -3-> B -1-> C -4-> D -5-> E
        """

        class fake_network:
            config = self.config
            asyncio_loop = util.get_asyncio_loop()
            trigger_callback = lambda *args: None
            register_callback = lambda *args: None
            interface = None

        fake_network.channel_db = lnrouter.ChannelDB(fake_network())
        fake_network.channel_db.data_loaded.set()
        self.cdb = fake_network.channel_db
        self.path_finder = lnrouter.LNPathFinder(self.cdb)
        self.assertEqual(self.cdb.num_channels, 0)
        self.cdb.add_channel_announcements({
            'node_id_1': node('b'), 'node_id_2': node('c'),
            'bitcoin_key_1': node('b'), 'bitcoin_key_2': node('c'),
            'short_channel_id': channel(1),
            'chain_hash': BitcoinTestnet.rev_genesis_bytes(),
            'len': 0, 'features': b''
        }, trusted=True)
        self.assertEqual(self.cdb.num_channels, 1)
        self.cdb.add_channel_announcements({
            'node_id_1': node('b'), 'node_id_2': node('e'),
            'bitcoin_key_1': node('b'), 'bitcoin_key_2': node('e'),
            'short_channel_id': channel(2),
            'chain_hash': BitcoinTestnet.rev_genesis_bytes(),
            'len': 0, 'features': b''
        }, trusted=True)
        self.cdb.add_channel_announcements({
            'node_id_1': node('a'), 'node_id_2': node('b'),
            'bitcoin_key_1': node('a'), 'bitcoin_key_2': node('b'),
            'short_channel_id': channel(3),
            'chain_hash': BitcoinTestnet.rev_genesis_bytes(),
            'len': 0, 'features': b''
        }, trusted=True)
        self.cdb.add_channel_announcements({
            'node_id_1': node('c'), 'node_id_2': node('d'),
            'bitcoin_key_1': node('c'), 'bitcoin_key_2': node('d'),
            'short_channel_id': channel(4),
            'chain_hash': BitcoinTestnet.rev_genesis_bytes(),
            'len': 0, 'features': b''
        }, trusted=True)
        self.cdb.add_channel_announcements({
            'node_id_1': node('d'), 'node_id_2': node('e'),
            'bitcoin_key_1': node('d'), 'bitcoin_key_2': node('e'),
            'short_channel_id': channel(5),
            'chain_hash': BitcoinTestnet.rev_genesis_bytes(),
            'len': 0, 'features': b''
        }, trusted=True)
        self.cdb.add_channel_announcements({
            'node_id_1': node('a'), 'node_id_2': node('d'),
            'bitcoin_key_1': node('a'), 'bitcoin_key_2': node('d'),
            'short_channel_id': channel(6),
            'chain_hash': BitcoinTestnet.rev_genesis_bytes(),
            'len': 0, 'features': b''
        }, trusted=True)
        self.cdb.add_channel_announcements({
            'node_id_1': node('c'), 'node_id_2': node('e'),
            'bitcoin_key_1': node('c'), 'bitcoin_key_2': node('e'),
            'short_channel_id': channel(7),
            'chain_hash': BitcoinTestnet.rev_genesis_bytes(),
            'len': 0, 'features': b''
        }, trusted=True)

        self.cdb.add_node_announcements({
            'node_id': node('a'),
            'alias': alias('a'),
            'addresses': [],
            'features': node_features(LnFeatures.OPTION_ONION_MESSAGE_OPT),
            'timestamp': 0
        })
        self.cdb.add_node_announcements({
            'node_id': node('b'),
            'alias': alias('b'),
            'addresses': [],
            'features': node_features(),
            'timestamp': 0
        })
        self.cdb.add_node_announcements({
            'node_id': node('c'),
            'alias': alias('c'),
            'addresses': [],
            'features': node_features(LnFeatures.OPTION_ONION_MESSAGE_OPT),
            'timestamp': 0
        })
        self.cdb.add_node_announcements({
            'node_id': node('d'),
            'alias': alias('d'),
            'addresses': [],
            'features': node_features(LnFeatures.OPTION_ONION_MESSAGE_OPT),
            'timestamp': 0
        })
        self.cdb.add_node_announcements({
            'node_id': node('e'),
            'alias': alias('e'),
            'addresses': [],
            'features': node_features(),
            'timestamp': 0
        })

        def add_chan_upd(payload):
            self.cdb.add_channel_update(payload, verify=False)

        add_chan_upd({'short_channel_id': channel(1), 'message_flags': b'\x00', 'channel_flags': b'\x00', 'cltv_expiry_delta': 10, 'htlc_minimum_msat': 250, 'fee_base_msat': 100, 'fee_proportional_millionths': 150, 'chain_hash': BitcoinTestnet.rev_genesis_bytes(), 'timestamp': 0})
        add_chan_upd({'short_channel_id': channel(1), 'message_flags': b'\x00', 'channel_flags': b'\x01', 'cltv_expiry_delta': 10, 'htlc_minimum_msat': 250, 'fee_base_msat': 100, 'fee_proportional_millionths': 150, 'chain_hash': BitcoinTestnet.rev_genesis_bytes(), 'timestamp': 0})
        add_chan_upd({'short_channel_id': channel(2), 'message_flags': b'\x00', 'channel_flags': b'\x00', 'cltv_expiry_delta': 99, 'htlc_minimum_msat': 250, 'fee_base_msat': 100, 'fee_proportional_millionths': 150, 'chain_hash': BitcoinTestnet.rev_genesis_bytes(), 'timestamp': 0})
        add_chan_upd({'short_channel_id': channel(2), 'message_flags': b'\x00', 'channel_flags': b'\x01', 'cltv_expiry_delta': 10, 'htlc_minimum_msat': 250, 'fee_base_msat': 100, 'fee_proportional_millionths': 150, 'chain_hash': BitcoinTestnet.rev_genesis_bytes(), 'timestamp': 0})
        add_chan_upd({'short_channel_id': channel(3), 'message_flags': b'\x00', 'channel_flags': b'\x01', 'cltv_expiry_delta': 10, 'htlc_minimum_msat': 250, 'fee_base_msat': 100, 'fee_proportional_millionths': 150, 'chain_hash': BitcoinTestnet.rev_genesis_bytes(), 'timestamp': 0})
        add_chan_upd({'short_channel_id': channel(3), 'message_flags': b'\x00', 'channel_flags': b'\x00', 'cltv_expiry_delta': 10, 'htlc_minimum_msat': 250, 'fee_base_msat': 100, 'fee_proportional_millionths': 150, 'chain_hash': BitcoinTestnet.rev_genesis_bytes(), 'timestamp': 0})
        add_chan_upd({'short_channel_id': channel(4), 'message_flags': b'\x00', 'channel_flags': b'\x01', 'cltv_expiry_delta': 10, 'htlc_minimum_msat': 250, 'fee_base_msat': 100, 'fee_proportional_millionths': 150, 'chain_hash': BitcoinTestnet.rev_genesis_bytes(), 'timestamp': 0})
        add_chan_upd({'short_channel_id': channel(4), 'message_flags': b'\x00', 'channel_flags': b'\x00', 'cltv_expiry_delta': 10, 'htlc_minimum_msat': 250, 'fee_base_msat': 100, 'fee_proportional_millionths': 150, 'chain_hash': BitcoinTestnet.rev_genesis_bytes(), 'timestamp': 0})
        add_chan_upd({'short_channel_id': channel(5), 'message_flags': b'\x00', 'channel_flags': b'\x01', 'cltv_expiry_delta': 10, 'htlc_minimum_msat': 250, 'fee_base_msat': 100, 'fee_proportional_millionths': 150, 'chain_hash': BitcoinTestnet.rev_genesis_bytes(), 'timestamp': 0})
        add_chan_upd({'short_channel_id': channel(5), 'message_flags': b'\x00', 'channel_flags': b'\x00', 'cltv_expiry_delta': 10, 'htlc_minimum_msat': 250, 'fee_base_msat': 100, 'fee_proportional_millionths': 999, 'chain_hash': BitcoinTestnet.rev_genesis_bytes(), 'timestamp': 0})
        add_chan_upd({'short_channel_id': channel(6), 'message_flags': b'\x00', 'channel_flags': b'\x00', 'cltv_expiry_delta': 10, 'htlc_minimum_msat': 250, 'fee_base_msat': 100, 'fee_proportional_millionths': 200, 'chain_hash': BitcoinTestnet.rev_genesis_bytes(), 'timestamp': 0})
        add_chan_upd({'short_channel_id': channel(6), 'message_flags': b'\x00', 'channel_flags': b'\x01', 'cltv_expiry_delta': 10, 'htlc_minimum_msat': 250, 'fee_base_msat': 100, 'fee_proportional_millionths': 150, 'chain_hash': BitcoinTestnet.rev_genesis_bytes(), 'timestamp': 0})
        add_chan_upd({'short_channel_id': channel(7), 'message_flags': b'\x00', 'channel_flags': b'\x00', 'cltv_expiry_delta': 10, 'htlc_minimum_msat': 250, 'fee_base_msat': 100, 'fee_proportional_millionths': 150, 'chain_hash': BitcoinTestnet.rev_genesis_bytes(), 'timestamp': 0})
        add_chan_upd({'short_channel_id': channel(7), 'message_flags': b'\x00', 'channel_flags': b'\x01', 'cltv_expiry_delta': 10, 'htlc_minimum_msat': 250, 'fee_base_msat': 100, 'fee_proportional_millionths': 150, 'chain_hash': BitcoinTestnet.rev_genesis_bytes(), 'timestamp': 0})

    async def test_find_path_for_payment(self):
        self.prepare_graph()
        amount_to_send = 100000

        path = self.path_finder.find_path_for_payment(
            nodeA=node('a'),
            nodeB=node('e'),
            invoice_amount_msat=amount_to_send)
        self.assertEqual([
            PathEdge(start_node=node('a'), end_node=node('b'), short_channel_id=channel(3)),
            PathEdge(start_node=node('b'), end_node=node('e'), short_channel_id=channel(2)),
        ], path)

        route = self.path_finder.create_route_from_path(path)
        self.assertEqual(node('b'), route[0].node_id)
        self.assertEqual(channel(3), route[0].short_channel_id)

    async def test_find_path_for_payment_with_node_filter(self):
        self.prepare_graph()
        amount_to_send = 100000

        def node_filter(node_info: 'NodeInfo'):
            return node_info.node_id != node('b')

        path = self.path_finder.find_path_for_payment(
            nodeA=node('a'),
            nodeB=node('e'),
            invoice_amount_msat=amount_to_send,
            node_filter=node_filter)
        self.assertEqual([
            PathEdge(start_node=node('a'), end_node=node('d'), short_channel_id=channel(6)),
            PathEdge(start_node=node('d'), end_node=node('e'), short_channel_id=channel(5)),
        ], path)

        route = self.path_finder.create_route_from_path(path)
        self.assertEqual(node('d'), route[0].node_id)
        self.assertEqual(channel(6), route[0].short_channel_id)

    async def test_find_path_liquidity_hints(self):
        self.prepare_graph()
        amount_to_send = 100000

        """
        assume failure over channel 2, B -> E
        A -3-> B |-2-> E
        A -6-> D -5-> E  <= chosen path
        A -6-> D -4-> C -7-> E
        A -3-> B -1-> C -7-> E
        A -6-> D -4-> C -1-> B -2-> E
        A -3-> B -1-> C -4-> D -5-> E
        """
        self.path_finder.liquidity_hints.update_cannot_send(node('b'), node('e'), channel(2), amount_to_send - 1)
        path = self.path_finder.find_path_for_payment(
            nodeA=node('a'),
            nodeB=node('e'),
            invoice_amount_msat=amount_to_send)
        self.assertEqual(channel(6), path[0].short_channel_id)
        self.assertEqual(channel(5), path[1].short_channel_id)

        """
        assume failure over channel 5, D -> E
        A -3-> B |-2-> E
        A -6-> D |-5-> E
        A -6-> D -4-> C -7-> E
        A -3-> B -1-> C -7-> E  <= chosen path
        A -6-> D -4-> C -1-> B |-2-> E
        A -3-> B -1-> C -4-> D |-5-> E
        """
        self.path_finder.liquidity_hints.update_cannot_send(node('d'), node('e'), channel(5), amount_to_send - 1)
        path = self.path_finder.find_path_for_payment(
            nodeA=node('a'),
            nodeB=node('e'),
            invoice_amount_msat=amount_to_send)
        self.assertEqual(channel(3), path[0].short_channel_id)
        self.assertEqual(channel(1), path[1].short_channel_id)
        self.assertEqual(channel(7), path[2].short_channel_id)

        """
        assume success over channel 4, D -> C
        A -3-> B |-2-> E
        A -6-> D |-5-> E
        A -6-> D -4-> C -7-> E  <= smaller penalty: chosen path
        A -3-> B -1-> C -7-> E
        A -6-> D -4-> C -1-> B |-2-> E
        A -3-> B -1-> C -4-> D |-5-> E
        """
        self.path_finder.liquidity_hints.update_can_send(node('d'), node('c'), channel(4), amount_to_send + 1000)
        path = self.path_finder.find_path_for_payment(
            nodeA=node('a'),
            nodeB=node('e'),
            invoice_amount_msat=amount_to_send)
        self.assertEqual(channel(6), path[0].short_channel_id)
        self.assertEqual(channel(4), path[1].short_channel_id)
        self.assertEqual(channel(7), path[2].short_channel_id)

    async def test_find_path_liquidity_hints_inflight_htlcs(self):
        self.prepare_graph()
        amount_to_send = 100000

        """
        add inflight htlc to channel 2, B -> E
        A -3-> B -2(1)-> E
        A -6-> D -5-> E <= chosen path
        A -6-> D -4-> C -7-> E
        A -3-> B -1-> C -7-> E
        A -6-> D -4-> C -1-> B -2-> E
        A -3-> B -1-> C -4-> D -5-> E
        """
        self.path_finder.liquidity_hints.add_htlc(node('b'), node('e'), channel(2))
        path = self.path_finder.find_path_for_payment(
            nodeA=node('a'),
            nodeB=node('e'),
            invoice_amount_msat=amount_to_send)
        self.assertEqual(channel(6), path[0].short_channel_id)
        self.assertEqual(channel(5), path[1].short_channel_id)

        """
        remove inflight htlc from channel 2, B -> E
        A -3-> B -2(0)-> E <= chosen path
        A -6-> D -5-> E
        A -6-> D -4-> C -7-> E
        A -3-> B -1-> C -7-> E
        A -6-> D -4-> C -1-> B -2-> E
        A -3-> B -1-> C -4-> D -5-> E
        """
        self.path_finder.liquidity_hints.remove_htlc(node('b'), node('e'), channel(2))
        path = self.path_finder.find_path_for_payment(
            nodeA=node('a'),
            nodeB=node('e'),
            invoice_amount_msat=amount_to_send)
        self.assertEqual(channel(3), path[0].short_channel_id)
        self.assertEqual(channel(2), path[1].short_channel_id)

    def test_liquidity_hints(self):
        liquidity_hints = LiquidityHintMgr()
        node_from = bytes(0)
        node_to = bytes(1)
        channel_id = ShortChannelID.from_components(0, 0, 0)
        amount_to_send = 1_000_000

        # check default penalty
        self.assertEqual(
            fee_for_edge_msat(amount_to_send, DEFAULT_PENALTY_BASE_MSAT, DEFAULT_PENALTY_PROPORTIONAL_MILLIONTH),
            liquidity_hints.penalty(node_from, node_to, channel_id, amount_to_send)
        )
        liquidity_hints.update_can_send(node_from, node_to, channel_id, 1_000_000)
        liquidity_hints.update_cannot_send(node_from, node_to, channel_id, 2_000_000)
        hint = liquidity_hints.get_hint(channel_id)
        self.assertEqual(1_000_000, hint.can_send(node_from < node_to))
        self.assertEqual(None, hint.cannot_send(node_to < node_from))
        self.assertEqual(2_000_000, hint.cannot_send(node_from < node_to))
        # the can_send backward hint is set automatically
        self.assertEqual(2_000_000, hint.can_send(node_to < node_from))

        # check penalties
        self.assertEqual(0., liquidity_hints.penalty(node_from, node_to, channel_id, 1_000_000))
        self.assertEqual(650, liquidity_hints.penalty(node_from, node_to, channel_id, 1_500_000))
        self.assertEqual(inf, liquidity_hints.penalty(node_from, node_to, channel_id, 2_000_000))

        # test that we don't overwrite significant info with less significant info
        liquidity_hints.update_can_send(node_from, node_to, channel_id, 500_000)
        hint = liquidity_hints.get_hint(channel_id)
        self.assertEqual(1_000_000, hint.can_send(node_from < node_to))

        # test case when can_send > cannot_send
        liquidity_hints.update_can_send(node_from, node_to, channel_id, 3_000_000)
        hint = liquidity_hints.get_hint(channel_id)
        self.assertEqual(3_000_000, hint.can_send(node_from < node_to))
        self.assertEqual(None, hint.cannot_send(node_from < node_to))

        # test inflight htlc
        liquidity_hints.reset_liquidity_hints()
        liquidity_hints.add_htlc(node_from, node_to, channel_id)
        liquidity_hints.get_hint(channel_id)
        # we have got 600 (attempt) + 600 (inflight) penalty
        self.assertEqual(1200, liquidity_hints.penalty(node_from, node_to, channel_id, 1_000_000))

    @needs_test_with_all_chacha20_implementations
    def test_new_onion_packet(self):
        # test vector from bolt-04
        payment_path_pubkeys = [
            bfh('02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619'),
            bfh('0324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c'),
            bfh('027f31ebc5462c1fdce1b737ecff52d37d75dea43ce11c74d25aa297165faa2007'),
            bfh('032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991'),
            bfh('02edabbd16b41c8371b92ef2f04c1185b4f03b6dcd52ba9b78d9d7c89c8f221145'),
        ]
        session_key = bfh('4141414141414141414141414141414141414141414141414141414141414141')
        associated_data = bfh('4242424242424242424242424242424242424242424242424242424242424242')
        hops_data = [
            OnionHopsDataSingle(),
            OnionHopsDataSingle(),
            OnionHopsDataSingle(),
            OnionHopsDataSingle(),
            OnionHopsDataSingle(),
        ]
        hops_data[0]._raw_bytes_payload = bfh("1202023a98040205dc06080000000000000001")
        hops_data[1]._raw_bytes_payload = bfh("52020236b00402057806080000000000000002fd02013c0102030405060708090a0b0c0d0e0f0102030405060708090a0b0c0d0e0f0102030405060708090a0b0c0d0e0f0102030405060708090a0b0c0d0e0f")
        hops_data[2]._raw_bytes_payload = bfh("12020230d4040204e206080000000000000003")
        hops_data[3]._raw_bytes_payload = bfh("1202022710040203e806080000000000000004")
        hops_data[4]._raw_bytes_payload = bfh("fd011002022710040203e8082224a33562c54507a9334e79f0dc4f17d407e6d7c61f0e2f3d0d38599502f617042710fd012de02a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a")
        packet = new_onion_packet(payment_path_pubkeys, session_key, hops_data, associated_data=associated_data)
        self.assertEqual(bfh('0002eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619f7f3416a5aa36dc7eeb3ec6d421e9615471ab870a33ac07fa5d5a51df0a8823aabe3fea3f90d387529d4f72837f9e687230371ccd8d263072206dbed0234f6505e21e282abd8c0e4f5b9ff8042800bbab065036eadd0149b37f27dde664725a49866e052e809d2b0198ab9610faa656bbf4ec516763a59f8f42c171b179166ba38958d4f51b39b3e98706e2d14a2dafd6a5df808093abfca5aeaaca16eded5db7d21fb0294dd1a163edf0fb445d5c8d7d688d6dd9c541762bf5a5123bf9939d957fe648416e88f1b0928bfa034982b22548e1a4d922690eecf546275afb233acf4323974680779f1a964cfe687456035cc0fba8a5428430b390f0057b6d1fe9a8875bfa89693eeb838ce59f09d207a503ee6f6299c92d6361bc335fcbf9b5cd44747aadce2ce6069cfdc3d671daef9f8ae590cf93d957c9e873e9a1bc62d9640dc8fc39c14902d49a1c80239b6c5b7fd91d05878cbf5ffc7db2569f47c43d6c0d27c438abff276e87364deb8858a37e5a62c446af95d8b786eaf0b5fcf78d98b41496794f8dcaac4eef34b2acfb94c7e8c32a9e9866a8fa0b6f2a06f00a1ccde569f97eec05c803ba7500acc96691d8898d73d8e6a47b8f43c3d5de74458d20eda61474c426359677001fbd75a74d7d5db6cb4feb83122f133206203e4e2d293f838bf8c8b3a29acb321315100b87e80e0edb272ee80fda944e3fb6084ed4d7f7c7d21c69d9da43d31a90b70693f9b0cc3eac74c11ab8ff655905688916cfa4ef0bd04135f2e50b7c689a21d04e8e981e74c6058188b9b1f9dfc3eec6838e9ffbcf22ce738d8a177c19318dffef090cee67e12de1a3e2a39f61247547ba5257489cbc11d7d91ed34617fcc42f7a9da2e3cf31a94a210a1018143173913c38f60e62b24bf0d7518f38b5bab3e6a1f8aeb35e31d6442c8abb5178efc892d2e787d79c6ad9e2fc271792983fa9955ac4d1d84a36c024071bc6e431b625519d556af38185601f70e29035ea6a09c8b676c9d88cf7e05e0f17098b584c4168735940263f940033a220f40be4c85344128b14beb9e75696db37014107801a59b13e89cd9d2258c169d523be6d31552c44c82ff4bb18ec9f099f3bf0e5b1bb2ba9a87d7e26f98d294927b600b5529c47e04d98956677cbcee8fa2b60f49776d8b8c367465b7c626da53700684fb6c918ead0eab8360e4f60edd25b4f43816a75ecf70f909301825b512469f8389d79402311d8aecb7b3ef8599e79485a4388d87744d899f7c47ee644361e17040a7958c8911be6f463ab6a9b2afacd688ec55ef517b38f1339efc54487232798bb25522ff4572ff68567fe830f92f7b8113efce3e98c3fffbaedce4fd8b50e41da97c0c08e423a72689cc68e68f752a5e3a9003e64e35c957ca2e1c48bb6f64b05f56b70b575ad2f278d57850a7ad568c24a4d32a3d74b29f03dc125488bc7c637da582357f40b0a52d16b3b40bb2c2315d03360bc24209e20972c200566bcf3bbe5c5b0aedd83132a8a4d5b4242ba370b6d67d9b67eb01052d132c7866b9cb502e44796d9d356e4e3cb47cc527322cd24976fe7c9257a2864151a38e568ef7a79f10d6ef27cc04ce382347a2488b1f404fdbf407fe1ca1c9d0d5649e34800e25e18951c98cae9f43555eef65fee1ea8f15828807366c3b612cd5753bf9fb8fced08855f742cddd6f765f74254f03186683d646e6f09ac2805586c7cf11998357cafc5df3f285329366f475130c928b2dceba4aa383758e7a9d20705c4bb9db619e2992f608a1ba65db254bb389468741d0502e2588aeb54390ac600c19af5c8e61383fc1bebe0029e4474051e4ef908828db9cca13277ef65db3fd47ccc2179126aaefb627719f421e20'),
                         packet.to_bytes())

    @needs_test_with_all_chacha20_implementations
    def test_process_onion_packet(self):
        # this test is not from bolt-04, but is based on the one there;
        # here the TLV payloads are all known types. This allows testing
        # decoding the onion and parsing hops_data into known TLV dicts.
        payment_path_pubkeys = [
            bfh('02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619'),
            bfh('0324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c'),
            bfh('027f31ebc5462c1fdce1b737ecff52d37d75dea43ce11c74d25aa297165faa2007'),
            bfh('032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991'),
            bfh('02edabbd16b41c8371b92ef2f04c1185b4f03b6dcd52ba9b78d9d7c89c8f221145'),
        ]
        payment_path_privkeys = [
            bfh('4141414141414141414141414141414141414141414141414141414141414141'),
            bfh('4242424242424242424242424242424242424242424242424242424242424242'),
            bfh('4343434343434343434343434343434343434343434343434343434343434343'),
            bfh('4444444444444444444444444444444444444444444444444444444444444444'),
            bfh('4545454545454545454545454545454545454545454545454545454545454545'),
        ]
        session_key = bfh('4141414141414141414141414141414141414141414141414141414141414141')
        associated_data = bfh('4242424242424242424242424242424242424242424242424242424242424242')
        hops_data = [
            OnionHopsDataSingle(payload={
                'amt_to_forward': {'amt_to_forward': 15000},
                'outgoing_cltv_value': {'outgoing_cltv_value': 1500},
                'short_channel_id': {'short_channel_id': bfh('0000000000000001')}}),
            OnionHopsDataSingle(payload={
                'amt_to_forward': {'amt_to_forward': 14000},
                'outgoing_cltv_value': {'outgoing_cltv_value': 1400},
                'short_channel_id': {'short_channel_id': bfh('0000000000000002')}}),
            OnionHopsDataSingle(payload={
                'amt_to_forward': {'amt_to_forward': 12500},
                'outgoing_cltv_value': {'outgoing_cltv_value': 1250},
                'short_channel_id': {'short_channel_id': bfh('0000000000000003')}}),
            OnionHopsDataSingle(payload={
                'amt_to_forward': {'amt_to_forward': 10000},
                'outgoing_cltv_value': {'outgoing_cltv_value': 1000},
                'short_channel_id': {'short_channel_id': bfh('0000000000000004')}}),
            OnionHopsDataSingle(payload={
                'amt_to_forward': {'amt_to_forward': 10000},
                'outgoing_cltv_value': {'outgoing_cltv_value': 1000},
                'payment_data': {'payment_secret': bfh('24a33562c54507a9334e79f0dc4f17d407e6d7c61f0e2f3d0d38599502f61704'), 'total_msat': 10000}}),
        ]
        packet = new_onion_packet(payment_path_pubkeys, session_key, hops_data, associated_data=associated_data)
        self.assertEqual(bfh('0002eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619f7f3416a5aa36dc7eeb3ec6d421e9615471ab858ba970cd3cceb768b44e692be2f390c0b7fe70122abae84d7801db070dfb1638cd8d263072206dbed0234f6505e21e282abd8587124c572aad8de04610a136d6c71a7648c0ef66f1b3655d8a9eea1f92349132c93befbd6c37dbfc55615814ae09e4cbef721c01b487007811bbbfdc1fc7bd869aeb70eb08b4140ff5f501394b3653ada2a3b36a263535ea421d26818afb278df46abcec093305b715cac22b0b03645f8f4797cf2987b1bf4bfdd9ed8648ed42ed1a831fc36ccd45416a132580281ddac4e7470e4d2afd675baad9282ec6335403a73e1391427e330996c834db93848b4ae29dd975f678b2f5155ad6865ca23190725d4b7238fb44f0e3762dd59091b45c97d45df8164a15d9ca0329ec76f957b0a0e49ae372154620708df5c0fa991f0dd12b6bff1ebaf9e2376bb64bc24713f7c57da569bcd9c43a50c088416564b786a87d1f40936a051a3dbfe023bd867a5e66148b61cdd24a79f8c18682150e55aa6969ce9becf51f7c69e72deafcd0659f6be4f78463eaef8716e56615c77b3fbea8190806359909dcbec13c1592523b3d2985ec3e83d42cb7286a66a22f58704ddf6979ceb6883ab4ad8ac99d30251035189ffd514e03ce1576844513d66965d4adfc2523f4eee0dede229ab96303e31348c72bc0c8c816c666a904e5ccbabadf5a919720438f4a14dbd4a802f8d4b942f0ca8572f59644c9ac1912c8c8efefc4afa7f19e27411d46b7541c55985e28ce5cd7620b335fea51de55fa00ef977e8522181ad19e5e04f93bcfc83a36edd7e96fe48e846f2e54fe7a7090fe8e46ba72123e1cdee0667777c38c4930e50401074d8ab31a9717457fcefaa46323003af553bee2b49ea7f907eb2ff3301463e64a8c53975c853bbdd2956b9001b5ce1562264963fce84201daaf752de6df7ca31291226969c9851d1fc4ea88ca67d38c38587c2cdd8bc4d3f7bdf705497a1e054246f684554b3b8dfac43194f1eadec7f83b711e663b5645bde6d7f8cefb59758303599fed25c3b4d2e4499d439c915910dd283b3e7118320f1c6e7385009fbcb9ae79bab72a85e644182b4dafc0a173241f2ae68ae6a504f17f102da1e91de4548c7f5bc1c107354519077a4e83407f0d6a8f0975b4ac0c2c7b30637a998dda27b56b56245371296b816876b859677bcf3473a07e0f300e788fdd60c51b1626b46050b182457c6d716994847aaef667ca45b2cede550c92d336ff29ce6effd933b875f81381cda6e59e9727e728a58c0b3e74035beeeb639ab7463744322bf40138b81895e9a8e8850c9513782dc7a79f04380c216cb177951d8940d576486b887a232fcd382adcbd639e70af0c1a08bcf1405496606fce4645aef10d769dc0c010a8a433d8cd24d5943843a89cdbc8d16531db027b312ab2c03a7f1fdb7f2bcb128639c49e86705c948137fd42d0080fda4be4e9ee812057c7974acbf0162730d3b647b355ac1a5adbb2993832eba443b7c9b5a0ae1fc00a6c0c2b0b65b9019690565739d6439bf602066a3a9bd9c67b83606de51792d25ae517cbbdf6e1827fa0e8b2b5c6023cbb1e9f0e10b786dc6fa154e282fd9c90b8d46ca685d0f4434760035073c92d131564b6845ef57457488add4f709073bbb41f5f31f8226904875a9fd9e1b7a2901e71426104d7a298a05af0d4ab549fbd69c539ebe64949a9b6088f16e2e4bc827c305cb8d64536b8364dc3d5f7519c3b431faa38b47a958cf0c6dcabf205280693abf747c262f44cd6ffa11b32fc38d4f9c3631d554d8b57389f1390ac65c06357843ee6d9f289bb054ef25de45c5149c090fe6ddcd4095696dcc9a5cfc09c8bdfd5b83a153'),
                         packet.to_bytes())
        for i, privkey in enumerate(payment_path_privkeys):
            processed_packet = process_onion_packet(packet, privkey, associated_data=associated_data)
            self.assertEqual(hops_data[i].to_bytes(), processed_packet.hop_data.to_bytes())
            packet = processed_packet.next_packet

    @needs_test_with_all_chacha20_implementations
    def test_decode_onion_error(self):
        # test vector from bolt-04
        payment_path_pubkeys = [
            bfh('02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619'),
            bfh('0324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c'),
            bfh('027f31ebc5462c1fdce1b737ecff52d37d75dea43ce11c74d25aa297165faa2007'),
            bfh('032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991'),
            bfh('02edabbd16b41c8371b92ef2f04c1185b4f03b6dcd52ba9b78d9d7c89c8f221145'),
        ]
        session_key = bfh('4141414141414141414141414141414141414141414141414141414141414141')
        error_packet_for_node_0 = bfh('9c5add3963fc7f6ed7f148623c84134b5647e1306419dbe2174e523fa9e2fbed3a06a19f899145610741c83ad40b7712aefaddec8c6baf7325d92ea4ca4d1df8bce517f7e54554608bf2bd8071a4f52a7a2f7ffbb1413edad81eeea5785aa9d990f2865dc23b4bc3c301a94eec4eabebca66be5cf638f693ec256aec514620cc28ee4a94bd9565bc4d4962b9d3641d4278fb319ed2b84de5b665f307a2db0f7fbb757366067d88c50f7e829138fde4f78d39b5b5802f1b92a8a820865af5cc79f9f30bc3f461c66af95d13e5e1f0381c184572a91dee1c849048a647a1158cf884064deddbf1b0b88dfe2f791428d0ba0f6fb2f04e14081f69165ae66d9297c118f0907705c9c4954a199bae0bb96fad763d690e7daa6cfda59ba7f2c8d11448b604d12d')

        decoded_error, index_of_sender = _decode_onion_error(error_packet_for_node_0, payment_path_pubkeys, session_key)
        self.assertEqual(bfh('4c2fc8bc08510334b6833ad9c3e79cd1b52ae59dfe5c2a4b23ead50f09f7ee0b0002200200fe0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'),
                             decoded_error)
        self.assertEqual(4, index_of_sender)

        failure_msg, index_of_sender = decode_onion_error(error_packet_for_node_0, payment_path_pubkeys, session_key)
        self.assertEqual(4, index_of_sender)
        self.assertEqual(OnionFailureCode.TEMPORARY_NODE_FAILURE, failure_msg.code)
        self.assertEqual(b'', failure_msg.data)

    async def test_find_path_for_onion_message(self):
        self.prepare_graph()
        amount_to_send = 1000  # we route along channels, and we use find_path_for_payment, so dummy this.

        path = self.path_finder.find_path_for_payment(
            nodeA=node('a'),
            nodeB=node('c'),
            invoice_amount_msat=amount_to_send,
            node_filter=is_onion_message_node)
        self.assertEqual([
            PathEdge(start_node=node('a'), end_node=node('d'), short_channel_id=channel(6)),
            PathEdge(start_node=node('d'), end_node=node('c'), short_channel_id=channel(4)),
        ], path)

        # impossible routes
        path = self.path_finder.find_path_for_payment(
            nodeA=node('e'),
            nodeB=node('a'),
            invoice_amount_msat=amount_to_send,
            node_filter=is_onion_message_node)
        self.assertIsNone(path)

        path = self.path_finder.find_path_for_payment(
            nodeA=node('a'),
            nodeB=node('e'),
            invoice_amount_msat=amount_to_send,
            node_filter=is_onion_message_node)
        self.assertIsNone(path)
