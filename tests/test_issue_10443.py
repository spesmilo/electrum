import unittest
from unittest.mock import MagicMock
from electrum.lnrouter import LNPathFinder, ChannelDB
from . import ElectrumTestCase

def node(character: str) -> bytes:
    return b'\x02' + f'{character}'.encode() * 32

def channel(number: int) -> bytes:
    return number.to_bytes(8, 'big')

class TestIssue10443(ElectrumTestCase):
    def setUp(self):
        super().setUp()
        class FakeNetwork:
            config = MagicMock()
            config.path = self.electrum_path
            asyncio_loop = None
            trigger_callback = lambda *args: None
        self.cdb = ChannelDB(FakeNetwork())
        self.path_finder = LNPathFinder(self.cdb)

    def test_prefer_shorter_path(self):
        # A -> B -> C (Short, expensive)
        # A -> D -> E -> F -> G -> H -> C (Long, cheap)

        # Add nodes
        for c in 'abcdefgh':
            self.cdb._nodes[node(c)] = None

        # Add channels and policies
        def add_edge(u, v, scid, fee_base, fee_rate):
            scid_bytes = channel(scid)
            self.cdb.add_channel_announcement({
                'node_id_1': node(u), 'node_id_2': node(v),
                'bitcoin_key_1': node(u), 'bitcoin_key_2': node(v),
                'short_channel_id': scid_bytes,
                'chain_hash': b'\x00'*32,
                'len': 0, 'features': b''
            }, trusted=True)
            self.cdb.add_channel_update({
                'short_channel_id': scid_bytes,
                'message_flags': b'\x00',
                'channel_flags': b'\x00' if node(u) < node(v) else b'\x01',
                'cltv_expiry_delta': 10,
                'htlc_minimum_msat': 0,
                'fee_base_msat': fee_base,
                'fee_proportional_millionths': fee_rate,
                'chain_hash': b'\x00'*32,
                'timestamp': 0
            }, verify=False)

        # Short path: A -> B -> C
        # A -> B (scid 1)
        add_edge('a', 'b', 1, 0, 0)
        # B -> C (scid 2)
        add_edge('b', 'c', 2, 5000, 0) # 5 sat fee

        # Long path: A -> D -> E -> F -> G -> H -> C
        add_edge('a', 'd', 3, 0, 0)
        add_edge('d', 'e', 4, 100, 0) # 0.1 sat fee
        add_edge('e', 'f', 5, 100, 0)
        add_edge('f', 'g', 6, 100, 0)
        add_edge('g', 'h', 7, 100, 0)
        add_edge('h', 'c', 8, 100, 0)
        # Total fee for long path = 500 msat = 0.5 sat

        # With penalty = 500 msat:
        # short path cost = 5000 (fee) + 500 (1 hop penalty) = 5500
        # long path cost = 500 (fee) + 5 * 500 (5 hops penalty) = 3000
        # 3000 < 5500 -> prefers long path!

        # With penalty = 2000 msat:
        # short path cost = 5000 (fee) + 2000 (1 hop penalty) = 7000
        # long path cost = 500 (fee) + 5 * 2000 (5 hops penalty) = 10500
        # 7000 < 10500 -> prefers short path!

        path = self.path_finder.find_path_for_payment(
            nodeA=node('a'),
            nodeB=node('c'),
            invoice_amount_msat=100000)

        # We expect the short path if penalty is high enough
        self.assertEqual(2, len(path))
        self.assertEqual(channel(1), path[0].short_channel_id)
        self.assertEqual(channel(2), path[1].short_channel_id)
