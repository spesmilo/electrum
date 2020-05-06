import unittest
import tempfile
import shutil
import asyncio

from electrum.util import bh2u, bfh, create_and_start_event_loop
from electrum.lnonion import (OnionHopsDataSingle, new_onion_packet,
                              process_onion_packet, _decode_onion_error, decode_onion_error,
                              OnionFailureCode, OnionPacket)
from electrum import bitcoin, lnrouter
from electrum.constants import BitcoinTestnet
from electrum.simple_config import SimpleConfig
from electrum.lnrouter import PathEdge

from . import TestCaseForTestnet
from .test_bitcoin import needs_test_with_all_chacha20_implementations


class Test_LNRouter(TestCaseForTestnet):

    def setUp(self):
        super().setUp()
        self.asyncio_loop, self._stop_loop, self._loop_thread = create_and_start_event_loop()
        self.config = SimpleConfig({'electrum_path': self.electrum_path})

    def tearDown(self):
        self.asyncio_loop.call_soon_threadsafe(self._stop_loop.set_result, 1)
        self._loop_thread.join(timeout=1)
        super().tearDown()

    def test_find_path_for_payment(self):
        class fake_network:
            config = self.config
            asyncio_loop = asyncio.get_event_loop()
            trigger_callback = lambda *args: None
            register_callback = lambda *args: None
            interface = None
        fake_network.channel_db = lnrouter.ChannelDB(fake_network())
        fake_network.channel_db.data_loaded.set()
        cdb = fake_network.channel_db
        path_finder = lnrouter.LNPathFinder(cdb)
        self.assertEqual(cdb.num_channels, 0)
        cdb.add_channel_announcement({'node_id_1': b'\x02bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 'node_id_2': b'\x02cccccccccccccccccccccccccccccccc',
                                     'bitcoin_key_1': b'\x02bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 'bitcoin_key_2': b'\x02cccccccccccccccccccccccccccccccc',
                                     'short_channel_id': bfh('0000000000000001'),
                                     'chain_hash': BitcoinTestnet.rev_genesis_bytes(),
                                     'len': 0, 'features': b''}, trusted=True)
        self.assertEqual(cdb.num_channels, 1)
        cdb.add_channel_announcement({'node_id_1': b'\x02bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 'node_id_2': b'\x02eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
                                     'bitcoin_key_1': b'\x02bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 'bitcoin_key_2': b'\x02eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
                                     'short_channel_id': bfh('0000000000000002'),
                                     'chain_hash': BitcoinTestnet.rev_genesis_bytes(),
                                     'len': 0, 'features': b''}, trusted=True)
        cdb.add_channel_announcement({'node_id_1': b'\x02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'node_id_2': b'\x02bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                                     'bitcoin_key_1': b'\x02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'bitcoin_key_2': b'\x02bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                                     'short_channel_id': bfh('0000000000000003'),
                                     'chain_hash': BitcoinTestnet.rev_genesis_bytes(),
                                     'len': 0, 'features': b''}, trusted=True)
        cdb.add_channel_announcement({'node_id_1': b'\x02cccccccccccccccccccccccccccccccc', 'node_id_2': b'\x02dddddddddddddddddddddddddddddddd',
                                     'bitcoin_key_1': b'\x02cccccccccccccccccccccccccccccccc', 'bitcoin_key_2': b'\x02dddddddddddddddddddddddddddddddd',
                                     'short_channel_id': bfh('0000000000000004'),
                                     'chain_hash': BitcoinTestnet.rev_genesis_bytes(),
                                     'len': 0, 'features': b''}, trusted=True)
        cdb.add_channel_announcement({'node_id_1': b'\x02dddddddddddddddddddddddddddddddd', 'node_id_2': b'\x02eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
                                     'bitcoin_key_1': b'\x02dddddddddddddddddddddddddddddddd', 'bitcoin_key_2': b'\x02eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
                                     'short_channel_id': bfh('0000000000000005'),
                                     'chain_hash': BitcoinTestnet.rev_genesis_bytes(),
                                     'len': 0, 'features': b''}, trusted=True)
        cdb.add_channel_announcement({'node_id_1': b'\x02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'node_id_2': b'\x02dddddddddddddddddddddddddddddddd',
                                     'bitcoin_key_1': b'\x02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'bitcoin_key_2': b'\x02dddddddddddddddddddddddddddddddd',
                                     'short_channel_id': bfh('0000000000000006'),
                                     'chain_hash': BitcoinTestnet.rev_genesis_bytes(),
                                     'len': 0, 'features': b''}, trusted=True)
        cdb.add_channel_update({'short_channel_id': bfh('0000000000000001'), 'message_flags': b'\x00', 'channel_flags': b'\x00', 'cltv_expiry_delta': 10, 'htlc_minimum_msat': 250, 'fee_base_msat': 100, 'fee_proportional_millionths': 150, 'chain_hash': BitcoinTestnet.rev_genesis_bytes(), 'timestamp': 0})
        cdb.add_channel_update({'short_channel_id': bfh('0000000000000001'), 'message_flags': b'\x00', 'channel_flags': b'\x01', 'cltv_expiry_delta': 10, 'htlc_minimum_msat': 250, 'fee_base_msat': 100, 'fee_proportional_millionths': 150, 'chain_hash': BitcoinTestnet.rev_genesis_bytes(), 'timestamp': 0})
        cdb.add_channel_update({'short_channel_id': bfh('0000000000000002'), 'message_flags': b'\x00', 'channel_flags': b'\x00', 'cltv_expiry_delta': 99, 'htlc_minimum_msat': 250, 'fee_base_msat': 100, 'fee_proportional_millionths': 150, 'chain_hash': BitcoinTestnet.rev_genesis_bytes(), 'timestamp': 0})
        cdb.add_channel_update({'short_channel_id': bfh('0000000000000002'), 'message_flags': b'\x00', 'channel_flags': b'\x01', 'cltv_expiry_delta': 10, 'htlc_minimum_msat': 250, 'fee_base_msat': 100, 'fee_proportional_millionths': 150, 'chain_hash': BitcoinTestnet.rev_genesis_bytes(), 'timestamp': 0})
        cdb.add_channel_update({'short_channel_id': bfh('0000000000000003'), 'message_flags': b'\x00', 'channel_flags': b'\x01', 'cltv_expiry_delta': 10, 'htlc_minimum_msat': 250, 'fee_base_msat': 100, 'fee_proportional_millionths': 150, 'chain_hash': BitcoinTestnet.rev_genesis_bytes(), 'timestamp': 0})
        cdb.add_channel_update({'short_channel_id': bfh('0000000000000003'), 'message_flags': b'\x00', 'channel_flags': b'\x00', 'cltv_expiry_delta': 10, 'htlc_minimum_msat': 250, 'fee_base_msat': 100, 'fee_proportional_millionths': 150, 'chain_hash': BitcoinTestnet.rev_genesis_bytes(), 'timestamp': 0})
        cdb.add_channel_update({'short_channel_id': bfh('0000000000000004'), 'message_flags': b'\x00', 'channel_flags': b'\x01', 'cltv_expiry_delta': 10, 'htlc_minimum_msat': 250, 'fee_base_msat': 100, 'fee_proportional_millionths': 150, 'chain_hash': BitcoinTestnet.rev_genesis_bytes(), 'timestamp': 0})
        cdb.add_channel_update({'short_channel_id': bfh('0000000000000004'), 'message_flags': b'\x00', 'channel_flags': b'\x00', 'cltv_expiry_delta': 10, 'htlc_minimum_msat': 250, 'fee_base_msat': 100, 'fee_proportional_millionths': 150, 'chain_hash': BitcoinTestnet.rev_genesis_bytes(), 'timestamp': 0})
        cdb.add_channel_update({'short_channel_id': bfh('0000000000000005'), 'message_flags': b'\x00', 'channel_flags': b'\x01', 'cltv_expiry_delta': 10, 'htlc_minimum_msat': 250, 'fee_base_msat': 100, 'fee_proportional_millionths': 150, 'chain_hash': BitcoinTestnet.rev_genesis_bytes(), 'timestamp': 0})
        cdb.add_channel_update({'short_channel_id': bfh('0000000000000005'), 'message_flags': b'\x00', 'channel_flags': b'\x00', 'cltv_expiry_delta': 10, 'htlc_minimum_msat': 250, 'fee_base_msat': 100, 'fee_proportional_millionths': 999, 'chain_hash': BitcoinTestnet.rev_genesis_bytes(), 'timestamp': 0})
        cdb.add_channel_update({'short_channel_id': bfh('0000000000000006'), 'message_flags': b'\x00', 'channel_flags': b'\x00', 'cltv_expiry_delta': 10, 'htlc_minimum_msat': 250, 'fee_base_msat': 100, 'fee_proportional_millionths': 99999999, 'chain_hash': BitcoinTestnet.rev_genesis_bytes(), 'timestamp': 0})
        cdb.add_channel_update({'short_channel_id': bfh('0000000000000006'), 'message_flags': b'\x00', 'channel_flags': b'\x01', 'cltv_expiry_delta': 10, 'htlc_minimum_msat': 250, 'fee_base_msat': 100, 'fee_proportional_millionths': 150, 'chain_hash': BitcoinTestnet.rev_genesis_bytes(), 'timestamp': 0})
        path = path_finder.find_path_for_payment(b'\x02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', b'\x02eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee', 100000)
        self.assertEqual([PathEdge(node_id=b'\x02bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', short_channel_id=bfh('0000000000000003')),
                          PathEdge(node_id=b'\x02eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee', short_channel_id=bfh('0000000000000002')),
                         ], path)
        start_node = b'\x02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        route = path_finder.create_route_from_path(path, start_node)
        self.assertEqual(b'\x02bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', route[0].node_id)
        self.assertEqual(bfh('0000000000000003'),                 route[0].short_channel_id)

        # need to duplicate tear_down here, as we also need to wait for the sql thread to stop
        self.asyncio_loop.call_soon_threadsafe(self._stop_loop.set_result, 1)
        self._loop_thread.join(timeout=1)
        cdb.sql_thread.join(timeout=1)

    @needs_test_with_all_chacha20_implementations
    def test_new_onion_packet_legacy(self):
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
            OnionHopsDataSingle(is_tlv_payload=False, payload={
                "amt_to_forward": {"amt_to_forward": 0},
                "outgoing_cltv_value": {"outgoing_cltv_value": 0},
                "short_channel_id": {"short_channel_id": bfh('0000000000000000')},
            }),
            OnionHopsDataSingle(is_tlv_payload=False, payload={
                "amt_to_forward": {"amt_to_forward": 1},
                "outgoing_cltv_value": {"outgoing_cltv_value": 1},
                "short_channel_id": {"short_channel_id": bfh('0101010101010101')},
            }),
            OnionHopsDataSingle(is_tlv_payload=False, payload={
                "amt_to_forward": {"amt_to_forward": 2},
                "outgoing_cltv_value": {"outgoing_cltv_value": 2},
                "short_channel_id": {"short_channel_id": bfh('0202020202020202')},
            }),
            OnionHopsDataSingle(is_tlv_payload=False, payload={
                "amt_to_forward": {"amt_to_forward": 3},
                "outgoing_cltv_value": {"outgoing_cltv_value": 3},
                "short_channel_id": {"short_channel_id": bfh('0303030303030303')},
            }),
            OnionHopsDataSingle(is_tlv_payload=False, payload={
                "amt_to_forward": {"amt_to_forward": 4},
                "outgoing_cltv_value": {"outgoing_cltv_value": 4},
                "short_channel_id": {"short_channel_id": bfh('0404040404040404')},
            }),
        ]
        packet = new_onion_packet(payment_path_pubkeys, session_key, hops_data, associated_data)
        self.assertEqual(bfh('0002eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619e5f14350c2a76fc232b5e46d421e9615471ab9e0bc887beff8c95fdb878f7b3a71e87f9aab8f6378c6ff744c1f34b393ad28d065b535c1a8668d85d3b34a1b3befd10f7d61ab590531cf08000178a333a347f8b4072e216400406bdf3bf038659793a1f9e7abc789266cc861cabd95818c0fc8efbdfdc14e3f7c2bc7eb8d6a79ef75ce721caad69320c3a469a202f3e468c67eaf7a7cda226d0fd32f7b48084dca885d014698cf05d742557763d9cb743faeae65dcc79dddaecf27fe5942be5380d15e9a1ec866abe044a9ad635778ba61fc0776dc832b39451bd5d35072d2269cf9b040a2a2fba158a0d8085926dc2e44f0c88bf487da56e13ef2d5e676a8589881b4869ed4c7f0218ff8c6c7dd7221d189c65b3b9aaa71a01484b122846c7c7b57e02e679ea8469b70e14fe4f70fee4d87b910cf144be6fe48eef24da475c0b0bcc6565a9f99728426ce2380a9580e2a9442481ceae7679906c30b1a0e21a10f26150e0645ab6edfdab1ce8f8bea7b1dee511c5fd38ac0e702c1c15bb86b52bca1b71e15b96982d262a442024c33ceb7dd8f949063c2e5e613e873250e2f8708bd4e1924abd45f65c2fa5617bfb10ee9e4a42d6b5811acc8029c16274f937dac9e8817c7e579fdb767ffe277f26d413ced06b620ede8362081da21cf67c2ca9d6f15fe5bc05f82f5bb93f8916bad3d63338ca824f3bbc11b57ce94a5fa1bc239533679903d6fec92a8c792fd86e2960188c14f21e399cfd72a50c620e10aefc6249360b463df9a89bf6836f4f26359207b765578e5ed76ae9f31b1cc48324be576e3d8e44d217445dba466f9b6293fdf05448584eb64f61e02903f834518622b7d4732471c6e0e22e22d1f45e31f0509eab39cdea5980a492a1da2aaac55a98a01216cd4bfe7abaa682af0fbff2dfed030ba28f1285df750e4d3477190dd193f8643b61d8ac1c427d590badb1f61a05d480908fbdc7c6f0502dd0c4abb51d725e92f95da2a8facb79881a844e2026911adcc659d1fb20a2fce63787c8bb0d9f6789c4b231c76da81c3f0718eb7156565a081d2be6b4170c0e0bcebddd459f53db2590c974bca0d705c055dee8c629bf854a5d58edc85228499ec6dde80cce4c8910b81b1e9e8b0f43bd39c8d69c3a80672729b7dc952dd9448688b6bd06afc2d2819cda80b66c57b52ccf7ac1a86601410d18d0c732f69de792e0894a9541684ef174de766fd4ce55efea8f53812867be6a391ac865802dbc26d93959df327ec2667c7256aa5a1d3c45a69a6158f285d6c97c3b8eedb09527848500517995a9eae4cd911df531544c77f5a9a2f22313e3eb72ca7a07dba243476bc926992e0d1e58b4a2fc8c7b01e0cad726237933ea319bad7537d39f3ed635d1e6c1d29e97b3d2160a09e30ee2b65ac5bce00996a73c008bcf351cecb97b6833b6d121dcf4644260b2946ea204732ac9954b228f0beaa15071930fd9583dfc466d12b5f0eeeba6dcf23d5ce8ae62ee5796359d97a4a15955c778d868d0ef9991d9f2833b5bb66119c5f8b396fd108baed7906cbb3cc376d13551caed97fece6f42a4c908ee279f1127fda1dd3ee77d8de0a6f3c135fa3f1cffe38591b6738dc97b55f0acc52be9753ce53e64d7e497bb00ca6123758df3b68fad99e35c04389f7514a8e36039f541598a417275e77869989782325a15b5342ac5011ff07af698584b476b35d941a4981eac590a07a092bb50342da5d3341f901aa07964a8d02b623c7b106dd0ae50bfa007a22d46c8772fa55558176602946cb1d11ea5460db7586fb89c6d3bcd3ab6dd20df4a4db63d2e7d52380800ad812b8640887e027e946df96488b47fbc4a4fadaa8beda4abe446fafea5403fae2ef'),
                         packet.to_bytes())

    @needs_test_with_all_chacha20_implementations
    def test_new_onion_packet_mixed_payloads(self):
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
            OnionHopsDataSingle(is_tlv_payload=False, payload={
                "amt_to_forward": {"amt_to_forward": 0},
                "outgoing_cltv_value": {"outgoing_cltv_value": 0},
                "short_channel_id": {"short_channel_id": bfh('0000000000000000')},
            }),
            OnionHopsDataSingle(is_tlv_payload=True),
            OnionHopsDataSingle(is_tlv_payload=True),
            OnionHopsDataSingle(is_tlv_payload=True),
            OnionHopsDataSingle(is_tlv_payload=False, payload={
                "amt_to_forward": {"amt_to_forward": 4},
                "outgoing_cltv_value": {"outgoing_cltv_value": 4},
                "short_channel_id": {"short_channel_id": bfh('0404040404040404')},
            }),
        ]
        hops_data[1]._raw_bytes_payload = bfh("0101010101010101000000000000000100000001")
        hops_data[2]._raw_bytes_payload = bfh("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
        hops_data[3]._raw_bytes_payload = bfh("0303030303030303000000000000000300000003")
        packet = new_onion_packet(payment_path_pubkeys, session_key, hops_data, associated_data)
        self.assertEqual(bfh('0002eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619e5f14350c2a76fc232b5e46d421e9615471ab9e0bc887beff8c95fdb878f7b3a710f8eaf9ccc768f66bb5dec1f7827f33c43fe2ddd05614c8283aa78e9e7573f87c50f7d61ab590531cf08000178a333a347f8b4072e1cea42da7552402b10765adae3f581408f35ff0a71a34b78b1d8ecae77df96c6404bae9a8e8d7178977d7094a1ae549f89338c0777551f874159eb42d3a59fb9285ad4e24883f27de23942ec966611e99bee1cee503455be9e8e642cef6cef7b9864130f692283f8a973d47a8f1c1726b6e59969385975c766e35737c8d76388b64f748ee7943ffb0e2ee45c57a1abc40762ae598723d21bd184e2b338f68ebff47219357bd19cd7e01e2337b806ef4d717888e129e59cd3dc31e6201ccb2fd6d7499836f37a993262468bcb3a4dcd03a22818aca49c6b7b9b8e9e870045631d8e039b066ff86e0d1b7291f71cefa7264c70404a8e538b566c17ccc5feab231401e6c08a01bd5edfc1aa8e3e533b96e82d1f91118d508924b923531929aea889fcdf057f5995d9731c4bf796fb0e41c885d488dcbc68eb742e27f44310b276edc6f652658149e7e9ced4edde5d38c9b8f92e16f6b4ab13d710ee5c193921909bdd75db331cd9d7581a39fca50814ed8d9d402b86e7f8f6ac2f3bca8e6fe47eb45fbdd3be21a8a8d200797eae3c9a0497132f92410d804977408494dff49dd3d8bce248e0b74fd9e6f0f7102c25ddfa02bd9ad9f746abbfa3379834bc2380d58e9d23237821475a1874484783a15d68f47d3dc339f38d9bf925655d5c946778680fd6d1f062f84128895aff09d35d6c92cca63d3f95a9ee8f2a84f383b4d6a087533e65de12fc8dcaf85777736a2088ff4b22462265028695b37e70963c10df8ef2458756c73007dc3e544340927f9e9f5ea4816a9fd9832c311d122e9512739a6b4714bba590e31caa143ce83cb84b36c738c60c3190ff70cd9ac286a9fd2ab619399b68f1f7447be376ce884b5913c8496d01cbf7a44a60b6e6747513f69dc538f340bc1388e0fde5d0c1db50a4dcb9cc0576e0e2474e4853af9623212578d502757ffb2e0e749695ed70f61c116560d0d4154b64dcf3cbf3c91d89fb6dd004dc19588e3479fcc63c394a4f9e8a3b8b961fce8a532304f1337f1a697a1bb14b94d2953f39b73b6a3125d24f27fcd4f60437881185370bde68a5454d816e7a70d4cea582effab9a4f1b730437e35f7a5c4b769c7b72f0346887c1e63576b2f1e2b3706142586883f8cf3a23595cc8e35a52ad290afd8d2f8bcd5b4c1b891583a4159af7110ecde092079209c6ec46d2bda60b04c519bb8bc6dffb5c87f310814ef2f3003671b3c90ddf5d0173a70504c2280d31f17c061f4bb12a978122c8a2a618bb7d1edcf14f84bf0fa181798b826a254fca8b6d7c81e0beb01bd77f6461be3c8647301d02b04753b0771105986aa0cbc13f7718d64e1b3437e8eef1d319359914a7932548c91570ef3ea741083ca5be5ff43c6d9444d29df06f76ec3dc936e3d180f4b6d0fbc495487c7d44d7c8fe4a70d5ff1461d0d9593f3f898c919c363fa18341ce9dae54f898ccf3fe792136682272941563387263c51b2a2f32363b804672cc158c9230472b554090a661aa81525d11876eefdcc45442249e61e07284592f1606491de5c0324d3af4be035d7ede75b957e879e9770cdde2e1bbc1ef75d45fe555f1ff6ac296a2f648eeee59c7c08260226ea333c285bcf37a9bbfa57ba2ab8083c4be6fc2ebe279537d22da96a07392908cf22b233337a74fe5c603b51712b43c3ee55010ee3d44dd9ba82bba3145ec358f863e04bbfa53799a7a9216718fd5859da2f0deb77b8e315ad6868fdec9400f45a48e6dc8ddbaeb3'),
                         packet.to_bytes())

    @needs_test_with_all_chacha20_implementations
    def test_process_onion_packet_mixed_payloads(self):
        # this test is not from bolt-04, but is based on the one there;
        # here the TLV payloads are actually sane...
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
            OnionHopsDataSingle(is_tlv_payload=False, payload={
                "amt_to_forward": {"amt_to_forward": 0},
                "outgoing_cltv_value": {"outgoing_cltv_value": 0},
                "short_channel_id": {"short_channel_id": bfh('0000000000000000')},
            }),
            OnionHopsDataSingle(is_tlv_payload=True, payload={
                "amt_to_forward": {"amt_to_forward": 1},
                "outgoing_cltv_value": {"outgoing_cltv_value": 1},
                "short_channel_id": {"short_channel_id": bfh('0101010101010101')},
            }),
            OnionHopsDataSingle(is_tlv_payload=True, payload={
                "amt_to_forward": {"amt_to_forward": 2},
                "outgoing_cltv_value": {"outgoing_cltv_value": 2},
                "short_channel_id": {"short_channel_id": bfh('0202020202020202')},
            }),
            OnionHopsDataSingle(is_tlv_payload=True, payload={
                "amt_to_forward": {"amt_to_forward": 3},
                "outgoing_cltv_value": {"outgoing_cltv_value": 3},
                "short_channel_id": {"short_channel_id": bfh('0303030303030303')},
            }),
            OnionHopsDataSingle(is_tlv_payload=False, payload={
                "amt_to_forward": {"amt_to_forward": 4},
                "outgoing_cltv_value": {"outgoing_cltv_value": 4},
                "short_channel_id": {"short_channel_id": bfh('0404040404040404')},
            }),
        ]
        packet = new_onion_packet(payment_path_pubkeys, session_key, hops_data, associated_data)
        self.assertEqual(bfh('0002eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619e5f14350c2a76fc232b5e46d421e9615471ab9e0bc887beff8c95fdb878f7b3a71bde5adfa90b337f34616d8673d09dd055937273045566ce537ffbe3f9d1f263dc10c7d61ae590536c609010079a232a247922a5395359a63dfbefb85f40317e23254f3023f7d4a98f746c9ab06647645ce55c67308e3c77dc87a1caeac51b03b23c60f05e536e1d757c8c1093e34accfc4f97b5920f6dd2069d5b9ddbb384c3ac575e999a92a4434470ab0aa040c4c3cace3162a405842a88be783e64fad54bd6727c23fc446b7ec0dc3eec5a03eb6c70ec2784911c9e6d274322ec465f0972eb8e771b149f319582ba64dbc2b8e56a3ea79002801c09354f1541cf79bd1dccf5d6bd6b6bacc87a0f24ce497e14e8037e5a79fb4d9ca63fe47f17765963e8f17468a5eaec19a6cca2bfc4e4a366fea3a92112a945856be55e45197ecbab523025e7589529c30cc8addc8fa39d23ef64fa2e51a219c3bd4d3c484832f8e5af16bc46cdba0403991f4fc1b74beef857acf15fefed82ac8678ca66d26262c681beddfdb485aa498813b1a6c5833f1339c1a35244ab76baa0ccaf681ec1f54004e387063335648a77b65d90dde74f1c4b0a729ca25fa53256f7db6d35818b4e5910ba78ec69cf3646bf248ef46cf9cc33062662de2afe4dcf005951b85fd759429fa1ae490b78b14132ccb791232a6c680f03634c0136817f51bf9603a0dba405e7b347830be4327fceccd4734456842b82cf6275393b279bc6ac93d743e00a2d6042960089f70c782ce554b9f73eeeefeea50df7f6f80de1c4e869a7b502f9a5df30d1175402fa780812d35c6d489a30bb0cea53a1088669a238cccf416ecb37f8d8e6ea1327b64979d48e937db69a44a902923a75113685a4aca4a8d9c62b388b48d9c9e2ab9c2df4d529223144de6e16f2dd95a063da79163b3fe006a80263cde4410648f7c3e1f4a7707f82eb0e209002d972c7e57b4ff8ce063fa7b4140f52f569f0cc8793a97a170613efb6b27ba3a0370f8ea74fc0d6aabba54e0ee967abc70e87b580d2aac244236b7752db9d83b159afc1faf6b44b697643235bf59e99f43428caff409d26b9139538865b1f5cf4699f9296088aca461209024ad1dd00e3566e4fde2117b7b3ffced6696b735816a00199890056de86dcbb1b930228143dbf04f07c0eb34370089ea55c43b2c4546cbe1ff0c3a6217d994af9b4225f4b5acb1e3129f5f5b98d381a4692a8561c670b2ee95869f9614e76bb07f623c5194e1c9d26334026f8f5437ec1cde526f914fa094a465f0adcea32b79bfa44d2562536b0d8366da9ee577666c1d5e39615444ca5c900b8199fafac002b8235688eaa0c6887475a913b37d9a4ed43a894ea4576102e5d475ae0b962240ea95fc367b7ac214a4f8682448a9c0d2eea35727bdedc235a975ecc8148a5b03d6291a051dbefe19c8b344d2713c6664dd94ced53c6be39a837fbf1169cca6a12b0a2710f443ba1afeecb51e94236b2a6ed1c2f365b595443b1515de86dcb8c67282807789b47c331cde2fdd721262bef165fa96b7919d11bc5f2022f5affffdd747c7dbe3de8add829a0a8913519fdf7dba4e8a7a25456d2d559746d39ea6ffa31c7b904792fb734bba30f2e1adf7457a994513a1807785fe7b22bf419d1f407f8e2db8b22c0512b078c0cfdfd599e6c4a9d0cc624b9e24b87f30541c3248cd6643df15d251775cc457df4ea6b4e4c5990d87541028c6f0eb28502db1c11a92797168d0b68cb0a0d345b3a3ad05fc4016862f403c64670c41a2c0c6d4e384f5f7da6a204a24530a51182fd7164f120e74a78decb1ab6cda6b9cfc68ac0a35f7a57e750ead65a8e0429cc16e733b9e4feaea25d06c1a4768'),
                         packet.to_bytes())
        for i, privkey in enumerate(payment_path_privkeys):
            processed_packet = process_onion_packet(packet, associated_data, privkey)
            self.assertEqual(hops_data[i].to_bytes(), processed_packet.hop_data.to_bytes())
            packet = processed_packet.next_packet

    @needs_test_with_all_chacha20_implementations
    def test_process_onion_packet_legacy(self):
        # this test is not from bolt-04, but is based on the one there;
        # except here we have the privkeys for these pubkeys
        payment_path_pubkeys = [
            bfh('03d75c0ee70f68d73d7d13aeb6261d8ace11416800860c7e59407afe4e2e2d42bb'),
            bfh('03960a0b830c7b8e76de745b819f252c62508346196b916f5e813cdb0773283cce'),
            bfh('0385620e0a571cbc3552620f8bf1bdcdab2d1a4a59c36fa10b8249114ccbdda40d'),
            bfh('02ee242cf6c38b7285f0152c33804ff777f5c51fd352ca8132e845e2cf23b3d8ba'),
            bfh('025c585fd2e174bf8245b2b4a119e52a417688904228643ea3edaa1728bf2a258e'),
        ]
        payment_path_privkeys = [
            bfh('3463a278617b3dd83f79bda7f97673f12609c54386e1f0d2b67b1c6354fda14e'),
            bfh('7e1255fddb52db1729fc3ceb21a46f95b8d9fe94cc83425e936a6c5223bb679d'),
            bfh('c7ce8c1462c311eec24dff9e2532ac6241e50ae57e7d1833af21942136972f23'),
            bfh('3d885f374d79a5e777459b083f7818cdc9493e5c4994ac9c7b843de8b70be661'),
            bfh('dd72ab44729527b7942e195e7a835e7c71f9c0ff61844eb21274d9c26166a8f8'),
        ]
        session_key = bfh('4141414141414141414141414141414141414141414141414141414141414141')
        associated_data = bfh('4242424242424242424242424242424242424242424242424242424242424242')
        hops_data = [
            OnionHopsDataSingle(is_tlv_payload=False, payload={
                "amt_to_forward": {"amt_to_forward": 0},
                "outgoing_cltv_value": {"outgoing_cltv_value": 0},
                "short_channel_id": {"short_channel_id": bfh('0000000000000000')},
            }),
            OnionHopsDataSingle(is_tlv_payload=False, payload={
                "amt_to_forward": {"amt_to_forward": 1},
                "outgoing_cltv_value": {"outgoing_cltv_value": 1},
                "short_channel_id": {"short_channel_id": bfh('0101010101010101')},
            }),
            OnionHopsDataSingle(is_tlv_payload=False, payload={
                "amt_to_forward": {"amt_to_forward": 2},
                "outgoing_cltv_value": {"outgoing_cltv_value": 2},
                "short_channel_id": {"short_channel_id": bfh('0202020202020202')},
            }),
            OnionHopsDataSingle(is_tlv_payload=False, payload={
                "amt_to_forward": {"amt_to_forward": 3},
                "outgoing_cltv_value": {"outgoing_cltv_value": 3},
                "short_channel_id": {"short_channel_id": bfh('0303030303030303')},
            }),
            OnionHopsDataSingle(is_tlv_payload=False, payload={
                "amt_to_forward": {"amt_to_forward": 4},
                "outgoing_cltv_value": {"outgoing_cltv_value": 4},
                "short_channel_id": {"short_channel_id": bfh('0404040404040404')},
            }),
        ]
        packet = new_onion_packet(payment_path_pubkeys, session_key, hops_data, associated_data)
        self.assertEqual(bfh('0002eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f28368661954176cd9869da33d713aa219fcef1e5c806fef11e696bcc66844de8271c27974a049d041ffc5be934b8575c6ff4371f2f88d4edfd73e445534d3f6ae15b64b0d8308390bebf8d149002e31bdc283056477ba27c8054c248ad7306de31663a7c99ec65b251704041f7c4cc40a0016ba172fbf805ec59132a65a4c7eb1f41337931c5df0f840704535729262d30c6132d1b390f073edec8fa057176c6268b6ad06a82ff0229c3be444ee50b40686bc1306838b93c65771de1b6ca05dace1ff9814a6e58b2dd71e8244c83e28b2ed5a3b09e9e7df5c8c747e5765ba366a4f7407a6c6b0a32fb5521cce7cd668f7434c909c1be027d8595d85893e5f612c49a93eeeed80a78bab9c4a621ce0f6f5df7d64a9c8d435db19de192d9db522c7f7b4e201fc1b61a9bd3efd062ae24455d463818b01e2756c7d0691bc3ac4c017be34c9a8b2913bb1b94056bf7a21730afc3f254ffa41ca140a5d87ff470f536d08619e8004d50de2fe5954d6aa4a00570da397ba15ae9ea4d7d1f136256a9093f0a787a36cbb3520b6a3cf4d1b13b16bf399c4b0326da1382a90bd79cf92f4808c8c84eaa50a8ccf44acbde0e35b2e6b72858c8446d6a05f3ba70fb4adc70af27cea9bd1dc1ea35fb3cc236b8b9b69b614903db339b22ad5dc2ddda7ac65fd7de24e60b7dbba7aafc9d26c0f9fcb03f1bb85dfc21762f862620651db52ea703ae60aa7e07febf11caa95c4245a4b37eb9c233e1ab1604fb85849e7f49cb9f7c681c4d91b7c320eb4b89b9c6bcb636ceadda59f6ed47aa5b1ea0a946ea98f6ad2614e79e0d4ef96d6d65903adb0479709e03008bbdf3355dd87df7d68965fdf1ad5c68b6dc2761b96b10f8eb4c0329a646bf38cf4702002e61565231b4ac7a9cde63d23f7b24c9d42797b3c434558d71ed8bf9fcab2c2aee3e8b38c19f9edc3ad3dfe9ebba7387ce4764f97ed1c1a83552dff8315546761479a6f929c39bcca0891d4a967d1b77fa80feed6ae74ac82ed5fb7be225c3f2b0ebdc652afc2255c47bc318ac645bbf19c0819ff527ff6708a78e19c8ca3dc8087035e10d5ac976e84b71148586c8a5a7b26ed11b5b401ce7bb2ac532207eaa24d2f53aaa8024607da764d807c91489e82fcad04e6b8992a507119367f576ee5ffe6807d5723d60234d4c3f94adce0acfed9dba535ca375446a4e9b500b74ad2a66e1c6b0fc38933f282d3a4a877bceceeca52b46e731ca51a9534224a883c4a45587f973f73a22069a4154b1da03d307d8575c821bef0eef87165b9a1bbf902ecfca82ddd805d10fbb7147b496f6772f01e9bf542b00288f3a6efab32590c1f34535ece03a0587ca187d27a98d4c9aa7c044794baa43a81abbe307f51d0bda6e7b4cf62c4be553b176321777e7fd483d6cec16df137293aaf3ad53608e1c7831368675bb9608db04d5c859e7714edab3d2389837fa071f0795adfabc51507b1adbadc7f83e80bd4e4eb9ed1a89c9e0a6dc16f38d55181d5666b02150651961aab34faef97d80fa4e1960864dfec3b687fd4eadf7aa6c709cb4698ae86ae112f386f33731d996b9d41926a2e820c6ba483a61674a4bae03af37e872ffdc0a9a8a034327af17e13e9e7ac619c9188c2a5c12a6ebf887721455c0e2822e67a621ed49f1f50dfc38b71c29d0224954e84ced086c80de552cca3a14adbe43035901225bafc3db3b672c780e4fa12b59221f93690527efc16a28e7c63d1a99fc881f023b03a157076a7e999a715ed37521adb483e2477d75ba5a55d4abad22b024c5317334b6544f15971591c774d896229e4e668fc1c7958fbd76fa0b152a6f14c95692083badd066b6621367fd73d88ba8d860566e6d55b871d80c68296b80ae8847d'),
                         packet.to_bytes())
        for i, privkey in enumerate(payment_path_privkeys):
            processed_packet = process_onion_packet(packet, associated_data, privkey)
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
