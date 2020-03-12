import unittest
import tempfile
import shutil
import asyncio

from electrum.util import bh2u, bfh, create_and_start_event_loop
from electrum.lnonion import (OnionHopsDataSingle, new_onion_packet, OnionPerHop,
                              process_onion_packet, _decode_onion_error, decode_onion_error,
                              OnionFailureCode)
from electrum import bitcoin, lnrouter
from electrum.constants import BitcoinTestnet
from electrum.simple_config import SimpleConfig

from . import TestCaseForTestnet
from .test_bitcoin import needs_test_with_all_chacha20_implementations


class Test_LNRouter(TestCaseForTestnet):

    #@staticmethod
    #def parse_witness_list(witness_bytes):
    #    amount_witnesses = witness_bytes[0]
    #    witness_bytes = witness_bytes[1:]
    #    res = []
    #    for i in range(amount_witnesses):
    #        witness_length = witness_bytes[0]
    #        this_witness = witness_bytes[1:witness_length+1]
    #        assert len(this_witness) == witness_length
    #        witness_bytes = witness_bytes[witness_length+1:]
    #        res += [bytes(this_witness)]
    #    assert witness_bytes == b"", witness_bytes
    #    return res

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
        self.assertEqual([(b'\x02bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', b'\x00\x00\x00\x00\x00\x00\x00\x03'),
                          (b'\x02eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee', b'\x00\x00\x00\x00\x00\x00\x00\x02'),
                         ], path)
        start_node = b'\x02bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
        route = path_finder.create_route_from_path(path, start_node)
        self.assertEqual(route[0].node_id, start_node)
        self.assertEqual(route[0].short_channel_id, bfh('0000000000000003'))

        # need to duplicate tear_down here, as we also need to wait for the sql thread to stop
        self.asyncio_loop.call_soon_threadsafe(self._stop_loop.set_result, 1)
        self._loop_thread.join(timeout=1)
        cdb.sql_thread.join(timeout=1)

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
            OnionHopsDataSingle(OnionPerHop(
                bfh('0000000000000000'), bfh('0000000000000000'), bfh('00000000')
            )),
            OnionHopsDataSingle(OnionPerHop(
                bfh('0101010101010101'), bfh('0000000000000001'), bfh('00000001')
            )),
            OnionHopsDataSingle(OnionPerHop(
                bfh('0202020202020202'), bfh('0000000000000002'), bfh('00000002')
            )),
            OnionHopsDataSingle(OnionPerHop(
                bfh('0303030303030303'), bfh('0000000000000003'), bfh('00000003')
            )),
            OnionHopsDataSingle(OnionPerHop(
                bfh('0404040404040404'), bfh('0000000000000004'), bfh('00000004')
            )),
        ]
        packet = new_onion_packet(payment_path_pubkeys, session_key, hops_data, associated_data)
        self.assertEqual(bfh('0002eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619e5f14350c2a76fc232b5e46d421e9615471ab9e0bc887beff8c95fdb878f7b3a71e87f9aab8f6378c6ff744c1f34b393ad28d065b535c1a8668d85d3b34a1b3befd10f7d61ab590531cf08000178a333a347f8b4072e216400406bdf3bf038659793a1f9e7abc789266cc861cabd95818c0fc8efbdfdc14e3f7c2bc7eb8d6a79ef75ce721caad69320c3a469a202f3e468c67eaf7a7cda226d0fd32f7b48084dca885d014698cf05d742557763d9cb743faeae65dcc79dddaecf27fe5942be5380d15e9a1ec866abe044a9ad635778ba61fc0776dc832b39451bd5d35072d2269cf9b040a2a2fba158a0d8085926dc2e44f0c88bf487da56e13ef2d5e676a8589881b4869ed4c7f0218ff8c6c7dd7221d189c65b3b9aaa71a01484b122846c7c7b57e02e679ea8469b70e14fe4f70fee4d87b910cf144be6fe48eef24da475c0b0bcc6565a9f99728426ce2380a9580e2a9442481ceae7679906c30b1a0e21a10f26150e0645ab6edfdab1ce8f8bea7b1dee511c5fd38ac0e702c1c15bb86b52bca1b71e15b96982d262a442024c33ceb7dd8f949063c2e5e613e873250e2f8708bd4e1924abd45f65c2fa5617bfb10ee9e4a42d6b5811acc8029c16274f937dac9e8817c7e579fdb767ffe277f26d413ced06b620ede8362081da21cf67c2ca9d6f15fe5bc05f82f5bb93f8916bad3d63338ca824f3bbc11b57ce94a5fa1bc239533679903d6fec92a8c792fd86e2960188c14f21e399cfd72a50c620e10aefc6249360b463df9a89bf6836f4f26359207b765578e5ed76ae9f31b1cc48324be576e3d8e44d217445dba466f9b6293fdf05448584eb64f61e02903f834518622b7d4732471c6e0e22e22d1f45e31f0509eab39cdea5980a492a1da2aaac55a98a01216cd4bfe7abaa682af0fbff2dfed030ba28f1285df750e4d3477190dd193f8643b61d8ac1c427d590badb1f61a05d480908fbdc7c6f0502dd0c4abb51d725e92f95da2a8facb79881a844e2026911adcc659d1fb20a2fce63787c8bb0d9f6789c4b231c76da81c3f0718eb7156565a081d2be6b4170c0e0bcebddd459f53db2590c974bca0d705c055dee8c629bf854a5d58edc85228499ec6dde80cce4c8910b81b1e9e8b0f43bd39c8d69c3a80672729b7dc952dd9448688b6bd06afc2d2819cda80b66c57b52ccf7ac1a86601410d18d0c732f69de792e0894a9541684ef174de766fd4ce55efea8f53812867be6a391ac865802dbc26d93959df327ec2667c7256aa5a1d3c45a69a6158f285d6c97c3b8eedb09527848500517995a9eae4cd911df531544c77f5a9a2f22313e3eb72ca7a07dba243476bc926992e0d1e58b4a2fc8c7b01e0cad726237933ea319bad7537d39f3ed635d1e6c1d29e97b3d2160a09e30ee2b65ac5bce00996a73c008bcf351cecb97b6833b6d121dcf4644260b2946ea204732ac9954b228f0beaa15071930fd9583dfc466d12b5f0eeeba6dcf23d5ce8ae62ee5796359d97a4a15955c778d868d0ef9991d9f2833b5bb66119c5f8b396fd108baed7906cbb3cc376d13551caed97fece6f42a4c908ee279f1127fda1dd3ee77d8de0a6f3c135fa3f1cffe38591b6738dc97b55f0acc52be9753ce53e64d7e497bb00ca6123758df3b68fad99e35c04389f7514a8e36039f541598a417275e77869989782325a15b5342ac5011ff07af698584b476b35d941a4981eac590a07a092bb50342da5d3341f901aa07964a8d02b623c7b106dd0ae50bfa007a22d46c8772fa55558176602946cb1d11ea5460db7586fb89c6d3bcd3ab6dd20df4a4db63d2e7d52380800ad812b8640887e027e946df96488b47fbc4a4fadaa8beda4abe446fafea5403fae2ef'),
                         packet.to_bytes())

    @needs_test_with_all_chacha20_implementations
    def test_process_onion_packet(self):
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
            OnionHopsDataSingle(OnionPerHop(
                bfh('0000000000000000'), bfh('0000000000000000'), bfh('00000000')
            )),
            OnionHopsDataSingle(OnionPerHop(
                bfh('0101010101010101'), bfh('0000000000000001'), bfh('00000001')
            )),
            OnionHopsDataSingle(OnionPerHop(
                bfh('0202020202020202'), bfh('0000000000000002'), bfh('00000002')
            )),
            OnionHopsDataSingle(OnionPerHop(
                bfh('0303030303030303'), bfh('0000000000000003'), bfh('00000003')
            )),
            OnionHopsDataSingle(OnionPerHop(
                bfh('0404040404040404'), bfh('0000000000000004'), bfh('00000004')
            )),
        ]
        packet = new_onion_packet(payment_path_pubkeys, session_key, hops_data, associated_data)
        self.assertEqual(bfh('0002eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f28368661954176cd9869da33d713aa219fcef1e5c806fef11e696bcc66844de8271c27974a049d041ffc5be934b8575c6ff4371f2f88d4edfd73e445534d3f6ae15b64b0d8308390bebf8d149002e31bdc283056477ba27c8054c248ad7306de31663a7c99ec65b251704041f7c4cc40a0016ba172fbf805ec59132a65a4c7eb1f41337931c5df0f840704535729262d30c6132d1b390f073edec8fa057176c6268b6ad06a82ff0229c3be444ee50b40686bc1306838b93c65771de1b6ca05dace1ff9814a6e58b2dd71e8244c83e28b2ed5a3b09e9e7df5c8c747e5765ba366a4f7407a6c6b0a32fb5521cce7cd668f7434c909c1be027d8595d85893e5f612c49a93eeeed80a78bab9c4a621ce0f6f5df7d64a9c8d435db19de192d9db522c7f7b4e201fc1b61a9bd3efd062ae24455d463818b01e2756c7d0691bc3ac4c017be34c9a8b2913bb1b94056bf7a21730afc3f254ffa41ca140a5d87ff470f536d08619e8004d50de2fe5954d6aa4a00570da397ba15ae9ea4d7d1f136256a9093f0a787a36cbb3520b6a3cf4d1b13b16bf399c4b0326da1382a90bd79cf92f4808c8c84eaa50a8ccf44acbde0e35b2e6b72858c8446d6a05f3ba70fb4adc70af27cea9bd1dc1ea35fb3cc236b8b9b69b614903db339b22ad5dc2ddda7ac65fd7de24e60b7dbba7aafc9d26c0f9fcb03f1bb85dfc21762f862620651db52ea703ae60aa7e07febf11caa95c4245a4b37eb9c233e1ab1604fb85849e7f49cb9f7c681c4d91b7c320eb4b89b9c6bcb636ceadda59f6ed47aa5b1ea0a946ea98f6ad2614e79e0d4ef96d6d65903adb0479709e03008bbdf3355dd87df7d68965fdf1ad5c68b6dc2761b96b10f8eb4c0329a646bf38cf4702002e61565231b4ac7a9cde63d23f7b24c9d42797b3c434558d71ed8bf9fcab2c2aee3e8b38c19f9edc3ad3dfe9ebba7387ce4764f97ed1c1a83552dff8315546761479a6f929c39bcca0891d4a967d1b77fa80feed6ae74ac82ed5fb7be225c3f2b0ebdc652afc2255c47bc318ac645bbf19c0819ff527ff6708a78e19c8ca3dc8087035e10d5ac976e84b71148586c8a5a7b26ed11b5b401ce7bb2ac532207eaa24d2f53aaa8024607da764d807c91489e82fcad04e6b8992a507119367f576ee5ffe6807d5723d60234d4c3f94adce0acfed9dba535ca375446a4e9b500b74ad2a66e1c6b0fc38933f282d3a4a877bceceeca52b46e731ca51a9534224a883c4a45587f973f73a22069a4154b1da03d307d8575c821bef0eef87165b9a1bbf902ecfca82ddd805d10fbb7147b496f6772f01e9bf542b00288f3a6efab32590c1f34535ece03a0587ca187d27a98d4c9aa7c044794baa43a81abbe307f51d0bda6e7b4cf62c4be553b176321777e7fd483d6cec16df137293aaf3ad53608e1c7831368675bb9608db04d5c859e7714edab3d2389837fa071f0795adfabc51507b1adbadc7f83e80bd4e4eb9ed1a89c9e0a6dc16f38d55181d5666b02150651961aab34faef97d80fa4e1960864dfec3b687fd4eadf7aa6c709cb4698ae86ae112f386f33731d996b9d41926a2e820c6ba483a61674a4bae03af37e872ffdc0a9a8a034327af17e13e9e7ac619c9188c2a5c12a6ebf887721455c0e2822e67a621ed49f1f50dfc38b71c29d0224954e84ced086c80de552cca3a14adbe43035901225bafc3db3b672c780e4fa12b59221f93690527efc16a28e7c63d1a99fc881f023b03a157076a7e999a715ed37521adb483e2477d75ba5a55d4abad22b024c5317334b6544f15971591c774d896229e4e668fc1c7958fbd76fa0b152a6f14c95692083badd066b6621367fd73d88ba8d860566e6d55b871d80c68296b80ae8847d'),
                         packet.to_bytes())
        for i, privkey in enumerate(payment_path_privkeys):
            processed_packet = process_onion_packet(packet, associated_data, privkey)
            self.assertEqual(hops_data[i].per_hop.to_bytes(), processed_packet.hop_data.per_hop.to_bytes())
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
