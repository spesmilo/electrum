import unittest
import tempfile
import shutil
import asyncio

from electrum.util import bh2u, bfh
from electrum.lnonion import (OnionHopsDataSingle, new_onion_packet, OnionPerHop,
                              process_onion_packet, _decode_onion_error)
from electrum import bitcoin, lnrouter
from electrum.simple_config import SimpleConfig

from . import TestCaseForTestnet

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

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.electrum_path = tempfile.mkdtemp()
        cls.config = SimpleConfig({'electrum_path': cls.electrum_path})

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        shutil.rmtree(cls.electrum_path)

    def test_find_path_for_payment(self):
        class fake_network:
            config = self.config
            asyncio_loop = asyncio.get_event_loop()
            trigger_callback = lambda *args: None
            async def add_job(self, *args): return None
        fake_network.channel_db = lnrouter.ChannelDB(fake_network())
        cdb = fake_network.channel_db
        path_finder = lnrouter.LNPathFinder(cdb)
        cdb.on_channel_announcement({'node_id_1': b'\x02bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 'node_id_2': b'\x02cccccccccccccccccccccccccccccccc',
                                     'bitcoin_key_1': b'\x02bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 'bitcoin_key_2': b'\x02cccccccccccccccccccccccccccccccc',
                                     'short_channel_id': bfh('0000000000000001'),
                                     'chain_hash': bfh('43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000'),
                                     'len': b'\x00\x00', 'features': b''}, trusted=True)
        cdb.on_channel_announcement({'node_id_1': b'\x02bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 'node_id_2': b'\x02eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
                                     'bitcoin_key_1': b'\x02bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 'bitcoin_key_2': b'\x02eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
                                     'short_channel_id': bfh('0000000000000002'),
                                     'chain_hash': bfh('43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000'),
                                     'len': b'\x00\x00', 'features': b''}, trusted=True)
        cdb.on_channel_announcement({'node_id_1': b'\x02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'node_id_2': b'\x02bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                                     'bitcoin_key_1': b'\x02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'bitcoin_key_2': b'\x02bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                                     'short_channel_id': bfh('0000000000000003'),
                                     'chain_hash': bfh('43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000'),
                                     'len': b'\x00\x00', 'features': b''}, trusted=True)
        cdb.on_channel_announcement({'node_id_1': b'\x02cccccccccccccccccccccccccccccccc', 'node_id_2': b'\x02dddddddddddddddddddddddddddddddd',
                                     'bitcoin_key_1': b'\x02cccccccccccccccccccccccccccccccc', 'bitcoin_key_2': b'\x02dddddddddddddddddddddddddddddddd',
                                     'short_channel_id': bfh('0000000000000004'),
                                     'chain_hash': bfh('43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000'),
                                     'len': b'\x00\x00', 'features': b''}, trusted=True)
        cdb.on_channel_announcement({'node_id_1': b'\x02dddddddddddddddddddddddddddddddd', 'node_id_2': b'\x02eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
                                     'bitcoin_key_1': b'\x02dddddddddddddddddddddddddddddddd', 'bitcoin_key_2': b'\x02eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
                                     'short_channel_id': bfh('0000000000000005'),
                                     'chain_hash': bfh('43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000'),
                                     'len': b'\x00\x00', 'features': b''}, trusted=True)
        cdb.on_channel_announcement({'node_id_1': b'\x02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'node_id_2': b'\x02dddddddddddddddddddddddddddddddd',
                                     'bitcoin_key_1': b'\x02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'bitcoin_key_2': b'\x02dddddddddddddddddddddddddddddddd',
                                     'short_channel_id': bfh('0000000000000006'),
                                     'chain_hash': bfh('43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000'),
                                     'len': b'\x00\x00', 'features': b''}, trusted=True)
        o = lambda i: i.to_bytes(8, "big")
        cdb.on_channel_update({'short_channel_id': bfh('0000000000000001'), 'flags': b'\x00', 'cltv_expiry_delta': o(10), 'htlc_minimum_msat': o(250), 'fee_base_msat': o(100), 'fee_proportional_millionths': o(150), 'chain_hash': bfh('43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000'), 'timestamp': b'\x00\x00\x00\x00'}, trusted=True)
        cdb.on_channel_update({'short_channel_id': bfh('0000000000000001'), 'flags': b'\x01', 'cltv_expiry_delta': o(10), 'htlc_minimum_msat': o(250), 'fee_base_msat': o(100), 'fee_proportional_millionths': o(150), 'chain_hash': bfh('43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000'), 'timestamp': b'\x00\x00\x00\x00'}, trusted=True)
        cdb.on_channel_update({'short_channel_id': bfh('0000000000000002'), 'flags': b'\x00', 'cltv_expiry_delta': o(99), 'htlc_minimum_msat': o(250), 'fee_base_msat': o(100), 'fee_proportional_millionths': o(150), 'chain_hash': bfh('43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000'), 'timestamp': b'\x00\x00\x00\x00'}, trusted=True)
        cdb.on_channel_update({'short_channel_id': bfh('0000000000000002'), 'flags': b'\x01', 'cltv_expiry_delta': o(10), 'htlc_minimum_msat': o(250), 'fee_base_msat': o(100), 'fee_proportional_millionths': o(150), 'chain_hash': bfh('43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000'), 'timestamp': b'\x00\x00\x00\x00'}, trusted=True)
        cdb.on_channel_update({'short_channel_id': bfh('0000000000000003'), 'flags': b'\x01', 'cltv_expiry_delta': o(10), 'htlc_minimum_msat': o(250), 'fee_base_msat': o(100), 'fee_proportional_millionths': o(150), 'chain_hash': bfh('43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000'), 'timestamp': b'\x00\x00\x00\x00'}, trusted=True)
        cdb.on_channel_update({'short_channel_id': bfh('0000000000000003'), 'flags': b'\x00', 'cltv_expiry_delta': o(10), 'htlc_minimum_msat': o(250), 'fee_base_msat': o(100), 'fee_proportional_millionths': o(150), 'chain_hash': bfh('43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000'), 'timestamp': b'\x00\x00\x00\x00'}, trusted=True)
        cdb.on_channel_update({'short_channel_id': bfh('0000000000000004'), 'flags': b'\x01', 'cltv_expiry_delta': o(10), 'htlc_minimum_msat': o(250), 'fee_base_msat': o(100), 'fee_proportional_millionths': o(150), 'chain_hash': bfh('43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000'), 'timestamp': b'\x00\x00\x00\x00'}, trusted=True)
        cdb.on_channel_update({'short_channel_id': bfh('0000000000000004'), 'flags': b'\x00', 'cltv_expiry_delta': o(10), 'htlc_minimum_msat': o(250), 'fee_base_msat': o(100), 'fee_proportional_millionths': o(150), 'chain_hash': bfh('43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000'), 'timestamp': b'\x00\x00\x00\x00'}, trusted=True)
        cdb.on_channel_update({'short_channel_id': bfh('0000000000000005'), 'flags': b'\x01', 'cltv_expiry_delta': o(10), 'htlc_minimum_msat': o(250), 'fee_base_msat': o(100), 'fee_proportional_millionths': o(150), 'chain_hash': bfh('43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000'), 'timestamp': b'\x00\x00\x00\x00'}, trusted=True)
        cdb.on_channel_update({'short_channel_id': bfh('0000000000000005'), 'flags': b'\x00', 'cltv_expiry_delta': o(10), 'htlc_minimum_msat': o(250), 'fee_base_msat': o(100), 'fee_proportional_millionths': o(999), 'chain_hash': bfh('43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000'), 'timestamp': b'\x00\x00\x00\x00'}, trusted=True)
        cdb.on_channel_update({'short_channel_id': bfh('0000000000000006'), 'flags': b'\x00', 'cltv_expiry_delta': o(10), 'htlc_minimum_msat': o(250), 'fee_base_msat': o(100), 'fee_proportional_millionths': o(99999999), 'chain_hash': bfh('43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000'), 'timestamp': b'\x00\x00\x00\x00'}, trusted=True)
        cdb.on_channel_update({'short_channel_id': bfh('0000000000000006'), 'flags': b'\x01', 'cltv_expiry_delta': o(10), 'htlc_minimum_msat': o(250), 'fee_base_msat': o(100), 'fee_proportional_millionths': o(150), 'chain_hash': bfh('43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000'), 'timestamp': b'\x00\x00\x00\x00'}, trusted=True)
        self.assertNotEqual(None, path_finder.find_path_for_payment(b'\x02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', b'\x02eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee', 100000))



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
        self.assertEqual(bfh('0002eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619e5f14350c2a76fc232b5e46d421e9615471ab9e0bc887beff8c95fdb878f7b3a71da571226458c510bbadd1276f045c21c520a07d35da256ef75b4367962437b0dd10f7d61ab590531cf08000178a333a347f8b4072e216400406bdf3bf038659793a86cae5f52d32f3438527b47a1cfc54285a8afec3a4c9f3323db0c946f5d4cb2ce721caad69320c3a469a202f3e468c67eaf7a7cda226d0fd32f7b48084dca885d15222e60826d5d971f64172d98e0760154400958f00e86697aa1aa9d41bee8119a1ec866abe044a9ad635778ba61fc0776dc832b39451bd5d35072d2269cf9b040d6ba38b54ec35f81d7fc67678c3be47274f3c4cc472aff005c3469eb3bc140769ed4c7f0218ff8c6c7dd7221d189c65b3b9aaa71a01484b122846c7c7b57e02e679ea8469b70e14fe4f70fee4d87b910cf144be6fe48eef24da475c0b0bcc6565ae82cd3f4e3b24c76eaa5616c6111343306ab35c1fe5ca4a77c0e314ed7dba39d6f1e0de791719c241a939cc493bea2bae1c1e932679ea94d29084278513c77b899cc98059d06a27d171b0dbdf6bee13ddc4fc17a0c4d2827d488436b57baa167544138ca2e64a11b43ac8a06cd0c2fba2d4d900ed2d9205305e2d7383cc98dacb078133de5f6fb6bed2ef26ba92cea28aafc3b9948dd9ae5559e8bd6920b8cea462aa445ca6a95e0e7ba52961b181c79e73bd581821df2b10173727a810c92b83b5ba4a0403eb710d2ca10689a35bec6c3a708e9e92f7d78ff3c5d9989574b00c6736f84c199256e76e19e78f0c98a9d580b4a658c84fc8f2096c2fbea8f5f8c59d0fdacb3be2802ef802abbecb3aba4acaac69a0e965abd8981e9896b1f6ef9d60f7a164b371af869fd0e48073742825e9434fc54da837e120266d53302954843538ea7c6c3dbfb4ff3b2fdbe244437f2a153ccf7bdb4c92aa08102d4f3cff2ae5ef86fab4653595e6a5837fa2f3e29f27a9cde5966843fb847a4a61f1e76c281fe8bb2b0a181d096100db5a1a5ce7a910238251a43ca556712eaadea167fb4d7d75825e440f3ecd782036d7574df8bceacb397abefc5f5254d2722215c53ff54af8299aaaad642c6d72a14d27882d9bbd539e1cc7a527526ba89b8c037ad09120e98ab042d3e8652b31ae0e478516bfaf88efca9f3676ffe99d2819dcaeb7610a626695f53117665d267d3f7abebd6bbd6733f645c72c389f03855bdf1e4b8075b516569b118233a0f0971d24b83113c0b096f5216a207ca99a7cddc81c130923fe3d91e7508c9ac5f2e914ff5dccab9e558566fa14efb34ac98d878580814b94b73acbfde9072f30b881f7f0fff42d4045d1ace6322d86a97d164aa84d93a60498065cc7c20e636f5862dc81531a88c60305a2e59a985be327a6902e4bed986dbf4a0b50c217af0ea7fdf9ab37f9ea1a1aaa72f54cf40154ea9b269f1a7c09f9f43245109431a175d50e2db0132337baa0ef97eed0fcf20489da36b79a1172faccc2f7ded7c60e00694282d93359c4682135642bc81f433574aa8ef0c97b4ade7ca372c5ffc23c7eddd839bab4e0f14d6df15c9dbeab176bec8b5701cf054eb3072f6dadc98f88819042bf10c407516ee58bce33fbe3b3d86a54255e577db4598e30a135361528c101683a5fcde7e8ba53f3456254be8f45fe3a56120ae96ea3773631fcb3873aa3abd91bcff00bd38bd43697a2e789e00da6077482e7b1b1a677b5afae4c54e6cbdf7377b694eb7d7a5b913476a5be923322d3de06060fd5e819635232a2cf4f0731da13b8546d1d6d4f8d75b9fce6c2341a71b0ea6f780df54bfdb0dd5cd9855179f602f917265f21f9190c70217774a6fbaaa7d63ad64199f4664813b955cff954949076dcf'),
                         packet.to_bytes())

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
        self.assertEqual(bfh('0002eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f28368661954176cd9869da33d713aa219fcef1e5c806fef11e696bcc66844de8271c27974a0fd57c2dbcb2c6dd4e8ef35d96db28d5a0e49b6ab3d6de31af65950723b8cddc108390bebf8d149002e31bdc283056477ba27c8054c248ad7306de31663a7c99ec659da15d0f6fbc7e1687485b39e9be0ec3b70164cb3618a9b546317e7c2d62ae9f0f840704535729262d30c6132d1b390f073edec8fa057176c6268b6ad06a82ff0d16d4c662194873e8b4ecf46eb2c9d4d58d2ee2021adb19840605ac5afd8bd942dd71e8244c83e28b2ed5a3b09e9e7df5c8c747e5765ba366a4f7407a6c6b0a32f74bc5e428f7fa4c3cf70e13ed91563177d94190d5149aa4b9c96d00e40d2ac35ab9c4a621ce0f6f5df7d64a9c8d435db19de192d9db522c7f7b4e201fc1b61a9bd3efd062ae24455d463818b01e2756c7d0691bc3ac4c017be34c9a8b2913bb1b937e31e0ae40f650a7cd820bcb4996825b1cbad1ff7ccc2b513b1104524c34f6573e1b59201c005a632ee5dccd3711a32e3ba1ff00fcffbe636e4b3a84bbe491b836a57ccec138b8cc2ec733846904d872f305d538d51db8e56232ec6e07877075328874cb7b09c7e799100a9ff085dead253886b174fc408a0ea7b48bce2c5d8992285011960af088f7e006ef60089d46ac9aa15acfac6c87c3cf6904764dd785419292fbafa9cca09c8ade24a6cd63f12d1cfc83fa35cf2f1cf503c39cbf78293f06c68a3cece7177169cd872bb49bf69d933a27a887dd9daefa9239fca9f0c3e309ec61d9df947211da98cf11a6e0fb77252629cdf9f2226dd69ca73fa51be4df224592f8d471b69a1aebbdaa2f3a798b3581253d97feb0a12e6606043ca0fc5efc0f49b8061d6796eff31cd8638499e2f25ffb96eec32837438ed7ebebbe587886648f63e35d80f41869f4c308f2e6970bd65fead5e8544e3239a6acc9d996b08d1546455bcafbe88ed3ed547714841946fe2e77180e4d7bf1452414e4b1745a7897184a2c4cbc3ac46f83342a55a48e29dc8f17cf595dd28f51e297ba89fd25ed0dbd1c0081a810beaab09758a36fbfd16fbdc3daa9fe05c8a73195f244ef2743a5df761f01ee6e693eb6c7f1a7834fab3671391e5ddebf611e119a2ae4456e2cee7a6d4f27a2246cdb1f8ef35f0b3d7044b3799d8d0ed0a6470557fd807c065d6d83acba07e96e10770ada8c0b4d4921522944188d5f30086a6ee0a4795331273f32beaaa43363fc58208a257e5c5c434c7325b583642219d81c7d67b908d5263b42ac1991edc69a777da60f38eff138c844af9e549374e8b29b166211bfded24587a29394e33828b784da7e7b62ab7e49ea2693fcdd17fa96186a5ef11ef1a8adffa50f93a3119e95e6c09014f3e3b0709183fa08a826ced6deb4608b7d986ebbcf99ad58e25451d4d9d38d0059734d8501467b97182cd11e0c07c91ca50f61cc31255a3147ade654976a5989097281892aafd8df595c63bd14f1e03f5955a9398d2dd6368bbcae833ae1cc2df31eb0980b4817dfd130020ffb275743fcc01df40e3ecda1c5988e8e1bde965353b0b1bf34ea05f095000c45b6249618d275905a24d3eb58c600aeab4fb552fbf1ccdb2a5c80ace220310f89829d7e53f78c126037b6d8d500220c7a118d9621b4d6bd5379edd7e24bcf540e87aba6b88862db16fa4ee00b009fda80577be67ab94910fd8a7807dfe4ebe66b8fdcd040aa2dc17ec22639298be56b2a2c9d8940647b75f2f6d81746df16e1cb2f05e23397a8c63baea0803441ff4b7d517ff172980a056726235e2f6af85e8aa9b91ba85f14532272d6170df3166b91169dc09d4f4a251610f57ff0885a93364cfaf650bdf436c89795efed5ca934bc7ffc0a4'),
                         packet.to_bytes())
        for i, privkey in enumerate(payment_path_privkeys):
            processed_packet = process_onion_packet(packet, associated_data, privkey)
            self.assertEqual(hops_data[i].per_hop.to_bytes(), processed_packet.hop_data.per_hop.to_bytes())
            packet = processed_packet.next_packet

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
