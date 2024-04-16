from electrum import segwit_addr
from electrum import bolt12
from electrum.bolt12 import is_offer, decode_offer
from electrum.lnmsg import UnknownMandatoryTLVRecordType, decode_msg
from electrum.lnonion import OnionHopsDataSingle, new_onion_packet2, OnionPacket
from electrum.segwit_addr import INVALID_BECH32
from electrum.util import bfh

from . import ElectrumTestCase


def bech32_decode(x):
    return segwit_addr.bech32_decode(x, ignore_long_length=True, with_checksum=False)


class TestBolt12(ElectrumTestCase):
    def test_decode(self):
        # https://bootstrap.bolt12.org/examples
        offer = 'lno1pg257enxv4ezqcneype82um50ynhxgrwdajx293pqglnyxw6q0hzngfdusg8umzuxe8kquuz7pjl90ldj8wadwgs0xlmc'
        d = bech32_decode(offer)
        self.assertNotEqual(d, INVALID_BECH32, "bech32 decode error")
        self.assertEqual(d.hrp, 'lno', "wrong hrp")
        self.assertTrue(is_offer(offer))
        od = decode_offer(offer)
        self.assertEqual(od, {'offer_description': {'description': b"Offer by rusty's node"},
                              'offer_node_id':
                                  {'node_id': b'\x02?2\x19\xda\x03\xee)\xa1-\xe4\x10~l\\6O`s\x82\xf0e\xf2\xbf\xed\x91\xdd\xd6\xb9\x10y\xbf\xbc'}
                              })

        offer = 'lno1pqqnyzsmx5cx6umpwssx6atvw35j6ut4v9h8g6t50ysx7enxv4epyrmjw4ehgcm0wfczucm0d5hxzag5qqtzzq3lxgva5qlw9xsjmeqs0ek9cdj0vpec9ur972l7mywa66u3q7dlhs'
        d = bech32_decode(offer)
        self.assertNotEqual(d, INVALID_BECH32, "bech32 decode error")
        self.assertEqual(d.hrp, 'lno', "wrong hrp")
        od = decode_offer(offer)
        self.assertEqual(od, {'offer_amount': {'amount': 50},
                              'offer_description': {'description': b'50msat multi-quantity offer'},
                              'offer_issuer': {'issuer': b'rustcorp.com.au'},
                              'offer_quantity_max': {'max': 0},
                              'offer_node_id':
                                  {'node_id': b'\x02?2\x19\xda\x03\xee)\xa1-\xe4\x10~l\\6O`s\x82\xf0e\xf2\xbf\xed\x91\xdd\xd6\xb9\x10y\xbf\xbc'}
                              })

        # TODO: tests below use recurrence (tlv record type 26) which is not supported/generated from wire specs
        # (c-lightning carries patches re-adding these, but for now we ignore them)

        offer = 'lno1pqqkgzs5xycrqmtnv96zqetkv4e8jgrdd9h82ar9zgg8yatnw3ujumm6d3skyuewdaexw93pqglnyxw6q0hzngfdusg8umzuxe8kquuz7pjl90ldj8wadwgs0xlmcxszqq7q'
        d = bech32_decode(offer)
        self.assertNotEqual(d, INVALID_BECH32, "bech32 decode error")
        self.assertEqual(d.hrp, 'lno', "wrong hrp")
        # contains TLV record type 26 which is not defined (yet) in 12-offer-encoding.md
        with self.assertRaises(UnknownMandatoryTLVRecordType):
            od = bolt12.decode_offer(offer)

        offer = 'lno1pqqkgz38xycrqmtnv96zqetkv4e8jgrdd9h82ar99ss82upqw3hjqargwfjk2gr5d9kk2ucjzpe82um50yhx77nvv938xtn0wfn3vggz8uepnksrac56zt0yzplxchpkfas88qhsvhetlmv3mhttjyreh77p5qsq8s0qzqs'
        d = bech32_decode(offer)
        self.assertNotEqual(d, INVALID_BECH32, "bech32 decode error")
        self.assertEqual(d.hrp, 'lno', "wrong hrp")
        # contains TLV record type 26 which is not defined (yet) in 12-offer-encoding.md
        with self.assertRaises(UnknownMandatoryTLVRecordType):
            od = bolt12.decode_offer(offer)

        offer = 'lno1pqqkgz3zxycrqmtnv96zqetkv4e8jgryv9ujcgrxwfhk6gp3949xzm3dxgcryvgjzpe82um50yhx77nvv938xtn0wfn3vggz8uepnksrac56zt0yzplxchpkfas88qhsvhetlmv3mhttjyreh77p5qspqysq2q2laenqq'
        d = bech32_decode(offer)
        self.assertNotEqual(d, INVALID_BECH32, "bech32 decode error")
        self.assertEqual(d.hrp, 'lno', "wrong hrp")
        # contains TLV record type 26 which is not defined (yet) in 12-offer-encoding.md
        with self.assertRaises(UnknownMandatoryTLVRecordType):
            od = bolt12.decode_offer(offer)

        offer = 'lno1pqpq86q2fgcnqvpsd4ekzapqv4mx2uneyqcnqgryv9uhxtpqveex7mfqxyk55ctw95erqv339ss8qcteyqcksu3qvfjkvmmjv5s8gmeqxcczqum9vdhkuernypkxzar9zgg8yatnw3ujumm6d3skyuewdaexw93pqglnyxw6q0hzngfdusg8umzuxe8kquuz7pjl90ldj8wadwgs0xlmcxszqy9pcpsqqq8pqqpuyqzszhlwvcqq'
        d = bech32_decode(offer)
        self.assertNotEqual(d, INVALID_BECH32, "bech32 decode error")
        self.assertEqual(d.hrp, 'lno', "wrong hrp")
        # contains TLV record type 26 which is not defined (yet) in 12-offer-encoding.md
        with self.assertRaises(UnknownMandatoryTLVRecordType):
            od = bolt12.decode_offer(offer)

        offer = 'lno1pqpq86q2xycnqvpsd4ekzapqv4mx2uneyqcnqgryv9uhxtpqveex7mfqxyk55ctw95erqv339ss8qun094exzarpzgg8yatnw3ujumm6d3skyuewdaexw93pqglnyxw6q0hzngfdusg8umzuxe8kquuz7pjl90ldj8wadwgs0xlmcxszqy9pczqqp5hsqqgd9uqzqpgptlhxvqq'
        d = bech32_decode(offer)
        self.assertNotEqual(d, INVALID_BECH32, "bech32 decode error")
        self.assertEqual(d.hrp, 'lno', "wrong hrp")
        # contains TLV record type 26 which is not defined (yet) in 12-offer-encoding.md
        with self.assertRaises(UnknownMandatoryTLVRecordType):
            od = bolt12.decode_offer(offer)

        offer = 'lno1qcp4256ypqpq86q2pucnq42ngssx2an9wfujqerp0yfpqun4wd68jtn00fkxzcnn9ehhyeckyypr7vsemgp7u2dp9hjpqlnvtsmy7crnstcxtu4lakgam44ezpuml0q6qgqsz'
        d = bech32_decode(offer)
        self.assertNotEqual(d, INVALID_BECH32, "bech32 decode error")
        self.assertEqual(d.hrp, 'lno', "wrong hrp")
        # contains TLV record type 26 which is not defined (yet) in 12-offer-encoding.md
        with self.assertRaises(UnknownMandatoryTLVRecordType):
            od = bolt12.decode_offer(offer)

    def test_path_pubkeys_blinded_path_appended(self):
        # test vectors https://github.com/lightning/bolts/pull/759/files
        payment_path_pubkeys = [
            (bfh('02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619'),   # Alice
             bfh('6363636363636363636363636363636363636363636363636363636363636363')),
            (bfh('0324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c'),  # Bob w blinding secret override
             bfh('0101010101010101010101010101010101010101010101010101010101010101')),
            bfh('027f31ebc5462c1fdce1b737ecff52d37d75dea43ce11c74d25aa297165faa2007'),   # Carol
            bfh('032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991')    # Dave
        ]
        session_key = bfh('0303030303030303030303030303030303030303030303030303030303030303')

        hops_data = [
            OnionHopsDataSingle(tlv_stream_name='onionmsg_tlv',
                                blind_fields={'next_node_id': {'node_id': bfh('0324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c')},
                                              'next_blinding_override': {'blinding': bfh('031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f')},
                                              #'blinding_override_secret': {'data': bfh('0101010101010101010101010101010101010101010101010101010101010101')}}
                                              # blinding_override_secret is not a member of encrypted_data_tlv
                                              }
                                ),
            OnionHopsDataSingle(tlv_stream_name='onionmsg_tlv',
                                blind_fields={'next_node_id': {'node_id': bfh('027f31ebc5462c1fdce1b737ecff52d37d75dea43ce11c74d25aa297165faa2007')},
                                              'unknown_tag_561': {'data': bfh('123456')}
                                              }
                                ),
            OnionHopsDataSingle(tlv_stream_name='onionmsg_tlv',
                                blind_fields={'padding': {'padding': bfh('0000000000')},
                                              'next_node_id': {'node_id': bfh('032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991')}
                                              }
                                ),
            OnionHopsDataSingle(tlv_stream_name='onionmsg_tlv', payload={'message': {'text': b'hello'}},
                                blind_fields={'padding': {'padding': b''},
                                              'path_id': {'data': bfh('deadbeefbadc0ffeedeadbeefbadc0ffeedeadbeefbadc0ffeedeadbeefbadc0')},
                                              'unknown_tag_65535': {'data': b'\x06\xc1'}
                                              }
                                )
        ]
        packet = new_onion_packet2(payment_path_pubkeys, session_key, hops_data)

        expected = bfh('0002531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe33793b828776d70aabbd8cef1a5b52d5a397ae1a20f20435ff6057cd8be339d5aee226660ef73b64afa45dbf2e6e8e26eb96a259b2db5aeecda1ce2e768bbc35d389d7f320ca3d2bd14e2689bef2f5ac0307eaaabc1924eb972c1563d4646ae131accd39da766257ed35ea36e4222527d1db4fa7b2000aab9eafcceed45e28b5560312d4e2299bd8d1e7fe27d10925966c28d497aec400b4630485e82efbabc00550996bdad5d6a9a8c75952f126d14ad2cff91e16198691a7ef2937de83209285f1fb90944b4e46bca7c856a9ce3da10cdf2a7d00dc2bf4f114bc4d3ed67b91cbde558ce9af86dc81fbdc37f8e301b29e23c1466659c62bdbf8cff5d4c20f0fb0851ec72f5e9385dd40fdd2e3ed67ca4517117825665e50a3e26f73c66998daf18e418e8aef9ce2d20da33c3629db2933640e03e7b44c2edf49e9b482db7b475cfd4c617ae1d46d5c24d697846f9f08561eac2b065f9b382501f6eabf07343ed6c602f61eab99cdb52adf63fd44a8db2d3016387ea708fc1c08591e19b4d9984ebe31edbd684c2ea86526dd8c7732b1d8d9117511dc1b643976d356258fce8313b1cb92682f41ab72dedd766f06de375f9edacbcd0ca8c99b865ea2b7952318ea1fd20775a28028b5cf59dece5de14f615b8df254eee63493a5111ea987224bea006d8f1b60d565eef06ac0da194dba2a6d02e79b2f2f34e9ca6e1984a507319d86e9d4fcaeea41b4b9144e0b1826304d4cc1da61cfc5f8b9850697df8adc5e9d6f3acb3219b02764b4909f2b2b22e799fd66c383414a84a7d791b899d4aa663770009eb122f90282c8cb9cda16aba6897edcf9b32951d0080c0f52be3ca011fbec3fb16423deb47744645c3b05fdbd932edf54ba6efd26e65340a8e9b1d1216582e1b30d64524f8ca2d6c5ba63a38f7120a3ed71bed8960bcac2feee2dd41c90be48e3c11ec518eb3d872779e4765a6cc28c6b0fa71ab57ced73ae963cc630edae4258cba2bf25821a6ae049fec2fca28b5dd1bb004d92924b65701b06dcf37f0ccd147a13a03f9bc0f98b7d78fe9058089756931e2cd0e0ed92ec6759d07b248069526c67e9e6ce095118fd3501ba0f858ef030b76c6f6beb11a09317b5ad25343f4b31aef02bc555951bc7791c2c289ecf94d5544dcd6ad3021ed8e8e3db34b2a73e1eedb57b578b068a5401836d6e382110b73690a94328c404af25e85a8d6b808893d1b71af6a31fadd8a8cc6e31ecc0d9ff7e6b91fd03c274a5c1f1ccd25b61150220a3fddb04c91012f5f7a83a5c90deb2470089d6e38cd5914b9c946eca6e9d31bbf8667d36cf87effc3f3ff283c21dd4137bd569fe7cf758feac94053e4baf7338bb592c8b7c291667fadf4a9bf9a2a154a18f612cbc7f851b3f8f2070e0a9d180622ee4f8e81b0ab250d504cef24116a3ff188cc829fcd8610b56343569e8dc997629410d1967ca9dd1d27eec5e01e4375aad16c46faba268524b154850d0d6fe3a76af2c6aa3e97647c51036049ac565370028d6a439a2672b6face56e1b171496c0722cfa22d9da631be359661617c5d5a2d286c5e19db9452c1e21a0107b6400debda2decb0c838f342dd017cdb2dccdf1fe97e3df3f881856b546997a3fed9e279c720145101567dd56be21688fed66bf9759e432a9aa89cbbd225d13cdea4ca05f7a45cfb6a682a3d5b1e18f7e6cf934fae5098108bae9058d05c3387a01d8d02a656d2bfff67e9f46b2d8a6aac28129e52efddf6e552214c3f8a45bc7a912cca9a7fec1d7d06412c6972cb9e3dc518983f56530b8bffe7f92c4b6eb47d4aef59fb513c4653a42de61bc17ad7728e7fc7590ff05a9e991de03f023d0aaf8688ed6170def5091c66576a424ac1cb')
        self.assertEqual(packet.to_bytes(), expected)

    def test_decode_onion_message_packet(self):
        packet = '0002531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe33793b828776d70aabbd8cef1a5b52d5a397ae1a20f20435ff6057cd8be339d5aee226660ef73b64afa45dbf2e6e8e26eb96a259b2db5aeecda1ce2e768bbc35d389d7f320ca3d2bd14e2689bef2f5ac0307eaaabc1924eb972c1563d4646ae131accd39da766257ed35ea36e4222527d1db4fa7b2000aab9eafcceed45e28b5560312d4e2299bd8d1e7fe27d10925966c28d497aec400b4630485e82efbabc00550996bdad5d6a9a8c75952f126d14ad2cff91e16198691a7ef2937de83209285f1fb90944b4e46bca7c856a9ce3da10cdf2a7d00dc2bf4f114bc4d3ed67b91cbde558ce9af86dc81fbdc37f8e301b29e23c1466659c62bdbf8cff5d4c20f0fb0851ec72f5e9385dd40fdd2e3ed67ca4517117825665e50a3e26f73c66998daf18e418e8aef9ce2d20da33c3629db2933640e03e7b44c2edf49e9b482db7b475cfd4c617ae1d46d5c24d697846f9f08561eac2b065f9b382501f6eabf07343ed6c602f61eab99cdb52adf63fd44a8db2d3016387ea708fc1c08591e19b4d9984ebe31edbd684c2ea86526dd8c7732b1d8d9117511dc1b643976d356258fce8313b1cb92682f41ab72dedd766f06de375f9edacbcd0ca8c99b865ea2b7952318ea1fd20775a28028b5cf59dece5de14f615b8df254eee63493a5111ea987224bea006d8f1b60d565eef06ac0da194dba2a6d02e79b2f2f34e9ca6e1984a507319d86e9d4fcaeea41b4b9144e0b1826304d4cc1da61cfc5f8b9850697df8adc5e9d6f3acb3219b02764b4909f2b2b22e799fd66c383414a84a7d791b899d4aa663770009eb122f90282c8cb9cda16aba6897edcf9b32951d0080c0f52be3ca011fbec3fb16423deb47744645c3b05fdbd932edf54ba6efd26e65340a8e9b1d1216582e1b30d64524f8ca2d6c5ba63a38f7120a3ed71bed8960bcac2feee2dd41c90be48e3c11ec518eb3d872779e4765a6cc28c6b0fa71ab57ced73ae963cc630edae4258cba2bf25821a6ae049fec2fca28b5dd1bb004d92924b65701b06dcf37f0ccd147a13a03f9bc0f98b7d78fe9058089756931e2cd0e0ed92ec6759d07b248069526c67e9e6ce095118fd3501ba0f858ef030b76c6f6beb11a09317b5ad25343f4b31aef02bc555951bc7791c2c289ecf94d5544dcd6ad3021ed8e8e3db34b2a73e1eedb57b578b068a5401836d6e382110b73690a94328c404af25e85a8d6b808893d1b71af6a31fadd8a8cc6e31ecc0d9ff7e6b91fd03c274a5c1f1ccd25b61150220a3fddb04c91012f5f7a83a5c90deb2470089d6e38cd5914b9c946eca6e9d31bbf8667d36cf87effc3f3ff283c21dd4137bd569fe7cf758feac94053e4baf7338bb592c8b7c291667fadf4a9bf9a2a154a18f612cbc7f851b3f8f2070e0a9d180622ee4f8e81b0ab250d504cef24116a3ff188cc829fcd8610b56343569e8dc997629410d1967ca9dd1d27eec5e01e4375aad16c46faba268524b154850d0d6fe3a76af2c6aa3e97647c51036049ac565370028d6a439a2672b6face56e1b171496c0722cfa22d9da631be359661617c5d5a2d286c5e19db9452c1e21a0107b6400debda2decb0c838f342dd017cdb2dccdf1fe97e3df3f881856b546997a3fed9e279c720145101567dd56be21688fed66bf9759e432a9aa89cbbd225d13cdea4ca05f7a45cfb6a682a3d5b1e18f7e6cf934fae5098108bae9058d05c3387a01d8d02a656d2bfff67e9f46b2d8a6aac28129e52efddf6e552214c3f8a45bc7a912cca9a7fec1d7d06412c6972cb9e3dc518983f56530b8bffe7f92c4b6eb47d4aef59fb513c4653a42de61bc17ad7728e7fc7590ff05a9e991de03f023d0aaf8688ed6170def5091c66576a424ac1cb'
        op = OnionPacket.from_bytes(bfh(packet))
        pass

    def test_decode_onion_message(self):
        msg = '0201025aaca62db7ce6b46386206ef9930daa32e979a35cb185a41cb951aa7d254b03c055600025550b2910294fa73bda99b9de9c851be9cbb481e23194a1743033630efba546b86e7d838d0f6e9cc0ed088dbf6889f0dceca3bfc745bd77d013a31311fa932a8bf1d28387d9ff521eabc651dee8f861fed609a68551145a451f017ec44978addeee97a423c08445531da488fd1ddc998e9cdbfcea59517b53fbf1833f0bbe6188dba6ca773a247220ec934010daca9cc185e1ceb136803469baac799e27a0d82abe53dc48a06a55d1f643885cc7894677dd20a4e4152577d1ba74b870b9279f065f9b340cedb3ca13b7df218e853e10ccd1b59c42a2acf93f489e170ee4373d30ab158b60fc20d3ba73a1f8c750951d69fb5b9321b968ddc8114936412346aff802df65516e1c09c51ef19849ff36c0199fd88c8bec301a30fef0c7cb497901c038611303f64e4174b5daf42832aa5586b84d2c9b95f382f4269a5d1bd4be898618dc78dfd451170f72ca16decac5b03e60702112e439cadd104fb3bbb3d5023c9b80823fdcd0a212a7e1aaa6eeb027adc7f8b3723031d135a09a979a4802788bb7861c6cc85501fb91137768b70aeab309b27b885686604ffc387004ac4f8c44b101c39bc0597ef7fd957f53fc5051f534b10eb3852100962b5e58254e5558689913c26ad6072ea41f5c5db10077cfc91101d4ae393be274c74297da5cc381cd88d54753aaa7df74b2f9da8d88a72bc9218fcd1f19e4ff4aace182312b9509c5175b6988f044c5756d232af02a451a02ca752f3c52747773acff6fd07d2032e6ce562a2c42105d106eba02d0b1904182cdc8c74875b082d4989d3a7e9f0e73de7c75d357f4af976c28c0b206c5e8123fc2391d078592d0d5ff686fd245c0a2de2e535b7cca99c0a37d432a8657393a9e3ca53eec1692159046ba52cb9bc97107349d8673f74cbc97e231f1108005c8d03e24ca813cea2294b39a7a493bcc062708f1f6cf0074e387e7d50e0666ce784ef4d31cb860f6cad767438d9ea5156ff0ae86e029e0247bf94df75ee0cda4f2006061455cb2eaff513d558863ae334cef7a3d45f55e7cc13153c6719e9901c1d4db6c03f643b69ea4860690305651794284d9e61eb848ccdf5a77794d376f0af62e46d4835acce6fd9eef5df73ebb8ea3bb48629766967f446e744ecc57ff3642c4aa1ccee9a2f72d5caa75fa05787d08b79408fce792485fdecdc25df34820fb061275d70b84ece540b0fc47b2453612be34f2b78133a64e812598fbe225fd85415f8ffe5340ce955b5fd9d67dd88c1c531dde298ed25f96df271558c812c26fa386966c76f03a6ebccbca49ac955916929bd42e134f982dde03f924c464be5fd1ba44f8dc4c3cbc8162755fd1d8f7dc044b15b1a796c53df7d8769bb167b2045b49cc71e08908796c92c16a235717cabc4bb9f60f8f66ff4fff1f9836388a99583acebdff4a7fb20f48eedcd1f4bdcc06ec8b48e35307df51d9bc81d38a94992dd135b30079e1f592da6e98dff496cb1a7776460a26b06395b176f585636ebdf7eab692b227a31d6979f5a6141292698e91346b6c806b90c7c6971e481559cae92ee8f4136f2226861f5c39ddd29bbdb118a35dece03f49a96804caea79a3dacfbf09d65f2611b5622de51d98e18151acb3bb84c09caaa0cc80edfa743a4679f37d6167618ce99e73362fa6f213409931762618a61f1738c071bba5afc1db24fe94afb70c40d731908ab9a505f76f57a7d40e708fd3df0efc5b7cbb2a7b75cd23449e09684a2f0e2bfa0d6176c35f96fe94d92fc9fa4103972781f81cb6e8df7dbeb0fc529c600d768bed3f08828b773d284f69e9a203459d88c12d6df7a75be2455fec128f07a497a2b2bf626cc6272d0419ca663e9dc66b8224227eb796f0246dcae9c5b0b6cfdbbd40c3245a610481c92047c968c9fc92c04b89cc41a0c15355a8f'
        msg = '0201031195a8046dcbb8e17034bca630065e7a0982e4e36f6f7e5a8d4554e4846fcd9905560002531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe33793b828776d70aabbd8cef1a5b52d5a397ae1a20f20435ff6057cd8be339d5aee226660ef73b64afa45dbf2e6e8e26eb96a259b2db5aeecda1ce2e768bbc35d389d7f320ca3d2bd14e2689bef2f5ac0307eaaabc1924eb972c1563d4646ae131accd39da766257ed35ea36e4222527d1db4fa7b2000aab9eafcceed45e28b5560312d4e2299bd8d1e7fe27d10925966c28d497aec400b4630485e82efbabc00550996bdad5d6a9a8c75952f126d14ad2cff91e16198691a7ef2937de83209285f1fb90944b4e46bca7c856a9ce3da10cdf2a7d00dc2bf4f114bc4d3ed67b91cbde558ce9af86dc81fbdc37f8e301b29e23c1466659c62bdbf8cff5d4c20f0fb0851ec72f5e9385dd40fdd2e3ed67ca4517117825665e50a3e26f73c66998daf18e418e8aef9ce2d20da33c3629db2933640e03e7b44c2edf49e9b482db7b475cfd4c617ae1d46d5c24d697846f9f08561eac2b065f9b382501f6eabf07343ed6c602f61eab99cdb52adf63fd44a8db2d3016387ea708fc1c08591e19b4d9984ebe31edbd684c2ea86526dd8c7732b1d8d9117511dc1b643976d356258fce8313b1cb92682f41ab72dedd766f06de375f9edacbcd0ca8c99b865ea2b7952318ea1fd20775a28028b5cf59dece5de14f615b8df254eee63493a5111ea987224bea006d8f1b60d565eef06ac0da194dba2a6d02e79b2f2f34e9ca6e1984a507319d86e9d4fcaeea41b4b9144e0b1826304d4cc1da61cfc5f8b9850697df8adc5e9d6f3acb3219b02764b4909f2b2b22e799fd66c383414a84a7d791b899d4aa663770009eb122f90282c8cb9cda16aba6897edcf9b32951d0080c0f52be3ca011fbec3fb16423deb47744645c3b05fdbd932edf54ba6efd26e65340a8e9b1d1216582e1b30d64524f8ca2d6c5ba63a38f7120a3ed71bed8960bcac2feee2dd41c90be48e3c11ec518eb3d872779e4765a6cc28c6b0fa71ab57ced73ae963cc630edae4258cba2bf25821a6ae049fec2fca28b5dd1bb004d92924b65701b06dcf37f0ccd147a13a03f9bc0f98b7d78fe9058089756931e2cd0e0ed92ec6759d07b248069526c67e9e6ce095118fd3501ba0f858ef030b76c6f6beb11a09317b5ad25343f4b31aef02bc555951bc7791c2c289ecf94d5544dcd6ad3021ed8e8e3db34b2a73e1eedb57b578b068a5401836d6e382110b73690a94328c404af25e85a8d6b808893d1b71af6a31fadd8a8cc6e31ecc0d9ff7e6b91fd03c274a5c1f1ccd25b61150220a3fddb04c91012f5f7a83a5c90deb2470089d6e38cd5914b9c946eca6e9d31bbf8667d36cf87effc3f3ff283c21dd4137bd569fe7cf758feac94053e4baf7338bb592c8b7c291667fadf4a9bf9a2a154a18f612cbc7f851b3f8f2070e0a9d180622ee4f8e81b0ab250d504cef24116a3ff188cc829fcd8610b56343569e8dc997629410d1967ca9dd1d27eec5e01e4375aad16c46faba268524b154850d0d6fe3a76af2c6aa3e97647c51036049ac565370028d6a439a2672b6face56e1b171496c0722cfa22d9da631be359661617c5d5a2d286c5e19db9452c1e21a0107b6400debda2decb0c838f342dd017cdb2dccdf1fe97e3df3f881856b546997a3fed9e279c720145101567dd56be21688fed66bf9759e432a9aa89cbbd225d13cdea4ca05f7a45cfb6a682a3d5b1e18f7e6cf934fae5098108bae9058d05c3387a01d8d02a656d2bfff67e9f46b2d8a6aac28129e52efddf6e552214c3f8a45bc7a912cca9a7fec1d7d06412c6972cb9e3dc518983f56530b8bffe7f92c4b6eb47d4aef59fb513c4653a42de61bc17ad7728e7fc7590ff05a9e991de03f023d0aaf8688ed6170def5091c66576a424ac1cb'
        op = decode_msg(bfh(msg))
        pass
