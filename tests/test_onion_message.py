import io

from electrum import ecc
from electrum.lnmsg import decode_msg, OnionWireSerializer
from electrum.lnonion import (get_shared_secrets_along_route2, OnionHopsDataSingle, OnionPacket,
                              process_onion_packet, get_bolt04_onion_key, encrypt_encrypted_data_tlv,
                              get_shared_secrets_along_route, new_onion_packet, ONION_MESSAGE_LARGE_SIZE,
                              HOPS_DATA_SIZE, InvalidPayloadSize)
from electrum.lnutil import get_ecdh
from electrum.onion_message import blinding_privkey, create_blinded_path, encrypt_onionmsg_tlv_hops_data
from electrum.util import bfh

from . import ElectrumTestCase


class TestOnionMessage(ElectrumTestCase):
    def test_path_pubkeys_blinded_path_appended(self):
        # test vectors https://github.com/lightning/bolts/pull/759/files
        payment_path_pubkeys = [
            (bfh('02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619'),  # Alice
             bfh('6363636363636363636363636363636363636363636363636363636363636363')),
            (bfh('0324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c'),  # Bob w blinding secret override
             bfh('0101010101010101010101010101010101010101010101010101010101010101')),
            bfh('027f31ebc5462c1fdce1b737ecff52d37d75dea43ce11c74d25aa297165faa2007'),  # Carol
            bfh('032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991')  # Dave
        ]

        session_key = bfh('0303030303030303030303030303030303030303030303030303030303030303')
        hop_shared_secrets, blinded_node_ids = get_shared_secrets_along_route2(payment_path_pubkeys, session_key)

        self.assertEqual(hop_shared_secrets, [
            bfh('c04d2a4c518241cb49f2800eea92554cb543f268b4c73f85693541e86d649205'),
            bfh('196f1f3e0be9d65f88463c1ab63e07f41b4e7c0368c28c3e6aa290cc0d22eaed'),
            bfh('c7b33d74a723e26331a91c15ae5bc77db28a18b801b6bc5cd5bba98418303a9d'),
            bfh('024955ed0d4ebbfab13498f5d7aacd00bf096c8d9ed0473cdfc96d90053c86b7')
        ])

        self.assertEqual(blinded_node_ids, [
            bfh('02d1c3d73f8cac67e7c5b6ec517282d5ba0a52b06a29ec92ff01e12decf76003c1'),
            bfh('03f1465ca5cf3ec83f16f9343d02e6c24b76993a93e1dea2398f3147a9be893d7a'),
            bfh('035dbc0493aa4e7eea369d6a06e8013fd03e66a5eea91c455ed65950c4942b624b'),
            bfh('0237bf019fa0fbecde8b4a1c7b197c9c1c76f9a23d67dd55bb5e42e1f50bb771a6')
        ])

        hops_data = [
            OnionHopsDataSingle(tlv_stream_name='onionmsg_tlv',
                                blind_fields={'next_node_id': {'node_id': bfh('0324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c')},
                                              'next_blinding_override': {'blinding': bfh('031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f')},
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
                                              'unknown_tag_65535': {'data': bfh('06c1')}
                                              }
                                )
        ]

        hop_shared_secrets, blinded_node_ids = get_shared_secrets_along_route2(payment_path_pubkeys, session_key)
        encrypt_onionmsg_tlv_hops_data(hops_data, hop_shared_secrets)
        packet = new_onion_packet(blinded_node_ids, session_key, hops_data, onion_message=True)

        self.assertEqual(packet.hmac, bfh('8e7fc7590ff05a9e991de03f023d0aaf8688ed6170def5091c66576a424ac1cb'))
        self.assertEqual(packet.public_key, bfh('02531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337'))
        self.assertEqual(packet.hops_data, bfh('93b828776d70aabbd8cef1a5b52d5a397ae1a20f20435ff6057cd8be339d5aee226660ef73b64afa45dbf2e6e8e26eb96a259b2db5aeecda1ce2e768bbc35d389d7f320ca3d2bd14e2689bef2f5ac0307eaaabc1924eb972c1563d4646ae131accd39da766257ed35ea36e4222527d1db4fa7b2000aab9eafcceed45e28b5560312d4e2299bd8d1e7fe27d10925966c28d497aec400b4630485e82efbabc00550996bdad5d6a9a8c75952f126d14ad2cff91e16198691a7ef2937de83209285f1fb90944b4e46bca7c856a9ce3da10cdf2a7d00dc2bf4f114bc4d3ed67b91cbde558ce9af86dc81fbdc37f8e301b29e23c1466659c62bdbf8cff5d4c20f0fb0851ec72f5e9385dd40fdd2e3ed67ca4517117825665e50a3e26f73c66998daf18e418e8aef9ce2d20da33c3629db2933640e03e7b44c2edf49e9b482db7b475cfd4c617ae1d46d5c24d697846f9f08561eac2b065f9b382501f6eabf07343ed6c602f61eab99cdb52adf63fd44a8db2d3016387ea708fc1c08591e19b4d9984ebe31edbd684c2ea86526dd8c7732b1d8d9117511dc1b643976d356258fce8313b1cb92682f41ab72dedd766f06de375f9edacbcd0ca8c99b865ea2b7952318ea1fd20775a28028b5cf59dece5de14f615b8df254eee63493a5111ea987224bea006d8f1b60d565eef06ac0da194dba2a6d02e79b2f2f34e9ca6e1984a507319d86e9d4fcaeea41b4b9144e0b1826304d4cc1da61cfc5f8b9850697df8adc5e9d6f3acb3219b02764b4909f2b2b22e799fd66c383414a84a7d791b899d4aa663770009eb122f90282c8cb9cda16aba6897edcf9b32951d0080c0f52be3ca011fbec3fb16423deb47744645c3b05fdbd932edf54ba6efd26e65340a8e9b1d1216582e1b30d64524f8ca2d6c5ba63a38f7120a3ed71bed8960bcac2feee2dd41c90be48e3c11ec518eb3d872779e4765a6cc28c6b0fa71ab57ced73ae963cc630edae4258cba2bf25821a6ae049fec2fca28b5dd1bb004d92924b65701b06dcf37f0ccd147a13a03f9bc0f98b7d78fe9058089756931e2cd0e0ed92ec6759d07b248069526c67e9e6ce095118fd3501ba0f858ef030b76c6f6beb11a09317b5ad25343f4b31aef02bc555951bc7791c2c289ecf94d5544dcd6ad3021ed8e8e3db34b2a73e1eedb57b578b068a5401836d6e382110b73690a94328c404af25e85a8d6b808893d1b71af6a31fadd8a8cc6e31ecc0d9ff7e6b91fd03c274a5c1f1ccd25b61150220a3fddb04c91012f5f7a83a5c90deb2470089d6e38cd5914b9c946eca6e9d31bbf8667d36cf87effc3f3ff283c21dd4137bd569fe7cf758feac94053e4baf7338bb592c8b7c291667fadf4a9bf9a2a154a18f612cbc7f851b3f8f2070e0a9d180622ee4f8e81b0ab250d504cef24116a3ff188cc829fcd8610b56343569e8dc997629410d1967ca9dd1d27eec5e01e4375aad16c46faba268524b154850d0d6fe3a76af2c6aa3e97647c51036049ac565370028d6a439a2672b6face56e1b171496c0722cfa22d9da631be359661617c5d5a2d286c5e19db9452c1e21a0107b6400debda2decb0c838f342dd017cdb2dccdf1fe97e3df3f881856b546997a3fed9e279c720145101567dd56be21688fed66bf9759e432a9aa89cbbd225d13cdea4ca05f7a45cfb6a682a3d5b1e18f7e6cf934fae5098108bae9058d05c3387a01d8d02a656d2bfff67e9f46b2d8a6aac28129e52efddf6e552214c3f8a45bc7a912cca9a7fec1d7d06412c6972cb9e3dc518983f56530b8bffe7f92c4b6eb47d4aef59fb513c4653a42de61bc17ad772'))

        self.assertEqual(packet.to_bytes(), bfh('0002531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe33793b828776d70aabbd8cef1a5b52d5a397ae1a20f20435ff6057cd8be339d5aee226660ef73b64afa45dbf2e6e8e26eb96a259b2db5aeecda1ce2e768bbc35d389d7f320ca3d2bd14e2689bef2f5ac0307eaaabc1924eb972c1563d4646ae131accd39da766257ed35ea36e4222527d1db4fa7b2000aab9eafcceed45e28b5560312d4e2299bd8d1e7fe27d10925966c28d497aec400b4630485e82efbabc00550996bdad5d6a9a8c75952f126d14ad2cff91e16198691a7ef2937de83209285f1fb90944b4e46bca7c856a9ce3da10cdf2a7d00dc2bf4f114bc4d3ed67b91cbde558ce9af86dc81fbdc37f8e301b29e23c1466659c62bdbf8cff5d4c20f0fb0851ec72f5e9385dd40fdd2e3ed67ca4517117825665e50a3e26f73c66998daf18e418e8aef9ce2d20da33c3629db2933640e03e7b44c2edf49e9b482db7b475cfd4c617ae1d46d5c24d697846f9f08561eac2b065f9b382501f6eabf07343ed6c602f61eab99cdb52adf63fd44a8db2d3016387ea708fc1c08591e19b4d9984ebe31edbd684c2ea86526dd8c7732b1d8d9117511dc1b643976d356258fce8313b1cb92682f41ab72dedd766f06de375f9edacbcd0ca8c99b865ea2b7952318ea1fd20775a28028b5cf59dece5de14f615b8df254eee63493a5111ea987224bea006d8f1b60d565eef06ac0da194dba2a6d02e79b2f2f34e9ca6e1984a507319d86e9d4fcaeea41b4b9144e0b1826304d4cc1da61cfc5f8b9850697df8adc5e9d6f3acb3219b02764b4909f2b2b22e799fd66c383414a84a7d791b899d4aa663770009eb122f90282c8cb9cda16aba6897edcf9b32951d0080c0f52be3ca011fbec3fb16423deb47744645c3b05fdbd932edf54ba6efd26e65340a8e9b1d1216582e1b30d64524f8ca2d6c5ba63a38f7120a3ed71bed8960bcac2feee2dd41c90be48e3c11ec518eb3d872779e4765a6cc28c6b0fa71ab57ced73ae963cc630edae4258cba2bf25821a6ae049fec2fca28b5dd1bb004d92924b65701b06dcf37f0ccd147a13a03f9bc0f98b7d78fe9058089756931e2cd0e0ed92ec6759d07b248069526c67e9e6ce095118fd3501ba0f858ef030b76c6f6beb11a09317b5ad25343f4b31aef02bc555951bc7791c2c289ecf94d5544dcd6ad3021ed8e8e3db34b2a73e1eedb57b578b068a5401836d6e382110b73690a94328c404af25e85a8d6b808893d1b71af6a31fadd8a8cc6e31ecc0d9ff7e6b91fd03c274a5c1f1ccd25b61150220a3fddb04c91012f5f7a83a5c90deb2470089d6e38cd5914b9c946eca6e9d31bbf8667d36cf87effc3f3ff283c21dd4137bd569fe7cf758feac94053e4baf7338bb592c8b7c291667fadf4a9bf9a2a154a18f612cbc7f851b3f8f2070e0a9d180622ee4f8e81b0ab250d504cef24116a3ff188cc829fcd8610b56343569e8dc997629410d1967ca9dd1d27eec5e01e4375aad16c46faba268524b154850d0d6fe3a76af2c6aa3e97647c51036049ac565370028d6a439a2672b6face56e1b171496c0722cfa22d9da631be359661617c5d5a2d286c5e19db9452c1e21a0107b6400debda2decb0c838f342dd017cdb2dccdf1fe97e3df3f881856b546997a3fed9e279c720145101567dd56be21688fed66bf9759e432a9aa89cbbd225d13cdea4ca05f7a45cfb6a682a3d5b1e18f7e6cf934fae5098108bae9058d05c3387a01d8d02a656d2bfff67e9f46b2d8a6aac28129e52efddf6e552214c3f8a45bc7a912cca9a7fec1d7d06412c6972cb9e3dc518983f56530b8bffe7f92c4b6eb47d4aef59fb513c4653a42de61bc17ad7728e7fc7590ff05a9e991de03f023d0aaf8688ed6170def5091c66576a424ac1cb'))

    def test_onion_message_payload_size(self):
        payment_path_pubkeys = [
            bfh('032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991')  # Dave
        ]

        session_key = bfh('0303030303030303030303030303030303030303030303030303030303030303')
        hop_shared_secrets, blinded_node_ids = get_shared_secrets_along_route2(payment_path_pubkeys, session_key)

        def hops_data_for_message(message):
            return [
                OnionHopsDataSingle(tlv_stream_name='onionmsg_tlv', payload={'message': {'text': message.encode('utf-8')}},
                                    blind_fields={'path_id': {'data': bfh('deadbeefbadc0ffeedeadbeefbadc0ffeedeadbeefbadc0ffeedeadbeefbadc0')},
                                                  }
                                    )
            ]

        hops_data = hops_data_for_message('short_message')  # fit in HOPS_DATA_SIZE
        encrypt_onionmsg_tlv_hops_data(hops_data, hop_shared_secrets)
        packet = new_onion_packet(blinded_node_ids, session_key, hops_data, onion_message=True)
        self.assertEqual(len(packet.to_bytes()), HOPS_DATA_SIZE + 66)

        hops_data = hops_data_for_message('A' * HOPS_DATA_SIZE)  # fit in ONION_MESSAGE_LARGE_SIZE
        encrypt_onionmsg_tlv_hops_data(hops_data, hop_shared_secrets)
        packet = new_onion_packet(blinded_node_ids, session_key, hops_data, onion_message=True)

        self.assertEqual(len(packet.to_bytes()), ONION_MESSAGE_LARGE_SIZE + 66)

        hops_data = hops_data_for_message('A' * ONION_MESSAGE_LARGE_SIZE)  # does not fit in ONION_MESSAGE_LARGE_SIZE
        encrypt_onionmsg_tlv_hops_data(hops_data, hop_shared_secrets)
        with self.assertRaises(InvalidPayloadSize):
            new_onion_packet(blinded_node_ids, session_key, hops_data, onion_message=True)

    def test_decode_onion_message_packet(self):
        packet = '0002531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe33793b828776d70aabbd8cef1a5b52d5a397ae1a20f20435ff6057cd8be339d5aee226660ef73b64afa45dbf2e6e8e26eb96a259b2db5aeecda1ce2e768bbc35d389d7f320ca3d2bd14e2689bef2f5ac0307eaaabc1924eb972c1563d4646ae131accd39da766257ed35ea36e4222527d1db4fa7b2000aab9eafcceed45e28b5560312d4e2299bd8d1e7fe27d10925966c28d497aec400b4630485e82efbabc00550996bdad5d6a9a8c75952f126d14ad2cff91e16198691a7ef2937de83209285f1fb90944b4e46bca7c856a9ce3da10cdf2a7d00dc2bf4f114bc4d3ed67b91cbde558ce9af86dc81fbdc37f8e301b29e23c1466659c62bdbf8cff5d4c20f0fb0851ec72f5e9385dd40fdd2e3ed67ca4517117825665e50a3e26f73c66998daf18e418e8aef9ce2d20da33c3629db2933640e03e7b44c2edf49e9b482db7b475cfd4c617ae1d46d5c24d697846f9f08561eac2b065f9b382501f6eabf07343ed6c602f61eab99cdb52adf63fd44a8db2d3016387ea708fc1c08591e19b4d9984ebe31edbd684c2ea86526dd8c7732b1d8d9117511dc1b643976d356258fce8313b1cb92682f41ab72dedd766f06de375f9edacbcd0ca8c99b865ea2b7952318ea1fd20775a28028b5cf59dece5de14f615b8df254eee63493a5111ea987224bea006d8f1b60d565eef06ac0da194dba2a6d02e79b2f2f34e9ca6e1984a507319d86e9d4fcaeea41b4b9144e0b1826304d4cc1da61cfc5f8b9850697df8adc5e9d6f3acb3219b02764b4909f2b2b22e799fd66c383414a84a7d791b899d4aa663770009eb122f90282c8cb9cda16aba6897edcf9b32951d0080c0f52be3ca011fbec3fb16423deb47744645c3b05fdbd932edf54ba6efd26e65340a8e9b1d1216582e1b30d64524f8ca2d6c5ba63a38f7120a3ed71bed8960bcac2feee2dd41c90be48e3c11ec518eb3d872779e4765a6cc28c6b0fa71ab57ced73ae963cc630edae4258cba2bf25821a6ae049fec2fca28b5dd1bb004d92924b65701b06dcf37f0ccd147a13a03f9bc0f98b7d78fe9058089756931e2cd0e0ed92ec6759d07b248069526c67e9e6ce095118fd3501ba0f858ef030b76c6f6beb11a09317b5ad25343f4b31aef02bc555951bc7791c2c289ecf94d5544dcd6ad3021ed8e8e3db34b2a73e1eedb57b578b068a5401836d6e382110b73690a94328c404af25e85a8d6b808893d1b71af6a31fadd8a8cc6e31ecc0d9ff7e6b91fd03c274a5c1f1ccd25b61150220a3fddb04c91012f5f7a83a5c90deb2470089d6e38cd5914b9c946eca6e9d31bbf8667d36cf87effc3f3ff283c21dd4137bd569fe7cf758feac94053e4baf7338bb592c8b7c291667fadf4a9bf9a2a154a18f612cbc7f851b3f8f2070e0a9d180622ee4f8e81b0ab250d504cef24116a3ff188cc829fcd8610b56343569e8dc997629410d1967ca9dd1d27eec5e01e4375aad16c46faba268524b154850d0d6fe3a76af2c6aa3e97647c51036049ac565370028d6a439a2672b6face56e1b171496c0722cfa22d9da631be359661617c5d5a2d286c5e19db9452c1e21a0107b6400debda2decb0c838f342dd017cdb2dccdf1fe97e3df3f881856b546997a3fed9e279c720145101567dd56be21688fed66bf9759e432a9aa89cbbd225d13cdea4ca05f7a45cfb6a682a3d5b1e18f7e6cf934fae5098108bae9058d05c3387a01d8d02a656d2bfff67e9f46b2d8a6aac28129e52efddf6e552214c3f8a45bc7a912cca9a7fec1d7d06412c6972cb9e3dc518983f56530b8bffe7f92c4b6eb47d4aef59fb513c4653a42de61bc17ad7728e7fc7590ff05a9e991de03f023d0aaf8688ed6170def5091c66576a424ac1cb'
        op = OnionPacket.from_bytes(bfh(packet))
        self.assertEqual(op.hmac, bfh('8e7fc7590ff05a9e991de03f023d0aaf8688ed6170def5091c66576a424ac1cb'))
        self.assertEqual(op.public_key, bfh('02531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337'))
        self.assertEqual(op.hops_data, bfh('93b828776d70aabbd8cef1a5b52d5a397ae1a20f20435ff6057cd8be339d5aee226660ef73b64afa45dbf2e6e8e26eb96a259b2db5aeecda1ce2e768bbc35d389d7f320ca3d2bd14e2689bef2f5ac0307eaaabc1924eb972c1563d4646ae131accd39da766257ed35ea36e4222527d1db4fa7b2000aab9eafcceed45e28b5560312d4e2299bd8d1e7fe27d10925966c28d497aec400b4630485e82efbabc00550996bdad5d6a9a8c75952f126d14ad2cff91e16198691a7ef2937de83209285f1fb90944b4e46bca7c856a9ce3da10cdf2a7d00dc2bf4f114bc4d3ed67b91cbde558ce9af86dc81fbdc37f8e301b29e23c1466659c62bdbf8cff5d4c20f0fb0851ec72f5e9385dd40fdd2e3ed67ca4517117825665e50a3e26f73c66998daf18e418e8aef9ce2d20da33c3629db2933640e03e7b44c2edf49e9b482db7b475cfd4c617ae1d46d5c24d697846f9f08561eac2b065f9b382501f6eabf07343ed6c602f61eab99cdb52adf63fd44a8db2d3016387ea708fc1c08591e19b4d9984ebe31edbd684c2ea86526dd8c7732b1d8d9117511dc1b643976d356258fce8313b1cb92682f41ab72dedd766f06de375f9edacbcd0ca8c99b865ea2b7952318ea1fd20775a28028b5cf59dece5de14f615b8df254eee63493a5111ea987224bea006d8f1b60d565eef06ac0da194dba2a6d02e79b2f2f34e9ca6e1984a507319d86e9d4fcaeea41b4b9144e0b1826304d4cc1da61cfc5f8b9850697df8adc5e9d6f3acb3219b02764b4909f2b2b22e799fd66c383414a84a7d791b899d4aa663770009eb122f90282c8cb9cda16aba6897edcf9b32951d0080c0f52be3ca011fbec3fb16423deb47744645c3b05fdbd932edf54ba6efd26e65340a8e9b1d1216582e1b30d64524f8ca2d6c5ba63a38f7120a3ed71bed8960bcac2feee2dd41c90be48e3c11ec518eb3d872779e4765a6cc28c6b0fa71ab57ced73ae963cc630edae4258cba2bf25821a6ae049fec2fca28b5dd1bb004d92924b65701b06dcf37f0ccd147a13a03f9bc0f98b7d78fe9058089756931e2cd0e0ed92ec6759d07b248069526c67e9e6ce095118fd3501ba0f858ef030b76c6f6beb11a09317b5ad25343f4b31aef02bc555951bc7791c2c289ecf94d5544dcd6ad3021ed8e8e3db34b2a73e1eedb57b578b068a5401836d6e382110b73690a94328c404af25e85a8d6b808893d1b71af6a31fadd8a8cc6e31ecc0d9ff7e6b91fd03c274a5c1f1ccd25b61150220a3fddb04c91012f5f7a83a5c90deb2470089d6e38cd5914b9c946eca6e9d31bbf8667d36cf87effc3f3ff283c21dd4137bd569fe7cf758feac94053e4baf7338bb592c8b7c291667fadf4a9bf9a2a154a18f612cbc7f851b3f8f2070e0a9d180622ee4f8e81b0ab250d504cef24116a3ff188cc829fcd8610b56343569e8dc997629410d1967ca9dd1d27eec5e01e4375aad16c46faba268524b154850d0d6fe3a76af2c6aa3e97647c51036049ac565370028d6a439a2672b6face56e1b171496c0722cfa22d9da631be359661617c5d5a2d286c5e19db9452c1e21a0107b6400debda2decb0c838f342dd017cdb2dccdf1fe97e3df3f881856b546997a3fed9e279c720145101567dd56be21688fed66bf9759e432a9aa89cbbd225d13cdea4ca05f7a45cfb6a682a3d5b1e18f7e6cf934fae5098108bae9058d05c3387a01d8d02a656d2bfff67e9f46b2d8a6aac28129e52efddf6e552214c3f8a45bc7a912cca9a7fec1d7d06412c6972cb9e3dc518983f56530b8bffe7f92c4b6eb47d4aef59fb513c4653a42de61bc17ad772'))

    def test_decode_onion_message(self):
        msg = '0201031195a8046dcbb8e17034bca630065e7a0982e4e36f6f7e5a8d4554e4846fcd9905560002531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe33793b828776d70aabbd8cef1a5b52d5a397ae1a20f20435ff6057cd8be339d5aee226660ef73b64afa45dbf2e6e8e26eb96a259b2db5aeecda1ce2e768bbc35d389d7f320ca3d2bd14e2689bef2f5ac0307eaaabc1924eb972c1563d4646ae131accd39da766257ed35ea36e4222527d1db4fa7b2000aab9eafcceed45e28b5560312d4e2299bd8d1e7fe27d10925966c28d497aec400b4630485e82efbabc00550996bdad5d6a9a8c75952f126d14ad2cff91e16198691a7ef2937de83209285f1fb90944b4e46bca7c856a9ce3da10cdf2a7d00dc2bf4f114bc4d3ed67b91cbde558ce9af86dc81fbdc37f8e301b29e23c1466659c62bdbf8cff5d4c20f0fb0851ec72f5e9385dd40fdd2e3ed67ca4517117825665e50a3e26f73c66998daf18e418e8aef9ce2d20da33c3629db2933640e03e7b44c2edf49e9b482db7b475cfd4c617ae1d46d5c24d697846f9f08561eac2b065f9b382501f6eabf07343ed6c602f61eab99cdb52adf63fd44a8db2d3016387ea708fc1c08591e19b4d9984ebe31edbd684c2ea86526dd8c7732b1d8d9117511dc1b643976d356258fce8313b1cb92682f41ab72dedd766f06de375f9edacbcd0ca8c99b865ea2b7952318ea1fd20775a28028b5cf59dece5de14f615b8df254eee63493a5111ea987224bea006d8f1b60d565eef06ac0da194dba2a6d02e79b2f2f34e9ca6e1984a507319d86e9d4fcaeea41b4b9144e0b1826304d4cc1da61cfc5f8b9850697df8adc5e9d6f3acb3219b02764b4909f2b2b22e799fd66c383414a84a7d791b899d4aa663770009eb122f90282c8cb9cda16aba6897edcf9b32951d0080c0f52be3ca011fbec3fb16423deb47744645c3b05fdbd932edf54ba6efd26e65340a8e9b1d1216582e1b30d64524f8ca2d6c5ba63a38f7120a3ed71bed8960bcac2feee2dd41c90be48e3c11ec518eb3d872779e4765a6cc28c6b0fa71ab57ced73ae963cc630edae4258cba2bf25821a6ae049fec2fca28b5dd1bb004d92924b65701b06dcf37f0ccd147a13a03f9bc0f98b7d78fe9058089756931e2cd0e0ed92ec6759d07b248069526c67e9e6ce095118fd3501ba0f858ef030b76c6f6beb11a09317b5ad25343f4b31aef02bc555951bc7791c2c289ecf94d5544dcd6ad3021ed8e8e3db34b2a73e1eedb57b578b068a5401836d6e382110b73690a94328c404af25e85a8d6b808893d1b71af6a31fadd8a8cc6e31ecc0d9ff7e6b91fd03c274a5c1f1ccd25b61150220a3fddb04c91012f5f7a83a5c90deb2470089d6e38cd5914b9c946eca6e9d31bbf8667d36cf87effc3f3ff283c21dd4137bd569fe7cf758feac94053e4baf7338bb592c8b7c291667fadf4a9bf9a2a154a18f612cbc7f851b3f8f2070e0a9d180622ee4f8e81b0ab250d504cef24116a3ff188cc829fcd8610b56343569e8dc997629410d1967ca9dd1d27eec5e01e4375aad16c46faba268524b154850d0d6fe3a76af2c6aa3e97647c51036049ac565370028d6a439a2672b6face56e1b171496c0722cfa22d9da631be359661617c5d5a2d286c5e19db9452c1e21a0107b6400debda2decb0c838f342dd017cdb2dccdf1fe97e3df3f881856b546997a3fed9e279c720145101567dd56be21688fed66bf9759e432a9aa89cbbd225d13cdea4ca05f7a45cfb6a682a3d5b1e18f7e6cf934fae5098108bae9058d05c3387a01d8d02a656d2bfff67e9f46b2d8a6aac28129e52efddf6e552214c3f8a45bc7a912cca9a7fec1d7d06412c6972cb9e3dc518983f56530b8bffe7f92c4b6eb47d4aef59fb513c4653a42de61bc17ad7728e7fc7590ff05a9e991de03f023d0aaf8688ed6170def5091c66576a424ac1cb'
        msgtype, data = decode_msg(bfh(msg))
        self.assertEqual(msgtype, 'onion_message')
        self.assertEqual(data, {
            'blinding': bfh('031195a8046dcbb8e17034bca630065e7a0982e4e36f6f7e5a8d4554e4846fcd99'),
            'len': 1366,
            'onion_message_packet': bfh('0002531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe33793b828776d70aabbd8cef1a5b52d5a397ae1a20f20435ff6057cd8be339d5aee226660ef73b64afa45dbf2e6e8e26eb96a259b2db5aeecda1ce2e768bbc35d389d7f320ca3d2bd14e2689bef2f5ac0307eaaabc1924eb972c1563d4646ae131accd39da766257ed35ea36e4222527d1db4fa7b2000aab9eafcceed45e28b5560312d4e2299bd8d1e7fe27d10925966c28d497aec400b4630485e82efbabc00550996bdad5d6a9a8c75952f126d14ad2cff91e16198691a7ef2937de83209285f1fb90944b4e46bca7c856a9ce3da10cdf2a7d00dc2bf4f114bc4d3ed67b91cbde558ce9af86dc81fbdc37f8e301b29e23c1466659c62bdbf8cff5d4c20f0fb0851ec72f5e9385dd40fdd2e3ed67ca4517117825665e50a3e26f73c66998daf18e418e8aef9ce2d20da33c3629db2933640e03e7b44c2edf49e9b482db7b475cfd4c617ae1d46d5c24d697846f9f08561eac2b065f9b382501f6eabf07343ed6c602f61eab99cdb52adf63fd44a8db2d3016387ea708fc1c08591e19b4d9984ebe31edbd684c2ea86526dd8c7732b1d8d9117511dc1b643976d356258fce8313b1cb92682f41ab72dedd766f06de375f9edacbcd0ca8c99b865ea2b7952318ea1fd20775a28028b5cf59dece5de14f615b8df254eee63493a5111ea987224bea006d8f1b60d565eef06ac0da194dba2a6d02e79b2f2f34e9ca6e1984a507319d86e9d4fcaeea41b4b9144e0b1826304d4cc1da61cfc5f8b9850697df8adc5e9d6f3acb3219b02764b4909f2b2b22e799fd66c383414a84a7d791b899d4aa663770009eb122f90282c8cb9cda16aba6897edcf9b32951d0080c0f52be3ca011fbec3fb16423deb47744645c3b05fdbd932edf54ba6efd26e65340a8e9b1d1216582e1b30d64524f8ca2d6c5ba63a38f7120a3ed71bed8960bcac2feee2dd41c90be48e3c11ec518eb3d872779e4765a6cc28c6b0fa71ab57ced73ae963cc630edae4258cba2bf25821a6ae049fec2fca28b5dd1bb004d92924b65701b06dcf37f0ccd147a13a03f9bc0f98b7d78fe9058089756931e2cd0e0ed92ec6759d07b248069526c67e9e6ce095118fd3501ba0f858ef030b76c6f6beb11a09317b5ad25343f4b31aef02bc555951bc7791c2c289ecf94d5544dcd6ad3021ed8e8e3db34b2a73e1eedb57b578b068a5401836d6e382110b73690a94328c404af25e85a8d6b808893d1b71af6a31fadd8a8cc6e31ecc0d9ff7e6b91fd03c274a5c1f1ccd25b61150220a3fddb04c91012f5f7a83a5c90deb2470089d6e38cd5914b9c946eca6e9d31bbf8667d36cf87effc3f3ff283c21dd4137bd569fe7cf758feac94053e4baf7338bb592c8b7c291667fadf4a9bf9a2a154a18f612cbc7f851b3f8f2070e0a9d180622ee4f8e81b0ab250d504cef24116a3ff188cc829fcd8610b56343569e8dc997629410d1967ca9dd1d27eec5e01e4375aad16c46faba268524b154850d0d6fe3a76af2c6aa3e97647c51036049ac565370028d6a439a2672b6face56e1b171496c0722cfa22d9da631be359661617c5d5a2d286c5e19db9452c1e21a0107b6400debda2decb0c838f342dd017cdb2dccdf1fe97e3df3f881856b546997a3fed9e279c720145101567dd56be21688fed66bf9759e432a9aa89cbbd225d13cdea4ca05f7a45cfb6a682a3d5b1e18f7e6cf934fae5098108bae9058d05c3387a01d8d02a656d2bfff67e9f46b2d8a6aac28129e52efddf6e552214c3f8a45bc7a912cca9a7fec1d7d06412c6972cb9e3dc518983f56530b8bffe7f92c4b6eb47d4aef59fb513c4653a42de61bc17ad7728e7fc7590ff05a9e991de03f023d0aaf8688ed6170def5091c66576a424ac1cb')
        })

    def test_decrypt_onion_message(self):
        onion_message_packet = bfh('0002531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe33793b828776d70aabbd8cef1a5b52d5a397ae1a20f20435ff6057cd8be339d5aee226660ef73b64afa45dbf2e6e8e26eb96a259b2db5aeecda1ce2e768bbc35d389d7f320ca3d2bd14e2689bef2f5ac0307eaaabc1924eb972c1563d4646ae131accd39da766257ed35ea36e4222527d1db4fa7b2000aab9eafcceed45e28b5560312d4e2299bd8d1e7fe27d10925966c28d497aec400b4630485e82efbabc00550996bdad5d6a9a8c75952f126d14ad2cff91e16198691a7ef2937de83209285f1fb90944b4e46bca7c856a9ce3da10cdf2a7d00dc2bf4f114bc4d3ed67b91cbde558ce9af86dc81fbdc37f8e301b29e23c1466659c62bdbf8cff5d4c20f0fb0851ec72f5e9385dd40fdd2e3ed67ca4517117825665e50a3e26f73c66998daf18e418e8aef9ce2d20da33c3629db2933640e03e7b44c2edf49e9b482db7b475cfd4c617ae1d46d5c24d697846f9f08561eac2b065f9b382501f6eabf07343ed6c602f61eab99cdb52adf63fd44a8db2d3016387ea708fc1c08591e19b4d9984ebe31edbd684c2ea86526dd8c7732b1d8d9117511dc1b643976d356258fce8313b1cb92682f41ab72dedd766f06de375f9edacbcd0ca8c99b865ea2b7952318ea1fd20775a28028b5cf59dece5de14f615b8df254eee63493a5111ea987224bea006d8f1b60d565eef06ac0da194dba2a6d02e79b2f2f34e9ca6e1984a507319d86e9d4fcaeea41b4b9144e0b1826304d4cc1da61cfc5f8b9850697df8adc5e9d6f3acb3219b02764b4909f2b2b22e799fd66c383414a84a7d791b899d4aa663770009eb122f90282c8cb9cda16aba6897edcf9b32951d0080c0f52be3ca011fbec3fb16423deb47744645c3b05fdbd932edf54ba6efd26e65340a8e9b1d1216582e1b30d64524f8ca2d6c5ba63a38f7120a3ed71bed8960bcac2feee2dd41c90be48e3c11ec518eb3d872779e4765a6cc28c6b0fa71ab57ced73ae963cc630edae4258cba2bf25821a6ae049fec2fca28b5dd1bb004d92924b65701b06dcf37f0ccd147a13a03f9bc0f98b7d78fe9058089756931e2cd0e0ed92ec6759d07b248069526c67e9e6ce095118fd3501ba0f858ef030b76c6f6beb11a09317b5ad25343f4b31aef02bc555951bc7791c2c289ecf94d5544dcd6ad3021ed8e8e3db34b2a73e1eedb57b578b068a5401836d6e382110b73690a94328c404af25e85a8d6b808893d1b71af6a31fadd8a8cc6e31ecc0d9ff7e6b91fd03c274a5c1f1ccd25b61150220a3fddb04c91012f5f7a83a5c90deb2470089d6e38cd5914b9c946eca6e9d31bbf8667d36cf87effc3f3ff283c21dd4137bd569fe7cf758feac94053e4baf7338bb592c8b7c291667fadf4a9bf9a2a154a18f612cbc7f851b3f8f2070e0a9d180622ee4f8e81b0ab250d504cef24116a3ff188cc829fcd8610b56343569e8dc997629410d1967ca9dd1d27eec5e01e4375aad16c46faba268524b154850d0d6fe3a76af2c6aa3e97647c51036049ac565370028d6a439a2672b6face56e1b171496c0722cfa22d9da631be359661617c5d5a2d286c5e19db9452c1e21a0107b6400debda2decb0c838f342dd017cdb2dccdf1fe97e3df3f881856b546997a3fed9e279c720145101567dd56be21688fed66bf9759e432a9aa89cbbd225d13cdea4ca05f7a45cfb6a682a3d5b1e18f7e6cf934fae5098108bae9058d05c3387a01d8d02a656d2bfff67e9f46b2d8a6aac28129e52efddf6e552214c3f8a45bc7a912cca9a7fec1d7d06412c6972cb9e3dc518983f56530b8bffe7f92c4b6eb47d4aef59fb513c4653a42de61bc17ad7728e7fc7590ff05a9e991de03f023d0aaf8688ed6170def5091c66576a424ac1cb')

        o = OnionPacket.from_bytes(onion_message_packet)
        our_privkey = bfh('4141414141414141414141414141414141414141414141414141414141414141')
        blinding = bfh('031195a8046dcbb8e17034bca630065e7a0982e4e36f6f7e5a8d4554e4846fcd99')

        shared_secret = get_ecdh(our_privkey, blinding)
        b_hmac = get_bolt04_onion_key(b'blinded_node_id', shared_secret)
        b_hmac_int = int.from_bytes(b_hmac, byteorder="big")

        our_privkey_int = int.from_bytes(our_privkey, byteorder="big")
        our_privkey_int = our_privkey_int * b_hmac_int % ecc.CURVE_ORDER
        our_privkey = our_privkey_int.to_bytes(32, byteorder="big")

        p = process_onion_packet(o, our_privkey, tlv_stream_name='onionmsg_tlv')

        self.assertEqual(p.hop_data.blind_fields, {})
        self.assertEqual(p.hop_data.hmac, bfh('a5296325ba478ba1e1a9d1f30a2d5052b2e2889bbd64f72c72bc71d8817288a2'))
        self.assertEqual(p.hop_data.payload, {'encrypted_recipient_data': {'encrypted_recipient_data': bfh('49531cf38d3280b7f4af6d6461a2b32e3df50acfd35176fc61422a1096eed4dfc3806f29bf74320f712a61c766e7f7caac0c42f86040125fbaeec0c7613202b206dbdd31fda56394367b66a711bfd7d5bedbe20bed1b')}})
        self.assertEqual(p.hop_data.tlv_stream_name, 'onionmsg_tlv')
        self.assertEqual(p.next_packet.hmac, bfh('a5296325ba478ba1e1a9d1f30a2d5052b2e2889bbd64f72c72bc71d8817288a2'))
        self.assertEqual(p.next_packet.public_key, bfh('02536d53f93796cad550b6c68662dca41f7e8c221c31022c64dd1a627b2df3982b'))
        self.assertEqual(p.next_packet.hops_data, bfh('25eac261e88369cfc66e1e3b6d9829cb3dcd707046e68a7796065202a7904811bf2608c5611cf74c9eb5371c7eb1a4428bb39a041493e2a568ddb0b2482a6cc6711bc6116cef144ebf988073cb18d9dd4ce2d3aa9de91a7dc6d7c6f11a852024626e66b41ba1158055505dff9cb15aa51099f315564d9ee3ed6349665dc3e209eedf9b5805ee4f69d315df44c80e63d0e2efbdab60ec96f44a3447c6a6ddb1efb6aa4e072bde1dab974081646bfddf3b02daa2b83847d74dd336465e76e9b8fecc2b0414045eeedfc39939088a76820177dd1103c99939e659beb07197bab9f714b30ba8dc83738e9a6553a57888aaeda156c68933a2f4ff35e3f81135076b944ed9856acbfee9c61299a5d1763eadd14bf5eaf71304c8e165e590d7ecbcd25f1650bf5b6c2ad1823b2dc9145e168974ecf6a2273c94decff76d94bc6708007a17f22262d63033c184d0166c14f41b225a956271947aae6ce65890ed8f0d09c6ffe05ec02ee8b9de69d7077a0c5adeb813aabcc1ba8975b73ab06ddea5f4db3c23a1de831602de2b83f990d4133871a1a81e53f86393e6a7c3a7b73f0c099fa72afe26c3027bb9412338a19303bd6e6591c04fb4cde9b832b5f41ae199301ea8c303b5cef3aca599454273565de40e1148156d1f97c1aa9e58459ab318304075e034f5b7899c12587b86776a18a1da96b7bcdc22864fccc4c41538ebce92a6f054d53bf46770273a70e75fe0155cd6d2f2e937465b0825ce3123b8c206fac4c30478fa0f08a97ade7216dce11626401374993213636e93545a31f500562130f2feb04089661ad8c34d5a4cbd2e4e426f37cb094c786198a220a2646ecadc38c04c29ee67b19d662c209a7b30bfecc7fe8bf7d274de0605ee5df4db490f6d32234f6af639d3fce38a2801bcf8d51e9c090a6c6932355a83848129a378095b34e71cb8f51152dc035a4fe8e802fec8de221a02ba5afd6765ce570bef912f87357936ea0b90cb2990f56035e89539ec66e8dbd6ed50835158614096990e019c3eba3d7dd6a77147641c6145e8b17552cd5cf7cd163dd40b9eaeba8c78e03a2cd8c0b7997d6f56d35f38983a202b4eb8a54e14945c4de1a6dde46167e11708b7a5ff5cb9c0f7fc12fae49a012aa90bb1995c038130b749c48e6f1ffb732e92086def42af10fbc460d94abeb7b2fa744a5e9a491d62a08452be8cf2fdef573deedc1fe97098bce889f98200b26f9bb99da9aceddda6d793d8e0e44a2601ef4590cfbb5c3d0197aac691e3d31c20fd8e38764962ca34dabeb85df28feabaf6255d4d0df3d814455186a84423182caa87f9673df770432ad8fdfe78d4888632d460d36d2719e8fa8e4b4ca10d817c5d6bc44a8b2affab8c2ba53b8bf4994d63286c2fad6be04c28661162fa1a67065ecda8ba8c13aee4a8039f4f0110e0c0da2366f178d8903e19136dad6df9d8693ce71f3a270f9941de2a93d9b67bc516207ac1687bf6e00b29723c42c7d9c90df9d5e599dbeb7b73add0a6a2b7aba82f98ac93cb6e60494040445229f983a81c34f7f686d166dfc98ec23a6318d4a02a311ac28d655ea4e0f9c3014984f31e621ef003e98c373561d9040893feece2e0fa6cd2dd565e6fbb2773a2407cb2c3273c306cf71f427f2e551c4092e067cf9869f31ac7c6c80dd52d4f85be57a891a41e34be0d564e39b4af6f46b85339254a58b205fb7e10e7d0470ee73622493f28c08962118c23a1198467e72c4ae1cd482144b419247a5895975ea90d135e2a46ef7e5794a1551a447ff0a0d299b66a7f565cd86531f5e7af5408d85d877ce95b1df12b88b7d5954903'))

    def test_blinding_privkey(self):
        a = blinding_privkey(bfh('4141414141414141414141414141414141414141414141414141414141414141'),
                             bfh('031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f'))
        self.assertEqual(a, bfh('7e959bf6bdd3a98caf26cbbee7b69678381d5fa2882c6c12eb2042c2367264b0'))

    def test_create_blinded_path(self):
        pubkey = bfh('02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619')  # alice
        session_key = bfh('3030303030303030303030303030303030303030303030303030303030303030')

        final_recipient_data = {'path_id': {'data': bfh('0102')}}
        rp = create_blinded_path(session_key, [pubkey], final_recipient_data)

        self.assertEqual(pubkey, rp['first_node_id'])
        self.assertEqual(bfh('022ed557f5ad336b31a49857e4e9664954ac33385aa20a93e2d64bfe7f08f51277'), rp['blinding'])
        self.assertEqual(1, rp['num_hops'])
        self.assertEqual([{
            'blinded_node_id': bfh('031e5d91e6c417f6e8c16d1086db1887edef7be9334f5e744d04edb8da7507481e'),
            'enclen': 20,
            'encrypted_recipient_data': bfh('2dbaa54a819775aa0548ab85db68c5099e7b1180')
        }], rp['path'])

        # TODO: serialization test to test_lnmsg.py
        with io.BytesIO() as blinded_path_fd:
            OnionWireSerializer._write_complex_field(fd=blinded_path_fd,
                                                     field_type='blinded_path',
                                                     count=1,
                                                     value=rp)
            blinded_path = blinded_path_fd.getvalue()
        self.assertEqual(blinded_path, bfh('02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619022ed557f5ad336b31a49857e4e9664954ac33385aa20a93e2d64bfe7f08f5127701031e5d91e6c417f6e8c16d1086db1887edef7be9334f5e744d04edb8da7507481e00142dbaa54a819775aa0548ab85db68c5099e7b1180'))

    def prepare_blinded_path_bob_to_dave(self):
        # test vectors https://github.com/lightning/bolts/pull/759/files
        bp_payment_path_pubkeys = [
            bfh('0324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c'),  # Bob
            bfh('027f31ebc5462c1fdce1b737ecff52d37d75dea43ce11c74d25aa297165faa2007'),  # Carol
            bfh('032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991')  # Dave
        ]

        bp_session_key = bfh('0101010101010101010101010101010101010101010101010101010101010101')

        final_recipient_data = {
            'padding': {'padding': b''},
            'path_id': {'data': bfh('deadbeefbadc0ffeedeadbeefbadc0ffeedeadbeefbadc0ffeedeadbeefbadc0')},
            'unknown_tag_65535': {'data': bfh('06c1')}
        }
        hop_extras = [
            {'unknown_tag_561': {'data': bfh('123456')}},
            {'padding': {'padding': bfh('0000000000')}}
        ]
        return create_blinded_path(bp_session_key, bp_payment_path_pubkeys, final_recipient_data, hop_extras)

    def test_create_onionmessage_to_blinded_path_via_alice(self):
        # test vectors https://github.com/lightning/bolts/pull/759/files
        blinded_path_to_dave = self.prepare_blinded_path_bob_to_dave()

        route_until_bob = [
            (bfh('02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619'),  # alice
             bfh('6363636363636363636363636363636363636363636363636363636363636363'))    # blinding secret
                                                                                         # bob is blinded_path[0]
        ]
        session_key = bfh('0303030303030303030303030303030303030303030303030303030303030303')
        hop_shared_secrets, blinded_node_ids = get_shared_secrets_along_route2(route_until_bob, session_key)

        hops_data = [
            OnionHopsDataSingle(tlv_stream_name='onionmsg_tlv',
                                blind_fields={'next_node_id': {'node_id': bfh('0324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c')},
                                              'next_blinding_override': {'blinding': bfh('031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f')},
                                              }
                                ),
        ]
        # encrypt encrypted_data_tlv here
        for i in range(len(hops_data)):
            encrypted_recipient_data = encrypt_encrypted_data_tlv(shared_secret=hop_shared_secrets[i], **hops_data[i].blind_fields)
            hops_data[i].payload['encrypted_recipient_data'] = {'encrypted_recipient_data': encrypted_recipient_data}

        blinded_path_blinded_ids = []
        for i, x in enumerate(blinded_path_to_dave.get('path')):
            blinded_path_blinded_ids.append(x.get('blinded_node_id'))
            payload = {'encrypted_recipient_data': {'encrypted_recipient_data': x.get('encrypted_recipient_data')}}
            if i == len(blinded_path_to_dave.get('path')) - 1:
                # add final recipient payload
                payload['message'] = {'text': b'hello'}
            hops_data.append(
                OnionHopsDataSingle(tlv_stream_name='onionmsg_tlv',
                                    payload=payload)
            )

        payment_path_pubkeys = blinded_node_ids + blinded_path_blinded_ids
        hop_shared_secrets = get_shared_secrets_along_route(payment_path_pubkeys, session_key)
        encrypt_onionmsg_tlv_hops_data(hops_data, hop_shared_secrets)
        packet = new_onion_packet(payment_path_pubkeys, session_key, hops_data, onion_message=True)

        self.assertEqual(packet.hmac, bfh('8e7fc7590ff05a9e991de03f023d0aaf8688ed6170def5091c66576a424ac1cb'))
        self.assertEqual(packet.public_key, bfh('02531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337'))
        self.assertEqual(packet.hops_data, bfh('93b828776d70aabbd8cef1a5b52d5a397ae1a20f20435ff6057cd8be339d5aee226660ef73b64afa45dbf2e6e8e26eb96a259b2db5aeecda1ce2e768bbc35d389d7f320ca3d2bd14e2689bef2f5ac0307eaaabc1924eb972c1563d4646ae131accd39da766257ed35ea36e4222527d1db4fa7b2000aab9eafcceed45e28b5560312d4e2299bd8d1e7fe27d10925966c28d497aec400b4630485e82efbabc00550996bdad5d6a9a8c75952f126d14ad2cff91e16198691a7ef2937de83209285f1fb90944b4e46bca7c856a9ce3da10cdf2a7d00dc2bf4f114bc4d3ed67b91cbde558ce9af86dc81fbdc37f8e301b29e23c1466659c62bdbf8cff5d4c20f0fb0851ec72f5e9385dd40fdd2e3ed67ca4517117825665e50a3e26f73c66998daf18e418e8aef9ce2d20da33c3629db2933640e03e7b44c2edf49e9b482db7b475cfd4c617ae1d46d5c24d697846f9f08561eac2b065f9b382501f6eabf07343ed6c602f61eab99cdb52adf63fd44a8db2d3016387ea708fc1c08591e19b4d9984ebe31edbd684c2ea86526dd8c7732b1d8d9117511dc1b643976d356258fce8313b1cb92682f41ab72dedd766f06de375f9edacbcd0ca8c99b865ea2b7952318ea1fd20775a28028b5cf59dece5de14f615b8df254eee63493a5111ea987224bea006d8f1b60d565eef06ac0da194dba2a6d02e79b2f2f34e9ca6e1984a507319d86e9d4fcaeea41b4b9144e0b1826304d4cc1da61cfc5f8b9850697df8adc5e9d6f3acb3219b02764b4909f2b2b22e799fd66c383414a84a7d791b899d4aa663770009eb122f90282c8cb9cda16aba6897edcf9b32951d0080c0f52be3ca011fbec3fb16423deb47744645c3b05fdbd932edf54ba6efd26e65340a8e9b1d1216582e1b30d64524f8ca2d6c5ba63a38f7120a3ed71bed8960bcac2feee2dd41c90be48e3c11ec518eb3d872779e4765a6cc28c6b0fa71ab57ced73ae963cc630edae4258cba2bf25821a6ae049fec2fca28b5dd1bb004d92924b65701b06dcf37f0ccd147a13a03f9bc0f98b7d78fe9058089756931e2cd0e0ed92ec6759d07b248069526c67e9e6ce095118fd3501ba0f858ef030b76c6f6beb11a09317b5ad25343f4b31aef02bc555951bc7791c2c289ecf94d5544dcd6ad3021ed8e8e3db34b2a73e1eedb57b578b068a5401836d6e382110b73690a94328c404af25e85a8d6b808893d1b71af6a31fadd8a8cc6e31ecc0d9ff7e6b91fd03c274a5c1f1ccd25b61150220a3fddb04c91012f5f7a83a5c90deb2470089d6e38cd5914b9c946eca6e9d31bbf8667d36cf87effc3f3ff283c21dd4137bd569fe7cf758feac94053e4baf7338bb592c8b7c291667fadf4a9bf9a2a154a18f612cbc7f851b3f8f2070e0a9d180622ee4f8e81b0ab250d504cef24116a3ff188cc829fcd8610b56343569e8dc997629410d1967ca9dd1d27eec5e01e4375aad16c46faba268524b154850d0d6fe3a76af2c6aa3e97647c51036049ac565370028d6a439a2672b6face56e1b171496c0722cfa22d9da631be359661617c5d5a2d286c5e19db9452c1e21a0107b6400debda2decb0c838f342dd017cdb2dccdf1fe97e3df3f881856b546997a3fed9e279c720145101567dd56be21688fed66bf9759e432a9aa89cbbd225d13cdea4ca05f7a45cfb6a682a3d5b1e18f7e6cf934fae5098108bae9058d05c3387a01d8d02a656d2bfff67e9f46b2d8a6aac28129e52efddf6e552214c3f8a45bc7a912cca9a7fec1d7d06412c6972cb9e3dc518983f56530b8bffe7f92c4b6eb47d4aef59fb513c4653a42de61bc17ad772'))

        self.assertEqual(packet.to_bytes(), bfh('0002531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe33793b828776d70aabbd8cef1a5b52d5a397ae1a20f20435ff6057cd8be339d5aee226660ef73b64afa45dbf2e6e8e26eb96a259b2db5aeecda1ce2e768bbc35d389d7f320ca3d2bd14e2689bef2f5ac0307eaaabc1924eb972c1563d4646ae131accd39da766257ed35ea36e4222527d1db4fa7b2000aab9eafcceed45e28b5560312d4e2299bd8d1e7fe27d10925966c28d497aec400b4630485e82efbabc00550996bdad5d6a9a8c75952f126d14ad2cff91e16198691a7ef2937de83209285f1fb90944b4e46bca7c856a9ce3da10cdf2a7d00dc2bf4f114bc4d3ed67b91cbde558ce9af86dc81fbdc37f8e301b29e23c1466659c62bdbf8cff5d4c20f0fb0851ec72f5e9385dd40fdd2e3ed67ca4517117825665e50a3e26f73c66998daf18e418e8aef9ce2d20da33c3629db2933640e03e7b44c2edf49e9b482db7b475cfd4c617ae1d46d5c24d697846f9f08561eac2b065f9b382501f6eabf07343ed6c602f61eab99cdb52adf63fd44a8db2d3016387ea708fc1c08591e19b4d9984ebe31edbd684c2ea86526dd8c7732b1d8d9117511dc1b643976d356258fce8313b1cb92682f41ab72dedd766f06de375f9edacbcd0ca8c99b865ea2b7952318ea1fd20775a28028b5cf59dece5de14f615b8df254eee63493a5111ea987224bea006d8f1b60d565eef06ac0da194dba2a6d02e79b2f2f34e9ca6e1984a507319d86e9d4fcaeea41b4b9144e0b1826304d4cc1da61cfc5f8b9850697df8adc5e9d6f3acb3219b02764b4909f2b2b22e799fd66c383414a84a7d791b899d4aa663770009eb122f90282c8cb9cda16aba6897edcf9b32951d0080c0f52be3ca011fbec3fb16423deb47744645c3b05fdbd932edf54ba6efd26e65340a8e9b1d1216582e1b30d64524f8ca2d6c5ba63a38f7120a3ed71bed8960bcac2feee2dd41c90be48e3c11ec518eb3d872779e4765a6cc28c6b0fa71ab57ced73ae963cc630edae4258cba2bf25821a6ae049fec2fca28b5dd1bb004d92924b65701b06dcf37f0ccd147a13a03f9bc0f98b7d78fe9058089756931e2cd0e0ed92ec6759d07b248069526c67e9e6ce095118fd3501ba0f858ef030b76c6f6beb11a09317b5ad25343f4b31aef02bc555951bc7791c2c289ecf94d5544dcd6ad3021ed8e8e3db34b2a73e1eedb57b578b068a5401836d6e382110b73690a94328c404af25e85a8d6b808893d1b71af6a31fadd8a8cc6e31ecc0d9ff7e6b91fd03c274a5c1f1ccd25b61150220a3fddb04c91012f5f7a83a5c90deb2470089d6e38cd5914b9c946eca6e9d31bbf8667d36cf87effc3f3ff283c21dd4137bd569fe7cf758feac94053e4baf7338bb592c8b7c291667fadf4a9bf9a2a154a18f612cbc7f851b3f8f2070e0a9d180622ee4f8e81b0ab250d504cef24116a3ff188cc829fcd8610b56343569e8dc997629410d1967ca9dd1d27eec5e01e4375aad16c46faba268524b154850d0d6fe3a76af2c6aa3e97647c51036049ac565370028d6a439a2672b6face56e1b171496c0722cfa22d9da631be359661617c5d5a2d286c5e19db9452c1e21a0107b6400debda2decb0c838f342dd017cdb2dccdf1fe97e3df3f881856b546997a3fed9e279c720145101567dd56be21688fed66bf9759e432a9aa89cbbd225d13cdea4ca05f7a45cfb6a682a3d5b1e18f7e6cf934fae5098108bae9058d05c3387a01d8d02a656d2bfff67e9f46b2d8a6aac28129e52efddf6e552214c3f8a45bc7a912cca9a7fec1d7d06412c6972cb9e3dc518983f56530b8bffe7f92c4b6eb47d4aef59fb513c4653a42de61bc17ad7728e7fc7590ff05a9e991de03f023d0aaf8688ed6170def5091c66576a424ac1cb'))
