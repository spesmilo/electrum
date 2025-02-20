import asyncio
import io
import os
import time
from functools import partial
import logging

import electrum_ecc as ecc
from electrum_ecc import ECPrivkey

from electrum import SimpleConfig
from electrum.lnmsg import decode_msg, OnionWireSerializer
from electrum.lnonion import (
    OnionHopsDataSingle, OnionPacket,
    process_onion_packet, get_bolt04_onion_key, encrypt_onionmsg_data_tlv,
    get_shared_secrets_along_route, new_onion_packet, ONION_MESSAGE_LARGE_SIZE,
    HOPS_DATA_SIZE, InvalidPayloadSize)
from electrum.crypto import get_ecdh, privkey_to_pubkey
from electrum.lnutil import LnFeatures, Keypair
from electrum.onion_message import (
    blinding_privkey, create_blinded_path, encrypt_onionmsg_tlv_hops_data,
    OnionMessageManager, NoRouteFound, Timeout
)
from electrum.util import bfh, read_json_file, OldTaskGroup, get_asyncio_loop
from electrum.logging import console_stderr_handler

from . import ElectrumTestCase, test_lnpeer
from .test_lnpeer import PutIntoOthersQueueTransport, PeerInTests, keypair

TIME_STEP = 0.01  # run tests 100 x faster
OnionMessageManager.SLEEP_DELAY *= TIME_STEP
OnionMessageManager.REQUEST_REPLY_TIMEOUT *= TIME_STEP
OnionMessageManager.REQUEST_REPLY_RETRY_DELAY *= TIME_STEP
OnionMessageManager.FORWARD_RETRY_TIMEOUT *= TIME_STEP
OnionMessageManager.FORWARD_RETRY_DELAY *= TIME_STEP

# test vectors https://github.com/lightning/bolts/pull/759/files
path = os.path.join(os.path.dirname(__file__), 'blinded-onion-message-onion-test.json')
test_vectors = read_json_file(path)
ONION_MESSAGE_PACKET = bfh(test_vectors['onionmessage']['onion_message_packet'])
HOPS = test_vectors['generate']['hops']
ALICE_TLVS = HOPS[0]['tlvs']
BOB_TLVS =   HOPS[1]['tlvs']
CAROL_TLVS = HOPS[2]['tlvs']
DAVE_TLVS =  HOPS[3]['tlvs']

ALICE_PUBKEY = bfh(test_vectors['route']['introduction_node_id'])
BOB_PUBKEY =   bfh(ALICE_TLVS['next_node_id'])
CAROL_PUBKEY = bfh(BOB_TLVS['next_node_id'])
DAVE_PUBKEY =  bfh(CAROL_TLVS['next_node_id'])

BLINDING_SECRET = bfh(HOPS[0]['blinding_secret'])
BLINDING_OVERRIDE_SECRET = bfh(ALICE_TLVS['blinding_override_secret'])

SESSION_KEY = bfh(test_vectors['generate']['session_key'])


class TestOnionMessage(ElectrumTestCase):

    def test_path_pubkeys_blinded_path_appended(self):

        hop_shared_secrets1, blinded_node_ids1 = get_shared_secrets_along_route([ALICE_PUBKEY], BLINDING_SECRET)
        hop_shared_secrets2, blinded_node_ids2 = get_shared_secrets_along_route([BOB_PUBKEY, CAROL_PUBKEY, DAVE_PUBKEY], BLINDING_OVERRIDE_SECRET)
        hop_shared_secrets = hop_shared_secrets1 + hop_shared_secrets2
        blinded_node_ids = blinded_node_ids1 + blinded_node_ids2

        for i, ss in enumerate(hop_shared_secrets):
            self.assertEqual(ss, bfh(HOPS[i]['ss']))
        for i, ss in enumerate(blinded_node_ids):
            self.assertEqual(ss, bfh(HOPS[i]['blinded_node_id']))

        hops_data = [
            OnionHopsDataSingle(
                tlv_stream_name='onionmsg_tlv',
                blind_fields={
                    'next_node_id': {'node_id': bfh(ALICE_TLVS['next_node_id'])},
                    'next_blinding_override': {'blinding': bfh(ALICE_TLVS['next_blinding_override'])},
                }
            ),
            OnionHopsDataSingle(
                tlv_stream_name='onionmsg_tlv',
                blind_fields={
                    'next_node_id': {'node_id': bfh(BOB_TLVS['next_node_id'])},
                    'unknown_tag_561': {'data': bfh(BOB_TLVS['unknown_tag_561'])},
                }
            ),
            OnionHopsDataSingle(
                tlv_stream_name='onionmsg_tlv',
                blind_fields={
                    'padding': {'padding': bfh(CAROL_TLVS['padding'])},
                    'next_node_id': {'node_id': bfh(CAROL_TLVS['next_node_id'])},
                }
            ),
            OnionHopsDataSingle(
                tlv_stream_name='onionmsg_tlv',
                payload={'message': {'text': bfh(test_vectors['onionmessage']['unknown_tag_1'])}},
                blind_fields={
                    'padding': {'padding': bfh(DAVE_TLVS['padding'])},
                    'path_id': {'data': bfh(DAVE_TLVS['path_id'])},
                    'unknown_tag_65535': {'data': bfh(DAVE_TLVS['unknown_tag_65535'])},
                }
            )
        ]

        encrypt_onionmsg_tlv_hops_data(hops_data, hop_shared_secrets)
        packet = new_onion_packet(blinded_node_ids, SESSION_KEY, hops_data, onion_message=True)
        self.assertEqual(packet.to_bytes(), ONION_MESSAGE_PACKET)

    def test_onion_message_payload_size(self):
        # Note: payload size is not _strictly_ limited to (1300+66, 32768+66), but Electrum only generates these sizes
        # However, the spec allows for other payload sizes.
        # https://github.com/lightning/bolts/blob/master/04-onion-routing.md
        # "SHOULD set onion_message_packet len to 1366 or 32834."
        hop_shared_secrets, blinded_node_ids = get_shared_secrets_along_route([DAVE_PUBKEY], SESSION_KEY)

        def hops_data_for_message(message):
            return [
                OnionHopsDataSingle(
                    tlv_stream_name='onionmsg_tlv',
                    payload={'message': {'text': message.encode('utf-8')}},
                    blind_fields={
                        'path_id': {'data': bfh('deadbeefbadc0ffeedeadbeefbadc0ffeedeadbeefbadc0ffeedeadbeefbadc0')},
                    }
                )
            ]
        hops_data = hops_data_for_message('short_message')  # fit in HOPS_DATA_SIZE
        encrypt_onionmsg_tlv_hops_data(hops_data, hop_shared_secrets)
        packet = new_onion_packet(blinded_node_ids, SESSION_KEY, hops_data, onion_message=True)
        self.assertEqual(len(packet.to_bytes()), HOPS_DATA_SIZE + 66)

        hops_data = hops_data_for_message('A' * HOPS_DATA_SIZE)  # fit in ONION_MESSAGE_LARGE_SIZE
        encrypt_onionmsg_tlv_hops_data(hops_data, hop_shared_secrets)
        packet = new_onion_packet(blinded_node_ids, SESSION_KEY, hops_data, onion_message=True)

        self.assertEqual(len(packet.to_bytes()), ONION_MESSAGE_LARGE_SIZE + 66)

        hops_data = hops_data_for_message('A' * ONION_MESSAGE_LARGE_SIZE)  # does not fit in ONION_MESSAGE_LARGE_SIZE
        encrypt_onionmsg_tlv_hops_data(hops_data, hop_shared_secrets)
        with self.assertRaises(InvalidPayloadSize):
            new_onion_packet(blinded_node_ids, SESSION_KEY, hops_data, onion_message=True)

    def test_decode_onion_message_packet(self):
        op = OnionPacket.from_bytes(ONION_MESSAGE_PACKET)
        self.assertEqual(op.hmac, bfh('8e7fc7590ff05a9e991de03f023d0aaf8688ed6170def5091c66576a424ac1cb'))
        self.assertEqual(op.public_key, bfh('02531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337'))
        self.assertEqual(op.hops_data, bfh('93b828776d70aabbd8cef1a5b52d5a397ae1a20f20435ff6057cd8be339d5aee226660ef73b64afa45dbf2e6e8e26eb96a259b2db5aeecda1ce2e768bbc35d389d7f320ca3d2bd14e2689bef2f5ac0307eaaabc1924eb972c1563d4646ae131accd39da766257ed35ea36e4222527d1db4fa7b2000aab9eafcceed45e28b5560312d4e2299bd8d1e7fe27d10925966c28d497aec400b4630485e82efbabc00550996bdad5d6a9a8c75952f126d14ad2cff91e16198691a7ef2937de83209285f1fb90944b4e46bca7c856a9ce3da10cdf2a7d00dc2bf4f114bc4d3ed67b91cbde558ce9af86dc81fbdc37f8e301b29e23c1466659c62bdbf8cff5d4c20f0fb0851ec72f5e9385dd40fdd2e3ed67ca4517117825665e50a3e26f73c66998daf18e418e8aef9ce2d20da33c3629db2933640e03e7b44c2edf49e9b482db7b475cfd4c617ae1d46d5c24d697846f9f08561eac2b065f9b382501f6eabf07343ed6c602f61eab99cdb52adf63fd44a8db2d3016387ea708fc1c08591e19b4d9984ebe31edbd684c2ea86526dd8c7732b1d8d9117511dc1b643976d356258fce8313b1cb92682f41ab72dedd766f06de375f9edacbcd0ca8c99b865ea2b7952318ea1fd20775a28028b5cf59dece5de14f615b8df254eee63493a5111ea987224bea006d8f1b60d565eef06ac0da194dba2a6d02e79b2f2f34e9ca6e1984a507319d86e9d4fcaeea41b4b9144e0b1826304d4cc1da61cfc5f8b9850697df8adc5e9d6f3acb3219b02764b4909f2b2b22e799fd66c383414a84a7d791b899d4aa663770009eb122f90282c8cb9cda16aba6897edcf9b32951d0080c0f52be3ca011fbec3fb16423deb47744645c3b05fdbd932edf54ba6efd26e65340a8e9b1d1216582e1b30d64524f8ca2d6c5ba63a38f7120a3ed71bed8960bcac2feee2dd41c90be48e3c11ec518eb3d872779e4765a6cc28c6b0fa71ab57ced73ae963cc630edae4258cba2bf25821a6ae049fec2fca28b5dd1bb004d92924b65701b06dcf37f0ccd147a13a03f9bc0f98b7d78fe9058089756931e2cd0e0ed92ec6759d07b248069526c67e9e6ce095118fd3501ba0f858ef030b76c6f6beb11a09317b5ad25343f4b31aef02bc555951bc7791c2c289ecf94d5544dcd6ad3021ed8e8e3db34b2a73e1eedb57b578b068a5401836d6e382110b73690a94328c404af25e85a8d6b808893d1b71af6a31fadd8a8cc6e31ecc0d9ff7e6b91fd03c274a5c1f1ccd25b61150220a3fddb04c91012f5f7a83a5c90deb2470089d6e38cd5914b9c946eca6e9d31bbf8667d36cf87effc3f3ff283c21dd4137bd569fe7cf758feac94053e4baf7338bb592c8b7c291667fadf4a9bf9a2a154a18f612cbc7f851b3f8f2070e0a9d180622ee4f8e81b0ab250d504cef24116a3ff188cc829fcd8610b56343569e8dc997629410d1967ca9dd1d27eec5e01e4375aad16c46faba268524b154850d0d6fe3a76af2c6aa3e97647c51036049ac565370028d6a439a2672b6face56e1b171496c0722cfa22d9da631be359661617c5d5a2d286c5e19db9452c1e21a0107b6400debda2decb0c838f342dd017cdb2dccdf1fe97e3df3f881856b546997a3fed9e279c720145101567dd56be21688fed66bf9759e432a9aa89cbbd225d13cdea4ca05f7a45cfb6a682a3d5b1e18f7e6cf934fae5098108bae9058d05c3387a01d8d02a656d2bfff67e9f46b2d8a6aac28129e52efddf6e552214c3f8a45bc7a912cca9a7fec1d7d06412c6972cb9e3dc518983f56530b8bffe7f92c4b6eb47d4aef59fb513c4653a42de61bc17ad772'))

    def test_decode_onion_message(self):
        msg = test_vectors['decrypt']['hops'][0]['onion_message']
        msgtype, data = decode_msg(bfh(msg))
        self.assertEqual(msgtype, 'onion_message')
        self.assertEqual(data, {
            'blinding': bfh(test_vectors['route']['blinding']),
            'len': 1366,
            'onion_message_packet': ONION_MESSAGE_PACKET,
        })

    def test_decrypt_onion_message(self):
        o = OnionPacket.from_bytes(ONION_MESSAGE_PACKET)
        our_privkey = bfh(test_vectors['decrypt']['hops'][0]['privkey'])
        blinding = bfh(test_vectors['route']['blinding'])

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

        onion_message_bob = test_vectors['decrypt']['hops'][1]['onion_message']
        msgtype, data = decode_msg(bfh(onion_message_bob))
        self.assertEqual(msgtype, 'onion_message')
        self.assertEqual(data, {
            'blinding': bfh(ALICE_TLVS['next_blinding_override']),
            'len': 1366,
            'onion_message_packet': p.next_packet.to_bytes(),
        })

    def test_blinding_privkey(self):
        a = blinding_privkey(bfh('4141414141414141414141414141414141414141414141414141414141414141'),
                             bfh('031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f'))
        self.assertEqual(a, bfh('7e959bf6bdd3a98caf26cbbee7b69678381d5fa2882c6c12eb2042c2367264b0'))

    def test_create_blinded_path(self):
        pubkey = ALICE_PUBKEY
        session_key = bfh('3030303030303030303030303030303030303030303030303030303030303030') # typo?
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
            OnionWireSerializer.write_field(
                fd=blinded_path_fd,
                field_type='blinded_path',
                count=1,
                value=rp)
            blinded_path = blinded_path_fd.getvalue()
        self.assertEqual(blinded_path, bfh('02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619022ed557f5ad336b31a49857e4e9664954ac33385aa20a93e2d64bfe7f08f5127701031e5d91e6c417f6e8c16d1086db1887edef7be9334f5e744d04edb8da7507481e00142dbaa54a819775aa0548ab85db68c5099e7b1180'))

    def prepare_blinded_path_bob_to_dave(self):
        final_recipient_data = {
            'padding': {'padding': bfh(DAVE_TLVS['padding'])},
            'path_id': {'data': bfh(DAVE_TLVS['path_id'])},
            'unknown_tag_65535': {'data': bfh(DAVE_TLVS['unknown_tag_65535'])}
        }
        hop_extras = [
            {'unknown_tag_561': {'data': bfh(BOB_TLVS['unknown_tag_561'])}},
            {'padding': {'padding': bfh(CAROL_TLVS['padding'])}}
        ]
        return create_blinded_path(BLINDING_OVERRIDE_SECRET, [BOB_PUBKEY, CAROL_PUBKEY, DAVE_PUBKEY], final_recipient_data, hop_extras=hop_extras)

    def test_create_onionmessage_to_blinded_path_via_alice(self):
        blinded_path_to_dave = self.prepare_blinded_path_bob_to_dave()
        hop_shared_secrets, blinded_node_ids = get_shared_secrets_along_route([ALICE_PUBKEY], BLINDING_SECRET)
        hops_data = [
            OnionHopsDataSingle(
                tlv_stream_name='onionmsg_tlv',
                blind_fields={
                    'next_node_id': {'node_id': BOB_PUBKEY},
                    'next_blinding_override': {'blinding': bfh(ALICE_TLVS['next_blinding_override'])},
                }
            ),
        ]
        # encrypt encrypted_data_tlv here
        for i in range(len(hops_data)):
            encrypted_recipient_data = encrypt_onionmsg_data_tlv(shared_secret=hop_shared_secrets[i], **hops_data[i].blind_fields)
            hops_data[i].payload['encrypted_recipient_data'] = {'encrypted_recipient_data': encrypted_recipient_data}

        blinded_path_blinded_ids = []
        for i, x in enumerate(blinded_path_to_dave.get('path')):
            blinded_path_blinded_ids.append(x.get('blinded_node_id'))
            payload = {'encrypted_recipient_data': {'encrypted_recipient_data': x.get('encrypted_recipient_data')}}
            if i == len(blinded_path_to_dave.get('path')) - 1:
                # add final recipient payload
                payload['message'] = {'text': bfh(test_vectors['onionmessage']['unknown_tag_1'])}
            hops_data.append(
                OnionHopsDataSingle(
                    tlv_stream_name='onionmsg_tlv',
                    payload=payload)
            )
        payment_path_pubkeys = blinded_node_ids + blinded_path_blinded_ids
        hop_shared_secrets, _ = get_shared_secrets_along_route(payment_path_pubkeys, SESSION_KEY)
        encrypt_onionmsg_tlv_hops_data(hops_data, hop_shared_secrets)
        packet = new_onion_packet(payment_path_pubkeys, SESSION_KEY, hops_data, onion_message=True)
        self.assertEqual(packet.to_bytes(), ONION_MESSAGE_PACKET)


class MockNetwork:
    def __init__(self):
        self.asyncio_loop = get_asyncio_loop()
        self.taskgroup = OldTaskGroup()
        self.config = SimpleConfig()
        self.config.EXPERIMENTAL_LN_FORWARD_PAYMENTS = True


class MockWallet:
    def __init__(self):
        pass


class MockLNWallet(test_lnpeer.MockLNWallet):

    async def add_peer(self, connect_str: str):
        t1 = PutIntoOthersQueueTransport(self.node_keypair, 'test')
        p1 = PeerInTests(self, keypair().pubkey, t1)
        self.peers[p1.pubkey] = p1
        p1.initialized.set_result(True)
        return p1


class MockPeer:
    their_features = LnFeatures(LnFeatures.OPTION_ONION_MESSAGE_OPT)

    def __init__(self, pubkey, on_send_message=None):
        self.pubkey = pubkey
        self.on_send_message = on_send_message

    async def wait_one_htlc_switch_iteration(self, *args):
        pass

    def send_message(self, *args, **kwargs):
        if self.on_send_message:
            self.on_send_message(*args, **kwargs)


class TestOnionMessageManager(ElectrumTestCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        console_stderr_handler.setLevel(logging.DEBUG)

    def setUp(self):
        super().setUp()

        def keypair(privkey: ECPrivkey):
            priv = privkey.get_secret_bytes()
            return Keypair(pubkey=privkey_to_pubkey(priv), privkey=priv)

        self.alice = keypair(ECPrivkey(privkey_bytes=b'\x41'*32))
        self.bob = keypair(ECPrivkey(privkey_bytes=b'\x42'*32))
        self.carol = keypair(ECPrivkey(privkey_bytes=b'\x43'*32))
        self.dave = keypair(ECPrivkey(privkey_bytes=b'\x44'*32))
        self.eve = keypair(ECPrivkey(privkey_bytes=b'\x45'*32))

    async def run_test1(self, t):
        t1 = t.submit_send(
            payload={'message': {'text': 'alice_timeout'.encode('utf-8')}},
            node_id_or_blinded_path=self.alice.pubkey)

        with self.assertRaises(Timeout):
            await t1

    async def run_test2(self, t):
        t2 = t.submit_send(
            payload={'message': {'text': 'bob_slow_timeout'.encode('utf-8')}},
            node_id_or_blinded_path=self.bob.pubkey)

        with self.assertRaises(Timeout):
            await t2

    async def run_test3(self, t, rkey):
        t3 = t.submit_send(
            payload={'message': {'text': 'carol_with_immediate_reply'.encode('utf-8')}},
            node_id_or_blinded_path=self.carol.pubkey,
            key=rkey)

        t3_result = await t3
        self.assertEqual(t3_result, ({'path_id': {'data': b'electrum' + rkey}}, {}))

    async def run_test4(self, t, rkey):
        t4 = t.submit_send(
            payload={'message': {'text': 'dave_with_slow_reply'.encode('utf-8')}},
            node_id_or_blinded_path=self.dave.pubkey,
            key=rkey)

        t4_result = await t4
        self.assertEqual(t4_result, ({'path_id': {'data': b'electrum' + rkey}}, {}))

    async def run_test5(self, t):
        t5 = t.submit_send(
            payload={'message': {'text': 'no_peer'.encode('utf-8')}},
            node_id_or_blinded_path=self.eve.pubkey)

        with self.assertRaises(NoRouteFound):
            await t5

    async def test_request_and_reply(self):
        n = MockNetwork()
        k = keypair()
        q1, q2 = asyncio.Queue(), asyncio.Queue()
        lnw = MockLNWallet(local_keypair=k, chans=[], tx_queue=q1, name='test_request_and_reply', has_anchors=False)

        def slow(*args, **kwargs):
            time.sleep(2*TIME_STEP)

        def withreply(key, *args, **kwargs):
            t.on_onion_message_received({'path_id': {'data': b'electrum' + key}}, {})

        def slowwithreply(key, *args, **kwargs):
            time.sleep(2*TIME_STEP)
            t.on_onion_message_received({'path_id': {'data': b'electrum' + key}}, {})

        rkey1 = bfh('0102030405060708')
        rkey2 = bfh('0102030405060709')

        lnw.peers[self.alice.pubkey] = MockPeer(self.alice.pubkey)
        lnw.peers[self.bob.pubkey] = MockPeer(self.bob.pubkey, on_send_message=slow)
        lnw.peers[self.carol.pubkey] = MockPeer(self.carol.pubkey, on_send_message=partial(withreply, rkey1))
        lnw.peers[self.dave.pubkey] = MockPeer(self.dave.pubkey, on_send_message=partial(slowwithreply, rkey2))
        t = OnionMessageManager(lnw)
        t.start_network(network=n)

        try:
            await asyncio.sleep(TIME_STEP)
            self.logger.debug('tests in sequence')
            await self.run_test1(t)
            await self.run_test2(t)
            await self.run_test3(t, rkey1)
            await self.run_test4(t, rkey2)
            await self.run_test5(t)
            self.logger.debug('tests in parallel')
            async with OldTaskGroup() as group:
                await group.spawn(self.run_test1(t))
                await group.spawn(self.run_test2(t))
                await group.spawn(self.run_test3(t, rkey1))
                await group.spawn(self.run_test4(t, rkey2))
                await group.spawn(self.run_test5(t))
        finally:
            await asyncio.sleep(TIME_STEP)

            self.logger.debug('stopping manager')
            await t.stop()
            await lnw.stop()

    async def test_forward(self):
        n = MockNetwork()
        q1 = asyncio.Queue()
        lnw = MockLNWallet(local_keypair=self.alice, chans=[], tx_queue=q1, name='alice', has_anchors=False)

        self.was_sent = False

        def on_send(to: str, *args, **kwargs):
            self.assertEqual(to, 'bob')
            self.was_sent = True
            # validate what's sent to bob
            self.assertEqual(bfh(HOPS[1]['E']), kwargs['blinding'])
            message_type, payload = decode_msg(bfh(test_vectors['decrypt']['hops'][1]['onion_message']))
            self.assertEqual(message_type, 'onion_message')
            self.assertEqual(payload['onion_message_packet'], kwargs['onion_message_packet'])

        lnw.peers[self.bob.pubkey] = MockPeer(self.bob.pubkey, on_send_message=partial(on_send, 'bob'))
        lnw.peers[self.carol.pubkey] = MockPeer(self.carol.pubkey, on_send_message=partial(on_send, 'carol'))
        t = OnionMessageManager(lnw)
        t.start_network(network=n)

        onionmsg = bfh(test_vectors['onionmessage']['onion_message_packet'])
        try:
            t.on_onion_message({
                'blinding': bfh(test_vectors['route']['blinding']),
                'len': len(onionmsg),
                'onion_message_packet': onionmsg
            })
        finally:
            await asyncio.sleep(2*TIME_STEP)

            self.logger.debug('stopping manager')
            await t.stop()
            await lnw.stop()

        self.assertTrue(self.was_sent)

    async def test_receive_unsolicited(self):
        n = MockNetwork()
        q1 = asyncio.Queue()
        lnw = MockLNWallet(local_keypair=self.dave, chans=[], tx_queue=q1, name='dave', has_anchors=False)

        t = OnionMessageManager(lnw)
        t.start_network(network=n)

        self.received_unsolicited = False

        def my_on_onion_message_received_unsolicited(*args, **kwargs):
            self.received_unsolicited = True

        t.on_onion_message_received_unsolicited = my_on_onion_message_received_unsolicited
        packet = bfh(test_vectors['decrypt']['hops'][3]['onion_message'])
        message_type, payload = decode_msg(packet)
        try:
            t.on_onion_message(payload)
            self.assertTrue(self.received_unsolicited)
        finally:
            await asyncio.sleep(TIME_STEP)

            self.logger.debug('stopping manager')
            await t.stop()
            await lnw.stop()
