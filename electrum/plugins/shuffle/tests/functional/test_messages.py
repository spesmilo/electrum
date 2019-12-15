import unittest

import imp
imp.load_module('electroncash', *imp.find_module('lib'))
imp.load_module('electroncash_plugins', *imp.find_module('plugins'))

from electroncash_plugins.shuffle.messages import Messages

class FakeEck(object):

    def sign_message(self, msg, compressed):
        return ("{} signed".format(msg)).encode('utf-8')

class TestMessages(unittest.TestCase):

    def __init__(self, *args, **kwargs):
        super(TestMessages,self).__init__(*args, **kwargs)
        self.messages = Messages()

    def test_001_make_greeting(self):
        verification_key = 'some verification key'
        amount = 11111
        self.messages.make_greeting(verification_key, amount)
        self.assertEquals(len(self.messages.packets.packet), 1,
                              msg="Should be one packet only")
        self.assertEquals(self.messages.packets.packet[0].packet.from_key.key, verification_key,
                          msg = "from key should be verification key")
        self.assertEquals(self.messages.packets.packet[0].packet.registration.amount, amount,
                          msg = "registration amount should be set")

    def test_002_encryption_key(self):
        ek = "encrytpion key"
        change = "change address"
        self.messages.add_encryption_key(ek, change)
        self.assertEquals(len(self.messages.packets.packet), 1,
                              msg="Should be one packet only")
        self.assertEquals(self.messages.packets.packet[0].packet.message.key.key, ek)
        self.assertEquals(self.messages.packets.packet[0].packet.message.address.address, change)
        ek_restored = self.messages.get_encryption_key()
        self.assertEquals(ek, ek_restored)

    def test_003_strs(self):
        strs = ["1","2","3"]
        for string in strs:
            self.messages.add_str(string)
        self.assertEquals(self.messages.get_strs(), strs)

    def test_004_hashes(self):
        hash = b"hash"
        self.messages.add_hash(hash)
        self.assertEquals(self.messages.get_hash(), hash)

    def test_005_signatures(self):
        signatures = {
            "hash_1": b'signature_1',
            "hash_2": b'signature_2',
            "hash_3": b'signature_3'
        }
        self.messages.add_signatures(signatures)
        self.assertEquals(self.messages.get_signatures(), signatures)

    def test_inputs(self):
        inputs = {
            "pubkey_1":[ "hash11", "hash12"],
            "pubkey_2":[ "hash21", "hash22"]
        }
        self.messages.add_inputs(inputs)
        self.assertEquals(self.messages.get_inputs(), inputs)

    def test_010_general_packet_issues(self):
        eck = FakeEck()
        session = b"session"
        number = 1111
        phase = "Announcement"
        vk_from = "from_key"
        vk_to = "to_key"
        self.messages.add_str("test_string")
        self.messages.add_hash(b"hash")
        self.messages.form_all_packets(eck, session, number, vk_from, vk_to, phase)
        for packet in self.messages.packets.packet:
            self.assertEquals(packet.packet.session, session)
            self.assertEquals(packet.packet.phase, self.messages.phases.get(phase, None))
            self.assertEquals(packet.packet.number, number)
            self.assertEquals(packet.packet.from_key.key, vk_from)
            self.assertEquals(packet.packet.to_key.key, vk_to)
            msg = packet.packet.SerializeToString()
            msg_signature = eck.sign_message(msg, True)
            self.assertEquals(packet.signature.signature, msg_signature)
            # Testing getters
            self.assertEquals(self.messages.get_session(), session)
            self.assertEquals(self.messages.get_phase(), self.messages.phases.get(phase, None))
            self.assertEquals(self.messages.get_number(), number)
            self.assertEquals(self.messages.get_from_key(), vk_from)
            self.assertEquals(self.messages.get_to_key(), vk_to)
        check_for_signatures= [[packet.signature.signature,
                                packet.packet.SerializeToString(),
                                packet.packet.from_key.key]
                                for packet in self.messages.packets.packet]
        self.assertEquals(self.messages.get_signatures_and_packets(), check_for_signatures)

    def test_020_blame_messages(self):
        accused = "liar"

        self.messages.blame_the_liar(accused)
        self.assertEquals(self.messages.get_accused_key(), accused)
        self.assertEquals(self.messages.get_blame_reason(), self.messages.blame_reason("LIAR"))
        self.messages.clear_packets()

        self.messages.blame_insufficient_funds(accused)
        self.assertEquals(self.messages.get_accused_key(), accused)
        self.assertEquals(self.messages.get_blame_reason(), self.messages.blame_reason("Insufficient funds"))
        self.messages.clear_packets()

        invalid_packets = b"some_invalid_packets"
        self.messages.blame_equivocation_failure(accused, invalid_packets=invalid_packets)
        self.assertEquals(self.messages.get_accused_key(), accused)
        self.assertEquals(self.messages.get_blame_reason(), self.messages.blame_reason("Equivocation failure"))
        self.assertEquals(self.messages.get_invalid_packets(), invalid_packets)
        self.messages.clear_packets()

        self.messages.blame_missing_output(accused)
        self.assertEquals(self.messages.get_accused_key(), accused)
        self.assertEquals(self.messages.get_blame_reason(), self.messages.blame_reason("Missing Output"))
        self.messages.clear_packets()

        hash = b"hash"
        self.messages.blame_shuffle_failure(accused, hash)
        self.assertEquals(self.messages.get_accused_key(), accused)
        self.assertEquals(self.messages.get_blame_reason(), self.messages.blame_reason("Shuffle Failure"))
        self.assertEquals(self.messages.get_hash(), hash)
        self.messages.clear_packets()

        encryption_key = "encryption key"
        decryption_key = "decryption_key"
        self.messages.blame_shuffle_and_equivocation_failure(accused, encryption_key,
                                                             decryption_key, invalid_packets)
        self.assertEquals(self.messages.get_accused_key(), accused)
        self.assertEquals(self.messages.get_blame_reason(), self.messages.blame_reason("Shuffle And Equivocation Failure"))
        self.assertEquals(self.messages.get_public_key(), encryption_key)
        self.assertEquals(self.messages.get_decryption_key(), decryption_key)
        self.assertEquals(self.messages.get_invalid_packets(), invalid_packets)
        self.messages.clear_packets()

        self.messages.blame_invalid_signature(accused)
        self.assertEquals(self.messages.get_accused_key(), accused)
        self.assertEquals(self.messages.get_blame_reason(), self.messages.blame_reason("Invalid Signature"))
        self.messages.clear_packets()

        self.messages.blame_wrong_transaction_signature(accused)
        self.assertEquals(self.messages.get_accused_key(), accused)
        self.assertEquals(self.messages.get_blame_reason(), self.messages.blame_reason("Invalid Signature"))
        self.messages.clear_packets()
