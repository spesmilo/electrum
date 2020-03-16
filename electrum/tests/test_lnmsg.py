import io

from electrum.lnmsg import (read_bigsize_int, write_bigsize_int, FieldEncodingNotMinimal,
                            UnexpectedEndOfStream, LNSerializer, UnknownMandatoryTLVRecordType,
                            MalformedMsg, MsgTrailingGarbage, MsgInvalidFieldOrder, encode_msg,
                            decode_msg, UnexpectedFieldSizeForEncoder)
from electrum.util import bfh
from electrum.lnutil import ShortChannelID, LnFeatures
from electrum import constants

from . import TestCaseForTestnet


class TestLNMsg(TestCaseForTestnet):

    def test_write_bigsize_int(self):
        self.assertEqual(bfh("00"), write_bigsize_int(0))
        self.assertEqual(bfh("fc"), write_bigsize_int(252))
        self.assertEqual(bfh("fd00fd"), write_bigsize_int(253))
        self.assertEqual(bfh("fdffff"), write_bigsize_int(65535))
        self.assertEqual(bfh("fe00010000"), write_bigsize_int(65536))
        self.assertEqual(bfh("feffffffff"), write_bigsize_int(4294967295))
        self.assertEqual(bfh("ff0000000100000000"), write_bigsize_int(4294967296))
        self.assertEqual(bfh("ffffffffffffffffff"), write_bigsize_int(18446744073709551615))

    def test_read_bigsize_int(self):
        self.assertEqual(0, read_bigsize_int(io.BytesIO(bfh("00"))))
        self.assertEqual(252, read_bigsize_int(io.BytesIO(bfh("fc"))))
        self.assertEqual(253, read_bigsize_int(io.BytesIO(bfh("fd00fd"))))
        self.assertEqual(65535, read_bigsize_int(io.BytesIO(bfh("fdffff"))))
        self.assertEqual(65536, read_bigsize_int(io.BytesIO(bfh("fe00010000"))))
        self.assertEqual(4294967295, read_bigsize_int(io.BytesIO(bfh("feffffffff"))))
        self.assertEqual(4294967296, read_bigsize_int(io.BytesIO(bfh("ff0000000100000000"))))
        self.assertEqual(18446744073709551615, read_bigsize_int(io.BytesIO(bfh("ffffffffffffffffff"))))

        with self.assertRaises(FieldEncodingNotMinimal):
            read_bigsize_int(io.BytesIO(bfh("fd00fc")))
        with self.assertRaises(FieldEncodingNotMinimal):
            read_bigsize_int(io.BytesIO(bfh("fe0000ffff")))
        with self.assertRaises(FieldEncodingNotMinimal):
            read_bigsize_int(io.BytesIO(bfh("ff00000000ffffffff")))
        with self.assertRaises(UnexpectedEndOfStream):
            read_bigsize_int(io.BytesIO(bfh("fd00")))
        with self.assertRaises(UnexpectedEndOfStream):
            read_bigsize_int(io.BytesIO(bfh("feffff")))
        with self.assertRaises(UnexpectedEndOfStream):
            read_bigsize_int(io.BytesIO(bfh("ffffffffff")))
        self.assertEqual(None, read_bigsize_int(io.BytesIO(bfh(""))))
        with self.assertRaises(UnexpectedEndOfStream):
            read_bigsize_int(io.BytesIO(bfh("fd")))
        with self.assertRaises(UnexpectedEndOfStream):
            read_bigsize_int(io.BytesIO(bfh("fe")))
        with self.assertRaises(UnexpectedEndOfStream):
            read_bigsize_int(io.BytesIO(bfh("ff")))

    def test_read_tlv_stream_tests1(self):
        # from https://github.com/lightningnetwork/lightning-rfc/blob/452a0eb916fedf4c954137b4fd0b61b5002b34ad/01-messaging.md#tlv-decoding-failures
        lnser = LNSerializer()
        for tlv_stream_name in ("n1", "n2"):
            with self.subTest(tlv_stream_name=tlv_stream_name):
                with self.assertRaises(UnexpectedEndOfStream):
                    lnser.read_tlv_stream(fd=io.BytesIO(bfh("fd")), tlv_stream_name=tlv_stream_name)
                with self.assertRaises(UnexpectedEndOfStream):
                    lnser.read_tlv_stream(fd=io.BytesIO(bfh("fd01")), tlv_stream_name=tlv_stream_name)
                with self.assertRaises(FieldEncodingNotMinimal):
                    lnser.read_tlv_stream(fd=io.BytesIO(bfh("fd000100")), tlv_stream_name=tlv_stream_name)
                with self.assertRaises(UnexpectedEndOfStream):
                    lnser.read_tlv_stream(fd=io.BytesIO(bfh("fd0101")), tlv_stream_name=tlv_stream_name)
                with self.assertRaises(UnexpectedEndOfStream):
                    lnser.read_tlv_stream(fd=io.BytesIO(bfh("0ffd")), tlv_stream_name=tlv_stream_name)
                with self.assertRaises(UnexpectedEndOfStream):
                    lnser.read_tlv_stream(fd=io.BytesIO(bfh("0ffd26")), tlv_stream_name=tlv_stream_name)
                with self.assertRaises(UnexpectedEndOfStream):
                    lnser.read_tlv_stream(fd=io.BytesIO(bfh("0ffd2602")), tlv_stream_name=tlv_stream_name)
                with self.assertRaises(FieldEncodingNotMinimal):
                    lnser.read_tlv_stream(fd=io.BytesIO(bfh("0ffd000100")), tlv_stream_name=tlv_stream_name)
                with self.assertRaises(UnexpectedEndOfStream):
                    lnser.read_tlv_stream(fd=io.BytesIO(bfh("0ffd0201000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")), tlv_stream_name="n1")
                with self.assertRaises(UnknownMandatoryTLVRecordType):
                    lnser.read_tlv_stream(fd=io.BytesIO(bfh("1200")), tlv_stream_name=tlv_stream_name)
                with self.assertRaises(UnknownMandatoryTLVRecordType):
                    lnser.read_tlv_stream(fd=io.BytesIO(bfh("fd010200")), tlv_stream_name=tlv_stream_name)
                with self.assertRaises(UnknownMandatoryTLVRecordType):
                    lnser.read_tlv_stream(fd=io.BytesIO(bfh("fe0100000200")), tlv_stream_name=tlv_stream_name)
                with self.assertRaises(UnknownMandatoryTLVRecordType):
                    lnser.read_tlv_stream(fd=io.BytesIO(bfh("ff010000000000000200")), tlv_stream_name=tlv_stream_name)
        with self.assertRaises(MsgTrailingGarbage):
            lnser.read_tlv_stream(fd=io.BytesIO(bfh("0109ffffffffffffffffff")), tlv_stream_name="n1")
        with self.assertRaises(FieldEncodingNotMinimal):
            lnser.read_tlv_stream(fd=io.BytesIO(bfh("010100")), tlv_stream_name="n1")
        with self.assertRaises(FieldEncodingNotMinimal):
            lnser.read_tlv_stream(fd=io.BytesIO(bfh("01020001")), tlv_stream_name="n1")
        with self.assertRaises(FieldEncodingNotMinimal):
            lnser.read_tlv_stream(fd=io.BytesIO(bfh("0103000100")), tlv_stream_name="n1")
        with self.assertRaises(FieldEncodingNotMinimal):
            lnser.read_tlv_stream(fd=io.BytesIO(bfh("010400010000")), tlv_stream_name="n1")
        with self.assertRaises(FieldEncodingNotMinimal):
            lnser.read_tlv_stream(fd=io.BytesIO(bfh("01050001000000")), tlv_stream_name="n1")
        with self.assertRaises(FieldEncodingNotMinimal):
            lnser.read_tlv_stream(fd=io.BytesIO(bfh("0106000100000000")), tlv_stream_name="n1")
        with self.assertRaises(FieldEncodingNotMinimal):
            lnser.read_tlv_stream(fd=io.BytesIO(bfh("010700010000000000")), tlv_stream_name="n1")
        with self.assertRaises(FieldEncodingNotMinimal):
            lnser.read_tlv_stream(fd=io.BytesIO(bfh("01080001000000000000")), tlv_stream_name="n1")
        with self.assertRaises(UnexpectedEndOfStream):
            lnser.read_tlv_stream(fd=io.BytesIO(bfh("020701010101010101")), tlv_stream_name="n1")
        with self.assertRaises(MsgTrailingGarbage):
            lnser.read_tlv_stream(fd=io.BytesIO(bfh("0209010101010101010101")), tlv_stream_name="n1")
        with self.assertRaises(UnexpectedEndOfStream):
            lnser.read_tlv_stream(fd=io.BytesIO(bfh("0321023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb")), tlv_stream_name="n1")
        with self.assertRaises(UnexpectedEndOfStream):
            lnser.read_tlv_stream(fd=io.BytesIO(bfh("0329023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb0000000000000001")), tlv_stream_name="n1")
        with self.assertRaises(UnexpectedEndOfStream):
            lnser.read_tlv_stream(fd=io.BytesIO(bfh("0330023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb000000000000000100000000000001")), tlv_stream_name="n1")
        # check if ECC point is valid?... skip for now.
        #with self.assertRaises(Exception):
        #    lnser.read_tlv_stream(fd=io.BytesIO(bfh("0331043da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb00000000000000010000000000000002")), tlv_stream_name="n1")
        with self.assertRaises(MsgTrailingGarbage):
            lnser.read_tlv_stream(fd=io.BytesIO(bfh("0332023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb0000000000000001000000000000000001")), tlv_stream_name="n1")
        with self.assertRaises(UnexpectedEndOfStream):
            lnser.read_tlv_stream(fd=io.BytesIO(bfh("fd00fe00")), tlv_stream_name="n1")
        with self.assertRaises(UnexpectedEndOfStream):
            lnser.read_tlv_stream(fd=io.BytesIO(bfh("fd00fe0101")), tlv_stream_name="n1")
        with self.assertRaises(MsgTrailingGarbage):
            lnser.read_tlv_stream(fd=io.BytesIO(bfh("fd00fe03010101")), tlv_stream_name="n1")
        with self.assertRaises(UnknownMandatoryTLVRecordType):
            lnser.read_tlv_stream(fd=io.BytesIO(bfh("0000")), tlv_stream_name="n1")

    def test_read_tlv_stream_tests2(self):
        # from https://github.com/lightningnetwork/lightning-rfc/blob/452a0eb916fedf4c954137b4fd0b61b5002b34ad/01-messaging.md#tlv-decoding-successes
        lnser = LNSerializer()
        for tlv_stream_name in ("n1", "n2"):
            with self.subTest(tlv_stream_name=tlv_stream_name):
                self.assertEqual({}, lnser.read_tlv_stream(fd=io.BytesIO(bfh("")), tlv_stream_name=tlv_stream_name))
                self.assertEqual({}, lnser.read_tlv_stream(fd=io.BytesIO(bfh("2100")), tlv_stream_name=tlv_stream_name))
                self.assertEqual({}, lnser.read_tlv_stream(fd=io.BytesIO(bfh("fd020100")), tlv_stream_name=tlv_stream_name))
                self.assertEqual({}, lnser.read_tlv_stream(fd=io.BytesIO(bfh("fd00fd00")), tlv_stream_name=tlv_stream_name))
                self.assertEqual({}, lnser.read_tlv_stream(fd=io.BytesIO(bfh("fd00ff00")), tlv_stream_name=tlv_stream_name))
                self.assertEqual({}, lnser.read_tlv_stream(fd=io.BytesIO(bfh("fe0200000100")), tlv_stream_name=tlv_stream_name))
                self.assertEqual({}, lnser.read_tlv_stream(fd=io.BytesIO(bfh("ff020000000000000100")), tlv_stream_name=tlv_stream_name))

        self.assertEqual({"tlv1": {"amount_msat": 0}},
                         lnser.read_tlv_stream(fd=io.BytesIO(bfh("0100")), tlv_stream_name="n1"))
        self.assertEqual({"tlv1": {"amount_msat": 1}},
                         lnser.read_tlv_stream(fd=io.BytesIO(bfh("010101")), tlv_stream_name="n1"))
        self.assertEqual({"tlv1": {"amount_msat": 256}},
                         lnser.read_tlv_stream(fd=io.BytesIO(bfh("01020100")), tlv_stream_name="n1"))
        self.assertEqual({"tlv1": {"amount_msat": 65536}},
                         lnser.read_tlv_stream(fd=io.BytesIO(bfh("0103010000")), tlv_stream_name="n1"))
        self.assertEqual({"tlv1": {"amount_msat": 16777216}},
                         lnser.read_tlv_stream(fd=io.BytesIO(bfh("010401000000")), tlv_stream_name="n1"))
        self.assertEqual({"tlv1": {"amount_msat": 4294967296}},
                         lnser.read_tlv_stream(fd=io.BytesIO(bfh("01050100000000")), tlv_stream_name="n1"))
        self.assertEqual({"tlv1": {"amount_msat": 1099511627776}},
                         lnser.read_tlv_stream(fd=io.BytesIO(bfh("0106010000000000")), tlv_stream_name="n1"))
        self.assertEqual({"tlv1": {"amount_msat": 281474976710656}},
                         lnser.read_tlv_stream(fd=io.BytesIO(bfh("010701000000000000")), tlv_stream_name="n1"))
        self.assertEqual({"tlv1": {"amount_msat": 72057594037927936}},
                         lnser.read_tlv_stream(fd=io.BytesIO(bfh("01080100000000000000")), tlv_stream_name="n1"))
        self.assertEqual({"tlv2": {"scid": ShortChannelID.from_components(0, 0, 550)}},
                         lnser.read_tlv_stream(fd=io.BytesIO(bfh("02080000000000000226")), tlv_stream_name="n1"))
        self.assertEqual({"tlv3": {"node_id": bfh("023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb"),
                                   "amount_msat_1": 1,
                                   "amount_msat_2": 2}},
                         lnser.read_tlv_stream(fd=io.BytesIO(bfh("0331023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb00000000000000010000000000000002")), tlv_stream_name="n1"))
        self.assertEqual({"tlv4": {"cltv_delta": 550}},
                         lnser.read_tlv_stream(fd=io.BytesIO(bfh("fd00fe020226")), tlv_stream_name="n1"))

    def test_read_tlv_stream_tests3(self):
        # from https://github.com/lightningnetwork/lightning-rfc/blob/452a0eb916fedf4c954137b4fd0b61b5002b34ad/01-messaging.md#tlv-stream-decoding-failure
        lnser = LNSerializer()
        with self.assertRaises(MsgInvalidFieldOrder):
            lnser.read_tlv_stream(fd=io.BytesIO(bfh("0208000000000000022601012a")), tlv_stream_name="n1")
        with self.assertRaises(MsgInvalidFieldOrder):
            lnser.read_tlv_stream(fd=io.BytesIO(bfh("0208000000000000023102080000000000000451")), tlv_stream_name="n1")
        with self.assertRaises(MsgInvalidFieldOrder):
            lnser.read_tlv_stream(fd=io.BytesIO(bfh("1f000f012a")), tlv_stream_name="n1")
        with self.assertRaises(MsgInvalidFieldOrder):
            lnser.read_tlv_stream(fd=io.BytesIO(bfh("1f001f012a")), tlv_stream_name="n1")
        with self.assertRaises(MsgInvalidFieldOrder):
            lnser.read_tlv_stream(fd=io.BytesIO(bfh("ffffffffffffffffff000000")), tlv_stream_name="n2")

    def test_encode_decode_msg__missing_mandatory_field_gets_set_to_zeroes(self):
        # "channel_update": "signature" missing -> gets set to zeroes
        self.assertEqual(bfh("01020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000043497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea33090000000000d43100006f00025e6ed0830100009000000000000000c8000001f400000023000000003b9aca00"),
                         encode_msg(
                             "channel_update",
                             short_channel_id=ShortChannelID.from_components(54321, 111, 2),
                             channel_flags=b'\x00',
                             message_flags=b'\x01',
                             cltv_expiry_delta=144,
                             htlc_minimum_msat=200,
                             htlc_maximum_msat=1_000_000_000,
                             fee_base_msat=500,
                             fee_proportional_millionths=35,
                             chain_hash=constants.net.rev_genesis_bytes(),
                             timestamp=1584320643,
                         ))
        self.assertEqual(('channel_update',
                         {'chain_hash': b'CI\x7f\xd7\xf8&\x95q\x08\xf4\xa3\x0f\xd9\xce\xc3\xae\xbay\x97 \x84\xe9\x0e\xad\x01\xea3\t\x00\x00\x00\x00',
                          'channel_flags': b'\x00',
                          'cltv_expiry_delta': 144,
                          'fee_base_msat': 500,
                          'fee_proportional_millionths': 35,
                          'htlc_maximum_msat': 1000000000,
                          'htlc_minimum_msat': 200,
                          'message_flags': b'\x01',
                          'short_channel_id': b'\x00\xd41\x00\x00o\x00\x02',
                          'signature': bytes(64),
                          'timestamp': 1584320643}
                          ),
                         decode_msg(bfh("01020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000043497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea33090000000000d43100006f00025e6ed0830100009000000000000000c8000001f400000023000000003b9aca00")))

    def test_encode_decode_msg__missing_optional_field_will_not_appear_in_decoded_dict(self):
        # "channel_update": optional field "htlc_maximum_msat" missing -> does not get put into dict
        self.assertEqual(bfh("01020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000043497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea33090000000000d43100006f00025e6ed0830100009000000000000000c8000001f400000023"),
                         encode_msg(
                             "channel_update",
                             short_channel_id=ShortChannelID.from_components(54321, 111, 2),
                             channel_flags=b'\x00',
                             message_flags=b'\x01',
                             cltv_expiry_delta=144,
                             htlc_minimum_msat=200,
                             fee_base_msat=500,
                             fee_proportional_millionths=35,
                             chain_hash=constants.net.rev_genesis_bytes(),
                             timestamp=1584320643,
                         ))
        self.assertEqual(('channel_update',
                         {'chain_hash': b'CI\x7f\xd7\xf8&\x95q\x08\xf4\xa3\x0f\xd9\xce\xc3\xae\xbay\x97 \x84\xe9\x0e\xad\x01\xea3\t\x00\x00\x00\x00',
                          'channel_flags': b'\x00',
                          'cltv_expiry_delta': 144,
                          'fee_base_msat': 500,
                          'fee_proportional_millionths': 35,
                          'htlc_minimum_msat': 200,
                          'message_flags': b'\x01',
                          'short_channel_id': b'\x00\xd41\x00\x00o\x00\x02',
                          'signature': bytes(64),
                          'timestamp': 1584320643}
                          ),
                         decode_msg(bfh("01020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000043497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea33090000000000d43100006f00025e6ed0830100009000000000000000c8000001f400000023")))

    def test_encode_decode_msg__ints_can_be_passed_as_bytes(self):
        self.assertEqual(bfh("01020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000043497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea33090000000000d43100006f00025e6ed0830100009000000000000000c8000001f400000023000000003b9aca00"),
                         encode_msg(
                             "channel_update",
                             short_channel_id=ShortChannelID.from_components(54321, 111, 2),
                             channel_flags=b'\x00',
                             message_flags=b'\x01',
                             cltv_expiry_delta=int.to_bytes(144, length=2, byteorder="big", signed=False),
                             htlc_minimum_msat=int.to_bytes(200, length=8, byteorder="big", signed=False),
                             htlc_maximum_msat=int.to_bytes(1_000_000_000, length=8, byteorder="big", signed=False),
                             fee_base_msat=int.to_bytes(500, length=4, byteorder="big", signed=False),
                             fee_proportional_millionths=int.to_bytes(35, length=4, byteorder="big", signed=False),
                             chain_hash=constants.net.rev_genesis_bytes(),
                             timestamp=int.to_bytes(1584320643, length=4, byteorder="big", signed=False),
                         ))
        self.assertEqual(('channel_update',
                         {'chain_hash': b'CI\x7f\xd7\xf8&\x95q\x08\xf4\xa3\x0f\xd9\xce\xc3\xae\xbay\x97 \x84\xe9\x0e\xad\x01\xea3\t\x00\x00\x00\x00',
                          'channel_flags': b'\x00',
                          'cltv_expiry_delta': 144,
                          'fee_base_msat': 500,
                          'fee_proportional_millionths': 35,
                          'htlc_maximum_msat': 1000000000,
                          'htlc_minimum_msat': 200,
                          'message_flags': b'\x01',
                          'short_channel_id': b'\x00\xd41\x00\x00o\x00\x02',
                          'signature': bytes(64),
                          'timestamp': 1584320643}
                          ),
                         decode_msg(bfh("01020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000043497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea33090000000000d43100006f00025e6ed0830100009000000000000000c8000001f400000023000000003b9aca00")))
        # "htlc_minimum_msat" is passed as bytes but with incorrect length
        with self.assertRaises(UnexpectedFieldSizeForEncoder):
            encode_msg(
                "channel_update",
                short_channel_id=ShortChannelID.from_components(54321, 111, 2),
                channel_flags=b'\x00',
                message_flags=b'\x01',
                cltv_expiry_delta=int.to_bytes(144, length=2, byteorder="big", signed=False),
                htlc_minimum_msat=int.to_bytes(200, length=4, byteorder="big", signed=False),
                htlc_maximum_msat=int.to_bytes(1_000_000_000, length=8, byteorder="big", signed=False),
                fee_base_msat=int.to_bytes(500, length=4, byteorder="big", signed=False),
                fee_proportional_millionths=int.to_bytes(35, length=4, byteorder="big", signed=False),
                chain_hash=constants.net.rev_genesis_bytes(),
                timestamp=int.to_bytes(1584320643, length=4, byteorder="big", signed=False),
            )

    def test_encode_decode_msg__commitment_signed(self):
        # "commitment_signed" is interesting because of the "htlc_signature" field,
        #  which is a concatenation of multiple ("num_htlcs") signatures.
        # 5 htlcs
        self.assertEqual(bfh("0084010101010101010101010101010101010101010101010101010101010101010106112951d0a6d7fc1dbca3bd1cdbda9acfee7f668b3c0a36bd944f7e2f305b274ba46a61279e15163b2d376c664bb3481d7c5e107a5b268301e39aebbda27d2d00056548bd093a2bd2f4f053f0c6eb2c5f541d55eb8a2ede4d35fe974e5d3cd0eec3138bfd4115f4483c3b14e7988b48811d2da75f29f5e6eee691251fb4fba5a2610ba8fe7007117fe1c9fa1a6b01805c84cfffbb0eba674b64342c7cac567dea50728c1bb1aadc6d23fc2f4145027eafca82d6072cc9ce6529542099f728a0521e4b2044df5d02f7f2cdf84404762b1979528aa689a3e060a2a90ba8ef9a83d24d31ffb0d95c71d9fb9049b24ecf2c949c1486e7eb3ae160d70d54e441dc785dc57f7f3c9901b9537398c66f546cfc1d65e0748895d14699342c407fe119ac17db079b103720124a5ba22d4ba14c12832324dea9cb60c61ee74376ee7dcffdd1836e354aa8838ce3b37854fa91465cc40c73b702915e3580bfebaace805d52373b57ac755ebe4a8fe97e5fc21669bea124b809c79968479148f7174f39b8014542"),
                         encode_msg(
                             "commitment_signed",
                             channel_id=b'\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01',
                             signature=b"\x06\x11)Q\xd0\xa6\xd7\xfc\x1d\xbc\xa3\xbd\x1c\xdb\xda\x9a\xcf\xee\x7ff\x8b<\n6\xbd\x94O~/0['K\xa4ja'\x9e\x15\x16;-7lfK\xb3H\x1d|^\x10z[&\x83\x01\xe3\x9a\xeb\xbd\xa2}-",
                             num_htlcs=5,
                             htlc_signature=bfh("6548bd093a2bd2f4f053f0c6eb2c5f541d55eb8a2ede4d35fe974e5d3cd0eec3138bfd4115f4483c3b14e7988b48811d2da75f29f5e6eee691251fb4fba5a2610ba8fe7007117fe1c9fa1a6b01805c84cfffbb0eba674b64342c7cac567dea50728c1bb1aadc6d23fc2f4145027eafca82d6072cc9ce6529542099f728a0521e4b2044df5d02f7f2cdf84404762b1979528aa689a3e060a2a90ba8ef9a83d24d31ffb0d95c71d9fb9049b24ecf2c949c1486e7eb3ae160d70d54e441dc785dc57f7f3c9901b9537398c66f546cfc1d65e0748895d14699342c407fe119ac17db079b103720124a5ba22d4ba14c12832324dea9cb60c61ee74376ee7dcffdd1836e354aa8838ce3b37854fa91465cc40c73b702915e3580bfebaace805d52373b57ac755ebe4a8fe97e5fc21669bea124b809c79968479148f7174f39b8014542"),
                         ))
        self.assertEqual(('commitment_signed',
                         {'channel_id': b'\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01',
                          'signature': b"\x06\x11)Q\xd0\xa6\xd7\xfc\x1d\xbc\xa3\xbd\x1c\xdb\xda\x9a\xcf\xee\x7ff\x8b<\n6\xbd\x94O~/0['K\xa4ja'\x9e\x15\x16;-7lfK\xb3H\x1d|^\x10z[&\x83\x01\xe3\x9a\xeb\xbd\xa2}-",
                          'num_htlcs': 5,
                          'htlc_signature': bfh("6548bd093a2bd2f4f053f0c6eb2c5f541d55eb8a2ede4d35fe974e5d3cd0eec3138bfd4115f4483c3b14e7988b48811d2da75f29f5e6eee691251fb4fba5a2610ba8fe7007117fe1c9fa1a6b01805c84cfffbb0eba674b64342c7cac567dea50728c1bb1aadc6d23fc2f4145027eafca82d6072cc9ce6529542099f728a0521e4b2044df5d02f7f2cdf84404762b1979528aa689a3e060a2a90ba8ef9a83d24d31ffb0d95c71d9fb9049b24ecf2c949c1486e7eb3ae160d70d54e441dc785dc57f7f3c9901b9537398c66f546cfc1d65e0748895d14699342c407fe119ac17db079b103720124a5ba22d4ba14c12832324dea9cb60c61ee74376ee7dcffdd1836e354aa8838ce3b37854fa91465cc40c73b702915e3580bfebaace805d52373b57ac755ebe4a8fe97e5fc21669bea124b809c79968479148f7174f39b8014542")}
                          ),
                         decode_msg(bfh("0084010101010101010101010101010101010101010101010101010101010101010106112951d0a6d7fc1dbca3bd1cdbda9acfee7f668b3c0a36bd944f7e2f305b274ba46a61279e15163b2d376c664bb3481d7c5e107a5b268301e39aebbda27d2d00056548bd093a2bd2f4f053f0c6eb2c5f541d55eb8a2ede4d35fe974e5d3cd0eec3138bfd4115f4483c3b14e7988b48811d2da75f29f5e6eee691251fb4fba5a2610ba8fe7007117fe1c9fa1a6b01805c84cfffbb0eba674b64342c7cac567dea50728c1bb1aadc6d23fc2f4145027eafca82d6072cc9ce6529542099f728a0521e4b2044df5d02f7f2cdf84404762b1979528aa689a3e060a2a90ba8ef9a83d24d31ffb0d95c71d9fb9049b24ecf2c949c1486e7eb3ae160d70d54e441dc785dc57f7f3c9901b9537398c66f546cfc1d65e0748895d14699342c407fe119ac17db079b103720124a5ba22d4ba14c12832324dea9cb60c61ee74376ee7dcffdd1836e354aa8838ce3b37854fa91465cc40c73b702915e3580bfebaace805d52373b57ac755ebe4a8fe97e5fc21669bea124b809c79968479148f7174f39b8014542")))
        # single htlc
        self.assertEqual(bfh("008401010101010101010101010101010101010101010101010101010101010101013b14af0c549dfb1fb287ff57c012371b3932996db5929eda5f251704751fb49d0dc2dcb88e5021575cb572fb71693758543f97d89e9165f913bfb7488d7cc26500012d31103b9f6e71131e4fee86fdfbdeba90e52b43fcfd11e8e53811cd4d59b2575ae6c3c82f85bea144c88cc35e568f1e6bdd0c57337e86de0b5da7cd9994067a"),
                         encode_msg(
                             "commitment_signed",
                             channel_id=b'\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01',
                             signature=b';\x14\xaf\x0cT\x9d\xfb\x1f\xb2\x87\xffW\xc0\x127\x1b92\x99m\xb5\x92\x9e\xda_%\x17\x04u\x1f\xb4\x9d\r\xc2\xdc\xb8\x8eP!W\\\xb5r\xfbqi7XT?\x97\xd8\x9e\x91e\xf9\x13\xbf\xb7H\x8d|\xc2e',
                             num_htlcs=1,
                             htlc_signature=bfh("2d31103b9f6e71131e4fee86fdfbdeba90e52b43fcfd11e8e53811cd4d59b2575ae6c3c82f85bea144c88cc35e568f1e6bdd0c57337e86de0b5da7cd9994067a"),
                         ))
        self.assertEqual(('commitment_signed',
                         {'channel_id': b'\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01',
                          'signature': b';\x14\xaf\x0cT\x9d\xfb\x1f\xb2\x87\xffW\xc0\x127\x1b92\x99m\xb5\x92\x9e\xda_%\x17\x04u\x1f\xb4\x9d\r\xc2\xdc\xb8\x8eP!W\\\xb5r\xfbqi7XT?\x97\xd8\x9e\x91e\xf9\x13\xbf\xb7H\x8d|\xc2e',
                          'num_htlcs': 1,
                          'htlc_signature': bfh("2d31103b9f6e71131e4fee86fdfbdeba90e52b43fcfd11e8e53811cd4d59b2575ae6c3c82f85bea144c88cc35e568f1e6bdd0c57337e86de0b5da7cd9994067a")}
                          ),
                         decode_msg(bfh("008401010101010101010101010101010101010101010101010101010101010101013b14af0c549dfb1fb287ff57c012371b3932996db5929eda5f251704751fb49d0dc2dcb88e5021575cb572fb71693758543f97d89e9165f913bfb7488d7cc26500012d31103b9f6e71131e4fee86fdfbdeba90e52b43fcfd11e8e53811cd4d59b2575ae6c3c82f85bea144c88cc35e568f1e6bdd0c57337e86de0b5da7cd9994067a")))
        # zero htlcs
        self.assertEqual(bfh("008401010101010101010101010101010101010101010101010101010101010101014e206ecf904d9237b1c5b4e08513555e9a5932c45b5f68be8764ce998df635ae04f6ce7bbcd3b4fd08e2daab7f9059b287ecab4155367b834682633497173f450000"),
                         encode_msg(
                             "commitment_signed",
                             channel_id=b'\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01',
                             signature=b'N n\xcf\x90M\x927\xb1\xc5\xb4\xe0\x85\x13U^\x9aY2\xc4[_h\xbe\x87d\xce\x99\x8d\xf65\xae\x04\xf6\xce{\xbc\xd3\xb4\xfd\x08\xe2\xda\xab\x7f\x90Y\xb2\x87\xec\xabAU6{\x83F\x82c4\x97\x17?E',
                             num_htlcs=0,
                             htlc_signature=bfh(""),
                         ))
        self.assertEqual(('commitment_signed',
                         {'channel_id': b'\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01',
                          'signature': b'N n\xcf\x90M\x927\xb1\xc5\xb4\xe0\x85\x13U^\x9aY2\xc4[_h\xbe\x87d\xce\x99\x8d\xf65\xae\x04\xf6\xce{\xbc\xd3\xb4\xfd\x08\xe2\xda\xab\x7f\x90Y\xb2\x87\xec\xabAU6{\x83F\x82c4\x97\x17?E',
                          'num_htlcs': 0,
                          'htlc_signature': bfh("")}
                          ),
                         decode_msg(bfh("008401010101010101010101010101010101010101010101010101010101010101014e206ecf904d9237b1c5b4e08513555e9a5932c45b5f68be8764ce998df635ae04f6ce7bbcd3b4fd08e2daab7f9059b287ecab4155367b834682633497173f450000")))

    def test_encode_decode_msg__init(self):
        # "init" is interesting because it has TLVs optionally
        self.assertEqual(bfh("00100000000220c2"),
                         encode_msg(
                             "init",
                             gflen=0,
                             flen=2,
                             features=(LnFeatures.OPTION_STATIC_REMOTEKEY_OPT |
                                       LnFeatures.GOSSIP_QUERIES_OPT |
                                       LnFeatures.GOSSIP_QUERIES_REQ |
                                       LnFeatures.OPTION_DATA_LOSS_PROTECT_OPT),
                         ))
        self.assertEqual(bfh("00100000000220c2"),
                         encode_msg("init", gflen=0, flen=2, features=bfh("20c2")))
        self.assertEqual(bfh("00100000000220c2012043497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000"),
                         encode_msg(
                             "init",
                             gflen=0,
                             flen=2,
                             features=(LnFeatures.OPTION_STATIC_REMOTEKEY_OPT |
                                       LnFeatures.GOSSIP_QUERIES_OPT |
                                       LnFeatures.GOSSIP_QUERIES_REQ |
                                       LnFeatures.OPTION_DATA_LOSS_PROTECT_OPT),
                             init_tlvs={
                                 'networks':
                                     {'chains': b'CI\x7f\xd7\xf8&\x95q\x08\xf4\xa3\x0f\xd9\xce\xc3\xae\xbay\x97 \x84\xe9\x0e\xad\x01\xea3\t\x00\x00\x00\x00'}
                             }
                         ))
        self.assertEqual(('init',
                         {'gflen': 2,
                          'globalfeatures': b'"\x00',
                          'flen': 3,
                          'features': b'\x02\xa2\xa1',
                          'init_tlvs': {}}
                          ),
                         decode_msg(bfh("001000022200000302a2a1")))
        self.assertEqual(('init',
                         {'gflen': 2,
                          'globalfeatures': b'"\x00',
                          'flen': 3,
                          'features': b'\x02\xaa\xa2',
                          'init_tlvs': {
                              'networks':
                                  {'chains': b'CI\x7f\xd7\xf8&\x95q\x08\xf4\xa3\x0f\xd9\xce\xc3\xae\xbay\x97 \x84\xe9\x0e\xad\x01\xea3\t\x00\x00\x00\x00'}
                          }}),
                         decode_msg(bfh("001000022200000302aaa2012043497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000")))
