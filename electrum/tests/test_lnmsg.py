import io

from electrum.lnmsg import (read_bigsize_int, write_bigsize_int, FieldEncodingNotMinimal,
                            UnexpectedEndOfStream, LNSerializer, UnknownMandatoryTLVRecordType,
                            MalformedMsg, MsgTrailingGarbage, MsgInvalidFieldOrder)
from electrum.util import bfh
from electrum.lnutil import ShortChannelID

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
