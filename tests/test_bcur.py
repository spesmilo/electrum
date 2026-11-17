from electrum import bcur, cbor
from electrum.bcur import UREncoder, URScanCollector, URError, decode_tx_ur
from electrum.transaction import tx_from_any
from electrum._vendor.bc_ur.bytewords import Bytewords, Bytewords_Style_minimal
from electrum._vendor.bc_ur.fountain_decoder import FountainDecoder
from electrum._vendor.bc_ur.fountain_encoder import FountainEncoder, Part, InvalidHeader
from electrum._vendor.bc_ur.fountain_utils import choose_fragments
from electrum._vendor.bc_ur.utils import crc32_int
from electrum._vendor.bc_ur.xoshiro256 import Xoshiro256

from . import ElectrumTestCase
from .test_transaction import psbt_legacy_and_segwit


def make_message(length: int) -> bytes:
    return bytes(Xoshiro256.from_string("Wolf").next_data(length))


def scan_all(encoder: UREncoder, *, skip_every: int = 0) -> str:
    """Feeds the parts of encoder into a URScanCollector, until it returns a result."""
    collector = URScanCollector()
    for i in range(1, 10_000):
        part = encoder.next_part()
        if skip_every and i % skip_every == 0:
            continue  # lost frame
        if (res := collector.add(part)) is not None:
            return res
    raise Exception('scanning did not finish')


class TestBCURVectors(ElectrumTestCase):
    # test vectors from https://github.com/BlockchainCommons/bc-ur

    def test_bytewords(self):
        data = bytes([0, 1, 2, 128, 255])
        self.assertEqual('aeadaolazmjendeoti', Bytewords.encode(Bytewords_Style_minimal, data))
        self.assertEqual(data, Bytewords.decode(Bytewords_Style_minimal, 'aeadaolazmjendeoti'))
        for text in ('aeadaolazojendeowf', 'wf', ''):  # bad checksum, too short
            with self.assertRaises(ValueError):
                Bytewords.decode(Bytewords_Style_minimal, text)

    def test_xoshiro256(self):
        rng = Xoshiro256.from_string("Wolf")
        self.assertEqual([42, 81, 85, 8, 82, 84, 76, 73, 70, 88], [rng.next() % 100 for _ in range(10)])

    def test_choose_fragments(self):
        message = make_message(1024)
        checksum = crc32_int(message)
        self.assertEqual(
            [[9], [2, 5, 6, 8, 9, 10], [8], [1, 5], [1], [0, 2, 4, 5, 8, 10]],
            [sorted(choose_fragments(seq_num, 11, checksum)) for seq_num in range(12, 18)])

    def test_ur_encoder(self):
        encoder = UREncoder('bytes', make_message(256), max_fragment_len=30)
        parts = [encoder.next_part() for _ in range(20)]
        expected_parts = [
            "ur:bytes/1-9/lpadascfadaxcywenbpljkhdcahkadaemejtswhhylkepmykhhtsytsnoyoyaxaedsuttydmmhhpktpmsrjtdkgslpgh",
            "ur:bytes/2-9/lpaoascfadaxcywenbpljkhdcagwdpfnsboxgwlbaawzuefywkdplrsrjynbvygabwjldapfcsgmghhkhstlrdcxaefz",
            "ur:bytes/3-9/lpaxascfadaxcywenbpljkhdcahelbknlkuejnbadmssfhfrdpsbiegecpasvssovlgeykssjykklronvsjksopdzmol",
            "ur:bytes/4-9/lpaaascfadaxcywenbpljkhdcasotkhemthydawydtaxneurlkosgwcekonertkbrlwmplssjtammdplolsbrdzcrtas",
            "ur:bytes/5-9/lpahascfadaxcywenbpljkhdcatbbdfmssrkzmcwnezelennjpfzbgmuktrhtejscktelgfpdlrkfyfwdajldejokbwf",
            "ur:bytes/6-9/lpamascfadaxcywenbpljkhdcackjlhkhybssklbwefectpfnbbectrljectpavyrolkzczcpkmwidmwoxkilghdsowp",
            "ur:bytes/7-9/lpatascfadaxcywenbpljkhdcavszmwnjkwtclrtvaynhpahrtoxmwvwatmedibkaegdosftvandiodagdhthtrlnnhy",
            "ur:bytes/8-9/lpayascfadaxcywenbpljkhdcadmsponkkbbhgsoltjntegepmttmoonftnbuoiyrehfrtsabzsttorodklubbuyaetk",
            "ur:bytes/9-9/lpasascfadaxcywenbpljkhdcajskecpmdckihdyhphfotjojtfmlnwmadspaxrkytbztpbauotbgtgtaeaevtgavtny",
            "ur:bytes/10-9/lpbkascfadaxcywenbpljkhdcahkadaemejtswhhylkepmykhhtsytsnoyoyaxaedsuttydmmhhpktpmsrjtwdkiplzs",
            "ur:bytes/11-9/lpbdascfadaxcywenbpljkhdcahelbknlkuejnbadmssfhfrdpsbiegecpasvssovlgeykssjykklronvsjkvetiiapk",
            "ur:bytes/12-9/lpbnascfadaxcywenbpljkhdcarllaluzmdmgstospeyiefmwejlwtpedamktksrvlcygmzemovovllarodtmtbnptrs",
            "ur:bytes/13-9/lpbtascfadaxcywenbpljkhdcamtkgtpknghchchyketwsvwgwfdhpgmgtylctotzopdrpayoschcmhplffziachrfgd",
            "ur:bytes/14-9/lpbaascfadaxcywenbpljkhdcapazewnvonnvdnsbyleynwtnsjkjndeoldydkbkdslgjkbbkortbelomueekgvstegt",
            "ur:bytes/15-9/lpbsascfadaxcywenbpljkhdcaynmhpddpzmversbdqdfyrehnqzlugmjzmnmtwmrouohtstgsbsahpawkditkckynwt",
            "ur:bytes/16-9/lpbeascfadaxcywenbpljkhdcawygekobamwtlihsnpalnsghenskkiynthdzotsimtojetprsttmukirlrsbtamjtpd",
            "ur:bytes/17-9/lpbyascfadaxcywenbpljkhdcamklgftaxykpewyrtqzhydntpnytyisincxmhtbceaykolduortotiaiaiafhiaoyce",
            "ur:bytes/18-9/lpbgascfadaxcywenbpljkhdcahkadaemejtswhhylkepmykhhtsytsnoyoyaxaedsuttydmmhhpktpmsrjtntwkbkwy",
            "ur:bytes/19-9/lpbwascfadaxcywenbpljkhdcadekicpaajootjzpsdrbalpeywllbdsnbinaerkurspbncxgslgftvtsrjtksplcpeo",
            "ur:bytes/20-9/lpbbascfadaxcywenbpljkhdcayapmrleeleaxpasfrtrdkncffwjyjzgyetdmlewtkpktgllepfrltataztksmhkbot",
        ]
        self.assertEqual([part.upper() for part in expected_parts], parts)

    def test_single_part_psbt_ur(self):
        # from BCR-2020-006
        psbt = bytes.fromhex(
            '70736274ff01009a020000000258e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd75'
            '0000000000ffffffff838d0427d0ec650a68aa46bb0b098aea4422c071b2ca78352a077959d07cea1d0100000000'
            'ffffffff0270aaf00800000000160014d85c2b71d0060b09c9886aeb815e50991dda124d00e1f505000000001600'
            '1400aea9a2e5f0f876a588df5546e8742d1d87008f000000000000000000')
        ur_text = (
            'ur:psbt/hdosjojkidjyzmadaenyaoaeaeaeaohdvsknclrejnpebncnrnmnjojofejzeojlkerdonspkpkkdkykfelokgprpyutkpaeae'
            'aeaeaezmzmzmzmlslgaaditiwpihbkispkfgrkbdaslewdfycprtjsprsgksecdratkkhktikewdcaadaeaeaeaezmzmzmzmaojopkwt'
            'ayaeaeaeaecmaebbtphhdnjstiambdassoloimwmlyhygdnlcatnbggtaevyykahaeaeaeaecmaebbaeplptoevwwtyakoonlourgofg'
            'vsjydpcaltaemyaeaeaeaeaeaeaeaeaebkgdcarh')
        encoder = UREncoder('psbt', psbt, max_fragment_len=1000)
        self.assertTrue(encoder.is_single_part)
        self.assertEqual(ur_text.upper(), encoder.next_part())
        self.assertEqual(psbt, decode_tx_ur(ur_text))


class TestURScanCollector(ElectrumTestCase):

    def test_passthrough(self):
        collector = URScanCollector()
        self.assertEqual('bitcoin:bc1qxyz', collector.add('bitcoin:bc1qxyz'))
        single = UREncoder('bytes', b'\x01' * 20, max_fragment_len=200).next_part()
        self.assertEqual(single, collector.add(single))
        self.assertFalse(collector.in_progress)

    def test_multipart_roundtrip_with_lost_parts(self):
        message = make_message(32767)
        encoder = UREncoder('bytes', message, max_fragment_len=1000)
        self.assertFalse(encoder.is_single_part)
        res = scan_all(encoder, skip_every=3)
        self.assertEqual(message, decode_tx_ur(res))
        # only mixed parts, so that they have to be reduced by each other (as in bc-ur's test_multipart_ur)
        encoder = UREncoder('bytes', message, max_fragment_len=1000)
        for _ in range(100):
            encoder.next_part()
        self.assertEqual(message, decode_tx_ur(scan_all(encoder)))

    def test_ignores_other_qr_codes_while_in_progress(self):
        encoder = UREncoder('bytes', make_message(500), max_fragment_len=100)
        collector = URScanCollector()
        self.assertIsNone(collector.add(encoder.next_part()))
        for _ in range(URScanCollector.MAX_FOREIGN_PARTS - 1):
            self.assertIsNone(collector.add('bitcoin:bc1qxyz'))
        self.assertIsNone(collector.add(encoder.next_part()))  # resets the count of foreign QR codes
        for _ in range(URScanCollector.MAX_FOREIGN_PARTS - 1):
            self.assertIsNone(collector.add('bitcoin:bc1qxyz'))
        self.assertEqual((2, 6), collector.progress)
        # the user is scanning a static QR code now
        self.assertEqual('bitcoin:bc1qxyz', collector.add('bitcoin:bc1qxyz'))
        self.assertFalse(collector.in_progress)
        # several QR codes in one frame: the parts of an animated QR code take precedence
        self.assertEqual('bitcoin:a', collector.add_frame(['bitcoin:a', 'bitcoin:b']))
        self.assertIsNone(collector.add_frame(['bitcoin:a', encoder.next_part()]))
        self.assertTrue(collector.in_progress)

    def test_collector_foreign_parts_reset(self):
        enc1 = UREncoder('bytes', make_message(500), max_fragment_len=100)
        enc2 = UREncoder('bytes', make_message(700), max_fragment_len=100)
        collector = URScanCollector()
        collector.add(enc1.next_part())
        for _ in range(URScanCollector.MAX_FOREIGN_PARTS - 1):
            self.assertIsNone(collector.add(enc2.next_part()))
            self.assertEqual(6, collector.progress[1])  # still on the first message
        collector.add(enc2.next_part())
        self.assertEqual(8, collector.progress[1])  # switched to the second message

    def test_collector_rejects_huge_seq_len(self):
        data = cbor.dumps([1, 2**32 - 1, 2**40, 0x12345678, b'\x00' * 100])
        text = 'ur:bytes/1-4294967295/' + Bytewords.encode(Bytewords_Style_minimal, data)
        collector = URScanCollector()
        self.assertIsNone(collector.add(text))
        self.assertFalse(collector.in_progress)

    def test_rejects_malformed_parts(self):
        self.assertEqual(2**32 - 1, Part.from_cbor(cbor.dumps([1, 1, 1, 2**32 - 1, b'x'])).checksum)
        for header in ([True, 1, 1, 0, b'x'], [-1, 1, 1, 0, b'x'], [1, 1, 1, 2**32, b'x'],
                       [1, 1, 1, 0, 'x'], [1, 1, 1, 0], [1, 1, 1, 0, b'x', 0]):
            with self.assertRaises(InvalidHeader):
                Part.from_cbor(cbor.dumps(header))
        # non-ASCII letters that match [a-z] case-insensitively
        self.assertFalse(bcur.is_multipart_ur('ur:bytes/1-2/\u0130\u0131\u017f\u212a'))

    def test_fountain_decoder_solves_mixed_parts(self):
        # parts that each mix 3 of the 4 fragments: none is a subset of another, so that bc-ur's
        # peeling decoder cannot reduce them, but together they determine the message
        message = make_message(100)
        decoder = FountainDecoder()
        counts = []
        for seq_num in (20, 24, 38, 20, 52):  # 20 twice
            decoder.receive_part(FountainEncoder(message, 25, first_seq_num=seq_num - 1).next_part())
            self.assertEqual(3, len(decoder.last_part_indexes))
            counts.append(decoder.independent_part_count())
        self.assertEqual([1, 2, 3, 3, 4], counts)
        self.assertEqual(message, decoder.result_message())


class TestTxUR(ElectrumTestCase):

    def test_psbt_roundtrip(self):
        tx = tx_from_any(psbt_legacy_and_segwit)
        encoder = UREncoder(bcur.UR_TYPE_CRYPTO_PSBT, tx.serialize_as_bytes(), max_fragment_len=100)
        self.assertEqual(tx.serialize(), tx_from_any(scan_all(encoder)).serialize())

    def test_decode_tx_ur_multipart_fragment_error(self):
        encoder = UREncoder('crypto-psbt', make_message(500), max_fragment_len=100)
        with self.assertRaises(URError) as ctx:
            tx_from_any(encoder.next_part())
        self.assertIn('animated QR code', str(ctx.exception))
        # a part that alone contains the whole message
        message = cbor.dumps(b'\x01\x02')
        part = Part(1, 1, len(message), crc32_int(message), message)
        self.assertEqual(b'\x01\x02', decode_tx_ur('ur:bytes/1-1/' + Bytewords.encode(Bytewords_Style_minimal, part.to_cbor())))

    def test_decode_tx_ur_unsupported_type(self):
        text = UREncoder('crypto-account', b'\x01\x02', max_fragment_len=100).next_part()
        with self.assertRaises(URError):
            decode_tx_ur(text)
        with self.assertRaises(URError):
            decode_tx_ur('ur:bytes/1of3/lpadascfadaxcy')  # UR 1.0
        self.assertEqual(b'\x01\x02', decode_tx_ur(UREncoder('bytes', b'\x01\x02', max_fragment_len=100).next_part()))
        tagged = 'ur:crypto-psbt/' + Bytewords.encode(Bytewords_Style_minimal, cbor.dumps(cbor.CBORTag(310, b'\x01')))
        self.assertEqual(b'\x01', decode_tx_ur(tagged))
