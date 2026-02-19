import os
import asyncio
from unittest.mock import patch

from electrum import SimpleConfig
from electrum.invoices import Invoice
from electrum.payment_identifier import (
    maybe_extract_bech32_lightning_payment_identifier, PaymentIdentifier, PaymentIdentifierType,
    PaymentIdentifierState, invoice_from_payment_identifier, remove_uri_prefix,
)
from electrum.lnurl import LNURL6Data, LNURL3Data, LNURLError
from electrum.transaction import PartialTxOutput

from . import ElectrumTestCase
from . import restore_wallet_from_text__for_unittest


class WalletMock:
    def __init__(self, electrum_path):
        self.config = SimpleConfig({
            'electrum_path': electrum_path,
            'decimal_point': 5
        })
        self.contacts = None


class TestPaymentIdentifier(ElectrumTestCase):
    def setUp(self):
        super().setUp()
        self.wallet = WalletMock(self.electrum_path)

        self.config = SimpleConfig({
            'electrum_path': self.electrum_path,
            'decimal_point': 5
        })
        self.wallet2_path = os.path.join(self.electrum_path, "somewallet2")

    def test_maybe_extract_bech32_lightning_payment_identifier(self):
        bolt11 = "lnbc1ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsdqq9qypqszpyrpe4tym8d3q87d43cgdhhlsrt78epu7u99mkzttmt2wtsx0304rrw50addkryfrd3vn3zy467vxwlmf4uz7yvntuwjr2hqjl9lw5cqwtp2dy"
        bolt12 = "lno1pqpzacq2qqgwuquxfmcztl0gldv8mxy3sm8x5jscdz27u39fy6luxu8zcdn9j73l3uprukkghkdufdz6adxl0ejhy0lmzfykj08u6df9v4v2c93qknz8eggzq2jyyszrrt35mmkyl7efrv5x8a3wspk07pghey4a5kcm4ef76p0ksqpnh7fqgmq9eaf7ntqspcksqkqk8ngvjtjp585mqw3qata3xe8aycgkpprk87yqcxhh705dxauxkghsc9xywqpez7lt5gw67kqwejl83unmuc7r44h32durffs4rmpcgrhxa8x8y9gqxgy9w2tqgpxqk0tl487a9ssuchyh5p9t3le3n5ylhevggk6ly8wzxvds0jawct4spe2tzqfp5d34kah9ss"
        lnurl = "lnurl1dp68gurn8ghj7um9wfmxjcm99e5k7telwy7nxenrxvmrgdtzxsenjcm98pjnwxq96s9"
        self.assertEqual(bolt11, maybe_extract_bech32_lightning_payment_identifier(f"{bolt11}".upper()))
        self.assertEqual(bolt11, maybe_extract_bech32_lightning_payment_identifier(f"lightning:{bolt11}"))
        self.assertEqual(bolt11, maybe_extract_bech32_lightning_payment_identifier(f"  lightning:{bolt11}   ".upper()))
        self.assertEqual(bolt12, maybe_extract_bech32_lightning_payment_identifier(f"{bolt12}".upper()))
        self.assertEqual(bolt12, maybe_extract_bech32_lightning_payment_identifier(f"lightning:{bolt12}"))
        self.assertEqual(bolt12, maybe_extract_bech32_lightning_payment_identifier(f"  lightning:{bolt12}   ".upper()))
        self.assertEqual(lnurl, maybe_extract_bech32_lightning_payment_identifier(lnurl))
        self.assertEqual(lnurl, maybe_extract_bech32_lightning_payment_identifier(f"  lightning:{lnurl}   ".upper()))

        self.assertEqual(None, maybe_extract_bech32_lightning_payment_identifier(f"bitcoin:{bolt11}"))
        self.assertEqual(None, maybe_extract_bech32_lightning_payment_identifier(f"bitcoin:{bolt12}"))
        self.assertEqual(None, maybe_extract_bech32_lightning_payment_identifier(f":{bolt11}"))
        self.assertEqual(None, maybe_extract_bech32_lightning_payment_identifier(f":{bolt12}"))
        self.assertEqual(None, maybe_extract_bech32_lightning_payment_identifier(f"garbage text"))

    def test_remove_uri_prefix(self):
        lightning, bitcoin = 'lightning', 'bitcoin'
        tests = (
            (lightning, '', ''),
            (lightning, 'lightning:test', 'test'),
            (lightning, 'bitcoin:test', 'bitcoin:test'),
            (lightning, 'lightningtest', 'lightningtest'),
            (lightning, 'lightning test', 'lightning test'),
            (bitcoin, 'lightning:test', 'lightning:test'),
            (bitcoin, 'bitcoin:test', 'test'),
            (bitcoin, 'bitcoin', 'bitcoin'),
            (bitcoin, 'bitcoin:', ''),
        )
        for prefix, input_str, expected_output_str in tests:
            output_str = remove_uri_prefix(input_str, prefix=prefix)
            self.assertEqual(expected_output_str, output_str, msg=output_str)
        with self.assertRaises(AssertionError):
            remove_uri_prefix(data=1234, prefix="test")

    def test_bolt11(self):
        # no amount, no fallback address
        bolt11 = 'lnbc1ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsdqq9qypqszpyrpe4tym8d3q87d43cgdhhlsrt78epu7u99mkzttmt2wtsx0304rrw50addkryfrd3vn3zy467vxwlmf4uz7yvntuwjr2hqjl9lw5cqwtp2dy'
        for pi_str in [
            f'{bolt11}',
            f'  {bolt11}',
            f'{bolt11}  ',
            f'lightning:{bolt11}',
            f'  lightning:{bolt11}',
            f'lightning:{bolt11}  ',
            f'lightning:{bolt11.upper()}',
            f'lightning:{bolt11}'.upper(),
        ]:
            pi = PaymentIdentifier(None, pi_str)
            self.assertTrue(pi.is_valid())
            self.assertEqual(PaymentIdentifierType.BOLT11, pi.type)
            self.assertFalse(pi.is_amount_locked())
            self.assertFalse(pi.is_error())
            self.assertIsNotNone(pi.lightning_invoice)

        for pi_str in [
            f'lightning:  {bolt11}',
            f'bitcoin:{bolt11}'
        ]:
            pi = PaymentIdentifier(None, pi_str)
            self.assertFalse(pi.is_valid())

        # amount, fallback address
        bolt_11_w_fallback = 'lnbc20m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqsfpp3qjmp7lwpagxun9pygexvgpjdc4jdj85fr9yq20q82gphp2nflc7jtzrcazrra7wwgzxqc8u7754cdlpfrmccae92qgzqvzq2ps8pqqqqqqpqqqqq9qqqvpeuqafqxu92d8lr6fvg0r5gv0heeeqgcrqlnm6jhphu9y00rrhy4grqszsvpcgpy9qqqqqqgqqqqq7qqzqj9n4evl6mr5aj9f58zp6fyjzup6ywn3x6sk8akg5v4tgn2q8g4fhx05wf6juaxu9760yp46454gpg5mtzgerlzezqcqvjnhjh8z3g2qqdhhwkj'
        pi = PaymentIdentifier(None, bolt_11_w_fallback)
        self.assertTrue(pi.is_valid())
        self.assertEqual(PaymentIdentifierType.BOLT11, pi.type)
        self.assertIsNotNone(pi.lightning_invoice)
        self.assertTrue(pi.is_lightning())
        self.assertTrue(pi.is_onchain())
        self.assertTrue(pi.is_amount_locked())

        self.assertFalse(pi.is_error())
        self.assertFalse(pi.need_resolve())
        self.assertFalse(pi.need_finalize())
        self.assertFalse(pi.is_multiline())

    def test_bolt12(self):
        offers = [
            ('lno1pqpzacq2qqgwuquxfmcztl0gldv8mxy3sm8x5jscdz27u39fy6luxu8zcdn9j73l3up5nwlwchur9zukwx743mvm0rvftrhskna22pcvtkyhufn5rc97j3gzqffs859lkadpfasgwxj47xvml7jgekez0lpfuwzhegyxsn2lzdx86qpny7xrmgwj6lphxcfauu22kenqnty4tqdlgnh8tyg87lamqe84nmh2vn0a2n908l7z7cfjghjsuusv7k079upfw0x7dpzavqpwj8swx9ee9q9cumg07fk4gvlajyhy6lfjv0cfe9gqxg0gykehtgjkxwzz24rqdssj4fjcm8xhv2rwel04ed4up2h5sf8n6y7scr0q5rt65k06s6u3mvefzer7qq', True),
            ('lno1pgqppmsrse80qf0aara4slvcjxrvu6j2rp5ftmjy4yntlsmsutpkvkt6878s9h02lqjy3hxc0x67pvwmu3evl6nsnvyy6adl2vn0dym4m2hdtrlnqgprp7jxwvnz5zj7xhz0fwel78cj0u90zgzpwr6we8j0nwzuv5tx9egqxdn72n27tdyers8ffdc2n75cydcl4tkd5lee0trwaekj9luzz5ydqh6cz07448ldts3yzkdk09ekl9t53ryq9lvvpuq90cmylys5saumem93wtvfd77z4alynefyj7ua7kr69dnfqqet7nsydwqa9ghdfy8udkc7x86ydl5l4nrsctfl8d3w4ejcceh9zqh0acy4cc4rcv6wv7zr6gh7fwsjzu8q', False),
        ]
        for bolt12, amount_locked in offers:
            for valid_pi_str in [
                f'{bolt12}',
                f'  {bolt12}',
                f'{bolt12}  ',
                f'lightning:{bolt12}',
                f'  lightning:{bolt12}',
                f'lightning:{bolt12}  ',
                f'lightning:{bolt12.upper()}',
                f'lightning:{bolt12}'.upper(),
            ]:
                pi = PaymentIdentifier(None, valid_pi_str)
                self.assertTrue(pi.is_valid())
                self.assertEqual(PaymentIdentifierType.BOLT12_OFFER, pi.type)
                self.assertEqual(pi.is_amount_locked(), amount_locked)
                self.assertFalse(pi.is_error())
                self.assertIsNotNone(pi.bolt12_offer)
                self.assertTrue(pi.need_finalize())
                self.assertFalse(pi.is_multiline())

            for invalid_pi_str in [
                f'lightning:  {bolt12}',
                f'bitcoin:{bolt12}'
            ]:
                pi = PaymentIdentifier(None, invalid_pi_str)
                self.assertFalse(pi.is_valid())

    def test_bip21(self):
        bip21 = 'bitcoin:bc1qj3zx2zc4rpv3npzmznxhdxzn0wm7pzqp8p2293?message=unit_test'
        for pi_str in [
            f'{bip21}',
            f'  {bip21}',
            f'{bip21}  ',
            f'{bip21}'.upper(),
        ]:
            pi = PaymentIdentifier(None, pi_str)
            self.assertTrue(pi.is_available())
            self.assertFalse(pi.is_lightning())
            self.assertTrue(pi.is_onchain())
            self.assertIsNotNone(pi.bip21)

        # amount, expired, message
        bip21 = 'bitcoin:bc1qy7ps80x5csdqpfcekn97qfljxtg2lrya8826ds?amount=0.001&message=unit_test&time=1707382023&exp=3600'

        pi = PaymentIdentifier(None, bip21)
        self.assertTrue(pi.is_available())
        self.assertFalse(pi.is_lightning())
        self.assertTrue(pi.is_onchain())
        self.assertIsNotNone(pi.bip21)

        self.assertTrue(pi.has_expired())
        self.assertEqual('unit_test', pi.bip21.get('message'))

        # amount, expired, message, lightning w matching amount
        bip21 = 'bitcoin:1RustyRX2oai4EYYDpQGWvEL62BBGqN9T?amount=0.02&message=unit_test&time=1707382023&exp=3600&lightning=lnbc20m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqsfpp3qjmp7lwpagxun9pygexvgpjdc4jdj85fr9yq20q82gphp2nflc7jtzrcazrra7wwgzxqc8u7754cdlpfrmccae92qgzqvzq2ps8pqqqqqqpqqqqq9qqqvpeuqafqxu92d8lr6fvg0r5gv0heeeqgcrqlnm6jhphu9y00rrhy4grqszsvpcgpy9qqqqqqgqqqqq7qqzqj9n4evl6mr5aj9f58zp6fyjzup6ywn3x6sk8akg5v4tgn2q8g4fhx05wf6juaxu9760yp46454gpg5mtzgerlzezqcqvjnhjh8z3g2qqdhhwkj'

        pi = PaymentIdentifier(None, bip21)
        self.assertTrue(pi.is_available())
        self.assertTrue(pi.is_lightning())
        self.assertTrue(pi.is_onchain())
        self.assertIsNotNone(pi.bip21)
        self.assertIsNotNone(pi.lightning_invoice)

        self.assertTrue(pi.has_expired())
        self.assertEqual('unit_test', pi.bip21.get('message'))

        # amount, expired, message, lightning w non-matching amount
        bip21 = 'bitcoin:1RustyRX2oai4EYYDpQGWvEL62BBGqN9T?amount=0.01&message=unit_test&time=1707382023&exp=3600&lightning=lnbc20m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqsfpp3qjmp7lwpagxun9pygexvgpjdc4jdj85fr9yq20q82gphp2nflc7jtzrcazrra7wwgzxqc8u7754cdlpfrmccae92qgzqvzq2ps8pqqqqqqpqqqqq9qqqvpeuqafqxu92d8lr6fvg0r5gv0heeeqgcrqlnm6jhphu9y00rrhy4grqszsvpcgpy9qqqqqqgqqqqq7qqzqj9n4evl6mr5aj9f58zp6fyjzup6ywn3x6sk8akg5v4tgn2q8g4fhx05wf6juaxu9760yp46454gpg5mtzgerlzezqcqvjnhjh8z3g2qqdhhwkj'

        pi = PaymentIdentifier(None, bip21)
        self.assertFalse(pi.is_valid())

        # amount bounds
        bip21 = 'bitcoin:1RustyRX2oai4EYYDpQGWvEL62BBGqN9T?amount=-1'
        pi = PaymentIdentifier(None, bip21)
        self.assertFalse(pi.is_valid())

        bip21 = 'bitcoin:1RustyRX2oai4EYYDpQGWvEL62BBGqN9T?amount=21000001'
        pi = PaymentIdentifier(None, bip21)
        self.assertFalse(pi.is_valid())

        bip21 = 'bitcoin:1RustyRX2oai4EYYDpQGWvEL62BBGqN9T?amount=0'
        pi = PaymentIdentifier(None, bip21)
        self.assertFalse(pi.is_valid())

    def test_lnurl_basic(self):
        """Test basic LNURL parsing without resolve"""
        valid_lnurl = 'lnurl1dp68gurn8ghj7um9wfmxjcm99e5k7telwy7nxenrxvmrgdtzxsenjcm98pjnwxq96s9'
        pi = PaymentIdentifier(None, valid_lnurl)
        self.assertTrue(pi.is_valid())
        self.assertEqual(PaymentIdentifierType.LNURL, pi.type)
        self.assertFalse(pi.is_available())
        self.assertTrue(pi.need_resolve())
        self.assertEqual(PaymentIdentifierState.NEED_RESOLVE, pi.state)

        # Test with lightning: prefix
        lightning_lnurl = f'lightning:{valid_lnurl}'
        pi = PaymentIdentifier(None, lightning_lnurl)
        self.assertTrue(pi.is_valid())
        self.assertEqual(PaymentIdentifierType.LNURL, pi.type)
        self.assertTrue(pi.need_resolve())

        # test with lud17 prefix
        unsupported_lud_17_lnurl_c = f"lnurlc://service.io/?q=3fc3645b439ce8e7"
        pi = PaymentIdentifier(None, unsupported_lud_17_lnurl_c)
        self.assertFalse(pi.is_valid())

        valid_lud_17_lnurl_w = f"lnurlw://service.io/?q=3fc3645b439ce8e7"
        pi = PaymentIdentifier(None, valid_lud_17_lnurl_w)
        self.assertTrue(pi.is_valid())
        self.assertEqual(PaymentIdentifierType.LNURL, pi.type)
        self.assertTrue(pi.need_resolve())

    @patch('electrum.payment_identifier.request_lnurl')
    def test_lnurl_pay_resolve(self, mock_request_lnurl):
        """Test LNURL-pay (LNURL6) with mocked resolve"""
        valid_lnurl = 'LNURL1DP68GURN8GHJ7MRWVF5HGUEWD3HXZERYWFJHXUEWVDHK6TMVDE6HYMRS9ANRV46DXETQPJQCS4'

        # Mock lnurl-p response
        mock_lnurl6_data = LNURL6Data(
            callback_url='https://example.com/lnurl-pay',
            max_sendable_sat=1_000_000,
            min_sendable_sat=1_000,
            metadata_plaintext='Test payment',
            comment_allowed=100,
        )
        mock_request_lnurl.return_value = mock_lnurl6_data

        pi = PaymentIdentifier(None, valid_lnurl)
        self.assertTrue(pi.need_resolve())
        self.assertEqual(PaymentIdentifierType.LNURL, pi.type)

        async def run_resolve():
            await pi._do_resolve()

        asyncio.run(run_resolve())

        self.assertEqual(PaymentIdentifierType.LNURLP, pi.type)
        self.assertEqual(PaymentIdentifierState.LNURLP_FINALIZE, pi.state)
        self.assertTrue(pi.need_finalize())
        self.assertIsNotNone(pi.lnurl_data)
        self.assertTrue(isinstance(pi.lnurl_data, LNURL6Data))
        self.assertEqual(1_000, pi.lnurl_data.min_sendable_sat)
        self.assertEqual(1_000_000, pi.lnurl_data.max_sendable_sat)
        self.assertEqual('Test payment', pi.lnurl_data.metadata_plaintext)
        self.assertEqual(100, pi.lnurl_data.comment_allowed)

    @patch('electrum.payment_identifier.request_lnurl')
    def test_lnurl_withdraw_resolve(self, mock_request_lnurl):
        """Test LNURL-withdraw (LNURL3) with mocked resolve"""
        valid_lnurl = 'LNURL1DP68GURN8GHJ7MRWVF5HGUEWD3HXZERYWFJHXUEWVDHK6TM4WPNHYCTYV4EJ7DFCVGENSDPH8QCRZETXVGCXGCMPVFJR' \
                        'WENP8P3NJEP3XE3NQWRPXFJR2VRRVSCX2V33V5UNVC3SXP3RXCFSVFSKVWPCV3SKZWTP8YUZ7AMFW35XGUNPWUHKZURF9AMRZT' \
                        'MVDE6HYMP0FETHVUNZDAMHQ7JSF4RX73TZ2VU9Z3J3GVMSLCJ57F'

        # Mock lnurl-w response
        mock_lnurl3_data = LNURL3Data(
            callback_url='https://example.com/lnurl-withdraw',
            k1='test-k1-value',
            default_description='Test withdrawal',
            min_withdrawable_sat=1_000,
            max_withdrawable_sat=500_000,
        )
        mock_request_lnurl.return_value = mock_lnurl3_data

        pi = PaymentIdentifier(None, valid_lnurl)
        self.assertTrue(pi.need_resolve())
        self.assertEqual(PaymentIdentifierType.LNURL, pi.type)

        async def run_resolve():
            await pi._do_resolve()

        asyncio.run(run_resolve())

        self.assertEqual(PaymentIdentifierType.LNURLW, pi.type)
        self.assertEqual(PaymentIdentifierState.LNURLW_FINALIZE, pi.state)
        self.assertIsNotNone(pi.lnurl_data)
        self.assertEqual('test-k1-value', pi.lnurl_data.k1)
        self.assertEqual('Test withdrawal', pi.lnurl_data.default_description)
        self.assertEqual(1000, pi.lnurl_data.min_withdrawable_sat)
        self.assertEqual(500000, pi.lnurl_data.max_withdrawable_sat)

    @patch('electrum.payment_identifier.request_lnurl')
    def test_lnurl_resolve_error(self, mock_request_lnurl):
        """Test LNURL resolve error handling"""
        lnurl = 'LNURL1DP68GURN8GHJ7MRWVF5HGUEWD3HXZERYWFJHXUEWVDHK6TM4WPNHYCTYV4EJ7DFCVGENSDPH8QCRZETXVGCXGCMPVFJR' \
                  'WENP8P3NJEP3XE3NQWRPXFJR2VRRVSCX2V33V5UNVC3SXP3RXCFSVFSKVWPCV3SKZWTP8YUZ7AMFW35XGUNPWUHKZURF9AMRZT' \
                  'MVDE6HYMP0FETHVUNZDAMHQ7JSF4RX73TZ2VU9Z3J3GVMSLCJ57F'

        # Mock LNURL error
        mock_request_lnurl.side_effect = LNURLError("Server error")

        pi = PaymentIdentifier(None, lnurl)
        self.assertTrue(pi.need_resolve())

        async def run_resolve():
            await pi._do_resolve()

        asyncio.run(run_resolve())

        self.assertEqual(PaymentIdentifierState.ERROR, pi.state)
        self.assertTrue(pi.is_error())
        self.assertIn("Server error", pi.get_error())

    def test_multiline(self):
        pi_str = '\n'.join([
            'bc1qj3zx2zc4rpv3npzmznxhdxzn0wm7pzqp8p2293,0.01',
            'bc1q66ex4c3vek4cdmrfjxtssmtguvs3r30pf42jpj,0.01',
        ])
        pi = PaymentIdentifier(self.wallet, pi_str)
        self.assertTrue(pi.is_valid())
        self.assertTrue(pi.is_multiline())
        self.assertFalse(pi.is_multiline_max())
        self.assertIsNotNone(pi.multiline_outputs)
        self.assertEqual(2, len(pi.multiline_outputs))
        self.assertTrue(all(lambda x: isinstance(x, PartialTxOutput) for x in pi.multiline_outputs))
        self.assertEqual(1000, pi.multiline_outputs[0].value)
        self.assertEqual(1000, pi.multiline_outputs[1].value)

        pi_str = '\n'.join([
            'bc1qj3zx2zc4rpv3npzmznxhdxzn0wm7pzqp8p2293,0.01',
            'bc1q66ex4c3vek4cdmrfjxtssmtguvs3r30pf42jpj,0.01',
            'bc1qy7ps80x5csdqpfcekn97qfljxtg2lrya8826ds,!',
        ])
        pi = PaymentIdentifier(self.wallet, pi_str)
        self.assertTrue(pi.is_valid())
        self.assertTrue(pi.is_multiline())
        self.assertTrue(pi.is_multiline_max())
        self.assertIsNotNone(pi.multiline_outputs)
        self.assertEqual(3, len(pi.multiline_outputs))
        self.assertTrue(all(lambda x: isinstance(x, PartialTxOutput) for x in pi.multiline_outputs))
        self.assertEqual(1000, pi.multiline_outputs[0].value)
        self.assertEqual(1000, pi.multiline_outputs[1].value)
        self.assertEqual('!', pi.multiline_outputs[2].value)

        pi_str = '\n'.join([
            'bc1qj3zx2zc4rpv3npzmznxhdxzn0wm7pzqp8p2293,0.01',
            'bc1q66ex4c3vek4cdmrfjxtssmtguvs3r30pf42jpj,2!',
            'bc1qy7ps80x5csdqpfcekn97qfljxtg2lrya8826ds,3!',
        ])
        pi = PaymentIdentifier(self.wallet, pi_str)
        self.assertTrue(pi.is_valid())
        self.assertTrue(pi.is_multiline())
        self.assertTrue(pi.is_multiline_max())
        self.assertIsNotNone(pi.multiline_outputs)
        self.assertEqual(3, len(pi.multiline_outputs))
        self.assertTrue(all(lambda x: isinstance(x, PartialTxOutput) for x in pi.multiline_outputs))
        self.assertEqual(1000, pi.multiline_outputs[0].value)
        self.assertEqual('2!', pi.multiline_outputs[1].value)
        self.assertEqual('3!', pi.multiline_outputs[2].value)

        pi_str = '\n'.join([
            'bc1qj3zx2zc4rpv3npzmznxhdxzn0wm7pzqp8p2293,0.01',
            'script(OP_RETURN baddc0ffee),0'
        ])
        pi = PaymentIdentifier(self.wallet, pi_str)
        self.assertTrue(pi.is_valid())
        self.assertTrue(pi.is_multiline())
        self.assertIsNotNone(pi.multiline_outputs)
        self.assertEqual(2, len(pi.multiline_outputs))
        self.assertTrue(all(lambda x: isinstance(x, PartialTxOutput) for x in pi.multiline_outputs))
        self.assertEqual(1000, pi.multiline_outputs[0].value)
        self.assertEqual(0, pi.multiline_outputs[1].value)

    def test_spk(self):
        address = 'bc1qj3zx2zc4rpv3npzmznxhdxzn0wm7pzqp8p2293'
        for pi_str in [
            f'{address}',
            f'  {address}',
            f'{address}  ',
            f'{address}'.upper(),
        ]:
            pi = PaymentIdentifier(None, pi_str)
            self.assertTrue(pi.is_valid())
            self.assertTrue(pi.is_available())

        spk = 'script(OP_RETURN baddc0ffee)'
        for pi_str in [
            f'{spk}',
            f'  {spk}',
            f'{spk}  ',
        ]:
            pi = PaymentIdentifier(None, pi_str)
            self.assertTrue(pi.is_valid())
            self.assertTrue(pi.is_available())

    def test_email_and_domain(self):
        # TODO resolve mock
        domain_pi_strings = (
            'some.domain',
            'some.weird.but.valid.domain',
            'lnbcsome.weird.but.valid.domain',
            'bc1qsome.weird.but.valid.domain',
            'lnurlsome.weird.but.valid.domain',
        )
        for pi_str in domain_pi_strings:
            pi = PaymentIdentifier(None, pi_str)
            self.assertTrue(pi.is_valid())
            self.assertEqual(PaymentIdentifierType.DOMAINLIKE, pi.type)
            self.assertFalse(pi.is_available())
            self.assertTrue(pi.need_resolve())

        email_pi_strings = (
            'user@some.domain',
            'user@some.weird.but.valid.domain',
            'lnbcuser@some.domain',
            'lnurluser@some.domain',
            'bc1quser@some.domain',
            'lightning:user@some.domain',
            'lightning:user@some.weird.but.valid.domain',
            'lightning:lnbcuser@some.domain',
            'lightning:lnurluser@some.domain',
            'lightning:bc1quser@some.domain',
        )
        for pi_str in email_pi_strings:
            pi = PaymentIdentifier(None, pi_str)
            self.assertTrue(pi.is_valid())
            self.assertEqual(PaymentIdentifierType.EMAILLIKE, pi.type)
            self.assertFalse(pi.is_available())
            self.assertTrue(pi.need_resolve())

    async def test_invoice_from_payment_identifier(self):
        # amount, expired, message, lightning w matching amount
        bip21 = 'bitcoin:1RustyRX2oai4EYYDpQGWvEL62BBGqN9T?amount=0.02&message=unit_test&time=1707382023&exp=3600&lightning=lnbc20m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqsfpp3qjmp7lwpagxun9pygexvgpjdc4jdj85fr9yq20q82gphp2nflc7jtzrcazrra7wwgzxqc8u7754cdlpfrmccae92qgzqvzq2ps8pqqqqqqpqqqqq9qqqvpeuqafqxu92d8lr6fvg0r5gv0heeeqgcrqlnm6jhphu9y00rrhy4grqszsvpcgpy9qqqqqqgqqqqq7qqzqj9n4evl6mr5aj9f58zp6fyjzup6ywn3x6sk8akg5v4tgn2q8g4fhx05wf6juaxu9760yp46454gpg5mtzgerlzezqcqvjnhjh8z3g2qqdhhwkj'

        pi = PaymentIdentifier(None, bip21)
        invoice = invoice_from_payment_identifier(pi, None, None)
        self.assertTrue(isinstance(invoice, Invoice))
        self.assertTrue(invoice.is_lightning())
        self.assertEqual(2_000_000_000, invoice.amount_msat)

        text = 'bitter grass shiver impose acquire brush forget axis eager alone wine silver'
        d = restore_wallet_from_text__for_unittest(text, path=self.wallet2_path, config=self.config)
        wallet2 = d['wallet']  # type: Standard_Wallet

        # no amount bip21+lightning, MAX amount passed
        bip21 = 'bitcoin:1RustyRX2oai4EYYDpQGWvEL62BBGqN9T?message=unit_test&time=1707382023&exp=3600&lightning=lnbc1ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsdqq9qypqszpyrpe4tym8d3q87d43cgdhhlsrt78epu7u99mkzttmt2wtsx0304rrw50addkryfrd3vn3zy467vxwlmf4uz7yvntuwjr2hqjl9lw5cqwtp2dy'
        pi = PaymentIdentifier(None, bip21)
        invoice = invoice_from_payment_identifier(pi, wallet2, '!')
        self.assertTrue(isinstance(invoice, Invoice))
        self.assertFalse(invoice.is_lightning())

        # no amount lightning, MAX amount passed -> expect raise
        bolt11 = 'lightning:lnbc1ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsdqq9qypqszpyrpe4tym8d3q87d43cgdhhlsrt78epu7u99mkzttmt2wtsx0304rrw50addkryfrd3vn3zy467vxwlmf4uz7yvntuwjr2hqjl9lw5cqwtp2dy'
        pi = PaymentIdentifier(None, bolt11)
        with self.assertRaises(AssertionError):
            invoice_from_payment_identifier(pi, wallet2, '!')
        invoice = invoice_from_payment_identifier(pi, wallet2, 1)
        self.assertEqual(1000, invoice.amount_msat)
