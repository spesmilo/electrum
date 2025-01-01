import os

from electrum import SimpleConfig
from electrum.invoices import Invoice
from electrum.payment_identifier import (maybe_extract_lightning_payment_identifier, PaymentIdentifier,
                                         PaymentIdentifierType, invoice_from_payment_identifier)
from electrum.wallet import restore_wallet_from_text

from . import ElectrumTestCase
from electrum.transaction import PartialTxOutput


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

    def test_maybe_extract_lightning_payment_identifier(self):
        bolt11 = "lnbc1ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsdqq9qypqszpyrpe4tym8d3q87d43cgdhhlsrt78epu7u99mkzttmt2wtsx0304rrw50addkryfrd3vn3zy467vxwlmf4uz7yvntuwjr2hqjl9lw5cqwtp2dy"
        lnurl = "lnurl1dp68gurn8ghj7um9wfmxjcm99e5k7telwy7nxenrxvmrgdtzxsenjcm98pjnwxq96s9"
        self.assertEqual(bolt11, maybe_extract_lightning_payment_identifier(f"{bolt11}".upper()))
        self.assertEqual(bolt11, maybe_extract_lightning_payment_identifier(f"lightning:{bolt11}"))
        self.assertEqual(bolt11, maybe_extract_lightning_payment_identifier(f"  lightning:{bolt11}   ".upper()))
        self.assertEqual(lnurl, maybe_extract_lightning_payment_identifier(lnurl))
        self.assertEqual(lnurl, maybe_extract_lightning_payment_identifier(f"  lightning:{lnurl}   ".upper()))

        self.assertEqual(None, maybe_extract_lightning_payment_identifier(f"bitcoin:{bolt11}"))
        self.assertEqual(None, maybe_extract_lightning_payment_identifier(f":{bolt11}"))
        self.assertEqual(None, maybe_extract_lightning_payment_identifier(f"garbage text"))

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
            self.assertIsNotNone(pi.bolt11)

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
        self.assertIsNotNone(pi.bolt11)
        self.assertTrue(pi.is_lightning())
        self.assertTrue(pi.is_onchain())
        self.assertTrue(pi.is_amount_locked())

        self.assertFalse(pi.is_error())
        self.assertFalse(pi.need_resolve())
        self.assertFalse(pi.need_finalize())
        self.assertFalse(pi.is_multiline())

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
        self.assertIsNotNone(pi.bolt11)

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

    def test_lnurl(self):
        lnurl = 'lnurl1dp68gurn8ghj7um9wfmxjcm99e5k7telwy7nxenrxvmrgdtzxsenjcm98pjnwxq96s9'
        pi = PaymentIdentifier(None, lnurl)
        self.assertTrue(pi.is_valid())
        self.assertFalse(pi.is_available())
        self.assertTrue(pi.need_resolve())

        # TODO: resolve mock

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
        pi_str = 'some.domain'
        pi = PaymentIdentifier(None, pi_str)
        self.assertTrue(pi.is_valid())
        self.assertEqual(PaymentIdentifierType.DOMAINLIKE, pi.type)
        self.assertFalse(pi.is_available())
        self.assertTrue(pi.need_resolve())

        pi_str = 'some.weird.but.valid.domain'
        pi = PaymentIdentifier(None, pi_str)
        self.assertTrue(pi.is_valid())
        self.assertEqual(PaymentIdentifierType.DOMAINLIKE, pi.type)
        self.assertFalse(pi.is_available())
        self.assertTrue(pi.need_resolve())

        pi_str = 'user@some.domain'
        pi = PaymentIdentifier(None, pi_str)
        self.assertTrue(pi.is_valid())
        self.assertEqual(PaymentIdentifierType.EMAILLIKE, pi.type)
        self.assertFalse(pi.is_available())
        self.assertTrue(pi.need_resolve())

        pi_str = 'user@some.weird.but.valid.domain'
        pi = PaymentIdentifier(None, pi_str)
        self.assertTrue(pi.is_valid())
        self.assertEqual(PaymentIdentifierType.EMAILLIKE, pi.type)
        self.assertFalse(pi.is_available())
        self.assertTrue(pi.need_resolve())

        # TODO resolve mock

    def test_bip70(self):
        pi_str = 'bitcoin:?r=https://test.bitpay.com/i/87iLJoaYVyJwFXtdassQJv'
        pi = PaymentIdentifier(None, pi_str)
        self.assertTrue(pi.is_valid())
        self.assertEqual(PaymentIdentifierType.BIP70, pi.type)
        self.assertFalse(pi.is_available())
        self.assertTrue(pi.need_resolve())

        # TODO resolve mock

    async def test_invoice_from_payment_identifier(self):
        # amount, expired, message, lightning w matching amount
        bip21 = 'bitcoin:1RustyRX2oai4EYYDpQGWvEL62BBGqN9T?amount=0.02&message=unit_test&time=1707382023&exp=3600&lightning=lnbc20m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqsfpp3qjmp7lwpagxun9pygexvgpjdc4jdj85fr9yq20q82gphp2nflc7jtzrcazrra7wwgzxqc8u7754cdlpfrmccae92qgzqvzq2ps8pqqqqqqpqqqqq9qqqvpeuqafqxu92d8lr6fvg0r5gv0heeeqgcrqlnm6jhphu9y00rrhy4grqszsvpcgpy9qqqqqqgqqqqq7qqzqj9n4evl6mr5aj9f58zp6fyjzup6ywn3x6sk8akg5v4tgn2q8g4fhx05wf6juaxu9760yp46454gpg5mtzgerlzezqcqvjnhjh8z3g2qqdhhwkj'

        pi = PaymentIdentifier(None, bip21)
        invoice = invoice_from_payment_identifier(pi, None, None)
        self.assertTrue(isinstance(invoice, Invoice))
        self.assertTrue(invoice.is_lightning())
        self.assertEqual(2_000_000_000, invoice.amount_msat)

        text = 'bitter grass shiver impose acquire brush forget axis eager alone wine silver'
        d = restore_wallet_from_text(text, path=self.wallet2_path, gap_limit=2, config=self.config)
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
