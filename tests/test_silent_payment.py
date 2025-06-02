import json
import os

from electrum_ecc import ECPrivkey
from electrum.segwit_addr import bech32_encode, convertbits, Encoding
from electrum.silent_payment import SilentPaymentAddress, create_silent_payment_outputs, SilentPaymentDerivationFailure, \
    _decode_silent_payment_addr, SILENT_PAYMENT_DUMMY_SPK
from electrum.transaction import TxOutpoint, PartialTxOutput, merge_duplicate_tx_outputs
from electrum.util import bfh
from . import ElectrumTestCase

class TestSilentPaymentCreateOutputs(ElectrumTestCase):
    """Test core logic of calculating silent payment outputs."""
    # This uses a curated subset of test vectors from BIP352.
    # Tests involving recipient relevancy, Taproot inputs, uncompressed public keys (P2PKH or P2WPKH),
    # malleated public keys (P2PKH pubkey extraction), and invalid P2SH scripts are skipped.
    #
    # These cases are not applicable to Electrum's current implementation, which only supports
    # standard wallets using BIP39 keystores for silent payments. All private keys are assumed to correspond to
    # compressed public keys. Taproot inputs are not yet supported in electrum.

    def test_silent_payment_create_outputs(self):
        # Note: Unlike the BIP352 reference implementation tests, this test also verifies
        # the correspondence between each silent payment address and its derived outputs.
        test_vector_file = os.path.join(os.path.dirname(__file__), "bip-0352", "sp_send_test_vectors.json")
        with open(test_vector_file, "r") as f:
            vectors = json.load(f)

        for case in vectors:
            given = case["given"]
            expected = case["expected"]

            outpoints: list[TxOutpoint] = []
            input_privkeys: list[ECPrivkey] = []

            for txin in given["vin"]:
                outpoints.append(TxOutpoint(txid=bfh(txin["txid"]), out_idx=txin["vout"]))
                input_privkeys.append(ECPrivkey(bfh(txin["private_key"])))

            recipients = [SilentPaymentAddress(recipient) for recipient in given["recipients"]]

            outputs_map = create_silent_payment_outputs(input_privkeys, outpoints, recipients)

            # Normalize actual output
            actual_map = {
                addr.encoded: {spk.hex() for spk in spks}
                for addr, spks in outputs_map.items()
            }

            # Normalize expected output
            expected_map = {
                sp_addr: set(spk_list)
                for sp_addr, spk_list in expected["outputs_by_sp_addr"].items()
            }
            self.assertEqual(actual_map, expected_map)


    def test_private_keys_sum_to_zero(self):
        outpoints: list[TxOutpoint] = [
            TxOutpoint(txid=bfh("3a286147b25e16ae80aff406f2673c6e565418c40f45c071245cdebc8a94174e"), out_idx=0),
            TxOutpoint(txid=bfh("3a286147b25e16ae80aff406f2673c6e565418c40f45c071245cdebc8a94174e"), out_idx=1)
        ]
        input_privkeys: list[ECPrivkey] = [
            ECPrivkey(bfh("a6df6a0bb448992a301df4258e06a89fe7cf7146f59ac3bd5ff26083acb22ceb")),
            ECPrivkey(bfh("592095f44bb766d5cfe20bda71f9575ed2df6b9fb9addc7e5fdffe0923841456"))
        ]
        recipients = [
            SilentPaymentAddress("sp1qqtrqglu5g8kh6mfsg4qxa9wq0nv9cauwfwxw70984wkqnw2uwz0w2qnehen8a7wuhwk9tgrzjh8gwzc8q2dlekedec5djk0js9d3d7qhnq6lqj3s")
        ]

        self.assertRaises(SilentPaymentDerivationFailure, create_silent_payment_outputs, input_privkeys, outpoints, recipients)

class TestSilentPaymentParseAddress(ElectrumTestCase):
    """Test core logic of parsing silent payment address."""
    def test_silent_payment_parse_address_success(self):
        addr_testnet = 'tsp1qqvs8aztfcfxsjtf4y759uaxpyw6h68jd40ptwe95ecplsugn84qyyq467304jp07mnxyu2xygnpw5j9wxc3l89l63v2sjul7lef6jljhsyvqp9wq'
        addr_mainnet = 'sp1qq2h2utp7zfk5kpxf8s6rxaz2x899p7un7gdm7ny44mjr87zxglc66qn70vcsuwyxmwuakj5hyh907em68l4wmpmza4cka8zr64caa8ptgqt8khxk'

        B_Scan, B_M = _decode_silent_payment_addr('tsp', addr_testnet)
        self.assertEqual(B_Scan.get_public_key_hex(), "03207e8969c24d092d3527a85e74c123b57d1e4dabc2b764b4ce03f871133d4042")
        self.assertEqual(B_M.get_public_key_hex(), "02baf45f5905fedccc4e28c444c2ea48ae3623f397fa8b150973fefe53a97e5781")

        B_Scan, B_M = _decode_silent_payment_addr('sp', addr_mainnet)
        self.assertEqual(B_Scan.get_public_key_hex(), "02aeae2c3e126d4b04c93c3433744a31ca50fb93f21bbf4c95aee433f84647f1ad")
        self.assertEqual(B_M.get_public_key_hex(), "027e7b310e3886dbb9db4a9725caff677a3feaed8762ed716e9c43d571de9c2b40")

    def test_malformed_silent_payment_address(self):
        # inconsistent hrp
        with self.assertRaises(ValueError) as ctx:
            _decode_silent_payment_addr('sp', 'tsp1qqvs8aztfcfxsjtf4y759uaxpyw6h68jd40ptwe95ecplsugn84qyyq467304jp07mnxyu2xygnpw5j9wxc3l89l63v2sjul7lef6jljhsyvqp9wq')
        self.assertIn("Invalid HRP", str(ctx.exception))

        # v0 must contain exactly 66 bytes of data
        with self.assertRaises(ValueError) as ctx:
            # Just a fake payload with 65 bytes (instead of 66)
            b32 = bech32_encode(Encoding.BECH32, 'sp', [0] + list(convertbits(bytes(65), 8, 5)))
            _decode_silent_payment_addr('sp', b32)
        self.assertIn("Silent payment v0 must contain exactly 66 bytes", str(ctx.exception))

        # v(1-30) versions are not supported
        with self.assertRaises(NotImplementedError) as ctx:
            vers = 8 # for example
            b32 = bech32_encode(Encoding.BECH32, 'sp', [vers] + list(convertbits(bytes(66), 8, 5)))
            _decode_silent_payment_addr('sp', b32)
        self.assertIn("Silent payment version 8 not yet supported", str(ctx.exception))

        # sp_addr contains invalid B_scan/B_m
        with self.assertRaises(ValueError) as ctx:
            invalid_pks = bytes(66)
            b32 = bech32_encode(Encoding.BECH32, 'sp', [0] + list(convertbits(invalid_pks, 8, 5)))
            _decode_silent_payment_addr('sp', b32)
        self.assertIn("Invalid public key(s) in silent payment address", str(ctx.exception))

class TestSilentPaymentTxCreation(ElectrumTestCase):

    def test_merge_duplicate_tx_outputs(self):
        sp_addr1 = SilentPaymentAddress("sp1qqtrqglu5g8kh6mfsg4qxa9wq0nv9cauwfwxw70984wkqnw2uwz0w2qnehen8a7wuhwk9tgrzjh8gwzc8q2dlekedec5djk0js9d3d7qhnq6lqj3s")
        sp_addr2 = SilentPaymentAddress("sp1qq2h2utp7zfk5kpxf8s6rxaz2x899p7un7gdm7ny44mjr87zxglc66qn70vcsuwyxmwuakj5hyh907em68l4wmpmza4cka8zr64caa8ptgqt8khxk")
        addr1 = "bc1qq2tmmcngng78nllq2pvrkchcdukemtj56uyue0"
        addr2 = "3DYoBqQ5N6dADzyQjy9FT1Ls4amiYVaqTG"

        sp_output1 = PartialTxOutput(value=1000, scriptpubkey=SILENT_PAYMENT_DUMMY_SPK)
        sp_output1.sp_addr = sp_addr1

        sp_output2 = PartialTxOutput(value=2100, scriptpubkey=SILENT_PAYMENT_DUMMY_SPK)
        sp_output2.sp_addr = sp_addr2

        output1 = PartialTxOutput.from_address_and_value(addr1, 3200)
        output2 = PartialTxOutput.from_address_and_value(addr2, 4300)

        # Test mixed merge
        merged = merge_duplicate_tx_outputs([sp_output1, sp_output1, sp_output1, sp_output2, output1, output1, output2])
        self.assertEqual(len(merged), 4)
        merged.sort(key=lambda o: o.value)
        self.assertEqual(merged[0].sp_addr, sp_addr2)
        self.assertEqual(merged[0].value, 2100)
        self.assertEqual(merged[1].sp_addr, sp_addr1)
        self.assertEqual(merged[1].value, 3000)
        self.assertEqual(merged[2].address, addr2)
        self.assertEqual(merged[2].value, 4300)
        self.assertEqual(merged[3].address, addr1)
        self.assertEqual(merged[3].value, 6400)

        # test: don't merge non dummy spk silent payment outputs
        spk = bfh("51203e9fce73d4e77a4809908e3c3a2e54ee147b9312dc5044a193d1fc85de46e3c1")
        sp_output1_non_dummy = PartialTxOutput(scriptpubkey=spk, value=1000)
        sp_output1_non_dummy.sp_addr = sp_addr1
        merged = merge_duplicate_tx_outputs([sp_output1_non_dummy, sp_output1])
        self.assertEqual(len(merged), 2)




