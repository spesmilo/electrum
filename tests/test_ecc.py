import csv
from ctypes import (
    c_int, c_char_p, c_size_t, c_void_p, create_string_buffer,
)
import io

from electrum import ecc, bitcoin
from electrum.ecc import ECPubkey, ECPrivkey
from electrum.ecc_fast import _libsecp256k1
from electrum import crypto
from electrum.crypto import sha256

from . import ElectrumTestCase


# note: lots of ecc-related tests are in test_bitcoin.py.

class TestSchnorr(ElectrumTestCase):

    def test_vectors_from_bip0340(self):
        bip0340_vectors = """index,secret key,public key,aux_rand,message,signature,verification result,comment
0,0000000000000000000000000000000000000000000000000000000000000003,F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9,0000000000000000000000000000000000000000000000000000000000000000,0000000000000000000000000000000000000000000000000000000000000000,E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0,TRUE,
1,B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF,DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659,0000000000000000000000000000000000000000000000000000000000000001,243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89,6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A,TRUE,
2,C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9,DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8,C87AA53824B4D7AE2EB035A2B5BBBCCC080E76CDC6D1692C4B0B62D798E6D906,7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C,5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1BAB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7,TRUE,
3,0B432B2677937381AEF05BB02A66ECD012773062CF3FA2549E44F58ED2401710,25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517,FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF,FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF,7EB0509757E246F19449885651611CB965ECC1A187DD51B64FDA1EDC9637D5EC97582B9CB13DB3933705B32BA982AF5AF25FD78881EBB32771FC5922EFC66EA3,TRUE,test fails if msg is reduced modulo p or n
4,,D69C3509BB99E412E68B0FE8544E72837DFA30746D8BE2AA65975F29D22DC7B9,,4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703,00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C6376AFB1548AF603B3EB45C9F8207DEE1060CB71C04E80F593060B07D28308D7F4,TRUE,
5,,EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34,,243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89,6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B,FALSE,public key not on the curve
6,,DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659,,243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89,FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A14602975563CC27944640AC607CD107AE10923D9EF7A73C643E166BE5EBEAFA34B1AC553E2,FALSE,has_even_y(R) is false
7,,DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659,,243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89,1FA62E331EDBC21C394792D2AB1100A7B432B013DF3F6FF4F99FCB33E0E1515F28890B3EDB6E7189B630448B515CE4F8622A954CFE545735AAEA5134FCCDB2BD,FALSE,negated message
8,,DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659,,243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89,6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769961764B3AA9B2FFCB6EF947B6887A226E8D7C93E00C5ED0C1834FF0D0C2E6DA6,FALSE,negated s value
9,,DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659,,243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89,0000000000000000000000000000000000000000000000000000000000000000123DDA8328AF9C23A94C1FEECFD123BA4FB73476F0D594DCB65C6425BD186051,FALSE,sG - eP is infinite. Test fails in single verification if has_even_y(inf) is defined as true and x(inf) as 0
10,,DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659,,243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89,00000000000000000000000000000000000000000000000000000000000000017615FBAF5AE28864013C099742DEADB4DBA87F11AC6754F93780D5A1837CF197,FALSE,sG - eP is infinite. Test fails in single verification if has_even_y(inf) is defined as true and x(inf) as 1
11,,DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659,,243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89,4A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B,FALSE,sig[0:32] is not an X coordinate on the curve
12,,DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659,,243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89,FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B,FALSE,sig[0:32] is equal to field size
13,,DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659,,243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89,6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,FALSE,sig[32:64] is equal to curve order
14,,FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30,,243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89,6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B,FALSE,public key is not a valid X coordinate because it exceeds the field size
"""
        with io.StringIO(bip0340_vectors) as f:
            csvreader = csv.reader(f)
            next(csvreader)  # skip first line
            for idx, seckey, pubkey, aux_rand, message, signature, expected_res, comment in csvreader:
                idx = int(idx)
                with self.subTest(msg=f"{idx=}"):
                    try:
                        pubkey = ECPubkey(bytes.fromhex("02" + pubkey))
                    except ecc.InvalidECPointException:
                        if idx in (5, 14, ):  # expected for these tests
                            continue
                        raise
                    msg32 = bytes.fromhex(message)
                    signature = bytes.fromhex(signature)
                    if seckey:
                        seckey = ECPrivkey(bytes.fromhex(seckey))
                        aux_rand = bytes.fromhex(aux_rand)
                        sig_created = seckey.schnorr_sign(msg32, aux_rand32=aux_rand)
                        self.assertEqual(signature, sig_created)
                    is_sig_good = pubkey.schnorr_verify(signature, msg32)
                    expected_res = True if expected_res == "TRUE" else False
                    self.assertEqual(expected_res, is_sig_good)

    def test_sign_schnorr_aux_rand(self):
        seckey = ECPrivkey(bytes.fromhex("B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF"))
        msg32 = sha256("hello there")
        sig1 = seckey.schnorr_sign(msg32, aux_rand32=None)
        sig2 = seckey.schnorr_sign(msg32, aux_rand32=b"\x00" * 32)
        self.assertEqual(sig1, sig2)
        sig3 = seckey.schnorr_sign(msg32, aux_rand32=bytes(range(32)))
        self.assertNotEqual(sig1, sig3)

    def test_y_parity_malleability(self):
        # BIP-0340 says:
        # > A hypothetical verification algorithm that treats points as public keys,
        # > and takes the point P directly as input would fail any time a point with
        # > odd Y is used. While it is possible to correct for this by negating points
        # > with odd Y coordinate before further processing, this would result in a scheme
        # > where every (message, signature) pair is valid for two public keys (a type of
        # > malleability that exists for ECDSA as well, but we don't wish to retain).
        # > We avoid these problems by treating just the X coordinate as public key.
        #
        # As the API in ecc.py treats points as public keys, this malleability exists here:
        seckey = ECPrivkey.from_secret_scalar(1337)
        pubkey1 = ECPubkey(seckey.get_public_key_bytes())
        pubkey2 = ecc.CURVE_ORDER * ecc.GENERATOR + (-1) * pubkey1
        self.assertNotEqual(pubkey1.get_public_key_bytes(True), pubkey2.get_public_key_bytes(True))
        self.assertEqual(pubkey1.get_public_key_bytes(True)[1:], pubkey2.get_public_key_bytes(True)[1:])
        msg32 = sha256("hello there")
        sig = seckey.schnorr_sign(msg32, aux_rand32=None)
        self.assertTrue(pubkey1.schnorr_verify(sig, msg32))
        self.assertTrue(pubkey2.schnorr_verify(sig, msg32))

    def test_bip340_tagged_hash(self):
        try:
            _libsecp256k1.secp256k1_tagged_sha256.argtypes = [c_void_p, c_char_p, c_char_p, c_size_t, c_char_p, c_size_t]
            _libsecp256k1.secp256k1_tagged_sha256.restype = c_int
        except (OSError, AttributeError):
            raise Exception('libsecp256k1 library too old: missing secp256k1_tagged_sha256 method')

        def bip340_tagged_hash__from_libsecp(tag: bytes, msg: bytes) -> bytes:
            assert isinstance(tag, bytes), type(tag)
            assert isinstance(msg, bytes), type(msg)
            thash = create_string_buffer(32)
            ret = _libsecp256k1.secp256k1_tagged_sha256(
                _libsecp256k1.ctx, thash, tag, len(tag), msg, len(msg))
            assert 1 == ret, ret
            thash = bytes(thash)
            return thash

        data = (
            (b"", b""),
            (b"", b"hello there"),
            (b"mytag", b""),
            (b"mytag", b"hello there"),
            (bytes(range(256)) * 10, bytes(range(256)) * 50),
            (bytes(range(256)) * 1000, bytes(range(256)) * 5000),
        )
        for tag, msg in data:
            self.assertEqual(bip340_tagged_hash__from_libsecp(tag, msg),
                             bitcoin.bip340_tagged_hash(tag, msg))


class TestEcdsa(ElectrumTestCase):

    def test_verify_enforces_low_s(self):
        # privkey = ecc.ECPrivkey(bytes.fromhex("d473e2ec218dca8e3508798f01cdfde0135fc79d95526b12e3537fe57e479ac1"))
        # r, low_s = privkey.ecdsa_sign(msg32, sigencode=lambda x, y: (x,y))
        # pubkey = ecc.ECPubkey(privkey.get_public_key_bytes())
        pubkey = ecc.ECPubkey(bytes.fromhex("03befe4f7c92eaed73fb8eddac28c6191c87c6a3546bf8dc09643e1e10bc6f5ab0"))
        msg32 = sha256("hello there")
        r = 29658118546717807188148256874354333643324863178937517286987684851194094232509
        # low-S
        low_s = 9695211969150896589566136599751503273246834163278279637071703776634378000266
        sig64_low_s = (
            int.to_bytes(r, length=32, byteorder="big") +
            int.to_bytes(low_s, length=32, byteorder="big"))
        self.assertTrue(pubkey.ecdsa_verify(sig64_low_s, msg32))
        # high-S
        high_s = ecc.CURVE_ORDER - low_s
        sig64_high_s = (
            int.to_bytes(r, length=32, byteorder="big") +
            int.to_bytes(high_s, length=32, byteorder="big"))
        self.assertFalse(pubkey.ecdsa_verify(sig64_high_s, msg32))
        self.assertTrue(pubkey.ecdsa_verify(sig64_high_s, msg32, enforce_low_s=False))
