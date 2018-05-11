import binascii
import json
import unittest

from lib.util import bh2u, bfh
from lib.lnbase import make_commitment, get_obscured_ctn, Peer, make_offered_htlc, make_received_htlc, make_htlc_tx
from lib.lnbase import secret_to_pubkey, derive_pubkey, derive_privkey, derive_blinded_pubkey, overall_weight
from lib.lnbase import make_htlc_tx_output, make_htlc_tx_inputs, get_per_commitment_secret_from_seed
from lib.lnbase import make_htlc_tx_witness, OnionHopsDataSingle, new_onion_packet, OnionPerHop
from lib.lnbase import RevocationStore, ShachainElement, shachain_derive
from lib.transaction import Transaction
from lib import bitcoin
import ecdsa.ellipticcurve
from ecdsa.curves import SECP256k1
from lib.util import bfh
from lib import bitcoin, lnbase

funding_tx_id = '8984484a580b825b9972d7adb15050b3ab624ccd731946b3eeddb92f4e7ef6be'
funding_output_index = 0
funding_amount_satoshi = 10000000
commitment_number = 42
local_delay = 144
local_dust_limit_satoshi = 546

local_payment_basepoint = bytes.fromhex('034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa')
remote_payment_basepoint = bytes.fromhex('032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991')
obs = get_obscured_ctn(42, local_payment_basepoint, remote_payment_basepoint)
local_funding_privkey = bytes.fromhex('30ff4956bbdd3222d44cc5e8a1261dab1e07957bdac5ae88fe3261ef321f374901')
local_funding_pubkey = bytes.fromhex('023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb')
remote_funding_pubkey = bytes.fromhex('030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c1')
local_privkey = bytes.fromhex('bb13b121cdc357cd2e608b0aea294afca36e2b34cf958e2e6451a2f27469449101')
localpubkey = bytes.fromhex('030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e7')
remotepubkey = bytes.fromhex('0394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b')
local_delayedpubkey = bytes.fromhex('03fd5960528dc152014952efdb702a88f71e3c1653b2314431701ec77e57fde83c')
local_revocation_pubkey = bytes.fromhex('0212a140cd0c6539d07cd08dfe09984dec3251ea808b892efeac3ede9402bf2b19')
# funding wscript = 5221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae

class Test_LNBase(unittest.TestCase):

    @staticmethod
    def parse_witness_list(witness_bytes):
        amount_witnesses = witness_bytes[0]
        witness_bytes = witness_bytes[1:]
        res = []
        for i in range(amount_witnesses):
            witness_length = witness_bytes[0]
            this_witness = witness_bytes[1:witness_length+1]
            assert len(this_witness) == witness_length
            witness_bytes = witness_bytes[witness_length+1:]
            res += [bytes(this_witness)]
        assert witness_bytes == b"", witness_bytes
        return res

    def test_simple_commitment_tx_with_no_HTLCs(self):
        to_local_msat = 7000000000
        to_remote_msat = 3000000000
        local_feerate_per_kw = 15000
        # base commitment transaction fee = 10860
        # actual commitment transaction fee = 10860
        # to_local amount 6989140 wscript 63210212a140cd0c6539d07cd08dfe09984dec3251ea808b892efeac3ede9402bf2b1967029000b2752103fd5960528dc152014952efdb702a88f71e3c1653b2314431701ec77e57fde83c68ac
        # to_remote amount 3000000 P2WPKH(0394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b)
        remote_signature = "3045022100f51d2e566a70ba740fc5d8c0f07b9b93d2ed741c3c0860c613173de7d39e7968022041376d520e9c0e1ad52248ddf4b22e12be8763007df977253ef45a4ca3bdb7c0"
        # local_signature = 3044022051b75c73198c6deee1a875871c3961832909acd297c6b908d59e3319e5185a46022055c419379c5051a78d00dbbce11b5b664a0c22815fbcc6fcef6b1937c3836939
        htlcs=[]
        local_amount = to_local_msat // 1000
        remote_amount = to_remote_msat // 1000
        our_commit_tx = make_commitment(
            commitment_number,
            local_funding_pubkey, remote_funding_pubkey, remotepubkey,
            local_payment_basepoint, remote_payment_basepoint,
            local_revocation_pubkey, local_delayedpubkey, local_delay,
            funding_tx_id, funding_output_index, funding_amount_satoshi,
            local_amount, remote_amount, local_dust_limit_satoshi,
            local_feerate_per_kw, True, htlcs=[])
        self.sign_and_insert_remote_sig(our_commit_tx, remote_funding_pubkey, remote_signature, local_funding_pubkey, local_funding_privkey)
        ref_commit_tx_str = '02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b8002c0c62d0000000000160014ccf1af2f2aabee14bb40fa3851ab2301de84311054a56a00000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0400473044022051b75c73198c6deee1a875871c3961832909acd297c6b908d59e3319e5185a46022055c419379c5051a78d00dbbce11b5b664a0c22815fbcc6fcef6b1937c383693901483045022100f51d2e566a70ba740fc5d8c0f07b9b93d2ed741c3c0860c613173de7d39e7968022041376d520e9c0e1ad52248ddf4b22e12be8763007df977253ef45a4ca3bdb7c001475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220'
        self.assertEqual(str(our_commit_tx), ref_commit_tx_str)

    def sign_and_insert_remote_sig(self, tx, remote_pubkey, remote_signature, pubkey, privkey):
        assert type(remote_pubkey) is bytes
        assert len(remote_pubkey) == 33
        assert type(remote_signature) is str
        assert type(pubkey) is bytes
        assert type(privkey) is bytes
        assert len(pubkey) == 33
        assert len(privkey) == 33
        tx.sign({bh2u(pubkey): (privkey[:-1], True)})
        pubkeys, _x_pubkeys = tx.get_sorted_pubkeys(tx.inputs()[0])
        index_of_pubkey = pubkeys.index(bh2u(remote_pubkey))
        tx._inputs[0]["signatures"][index_of_pubkey] = remote_signature + "01"
        tx.raw = None

    def test_commitment_tx_with_all_five_HTLCs_untrimmed_minimum_feerate(self):
        to_local_msat = 6988000000
        to_remote_msat = 3000000000
        local_feerate_per_kw = 0
        # base commitment transaction fee = 0
        # actual commitment transaction fee = 0

        per_commitment_secret = 0x1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100
        per_commitment_point = SECP256k1.generator * per_commitment_secret 

        remote_htlcpubkey = remotepubkey
        local_htlcpubkey = localpubkey

        htlc2_cltv_timeout = 502
        htlc2_payment_preimage = b"\x02" * 32
        htlc2 = make_offered_htlc(local_revocation_pubkey, remote_htlcpubkey, local_htlcpubkey, bitcoin.sha256(htlc2_payment_preimage))
        # HTLC 2 offered amount 2000
        ref_htlc2_wscript = "76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a914b43e1b38138a41b37f7cd9a1d274bc63e3a9b5d188ac6868"
        self.assertEqual(htlc2, bfh(ref_htlc2_wscript))

        htlc3_cltv_timeout = 503
        htlc3_payment_preimage = b"\x03" * 32
        htlc3 = make_offered_htlc(local_revocation_pubkey, remote_htlcpubkey, local_htlcpubkey, bitcoin.sha256(htlc3_payment_preimage))
        # HTLC 3 offered amount 3000 
        ref_htlc3_wscript = "76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a9148a486ff2e31d6158bf39e2608864d63fefd09d5b88ac6868"
        self.assertEqual(htlc3, bfh(ref_htlc3_wscript))

        htlc0_cltv_timeout = 500
        htlc0_payment_preimage = b"\x00" * 32
        htlc0 = make_received_htlc(local_revocation_pubkey, remote_htlcpubkey, local_htlcpubkey, bitcoin.sha256(htlc0_payment_preimage), htlc0_cltv_timeout)
        # HTLC 0 received amount 1000
        ref_htlc0_wscript = "76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a914b8bcb07f6344b42ab04250c86a6e8b75d3fdbbc688527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f401b175ac6868"
        self.assertEqual(htlc0, bfh(ref_htlc0_wscript))

        htlc1_cltv_timeout = 501
        htlc1_payment_preimage = b"\x01" * 32
        htlc1 = make_received_htlc(local_revocation_pubkey, remote_htlcpubkey, local_htlcpubkey, bitcoin.sha256(htlc1_payment_preimage), htlc1_cltv_timeout)
        # HTLC 1 received amount 2000 
        ref_htlc1_wscript = "76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a9144b6b2e5444c2639cc0fb7bcea5afba3f3cdce23988527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f501b175ac6868"
        self.assertEqual(htlc1, bfh(ref_htlc1_wscript))

        htlc4_cltv_timeout = 504
        htlc4_payment_preimage = b"\x04" * 32
        htlc4 = make_received_htlc(local_revocation_pubkey, remote_htlcpubkey, local_htlcpubkey, bitcoin.sha256(htlc4_payment_preimage), htlc4_cltv_timeout)
        # HTLC 4 received amount 4000 
        ref_htlc4_wscript = "76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a91418bc1a114ccf9c052d3d23e28d3b0a9d1227434288527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f801b175ac6868"
        self.assertEqual(htlc4, bfh(ref_htlc4_wscript))

        # to_local amount 6988000 wscript 63210212a140cd0c6539d07cd08dfe09984dec3251ea808b892efeac3ede9402bf2b1967029000b2752103fd5960528dc152014952efdb702a88f71e3c1653b2314431701ec77e57fde83c68ac
        # to_remote amount 3000000 P2WPKH(0394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b)
        remote_signature = "304402204fd4928835db1ccdfc40f5c78ce9bd65249b16348df81f0c44328dcdefc97d630220194d3869c38bc732dd87d13d2958015e2fc16829e74cd4377f84d215c0b70606"
        # local_signature = 30440220275b0c325a5e9355650dc30c0eccfbc7efb23987c24b556b9dfdd40effca18d202206caceb2c067836c51f296740c7ae807ffcbfbf1dd3a0d56b6de9a5b247985f06
        output_commit_tx = "02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b8007e80300000000000022002052bfef0479d7b293c27e0f1eb294bea154c63a3294ef092c19af51409bce0e2ad007000000000000220020403d394747cae42e98ff01734ad5c08f82ba123d3d9a620abda88989651e2ab5d007000000000000220020748eba944fedc8827f6b06bc44678f93c0f9e6078b35c6331ed31e75f8ce0c2db80b000000000000220020c20b5d1f8584fd90443e7b7b720136174fa4b9333c261d04dbbd012635c0f419a00f0000000000002200208c48d15160397c9731df9bc3b236656efb6665fbfe92b4a6878e88a499f741c4c0c62d0000000000160014ccf1af2f2aabee14bb40fa3851ab2301de843110e0a06a00000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e04004730440220275b0c325a5e9355650dc30c0eccfbc7efb23987c24b556b9dfdd40effca18d202206caceb2c067836c51f296740c7ae807ffcbfbf1dd3a0d56b6de9a5b247985f060147304402204fd4928835db1ccdfc40f5c78ce9bd65249b16348df81f0c44328dcdefc97d630220194d3869c38bc732dd87d13d2958015e2fc16829e74cd4377f84d215c0b7060601475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220"

        htlc0_msat = 1000 * 1000
        htlc2_msat = 2000 * 1000
        htlc3_msat = 3000 * 1000
        htlc1_msat = 2000 * 1000
        htlc4_msat = 4000 * 1000
        htlcs = [(htlc2, htlc2_msat), (htlc3, htlc3_msat), (htlc0, htlc0_msat), (htlc1, htlc1_msat), (htlc4, htlc4_msat)]

        local_amount = to_local_msat // 1000
        remote_amount = to_remote_msat // 1000
        our_commit_tx = make_commitment(
            commitment_number,
            local_funding_pubkey, remote_funding_pubkey, remotepubkey,
            local_payment_basepoint, remote_payment_basepoint,
            local_revocation_pubkey, local_delayedpubkey, local_delay,
            funding_tx_id, funding_output_index, funding_amount_satoshi,
            local_amount, remote_amount, local_dust_limit_satoshi,
            local_feerate_per_kw, True, htlcs=htlcs)
        self.sign_and_insert_remote_sig(our_commit_tx, remote_funding_pubkey, remote_signature, local_funding_pubkey, local_funding_privkey)
        self.assertEqual(str(our_commit_tx), output_commit_tx)

        # (HTLC 0)
        signature_for_output_remote_htlc_0 = "304402206a6e59f18764a5bf8d4fa45eebc591566689441229c918b480fb2af8cc6a4aeb02205248f273be447684b33e3c8d1d85a8e0ca9fa0bae9ae33f0527ada9c162919a6"
        # (HTLC 2)
        signature_for_output_remote_htlc_2 = "3045022100d5275b3619953cb0c3b5aa577f04bc512380e60fa551762ce3d7a1bb7401cff9022037237ab0dac3fe100cde094e82e2bed9ba0ed1bb40154b48e56aa70f259e608b"
        # (HTLC 1)
        signature_for_output_remote_htlc_1 = "304402201b63ec807771baf4fdff523c644080de17f1da478989308ad13a58b51db91d360220568939d38c9ce295adba15665fa68f51d967e8ed14a007b751540a80b325f202"
        # (HTLC 3)
        signature_for_output_remote_htlc_3 = "3045022100daee1808f9861b6c3ecd14f7b707eca02dd6bdfc714ba2f33bc8cdba507bb182022026654bf8863af77d74f51f4e0b62d461a019561bb12acb120d3f7195d148a554"
        # (HTLC 4)
        signature_for_output_remote_htlc_4 = "304402207e0410e45454b0978a623f36a10626ef17b27d9ad44e2760f98cfa3efb37924f0220220bd8acd43ecaa916a80bd4f919c495a2c58982ce7c8625153f8596692a801d"


        local_signature_htlc0 = "304402207cb324fa0de88f452ffa9389678127ebcf4cabe1dd848b8e076c1a1962bf34720220116ed922b12311bd602d67e60d2529917f21c5b82f25ff6506c0f87886b4dfd5" # derive ourselves
        output_htlc_success_tx_0 = "020000000001018154ecccf11a5fb56c39654c4deb4d2296f83c69268280b94d021370c94e219700000000000000000001e8030000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e050047304402206a6e59f18764a5bf8d4fa45eebc591566689441229c918b480fb2af8cc6a4aeb02205248f273be447684b33e3c8d1d85a8e0ca9fa0bae9ae33f0527ada9c162919a60147304402207cb324fa0de88f452ffa9389678127ebcf4cabe1dd848b8e076c1a1962bf34720220116ed922b12311bd602d67e60d2529917f21c5b82f25ff6506c0f87886b4dfd5012000000000000000000000000000000000000000000000000000000000000000008a76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a914b8bcb07f6344b42ab04250c86a6e8b75d3fdbbc688527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f401b175ac686800000000"

        local_signature_htlc2 = "3045022100c89172099507ff50f4c925e6c5150e871fb6e83dd73ff9fbb72f6ce829a9633f02203a63821d9162e99f9be712a68f9e589483994feae2661e4546cd5b6cec007be5"
        output_htlc_timeout_tx_2 = "020000000001018154ecccf11a5fb56c39654c4deb4d2296f83c69268280b94d021370c94e219701000000000000000001d0070000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500483045022100d5275b3619953cb0c3b5aa577f04bc512380e60fa551762ce3d7a1bb7401cff9022037237ab0dac3fe100cde094e82e2bed9ba0ed1bb40154b48e56aa70f259e608b01483045022100c89172099507ff50f4c925e6c5150e871fb6e83dd73ff9fbb72f6ce829a9633f02203a63821d9162e99f9be712a68f9e589483994feae2661e4546cd5b6cec007be501008576a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a914b43e1b38138a41b37f7cd9a1d274bc63e3a9b5d188ac6868f6010000"

        local_signature_htlc1 = "3045022100def389deab09cee69eaa1ec14d9428770e45bcbe9feb46468ecf481371165c2f022015d2e3c46600b2ebba8dcc899768874cc6851fd1ecb3fffd15db1cc3de7e10da"
        output_htlc_success_tx_1 = "020000000001018154ecccf11a5fb56c39654c4deb4d2296f83c69268280b94d021370c94e219702000000000000000001d0070000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e050047304402201b63ec807771baf4fdff523c644080de17f1da478989308ad13a58b51db91d360220568939d38c9ce295adba15665fa68f51d967e8ed14a007b751540a80b325f20201483045022100def389deab09cee69eaa1ec14d9428770e45bcbe9feb46468ecf481371165c2f022015d2e3c46600b2ebba8dcc899768874cc6851fd1ecb3fffd15db1cc3de7e10da012001010101010101010101010101010101010101010101010101010101010101018a76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a9144b6b2e5444c2639cc0fb7bcea5afba3f3cdce23988527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f501b175ac686800000000"

        local_signature_htlc3 = "30440220643aacb19bbb72bd2b635bc3f7375481f5981bace78cdd8319b2988ffcc6704202203d27784ec8ad51ed3bd517a05525a5139bb0b755dd719e0054332d186ac08727"
        output_htlc_timeout_tx_3 = "020000000001018154ecccf11a5fb56c39654c4deb4d2296f83c69268280b94d021370c94e219703000000000000000001b80b0000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500483045022100daee1808f9861b6c3ecd14f7b707eca02dd6bdfc714ba2f33bc8cdba507bb182022026654bf8863af77d74f51f4e0b62d461a019561bb12acb120d3f7195d148a554014730440220643aacb19bbb72bd2b635bc3f7375481f5981bace78cdd8319b2988ffcc6704202203d27784ec8ad51ed3bd517a05525a5139bb0b755dd719e0054332d186ac0872701008576a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a9148a486ff2e31d6158bf39e2608864d63fefd09d5b88ac6868f7010000"

        local_signature_htlc4 = "30440220549e80b4496803cbc4a1d09d46df50109f546d43fbbf86cd90b174b1484acd5402205f12a4f995cb9bded597eabfee195a285986aa6d93ae5bb72507ebc6a4e2349e"
        output_htlc_success_tx_4 = "020000000001018154ecccf11a5fb56c39654c4deb4d2296f83c69268280b94d021370c94e219704000000000000000001a00f0000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e050047304402207e0410e45454b0978a623f36a10626ef17b27d9ad44e2760f98cfa3efb37924f0220220bd8acd43ecaa916a80bd4f919c495a2c58982ce7c8625153f8596692a801d014730440220549e80b4496803cbc4a1d09d46df50109f546d43fbbf86cd90b174b1484acd5402205f12a4f995cb9bded597eabfee195a285986aa6d93ae5bb72507ebc6a4e2349e012004040404040404040404040404040404040404040404040404040404040404048a76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a91418bc1a114ccf9c052d3d23e28d3b0a9d1227434288527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f801b175ac686800000000"

        def test_htlc_tx(htlc, htlc_output_index, amount_msat, ref_local_sig, htlc_payment_preimage, remote_htlc_sig, ref_tx, success, cltv_timeout):
            our_htlc_tx_output = make_htlc_tx_output(
                amount_msat=amount_msat,
                local_feerate=local_feerate_per_kw,
                revocationpubkey=local_revocation_pubkey,
                local_delayedpubkey=local_delayedpubkey,
                success=success,
                to_self_delay=local_delay)
            our_htlc_tx_inputs = make_htlc_tx_inputs(
                htlc_output_txid=our_commit_tx.txid(),
                htlc_output_index=htlc_output_index,
                revocationpubkey=local_revocation_pubkey,
                local_delayedpubkey=local_delayedpubkey,
                amount_msat=amount_msat,
                witness_script=bh2u(htlc))
            our_htlc_tx = make_htlc_tx(cltv_timeout,
                inputs=our_htlc_tx_inputs,
                output=our_htlc_tx_output)

            local_sig = our_htlc_tx.sign_txin(0, local_privkey[:-1])
            #self.assertEqual(ref_local_sig + "01", local_sig)  # commented out as it is sufficient to compare the serialized txn

            our_htlc_tx_witness = make_htlc_tx_witness(  # FIXME only correct for success=True
                remotehtlcsig=bfh(remote_htlc_sig) + b"\x01",  # 0x01 is SIGHASH_ALL
                localhtlcsig=bfh(local_sig),
                payment_preimage=htlc_payment_preimage if success else b'',  # will put 00 on witness if timeout
                witness_script=htlc)
            our_htlc_tx._inputs[0]['witness'] = bh2u(our_htlc_tx_witness)
            self.assertEqual(ref_tx, str(our_htlc_tx))

        test_htlc_tx(htlc=htlc0, htlc_output_index=0,
                     amount_msat=htlc0_msat,
                     ref_local_sig=local_signature_htlc0,
                     htlc_payment_preimage=htlc0_payment_preimage,
                     remote_htlc_sig=signature_for_output_remote_htlc_0,
                     ref_tx=output_htlc_success_tx_0,
                     success=True, cltv_timeout=0)
        test_htlc_tx(htlc=htlc1, htlc_output_index=2,
                     amount_msat=htlc1_msat,
                     ref_local_sig=local_signature_htlc1,
                     htlc_payment_preimage=htlc1_payment_preimage,
                     remote_htlc_sig=signature_for_output_remote_htlc_1,
                     ref_tx=output_htlc_success_tx_1,
                     success=True, cltv_timeout=0)
        test_htlc_tx(htlc=htlc2,  htlc_output_index=1,
                     amount_msat=htlc2_msat,
                     ref_local_sig=local_signature_htlc2,
                     htlc_payment_preimage=htlc2_payment_preimage,
                     remote_htlc_sig=signature_for_output_remote_htlc_2,
                     ref_tx=output_htlc_timeout_tx_2,
                     success=False, cltv_timeout=htlc2_cltv_timeout)
        test_htlc_tx(htlc=htlc3,  htlc_output_index=3,
                     amount_msat=htlc3_msat,
                     ref_local_sig=local_signature_htlc3,
                     htlc_payment_preimage=htlc3_payment_preimage,
                     remote_htlc_sig=signature_for_output_remote_htlc_3,
                     ref_tx=output_htlc_timeout_tx_3,
                     success=False, cltv_timeout=htlc3_cltv_timeout)
        test_htlc_tx(htlc=htlc4,  htlc_output_index=4,
                     amount_msat=htlc4_msat,
                     ref_local_sig=local_signature_htlc4,
                     htlc_payment_preimage=htlc4_payment_preimage,
                     remote_htlc_sig=signature_for_output_remote_htlc_4,
                     ref_tx=output_htlc_success_tx_4,
                     success=True, cltv_timeout=0)

    def test_find_path_for_payment(self):
        p = Peer('', 0, 'a', bitcoin.sha256('privkeyseed'))
        p.on_channel_announcement({'node_id_1': 'b', 'node_id_2': 'c', 'short_channel_id': bfh('0000000000000001')})
        p.on_channel_announcement({'node_id_1': 'b', 'node_id_2': 'e', 'short_channel_id': bfh('0000000000000002')})
        p.on_channel_announcement({'node_id_1': 'b', 'node_id_2': 'a', 'short_channel_id': bfh('0000000000000003')})
        p.on_channel_announcement({'node_id_1': 'd', 'node_id_2': 'c', 'short_channel_id': bfh('0000000000000004')})
        p.on_channel_announcement({'node_id_1': 'e', 'node_id_2': 'd', 'short_channel_id': bfh('0000000000000005')})
        p.on_channel_announcement({'node_id_1': 'a', 'node_id_2': 'd', 'short_channel_id': bfh('0000000000000006')})
        p.on_channel_update({'short_channel_id': bfh('0000000000000001'), 'flags': b'0', 'cltv_expiry_delta': 10, 'htlc_minimum_msat': 250, 'fee_base_msat': 100, 'fee_proportional_millionths': 150})
        p.on_channel_update({'short_channel_id': bfh('0000000000000001'), 'flags': b'1', 'cltv_expiry_delta': 10, 'htlc_minimum_msat': 250, 'fee_base_msat': 100, 'fee_proportional_millionths': 150})
        p.on_channel_update({'short_channel_id': bfh('0000000000000002'), 'flags': b'0', 'cltv_expiry_delta': 99, 'htlc_minimum_msat': 250, 'fee_base_msat': 100, 'fee_proportional_millionths': 150})
        p.on_channel_update({'short_channel_id': bfh('0000000000000002'), 'flags': b'1', 'cltv_expiry_delta': 10, 'htlc_minimum_msat': 250, 'fee_base_msat': 100, 'fee_proportional_millionths': 150})
        p.on_channel_update({'short_channel_id': bfh('0000000000000003'), 'flags': b'0', 'cltv_expiry_delta': 10, 'htlc_minimum_msat': 250, 'fee_base_msat': 100, 'fee_proportional_millionths': 150})
        p.on_channel_update({'short_channel_id': bfh('0000000000000003'), 'flags': b'1', 'cltv_expiry_delta': 10, 'htlc_minimum_msat': 250, 'fee_base_msat': 100, 'fee_proportional_millionths': 150})
        p.on_channel_update({'short_channel_id': bfh('0000000000000004'), 'flags': b'0', 'cltv_expiry_delta': 10, 'htlc_minimum_msat': 250, 'fee_base_msat': 100, 'fee_proportional_millionths': 150})
        p.on_channel_update({'short_channel_id': bfh('0000000000000004'), 'flags': b'1', 'cltv_expiry_delta': 10, 'htlc_minimum_msat': 250, 'fee_base_msat': 100, 'fee_proportional_millionths': 150})
        p.on_channel_update({'short_channel_id': bfh('0000000000000005'), 'flags': b'0', 'cltv_expiry_delta': 10, 'htlc_minimum_msat': 250, 'fee_base_msat': 100, 'fee_proportional_millionths': 150})
        p.on_channel_update({'short_channel_id': bfh('0000000000000005'), 'flags': b'1', 'cltv_expiry_delta': 10, 'htlc_minimum_msat': 250, 'fee_base_msat': 100, 'fee_proportional_millionths': 999})
        p.on_channel_update({'short_channel_id': bfh('0000000000000006'), 'flags': b'0', 'cltv_expiry_delta': 10, 'htlc_minimum_msat': 250, 'fee_base_msat': 100, 'fee_proportional_millionths': 99999999})
        p.on_channel_update({'short_channel_id': bfh('0000000000000006'), 'flags': b'1', 'cltv_expiry_delta': 10, 'htlc_minimum_msat': 250, 'fee_base_msat': 100, 'fee_proportional_millionths': 150})
        print(p.path_finder.find_path_for_payment('a', 'e', 100000))

    def test_key_derivation(self):
        # BOLT3, Appendix E
        base_secret = 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
        per_commitment_secret = 0x1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100
        revocation_basepoint_secret = 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
        base_point = secret_to_pubkey(base_secret)
        self.assertEqual(base_point, bfh('036d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2'))
        per_commitment_point = secret_to_pubkey(per_commitment_secret)
        self.assertEqual(per_commitment_point, bfh('025f7117a78150fe2ef97db7cfc83bd57b2e2c0d0dd25eaf467a4a1c2a45ce1486'))
        localpubkey = derive_pubkey(base_point, per_commitment_point)
        self.assertEqual(localpubkey, bfh('0235f2dbfaa89b57ec7b055afe29849ef7ddfeb1cefdb9ebdc43f5494984db29e5'))
        localprivkey = derive_privkey(base_secret, per_commitment_point)
        self.assertEqual(localprivkey, 0xcbced912d3b21bf196a766651e436aff192362621ce317704ea2f75d87e7be0f)
        revocation_basepoint = secret_to_pubkey(revocation_basepoint_secret)
        self.assertEqual(revocation_basepoint, bfh('036d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2'))
        revocationpubkey = derive_blinded_pubkey(revocation_basepoint, per_commitment_point)
        self.assertEqual(revocationpubkey, bfh('02916e326636d19c33f13e8c0c3a03dd157f332f3e99c317c141dd865eb01f8ff0'))

    def test_per_commitment_secret_from_seed(self):
        self.assertEqual(0x02a40c85b6f28da08dfdbe0926c53fab2de6d28c10301f8f7c4073d5e42e3148.to_bytes(byteorder="big", length=32),
                         get_per_commitment_secret_from_seed(0x0000000000000000000000000000000000000000000000000000000000000000.to_bytes(byteorder="big", length=32), 281474976710655))
        self.assertEqual(0x7cc854b54e3e0dcdb010d7a3fee464a9687be6e8db3be6854c475621e007a5dc.to_bytes(byteorder="big", length=32),
                         get_per_commitment_secret_from_seed(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF.to_bytes(byteorder="big", length=32), 281474976710655))
        self.assertEqual(0x56f4008fb007ca9acf0e15b054d5c9fd12ee06cea347914ddbaed70d1c13a528.to_bytes(byteorder="big", length=32),
                         get_per_commitment_secret_from_seed(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF.to_bytes(byteorder="big", length=32), 0xaaaaaaaaaaa))
        self.assertEqual(0x9015daaeb06dba4ccc05b91b2f73bd54405f2be9f217fbacd3c5ac2e62327d31.to_bytes(byteorder="big", length=32),
                         get_per_commitment_secret_from_seed(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF.to_bytes(byteorder="big", length=32), 0x555555555555))
        self.assertEqual(0x915c75942a26bb3a433a8ce2cb0427c29ec6c1775cfc78328b57f6ba7bfeaa9c.to_bytes(byteorder="big", length=32),
                         get_per_commitment_secret_from_seed(0x0101010101010101010101010101010101010101010101010101010101010101.to_bytes(byteorder="big", length=32), 1))

    def test_new_onion_packet(self):
        # test vector from bolt-04
        payment_path_pubkeys = [
            bfh('02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619'),
            bfh('0324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c'),
            bfh('027f31ebc5462c1fdce1b737ecff52d37d75dea43ce11c74d25aa297165faa2007'),
            bfh('032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991'),
            bfh('02edabbd16b41c8371b92ef2f04c1185b4f03b6dcd52ba9b78d9d7c89c8f221145'),
        ]
        session_key = bfh('4141414141414141414141414141414141414141414141414141414141414141')
        associated_data = bfh('4242424242424242424242424242424242424242424242424242424242424242')
        hops_data = [
            OnionHopsDataSingle(OnionPerHop(
                bfh('0000000000000000'), bfh('0000000000000000'), bfh('00000000')
            )),
            OnionHopsDataSingle(OnionPerHop(
                bfh('0101010101010101'), bfh('0000000000000001'), bfh('00000001')
            )),
            OnionHopsDataSingle(OnionPerHop(
                bfh('0202020202020202'), bfh('0000000000000002'), bfh('00000002')
            )),
            OnionHopsDataSingle(OnionPerHop(
                bfh('0303030303030303'), bfh('0000000000000003'), bfh('00000003')
            )),
            OnionHopsDataSingle(OnionPerHop(
                bfh('0404040404040404'), bfh('0000000000000004'), bfh('00000004')
            )),
        ]
        packet = new_onion_packet(payment_path_pubkeys, session_key, hops_data, associated_data)
        self.assertEqual(bfh('0002eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619e5f14350c2a76fc232b5e46d421e9615471ab9e0bc887beff8c95fdb878f7b3a71da571226458c510bbadd1276f045c21c520a07d35da256ef75b4367962437b0dd10f7d61ab590531cf08000178a333a347f8b4072e216400406bdf3bf038659793a86cae5f52d32f3438527b47a1cfc54285a8afec3a4c9f3323db0c946f5d4cb2ce721caad69320c3a469a202f3e468c67eaf7a7cda226d0fd32f7b48084dca885d15222e60826d5d971f64172d98e0760154400958f00e86697aa1aa9d41bee8119a1ec866abe044a9ad635778ba61fc0776dc832b39451bd5d35072d2269cf9b040d6ba38b54ec35f81d7fc67678c3be47274f3c4cc472aff005c3469eb3bc140769ed4c7f0218ff8c6c7dd7221d189c65b3b9aaa71a01484b122846c7c7b57e02e679ea8469b70e14fe4f70fee4d87b910cf144be6fe48eef24da475c0b0bcc6565ae82cd3f4e3b24c76eaa5616c6111343306ab35c1fe5ca4a77c0e314ed7dba39d6f1e0de791719c241a939cc493bea2bae1c1e932679ea94d29084278513c77b899cc98059d06a27d171b0dbdf6bee13ddc4fc17a0c4d2827d488436b57baa167544138ca2e64a11b43ac8a06cd0c2fba2d4d900ed2d9205305e2d7383cc98dacb078133de5f6fb6bed2ef26ba92cea28aafc3b9948dd9ae5559e8bd6920b8cea462aa445ca6a95e0e7ba52961b181c79e73bd581821df2b10173727a810c92b83b5ba4a0403eb710d2ca10689a35bec6c3a708e9e92f7d78ff3c5d9989574b00c6736f84c199256e76e19e78f0c98a9d580b4a658c84fc8f2096c2fbea8f5f8c59d0fdacb3be2802ef802abbecb3aba4acaac69a0e965abd8981e9896b1f6ef9d60f7a164b371af869fd0e48073742825e9434fc54da837e120266d53302954843538ea7c6c3dbfb4ff3b2fdbe244437f2a153ccf7bdb4c92aa08102d4f3cff2ae5ef86fab4653595e6a5837fa2f3e29f27a9cde5966843fb847a4a61f1e76c281fe8bb2b0a181d096100db5a1a5ce7a910238251a43ca556712eaadea167fb4d7d75825e440f3ecd782036d7574df8bceacb397abefc5f5254d2722215c53ff54af8299aaaad642c6d72a14d27882d9bbd539e1cc7a527526ba89b8c037ad09120e98ab042d3e8652b31ae0e478516bfaf88efca9f3676ffe99d2819dcaeb7610a626695f53117665d267d3f7abebd6bbd6733f645c72c389f03855bdf1e4b8075b516569b118233a0f0971d24b83113c0b096f5216a207ca99a7cddc81c130923fe3d91e7508c9ac5f2e914ff5dccab9e558566fa14efb34ac98d878580814b94b73acbfde9072f30b881f7f0fff42d4045d1ace6322d86a97d164aa84d93a60498065cc7c20e636f5862dc81531a88c60305a2e59a985be327a6902e4bed986dbf4a0b50c217af0ea7fdf9ab37f9ea1a1aaa72f54cf40154ea9b269f1a7c09f9f43245109431a175d50e2db0132337baa0ef97eed0fcf20489da36b79a1172faccc2f7ded7c60e00694282d93359c4682135642bc81f433574aa8ef0c97b4ade7ca372c5ffc23c7eddd839bab4e0f14d6df15c9dbeab176bec8b5701cf054eb3072f6dadc98f88819042bf10c407516ee58bce33fbe3b3d86a54255e577db4598e30a135361528c101683a5fcde7e8ba53f3456254be8f45fe3a56120ae96ea3773631fcb3873aa3abd91bcff00bd38bd43697a2e789e00da6077482e7b1b1a677b5afae4c54e6cbdf7377b694eb7d7a5b913476a5be923322d3de06060fd5e819635232a2cf4f0731da13b8546d1d6d4f8d75b9fce6c2341a71b0ea6f780df54bfdb0dd5cd9855179f602f917265f21f9190c70217774a6fbaaa7d63ad64199f4664813b955cff954949076dcf'),
                         packet.to_bytes())

    def test_process_onion_packet(self):
        # this test is not from bolt-04, but is based on the one there;
        # except here we have the privkeys for these pubkeys
        payment_path_pubkeys = [
            bfh('03d75c0ee70f68d73d7d13aeb6261d8ace11416800860c7e59407afe4e2e2d42bb'),
            bfh('03960a0b830c7b8e76de745b819f252c62508346196b916f5e813cdb0773283cce'),
            bfh('0385620e0a571cbc3552620f8bf1bdcdab2d1a4a59c36fa10b8249114ccbdda40d'),
            bfh('02ee242cf6c38b7285f0152c33804ff777f5c51fd352ca8132e845e2cf23b3d8ba'),
            bfh('025c585fd2e174bf8245b2b4a119e52a417688904228643ea3edaa1728bf2a258e'),
        ]
        payment_path_privkeys = [
            bfh('3463a278617b3dd83f79bda7f97673f12609c54386e1f0d2b67b1c6354fda14e'),
            bfh('7e1255fddb52db1729fc3ceb21a46f95b8d9fe94cc83425e936a6c5223bb679d'),
            bfh('c7ce8c1462c311eec24dff9e2532ac6241e50ae57e7d1833af21942136972f23'),
            bfh('3d885f374d79a5e777459b083f7818cdc9493e5c4994ac9c7b843de8b70be661'),
            bfh('dd72ab44729527b7942e195e7a835e7c71f9c0ff61844eb21274d9c26166a8f8'),
        ]
        session_key = bfh('4141414141414141414141414141414141414141414141414141414141414141')
        associated_data = bfh('4242424242424242424242424242424242424242424242424242424242424242')
        hops_data = [
            OnionHopsDataSingle(OnionPerHop(
                bfh('0000000000000000'), bfh('0000000000000000'), bfh('00000000')
            )),
            OnionHopsDataSingle(OnionPerHop(
                bfh('0101010101010101'), bfh('0000000000000001'), bfh('00000001')
            )),
            OnionHopsDataSingle(OnionPerHop(
                bfh('0202020202020202'), bfh('0000000000000002'), bfh('00000002')
            )),
            OnionHopsDataSingle(OnionPerHop(
                bfh('0303030303030303'), bfh('0000000000000003'), bfh('00000003')
            )),
            OnionHopsDataSingle(OnionPerHop(
                bfh('0404040404040404'), bfh('0000000000000004'), bfh('00000004')
            )),
        ]
        packet = new_onion_packet(payment_path_pubkeys, session_key, hops_data, associated_data)
        self.assertEqual(bfh('0002eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f28368661954176cd9869da33d713aa219fcef1e5c806fef11e696bcc66844de8271c27974a0fd57c2dbcb2c6dd4e8ef35d96db28d5a0e49b6ab3d6de31af65950723b8cddc108390bebf8d149002e31bdc283056477ba27c8054c248ad7306de31663a7c99ec659da15d0f6fbc7e1687485b39e9be0ec3b70164cb3618a9b546317e7c2d62ae9f0f840704535729262d30c6132d1b390f073edec8fa057176c6268b6ad06a82ff0d16d4c662194873e8b4ecf46eb2c9d4d58d2ee2021adb19840605ac5afd8bd942dd71e8244c83e28b2ed5a3b09e9e7df5c8c747e5765ba366a4f7407a6c6b0a32f74bc5e428f7fa4c3cf70e13ed91563177d94190d5149aa4b9c96d00e40d2ac35ab9c4a621ce0f6f5df7d64a9c8d435db19de192d9db522c7f7b4e201fc1b61a9bd3efd062ae24455d463818b01e2756c7d0691bc3ac4c017be34c9a8b2913bb1b937e31e0ae40f650a7cd820bcb4996825b1cbad1ff7ccc2b513b1104524c34f6573e1b59201c005a632ee5dccd3711a32e3ba1ff00fcffbe636e4b3a84bbe491b836a57ccec138b8cc2ec733846904d872f305d538d51db8e56232ec6e07877075328874cb7b09c7e799100a9ff085dead253886b174fc408a0ea7b48bce2c5d8992285011960af088f7e006ef60089d46ac9aa15acfac6c87c3cf6904764dd785419292fbafa9cca09c8ade24a6cd63f12d1cfc83fa35cf2f1cf503c39cbf78293f06c68a3cece7177169cd872bb49bf69d933a27a887dd9daefa9239fca9f0c3e309ec61d9df947211da98cf11a6e0fb77252629cdf9f2226dd69ca73fa51be4df224592f8d471b69a1aebbdaa2f3a798b3581253d97feb0a12e6606043ca0fc5efc0f49b8061d6796eff31cd8638499e2f25ffb96eec32837438ed7ebebbe587886648f63e35d80f41869f4c308f2e6970bd65fead5e8544e3239a6acc9d996b08d1546455bcafbe88ed3ed547714841946fe2e77180e4d7bf1452414e4b1745a7897184a2c4cbc3ac46f83342a55a48e29dc8f17cf595dd28f51e297ba89fd25ed0dbd1c0081a810beaab09758a36fbfd16fbdc3daa9fe05c8a73195f244ef2743a5df761f01ee6e693eb6c7f1a7834fab3671391e5ddebf611e119a2ae4456e2cee7a6d4f27a2246cdb1f8ef35f0b3d7044b3799d8d0ed0a6470557fd807c065d6d83acba07e96e10770ada8c0b4d4921522944188d5f30086a6ee0a4795331273f32beaaa43363fc58208a257e5c5c434c7325b583642219d81c7d67b908d5263b42ac1991edc69a777da60f38eff138c844af9e549374e8b29b166211bfded24587a29394e33828b784da7e7b62ab7e49ea2693fcdd17fa96186a5ef11ef1a8adffa50f93a3119e95e6c09014f3e3b0709183fa08a826ced6deb4608b7d986ebbcf99ad58e25451d4d9d38d0059734d8501467b97182cd11e0c07c91ca50f61cc31255a3147ade654976a5989097281892aafd8df595c63bd14f1e03f5955a9398d2dd6368bbcae833ae1cc2df31eb0980b4817dfd130020ffb275743fcc01df40e3ecda1c5988e8e1bde965353b0b1bf34ea05f095000c45b6249618d275905a24d3eb58c600aeab4fb552fbf1ccdb2a5c80ace220310f89829d7e53f78c126037b6d8d500220c7a118d9621b4d6bd5379edd7e24bcf540e87aba6b88862db16fa4ee00b009fda80577be67ab94910fd8a7807dfe4ebe66b8fdcd040aa2dc17ec22639298be56b2a2c9d8940647b75f2f6d81746df16e1cb2f05e23397a8c63baea0803441ff4b7d517ff172980a056726235e2f6af85e8aa9b91ba85f14532272d6170df3166b91169dc09d4f4a251610f57ff0885a93364cfaf650bdf436c89795efed5ca934bc7ffc0a4'),
                         packet.to_bytes())
        for i, privkey in enumerate(payment_path_privkeys):
            processed_packet = lnbase.process_onion_packet(packet, associated_data, privkey)
            self.assertEqual(hops_data[i].per_hop.to_bytes(), processed_packet.hop_data.per_hop.to_bytes())
            packet = processed_packet.next_packet

    def test_shachain_store(self):
        tests = [
            {
                "name": "insert_secret correct sequence",
                "inserts": [
                    {
                        "index": 281474976710655,
                        "secret": "7cc854b54e3e0dcdb010d7a3fee464a9687b" +\
                            "e6e8db3be6854c475621e007a5dc",
                        "successful": True
                    },
                    {
                        "index": 281474976710654,
                        "secret": "c7518c8ae4660ed02894df8976fa1a3659c1" +\
                            "a8b4b5bec0c4b872abeba4cb8964",
                        "successful": True
                    },
                    {
                        "index": 281474976710653,
                        "secret": "2273e227a5b7449b6e70f1fb4652864038b1" +\
                            "cbf9cd7c043a7d6456b7fc275ad8",
                        "successful": True
                    },
                    {
                        "index": 281474976710652,
                        "secret": "27cddaa5624534cb6cb9d7da077cf2b22ab2" +\
                            "1e9b506fd4998a51d54502e99116",
                        "successful": True
                    },
                    {
                        "index": 281474976710651,
                        "secret": "c65716add7aa98ba7acb236352d665cab173" +\
                            "45fe45b55fb879ff80e6bd0c41dd",
                        "successful": True
                    },
                    {
                        "index": 281474976710650,
                        "secret": "969660042a28f32d9be17344e09374b37996" +\
                            "2d03db1574df5a8a5a47e19ce3f2",
                        "successful": True
                    },
                    {
                        "index": 281474976710649,
                        "secret": "a5a64476122ca0925fb344bdc1854c1c0a59" +\
                            "fc614298e50a33e331980a220f32",
                        "successful": True
                    },
                    {
                        "index": 281474976710648,
                        "secret": "05cde6323d949933f7f7b78776bcc1ea6d9b" +\
                            "31447732e3802e1f7ac44b650e17",
                        "successful": True
                    }
                ]
            },
            {
                "name": "insert_secret #1 incorrect",
                "inserts": [
                    {
                        "index": 281474976710655,
                        "secret": "02a40c85b6f28da08dfdbe0926c53fab2d" +\
                            "e6d28c10301f8f7c4073d5e42e3148",
                        "successful": True
                    },
                    {
                        "index": 281474976710654,
                        "secret": "c7518c8ae4660ed02894df8976fa1a3659" +\
                            "c1a8b4b5bec0c4b872abeba4cb8964",
                        "successful": False
                    }
                ]
            },
            {
                "name": "insert_secret #2 incorrect (#1 derived from incorrect)",
                "inserts": [
                    {
                        "index": 281474976710655,
                        "secret": "02a40c85b6f28da08dfdbe0926c53fab2de6" +\
                            "d28c10301f8f7c4073d5e42e3148",
                        "successful": True
                    },
                    {
                        "index": 281474976710654,
                        "secret": "dddc3a8d14fddf2b68fa8c7fbad274827493" +\
                            "7479dd0f8930d5ebb4ab6bd866a3",
                        "successful": True
                    },
                    {
                        "index": 281474976710653,
                        "secret": "2273e227a5b7449b6e70f1fb4652864038b1" +\
                            "cbf9cd7c043a7d6456b7fc275ad8",
                        "successful": True
                    },
                    {
                        "index": 281474976710652,
                        "secret": "27cddaa5624534cb6cb9d7da077cf2b22a" +\
                            "b21e9b506fd4998a51d54502e99116",
                        "successful": False
                    }
                ]
            },
            {
                "name": "insert_secret #3 incorrect",
                "inserts": [
                    {
                        "index": 281474976710655,
                        "secret": "7cc854b54e3e0dcdb010d7a3fee464a9687b" +\
                            "e6e8db3be6854c475621e007a5dc",
                        "successful": True
                    },
                    {
                        "index": 281474976710654,
                        "secret": "c7518c8ae4660ed02894df8976fa1a3659c1" +\
                            "a8b4b5bec0c4b872abeba4cb8964",
                        "successful": True
                    },
                    {
                        "index": 281474976710653,
                        "secret": "c51a18b13e8527e579ec56365482c62f180b" +\
                            "7d5760b46e9477dae59e87ed423a",
                        "successful": True
                    },
                    {
                        "index": 281474976710652,
                        "secret": "27cddaa5624534cb6cb9d7da077cf2b22ab2" +\
                            "1e9b506fd4998a51d54502e99116",
                        "successful": False
                    }
                ]
            },
            {
                "name": "insert_secret #4 incorrect (1,2,3 derived from incorrect)",
                "inserts": [
                    {
                        "index": 281474976710655,
                        "secret": "02a40c85b6f28da08dfdbe0926c53fab2de6" +\
                            "d28c10301f8f7c4073d5e42e3148",
                        "successful": True
                    },
                    {
                        "index": 281474976710654,
                        "secret": "dddc3a8d14fddf2b68fa8c7fbad274827493" +\
                            "7479dd0f8930d5ebb4ab6bd866a3",
                        "successful": True
                    },
                    {
                        "index": 281474976710653,
                        "secret": "c51a18b13e8527e579ec56365482c62f18" +\
                            "0b7d5760b46e9477dae59e87ed423a",
                        "successful": True
                    },
                    {
                        "index": 281474976710652,
                        "secret": "ba65d7b0ef55a3ba300d4e87af29868f39" +\
                            "4f8f138d78a7011669c79b37b936f4",
                        "successful": True
                    },
                    {
                        "index": 281474976710651,
                        "secret": "c65716add7aa98ba7acb236352d665cab1" +\
                            "7345fe45b55fb879ff80e6bd0c41dd",
                        "successful": True
                    },
                    {
                        "index": 281474976710650,
                        "secret": "969660042a28f32d9be17344e09374b379" +\
                            "962d03db1574df5a8a5a47e19ce3f2",
                        "successful": True
                    },
                    {
                        "index": 281474976710649,
                        "secret": "a5a64476122ca0925fb344bdc1854c1c0a" +\
                            "59fc614298e50a33e331980a220f32",
                        "successful": True
                    },
                    {
                        "index": 281474976710649,
                        "secret": "05cde6323d949933f7f7b78776bcc1ea6d9b" +\
                            "31447732e3802e1f7ac44b650e17",
                        "successful": False
                    }
                ]
            },
            {
                "name": "insert_secret #5 incorrect",
                "inserts": [
                    {
                        "index": 281474976710655,
                        "secret": "7cc854b54e3e0dcdb010d7a3fee464a9687b" +\
                            "e6e8db3be6854c475621e007a5dc",
                        "successful": True
                    },
                    {
                        "index": 281474976710654,
                        "secret": "c7518c8ae4660ed02894df8976fa1a3659c1a" +\
                            "8b4b5bec0c4b872abeba4cb8964",
                        "successful": True
                    },
                    {
                        "index": 281474976710653,
                        "secret": "2273e227a5b7449b6e70f1fb4652864038b1" +\
                            "cbf9cd7c043a7d6456b7fc275ad8",
                        "successful": True
                    },
                    {
                        "index": 281474976710652,
                        "secret": "27cddaa5624534cb6cb9d7da077cf2b22ab21" +\
                            "e9b506fd4998a51d54502e99116",
                        "successful": True
                    },
                    {
                        "index": 281474976710651,
                        "secret": "631373ad5f9ef654bb3dade742d09504c567" +\
                            "edd24320d2fcd68e3cc47e2ff6a6",
                        "successful": True
                    },
                    {
                        "index": 281474976710650,
                        "secret": "969660042a28f32d9be17344e09374b37996" +\
                            "2d03db1574df5a8a5a47e19ce3f2",
                        "successful": False
                    }
                ]
            },
            {
                "name": "insert_secret #6 incorrect (5 derived from incorrect)",
                "inserts": [
                    {
                        "index": 281474976710655,
                        "secret": "7cc854b54e3e0dcdb010d7a3fee464a9687b" +\
                            "e6e8db3be6854c475621e007a5dc",
                        "successful": True
                    },
                    {
                        "index": 281474976710654,
                        "secret": "c7518c8ae4660ed02894df8976fa1a3659c1a" +\
                            "8b4b5bec0c4b872abeba4cb8964",
                        "successful": True
                    },
                    {
                        "index": 281474976710653,
                        "secret": "2273e227a5b7449b6e70f1fb4652864038b1" +\
                            "cbf9cd7c043a7d6456b7fc275ad8",
                        "successful": True
                    },
                    {
                        "index": 281474976710652,
                        "secret": "27cddaa5624534cb6cb9d7da077cf2b22ab21" +\
                            "e9b506fd4998a51d54502e99116",
                        "successful": True
                    },
                    {
                        "index": 281474976710651,
                        "secret": "631373ad5f9ef654bb3dade742d09504c567" +\
                            "edd24320d2fcd68e3cc47e2ff6a6",
                        "successful": True
                    },
                    {
                        "index": 281474976710650,
                        "secret": "b7e76a83668bde38b373970155c868a65330" +\
                            "4308f9896692f904a23731224bb1",
                        "successful": True
                    },
                    {
                        "index": 281474976710649,
                        "secret": "a5a64476122ca0925fb344bdc1854c1c0a59f" +\
                            "c614298e50a33e331980a220f32",
                        "successful": True
                    },
                    {
                        "index": 281474976710648,
                        "secret": "05cde6323d949933f7f7b78776bcc1ea6d9b" +\
                            "31447732e3802e1f7ac44b650e17",
                        "successful": False
                    }
                ]
            },
            {
                "name": "insert_secret #7 incorrect",
                "inserts": [
                    {
                        "index": 281474976710655,
                        "secret": "7cc854b54e3e0dcdb010d7a3fee464a9687b" +\
                            "e6e8db3be6854c475621e007a5dc",
                        "successful": True
                    },
                    {
                        "index": 281474976710654,
                        "secret": "c7518c8ae4660ed02894df8976fa1a3659c1a" +\
                            "8b4b5bec0c4b872abeba4cb8964",
                        "successful": True
                    },
                    {
                        "index": 281474976710653,
                        "secret": "2273e227a5b7449b6e70f1fb4652864038b1" +\
                            "cbf9cd7c043a7d6456b7fc275ad8",
                        "successful": True
                    },
                    {
                        "index": 281474976710652,
                        "secret": "27cddaa5624534cb6cb9d7da077cf2b22ab21" +\
                            "e9b506fd4998a51d54502e99116",
                        "successful": True
                    },
                    {
                        "index": 281474976710651,
                        "secret": "c65716add7aa98ba7acb236352d665cab173" +\
                            "45fe45b55fb879ff80e6bd0c41dd",
                        "successful": True
                    },
                    {
                        "index": 281474976710650,
                        "secret": "969660042a28f32d9be17344e09374b37996" +\
                            "2d03db1574df5a8a5a47e19ce3f2",
                        "successful": True
                    },
                    {
                        "index": 281474976710649,
                        "secret": "e7971de736e01da8ed58b94c2fc216cb1d" +\
                            "ca9e326f3a96e7194fe8ea8af6c0a3",
                        "successful": True
                    },
                    {
                        "index": 281474976710648,
                        "secret": "05cde6323d949933f7f7b78776bcc1ea6d" +\
                            "9b31447732e3802e1f7ac44b650e17",
                        "successful": False
                    }
                ]
            },
            {
                "name": "insert_secret #8 incorrect",
                "inserts": [
                    {
                        "index": 281474976710655,
                        "secret": "7cc854b54e3e0dcdb010d7a3fee464a9687b" +\
                            "e6e8db3be6854c475621e007a5dc",
                        "successful": True
                    },
                    {
                        "index": 281474976710654,
                        "secret": "c7518c8ae4660ed02894df8976fa1a3659c1a" +\
                            "8b4b5bec0c4b872abeba4cb8964",
                        "successful": True
                    },
                    {
                        "index": 281474976710653,
                        "secret": "2273e227a5b7449b6e70f1fb4652864038b1" +\
                            "cbf9cd7c043a7d6456b7fc275ad8",
                        "successful": True
                    },
                    {
                        "index": 281474976710652,
                        "secret": "27cddaa5624534cb6cb9d7da077cf2b22ab21" +\
                            "e9b506fd4998a51d54502e99116",
                        "successful": True
                    },
                    {
                        "index": 281474976710651,
                        "secret": "c65716add7aa98ba7acb236352d665cab173" +\
                            "45fe45b55fb879ff80e6bd0c41dd",
                        "successful": True
                    },
                    {
                        "index": 281474976710650,
                        "secret": "969660042a28f32d9be17344e09374b37996" +\
                            "2d03db1574df5a8a5a47e19ce3f2",
                        "successful": True
                    },
                    {
                        "index": 281474976710649,
                        "secret": "a5a64476122ca0925fb344bdc1854c1c0a" +\
                            "59fc614298e50a33e331980a220f32",
                        "successful": True
                    },
                    {
                        "index": 281474976710648,
                        "secret": "a7efbc61aac46d34f77778bac22c8a20c6" +\
                            "a46ca460addc49009bda875ec88fa4",
                        "successful": False
                    }
                ]
            }
        ]

        for test in tests:
            receiver = RevocationStore()
            for insert in test["inserts"]:
                secret = bytes.fromhex(insert["secret"])

                try:
                    receiver.add_next_entry(secret)
                except Exception as e:
                    if insert["successful"]:
                        raise Exception("Failed ({}): error was received but it shouldn't: {}".format(test["name"], e))
                else:
                    if not insert["successful"]:
                        raise Exception("Failed ({}): error wasn't received".format(test["name"]))

            print("Passed ({})".format(test["name"]))

    def test_shachain_produce_consume(self):
        seed = bitcoin.sha256(b"shachaintest")
        consumer = RevocationStore()
        for i in range(10000):
            secret = shachain_derive(ShachainElement(seed, 0), 2**48 - i - 1).secret
            try:
                consumer.add_next_entry(secret)
            except Exception as e:
                raise Exception("iteration " + str(i) + ": " + str(e))
