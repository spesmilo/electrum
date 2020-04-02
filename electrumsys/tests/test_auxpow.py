from electrumsys import auxpow, blockchain, constants
from electrumsys.util import bfh, bh2u

from . import SequentialTestCase
from . import TestCaseForTestnet
from . import FAST_TESTS

namecoin_header_19204 = '01000100f65a247291f5ee322a1ff3f22c3fdb0f60d15707a9842db5e0fa332f5dd8d6071d7bc906ea494a8aa32fdde281fe26a84befefaddaf0dcd41dd2da3053bcd5450635904e69b2001b29f30bc9'

namecoin_header_19414 = '010101006100f86b5cc8089123e8c3eed1d5408661b97a9acc4da490aba5fa343b9e978b5831f525a853513807f9fd2e2704cb22960e626f29ade2399adc91e4d49af0cefe2d934e69b2001b0000000001000000010000000000000000000000000000000000000000000000000000000000000000ffffffff3907456c6967697573032f65012c4d4d3d3d5fb89c3b18c27bc38d351d516177cbd3504c95ca0494cbbbbd52f2fb5f2ff1ec0100000000000000ffffffff340100000000000000434104f3726baa8091a14d31dcd3749c7f0a63d0b61270072f69aec2a107ba4b68f2b034eae71aa6f3a365f5861b83c1f489fef67197df452a970d3c2faca2cb099a83acdc65d900000000001976a914672fa694c71dbc51487015cf2053b21ac5f371a288ac79bd4604000000001976a91445147ab00338133839291502266fe389be5b4b4888ac0c439404000000001976a9142fcf7d1c9670945ea5cc614219b67f823181403488acd9f5f10a000000001976a914cd907cd4eec2aa1a10896cc9e49d52eb343a4bd988acdd5a2f04000000001976a914e8ff106e7bc09d6a230e6c59438d601814e1062f88acdd11bb09000000001976a9147735208ec688d8c8cd30ae198097a21bf3e55a9c88ac22400b04000000001976a914313f5646306492ad76409c4e686ba17f6f7307a188ac29053507000000001976a914b9c34a731b497d78f878a29eff050c14426f1bcb88ac8c983804000000001976a914cd1c308cb400b4da883c694365db23d3cc94c9ca88acb3690d00000000001976a91445079084023041ac0642fd3cc5d31b8fe848981588acc5e41e04000000001976a914af652c623045da48c22e117616d8305d05982b0088ac30e6470a000000001976a91480d9db836764688c1317808e5c62fbbcaec662e788ace48ad20a000000001976a9146a50b12a735ba630509308d88b28061153b834c988acb30cbb04000000001976a9146f67318de52ca1d2082b9bf094d08b06492c435f88ac79791d05000000001976a91470d54ff105025d9b22c7a96b7d325d17631fd99788acbc73250a000000001976a914146a63cc1e6b63e33358aeae88fb3afaf4b9783e88acd88cc70b000000001976a914977038d30db5d45910c504978b2cae32c452cc0f88ac894aac06000000001976a9140e08d60695953dcc4446bebf04c8e86a6fba044b88ac10361604000000001976a9140ae2653f585cd8c4f9175b9e2385f0139535763e88acdaa10000000000001976a914ef588d372c1bf7ede570a1e38514b959902035f988ac1478ba04000000001976a9142fdc70416f2ecb42dfa9d03e46c0c3e5309866a088acfae0b30a000000001976a9141139dad1a13049a46f8fe561dc4b6ee3693785cb88ac2fae3904000000001976a914cf4870debb2bb91753a48d6474bb3568e779d90188ac68682304000000001976a91424874579edf133c19d44154aff5f5b26989dcd5588acae983604000000001976a914286c7d6a5cbdd61784d14f2283c2115411b0b0b388acfa102c04000000001976a9140de91da760129641f3dc0747a270007ec2d2e06688ac29c39704000000001976a914476e2f81fe2a2cf473bd357ad326e5ca7539cf2188ac0c878507000000001976a914bb097d8d5f6f5f8650d91ceb6a5ff0995c068c7a88acd1137104000000001976a914dada56f3d1eacb8ef36d00d4eb5bd06449759ac988ac4f237204000000001976a914dad596aa198f76150caf3c43ae0c922bf76e011788acb5e8ed09000000001976a9145ffb72262cfd9e5e11076246c4fe51655658946188ac08753a04000000001976a9141db2707b825dc79d3081e75ff53445d18a2df6ad88ac8f0b0000000000001976a9145ff6931e4f1bce9bfd37a3f0c976d5195a8e973a88ac7c22760a000000001976a9142777969c44603d882a064e693276be0b2a552b9088ac7c5d5104000000001976a91408d0de24e73fd813151ec02344d41ac0e9660e7d88ace8e0a70b000000001976a914fc31f9e640ff5aa7334fdc181bc0fb342f2fce2388acec314b06000000001976a914ec2b24ac3b6025fca946b79a16b317c575266e2588ac34d4280d000000001976a914b44ff1af7c613f6d2af30b5e31114345c783e3c388ac141d870a000000001976a9144e34245f793c687a2aa197ecd07cd35c82098c0488ac1f2b430c000000001976a914a346c220341b7f34aae308e4e38429b21f976dcc88ac31704104000000001976a914a10aeb0d9c1cb25413e65e14175f50dde148847e88ac0fe9bb04000000001976a91467cec2520fd4a12f815f6b69601a30ba95e4e1d888acf6cf9d04000000001976a91439eb449e3cdf858e054533de91c543fff76d2ae088acde3abb04000000001976a9142e62c5bdc366b30e74896527d772846fed7f463b88ac63081504000000001976a9141d71a68b2bfc1af6842744794a460a532e9112ed88ac2d7e3504000000001976a9142753bd08abbe9991dab8632d5645798aae203fcb88ac3a2de504000000001976a914ef443310486a974a02e11631590d64785a5e42e088ac12b35604000000001976a914d225030e127be48532677cb075a21584e421a40188acb39d0700000000001976a914a954a14818bcfd39358dc48999cf6a973fbed1a988ac3a762f04000000001976a9148301704b2598306633b2dccb22495e4560261ec488acc4f65504000000001976a91421d2189694170472479470e6c9b4d22cfedba22488ac00000000fab0ef6519ac3ede4ab81a892b81f622d6d7a39fe5b0a954ce30000000000000047f52d1ef8653d3f85a94566cef62624e9df0e26282da207d3cafcaf42ebdaae60db5421958e852c8317995bfafe823e71550ff4dee1cd623a4e28d37d23857abee534922e7c44c26aaa76ec0842283d0005296bc2f39f5f861fbb2a4848f089be095e6fa7cc786d6379e97ac40eb1bbbbb5b9b537c3162ccdae4b90334e6a46100000000000000000001000000c782884057fab9d47c4279e0dd45b48831b67eed216771c606070000000000006bfb72b3f23c72356557bdea5580a1a3b6378775a35c5708d620265f7bc8b212ca2e934e5dee091ae3215b05'
namecoin_prev_hash_19414 = '8b979e3b34faa5ab90a44dcc9a7ab9618640d5d1eec3e8239108c85c6bf80061'
namecoin_target_19414 = 0xb269000000000000000000000000000000000000000000000000

namecoin_header_37174 = '01010100d681bfa4acb5e0dc772a0099ce069ae4841ee2292ba731a63ac746bde66ddc8a79ad23ebbe11a144734b56d5bba0d0fb9ee68928112eb695a342e74899b3f78138950a4f4a2a241a0000000001000000010000000000000000000000000000000000000000000000000000000000000000ffffffff3907456c696769757303f8a7022cfabe6d6d2d27ea3a0cbe9d4edcecb32f6ed254b2bd017cb1f13258c9fd040b20519cbae41000000000000000ffffffff20abdd2a000000000043410400ffc6890975ea785b450af3d4d0908303969581b3bc9f2b32172312fdd0c2e0e92285856abfc6f5abf6f79572a9084cdaf1678905dc7c00b2aa24368d90454cac283ee709000000001976a9148eafb1970e427d4d6ebb213b737b7dcdc96791e988acf974b706000000001976a91432e9b63db5ade6c81433fc1f3386d2a9d61c5ca388ac31e8c406000000001976a914b8c835af5f431a5b29f02f27f34617fab43f869d88ac5c5c1905000000001976a91438eb0cfbf241ce393845eaab98b03509b1a4f4c988ac12a99406000000001976a914a9e01ae5f2e882d018ca6c9c0b62805f419f678488ac2eafeb0e000000001976a914e5673d0aaa04d7ef76cac33443c4d65f1f9d3abd88acab8c3b06000000001976a914890ee1d550411d3a56f90785f0b50d32422685e588ac2b83040e000000001976a914d6309a28ad26747380adee68c78a82afc2e380b088ac37d85708000000001976a914cac51e198e50f78b352b7543450d4adb19a1ecb588ac7024b209000000001976a9141ba5c1c3c0916014ee18f35b2c8972d974e0c2c688ac042c9e0f000000001976a9149bc7fd00183f8007edb836e54aaa43fa7093564b88ac11a3270d000000001976a914c784d5639cba9cac3ee83b8419d0df127f814dac88ac9e1a0904000000001976a914ad9d837dd996b6f09408c48fb021f47113893e1288acb2d8b804000000001976a914773e6c68a0a90c3fa8d724a8d956d391cb2e780588acfadfa30a000000001976a91465d2028ef9a711679dd0475ee8c063e03f283b9988ac2cc7de04000000001976a914634a731a7cac60d4009e02de89adeba55b9e7c6988acf4f83704000000001976a914432c607e716ce918f4025ecd34e22149a52d66ac88acd0b63904000000001976a91467cec2520fd4a12f815f6b69601a30ba95e4e1d888aceada260b000000001976a91476ea1118754fe1c7bd7e6e5a3bbf0a58bb50793e88acebc87810000000001976a9146284a45230cf59afc7014972809b33fcd697feae88ac4bd1800e000000001976a9141c0320b4b7d9f4462176b099412804a75ce1b0c288acf71ba505000000001976a914220b8d06c0954da6d4434aac55b6478b116f0d6b88ac795db109000000001976a914c3dd52845bfba22107c21501138a0c8b04a0347588ac84e7560e000000001976a9147ac2b007faf68d60460f26884f41630a0c84bb1f88acbb4ec312000000001976a91471556a3df90c4bfe9e3b0dc1d17b96bef721c15088ac5ed1c909000000001976a9142de17c20ad4acd2eb0a6113b16a296e91dbed2e088ac585e1b04000000001976a9145e141e1a4346cfdcf9059a8d53e12fe73d9fc96188ac1400ed09000000001976a9149465fdac29b5c47b99c8d17379d0fc6d99c1e4a688ac93f00f0b000000001976a914cc48bc094901e59d9f696b4d8b5c6045006bd33188ac76bbb70c000000001976a9149eb551c3924ed46408b3616242db21b7fcc7f9a288ac39186f0a000000001976a914959ccd483cd07cb7ab9c63ae088d36833e52a29388ac0000000084db572a0c547f2d33793a50525ff96d90d46ab361f57311112400000000000005e0dd9751b7164f0bd8da996fd31d1944dd28bbba422612ae65512a021473f2f8b0edec19fc4bd2b5e0df0feaf0c35b9eed377a4c17c04bb0e7de170e42dca9c82036c3370630069cc8b763dcc4dff4e8c45d4398927baae42725218eb9c5e90c3641e824664bb1f0c6011f45bdf646049f836104449a87cb47b0a522410c6d3bcb36e428be422a5de15c00b24f0352dd8fc0d9525edf1251218ba638be00854500000000040a0000000000000000000000000000000000000000000000000000000000000002837963a2278915e751bb7f197f196b39e559867e97076564a3e3c7b28ebd65e9720db28e9dc39e9b719e7bf8955c5397701fa07683b2ab05d78932b11b965f50eb6b2eb0dc8cd70c2e6d93a25b679b0cdcbd53670aa435610d1241ccfdb57c0b0000000100000055a7bc918827dbe7d8027781d803f4b418589b7b9fc03e718a03000000000000625a3d6dc4dfb0ab25f450cd202ff3bdb074f2edde1ddb4af5217e10c9dbafb9639a0a4fd7690d1a25aeaa97'
namecoin_prev_hash_37174 = '8adc6de6bd46c73aa631a72b29e21e84e49a06ce99002a77dce0b5aca4bf81d6'
namecoin_target_37174 = 0x242a4a0000000000000000000000000000000000000000000000

class Test_auxpow(SequentialTestCase):

    @staticmethod
    def deserialize_with_auxpow(data_hex: str, **kwargs):
        """Deserializes a block header given as hex string

        This makes sure that the data is always deserialised as full
        block header with AuxPoW.

        The keyword-arguments expect_trailing_data and start_position can be
        set and will be passed on to deserialize_full_header."""

        # We pass a height beyond the last checkpoint, because
        # deserialize_full_header expects checkpointed headers to be truncated
        # by ElectrumX (i.e. not contain an AuxPoW).
        return blockchain.deserialize_full_header(bfh(data_hex), constants.net.max_checkpoint() + 1, **kwargs)

    @staticmethod
    def clear_coinbase_outputs(auxpow_header: dict, fix_merkle_root=True) -> None:
        """Clears the auxpow coinbase outputs

        Set the outputs of the auxpow coinbase to an empty list.  This is
        necessary when the coinbase has been modified and needs to be
        re-serialised, since present outputs are invalid due to the
        fast_tx_deserialize optimisation."""

        auxpow_header['parent_coinbase_tx']._outputs = []

        # Clear the cached raw serialization
        auxpow_header['parent_coinbase_tx'].invalidate_ser_cache()

        # Re-serialize.  Note that our AuxPoW library won't do this for us,
        # because it optimizes via fast_txid.
        auxpow_header['parent_coinbase_tx']._cached_network_ser_bytes = bfh(auxpow_header['parent_coinbase_tx'].serialize_to_network(force_legacy=True))

        # Correct the coinbase Merkle root.
        if fix_merkle_root:
            update_merkle_root_to_match_coinbase(auxpow_header)

    # Deserialize the AuxPoW header from Namecoin block #37,174.
    # This height was chosen because it has large, non-equal lengths of the
    # coinbase and chain Merkle branches.  It has an explicit coinbase MM
    # header.
    def test_deserialize_auxpow_header_explicit_coinbase(self):
        header = self.deserialize_with_auxpow(namecoin_header_37174)
        header_auxpow = header['auxpow']

        self.assertEqual(constants.net.AUXPOW_CHAIN_ID, header_auxpow['chain_id'])

        coinbase_tx = header_auxpow['parent_coinbase_tx']
        expected_coinbase_txid = '8a3164be45a621f85318647d425fe9f45837b8e42ec4fdd902d7f64daf61ff4a'
        observed_coinbase_txid = auxpow.fast_txid(coinbase_tx)

        self.assertEqual(expected_coinbase_txid, observed_coinbase_txid)

        self.assertEqual(header_auxpow['coinbase_merkle_branch'], [
            "f8f27314022a5165ae122642babb28dd44191dd36f99dad80b4f16b75197dde0",
            "c8a9dc420e17dee7b04bc0174c7a37ed9e5bc3f0ea0fdfe0b5d24bfc19ecedb0",
            "0ce9c5b98e212527e4aa7b9298435dc4e8f4dfc4dc63b7c89c06300637c33620",
            "3b6d0c4122a5b047cb879a440461839f0446f6bd451f01c6f0b14b6624e84136",
            "458500be38a68b215112df5e52d9c08fdd52034fb2005ce15d2a42be28e436cb",
        ])

        coinbase_merkle_index = header_auxpow['coinbase_merkle_index']
        self.assertEqual(0, coinbase_merkle_index)

        self.assertEqual(header_auxpow['chain_merkle_branch'], [
            "000000000000000000000000000000000000000000000000000000000000000a",
            "65bd8eb2c7e3a3646507977e8659e5396b197f197fbb51e7158927a263798302",
            "5f961bb13289d705abb28376a01f7097535c95f87b9e719b9ec39d8eb20d72e9",
            "7cb5fdcc41120d6135a40a6753bddc0c9b675ba2936d2e0cd78cdcb02e6beb50",
        ])

        chain_merkle_index = header_auxpow['chain_merkle_index']
        self.assertEqual(11, chain_merkle_index)

        expected_parent_header = blockchain.deserialize_pure_header(bfh('0100000055a7bc918827dbe7d8027781d803f4b418589b7b9fc03e718a03000000000000625a3d6dc4dfb0ab25f450cd202ff3bdb074f2edde1ddb4af5217e10c9dbafb9639a0a4fd7690d1a25aeaa97'), None)

        expected_parent_hash = blockchain.hash_header(expected_parent_header)
        observed_parent_hash = blockchain.hash_header(header_auxpow['parent_header'])
        self.assertEqual(expected_parent_hash, observed_parent_hash)

        expected_parent_merkle_root = expected_parent_header['merkle_root']
        observed_parent_merkle_root = header_auxpow['parent_header']['merkle_root']
        self.assertEqual(expected_parent_merkle_root, observed_parent_merkle_root)

    def test_deserialize_should_reject_trailing_junk(self):
        with self.assertRaises(Exception):
            self.deserialize_with_auxpow(namecoin_header_37174 + "00")

    def test_deserialize_with_expected_trailing_data(self):
        data = "00" + namecoin_header_37174 + "00"
        _, start_position = self.deserialize_with_auxpow(data, expect_trailing_data=True, start_position=1)
        self.assertEqual(start_position, len(namecoin_header_37174)//2 + 1)

    # Verify the AuxPoW header from Namecoin block #37,174.
    def test_verify_auxpow_header_explicit_coinbase(self):
        header = self.deserialize_with_auxpow(namecoin_header_37174)
        blockchain.Blockchain.verify_header(header, namecoin_prev_hash_37174, namecoin_target_37174)

    # Verify the AuxPoW header from Namecoin block #19,414.  This header
    # doesn't have an explicit MM coinbase header.
    def test_verify_auxpow_header_implicit_coinbase(self):
        header = self.deserialize_with_auxpow(namecoin_header_19414)
        blockchain.Blockchain.verify_header(header, namecoin_prev_hash_19414, namecoin_target_19414)

    # Check that a non-generate AuxPoW transaction is rejected.
    def test_should_reject_non_generate_auxpow(self):
        header = self.deserialize_with_auxpow(namecoin_header_37174)
        header['auxpow']['coinbase_merkle_index'] = 0x01

        with self.assertRaises(auxpow.AuxPoWNotGenerateError):
            blockchain.Blockchain.verify_header(header, namecoin_prev_hash_37174, namecoin_target_37174)

    # Check that block headers from the sidechain are rejected as parent chain
    # for AuxPoW, via checking of the chain ID's.
    def test_should_reject_own_chain_id(self):
        parent_header = self.deserialize_with_auxpow(namecoin_header_19204)
        self.assertEqual(1, auxpow.get_chain_id(parent_header))

        header = self.deserialize_with_auxpow(namecoin_header_37174)
        header['auxpow']['parent_header'] = parent_header

        with self.assertRaises(auxpow.AuxPoWOwnChainIDError):
            blockchain.Blockchain.verify_header(header, namecoin_prev_hash_37174, namecoin_target_37174)

    # Check that where the chain merkle branch is far too long to use, it's
    # rejected.
    def test_should_reject_very_long_merkle_branch(self):
        header = self.deserialize_with_auxpow(namecoin_header_37174)
        header['auxpow']['chain_merkle_branch'] = list([32 * '00' for i in range(32)])

        with self.assertRaises(auxpow.AuxPoWChainMerkleTooLongError):
            blockchain.Blockchain.verify_header(header, namecoin_prev_hash_37174, namecoin_target_37174)

    # Later steps in AuxPoW validation depend on the contents of the coinbase
    # transaction. Obviously that's useless if we don't check the coinbase
    # transaction is actually part of the parent chain block, so first we test
    # that the transaction hash is part of the merkle tree. This test modifies
    # the transaction, invalidating the hash, to confirm that it's rejected.
    def test_should_reject_bad_coinbase_merkle_branch(self):
        header = self.deserialize_with_auxpow(namecoin_header_37174)

        # Clearing the outputs modifies the coinbase transaction so that its
        # hash no longer matches the parent block merkle root.
        self.clear_coinbase_outputs(header['auxpow'], fix_merkle_root=False)

        with self.assertRaises(auxpow.AuxPoWBadCoinbaseMerkleBranchError):
            blockchain.Blockchain.verify_header(header, namecoin_prev_hash_37174, namecoin_target_37174)

    # Ensure that in case of a malformed coinbase transaction (no inputs) it's
    # caught and processed neatly.
    def test_should_reject_coinbase_no_inputs(self):
        header = self.deserialize_with_auxpow(namecoin_header_37174)

        # Set inputs to an empty list
        header['auxpow']['parent_coinbase_tx']._inputs = []

        self.clear_coinbase_outputs(header['auxpow'])

        with self.assertRaises(auxpow.AuxPoWCoinbaseNoInputsError):
            blockchain.Blockchain.verify_header(header, namecoin_prev_hash_37174, namecoin_target_37174)

    # Catch the case that the coinbase transaction does not contain details of
    # the merged block. In this case we make the transaction script too short
    # for it to do so.  This test is for the code path with an implicit MM
    # coinbase header.
    def test_should_reject_coinbase_root_too_late(self):
        header = self.deserialize_with_auxpow(namecoin_header_19414)

        input_script = header['auxpow']['parent_coinbase_tx'].inputs()[0].script_sig

        padded_script = bfh('00') * (auxpow.MAX_INDEX_PC_BACKWARDS_COMPATIBILITY + 4)
        padded_script += input_script[8:]

        header['auxpow']['parent_coinbase_tx']._inputs[0].script_sig = padded_script

        self.clear_coinbase_outputs(header['auxpow'])

        with self.assertRaises(auxpow.AuxPoWCoinbaseRootTooLate):
            blockchain.Blockchain.verify_header(header, namecoin_prev_hash_19414, namecoin_target_19414)

    # Verifies that the commitment of the auxpow to the block header it is
    # proving for is actually checked.
    def test_should_reject_coinbase_root_missing(self):
        header = self.deserialize_with_auxpow(namecoin_header_19414)
        # Modify the header so that its hash no longer matches the
        # chain Merkle root in the AuxPoW.
        header["timestamp"] = 42
        with self.assertRaises(auxpow.AuxPoWCoinbaseRootMissingError):
            blockchain.Blockchain.verify_header(header, namecoin_prev_hash_19414, namecoin_target_19414)


def update_merkle_root_to_match_coinbase(auxpow_header):
    """Updates the parent block merkle root

    This modifies the merkle root in the auxpow's parent block header to
    match the auxpow coinbase transaction.  We need this after modifying
    the coinbase for tests.

    Note that this also breaks the PoW.  This is fine for tests that
    fail due to an earlier check already."""

    coinbase = auxpow_header['parent_coinbase_tx']

    revised_coinbase_txid = auxpow.fast_txid(coinbase)
    revised_merkle_branch = [revised_coinbase_txid]
    revised_merkle_root = auxpow.calculate_merkle_root(revised_coinbase_txid, revised_merkle_branch, auxpow_header['coinbase_merkle_index'])

    auxpow_header['parent_header']['merkle_root'] = revised_merkle_root
    auxpow_header['coinbase_merkle_branch'] = revised_merkle_branch
