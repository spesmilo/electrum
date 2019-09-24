import shutil
import tempfile
import os

from electrum_ltc import constants, blockchain
from electrum_ltc.simple_config import SimpleConfig
from electrum_ltc.blockchain import Blockchain, deserialize_header, hash_header
from electrum_ltc.util import bh2u, bfh, make_dir

from . import ElectrumTestCase


class TestBlockchain(ElectrumTestCase):

    HEADERS = {
        'A': deserialize_header(bfh("010000000000000000000000000000000000000000000000000000000000000000000000d9ced4ed1130f7b7faad9be25323ffafa33232a17c3edf6cfd97bee6bafbdd97dae5494dffff7f2000000000"), 0),
        'B': deserialize_header(bfh("00000020f916c456fc51df627885d7d674ed02dc88a225adb3f02ad13eb4938ff3270853186c8dfd970a4545f79916bc1d75c9d00432f57c89209bf3bb115b7612848f509c25f45bffff7f2005000000"), 1),
        'C': deserialize_header(bfh("00000020e9078937b6b92a74120d9a8876475a6e97227e59b54cf05f87e24eb8b0a7199bbf2cbf153013a1c54abaf70e95198fcef2f3059cc6b4d0f7e876808e7d24d11cc825f45bffff7f2000000000"), 2),
        'D': deserialize_header(bfh("0000002081e2f5ea4e64d6370c6334a78dc8c128bbc3388ae5be3ec434b61d19b2b26903e71019d7feecd9b8596eca9a67032c5f4641b23b5d731dc393e37de7f9c2f299e725f45bffff7f2001000000"), 3),
        'E': deserialize_header(bfh("00000020c7c8ca692fade08a253136051e07c62bb0d76af97aa47945bd28335360e91338a3586da94c71753f27c075f57f44faf913c31177a0957bbda42e7699e3a2141aed25f45bffff7f2001000000"), 4),
        'F': deserialize_header(bfh("00000020c8e83c4c4dc2a38820e8c330eda47aa84eb82722ce1e3a649b8b202501db40bc7aee1d692d1615c3bdf52c291032144ce9e3b258a473c17c745047f3431ff8e2ee25f45bffff7f2000000000"), 5),
        'O': deserialize_header(bfh("000000209acbe22912d4a4e67a39d7779f04549c724be5f8e081955cce786290081a79903a141ce635cbb1cd2b3a4fcdd0a3380517845ba41736c82a79cab535d31128066526f45bffff7f2001000000"), 6),
        'P': deserialize_header(bfh("0000002018cca0f1541812329cec7f75e7c13922a5b9976801a320b0d8174846a6285aa09690c2fe7c1a4450c74dc908fe94dd96c3b0637d51475e9e06a78e944a0c7fe28126f45bffff7f2002000000"), 7),
        'Q': deserialize_header(bfh("000000202fb59385b4e743696bffaa4cf2338202822e446db933ae456b924660d6f69b78148be228a4c3f2061bafe7efdfc4a8d5a94759464b9b5c619994d45dfcaf49e1a126f45bffff7f2002000000"), 8),
        'R': deserialize_header(bfh("00000020778597da18ab4664f4543c8b27d601aec685073ffeccfb2d7950088602a1f17a15681cb2d00ff889193f6a68a93f5096aeb2d84ca0af6185a462555822552221a626f45bffff7f2001000000"), 9),
        'S': deserialize_header(bfh("00000020f69aceedf7013f73fe9d508d1e4df9d89700e18b07a2ea1fa8fd19367a07d2af9dc087fc977b06c24a69c682d1afd1020e6dc1f087571ccec66310a786e1548fab26f45bffff7f2000000000"), 10),
        'T': deserialize_header(bfh("0000002042a4bf62d587d353871034d5128c7ef12479012586bd535d159e1d0b5d3e387f03b243756c25053253aeda309604363460a3911015929e68705bd89dff6fe064b026f45bffff7f2000000000"), 11),
        'U': deserialize_header(bfh("0000002034f706a01b82ea66aa869a887bf25bbed0dfc0f0f3840994446f1e4fd8f58f7dd67cb902a7d807cee7676cb543feec3e053aa824d5dfb528d5b94f9760313d9db726f45bffff7f2001000000"), 12),
        'G': deserialize_header(bfh("000000209acbe22912d4a4e67a39d7779f04549c724be5f8e081955cce786290081a79903a141ce635cbb1cd2b3a4fcdd0a3380517845ba41736c82a79cab535d31128066928f45bffff7f2001000000"), 6),
        'H': deserialize_header(bfh("000000205b976fbe6fccb4c67de1a081747bb888a0cb486b06d0203f76b9b3916cf46d839690c2fe7c1a4450c74dc908fe94dd96c3b0637d51475e9e06a78e944a0c7fe26a28f45bffff7f2000000000"), 7),
        'I': deserialize_header(bfh("000000206c767e525915ac216be783dbc4554ac569a121ccc4c5dac8abe521dae7eac670148be228a4c3f2061bafe7efdfc4a8d5a94759464b9b5c619994d45dfcaf49e16a28f45bffff7f2000000000"), 8),
        'J': deserialize_header(bfh("00000020bfa64ff6b96eb438d24c32f2ca27a96d8e20b23671577dce2b37b3a815e9739615681cb2d00ff889193f6a68a93f5096aeb2d84ca0af6185a462555822552221c928f45bffff7f2000000000"), 9),
        'K': deserialize_header(bfh("00000020b9e0539dedc1177c8f0cb6c90b6afa6953a67e92932cb9852529bd211a9ec4599dc087fc977b06c24a69c682d1afd1020e6dc1f087571ccec66310a786e1548fca28f45bffff7f2000000000"), 10),
        'L': deserialize_header(bfh("000000206ac59045b5e3b8ec016cb5a56780c0346fb79454b62e95a63c426fb16bb01dc503b243756c25053253aeda309604363460a3911015929e68705bd89dff6fe064ca28f45bffff7f2000000000"), 11),
        'M': deserialize_header(bfh("00000020bfa64ff6b96eb438d24c32f2ca27a96d8e20b23671577dce2b37b3a815e9739615681cb2d00ff889193f6a68a93f5096aeb2d84ca0af6185a4625558225522214229f45bffff7f2000000000"), 9),
        'N': deserialize_header(bfh("000000208a469366884904d3f6b51dc44098335404dbe7092f1dc824bcd8608c122b8e299dc087fc977b06c24a69c682d1afd1020e6dc1f087571ccec66310a786e1548f4329f45bffff7f2001000000"), 10),
        'X': deserialize_header(bfh("00000020b381f50227543a4feea529064fbb654fd3ce9f251c978ee4168cd3c9f41068cb03b243756c25053253aeda309604363460a3911015929e68705bd89dff6fe0649b29f45bffff7f2001000000"), 11),
        'Y': deserialize_header(bfh("00000020b2c2c09de3206a17c4fd5ec3f7e1e4b4c339f1df94e1498be161ca15df0b6ca4d67cb902a7d807cee7676cb543feec3e053aa824d5dfb528d5b94f9760313d9d9b29f45bffff7f2004000000"), 12),
        'Z': deserialize_header(bfh("000000202c5fda8478f58b64cdd57b405929b423158c4913374ae1645c56093aad15febb0f2596c29203f8a0f71ae94193092dc8f113be3dbee4579f1e649fa3d6dcc38c622ef45bffff7f2000000000"), 13),
    }
    # tree of headers:
    #                                            - M <- N <- X <- Y <- Z
    #                                          /
    #                             - G <- H <- I <- J <- K <- L
    #                           /
    # A <- B <- C <- D <- E <- F <- O <- P <- Q <- R <- S <- T <- U

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        constants.set_regtest()

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        constants.set_mainnet()

    def setUp(self):
        super().setUp()
        self.data_dir = self.electrum_path
        make_dir(os.path.join(self.data_dir, 'forks'))
        self.config = SimpleConfig({'electrum_path': self.data_dir})
        blockchain.blockchains = {}

    def _append_header(self, chain: Blockchain, header: dict):
        self.assertTrue(chain.can_connect(header))
        chain.save_header(header)

    def test_get_height_of_last_common_block_with_chain(self):
        blockchain.blockchains[constants.net.GENESIS] = chain_u = Blockchain(
            config=self.config, forkpoint=0, parent=None,
            forkpoint_hash=constants.net.GENESIS, prev_hash=None)
        open(chain_u.path(), 'w+').close()
        self._append_header(chain_u, self.HEADERS['A'])
        self._append_header(chain_u, self.HEADERS['B'])
        self._append_header(chain_u, self.HEADERS['C'])
        self._append_header(chain_u, self.HEADERS['D'])
        self._append_header(chain_u, self.HEADERS['E'])
        self._append_header(chain_u, self.HEADERS['F'])
        self._append_header(chain_u, self.HEADERS['O'])
        self._append_header(chain_u, self.HEADERS['P'])
        self._append_header(chain_u, self.HEADERS['Q'])

        chain_l = chain_u.fork(self.HEADERS['G'])
        self._append_header(chain_l, self.HEADERS['H'])
        self._append_header(chain_l, self.HEADERS['I'])
        self._append_header(chain_l, self.HEADERS['J'])
        self._append_header(chain_l, self.HEADERS['K'])
        self._append_header(chain_l, self.HEADERS['L'])

        self.assertEqual({chain_u:  8, chain_l: 5}, chain_u.get_parent_heights())
        self.assertEqual({chain_l: 11},             chain_l.get_parent_heights())

        chain_z = chain_l.fork(self.HEADERS['M'])
        self._append_header(chain_z, self.HEADERS['N'])
        self._append_header(chain_z, self.HEADERS['X'])
        self._append_header(chain_z, self.HEADERS['Y'])
        self._append_header(chain_z, self.HEADERS['Z'])

        self.assertEqual({chain_u:  8, chain_z: 5}, chain_u.get_parent_heights())
        self.assertEqual({chain_l: 11, chain_z: 8}, chain_l.get_parent_heights())
        self.assertEqual({chain_z: 13},             chain_z.get_parent_heights())
        self.assertEqual(5, chain_u.get_height_of_last_common_block_with_chain(chain_l))
        self.assertEqual(5, chain_l.get_height_of_last_common_block_with_chain(chain_u))
        self.assertEqual(5, chain_u.get_height_of_last_common_block_with_chain(chain_z))
        self.assertEqual(5, chain_z.get_height_of_last_common_block_with_chain(chain_u))
        self.assertEqual(8, chain_l.get_height_of_last_common_block_with_chain(chain_z))
        self.assertEqual(8, chain_z.get_height_of_last_common_block_with_chain(chain_l))

        self._append_header(chain_u, self.HEADERS['R'])
        self._append_header(chain_u, self.HEADERS['S'])
        self._append_header(chain_u, self.HEADERS['T'])
        self._append_header(chain_u, self.HEADERS['U'])

        self.assertEqual({chain_u: 12, chain_z: 5}, chain_u.get_parent_heights())
        self.assertEqual({chain_l: 11, chain_z: 8}, chain_l.get_parent_heights())
        self.assertEqual({chain_z: 13},             chain_z.get_parent_heights())
        self.assertEqual(5, chain_u.get_height_of_last_common_block_with_chain(chain_l))
        self.assertEqual(5, chain_l.get_height_of_last_common_block_with_chain(chain_u))
        self.assertEqual(5, chain_u.get_height_of_last_common_block_with_chain(chain_z))
        self.assertEqual(5, chain_z.get_height_of_last_common_block_with_chain(chain_u))
        self.assertEqual(8, chain_l.get_height_of_last_common_block_with_chain(chain_z))
        self.assertEqual(8, chain_z.get_height_of_last_common_block_with_chain(chain_l))

    def test_parents_after_forking(self):
        blockchain.blockchains[constants.net.GENESIS] = chain_u = Blockchain(
            config=self.config, forkpoint=0, parent=None,
            forkpoint_hash=constants.net.GENESIS, prev_hash=None)
        open(chain_u.path(), 'w+').close()
        self._append_header(chain_u, self.HEADERS['A'])
        self._append_header(chain_u, self.HEADERS['B'])
        self._append_header(chain_u, self.HEADERS['C'])
        self._append_header(chain_u, self.HEADERS['D'])
        self._append_header(chain_u, self.HEADERS['E'])
        self._append_header(chain_u, self.HEADERS['F'])
        self._append_header(chain_u, self.HEADERS['O'])
        self._append_header(chain_u, self.HEADERS['P'])
        self._append_header(chain_u, self.HEADERS['Q'])

        self.assertEqual(None, chain_u.parent)

        chain_l = chain_u.fork(self.HEADERS['G'])
        self._append_header(chain_l, self.HEADERS['H'])
        self._append_header(chain_l, self.HEADERS['I'])
        self._append_header(chain_l, self.HEADERS['J'])
        self._append_header(chain_l, self.HEADERS['K'])
        self._append_header(chain_l, self.HEADERS['L'])

        self.assertEqual(None,    chain_l.parent)
        self.assertEqual(chain_l, chain_u.parent)

        chain_z = chain_l.fork(self.HEADERS['M'])
        self._append_header(chain_z, self.HEADERS['N'])
        self._append_header(chain_z, self.HEADERS['X'])
        self._append_header(chain_z, self.HEADERS['Y'])
        self._append_header(chain_z, self.HEADERS['Z'])

        self.assertEqual(chain_z, chain_u.parent)
        self.assertEqual(chain_z, chain_l.parent)
        self.assertEqual(None,    chain_z.parent)

        self._append_header(chain_u, self.HEADERS['R'])
        self._append_header(chain_u, self.HEADERS['S'])
        self._append_header(chain_u, self.HEADERS['T'])
        self._append_header(chain_u, self.HEADERS['U'])

        self.assertEqual(chain_z, chain_u.parent)
        self.assertEqual(chain_z, chain_l.parent)
        self.assertEqual(None,    chain_z.parent)

    def test_forking_and_swapping(self):
        blockchain.blockchains[constants.net.GENESIS] = chain_u = Blockchain(
            config=self.config, forkpoint=0, parent=None,
            forkpoint_hash=constants.net.GENESIS, prev_hash=None)
        open(chain_u.path(), 'w+').close()

        self._append_header(chain_u, self.HEADERS['A'])
        self._append_header(chain_u, self.HEADERS['B'])
        self._append_header(chain_u, self.HEADERS['C'])
        self._append_header(chain_u, self.HEADERS['D'])
        self._append_header(chain_u, self.HEADERS['E'])
        self._append_header(chain_u, self.HEADERS['F'])
        self._append_header(chain_u, self.HEADERS['O'])
        self._append_header(chain_u, self.HEADERS['P'])
        self._append_header(chain_u, self.HEADERS['Q'])
        self._append_header(chain_u, self.HEADERS['R'])

        chain_l = chain_u.fork(self.HEADERS['G'])
        self._append_header(chain_l, self.HEADERS['H'])
        self._append_header(chain_l, self.HEADERS['I'])
        self._append_header(chain_l, self.HEADERS['J'])

        # do checks
        self.assertEqual(2, len(blockchain.blockchains))
        self.assertEqual(1, len(os.listdir(os.path.join(self.data_dir, "forks"))))
        self.assertEqual(0, chain_u.forkpoint)
        self.assertEqual(None, chain_u.parent)
        self.assertEqual(constants.net.GENESIS, chain_u._forkpoint_hash)
        self.assertEqual(None, chain_u._prev_hash)
        self.assertEqual(os.path.join(self.data_dir, "blockchain_headers"), chain_u.path())
        self.assertEqual(10 * 80, os.stat(chain_u.path()).st_size)
        self.assertEqual(6, chain_l.forkpoint)
        self.assertEqual(chain_u, chain_l.parent)
        self.assertEqual(hash_header(self.HEADERS['G']), chain_l._forkpoint_hash)
        self.assertEqual(hash_header(self.HEADERS['F']), chain_l._prev_hash)
        self.assertEqual(os.path.join(self.data_dir, "forks", "fork2_6_90791a08906278ce5c9581e0f8e54b729c54049f77d7397ae6a4d41229e2cb9a_836df46c91b3b9763f20d0066b48cba088b87b7481a0e17dc6b4cc6fbe6f975b"), chain_l.path())
        self.assertEqual(4 * 80, os.stat(chain_l.path()).st_size)

        self._append_header(chain_l, self.HEADERS['K'])

        # chains were swapped, do checks
        self.assertEqual(2, len(blockchain.blockchains))
        self.assertEqual(1, len(os.listdir(os.path.join(self.data_dir, "forks"))))
        self.assertEqual(6, chain_u.forkpoint)
        self.assertEqual(chain_l, chain_u.parent)
        self.assertEqual(hash_header(self.HEADERS['O']), chain_u._forkpoint_hash)
        self.assertEqual(hash_header(self.HEADERS['F']), chain_u._prev_hash)
        self.assertEqual(os.path.join(self.data_dir, "forks", "fork2_6_90791a08906278ce5c9581e0f8e54b729c54049f77d7397ae6a4d41229e2cb9a_a05a28a6464817d8b020a3016897b9a52239c1e7757fec9c32121854f1a0cc18"), chain_u.path())
        self.assertEqual(4 * 80, os.stat(chain_u.path()).st_size)
        self.assertEqual(0, chain_l.forkpoint)
        self.assertEqual(None, chain_l.parent)
        self.assertEqual(constants.net.GENESIS, chain_l._forkpoint_hash)
        self.assertEqual(None, chain_l._prev_hash)
        self.assertEqual(os.path.join(self.data_dir, "blockchain_headers"), chain_l.path())
        self.assertEqual(11 * 80, os.stat(chain_l.path()).st_size)
        for b in (chain_u, chain_l):
            self.assertTrue(all([b.can_connect(b.read_header(i), False) for i in range(b.height())]))

        self._append_header(chain_u, self.HEADERS['S'])
        self._append_header(chain_u, self.HEADERS['T'])
        self._append_header(chain_u, self.HEADERS['U'])
        self._append_header(chain_l, self.HEADERS['L'])

        chain_z = chain_l.fork(self.HEADERS['M'])
        self._append_header(chain_z, self.HEADERS['N'])
        self._append_header(chain_z, self.HEADERS['X'])
        self._append_header(chain_z, self.HEADERS['Y'])
        self._append_header(chain_z, self.HEADERS['Z'])

        # chain_z became best chain, do checks
        self.assertEqual(3, len(blockchain.blockchains))
        self.assertEqual(2, len(os.listdir(os.path.join(self.data_dir, "forks"))))
        self.assertEqual(0, chain_z.forkpoint)
        self.assertEqual(None, chain_z.parent)
        self.assertEqual(constants.net.GENESIS, chain_z._forkpoint_hash)
        self.assertEqual(None, chain_z._prev_hash)
        self.assertEqual(os.path.join(self.data_dir, "blockchain_headers"), chain_z.path())
        self.assertEqual(14 * 80, os.stat(chain_z.path()).st_size)
        self.assertEqual(9, chain_l.forkpoint)
        self.assertEqual(chain_z, chain_l.parent)
        self.assertEqual(hash_header(self.HEADERS['J']), chain_l._forkpoint_hash)
        self.assertEqual(hash_header(self.HEADERS['I']), chain_l._prev_hash)
        self.assertEqual(os.path.join(self.data_dir, "forks", "fork2_9_9673e915a8b3372bce7d577136b2208e6da927caf2324cd238b46eb9f64fa6bf_59c49e1a21bd292585b92c93927ea65369fa6a0bc9b60c8f7c17c1ed9d53e0b9"), chain_l.path())
        self.assertEqual(3 * 80, os.stat(chain_l.path()).st_size)
        self.assertEqual(6, chain_u.forkpoint)
        self.assertEqual(chain_z, chain_u.parent)
        self.assertEqual(hash_header(self.HEADERS['O']), chain_u._forkpoint_hash)
        self.assertEqual(hash_header(self.HEADERS['F']), chain_u._prev_hash)
        self.assertEqual(os.path.join(self.data_dir, "forks", "fork2_6_90791a08906278ce5c9581e0f8e54b729c54049f77d7397ae6a4d41229e2cb9a_a05a28a6464817d8b020a3016897b9a52239c1e7757fec9c32121854f1a0cc18"), chain_u.path())
        self.assertEqual(7 * 80, os.stat(chain_u.path()).st_size)
        for b in (chain_u, chain_l, chain_z):
            self.assertTrue(all([b.can_connect(b.read_header(i), False) for i in range(b.height())]))

        self.assertEqual(constants.net.GENESIS, chain_z.get_hash(0))
        self.assertEqual(hash_header(self.HEADERS['F']), chain_z.get_hash(5))
        self.assertEqual(hash_header(self.HEADERS['G']), chain_z.get_hash(6))
        self.assertEqual(hash_header(self.HEADERS['I']), chain_z.get_hash(8))
        self.assertEqual(hash_header(self.HEADERS['M']), chain_z.get_hash(9))
        self.assertEqual(hash_header(self.HEADERS['Z']), chain_z.get_hash(13))

    def test_doing_multiple_swaps_after_single_new_header(self):
        blockchain.blockchains[constants.net.GENESIS] = chain_u = Blockchain(
            config=self.config, forkpoint=0, parent=None,
            forkpoint_hash=constants.net.GENESIS, prev_hash=None)
        open(chain_u.path(), 'w+').close()

        self._append_header(chain_u, self.HEADERS['A'])
        self._append_header(chain_u, self.HEADERS['B'])
        self._append_header(chain_u, self.HEADERS['C'])
        self._append_header(chain_u, self.HEADERS['D'])
        self._append_header(chain_u, self.HEADERS['E'])
        self._append_header(chain_u, self.HEADERS['F'])
        self._append_header(chain_u, self.HEADERS['O'])
        self._append_header(chain_u, self.HEADERS['P'])
        self._append_header(chain_u, self.HEADERS['Q'])
        self._append_header(chain_u, self.HEADERS['R'])
        self._append_header(chain_u, self.HEADERS['S'])

        self.assertEqual(1, len(blockchain.blockchains))
        self.assertEqual(0, len(os.listdir(os.path.join(self.data_dir, "forks"))))

        chain_l = chain_u.fork(self.HEADERS['G'])
        self._append_header(chain_l, self.HEADERS['H'])
        self._append_header(chain_l, self.HEADERS['I'])
        self._append_header(chain_l, self.HEADERS['J'])
        self._append_header(chain_l, self.HEADERS['K'])
        # now chain_u is best chain, but it's tied with chain_l

        self.assertEqual(2, len(blockchain.blockchains))
        self.assertEqual(1, len(os.listdir(os.path.join(self.data_dir, "forks"))))

        chain_z = chain_l.fork(self.HEADERS['M'])
        self._append_header(chain_z, self.HEADERS['N'])
        self._append_header(chain_z, self.HEADERS['X'])

        self.assertEqual(3, len(blockchain.blockchains))
        self.assertEqual(2, len(os.listdir(os.path.join(self.data_dir, "forks"))))

        # chain_z became best chain, do checks
        self.assertEqual(0, chain_z.forkpoint)
        self.assertEqual(None, chain_z.parent)
        self.assertEqual(constants.net.GENESIS, chain_z._forkpoint_hash)
        self.assertEqual(None, chain_z._prev_hash)
        self.assertEqual(os.path.join(self.data_dir, "blockchain_headers"), chain_z.path())
        self.assertEqual(12 * 80, os.stat(chain_z.path()).st_size)
        self.assertEqual(9, chain_l.forkpoint)
        self.assertEqual(chain_z, chain_l.parent)
        self.assertEqual(hash_header(self.HEADERS['J']), chain_l._forkpoint_hash)
        self.assertEqual(hash_header(self.HEADERS['I']), chain_l._prev_hash)
        self.assertEqual(os.path.join(self.data_dir, "forks", "fork2_9_9673e915a8b3372bce7d577136b2208e6da927caf2324cd238b46eb9f64fa6bf_59c49e1a21bd292585b92c93927ea65369fa6a0bc9b60c8f7c17c1ed9d53e0b9"), chain_l.path())
        self.assertEqual(2 * 80, os.stat(chain_l.path()).st_size)
        self.assertEqual(6, chain_u.forkpoint)
        self.assertEqual(chain_z, chain_u.parent)
        self.assertEqual(hash_header(self.HEADERS['O']), chain_u._forkpoint_hash)
        self.assertEqual(hash_header(self.HEADERS['F']), chain_u._prev_hash)
        self.assertEqual(os.path.join(self.data_dir, "forks", "fork2_6_90791a08906278ce5c9581e0f8e54b729c54049f77d7397ae6a4d41229e2cb9a_a05a28a6464817d8b020a3016897b9a52239c1e7757fec9c32121854f1a0cc18"), chain_u.path())
        self.assertEqual(5 * 80, os.stat(chain_u.path()).st_size)

        self.assertEqual(constants.net.GENESIS, chain_z.get_hash(0))
        self.assertEqual(hash_header(self.HEADERS['F']), chain_z.get_hash(5))
        self.assertEqual(hash_header(self.HEADERS['G']), chain_z.get_hash(6))
        self.assertEqual(hash_header(self.HEADERS['I']), chain_z.get_hash(8))
        self.assertEqual(hash_header(self.HEADERS['M']), chain_z.get_hash(9))
        self.assertEqual(hash_header(self.HEADERS['X']), chain_z.get_hash(11))

        for b in (chain_u, chain_l, chain_z):
            self.assertTrue(all([b.can_connect(b.read_header(i), False) for i in range(b.height())]))


class TestVerifyHeader(ElectrumTestCase):

    # Data for Litecoin block header #100.
    valid_header = "01000000fb040b4b30f4f0d90b5d4819f566a156669565f73998fb37cf072c4ec5daac08fd5a56f1650756fec9f1a587f9f69e5298723bf4e296aff71670b7d471f1a31e9e55964ef0ff0f1e27010000"
    target = Blockchain.bits_to_target(0x1e0ffff0)
    prev_hash = "08acdac54e2c07cf37fb9839f765956656a166f519485d0bd9f0f4304b0b04fb"

    def setUp(self):
        super().setUp()
        self.header = deserialize_header(bfh(self.valid_header), 100)

    def test_valid_header(self):
        Blockchain.verify_header(self.header, self.prev_hash, self.target)

    def test_expected_hash_mismatch(self):
        with self.assertRaises(Exception):
            Blockchain.verify_header(self.header, self.prev_hash, self.target,
                                     expected_header_hash="foo")

    def test_prev_hash_mismatch(self):
        with self.assertRaises(Exception):
            Blockchain.verify_header(self.header, "foo", self.target)

    def test_target_mismatch(self):
        with self.assertRaises(Exception):
            other_target = Blockchain.bits_to_target(0x1d00eeee)
            Blockchain.verify_header(self.header, self.prev_hash, other_target)

    def test_insufficient_pow(self):
        with self.assertRaises(Exception):
            self.header["nonce"] = 42
            Blockchain.verify_header(self.header, self.prev_hash, self.target)
