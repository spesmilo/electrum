import json
import unittest
from lib.util import bh2u
from lib.lnbase import make_commitment, get_locktime
from lib.transaction import Transaction
from lib import bitcoin

class Test_LNBase(unittest.TestCase):

    def test_commitment_tx(self):

        funding_tx_id = '8984484a580b825b9972d7adb15050b3ab624ccd731946b3eeddb92f4e7ef6be'
        funding_output_index = 0
        funding_amount_satoshi = 10000000
        commitment_number = 42
        local_delay = 144
        local_dust_limit_satoshi = 546

        local_payment_basepoint = bytes.fromhex('034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa')
        remote_payment_basepoint = bytes.fromhex('032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991')
        locktime = get_locktime(42, local_payment_basepoint, remote_payment_basepoint)

        local_funding_privkey = bytes.fromhex('30ff4956bbdd3222d44cc5e8a1261dab1e07957bdac5ae88fe3261ef321f374901')
        local_funding_pubkey = bytes.fromhex('023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb')
        remote_funding_pubkey = bytes.fromhex('030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c1')
        local_privkey = bytes.fromhex('bb13b121cdc357cd2e608b0aea294afca36e2b34cf958e2e6451a2f27469449101')
        localpubkey = bytes.fromhex('030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e7')
        remotepubkey = bytes.fromhex('0394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b')
        local_delayedpubkey = bytes.fromhex('03fd5960528dc152014952efdb702a88f71e3c1653b2314431701ec77e57fde83c')
        local_revocation_pubkey = bytes.fromhex('0212a140cd0c6539d07cd08dfe09984dec3251ea808b892efeac3ede9402bf2b19')
        # funding wscript = 5221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae

        #name: simple commitment tx with no HTLCs
        to_local_msat = 7000000000
        to_remote_msat = 3000000000
        local_feerate_per_kw = 15000
        # base commitment transaction fee = 10860
        # actual commitment transaction fee = 10860
        # to_local amount 6989140 wscript 63210212a140cd0c6539d07cd08dfe09984dec3251ea808b892efeac3ede9402bf2b1967029000b2752103fd5960528dc152014952efdb702a88f71e3c1653b2314431701ec77e57fde83c68ac
        # to_remote amount 3000000 P2WPKH(0394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b)
        remote_signature = "3045022100f51d2e566a70ba740fc5d8c0f07b9b93d2ed741c3c0860c613173de7d39e7968022041376d520e9c0e1ad52248ddf4b22e12be8763007df977253ef45a4ca3bdb7c0"
        # local_signature = 3044022051b75c73198c6deee1a875871c3961832909acd297c6b908d59e3319e5185a46022055c419379c5051a78d00dbbce11b5b664a0c22815fbcc6fcef6b1937c3836939
        #num_htlcs: 0
        our_commit_tx = make_commitment(
            local_funding_pubkey, remote_funding_pubkey,
            local_payment_basepoint, remote_payment_basepoint,
            local_revocation_pubkey, local_delayedpubkey,
            funding_tx_id, funding_output_index, funding_amount_satoshi)
        our_commit_tx.sign({bh2u(local_funding_pubkey): (local_funding_privkey[:-1], True)})

        ref_commit_tx_str = '02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b8002c0c62d0000000000160014ccf1af2f2aabee14bb40fa3851ab2301de84311054a56a00000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0400473044022051b75c73198c6deee1a875871c3961832909acd297c6b908d59e3319e5185a46022055c419379c5051a78d00dbbce11b5b664a0c22815fbcc6fcef6b1937c383693901483045022100f51d2e566a70ba740fc5d8c0f07b9b93d2ed741c3c0860c613173de7d39e7968022041376d520e9c0e1ad52248ddf4b22e12be8763007df977253ef45a4ca3bdb7c001475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220'
        ref_commit_tx = Transaction(ref_commit_tx_str)

        pubkeys, _x_pubkeys = our_commit_tx.get_sorted_pubkeys(our_commit_tx.inputs()[0])
        index_of_pubkey = pubkeys.index(bh2u(remote_funding_pubkey))
        our_commit_tx._inputs[0]["signatures"][index_of_pubkey] = remote_signature + "01"

        print("Reference inputs", json.dumps(ref_commit_tx.inputs(), indent=2))
        print("Our inputs", json.dumps(our_commit_tx.inputs(), indent=2))

        for idx, inp in enumerate(our_commit_tx.inputs()):
            for field in inp.keys():
                 self.assertEqual(inp[field], ref_commit_tx.inputs()[idx][field], field)

        self.assertEquals(ref_commit_tx.inputs()[0]["witness"], our_commit_tx.serialize_witness(txin=our_commit_tx.inputs()[0]))

        output1adr = ref_commit_tx.outputs()[0][1]
        output2adr = ref_commit_tx.outputs()[1][1]
        self.assertTrue(bitcoin.redeem_script_to_address("p2wsh", "63210212a140cd0c6539d07cd08dfe09984dec3251ea808b892efeac3ede9402bf2b1967029000b2752103fd5960528dc152014952efdb702a88f71e3c1653b2314431701ec77e57fde83c68ac") in [output1adr, output2adr])
        # todo check order and other output

        self.assertEqual(str(our_commit_tx), ref_commit_tx_str)
