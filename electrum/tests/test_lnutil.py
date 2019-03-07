import unittest
import json
from electrum import bitcoin
from electrum.lnutil import (RevocationStore, get_per_commitment_secret_from_seed, make_offered_htlc,
                             make_received_htlc, make_commitment, make_htlc_tx_witness, make_htlc_tx_output,
                             make_htlc_tx_inputs, secret_to_pubkey, derive_blinded_pubkey, derive_privkey,
                             derive_pubkey, make_htlc_tx, extract_ctn_from_tx, UnableToDeriveSecret,
                             get_compressed_pubkey_from_bech32, split_host_port, ConnStringFormatError,
                             ScriptHtlc, extract_nodeid, calc_onchain_fees, UpdateAddHtlc)
from electrum.util import bh2u, bfh
from electrum.transaction import Transaction

funding_tx_id = '8984484a580b825b9972d7adb15050b3ab624ccd731946b3eeddb92f4e7ef6be'
funding_output_index = 0
funding_amount_satoshi = 10000000
commitment_number = 42
local_delay = 144
local_dust_limit_satoshi = 546

local_payment_basepoint = bytes.fromhex('034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa')
remote_payment_basepoint = bytes.fromhex('032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991')
# obs = get_obscured_ctn(42, local_payment_basepoint, remote_payment_basepoint)
local_funding_privkey = bytes.fromhex('30ff4956bbdd3222d44cc5e8a1261dab1e07957bdac5ae88fe3261ef321f374901')
local_funding_pubkey = bytes.fromhex('023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb')
remote_funding_pubkey = bytes.fromhex('030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c1')
local_privkey = bytes.fromhex('bb13b121cdc357cd2e608b0aea294afca36e2b34cf958e2e6451a2f27469449101')
localpubkey = bytes.fromhex('030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e7')
remotepubkey = bytes.fromhex('0394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b')
local_delayedpubkey = bytes.fromhex('03fd5960528dc152014952efdb702a88f71e3c1653b2314431701ec77e57fde83c')
local_revocation_pubkey = bytes.fromhex('0212a140cd0c6539d07cd08dfe09984dec3251ea808b892efeac3ede9402bf2b19')
# funding wscript = 5221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae

class TestLNUtil(unittest.TestCase):
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

            for insert in test["inserts"]:
                secret = bytes.fromhex(insert["secret"])
                index = insert["index"]
                if insert["successful"]:
                    self.assertEqual(secret, receiver.retrieve_secret(index))

            print("Passed ({})".format(test["name"]))

    def test_shachain_produce_consume(self):
        seed = bitcoin.sha256(b"shachaintest")
        consumer = RevocationStore()
        for i in range(10000):
            secret = get_per_commitment_secret_from_seed(seed, RevocationStore.START_INDEX - i)
            try:
                consumer.add_next_entry(secret)
            except Exception as e:
                raise Exception("iteration " + str(i) + ": " + str(e))
            if i % 1000 == 0: self.assertEqual(consumer.serialize(), RevocationStore.from_json_obj(json.loads(json.dumps(consumer.serialize()))).serialize())

    def test_commitment_tx_with_all_five_HTLCs_untrimmed_minimum_feerate(self):
        to_local_msat = 6988000000
        to_remote_msat = 3000000000
        local_feerate_per_kw = 0
        # base commitment transaction fee = 0
        # actual commitment transaction fee = 0

        per_commitment_secret = 0x1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100
        per_commitment_point = secret_to_pubkey(per_commitment_secret)

        remote_htlcpubkey = remotepubkey
        local_htlcpubkey = localpubkey

        htlc_cltv_timeout = {}
        htlc_payment_preimage = {}
        htlc = {}

        htlc_cltv_timeout[2] = 502
        htlc_payment_preimage[2] = b"\x02" * 32
        htlc[2] = make_offered_htlc(local_revocation_pubkey, remote_htlcpubkey, local_htlcpubkey, bitcoin.sha256(htlc_payment_preimage[2]))

        htlc_cltv_timeout[3] = 503
        htlc_payment_preimage[3] = b"\x03" * 32
        htlc[3] = make_offered_htlc(local_revocation_pubkey, remote_htlcpubkey, local_htlcpubkey, bitcoin.sha256(htlc_payment_preimage[3]))

        htlc_cltv_timeout[0] = 500
        htlc_payment_preimage[0] = b"\x00" * 32
        htlc[0] = make_received_htlc(local_revocation_pubkey, remote_htlcpubkey, local_htlcpubkey, bitcoin.sha256(htlc_payment_preimage[0]), htlc_cltv_timeout[0])

        htlc_cltv_timeout[1] = 501
        htlc_payment_preimage[1] = b"\x01" * 32
        htlc[1] = make_received_htlc(local_revocation_pubkey, remote_htlcpubkey, local_htlcpubkey, bitcoin.sha256(htlc_payment_preimage[1]), htlc_cltv_timeout[1])

        htlc_cltv_timeout[4] = 504
        htlc_payment_preimage[4] = b"\x04" * 32
        htlc[4] = make_received_htlc(local_revocation_pubkey, remote_htlcpubkey, local_htlcpubkey, bitcoin.sha256(htlc_payment_preimage[4]), htlc_cltv_timeout[4])

        remote_signature = "304402204fd4928835db1ccdfc40f5c78ce9bd65249b16348df81f0c44328dcdefc97d630220194d3869c38bc732dd87d13d2958015e2fc16829e74cd4377f84d215c0b70606"
        output_commit_tx = "02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b8007e80300000000000022002052bfef0479d7b293c27e0f1eb294bea154c63a3294ef092c19af51409bce0e2ad007000000000000220020403d394747cae42e98ff01734ad5c08f82ba123d3d9a620abda88989651e2ab5d007000000000000220020748eba944fedc8827f6b06bc44678f93c0f9e6078b35c6331ed31e75f8ce0c2db80b000000000000220020c20b5d1f8584fd90443e7b7b720136174fa4b9333c261d04dbbd012635c0f419a00f0000000000002200208c48d15160397c9731df9bc3b236656efb6665fbfe92b4a6878e88a499f741c4c0c62d0000000000160014ccf1af2f2aabee14bb40fa3851ab2301de843110e0a06a00000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e04004730440220275b0c325a5e9355650dc30c0eccfbc7efb23987c24b556b9dfdd40effca18d202206caceb2c067836c51f296740c7ae807ffcbfbf1dd3a0d56b6de9a5b247985f060147304402204fd4928835db1ccdfc40f5c78ce9bd65249b16348df81f0c44328dcdefc97d630220194d3869c38bc732dd87d13d2958015e2fc16829e74cd4377f84d215c0b7060601475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220"

        htlc_obj = {}
        for num, msat in [(0, 1000 * 1000),
            (2, 2000 * 1000),
            (1, 2000 * 1000),
            (3, 3000 * 1000),
            (4, 4000 * 1000)]:
            htlc_obj[num] = UpdateAddHtlc(amount_msat=msat, payment_hash=bitcoin.sha256(htlc_payment_preimage[num]), cltv_expiry=None, htlc_id=None, timestamp=0)
        htlcs = [ScriptHtlc(htlc[x], htlc_obj[x]) for x in range(5)]

        our_commit_tx = make_commitment(
            commitment_number,
            local_funding_pubkey, remote_funding_pubkey, remotepubkey,
            local_payment_basepoint, remote_payment_basepoint,
            local_revocation_pubkey, local_delayedpubkey, local_delay,
            funding_tx_id, funding_output_index, funding_amount_satoshi,
            to_local_msat, to_remote_msat, local_dust_limit_satoshi,
            calc_onchain_fees(len(htlcs), local_feerate_per_kw, True), htlcs=htlcs)
        self.sign_and_insert_remote_sig(our_commit_tx, remote_funding_pubkey, remote_signature, local_funding_pubkey, local_funding_privkey)
        self.assertEqual(str(our_commit_tx), output_commit_tx)

        signature_for_output_remote_htlc = {}
        signature_for_output_remote_htlc[0] = "304402206a6e59f18764a5bf8d4fa45eebc591566689441229c918b480fb2af8cc6a4aeb02205248f273be447684b33e3c8d1d85a8e0ca9fa0bae9ae33f0527ada9c162919a6"
        signature_for_output_remote_htlc[2] = "3045022100d5275b3619953cb0c3b5aa577f04bc512380e60fa551762ce3d7a1bb7401cff9022037237ab0dac3fe100cde094e82e2bed9ba0ed1bb40154b48e56aa70f259e608b"
        signature_for_output_remote_htlc[1] = "304402201b63ec807771baf4fdff523c644080de17f1da478989308ad13a58b51db91d360220568939d38c9ce295adba15665fa68f51d967e8ed14a007b751540a80b325f202"
        signature_for_output_remote_htlc[3] = "3045022100daee1808f9861b6c3ecd14f7b707eca02dd6bdfc714ba2f33bc8cdba507bb182022026654bf8863af77d74f51f4e0b62d461a019561bb12acb120d3f7195d148a554"
        signature_for_output_remote_htlc[4] = "304402207e0410e45454b0978a623f36a10626ef17b27d9ad44e2760f98cfa3efb37924f0220220bd8acd43ecaa916a80bd4f919c495a2c58982ce7c8625153f8596692a801d"

        output_htlc_tx = {}
        SUCCESS = True
        TIMEOUT = False
        output_htlc_tx[0] = (SUCCESS, "020000000001018154ecccf11a5fb56c39654c4deb4d2296f83c69268280b94d021370c94e219700000000000000000001e8030000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e050047304402206a6e59f18764a5bf8d4fa45eebc591566689441229c918b480fb2af8cc6a4aeb02205248f273be447684b33e3c8d1d85a8e0ca9fa0bae9ae33f0527ada9c162919a60147304402207cb324fa0de88f452ffa9389678127ebcf4cabe1dd848b8e076c1a1962bf34720220116ed922b12311bd602d67e60d2529917f21c5b82f25ff6506c0f87886b4dfd5012000000000000000000000000000000000000000000000000000000000000000008a76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a914b8bcb07f6344b42ab04250c86a6e8b75d3fdbbc688527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f401b175ac686800000000")

        output_htlc_tx[2] = (TIMEOUT, "020000000001018154ecccf11a5fb56c39654c4deb4d2296f83c69268280b94d021370c94e219701000000000000000001d0070000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500483045022100d5275b3619953cb0c3b5aa577f04bc512380e60fa551762ce3d7a1bb7401cff9022037237ab0dac3fe100cde094e82e2bed9ba0ed1bb40154b48e56aa70f259e608b01483045022100c89172099507ff50f4c925e6c5150e871fb6e83dd73ff9fbb72f6ce829a9633f02203a63821d9162e99f9be712a68f9e589483994feae2661e4546cd5b6cec007be501008576a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a914b43e1b38138a41b37f7cd9a1d274bc63e3a9b5d188ac6868f6010000")

        output_htlc_tx[1] = (SUCCESS, "020000000001018154ecccf11a5fb56c39654c4deb4d2296f83c69268280b94d021370c94e219702000000000000000001d0070000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e050047304402201b63ec807771baf4fdff523c644080de17f1da478989308ad13a58b51db91d360220568939d38c9ce295adba15665fa68f51d967e8ed14a007b751540a80b325f20201483045022100def389deab09cee69eaa1ec14d9428770e45bcbe9feb46468ecf481371165c2f022015d2e3c46600b2ebba8dcc899768874cc6851fd1ecb3fffd15db1cc3de7e10da012001010101010101010101010101010101010101010101010101010101010101018a76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a9144b6b2e5444c2639cc0fb7bcea5afba3f3cdce23988527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f501b175ac686800000000")

        output_htlc_tx[3] = (TIMEOUT, "020000000001018154ecccf11a5fb56c39654c4deb4d2296f83c69268280b94d021370c94e219703000000000000000001b80b0000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500483045022100daee1808f9861b6c3ecd14f7b707eca02dd6bdfc714ba2f33bc8cdba507bb182022026654bf8863af77d74f51f4e0b62d461a019561bb12acb120d3f7195d148a554014730440220643aacb19bbb72bd2b635bc3f7375481f5981bace78cdd8319b2988ffcc6704202203d27784ec8ad51ed3bd517a05525a5139bb0b755dd719e0054332d186ac0872701008576a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a9148a486ff2e31d6158bf39e2608864d63fefd09d5b88ac6868f7010000")

        output_htlc_tx[4] = (SUCCESS, "020000000001018154ecccf11a5fb56c39654c4deb4d2296f83c69268280b94d021370c94e219704000000000000000001a00f0000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e050047304402207e0410e45454b0978a623f36a10626ef17b27d9ad44e2760f98cfa3efb37924f0220220bd8acd43ecaa916a80bd4f919c495a2c58982ce7c8625153f8596692a801d014730440220549e80b4496803cbc4a1d09d46df50109f546d43fbbf86cd90b174b1484acd5402205f12a4f995cb9bded597eabfee195a285986aa6d93ae5bb72507ebc6a4e2349e012004040404040404040404040404040404040404040404040404040404040404048a76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a91418bc1a114ccf9c052d3d23e28d3b0a9d1227434288527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f801b175ac686800000000")

        htlc_output_index = {0: 0, 1: 2, 2: 1, 3: 3, 4: 4}

        for i in range(5):
            self.assertEqual(output_htlc_tx[i][1], self.htlc_tx(htlc[i], htlc_output_index[i],
                htlcs[i].htlc.amount_msat,
                htlc_payment_preimage[i],
                signature_for_output_remote_htlc[i],
                output_htlc_tx[i][0], htlc_cltv_timeout[i] if not output_htlc_tx[i][0] else 0,
                local_feerate_per_kw,
                our_commit_tx))

    def htlc_tx(self, htlc, htlc_output_index, amount_msat, htlc_payment_preimage, remote_htlc_sig, success, cltv_timeout, local_feerate_per_kw, our_commit_tx):
        _script, our_htlc_tx_output = make_htlc_tx_output(
            amount_msat=amount_msat,
            local_feerate=local_feerate_per_kw,
            revocationpubkey=local_revocation_pubkey,
            local_delayedpubkey=local_delayedpubkey,
            success=success,
            to_self_delay=local_delay)
        our_htlc_tx_inputs = make_htlc_tx_inputs(
            htlc_output_txid=our_commit_tx.txid(),
            htlc_output_index=htlc_output_index,
            amount_msat=amount_msat,
            witness_script=bh2u(htlc))
        our_htlc_tx = make_htlc_tx(cltv_timeout,
            inputs=our_htlc_tx_inputs,
            output=our_htlc_tx_output,
            name='test',
            cltv_expiry=0)

        local_sig = our_htlc_tx.sign_txin(0, local_privkey[:-1])

        our_htlc_tx_witness = make_htlc_tx_witness(
            remotehtlcsig=bfh(remote_htlc_sig) + b"\x01",  # 0x01 is SIGHASH_ALL
            localhtlcsig=bfh(local_sig),
            payment_preimage=htlc_payment_preimage if success else b'',  # will put 00 on witness if timeout
            witness_script=htlc)
        our_htlc_tx._inputs[0]['witness'] = bh2u(our_htlc_tx_witness)
        return str(our_htlc_tx)

    def test_commitment_tx_with_one_output(self):
        to_local_msat= 6988000000
        to_remote_msat= 3000000000
        local_feerate_per_kw= 9651181
        remote_signature = "3044022064901950be922e62cbe3f2ab93de2b99f37cff9fc473e73e394b27f88ef0731d02206d1dfa227527b4df44a07599289e207d6fd9cca60c0365682dcd3deaf739567e"
        output_commit_tx= "02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b8001c0c62d0000000000160014ccf1af2f2aabee14bb40fa3851ab2301de8431100400473044022031a82b51bd014915fe68928d1abf4b9885353fb896cac10c3fdd88d7f9c7f2e00220716bda819641d2c63e65d3549b6120112e1aeaf1742eed94a471488e79e206b101473044022064901950be922e62cbe3f2ab93de2b99f37cff9fc473e73e394b27f88ef0731d02206d1dfa227527b4df44a07599289e207d6fd9cca60c0365682dcd3deaf739567e01475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220"

        our_commit_tx = make_commitment(
            commitment_number,
            local_funding_pubkey, remote_funding_pubkey, remotepubkey,
            local_payment_basepoint, remote_payment_basepoint,
            local_revocation_pubkey, local_delayedpubkey, local_delay,
            funding_tx_id, funding_output_index, funding_amount_satoshi,
            to_local_msat, to_remote_msat, local_dust_limit_satoshi,
            calc_onchain_fees(0, local_feerate_per_kw, True), htlcs=[])
        self.sign_and_insert_remote_sig(our_commit_tx, remote_funding_pubkey, remote_signature, local_funding_pubkey, local_funding_privkey)

        self.assertEqual(str(our_commit_tx), output_commit_tx)

    def test_commitment_tx_with_fee_greater_than_funder_amount(self):
        to_local_msat= 6988000000
        to_remote_msat= 3000000000
        local_feerate_per_kw= 9651936
        remote_signature = "3044022064901950be922e62cbe3f2ab93de2b99f37cff9fc473e73e394b27f88ef0731d02206d1dfa227527b4df44a07599289e207d6fd9cca60c0365682dcd3deaf739567e"
        output_commit_tx= "02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b8001c0c62d0000000000160014ccf1af2f2aabee14bb40fa3851ab2301de8431100400473044022031a82b51bd014915fe68928d1abf4b9885353fb896cac10c3fdd88d7f9c7f2e00220716bda819641d2c63e65d3549b6120112e1aeaf1742eed94a471488e79e206b101473044022064901950be922e62cbe3f2ab93de2b99f37cff9fc473e73e394b27f88ef0731d02206d1dfa227527b4df44a07599289e207d6fd9cca60c0365682dcd3deaf739567e01475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220"

        our_commit_tx = make_commitment(
            commitment_number,
            local_funding_pubkey, remote_funding_pubkey, remotepubkey,
            local_payment_basepoint, remote_payment_basepoint,
            local_revocation_pubkey, local_delayedpubkey, local_delay,
            funding_tx_id, funding_output_index, funding_amount_satoshi,
            to_local_msat, to_remote_msat, local_dust_limit_satoshi,
            calc_onchain_fees(0, local_feerate_per_kw, True), htlcs=[])
        self.sign_and_insert_remote_sig(our_commit_tx, remote_funding_pubkey, remote_signature, local_funding_pubkey, local_funding_privkey)

        self.assertEqual(str(our_commit_tx), output_commit_tx)

    def test_extract_commitment_number_from_tx(self):
        raw_tx = "02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b8007e80300000000000022002052bfef0479d7b293c27e0f1eb294bea154c63a3294ef092c19af51409bce0e2ad007000000000000220020403d394747cae42e98ff01734ad5c08f82ba123d3d9a620abda88989651e2ab5d007000000000000220020748eba944fedc8827f6b06bc44678f93c0f9e6078b35c6331ed31e75f8ce0c2db80b000000000000220020c20b5d1f8584fd90443e7b7b720136174fa4b9333c261d04dbbd012635c0f419a00f0000000000002200208c48d15160397c9731df9bc3b236656efb6665fbfe92b4a6878e88a499f741c4c0c62d0000000000160014ccf1af2f2aabee14bb40fa3851ab2301de843110e0a06a00000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e04004730440220275b0c325a5e9355650dc30c0eccfbc7efb23987c24b556b9dfdd40effca18d202206caceb2c067836c51f296740c7ae807ffcbfbf1dd3a0d56b6de9a5b247985f060147304402204fd4928835db1ccdfc40f5c78ce9bd65249b16348df81f0c44328dcdefc97d630220194d3869c38bc732dd87d13d2958015e2fc16829e74cd4377f84d215c0b7060601475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220"
        tx = Transaction(raw_tx)
        self.assertEqual(commitment_number, extract_ctn_from_tx(tx, 0, local_payment_basepoint, remote_payment_basepoint))

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
        our_commit_tx = make_commitment(
            commitment_number,
            local_funding_pubkey, remote_funding_pubkey, remotepubkey,
            local_payment_basepoint, remote_payment_basepoint,
            local_revocation_pubkey, local_delayedpubkey, local_delay,
            funding_tx_id, funding_output_index, funding_amount_satoshi,
            to_local_msat, to_remote_msat, local_dust_limit_satoshi,
            calc_onchain_fees(0, local_feerate_per_kw, True), htlcs=[])
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

    def test_get_compressed_pubkey_from_bech32(self):
        self.assertEqual(b'\x03\x84\xef\x87\xd9d\xa2\xaaa7=\xff\xb8\xfe=t8[}>;\n\x13\xa8e\x8eo:\xf5Mi\xb5H',
                         get_compressed_pubkey_from_bech32('ln1qwzwlp7evj325cfh8hlm3l3awsu9klf78v9p82r93ehn4a2ddx65s66awg5'))

    def test_split_host_port(self):
        self.assertEqual(split_host_port("[::1]:8000"), ("::1", "8000"))
        self.assertEqual(split_host_port("[::1]"), ("::1", "9735"))
        self.assertEqual(split_host_port("kæn.guru:8000"), ("kæn.guru", "8000"))
        self.assertEqual(split_host_port("kæn.guru"), ("kæn.guru", "9735"))
        self.assertEqual(split_host_port("127.0.0.1:8000"), ("127.0.0.1", "8000"))
        self.assertEqual(split_host_port("127.0.0.1"), ("127.0.0.1", "9735"))
        # accepted by getaddrinfo but not ipaddress.ip_address
        self.assertEqual(split_host_port("127.0.0:8000"), ("127.0.0", "8000"))
        self.assertEqual(split_host_port("127.0.0"), ("127.0.0", "9735"))
        self.assertEqual(split_host_port("electrum.org:8000"), ("electrum.org", "8000"))
        self.assertEqual(split_host_port("electrum.org"), ("electrum.org", "9735"))

        with self.assertRaises(ConnStringFormatError):
            split_host_port("electrum.org:8000:")
        with self.assertRaises(ConnStringFormatError):
            split_host_port("electrum.org:")

    def test_extract_nodeid(self):
        with self.assertRaises(ConnStringFormatError):
            extract_nodeid("00" * 32 + "@localhost")
        with self.assertRaises(ConnStringFormatError):
            extract_nodeid("00" * 33 + "@")
        self.assertEqual(extract_nodeid("00" * 33 + "@localhost"), (b"\x00" * 33, "localhost"))
