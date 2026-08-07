# Copyright (C) 2026 The Electrum developers
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://www.opensource.org/licenses/mit-license.php

from unittest.mock import patch

from electrum_ecc import ECPrivkey, ECPubkey, musig

from electrum.bitcoin import (
    LEAF_VERSION_TAPSCRIPT,
    NLOCKTIME_BLOCKHEIGHT_MAX,
    address_to_script,
    construct_witness,
    witness_push,
)
from electrum.crypto import sha256
from electrum.taproot_swaps import (
    MuSig2Session,
    SwapDirection,
    SwapLeaf,
    TaprootSwapContract,
)

from . import ElectrumTestCase


# Generated independently with Boltz Core 5.0.0 at commit
# 336737051d62e73baf27bff5878775e11ed46482, using swapTree,
# reverseSwapTree, Musig.create([provider, user]), tweakMusig, and
# createControlBlock. The secrets are scalars 1 and 2.
PROVIDER_PUBKEY = bytes.fromhex(
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
)
USER_PUBKEY = bytes.fromhex(
    "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
)
PREIMAGE = b"\xaa" * 32
PAYMENT_HASH = sha256(PREIMAGE)
LOCKTIME = 800_000

FORWARD_ROOT = bytes.fromhex(
    "75372846f2df145268cb58b82356acb491acb36f7de6af011edc06204fb0e6a6"
)
REVERSE_ROOT = bytes.fromhex(
    "4fb9cb38b2fc4c13b2a7f6014281ff40a7ba80ee0c731ecb4d3ed2d3d741d7d1"
)
INTERNAL_PUBKEY = bytes.fromhex(
    "3b46d262d2f610e9038b44beabdfe97ab5a0feb89870acc2264edfb7f63ec2ec"
)
FORWARD_ADDRESS = (
    "bc1pqq3wm8st9gsulhkf289sm547l63r8zl0zvsa6lul42yhh84eqeaqtw5767"
)
REVERSE_ADDRESS = (
    "bc1p5cr57xdpjm8l7jwm2yyhrwuq4y2p7u808hqeau7alf0ug2lcn9kqqks077"
)


def make_contract(direction=SwapDirection.FORWARD, **overrides):
    params = {
        "direction": direction,
        "payment_hash": PAYMENT_HASH,
        "locktime": LOCKTIME,
        "provider_pubkey": PROVIDER_PUBKEY,
        "user_pubkey": USER_PUBKEY,
    }
    params.update(overrides)
    return TaprootSwapContract(**params)


class TestTaprootSwapContract(ElectrumTestCase):
    def test_forward_reference_vector(self):
        contract = make_contract()
        expected_claim = bytes.fromhex(
            "a914b3256e789b42b4e73b0954beb516ec7dfc032dd3882079be667ef9dcbb"
            "ac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac"
        )
        expected_refund = bytes.fromhex(
            "20c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c7"
            "09ee5ad0300350cb1"
        )
        self.assertEqual(PROVIDER_PUBKEY, contract.claim_pubkey)
        self.assertEqual(USER_PUBKEY, contract.refund_pubkey)
        self.assertEqual(expected_claim, contract.claim_leaf_script)
        self.assertEqual(expected_refund, contract.refund_leaf_script)
        self.assertEqual(FORWARD_ROOT, contract.merkle_root)
        self.assertEqual(INTERNAL_PUBKEY, contract.internal_pubkey)
        self.assertEqual(
            "51200022ed9e0b2a21cfdec951cb0dd2befea2338bef1321dd7f9faa897b9e"
            "b9067a",
            contract.output_script.hex(),
        )
        self.assertEqual(FORWARD_ADDRESS, contract.address())

    def test_reverse_reference_vector_and_roles(self):
        contract = make_contract(SwapDirection.REVERSE)
        expected_claim = bytes.fromhex(
            "82012088a914b3256e789b42b4e73b0954beb516ec7dfc032dd38820c6047f"
            "9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5ac"
        )
        expected_refund = bytes.fromhex(
            "2079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8"
            "1798ad0300350cb1"
        )
        self.assertEqual(USER_PUBKEY, contract.claim_pubkey)
        self.assertEqual(PROVIDER_PUBKEY, contract.refund_pubkey)
        self.assertEqual(expected_claim, contract.claim_leaf_script)
        self.assertEqual(expected_refund, contract.refund_leaf_script)
        self.assertEqual(REVERSE_ROOT, contract.merkle_root)
        self.assertEqual(INTERNAL_PUBKEY, contract.internal_pubkey)
        self.assertEqual(
            "5120a6074f19a196cfff49db510971bb80a9141f70ef3dc19ef3ddfa5fc42b"
            "f8996c",
            contract.output_script.hex(),
        )
        self.assertEqual(REVERSE_ADDRESS, contract.address())

    def test_provider_first_key_aggregation_is_direction_independent(self):
        forward = make_contract()
        reverse = make_contract(SwapDirection.REVERSE)
        swapped_roles = make_contract(
            provider_pubkey=USER_PUBKEY, user_pubkey=PROVIDER_PUBKEY
        )
        self.assertEqual(forward.internal_pubkey, reverse.internal_pubkey)
        self.assertNotEqual(
            forward.internal_pubkey, swapped_roles.internal_pubkey
        )

    def test_address_decodes_to_output_script(self):
        for direction in SwapDirection:
            with self.subTest(direction=direction):
                contract = make_contract(direction)
                self.assertEqual(
                    contract.output_script,
                    address_to_script(contract.address()),
                )

    def test_cltv_uses_canonical_script_numbers(self):
        expected_suffixes = {
            1: "51b1",
            16: "60b1",
            17: "0111b1",
            127: "017fb1",
            128: "028000b1",
            NLOCKTIME_BLOCKHEIGHT_MAX: "04ff64cd1db1",
        }
        for locktime, suffix in expected_suffixes.items():
            with self.subTest(locktime=locktime):
                script = make_contract(locktime=locktime).refund_leaf_script
                self.assertTrue(script.hex().endswith(suffix))

    def test_contract_rejects_invalid_boundaries(self):
        invalid_calls = [
            lambda: make_contract(direction="forward"),
            lambda: make_contract(payment_hash=bytearray(32)),
            lambda: make_contract(payment_hash=bytes(31)),
            lambda: make_contract(locktime=True),
            lambda: make_contract(locktime=0),
            lambda: make_contract(locktime=NLOCKTIME_BLOCKHEIGHT_MAX + 1),
            lambda: make_contract(provider_pubkey=PROVIDER_PUBKEY[1:]),
            lambda: make_contract(provider_pubkey=b"\x04" + bytes(32)),
            lambda: make_contract(provider_pubkey=b"\x02" + b"\xff" * 32),
            lambda: make_contract(user_pubkey=PROVIDER_PUBKEY),
            lambda: make_contract(
                user_pubkey=b"\x03" + PROVIDER_PUBKEY[1:]
            ),
        ]
        for call in invalid_calls:
            with self.subTest(call=call):
                with self.assertRaises((TypeError, ValueError)):
                    call()

    def test_control_block_reference_vectors(self):
        vectors = {
            (SwapDirection.FORWARD, SwapLeaf.CLAIM): (
                "c03b46d262d2f610e9038b44beabdfe97ab5a0feb89870acc2264edfb7f63"
                "ec2eceb0b7997538e555615e4c0460ef19a4045cc07d87897f75c5a1475"
                "165c9efbb4"
            ),
            (SwapDirection.FORWARD, SwapLeaf.REFUND): (
                "c03b46d262d2f610e9038b44beabdfe97ab5a0feb89870acc2264edfb7f63"
                "ec2ec30f0249ca36c7b1baa9d607c8df543cb04160e76cd47100ca595f806"
                "af2c3de3"
            ),
            (SwapDirection.REVERSE, SwapLeaf.CLAIM): (
                "c03b46d262d2f610e9038b44beabdfe97ab5a0feb89870acc2264edfb7f63"
                "ec2ece2e90dbc4796d23159a2b8e349dda9ce48c9edcd4738cecb4a562aa0"
                "99c73fe4"
            ),
            (SwapDirection.REVERSE, SwapLeaf.REFUND): (
                "c03b46d262d2f610e9038b44beabdfe97ab5a0feb89870acc2264edfb7f63"
                "ec2ecb99ef483be975255d995eceac74f027a9146509c4b5217a44fb9a7d1"
                "6024dbf7"
            ),
        }
        for (direction, leaf), expected_control_block in vectors.items():
            with self.subTest(direction=direction, leaf=leaf):
                contract = make_contract(direction)
                script, control_block = contract.script_path(leaf)
                expected_script = (
                    contract.claim_leaf_script
                    if leaf is SwapLeaf.CLAIM
                    else contract.refund_leaf_script
                )
                self.assertEqual(expected_script, script)
                self.assertEqual(expected_control_block, control_block.hex())
                self.assertEqual(65, len(control_block))
                self.assertEqual(
                    LEAF_VERSION_TAPSCRIPT, control_block[0] & 0xFE
                )
                self.assertEqual(contract.internal_pubkey, control_block[1:33])

    def test_control_block_commits_odd_output_parity(self):
        contract = make_contract(locktime=800_003)
        _, control_block = contract.script_path(SwapLeaf.CLAIM)
        self.assertEqual(
            "5120f0bfbe2cdf78f18ce2a7ca9efad7eec2b20d7faa1950ab17d874c46c"
            "d17841b4",
            contract.output_script.hex(),
        )
        self.assertEqual(0xC1, control_block[0])

    def test_script_path_witness_order(self):
        signature = b"\x11" * 64
        for direction in SwapDirection:
            contract = make_contract(direction)
            claim_script, claim_control = contract.script_path(SwapLeaf.CLAIM)
            refund_script, refund_control = contract.script_path(
                SwapLeaf.REFUND
            )
            claim_witness = [signature, PREIMAGE, claim_script, claim_control]
            refund_witness = [signature, refund_script, refund_control]
            self.assertEqual(
                construct_witness(claim_witness),
                b"\x04"
                + witness_push(signature)
                + witness_push(PREIMAGE)
                + witness_push(claim_script)
                + witness_push(claim_control),
            )
            self.assertEqual(
                construct_witness(refund_witness),
                b"\x03"
                + witness_push(signature)
                + witness_push(refund_script)
                + witness_push(refund_control),
            )
            self.assertEqual(signature, claim_witness[0])
            self.assertEqual(PREIMAGE, claim_witness[1])
            self.assertEqual(claim_script, claim_witness[-2])
            self.assertEqual(signature, refund_witness[0])
            self.assertEqual(refund_script, refund_witness[-2])

    def test_script_path_rejects_untyped_leaf(self):
        with self.assertRaises(TypeError):
            make_contract().script_path("claim")


class TestContractValidation(ElectrumTestCase):
    def test_both_directions_accept_canonical_tree(self):
        for direction in SwapDirection:
            with self.subTest(direction=direction):
                contract = make_contract(direction)
                tree = contract.serialized_tree()
                claim_output = tree["claimLeaf"]["output"]
                tree["claimLeaf"]["output"] = claim_output.upper()
                contract.validate_provider_data(
                    serialized_tree=tree, address=contract.address()
                )

    def test_rejects_unexpected_leaves_and_fields(self):
        contract = make_contract()
        variants = []

        tree = contract.serialized_tree()
        tree["extraLeaf"] = tree["claimLeaf"].copy()
        variants.append(tree)

        tree = contract.serialized_tree()
        tree["claimLeaf"]["metadata"] = True
        variants.append(tree)

        for tree in variants:
            with self.subTest(tree=tree), self.assertRaisesRegex(
                ValueError, "only"
            ):
                contract.validate_provider_data(
                    serialized_tree=tree, address=contract.address()
                )

    def test_rejects_tree_and_address_tampering(self):
        contract = make_contract()
        tree = contract.serialized_tree()
        tree["claimLeaf"]["output"] = tree["refundLeaf"]["output"]
        with self.assertRaisesRegex(ValueError, "claimLeaf"):
            contract.validate_provider_data(
                serialized_tree=tree, address=contract.address()
            )

        tree = contract.serialized_tree()
        tree["claimLeaf"], tree["refundLeaf"] = (
            tree["refundLeaf"],
            tree["claimLeaf"],
        )
        with self.assertRaisesRegex(ValueError, "claimLeaf"):
            contract.validate_provider_data(
                serialized_tree=tree, address=contract.address()
            )

        with self.assertRaisesRegex(ValueError, "address"):
            contract.validate_provider_data(
                serialized_tree=contract.serialized_tree(),
                address=REVERSE_ADDRESS,
            )

    def test_rejects_wrong_contract_semantics(self):
        original = make_contract()
        variants = [
            make_contract(SwapDirection.REVERSE),
            make_contract(payment_hash=sha256(b"different payment")),
            make_contract(locktime=LOCKTIME + 1),
            make_contract(
                provider_pubkey=USER_PUBKEY, user_pubkey=PROVIDER_PUBKEY
            ),
        ]
        for variant in variants:
            with self.subTest(variant=variant):
                with self.assertRaises(ValueError):
                    variant.validate_provider_data(
                        serialized_tree=original.serialized_tree(),
                        address=original.address(),
                    )

    def test_rejects_malformed_serialized_tree(self):
        contract = make_contract()
        valid = contract.serialized_tree()
        malformed = [
            None,
            {},
            {"claimLeaf": None, "refundLeaf": valid["refundLeaf"]},
            {"claimLeaf": {}, "refundLeaf": valid["refundLeaf"]},
            {
                "claimLeaf": {"version": 0xC2, "output": "00"},
                "refundLeaf": valid["refundLeaf"],
            },
            {
                "claimLeaf": {"version": 0xC0, "output": []},
                "refundLeaf": valid["refundLeaf"],
            },
            {
                "claimLeaf": {"version": 0xC0, "output": "not hex"},
                "refundLeaf": valid["refundLeaf"],
            },
            {
                "claimLeaf": {"version": 0xC0, "output": "00" * 10_001},
                "refundLeaf": valid["refundLeaf"],
            },
        ]
        for tree in malformed:
            with self.subTest(tree=tree):
                with self.assertRaises(ValueError):
                    contract.validate_provider_data(
                        serialized_tree=tree, address=contract.address()
                    )

    def test_rejects_non_string_address(self):
        with self.assertRaises(TypeError):
            make_contract().validate_provider_data(
                serialized_tree=make_contract().serialized_tree(), address=None
            )


PROVIDER_SECKEY = bytes.fromhex(
    "b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef"
)
USER_SECKEY = bytes.fromhex(
    "c90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b14e5c9"
)
SIGNING_PROVIDER_PUBKEY = ECPrivkey(PROVIDER_SECKEY).get_public_key_bytes(
    compressed=True
)
SIGNING_USER_PUBKEY = ECPrivkey(USER_SECKEY).get_public_key_bytes(
    compressed=True
)
MSG32 = sha256(b"BIP341 key-path sighash fixture")


class TestMuSig2Session(ElectrumTestCase):
    def setUp(self):
        super().setUp()
        self.contract = make_contract(
            SwapDirection.REVERSE,
            provider_pubkey=SIGNING_PROVIDER_PUBKEY,
            user_pubkey=SIGNING_USER_PUBKEY,
        )

    def make_sessions(
        self, *, provider_msg=MSG32, user_msg=MSG32, user_session_id=None
    ):
        provider = MuSig2Session.create(
            contract=self.contract,
            local_seckey=PROVIDER_SECKEY,
            msg32=provider_msg,
        )
        user = MuSig2Session.create(
            contract=self.contract,
            local_seckey=USER_SECKEY,
            msg32=user_msg,
            session_id32=user_session_id,
        )
        return provider, user

    @staticmethod
    def exchange_partials(provider, user):
        provider_partial = provider.sign_partial(user.public_nonce)
        user_partial = user.sign_partial(provider.public_nonce)
        return provider_partial, user_partial

    def test_two_party_signature_verifies_for_funding_output(self):
        provider, user = self.make_sessions()
        provider_partial, user_partial = self.exchange_partials(provider, user)
        provider_signature = provider.aggregate(user_partial)
        user_signature = user.aggregate(provider_partial)
        self.assertEqual(provider_signature, user_signature)
        self.assertEqual(64, len(provider_signature))
        output_key = ECPubkey(b"\x02" + self.contract.output_script[2:])
        self.assertTrue(output_key.schnorr_verify(provider_signature, MSG32))
        self.assertEqual(
            b"\x01\x40" + provider_signature,
            construct_witness([provider_signature]),
        )

    def test_nonce_and_partial_wire_sizes(self):
        provider, user = self.make_sessions()
        self.assertEqual(66, len(provider.public_nonce))
        provider_partial, user_partial = self.exchange_partials(provider, user)
        self.assertEqual(32, len(provider_partial))
        self.assertEqual(32, len(user_partial))

    def test_public_nonces_follow_provider_first_key_order(self):
        provider, user = self.make_sessions()
        with patch(
            "electrum.taproot_swaps.musig.nonce_agg",
            wraps=musig.nonce_agg,
        ) as nonce_agg:
            provider.sign_partial(user.public_nonce)
            user.sign_partial(provider.public_nonce)

        provider_order, user_order = [
            [nonce.to_bytes() for nonce in call.args[0]]
            for call in nonce_agg.call_args_list
        ]
        expected_order = [provider.public_nonce, user.public_nonce]
        self.assertEqual(expected_order, provider_order)
        self.assertEqual(expected_order, user_order)

    def test_partial_signing_is_single_use_even_after_failure(self):
        provider, user = self.make_sessions()
        provider.sign_partial(user.public_nonce)
        self.assertIsNone(provider._local_seckey)
        self.assertIsNone(provider._secnonce)
        with self.assertRaisesRegex(RuntimeError, "already signed"):
            provider.sign_partial(user.public_nonce)

        provider, user = self.make_sessions()
        with patch(
            "electrum.taproot_swaps.musig.partial_sign",
            side_effect=RuntimeError("signing failed"),
        ), self.assertRaisesRegex(RuntimeError, "signing failed"):
            provider.sign_partial(user.public_nonce)
        self.assertIsNone(provider._local_seckey)
        self.assertIsNone(provider._secnonce)
        with self.assertRaisesRegex(RuntimeError, "already signed"):
            provider.sign_partial(user.public_nonce)

    def test_rejects_forged_partial_signature(self):
        provider, user = self.make_sessions()
        provider_partial, user_partial = self.exchange_partials(provider, user)
        forged = bytes([provider_partial[0] ^ 1]) + provider_partial[1:]
        with self.assertRaisesRegex(ValueError, "invalid"):
            user.aggregate(forged)
        self.assertEqual(64, len(user.aggregate(provider_partial)))
        self.assertEqual(64, len(provider.aggregate(user_partial)))

    def test_rejects_partial_from_different_nonce_session(self):
        provider, user = self.make_sessions()
        other_provider, other_user = self.make_sessions(
            user_session_id=b"\x01" * 32
        )
        provider.sign_partial(other_user.public_nonce)
        _, user_partial = self.exchange_partials(other_provider, user)
        with self.assertRaisesRegex(ValueError, "invalid"):
            provider.aggregate(user_partial)

    def test_rejects_message_mismatch(self):
        provider, user = self.make_sessions(user_msg=sha256(b"other message"))
        provider_partial, user_partial = self.exchange_partials(provider, user)
        with self.assertRaisesRegex(ValueError, "invalid"):
            provider.aggregate(user_partial)
        with self.assertRaisesRegex(ValueError, "invalid"):
            user.aggregate(provider_partial)

    def test_session_id_is_bound_into_nonce_generation(self):
        with patch(
            "electrum_ecc.musig.secrets.token_bytes",
            return_value=b"\x03" * 32,
        ):
            first = MuSig2Session.create(
                contract=self.contract,
                local_seckey=USER_SECKEY,
                msg32=MSG32,
                session_id32=b"\x01" * 32,
            )
            second = MuSig2Session.create(
                contract=self.contract,
                local_seckey=USER_SECKEY,
                msg32=MSG32,
                session_id32=b"\x02" * 32,
            )
        self.assertNotEqual(first.public_nonce, second.public_nonce)

    def test_rejects_aggregate_before_partial_and_bad_nonce(self):
        provider, _ = self.make_sessions()
        with self.assertRaisesRegex(RuntimeError, "sign_partial"):
            provider.aggregate(bytes(32))
        for nonce in (bytes(65), bytes(66), b"not bytes"):
            provider, _ = self.make_sessions()
            with self.subTest(nonce=nonce):
                with self.assertRaises((TypeError, ValueError)):
                    provider.sign_partial(nonce)

    def test_rejects_foreign_secret_and_invalid_inputs(self):
        stranger = bytes.fromhex("00" * 31 + "03")
        calls = [
            lambda: MuSig2Session.create(
                contract=object(), local_seckey=PROVIDER_SECKEY, msg32=MSG32
            ),
            lambda: MuSig2Session.create(
                contract=self.contract, local_seckey=stranger, msg32=MSG32
            ),
            lambda: MuSig2Session.create(
                contract=self.contract, local_seckey=bytes(32), msg32=MSG32
            ),
            lambda: MuSig2Session.create(
                contract=self.contract, local_seckey=bytearray(32), msg32=MSG32
            ),
            lambda: MuSig2Session.create(
                contract=self.contract,
                local_seckey=PROVIDER_SECKEY,
                msg32=bytes(31),
            ),
            lambda: MuSig2Session.create(
                contract=self.contract,
                local_seckey=PROVIDER_SECKEY,
                msg32=MSG32,
                session_id32=bytes(31),
            ),
            lambda: MuSig2Session.create(
                contract=self.contract,
                local_seckey=PROVIDER_SECKEY,
                msg32=MSG32,
                session_id32=bytearray(32),
            ),
        ]
        for call in calls:
            with self.subTest(call=call):
                with self.assertRaises((TypeError, ValueError)):
                    call()

    def test_direct_construction_is_rejected(self):
        with self.assertRaisesRegex(TypeError, "created with create"):
            MuSig2Session(
                contract=None,
                local_seckey=None,
                local_pubkey=None,
                counterparty_pubkey=None,
                msg32=None,
                keyagg_cache=None,
                secnonce=None,
                pubnonce=None,
            )

    def test_final_signature_is_verified(self):
        provider, user = self.make_sessions()
        _, user_partial = self.exchange_partials(provider, user)
        with patch(
            "electrum.taproot_swaps.musig.partial_sig_agg",
            return_value=bytes(64),
        ), self.assertRaisesRegex(ValueError, "does not verify"):
            provider.aggregate(user_partial)

    def test_aggregate_succeeds_once(self):
        provider, user = self.make_sessions()
        _, user_partial = self.exchange_partials(provider, user)
        self.assertEqual(64, len(provider.aggregate(user_partial)))
        with self.assertRaisesRegex(RuntimeError, "already aggregated"):
            provider.aggregate(user_partial)
