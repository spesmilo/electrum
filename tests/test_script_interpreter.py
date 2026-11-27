import json
import os
import random
from decimal import Decimal
from typing import List, Sequence, Tuple

import electrum_ecc as ecc
from electrum_ecc.util import bip340_tagged_hash

from electrum import script_interpreter as si
from electrum.script_interpreter import (
    ScriptError, ScriptFlags, SigVersion, PrecomputedTransactionData, TransactionSignatureChecker,
    ScriptVerificationError, MissingSpentOutputs,
    verify_script, verify_input,
    CONSENSUS_FLAGS, STANDARD_FLAGS, MEMPOOL_FLAGS,
)
from electrum.bitcoin import (
    opcodes, construct_witness, add_number_to_script, script_num_to_bytes, taproot_output_script,
    control_block_for_taproot_script_spend,
)
from electrum.crypto import sha256, hash_160
from electrum.transaction import (
    Transaction, TxInput, TxOutput, TxOutpoint, PartialTransaction, SerializationError, BCDataStream,
)
from electrum.util import bfh

from . import ElectrumTestCase


VECTORS_DIR = os.path.join(os.path.dirname(__file__), "bitcoin-core-vectors")
BIP341_VECTORS = os.path.join(os.path.dirname(__file__), "bip-0341", "wallet-test-vectors.json")
FULL_ASSETS_ENV = "ELECTRUM_SCRIPT_ASSETS_TEST_JSON"

MASK64 = (1 << 64) - 1
P2SH = int(ScriptFlags.P2SH)
WITNESS = int(ScriptFlags.WITNESS)
CLEANSTACK = int(ScriptFlags.CLEANSTACK)

# Core: ScriptFlagNamesToEnum
FLAG_NAMES = {name: int(flag) for name, flag in ScriptFlags.__members__.items() if name != 'NONE'}


def _load_json(name: str):
    with open(os.path.join(VECTORS_DIR, name), "r") as f:
        return json.load(f, parse_float=Decimal)


# --- ports of Bitcoin Core test helpers --------------------------------------------------

# Core: GetOpName, for the opcodes that ParseScript accepts by name (OP_RESERVED, OP_NOP..MAX_OPCODE)
_OP_NAMES = {int(op): op.name for op in opcodes if op == opcodes.OP_RESERVED or opcodes.OP_NOP <= op <= opcodes.OP_NOP10}
_OPCODE_BY_NAME = {}
for _op, _name in _OP_NAMES.items():
    _OPCODE_BY_NAME[_name] = _op
    _OPCODE_BY_NAME[_name[3:]] = _op  # Convenience: OP_ADD and just ADD are both recognized


def parse_script(s: str) -> bytes:
    """Core: ParseScript (core_io.cpp)"""
    result = bytearray()
    for w in s.replace('\t', ' ').replace('\n', ' ').split(' '):
        if not w:
            continue  # Empty string, ignore.
        if w.isdigit() or (w[0] == '-' and len(w) > 1 and w[1:].isdigit()):
            # Number
            num = int(w)
            # limit the range of numbers ParseScript accepts in decimal
            # since numbers outside -0xFFFFFFFF...0xFFFFFFFF are illegal in scripts
            if not (-0xffffffff <= num <= 0xffffffff):
                raise ValueError("script parse error: decimal numeric value only allowed in the "
                                 "range -0xFFFFFFFF...0xFFFFFFFF")
            result += add_number_to_script(num)  # Core: CScript::push_int64
        elif w.startswith("0x") and len(w) > 2 and len(w) % 2 == 0 and all(c in '0123456789abcdefABCDEF' for c in w[2:]):
            # Raw hex data, inserted NOT pushed onto stack:
            result += bytes.fromhex(w[2:])
        elif len(w) >= 2 and w[0] == "'" and w[-1] == "'":
            # Single-quoted string, pushed as data.
            result += si._push_data(w[1:-1].encode('latin-1'))
        else:
            # opcode, e.g. OP_ADD or ADD:
            if w not in _OPCODE_BY_NAME:
                raise ValueError(f"script parse error: unknown opcode {w!r}")
            result.append(_OPCODE_BY_NAME[w])
    return bytes(result)


def parse_script_flags(s: str) -> int:
    """Core: ParseScriptFlags (transaction_tests.cpp)"""
    flags = 0
    if not s or s == "NONE":
        return flags
    for word in s.split(','):
        flags |= FLAG_NAMES[word]  # KeyError: "Bad test: unknown verification flag"
    return flags


def amount_from_value(v) -> int:
    """Core: AmountFromValue (BTC amount to satoshis)"""
    sats = Decimal(v) * 100_000_000
    assert sats == int(sats)
    return int(sats)


def make_tx(version: int, vin: Sequence[Tuple[bytes, int, bytes, int, Sequence[bytes]]],
            vout: Sequence[Tuple[int, bytes]], locktime: int) -> Transaction:
    """Transaction from its fields."""
    tx = Transaction(None)
    tx._inputs = [TxInput(prevout=TxOutpoint(txid=txid, out_idx=n), script_sig=script_sig, nsequence=seq,
                          witness=construct_witness(list(wit)) if wit else None)
                  for txid, n, script_sig, seq, wit in vin]
    tx._outputs = [TxOutput(scriptpubkey=spk, value=value) for value, spk in vout]
    tx._version = version
    tx._locktime = locktime
    return tx


def deserialize_tx(raw: bytes, *, allow_witness: bool = True) -> Transaction:
    """Core: UnserializeTransaction (TX_WITH_WITNESS / TX_NO_WITNESS).
    Returns the Transaction of Electrum's own parser, after cross-checking it."""
    r = BCDataStream()
    r.write(raw)
    version = r.read_uint32()

    def var_bytes():
        return r.read_bytes(r.read_compact_size())

    def read_vin():
        return [[r.read_bytes(32)[::-1], r.read_uint32(), var_bytes(), r.read_uint32(), []]
                for _ in range(r.read_compact_size())]

    def read_vout():
        return [(r.read_int64(), var_bytes()) for _ in range(r.read_compact_size())]

    flags = 0
    vin = read_vin()
    vout = []
    if len(vin) == 0 and allow_witness:
        # We read a dummy or an empty vin.
        flags = r.read_bytes(1)[0]
        if flags != 0:
            vin = read_vin()
            vout = read_vout()
    else:
        # We read a non-empty vin. Assume a normal vout follows.
        vout = read_vout()
    if flags & 1 and allow_witness:
        # The witness flag is present, and we support witnesses.
        flags ^= 1
        for txin in vin:
            txin[4] = [var_bytes() for _ in range(r.read_compact_size())]
        if not any(txin[4] for txin in vin):
            raise ValueError("Superfluous witness record")
    if flags:
        raise ValueError("Unknown transaction optional data")
    locktime = r.read_uint32()

    tx = Transaction(raw[:r.read_cursor])
    # cross-check Electrum's parser
    assert tx.version & 0xffffffff == version and tx.locktime == locktime
    assert [(o.value, o.scriptpubkey) for o in tx.outputs()] == vout
    assert [[i.prevout.txid, i.prevout.out_idx, i.script_sig, i.nsequence, i.witness_elements()]
            for i in tx.inputs()] == vin
    return tx


def build_crediting_and_spending_tx(script_pubkey: bytes, script_sig: bytes, witness: List[bytes],
                                    value: int) -> Tuple[Transaction, Transaction]:
    """Core: BuildCreditingTransaction, BuildSpendingTransaction (test/util/transaction_utils.cpp)"""
    credit = make_tx(1, [(bytes(32), 0xffffffff, b'\x00\x00', 0xffffffff, [])], [(value, script_pubkey)], 0)
    spend = make_tx(1, [(bfh(credit.txid()), 0, script_sig, 0xffffffff, witness)], [(value, b'')], 0)
    return credit, spend


class TaprootBuilder:
    """Single leaf at depth 0, which is all that script_tests.json needs (#CONTROLBLOCK#, #TAPROOTOUTPUT#)."""
    INTERNAL_KEY = ecc.GENERATOR.get_public_key_bytes()[1:]  # Core: keys.key0, the private key 1

    def __init__(self, script: bytes):
        script_tree = (si.TAPROOT_LEAF_TAPSCRIPT, script)
        _, self.control_block = control_block_for_taproot_script_spend(
            internal_pubkey=self.INTERNAL_KEY, script_tree=script_tree, script_num=0)
        self.output_script = taproot_output_script(self.INTERNAL_KEY, script_tree=script_tree)


class CachingSignatureChecker(TransactionSignatureChecker):
    """Core: CachingTransactionSignatureChecker. Only caches valid signatures, like Core's SignatureCache."""
    _cache = set()

    def VerifyECDSASignature(self, sig, pubkey, sighash):
        key = (b'e', bytes(sig), bytes(pubkey), sighash)
        if key in self._cache:
            return True
        ok = super().VerifyECDSASignature(sig, pubkey, sighash)
        if ok:
            self._cache.add(key)
        return ok

    def VerifySchnorrSignature(self, sig, pubkey, sighash):
        key = (b's', bytes(sig), bytes(pubkey), sighash)
        if key in self._cache:
            return True
        ok = super().VerifySchnorrSignature(sig, pubkey, sighash)
        if ok:
            self._cache.add(key)
        return ok


# Core: TrimFlags, FillFlags, ExcludeIndividualFlags (transaction_tests.cpp), on uint64 flags
def trim_flags(flags: int) -> int:
    # WITNESS requires P2SH
    if not flags & P2SH:
        flags &= ~WITNESS & MASK64
    # CLEANSTACK requires WITNESS (and transitively CLEANSTACK requires P2SH)
    if not flags & WITNESS:
        flags &= ~CLEANSTACK & MASK64
    assert si.is_valid_flag_combination(flags)
    return flags


def fill_flags(flags: int) -> int:
    # CLEANSTACK implies WITNESS
    if flags & CLEANSTACK:
        flags |= WITNESS
    # WITNESS implies P2SH (and transitively CLEANSTACK implies P2SH)
    if flags & WITNESS:
        flags |= P2SH
    assert si.is_valid_flag_combination(flags)
    return flags


def exclude_individual_flags(flags: int) -> set:
    combos = set()
    for flag in FLAG_NAMES.values():
        flags_excluding_one = trim_flags(flags & ~flag & MASK64)
        if flags != flags_excluding_one:
            combos.add(flags_excluding_one)
    return combos


def inv(flags: int) -> int:
    return ~flags & MASK64


def all_consensus_flags() -> List[int]:
    """Core: AllConsensusFlags (script_assets_tests.cpp)"""
    ret = []
    for i in range(128):
        bits = (ScriptFlags.P2SH, ScriptFlags.DERSIG, ScriptFlags.NULLDUMMY, ScriptFlags.CHECKLOCKTIMEVERIFY,
                ScriptFlags.CHECKSEQUENCEVERIFY, ScriptFlags.WITNESS, ScriptFlags.TAPROOT)
        flag = 0
        for j, bit in enumerate(bits):
            if i & (1 << j):
                flag |= bit
        # SCRIPT_VERIFY_WITNESS requires SCRIPT_VERIFY_P2SH
        if flag & ScriptFlags.WITNESS and not flag & ScriptFlags.P2SH:
            continue
        # SCRIPT_VERIFY_TAPROOT requires SCRIPT_VERIFY_WITNESS
        if flag & ScriptFlags.TAPROOT and not flag & ScriptFlags.WITNESS:
            continue
        ret.append(int(flag))
    return ret


ALL_CONSENSUS_FLAGS = all_consensus_flags()


def asset_test(test: dict) -> List[str]:
    """Core: AssetTest (script_assets_tests.cpp). Returns a list of failure descriptions."""
    failures = []
    tx = deserialize_tx(bytes.fromhex(test["tx"]), allow_witness=False)
    prevouts = [TxOutput.from_network_bytes(bytes.fromhex(p)) for p in test["prevouts"]]
    assert len(prevouts) == len(tx.inputs())
    idx = test["index"]
    test_flags = parse_script_flags(test["flags"])
    fin = test.get("final", False)
    for key, expect_ok in (("success", True), ("failure", False)):
        if key not in test:
            continue
        txin = tx.inputs()[idx]
        txin.script_sig = bytes.fromhex(test[key]["scriptSig"])
        txin.witness = construct_witness([bytes.fromhex(x) for x in test[key]["witness"]])
        txdata = PrecomputedTransactionData(tx, prevouts)
        checker = CachingSignatureChecker(txdata, idx, prevouts[idx].value)
        for flags in ALL_CONSENSUS_FLAGS:
            if expect_ok:
                # "final": true tests are valid for all flags. Others are only valid with flags that are
                # a subset of test_flags.
                if not (fin or (flags & test_flags) == flags):
                    continue
            else:
                # If a test is supposed to fail with test_flags, it should also fail with any superset thereof.
                if (flags & test_flags) != test_flags:
                    continue
            err = verify_script(txin.script_sig, prevouts[idx].scriptpubkey, txin.witness_elements(), flags, checker)
            if (err == ScriptError.OK) != expect_ok:
                failures.append(f"{test['comment']}: {key} with flags {flags:#x} gave {err.name}")
    return failures


class TestScriptInterpreterCoreVectors(ElectrumTestCase):
    """Bitcoin Core's own test vectors, run with Core's test logic."""

    def test_script_tests_json(self):
        """Core: script_json_test, DoTest (script_tests.cpp)"""
        tests = _load_json("script_tests.json")
        rng = random.Random(1)
        failures = []
        n_run = 0
        for test in tests:
            str_test = json.dumps(test, default=str)
            witness = []
            value = 0
            pos = 0
            taproot_builder = None
            if len(test) > 0 and isinstance(test[pos], list):
                for element in test[pos][:-1]:
                    # We use #SCRIPT# to flag a non-hex script that we can read using ParseScript
                    if element.startswith("#SCRIPT#"):
                        witness.append(parse_script(element[len("#SCRIPT#"):]))
                    elif element == "#CONTROLBLOCK#":
                        # Taproot script control block - second from the last element in witness stack
                        taproot_builder = TaprootBuilder(witness[-1])
                        witness.append(taproot_builder.control_block)
                    else:
                        witness.append(bytes.fromhex(element))
                value = amount_from_value(test[pos][-1])
                pos += 1
            if len(test) < 4 + pos:  # Allow size > 3; extra stuff ignored (useful for comments)
                self.assertEqual(1, len(test), f"Bad test: {str_test}")
                continue
            script_sig = parse_script(test[pos])
            pos += 1
            if test[pos] == "0x51 0x20 #TAPROOTOUTPUT#":
                self.assertIsNotNone(taproot_builder)
                script_pubkey = taproot_builder.output_script
            else:
                script_pubkey = parse_script(test[pos])
            pos += 1
            flags = parse_script_flags(test[pos])
            pos += 1
            expected = ScriptError[test[pos]]
            n_run += 1
            failures += self._do_test(script_pubkey, script_sig, witness, flags, str_test, expected, value, rng)
        self.assertEqual([], failures)
        self.assertGreater(n_run, 1200)

    @staticmethod
    def _do_test(script_pubkey: bytes, script_sig: bytes, witness: List[bytes], flags: int, message: str,
                 expected: ScriptError, value: int, rng: random.Random) -> List[str]:
        failures = []
        expect = expected == ScriptError.OK
        if flags & CLEANSTACK:
            flags |= P2SH | WITNESS
        credit, spend = build_crediting_and_spending_tx(script_pubkey, script_sig, witness, value)
        txdata = PrecomputedTransactionData(spend, credit.outputs())
        checker = TransactionSignatureChecker(txdata, 0, value)
        err = verify_script(script_sig, script_pubkey, witness, flags, checker)
        if err != expected:
            failures.append(f"{err.name} where {expected.name} expected: {message}")
        # Verify that removing flags from a passing test or adding flags to a failing test does not change the result.
        for i in range(256):
            extra_flags = rng.getrandbits(si.MAX_SCRIPT_VERIFY_FLAGS_BITS)
            combined_flags = (flags & ~extra_flags) if expect else (flags | extra_flags)
            # Weed out some invalid flag combinations.
            if combined_flags & CLEANSTACK and ~combined_flags & (P2SH | WITNESS):
                continue
            if combined_flags & WITNESS and ~combined_flags & P2SH:
                continue
            checker = CachingSignatureChecker(txdata, 0, value)
            err = verify_script(script_sig, script_pubkey, witness, combined_flags, checker)
            if (err == ScriptError.OK) != expect:
                failures.append(f"{err.name} with flags {combined_flags:#x}: {message}")
        return failures

    @staticmethod
    def _read_tx_test(test) -> Tuple[Transaction, List[TxOutput]]:
        prevouts = {}
        for vinput in test[0]:
            assert isinstance(vinput, list) and 3 <= len(vinput) <= 4, f"Bad test: {test}"
            outpoint = (bytes.fromhex(vinput[0]), vinput[1] & 0xffffffff)
            amount = vinput[3] if len(vinput) >= 4 else 0  # Core: amount 0 if not given
            prevouts[outpoint] = TxOutput(scriptpubkey=parse_script(vinput[2]), value=amount)
        tx = deserialize_tx(bytes.fromhex(test[1]))
        spent_outputs = [prevouts[(txin.prevout.txid, txin.prevout.out_idx)] for txin in tx.inputs()]
        return tx, spent_outputs

    @staticmethod
    def _check_tx_scripts(txdata: PrecomputedTransactionData, flags: int, expect_valid: bool) -> bool:
        """Core: CheckTxScripts"""
        tx_valid = True
        for i in range(len(txdata.vin)):
            try:
                verify_input(txdata, i, flags=flags)
            except ScriptVerificationError as e:
                assert e.error != ScriptError.OK and e.txin_index == i
                tx_valid = False
                break
        return tx_valid == expect_valid

    def test_tx_valid_json(self):
        """Core: tx_valid (transaction_tests.cpp)"""
        tests = _load_json("tx_valid.json")
        rng = random.Random(2)
        failures = []
        n_run = 0
        for test in tests:
            if not isinstance(test[0], list):
                continue
            n_run += 1
            str_test = json.dumps(test)
            self.assertTrue(len(test) == 3 and isinstance(test[1], str) and isinstance(test[2], str), str_test)
            tx, spent_outputs = self._read_tx_test(test)
            txdata = PrecomputedTransactionData(tx, spent_outputs)
            verify_flags = parse_script_flags(test[2])
            # Check that the test gives a valid combination of flags (otherwise VerifyScript will throw). Don't edit the flags.
            self.assertEqual(inv(verify_flags), fill_flags(inv(verify_flags)), f"Bad test flags: {str_test}")
            if not self._check_tx_scripts(txdata, inv(verify_flags), True):
                failures.append(f"Tx unexpectedly failed: {str_test}")
            # Backwards compatibility of script verification flags: Removing any flag(s) should not invalidate a valid transaction
            for name, flag in FLAG_NAMES.items():
                # Removing individual flags
                flags = trim_flags(inv(verify_flags | flag))
                if not self._check_tx_scripts(txdata, flags, True):
                    failures.append(f"Tx unexpectedly failed with flag {name} unset: {str_test}")
                # Removing random combinations of flags
                flags = trim_flags(inv(verify_flags | rng.getrandbits(si.MAX_SCRIPT_VERIFY_FLAGS_BITS)))
                if not self._check_tx_scripts(txdata, flags, True):
                    failures.append(f"Tx unexpectedly failed with random flags {flags}: {str_test}")
            # Check that flags are maximal: transaction should fail if any unset flags are set.
            for flags_excluding_one in exclude_individual_flags(verify_flags):
                if not self._check_tx_scripts(txdata, inv(flags_excluding_one), False):
                    failures.append(f"Too many flags unset: {str_test}")
        self.assertEqual([], failures)
        self.assertEqual(121, n_run)

    def test_tx_invalid_json(self):
        """Core: tx_invalid (transaction_tests.cpp)"""
        tests = _load_json("tx_invalid.json")
        rng = random.Random(3)
        failures = []
        n_run = 0
        for test in tests:
            if not isinstance(test[0], list):
                continue
            if test[2] == "BADTX":
                continue  # expected to fail Core's CheckTransaction, which is not part of the script interpreter
            n_run += 1
            str_test = json.dumps(test)
            self.assertTrue(len(test) == 3 and isinstance(test[1], str) and isinstance(test[2], str), str_test)
            tx, spent_outputs = self._read_tx_test(test)
            txdata = PrecomputedTransactionData(tx, spent_outputs)
            verify_flags = parse_script_flags(test[2])
            # Check that the test gives a valid combination of flags (otherwise VerifyScript will throw). Don't edit the flags.
            self.assertEqual(verify_flags, fill_flags(verify_flags), f"Bad test flags: {str_test}")
            # Not using FillFlags() in the main test, in order to detect invalid verifyFlags combination
            if not self._check_tx_scripts(txdata, verify_flags, False):
                failures.append(f"Tx unexpectedly passed: {str_test}")
            # Backwards compatibility of script verification flags: Adding any flag(s) should not validate an invalid transaction
            for name, flag in FLAG_NAMES.items():
                # Adding individual flags
                flags = fill_flags(verify_flags | flag)
                if not self._check_tx_scripts(txdata, flags, False):
                    failures.append(f"Tx unexpectedly passed with flag {name} set: {str_test}")
                # Adding random combinations of flags
                flags = fill_flags(verify_flags | rng.getrandbits(si.MAX_SCRIPT_VERIFY_FLAGS_BITS))
                if not self._check_tx_scripts(txdata, flags, False):
                    failures.append(f"Tx unexpectedly passed with random flags {flags}: {str_test}")
            # Check that flags are minimal: transaction should succeed if any set flags are unset.
            for flags_excluding_one in exclude_individual_flags(verify_flags):
                if not self._check_tx_scripts(txdata, flags_excluding_one, True):
                    failures.append(f"Too many flags set: {str_test}")
        self.assertEqual([], failures)
        self.assertEqual(84, n_run)

    def test_sighash_json(self):
        """Core: sighash_from_data (sighash_tests.cpp)"""
        tests = _load_json("sighash.json")
        failures = []
        n_run = 0
        for test in tests:
            if len(test) == 1:
                continue  # comment
            raw_tx, raw_script, n_in, hash_type, sighash_hex = test
            tx = deserialize_tx(bytes.fromhex(raw_tx))
            sh = si.SignatureHash(bytes.fromhex(raw_script), PrecomputedTransactionData(tx), n_in, hash_type, 0, SigVersion.BASE)
            n_run += 1
            if sh[::-1].hex() != sighash_hex:  # Core: uint256::GetHex() is byte-reversed
                failures.append(json.dumps(test))
        self.assertEqual([], failures)
        self.assertEqual(500, n_run)

    def test_script_assets_subset(self):
        """Core: script_assets_test, on a vendored subset of qa-assets' script_assets_test.json"""
        tests = _load_json("script_assets_test_subset.json")
        failures = []
        for test in tests:
            failures += asset_test(test)
        self.assertEqual([], failures)
        self.assertEqual(159, len(tests))

    def test_script_assets_full(self):
        """The full qa-assets file (9 MB, not vendored); set ELECTRUM_SCRIPT_ASSETS_TEST_JSON to its path."""
        path = os.environ.get(FULL_ASSETS_ENV)
        if not path:
            self.skipTest(f"{FULL_ASSETS_ENV} not set")
        with open(path, "r") as f:
            tests = json.load(f)
        failures = []
        for test in tests:
            failures += asset_test(test)
        self.assertEqual([], failures)
        self.assertGreater(len(tests), 0)

    def test_bip341_wallet_vectors(self):
        """Core: bip341_keypath_test_vectors (script_tests.cpp), plus verification of the signed txs"""
        with open(BIP341_VECTORS, "r") as f:
            vectors = json.load(f)
        self.assertTrue(len(vectors["keyPathSpending"]) > 0)
        n_inputs = 0
        for vec in vectors["keyPathSpending"]:
            tx = Transaction(vec["given"]["rawUnsignedTx"])
            utxos = [TxOutput(scriptpubkey=bfh(u["scriptPubKey"]), value=u["amountSats"])
                     for u in vec["given"]["utxosSpent"]]
            txdata = PrecomputedTransactionData(tx, utxos)
            inter = vec["intermediary"]
            self.assertEqual(inter["hashAmounts"], txdata.spent_amounts_single_hash.hex())
            self.assertEqual(inter["hashOutputs"], txdata.outputs_single_hash.hex())
            self.assertEqual(inter["hashPrevouts"], txdata.prevouts_single_hash.hex())
            self.assertEqual(inter["hashScriptPubkeys"], txdata.spent_scripts_single_hash.hex())
            self.assertEqual(inter["hashSequences"], txdata.sequences_single_hash.hex())

            signed_tx = Transaction(vec["auxiliary"]["fullySignedTx"])
            signed_txdata = PrecomputedTransactionData(signed_tx, utxos)
            # Electrum's own signing code
            psbt = PartialTransaction.from_tx(Transaction(vec["given"]["rawUnsignedTx"]))
            for txin, utxo in zip(psbt.inputs(), utxos):
                txin.witness_utxo = utxo
            for inp in vec["inputSpending"]:
                n_inputs += 1
                txin_index = inp["given"]["txinIndex"]
                hash_type = inp["given"]["hashType"]
                execdata = si.ScriptExecutionData()
                execdata.annex_present = False
                sighash = si.SignatureHashSchnorr(execdata, txdata, txin_index, hash_type, SigVersion.TAPROOT)
                self.assertEqual(inp["intermediary"]["sigHash"], sighash.hex())
                sig_msg = bfh(inp["intermediary"]["sigMsg"])
                self.assertEqual(inp["intermediary"]["sigHash"], bip340_tagged_hash(b"TapSighash", sig_msg).hex())
                # the fully signed key-path spend verifies...
                self.assertEqual(inp["expected"]["witness"], [w.hex() for w in signed_tx.inputs()[txin_index].witness_elements()])
                verify_input(signed_txdata, txin_index, flags=CONSENSUS_FLAGS)
                verify_input(signed_txdata, txin_index, flags=MEMPOOL_FLAGS)
                # ... but cannot be verified if the output spent by another input is unknown: its signature commits to it
                partial_utxos = [utxo if i == txin_index else None for i, utxo in enumerate(utxos)]
                with self.assertRaises(MissingSpentOutputs):
                    verify_input(PrecomputedTransactionData(signed_tx, partial_utxos), txin_index, flags=CONSENSUS_FLAGS)
                # ... and stops verifying if one bit of its signature is flipped
                bad_tx = Transaction(vec["auxiliary"]["fullySignedTx"])
                sig = bytearray(bfh(inp["expected"]["witness"][0]))
                sig[n_inputs % 64] ^= 1 << (n_inputs % 8)
                bad_tx.inputs()[txin_index].witness = construct_witness([bytes(sig)])
                with self.assertRaises(ScriptVerificationError) as ctx:
                    verify_input(PrecomputedTransactionData(bad_tx, utxos), txin_index, flags=CONSENSUS_FLAGS)
                self.assertEqual(ScriptError.SCHNORR_SIG, ctx.exception.error)
                self.assertEqual(txin_index, ctx.exception.txin_index)
                # Electrum's signature (it signs with the sighash type given in the vector)
                ptxin = psbt.inputs()[txin_index]
                ptxin.sighash = hash_type
                ptxin.tap_merkle_root = bfh(inp["given"]["merkleRoot"]) if inp["given"]["merkleRoot"] else None
                sig = psbt.sign_txin(txin_index, bfh(inp["given"]["internalPrivkey"]))
                bad_tx.inputs()[txin_index].witness = construct_witness([sig])
                verify_input(PrecomputedTransactionData(bad_tx, utxos), txin_index, flags=CONSENSUS_FLAGS)
        self.assertEqual(7, n_inputs)


class TestScriptInterpreter(ElectrumTestCase):

    def test_find_and_delete(self):
        """Core: script_FindAndDelete (script_tests.cpp)"""
        def check(s, d, n, expect):
            self.assertEqual((expect, n), si.FindAndDelete(s, d))
        check(bfh("5152"), b'', 0, bfh("5152"))  # delete nothing should be a no-op
        check(bfh("515253"), bfh("52"), 1, bfh("5153"))
        check(bfh("535153535453"), bfh("53"), 4, bfh("5154"))
        check(bfh("0302ff03"), bfh("0302ff03"), 1, b'')
        check(bfh("0302ff030302ff03"), bfh("0302ff03"), 2, b'')
        check(bfh("0302ff030302ff03"), bfh("02"), 0, bfh("0302ff030302ff03"))  # FindAndDelete matches entire opcodes
        check(bfh("0302ff030302ff03"), bfh("ff"), 0, bfh("0302ff030302ff03"))
        # This is an odd edge case: strip of the push-three-bytes prefix, leaving 02ff03 which is push-two-bytes:
        check(bfh("0302ff030302ff03"), bfh("03"), 2, bfh("02ff0302ff03"))
        # Byte sequence that spans multiple opcodes:
        check(bfh("02feed5169"), bfh("feed51"), 0, bfh("02feed5169"))  # doesn't match 'inside' opcodes
        check(bfh("02feed5169"), bfh("02feed51"), 1, bfh("69"))
        check(bfh("516902feed5169"), bfh("feed51"), 0, bfh("516902feed5169"))
        check(bfh("516902feed5169"), bfh("02feed51"), 1, bfh("516969"))
        check(bfh("00005151"), bfh("0051"), 1, bfh("0051"))  # FindAndDelete is single-pass
        check(bfh("000051005151"), bfh("0051"), 2, bfh("0051"))  # FindAndDelete is single-pass
        # Another weird edge case: end with invalid push (not enough data)...
        check(bfh("0003feed"), bfh("03feed"), 1, bfh("00"))  # ... can remove the invalid push
        check(bfh("0003feed"), bfh("00"), 1, bfh("03feed"))

    def test_scriptnum(self):
        for n in (0, 1, -1, 127, 128, -128, 255, -255, 256, 0x7fffffff, -0x7fffffff, 0xffffffff, 2**39 - 1):
            enc = script_num_to_bytes(n)
            self.assertEqual(n, si.CScriptNum(enc, True, 5))
        self.assertEqual(0, si.CScriptNum(b'\x80', False))  # negative zero
        with self.assertRaises(si.ScriptNumError):
            si.CScriptNum(b'\x80', True)
        with self.assertRaises(si.ScriptNumError):
            si.CScriptNum(b'\x01\x00', True)
        self.assertEqual(-255, si.CScriptNum(b'\xff\x80', True))
        with self.assertRaises(si.ScriptNumError):
            si.CScriptNum(bytes(5), False)

    def test_serialize_script_code(self):
        # OP_CODESEPARATORs are removed
        self.assertEqual(bfh("02" "5151"), si.SerializeScriptCode(bfh("51ab51")))
        # pushed 0xab bytes are kept
        self.assertEqual(bfh("02" "01ab"), si.SerializeScriptCode(bfh("01ab")))
        # Core quirk: a truncated push keeps the original length but only writes up to where GetOp failed
        self.assertEqual(bfh("02" "02"), si.SerializeScriptCode(bfh("0200")))
        self.assertEqual(bfh("02" "02"), si.SerializeScriptCode(bfh("ab0200")))
        # the same for OP_PUSHDATA1/2/4: their pushed 0xab bytes are kept
        self.assertEqual(bfh("03" "4c01ab"), si.SerializeScriptCode(bfh("ab4c01ab")))
        self.assertEqual(bfh("04" "4d0100ab"), si.SerializeScriptCode(bfh("ab4d0100ab")))
        self.assertEqual(bfh("06" "4e01000000ab"), si.SerializeScriptCode(bfh("ab4e01000000ab")))
        # and if their length bytes are truncated, GetOp fails right after the opcode:
        # https://github.com/bitcoin/bitcoin/blob/3f9c55426a12a16bd11de6dec139c4df58788360/src/script/script.cpp#L333-L352
        self.assertEqual(bfh("01" "4c"), si.SerializeScriptCode(bfh("4c")))
        self.assertEqual(bfh("02" "4d"), si.SerializeScriptCode(bfh("4d00")))
        self.assertEqual(bfh("04" "4e"), si.SerializeScriptCode(bfh("4e000000")))

    def test_compute_tapbranch_tapleaf(self):
        """Core: compute_tapbranch, compute_tapleaf (script_tests.cpp); uint256 hex is byte-reversed"""
        hash1 = bfh("8ad69ec7cf41c2a4001fd1f738bf1e505ce2277acdcaa63fe4765192497f47a7")[::-1]
        hash2 = bfh("f224a923cd0021ab202ab139cc56802ddb92dcfc172b9212261a539df79a112a")[::-1]
        result = bfh("a64c5b7b943315f9b805d7a7296bedfcfd08919270a1f7a1466e98f8693d8cd9")[::-1]
        self.assertEqual(result, si.ComputeTapbranchHash(hash1, hash2))
        self.assertEqual(bfh("edbc10c272a1215dcdcc11d605b9027b5ad6ed97cd45521203f136767b5b9c06")[::-1],
                         si.ComputeTapleafHash(0xc0, b"foobar"))
        self.assertEqual(bfh("8b5c4f90ae6bf76e259dbef5d8a59df06359c391b59263741b25eca76451b27a")[::-1],
                         si.ComputeTapleafHash(0xc2, b"foobar"))

    def test_low_s_boundary(self):
        def der(r: int, s: int) -> bytes:
            def der_int(x):
                b = x.to_bytes(33, 'big').lstrip(b'\x00')
                return b'\x02' + bytes((len(b) + (b[0] >= 0x80),)) + (b'\x00' if b[0] >= 0x80 else b'') + b
            body = der_int(r) + der_int(s)
            return b'\x30' + bytes((len(body),)) + body + b'\x01'
        half_n = ecc.CURVE_ORDER // 2
        self.assertEqual(ScriptError.OK, si.CheckSignatureEncoding(der(1, half_n), ScriptFlags.LOW_S))
        self.assertEqual(ScriptError.SIG_HIGH_S, si.CheckSignatureEncoding(der(1, half_n + 1), ScriptFlags.LOW_S))
        # Core: an overflowing S parses as the zero signature, which is not "high"
        self.assertEqual(ScriptError.OK, si.CheckSignatureEncoding(der(1, ecc.CURVE_ORDER), ScriptFlags.LOW_S))

    def test_pay_to_anchor(self):
        p2a = bfh("51024e73")
        p2sh_p2a = b'\xa9\x14' + hash_160(p2a) + b'\x87'
        flags = STANDARD_FLAGS
        credit, spend = build_crediting_and_spending_tx(p2a, b'', [], 0)
        verify_input(PrecomputedTransactionData(spend, credit.outputs()), 0, flags=flags)
        # P2A is only special when not P2SH-wrapped
        credit, spend = build_crediting_and_spending_tx(p2sh_p2a, si._push_data(p2a), [], 0)
        verify_input(PrecomputedTransactionData(spend, credit.outputs()), 0, flags=CONSENSUS_FLAGS)
        with self.assertRaises(ScriptVerificationError) as ctx:
            verify_input(PrecomputedTransactionData(spend, credit.outputs()), 0, flags=flags)
        self.assertEqual(ScriptError.DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM, ctx.exception.error)
        # other 2-byte v1 programs are upgradable
        credit, spend = build_crediting_and_spending_tx(bfh("51024e74"), b'', [], 0)
        with self.assertRaises(ScriptVerificationError) as ctx:
            verify_input(PrecomputedTransactionData(spend, credit.outputs()), 0, flags=flags)
        self.assertEqual(ScriptError.DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM, ctx.exception.error)

    def _verify(self, script_pubkey: bytes, script_sig: bytes = b'', witness: Sequence[bytes] = (), flags: int = CONSENSUS_FLAGS) -> ScriptError:
        credit, spend = build_crediting_and_spending_tx(script_pubkey, script_sig, list(witness), 0)
        try:
            verify_input(PrecomputedTransactionData(spend, credit.outputs()), 0, flags=flags)
        except ScriptVerificationError as e:
            return e.error
        return ScriptError.OK

    def test_edge_cases_not_in_core_vectors(self):
        # OP_DEPTH does not count the altstack
        self.assertEqual(ScriptError.OK, self._verify(parse_script("1 TOALTSTACK DEPTH 0 EQUAL")))
        # IsPushOnly treats OP_RESERVED as a push; it fails when executed instead
        self.assertEqual(ScriptError.BAD_OPCODE, self._verify(b'\x51', b'\x50', flags=ScriptFlags.SIGPUSHONLY))
        # CONST_SCRIPTCODE rejects OP_CODESEPARATOR even in an unexecuted branch (only in legacy scripts)
        self.assertEqual(ScriptError.OP_CODESEPARATOR, self._verify(parse_script("0 IF CODESEPARATOR ENDIF 1"), flags=STANDARD_FLAGS))
        self.assertEqual(ScriptError.OK, self._verify(parse_script("0 IF CODESEPARATOR ENDIF 1"), flags=CONSENSUS_FLAGS))
        # 40-byte witness programs are witness programs (anyone-can-spend if not v0), 41-byte ones are not
        prog40 = b'\x52\x28' + b'\x01' * 40
        self.assertEqual(ScriptError.OK, self._verify(prog40, witness=[b'\x01']))
        self.assertEqual(ScriptError.DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM, self._verify(prog40, witness=[b'\x01'], flags=STANDARD_FLAGS))
        self.assertEqual(ScriptError.WITNESS_UNEXPECTED, self._verify(b'\x52\x29' + b'\x01' * 41, witness=[b'\x01']))
        # STRICTENC: hash types other than 1-3 (with or without ANYONECANPAY) are undefined
        sig = bfh("3006020101020101")
        for hash_type, err in ((0x01, ScriptError.OK), (0x83, ScriptError.OK), (0x21, ScriptError.SIG_HASHTYPE),
                               (0x84, ScriptError.SIG_HASHTYPE), (0x00, ScriptError.SIG_HASHTYPE)):
            self.assertEqual(err, si.CheckSignatureEncoding(sig + bytes((hash_type,)), ScriptFlags.STRICTENC))

    def test_ber_signature(self):
        """Pre-BIP66 signatures may use long-form lengths and zero padding (ecdsa_signature_parse_der_lax)"""
        priv = ecc.ECPrivkey(bytes(31) + b'\x07')
        script_pubkey = si._push_data(priv.get_public_key_bytes()) + b'\xac'
        credit, spend = build_crediting_and_spending_tx(script_pubkey, b'', [], 0)
        sighash = si.SignatureHash(script_pubkey, PrecomputedTransactionData(spend), 0, 1, 0, SigVersion.BASE)
        r, s = priv.ecdsa_sign(sighash, sigencode=lambda r, s: (r, s))
        r_ber = bytes(268) + r.to_bytes(32, 'big')  # 300 bytes, 2-byte long-form length
        s_ber = s.to_bytes(32, 'big')
        body = b'\x02\x82' + len(r_ber).to_bytes(2, 'big') + r_ber + b'\x02\x83\x00\x00\x20' + s_ber
        sig = b'\x30\x82' + len(body).to_bytes(2, 'big') + body + b'\x01'
        self.assertEqual(ScriptError.OK, self._verify(script_pubkey, si._push_data(sig), flags=ScriptFlags.P2SH))
        self.assertEqual(ScriptError.SIG_DER, self._verify(script_pubkey, si._push_data(sig), flags=CONSENSUS_FLAGS))

    def test_taproot_edge_cases(self):
        # tapscripts are not subject to the 10000 byte script size limit (nor the 201 opcode limit)
        script = b'\x61' * 10001 + b'\x51'
        builder = TaprootBuilder(script)
        self.assertEqual(ScriptError.OK, self._verify(builder.output_script, witness=[script, builder.control_block]))
        # unknown public key types are anyone-can-sign, unless discouraged
        script = b'\x01\xaa' + si._push_data(bytes(33)) + b'\xac'
        builder = TaprootBuilder(script)
        self.assertEqual(ScriptError.OK, self._verify(builder.output_script, witness=[script, builder.control_block]))
        self.assertEqual(ScriptError.DISCOURAGE_UPGRADABLE_PUBKEYTYPE,
                         self._verify(builder.output_script, witness=[script, builder.control_block], flags=STANDARD_FLAGS))
        # a single witness element starting with 0x50 is a signature, not an annex
        self.assertEqual(ScriptError.SCHNORR_SIG, self._verify(builder.output_script, witness=[b'\x50' + bytes(63)]))
        self.assertEqual(ScriptError.WITNESS_PROGRAM_WITNESS_EMPTY, self._verify(builder.output_script, witness=[]))
        # control blocks have at most 128 nodes
        for n_nodes, err in ((128, ScriptError.WITNESS_PROGRAM_MISMATCH), (129, ScriptError.TAPROOT_WRONG_CONTROL_SIZE)):
            control = builder.control_block + bytes(32 * n_nodes)
            self.assertEqual(err, self._verify(builder.output_script, witness=[script, control]))

    def test_invalid_flag_combinations(self):
        checker = si.BaseSignatureChecker()
        for flags in (WITNESS, CLEANSTACK, CLEANSTACK | P2SH):
            with self.assertRaises(ValueError):
                verify_script(b'', b'\x51', [], flags, checker)
        # unknown flag bits are ignored
        self.assertEqual(ScriptError.OK, verify_script(b'', b'\x51', [], CONSENSUS_FLAGS | (1 << 40), checker))


# funding and spending txs signed by Electrum
ELECTRUM_SIGNED_TXS = {
    "uncompressed_p2pk": (
        "010000000001021b41471d6af3aa80ebe536dbf4f505a6d46af456131a8e12e1950171959b690e0f00000000fdffffff2ef29833a69863b31e884fc5e6f7b99a23b5601e14f0eb65905faa42fec0776d0000000000fdffffff02f96a070000000000160014e61b989a740056254b5f8061281ac96ca15d35e140420f00000000004341049afa8fb50f52104b381a673c6e4fb7fb54987271d0e948dd9a568bb2af6f9310a7a809ce06e09d1510e5836f20414596232e2c0be63715459fa3cf8e7092af05ac0247304402201fe20012c1c732a6a8f942c4e0feed5ed0bddfb94db736ec3d0c0d38f0f7f46a022021d690e6d2688b90b76002f4c3134981502d666211e85e8a6ca91e78405dfa3801210346fb31136ab48e6c648865264d32004b43643d01f0ba485cffac4bb0b3f739470247304402204a2473ab4b3bfc8e6b1a6b8675dc2c3d115d8c04f5df37f29779dca6d300d9db02205e72ebbccd018c67b86ae4da6b0e6222902a8de85915ed6115330b9328764b370121027a93ffc9444a12d99307318e2e538949072cb35b2aca344b8163795a022414c7d73a1400",
        "010000000129349e5641d79915e9d0282fdbaee8c3df0b6731bab9d70bf626e8588bde24ac010000004847304402206bf0d0a93abae0d5873a62ebf277a5dd2f33837821e8b93e74d04e19d71b578002201a6d729bc159941ef5c4c9e5fe13ece9fc544351ba531b00f68ba549c8b38a9a01fdffffff01b82e0f00000000001600148ba0a0bc12b51831f58c7ea8607e76c5982c071fd93a1400",
    ),
    "compressed_p2pk": (
        "02000000000102b7bfcd442c91134743c6e4100bb9f79456a6015de3c3920166bb0c3b7a8f7c070100000000fdffffff5ab39480d4b35ffa843691d944a8479dfe825d38b03fcb1804197482bfad80fb0100000000fdffffff02d4ec000000000000160014769114e56e0913de3719a3b00a446b78e61751f007b201000000000023210332e147520e4743299d95196afaf9db7c86fe02507d9ca89acd7a4e96a63653d5ac0247304402200387fe79ffe10cec73d9b131058d7128665f729d14597828b483842889c4f5ea02201197b2f1295e4011e2d174d53c240fd13c6351451ab961ccb3678fc21fa5323b0121023c221dfbf7c3f61b9e5f66343c1a302d6beca2a8883504b0f484faec9919636b024730440220687d387af37df458efc104ee0065262cb5ea195e526ed7a480fd16e6cf708c3a022019bd3fd9c3ca3f1a1fbeabe20547876eb4572a7339de37b706fbd55031e60428012102c9c459e58b01a864d7bb80f6d577326465a04219c48541b5f3ea556a06ca61a425ed2400",
        "02000000015eb359ccfcd67c3e6b10bb937a796807007708c1f413840d0e627a3f94a1a48401000000484730440220043fc85a43e918ac41e494e309fdf204ca245d260cb5ea09108b196ca65d8a09022056f852f0f521e79ab2124d7e9f779c7290329ce5628ef8e92601980b065d3eb501fdffffff017f9e010000000000160014a709434b13a510e6db68bdd672062c70a2f39d3a26ed2400",
    ),
    "uncompressed_p2pkh": (
        "02000000000101c6a49fbd701f1526c8e43025a6dda8dd235b3593cfd38af040cba3e37b474fdb0e00000000fdffffff020e640300000000001976a914f1b02b7028fb81aefbb25809a2baf8d94d0c2ba288acb9e3080000000000160014c2eee75efe6621be177f7edd8198f671d1640c2602473044022072b8a6154590704063c377af451b4d69f76cc9064085d4a0c80f08625c57628802207844164839d93ce54ce7db092bbd809d5270142b5dedc823e95400e8bdae88c6012102b6ad13f48fd679a209b7d822376550e5e694a3a2862546ceb72c4012977eac4829ed2400",
        "02000000010615142d6c296f276c7da9fb2b09f655d594f73b76740404f1424c66c78ca715000000008a47304402206d2dae571ca2f51e0d4a8ce6a6335fa25ac09f4bbed26439124d93f035bdbb130220249dc2039f1da338a40679f0e79c25a2dc2983688e6c04753348f2aa8435e375014104b875ab889006d4a9be8467c9256cf54e1073f7f9a037604f571cc025bbf47b2987b4c862d5b687bb5328adccc69e67a17b109b6328228695a1c384573acd6199fdffffff0186500300000000001600148ba0a0bc12b51831f58c7ea8607e76c5982c071f2aed2400",
    ),
    "compressed_p2pkh": (
        "020000000001010615142d6c296f276c7da9fb2b09f655d594f73b76740404f1424c66c78ca7150100000000fdffffff0240e20100000000001976a914f1d49f51f9b58c4805431c303d12d3dcf51ae54188ace9000700000000001600145bdb04f2d096ee48b8b350c85481392ab47c01e70247304402200a72a4599cb27f16011cd67e2951733d6775cbd008506eacb2c20d69db3f531702204c944ec09224a347481c9eea78cac79b77b194b19dfef01b1e3b428010a82570012102fc38612ca7cc42d05a7089f1a6ec3900535604bd779f83c7817aae7bfd907dbd2aed2400",
        "02000000016717835a2e1e152a69e7528a0f1346c1d37ee6e76c5e23b5d1c5a5b40241768a000000006a473044022038ad38003943bfd3ed39ba4340d545753fcad632a8fe882d01e4f0140ddb3cfb022019498260e29f5fbbcde9176bfb3553b7acec5fe284a9a3a33547a2d082b60355012103b875ab889006d4a9be8467c9256cf54e1073f7f9a037604f571cc025bbf47b29fdffffff0158de010000000000160014f1d49f51f9b58c4805431c303d12d3dcf51ae5412aed2400",
    ),
    "p2wpkh_p2sh": (
        "020000000001038fc862be3bc8022866cc83b4f2feeaa914b015a3c6644251960baaccc4a5740b0000000000fdffffff7bfd61e391034e28848fae269183f1c5929e26befd5b2d798cf12c91d4d00dbf0100000000fdffffff014764d324e70e7e3e4fa27077bda2d880b3d1545588b75f79deb2855d9f31cb0000000000fdffffff01f04902000000000017a9147d0530db22c8124ff1558269f543dfeedd37131b87024730440220568ae75314f6414ccf2b0bbed522e1b4b1086ed6eb185ba4bc044ba2723c1f3402206c82253797d0f180db38986b46d8ad952829cf25bc31e3ca6ee54665f5a44b3c0121038a466bdcb979b96d70fde84b9ded4aba0c3cd9c0d2d59121fc3555428fd1a4890247304402203ba1b482b0b6ce5c3d29ef21ee8afad641af8381d3b131103c384757922f0c04022072320e260b60fc862669b2ea3dfb663f7f3a0b6babe8d265ac9ebf268e7225c2012103ff0877f34157a3444afbfdd7432032a93187bc1932e1c155d56dd66ef527906c02473044022058b1c1a2a8c1a256d4870b550ba93777a2cce36b89abe3515f024fd4eec48ce4022023e0002193a26064275433e8ade98642d74d58ee4f8e9717a8acca737856a6c401210364e8f5d9c30986931bca1197138d7250a17a0711a223f113b3ccc11ef09efccb2aed2400",
        "020000000001011d1725072a6e60687a59b878ecaf940ea0385880613d9d5502102bd78ef97b9a0000000017160014e7a6a58b657f629516cc37ee2863cbabdadb3fd4fdffffff01fc47020000000000160014e7a6a58b657f629516cc37ee2863cbabdadb3fd402473044022048ea4c558fd374f5d5066440a7f4933393cb377802cb949e3039fedf0378a29402204b4a58c591117cc1e37f07b03cc03cc6198dbf547e2bff813e2e2102bd2057e00121029f46ba81b3c6ad84e52841364dc54ca1097d0c30a68fb529766504c4b1c599352aed2400",
    ),
    "p2wpkh": (
        "02000000000101208840a3310ae4b88181374b5812f56f5dd56f12574f3bcd8041b48bfadc92cf0000000000fdffffff02fc7f010000000000160014d339efed7cd5d28d31995caf10b8973a9a13c656a08601000000000043410403886197eb13c59721b94a29f9a68a841caedb7782b35121cd81d50d0cc70db3f8955c7a07b08dd6470141b66eedd324406e29d6b6799033314512334461e3f9ac0247304402203328153753e934d7a13215bf58f093f84281d57f8c7d42f3b7704cd714c7b32c02205a502f3f3e4302561ccc93df413be3c78a439ff35b60cea03d19f8804a9a1239012103f41052be701441d1bc8f7cc6a6053d7e7f5e63be212fe5e3687344ddd52e3af525ed2400",
        "02000000000101e328aeb4f9dc1b85a2709ce59b0478a15ed9fb5e7f84fb62422f99b8cd6ad7010000000000fdffffff01087e010000000000160014bf08acd69f1b7012c2b91642b352ce3627db89010247304402204993099c4663d92ef4c9a28b3f45a40a6585754fe22ecfdc0a76c43fda7c9d04022006a75e0fd3ad1862d8e81015a71d2a1489ec7a9264e6e63b8fe6bb90c27e799b0121038ca94e7c715152fd89803c2a40a934c7c4035fb87b3cba981cd1e407369cfe312aed2400",
    ),
    "p2sh_multisig_2of3": (
        "010000000001014121f99dc02f0364d2dab3d08905ff4c36fc76c55437fd90b769c35cc18618280100000000fdffffff02d4c22d00000000001600143fd1bc5d32245850c8cb5be5b09c73ccbb9a0f75001bb7000000000017a91480c2353f6a7bc3c71e99e062655b19adb3dd2e4887024830450221008781c78df0c9d4b5ea057333195d5d76bc29494d773f14fa80e27d2f288b2c360220762531614799b6f0fb8d539b18cb5232ab4253dd4385435157b28a44ff63810d0121033de77d21926e09efd04047ae2d39dbd3fb9db446e8b7ed53e0f70f9c9478f735dac11300",
        "01000000017120d4e1f2cdfe7df000d632cff74167fb354f0546d5cfc228e5c98756d55cb201000000fc004730440220751ee3599e59debb8b2aeef61bb5f574f26379cd961caf382d711a507bc632390220598d53e62557c4a5ab8cfb2f8948f37cca06a861714b55c781baf2c3d7a580b501473044022023b55c679397bdf3a04d545adc6193eabc11b3a28850d3d46049a51a30c6732402205dbfdade5620e9072ae4aa7577c5f0fd294f59a6b0064cc7105093c0fe7a6d24014c69522102afb4af9a91264e1c6dce3ebe5312801723270ac0ba8134b7b49129328fcb0f2821030b482838721a38d94847699fed8818b5c5f56500ef72f13489e365b65e5749cf2103e5db7969ae2f2576e6a061bf3bb2db16571e77ffb41e0b27170734359235cbce53aefeffffff0250a50500000000001976a9149cd3dfb0d87a861770ae4e268e74b45335cf00ab88ac2862b1000000000017a9142e517854aa54668128c0e9a3fdd4dec13ad571368700000000",
    ),
    "p2wsh_p2sh_multisig_2of2": (
        "01000000000101213e1012a461e056752fab5a6414a2fb63f950cd21a50ac5e2b82d339d6cbdd20000000000feffffff023075000000000000220020cc5e4cc05a76d0648cd0742768556317e9f8cc729aed077134287909035dba88888402000000000017a914187842cea9c15989a51ce7ca889a08b824bf8743870400473044022055cb04fa71c4b5955724d7ac5da90436d75212e7847fc121cb588f54bcdffdc4022064eca1ad639b7c748101059dc69f2893abb3b396bcf9c13f670415076f93ddbf01473044022009230e456724f2a4c10d886c836eeec599b21db0bf078aa8fc8c95868b8920ec02200dfda835a66acb5af50f0d95fcc4b76c6e8f4789a7184c182275b087d1efe556016952210223f815ab09f6bfc8519165c5232947ae89d9d43d678fb3486f3b28382a2371fa210273c529c2c9a99592f2066cebc2172a48991af2b471cb726b9df78c6497ce984e2102aa8fc578b445a1e4257be6b978fcece92980def98dce0e1eb89e7364635ae94153ae00000000",
        "0100000000010149d077be0ee9d52776211e9b4fec1cc02bd53661a04e120a97db8b78d83c9c6e01000000232200204311edae835c7a5aa712c8ca644180f13a3b2f3b420fa879b181474724d6163cfeffffff0260ea00000000000017a9143025051b6b5ccd4baf30dfe2de8aa84f0dd567ed87a086010000000000220020f7b6b30c3073ae2680a7e90c589bbfec5303331be68bbab843eed5d51ba0123904004730440220091ea67af7c1131f51f62fe9596dff0a60c8b45bfc5be675389e193912e8a71802201bf813bbf83933a35ecc46e2d5b0442bd8758fa82e0f8ed16392c10d51f7f7660147304402203ecf75b0316a449dd31bc549251b687dc904194aa551941bd5e8c67603661bdb02204ed58b3a6b070ec138d2127093bebcc6581495818fa611583e1c81cd9b2cf5ee0147522102119f899075a131d4d519d4cdcf5de5907dc2df3b93d54b53ded852211d2b6cb12102fdb0f6775d4b6619257c43343ba5e7807b0164f1eb3f00f2b594ab9e53ab812652ae00000000",
    ),
    "p2wsh_multisig_2of3": (
        "01000000000101a41aae475d026c9255200082c7fad26dc47771275b0afba238dccda98a597bd20000000000fdffffff02400d0300000000002200203c43ac80d6e3015cf378bf6bac0c22456723d6050bef324ec641e7762440c63c9dcd410000000000160014824626055515f3ed1d2cfc9152d2e70685c71e8f02483045022100b9f39fad57d07ce1e18251424034f21f10f20e59931041b5167ae343ce973cf602200fefb727fa0ffd25b353f1bcdae2395898fe407b692c62f5885afbf52fa06f5701210301a28f68511ace43114b674371257bb599fd2c686c4b19544870b1799c954b40e9c11300",
        "01000000000101213e1012a461e056752fab5a6414a2fb63f950cd21a50ac5e2b82d339d6cbdd20000000000feffffff023075000000000000220020cc5e4cc05a76d0648cd0742768556317e9f8cc729aed077134287909035dba88888402000000000017a914187842cea9c15989a51ce7ca889a08b824bf8743870400473044022055cb04fa71c4b5955724d7ac5da90436d75212e7847fc121cb588f54bcdffdc4022064eca1ad639b7c748101059dc69f2893abb3b396bcf9c13f670415076f93ddbf01473044022009230e456724f2a4c10d886c836eeec599b21db0bf078aa8fc8c95868b8920ec02200dfda835a66acb5af50f0d95fcc4b76c6e8f4789a7184c182275b087d1efe556016952210223f815ab09f6bfc8519165c5232947ae89d9d43d678fb3486f3b28382a2371fa210273c529c2c9a99592f2066cebc2172a48991af2b471cb726b9df78c6497ce984e2102aa8fc578b445a1e4257be6b978fcece92980def98dce0e1eb89e7364635ae94153ae00000000",
    ),
}


def _spent_outputs(funding_txs: Sequence[Transaction], tx: Transaction) -> List[TxOutput]:
    by_txid = {bfh(ftx.txid()): ftx for ftx in funding_txs}
    return [by_txid[txin.prevout.txid].outputs()[txin.prevout.out_idx] for txin in tx.inputs()]


class TestVerifyInput(ElectrumTestCase):

    def test_electrum_signed_txs(self):
        for name, (funding_raw, spending_raw) in ELECTRUM_SIGNED_TXS.items():
            tx = Transaction(spending_raw)
            spent = _spent_outputs([Transaction(funding_raw)], tx)
            txdata = PrecomputedTransactionData(tx, spent)
            verify_input(txdata, 0, flags=CONSENSUS_FLAGS)
            verify_input(txdata, 0, flags=MEMPOOL_FLAGS)
            with self.assertRaises(ValueError, msg=name):
                # the output spent by the input itself is needed
                verify_input(PrecomputedTransactionData(tx, [None]), 0, flags=CONSENSUS_FLAGS)
            # a different amount or scriptPubKey breaks it (except for the legacy sighash, which commits to neither)
            if tx.inputs()[0].witness_elements():
                other_amount = TxOutput(scriptpubkey=spent[0].scriptpubkey, value=spent[0].value + 1)
                with self.assertRaises(ScriptVerificationError, msg=name):
                    verify_input(PrecomputedTransactionData(tx, [other_amount]), 0, flags=CONSENSUS_FLAGS)
            spk = bytearray(spent[0].scriptpubkey)
            spk[len(spk) // 2] ^= 1  # inside the pubkey or hash
            other_script = TxOutput(scriptpubkey=bytes(spk), value=spent[0].value)
            with self.assertRaises(ScriptVerificationError, msg=name):
                verify_input(PrecomputedTransactionData(tx, [other_script]), 0, flags=CONSENSUS_FLAGS)

    def test_electrum_bip143_sighash_types(self):
        # signatures made by Electrum in test_transaction.TestSighashBIP143 (= the BIP143 test vectors)
        from .test_transaction import TestSighashBIP143 as T
        tx = PartialTransaction.from_io(inputs=[T.txin], outputs=[T.txout1, T.txout2], locktime=T.locktime, version=1, BIP69_sort=False)
        txdata = PrecomputedTransactionData(tx)
        cases = [
            ('730fff80e1413068a05b57d6a58261f07551163369787f349438ea38ca80fac6', '304402206ac44d672dac41f9b00e28f4df20c52eeb087207e8d758d76d92c6fab3b73e2b0220367750dbbe19290069cba53d096f44530e4f98acaa594810388cf7409a1870ce01'),
            ('11fa3d25a17cbc22b29c44a484ba552b5a53149d106d3d853e22fdd05a2d8bb3', '3044022068c7946a43232757cbdf9176f009a928e1cd9a1a8c212f15c1e11ac9f2925d9002205b75f937ff2f9f3c1246e547e54f62e027f64eefa2695578cc6432cdabce271502'),
            ('77bf4141a87d55bdd7f3cd0bdccf6e9e642935fec45f2f30047be7b799120661', '3044022059ebf56d98010a932cf8ecfec54c48e6139ed6adb0728c09cbe1e4fa0915302e022007cd986c8fa870ff5d2b3a89139c9fe7e499259875357e20fcbb15571c76795403'),
            ('14af36970f5025ea3e8b5542c0f8ebe7763e674838d08808896b63c3351ffe49', '3045022100fbefd94bd0a488d50b79102b5dad4ab6ced30c4069f1eaa69a4b5a763414067e02203156c6a5c9cf88f91265f5a942e96213afae16d83321c8b31bb342142a14d16381'),
            ('fe9a95c19eef81dde2b95c1284ef39be497d128e2aa46916fb02d552485e0323', '3045022100a5263ea0553ba89221984bd7f0b13613db16e7a70c549a86de0cc0444141a407022005c360ef0ae5a5d4f9f2f87a56c1546cc8268cab08c73501d6b3be2e1e1a8a0882'),
            ('428a7aee9f0c2af0cd19af3cf1c78149951ea528726989b2e83e4778d2c3f890', '30440220525406a1482936d5a21888260dc165497a90a15669636d8edca6b9fe490d309c022032af0c646a34a44d1f4576bf6a4a74b67940f8faa84c7df9abe12a01a11e2b4783'),
        ]
        for privkey, sig in cases:
            pubkey = ecc.ECPrivkey(bfh(privkey)).get_public_key_bytes()
            for amount, ok in ((T.txin._trusted_value_sats, True), (T.txin._trusted_value_sats + 1, False)):
                checker = TransactionSignatureChecker(txdata, 0, amount)
                self.assertEqual(ok, checker.CheckECDSASignature(bfh(sig), pubkey, T.txin.witness_script, SigVersion.WITNESS_V0))
            with self.assertRaises(MissingSpentOutputs):  # the BIP143 sighash commits to the amount
                TransactionSignatureChecker(txdata, 0, None).CheckECDSASignature(bfh(sig), pubkey, T.txin.witness_script, SigVersion.WITNESS_V0)

    def test_undecodable_tx(self):
        """Electrum deserializes lazily: a malformed serialization raises SerializationError (documented)."""
        with self.assertRaises(SerializationError):
            PrecomputedTransactionData(Transaction('0200000001'))

    def test_garbage_never_raises(self):
        """Random scripts, witnesses and flags only ever produce a ScriptError."""
        rng = random.Random(4)
        pieces = [bytes([op]) for op in range(256)] + [
            si._push_data(bytes(33)), si._push_data(ecc.GENERATOR.get_public_key_bytes()), b'\x4c', b'\x4d\xff',
            b'\x4e\xff\xff\xff\xff', si._push_data(bytes.fromhex(
                "3044022020e3c33fa2a7c74fb5e6eba4be3ab2a12b5e0f78b1cf7f7d6ae8ec90a4f6d1a7022025b8e1deae9e9c8"
                "5f72e5fd4ad7fa8f5e2fd6b5f2c3a1a7d0c4d3eba8f3e2c2e01")), b'\x00\x63', b'\x51\x67', b'\x68',
        ]

        def garbage(n):
            return b''.join(rng.choice(pieces) for _ in range(rng.randrange(n)))

        for i in range(4000):
            witness = [garbage(4) for _ in range(rng.randrange(4))]
            spk = rng.choice([garbage(12), b'\x00\x14' + bytes(20), b'\x00\x20' + bytes(32), b'\x51\x20' + bytes(32),
                              b'\xa9\x14' + bytes(20) + b'\x87', b'\x51\x02\x4e\x73', garbage(3)])
            if rng.random() < 0.3:
                witness.append(garbage(20))
                spk = b'\x00\x20' + sha256(witness[-1])
            flags = rng.getrandbits(si.MAX_SCRIPT_VERIFY_FLAGS_BITS)
            if not si.is_valid_flag_combination(flags):
                flags = fill_flags(flags)
            credit, spend = build_crediting_and_spending_tx(spk, garbage(12), witness, rng.randrange(2**40))
            txdata = PrecomputedTransactionData(spend, credit.outputs())
            try:
                verify_input(txdata, 0, flags=flags)
            except ScriptVerificationError:
                pass
