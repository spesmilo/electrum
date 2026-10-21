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
    VerificationBudget, ScriptVerificationError, TxValidationError, ResourceLimitExceeded,
    verify_script, verify_input, verify_transaction, check_transaction,
    signature_hash_legacy, signature_hash_schnorr, CONSENSUS_FLAGS, STANDARD_FLAGS,
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
from .test_transaction import VERIFYSIG_TXS as ELECTRUM_SIGNED_TXS


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
    """Transaction from its fields, for transactions that Electrum's parser refuses
    (no inputs/outputs, out-of-range values), which Core can still deserialize."""
    tx = Transaction(None)
    tx._inputs = [TxInput(prevout=TxOutpoint(txid=txid, out_idx=n), script_sig=script_sig, nsequence=seq,
                          witness=construct_witness(list(wit)) if wit else None)
                  for txid, n, script_sig, seq, wit in vin]
    tx._outputs = [TxOutput(scriptpubkey=spk, value=value) for value, spk in vout]
    tx._version = version
    tx._locktime = locktime
    return tx


def deserialize_tx(raw: bytes, *, allow_witness: bool = True) -> Transaction:
    """Core: UnserializeTransaction (TX_WITH_WITNESS / TX_NO_WITNESS). Returns an Electrum
    Transaction. Electrum's own parser is used (and cross-checked) whenever it accepts the tx."""
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

    try:
        tx = Transaction(raw[:r.read_cursor])
        tx.inputs()
    except Exception:
        return make_tx(version, vin, vout, locktime)
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
    def _check_tx_scripts(tx: Transaction, spent_outputs: List[TxOutput], flags: int,
                          txdata: PrecomputedTransactionData, expect_valid: bool) -> bool:
        """Core: CheckTxScripts"""
        tx_valid = True
        for i in range(len(tx.inputs())):
            try:
                verify_input(tx, i, spent_outputs, flags=flags, txdata=txdata)
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
            check_transaction(tx)
            txdata = PrecomputedTransactionData(tx, spent_outputs)
            verify_flags = parse_script_flags(test[2])
            # Check that the test gives a valid combination of flags (otherwise VerifyScript will throw). Don't edit the flags.
            self.assertEqual(inv(verify_flags), fill_flags(inv(verify_flags)), f"Bad test flags: {str_test}")
            if not self._check_tx_scripts(tx, spent_outputs, inv(verify_flags), txdata, True):
                failures.append(f"Tx unexpectedly failed: {str_test}")
            # Backwards compatibility of script verification flags: Removing any flag(s) should not invalidate a valid transaction
            for name, flag in FLAG_NAMES.items():
                # Removing individual flags
                flags = trim_flags(inv(verify_flags | flag))
                if not self._check_tx_scripts(tx, spent_outputs, flags, txdata, True):
                    failures.append(f"Tx unexpectedly failed with flag {name} unset: {str_test}")
                # Removing random combinations of flags
                flags = trim_flags(inv(verify_flags | rng.getrandbits(si.MAX_SCRIPT_VERIFY_FLAGS_BITS)))
                if not self._check_tx_scripts(tx, spent_outputs, flags, txdata, True):
                    failures.append(f"Tx unexpectedly failed with random flags {flags}: {str_test}")
            # Check that flags are maximal: transaction should fail if any unset flags are set.
            for flags_excluding_one in exclude_individual_flags(verify_flags):
                if not self._check_tx_scripts(tx, spent_outputs, inv(flags_excluding_one), txdata, False):
                    failures.append(f"Too many flags unset: {str_test}")
        self.assertEqual([], failures)
        self.assertEqual(121, n_run)

    def test_tx_invalid_json(self):
        """Core: tx_invalid (transaction_tests.cpp)"""
        tests = _load_json("tx_invalid.json")
        rng = random.Random(3)
        failures = []
        n_run = n_badtx = 0
        for test in tests:
            if not isinstance(test[0], list):
                continue
            n_run += 1
            str_test = json.dumps(test)
            self.assertTrue(len(test) == 3 and isinstance(test[1], str) and isinstance(test[2], str), str_test)
            tx, spent_outputs = self._read_tx_test(test)
            try:
                check_transaction(tx)
            except TxValidationError:
                self.assertEqual("BADTX", test[2], str_test)
                n_badtx += 1
                continue
            txdata = PrecomputedTransactionData(tx, spent_outputs)
            verify_flags = parse_script_flags(test[2])
            # Check that the test gives a valid combination of flags (otherwise VerifyScript will throw). Don't edit the flags.
            self.assertEqual(verify_flags, fill_flags(verify_flags), f"Bad test flags: {str_test}")
            # Not using FillFlags() in the main test, in order to detect invalid verifyFlags combination
            if not self._check_tx_scripts(tx, spent_outputs, verify_flags, txdata, False):
                failures.append(f"Tx unexpectedly passed: {str_test}")
            # Backwards compatibility of script verification flags: Adding any flag(s) should not validate an invalid transaction
            for name, flag in FLAG_NAMES.items():
                # Adding individual flags
                flags = fill_flags(verify_flags | flag)
                if not self._check_tx_scripts(tx, spent_outputs, flags, txdata, False):
                    failures.append(f"Tx unexpectedly passed with flag {name} set: {str_test}")
                # Adding random combinations of flags
                flags = fill_flags(verify_flags | rng.getrandbits(si.MAX_SCRIPT_VERIFY_FLAGS_BITS))
                if not self._check_tx_scripts(tx, spent_outputs, flags, txdata, False):
                    failures.append(f"Tx unexpectedly passed with random flags {flags}: {str_test}")
            # Check that flags are minimal: transaction should succeed if any set flags are unset.
            for flags_excluding_one in exclude_individual_flags(verify_flags):
                if not self._check_tx_scripts(tx, spent_outputs, flags_excluding_one, txdata, True):
                    failures.append(f"Too many flags set: {str_test}")
        self.assertEqual([], failures)
        self.assertEqual(93, n_run)
        self.assertEqual(sum(1 for t in tests if isinstance(t[0], list) and t[2] == "BADTX"), n_badtx)

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
            check_transaction(tx)
            sh = signature_hash_legacy(bytes.fromhex(raw_script), tx, n_in, hash_type)
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
            # Electrum's own signing code
            psbt = PartialTransaction.from_tx(Transaction(vec["given"]["rawUnsignedTx"]))
            for txin, utxo in zip(psbt.inputs(), utxos):
                txin.witness_utxo = utxo
            for inp in vec["inputSpending"]:
                n_inputs += 1
                txin_index = inp["given"]["txinIndex"]
                hash_type = inp["given"]["hashType"]
                sighash = signature_hash_schnorr(tx, txin_index, hash_type, SigVersion.TAPROOT, txdata)
                self.assertEqual(inp["intermediary"]["sigHash"], sighash.hex())
                sig_msg = bfh(inp["intermediary"]["sigMsg"])
                self.assertEqual(inp["intermediary"]["sigHash"], bip340_tagged_hash(b"TapSighash", sig_msg).hex())
                # the fully signed key-path spend verifies...
                self.assertEqual(inp["expected"]["witness"], [w.hex() for w in signed_tx.inputs()[txin_index].witness_elements()])
                verify_input(signed_tx, txin_index, utxos)
                verify_input(signed_tx, txin_index, utxos, flags=STANDARD_FLAGS)
                # ... and stops verifying if one bit of its signature is flipped
                bad_tx = Transaction(vec["auxiliary"]["fullySignedTx"])
                sig = bytearray(bfh(inp["expected"]["witness"][0]))
                sig[n_inputs % 64] ^= 1 << (n_inputs % 8)
                bad_tx.inputs()[txin_index].witness = construct_witness([bytes(sig)])
                with self.assertRaises(ScriptVerificationError) as ctx:
                    verify_input(bad_tx, txin_index, utxos)
                self.assertEqual(ScriptError.SCHNORR_SIG, ctx.exception.error)
                self.assertEqual(txin_index, ctx.exception.txin_index)
                # Electrum's signature (it signs with the sighash type given in the vector)
                ptxin = psbt.inputs()[txin_index]
                ptxin.sighash = hash_type
                ptxin.tap_merkle_root = bfh(inp["given"]["merkleRoot"]) if inp["given"]["merkleRoot"] else None
                sig = psbt.sign_txin(txin_index, bfh(inp["given"]["internalPrivkey"]))
                bad_tx.inputs()[txin_index].witness = construct_witness([sig])
                verify_input(bad_tx, txin_index, utxos)
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
        verify_input(spend, 0, credit.outputs(), flags=flags)
        # P2A is only special when not P2SH-wrapped
        credit, spend = build_crediting_and_spending_tx(p2sh_p2a, si._push_data(p2a), [], 0)
        verify_input(spend, 0, credit.outputs(), flags=CONSENSUS_FLAGS)
        with self.assertRaises(ScriptVerificationError) as ctx:
            verify_input(spend, 0, credit.outputs(), flags=flags)
        self.assertEqual(ScriptError.DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM, ctx.exception.error)
        # other 2-byte v1 programs are upgradable
        credit, spend = build_crediting_and_spending_tx(bfh("51024e74"), b'', [], 0)
        with self.assertRaises(ScriptVerificationError) as ctx:
            verify_input(spend, 0, credit.outputs(), flags=flags)
        self.assertEqual(ScriptError.DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM, ctx.exception.error)

    def _verify(self, script_pubkey: bytes, script_sig: bytes = b'', witness: Sequence[bytes] = (), flags: int = CONSENSUS_FLAGS) -> ScriptError:
        credit, spend = build_crediting_and_spending_tx(script_pubkey, script_sig, list(witness), 0)
        try:
            verify_input(spend, 0, credit.outputs(), flags=flags)
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
        sighash = signature_hash_legacy(script_pubkey, spend, 0, 1)
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


def _spent_outputs(funding_txs: Sequence[Transaction], tx: Transaction) -> List[TxOutput]:
    by_txid = {bfh(ftx.txid()): ftx for ftx in funding_txs}
    return [by_txid[txin.prevout.txid].outputs()[txin.prevout.out_idx] for txin in tx.inputs()]


class TestVerifyTransaction(ElectrumTestCase):

    def test_electrum_signed_txs(self):
        for name, (funding_raw, spending_raw) in ELECTRUM_SIGNED_TXS.items():
            tx = Transaction(spending_raw)
            spent = _spent_outputs([Transaction(funding_raw)], tx)
            verify_transaction(tx, spent)
            verify_transaction(tx, spent, flags=STANDARD_FLAGS)
            # a different amount or scriptPubKey breaks it (except for the legacy sighash, which commits to neither)
            if tx.inputs()[0].witness_elements():
                with self.assertRaises(ScriptVerificationError, msg=name):
                    verify_input(tx, 0, [TxOutput(scriptpubkey=spent[0].scriptpubkey, value=spent[0].value + 1)])
            spk = bytearray(spent[0].scriptpubkey)
            spk[len(spk) // 2] ^= 1  # inside the pubkey or hash
            with self.assertRaises(ScriptVerificationError, msg=name):
                verify_input(tx, 0, [TxOutput(scriptpubkey=bytes(spk), value=spent[0].value)])

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

    def _multisig_tx(self) -> Tuple[Transaction, List[TxOutput]]:
        funding_raw, spending_raw = ELECTRUM_SIGNED_TXS["p2wsh_multisig_2of3"]
        tx = Transaction(spending_raw)
        return tx, _spent_outputs([Transaction(funding_raw)], tx)

    def test_value_rules(self):
        tx, spent = self._multisig_tx()
        verify_transaction(tx, spent)
        # mismatched spent_outputs length
        with self.assertRaises(ValueError):
            verify_transaction(tx, spent + spent)
        with self.assertRaises(ValueError):
            verify_transaction(tx, [])
        # input values
        for value, reason in ((-1, "bad-txns-inputvalues-outofrange"),
                              (si.MAX_MONEY + 1, "bad-txns-inputvalues-outofrange"),
                              (tx.output_value() - 1, "bad-txns-in-belowout")):
            with self.assertRaises(TxValidationError) as ctx:
                verify_transaction(tx, [TxOutput(scriptpubkey=spent[0].scriptpubkey, value=value)])
            self.assertEqual(reason, ctx.exception.reason)
        # zero fee is fine as far as consensus is concerned, but the signature commits to the amount
        with self.assertRaises(ScriptVerificationError):
            verify_transaction(tx, [TxOutput(scriptpubkey=spent[0].scriptpubkey, value=tx.output_value())])

    def test_coinbase_rejected(self):
        coinbase = make_tx(1, [(bytes(32), 0xffffffff, b'\x03\x01\x02\x03', 0xffffffff, [])], [(50 * si.COIN, b'\x51')], 0)
        check_transaction(coinbase)
        with self.assertRaises(TxValidationError) as ctx:
            verify_transaction(coinbase, [TxOutput(scriptpubkey=b'', value=0)])
        self.assertEqual("coinbase", ctx.exception.reason)

    def test_check_transaction(self):
        op = (bytes(range(32)), 0, b'', 0xffffffff, [])
        op2 = (bytes(range(32)), 1, b'', 0xffffffff, [])
        null_op = (bytes(32), 0xffffffff, b'', 0xffffffff, [])
        cases = [
            ([], [(1, b'')], "bad-txns-vin-empty"),
            ([op], [], "bad-txns-vout-empty"),
            ([op], [(1, b'\x6a' + bytes(si.MAX_BLOCK_WEIGHT // 4))], "bad-txns-oversize"),
            ([op], [(-1, b'')], "bad-txns-vout-negative"),
            ([op], [(si.MAX_MONEY + 1, b'')], "bad-txns-vout-toolarge"),
            ([op], [(si.MAX_MONEY, b''), (1, b'')], "bad-txns-txouttotal-toolarge"),
            ([op, op], [(1, b'')], "bad-txns-inputs-duplicate"),
            ([null_op], [(1, b'')], "bad-cb-length"),
            ([op, null_op], [(1, b'')], "bad-txns-prevout-null"),
        ]
        for vin, vout, reason in cases:
            with self.assertRaises(TxValidationError) as ctx:
                check_transaction(make_tx(2, vin, vout, 0))
            self.assertEqual(reason, ctx.exception.reason)
        check_transaction(make_tx(2, [op, op2], [(si.MAX_MONEY, b'')], 0))
        # a null prevout needs the null txid and index 0xffffffff (unlike Electrum's TxOutpoint.is_coinbase)
        check_transaction(make_tx(2, [(bytes(32), 0, b'', 0xffffffff, [])], [(1, b'')], 0))
        # exactly at the size limit
        base_size = len(make_tx(2, [op], [(1, b'\x6a')], 0).serialize_as_bytes()) + 4  # + 4: 5-byte compact size
        check_transaction(make_tx(2, [op], [(1, b'\x6a' + bytes(si.MAX_BLOCK_WEIGHT // 4 - base_size))], 0))
        with self.assertRaises(TxValidationError):
            check_transaction(make_tx(2, [op], [(1, b'\x6a' + bytes(si.MAX_BLOCK_WEIGHT // 4 - base_size + 1))], 0))

    def test_block_sigop_cost_limit(self):
        """A tx whose sigop cost exceeds MAX_BLOCK_SIGOPS_COST cannot be in a block (Core: ConnectBlock)."""
        # OP_0 OP_IF <198 x OP_CHECKMULTISIG> OP_ENDIF OP_1: valid, 200 ops, 198 * 20 accurate sigops
        ms = b'\x00\x63' + b'\xae' * 198 + b'\x68\x51'
        p2sh = b'\xa9\x14' + hash_160(ms) + b'\x87'
        p2wsh = b'\x00\x20' + sha256(ms)
        cases = [  # (inputs as (script_sig, witness, spent scriptPubKey), output script, sigop cost, valid spend)
            ([(b'', [], b'\x51')], b'\x52\xae', 4 * 20, True),  # legacy: x4, multisig always 20
            ([(si._push_data(ms), [], p2sh)] * 5, b'', 5 * 4 * 3960, True),  # P2SH redeemScript: x4
            ([(b'', [ms], p2wsh)] * 20, b'', 20 * 3960, True),  # P2WSH witnessScript: x1
            ([(b'', [ms], b'\x00\x14' + bytes(20)), (b'', [ms], b'\x51\x20' + bytes(32))], b'', 1, False),  # P2WPKH 1, P2TR 0
        ]
        for vin, out_script, cost, valid in cases:
            spent = [TxOutput(scriptpubkey=spk, value=1000) for *_, spk in vin]
            vin = [(bytes([i + 1]) * 32, 0, script_sig, 0xffffffff, wit) for i, (script_sig, wit, _) in enumerate(vin)]
            tx = make_tx(2, vin, [(0, out_script)], 0)
            self.assertEqual(cost, si.GetTransactionSigOpCost(tx, spent, CONSENSUS_FLAGS))
            self.assertEqual(4 * si.GetLegacySigOpCount(tx), si.GetTransactionSigOpCost(tx, spent, 0))
            if not valid:
                continue
            # fill up to the limit with legacy sigops (4 each) in a second output
            n = (si.MAX_BLOCK_SIGOPS_COST - cost) // 4
            verify_transaction(make_tx(2, vin, [(0, out_script), (0, b'\xac' * n)], 0), spent)
            with self.assertRaises(TxValidationError) as ctx:
                verify_transaction(make_tx(2, vin, [(0, out_script), (0, b'\xac' * (n + 1))], 0), spent)
            self.assertEqual("bad-blk-sigops", ctx.exception.reason)

    def test_block_weight_limit(self):
        """A tx heavier than MAX_BLOCK_WEIGHT cannot be in a block (Core: ContextualCheckBlock)."""
        spent = [TxOutput(scriptpubkey=b'\x52\x02\x11\x22', value=1000)]  # unknown witness version

        def fields(n):
            return 2, [(bytes(range(32)), 0, b'', 0xffffffff, [bytes(n)])], [(0, b'\x51')], 0
        n = si.MAX_BLOCK_WEIGHT - si.GetTransactionWeight(make_tx(*fields(0))) - 4  # 5-byte compact size
        tx = make_tx(*fields(n))
        self.assertEqual(si.MAX_BLOCK_WEIGHT, 3 * len(bfh(tx.serialize_to_network(force_legacy=True))) + len(tx.serialize_as_bytes()))
        verify_transaction(make_tx(*fields(n)), spent)
        with self.assertRaises(TxValidationError) as ctx:
            verify_transaction(make_tx(*fields(n + 1)), spent)
        self.assertEqual("bad-blk-weight", ctx.exception.reason)

    def test_undecodable_tx(self):
        """Electrum deserializes lazily: a malformed serialization raises SerializationError (documented)."""
        for f in (check_transaction, lambda tx: verify_transaction(tx, []), lambda tx: verify_input(tx, 0, [])):
            with self.assertRaises(SerializationError):
                f(Transaction('0200000001'))

    def test_verification_budget(self):
        tx, spent = self._multisig_tx()  # 2-of-3, signed by keys 1 and 3: 3 signature checks
        budget = VerificationBudget(max_sig_checks=3, max_sighash_bytes=10_000)
        verify_transaction(tx, spent, budget=budget)
        self.assertEqual(3, budget.sig_checks)
        self.assertGreater(budget.sighash_bytes, 0)
        with self.assertRaises(ResourceLimitExceeded):
            verify_transaction(tx, spent, budget=VerificationBudget(max_sig_checks=2, max_sighash_bytes=10_000))
        with self.assertRaises(ResourceLimitExceeded):
            verify_transaction(tx, spent, budget=VerificationBudget(max_sig_checks=10, max_sighash_bytes=100))
        # legacy sighashes are charged per signature check, with the size of the whole tx
        funding_raw, spending_raw = ELECTRUM_SIGNED_TXS["uncompressed_p2pkh"]
        tx = Transaction(spending_raw)
        spent = _spent_outputs([Transaction(funding_raw)], tx)
        budget = VerificationBudget(max_sig_checks=1, max_sighash_bytes=10_000)
        verify_transaction(tx, spent, budget=budget)
        self.assertGreater(budget.sighash_bytes, len(tx.serialize_as_bytes()) - len(tx.inputs()[0].script_sig))
        # a budget is cumulative
        with self.assertRaises(ResourceLimitExceeded):
            verify_transaction(tx, spent, budget=budget)

    def test_find_and_delete_is_charged(self):
        # <sig> <pubkey> | <sig> OP_DROP OP_CHECKSIG: FindAndDelete has to walk the script
        sig = bytes(70)
        script_pubkey = si._push_data(sig) + b'\x75\xac\x51'
        credit, spend = build_crediting_and_spending_tx(script_pubkey, si._push_data(sig) + si._push_data(bytes(33)), [], 0)
        budget = VerificationBudget(max_sig_checks=10, max_sighash_bytes=10**6)
        verify_input(spend, 0, credit.outputs(), flags=ScriptFlags.P2SH, budget=budget)
        self.assertGreaterEqual(budget.sighash_bytes, len(script_pubkey) * VerificationBudget.SCRIPT_WALK_COST)

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
            try:
                verify_input(spend, 0, credit.outputs(), flags=flags,
                             budget=VerificationBudget(max_sig_checks=100, max_sighash_bytes=10**7))
            except (ScriptVerificationError, ResourceLimitExceeded):
                pass
