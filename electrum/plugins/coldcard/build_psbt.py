#
# build_psbt.py - create a PSBT from (unsigned) transaction and keystore data.
#
import io
import struct
from binascii import a2b_hex, b2a_hex
from struct import pack, unpack

from electrum.transaction import (Transaction, multisig_script, parse_redeemScript_multisig,
                                  NotRecognizedRedeemScript)

from electrum.logging import get_logger
from electrum.wallet import Standard_Wallet, Multisig_Wallet, Abstract_Wallet
from electrum.keystore import xpubkey_to_pubkey, Xpub
from electrum.util import bfh, bh2u
from electrum.crypto import hash_160, sha256
from electrum.bitcoin import DecodeBase58Check
from electrum.i18n import _

from .basic_psbt import (
        PSBT_GLOBAL_UNSIGNED_TX, PSBT_GLOBAL_XPUB, PSBT_IN_NON_WITNESS_UTXO, PSBT_IN_WITNESS_UTXO,
        PSBT_IN_SIGHASH_TYPE, PSBT_IN_REDEEM_SCRIPT, PSBT_IN_WITNESS_SCRIPT, PSBT_IN_PARTIAL_SIG,
        PSBT_IN_BIP32_DERIVATION, PSBT_OUT_BIP32_DERIVATION,
        PSBT_OUT_REDEEM_SCRIPT, PSBT_OUT_WITNESS_SCRIPT)
from .basic_psbt import BasicPSBT


_logger = get_logger(__name__)

def xfp2str(xfp):
    # Standardized way to show an xpub's fingerprint... it's a 4-byte string
    # and not really an integer. Used to show as '0x%08x' but that's wrong endian.
    return b2a_hex(pack('<I', xfp)).decode('ascii').upper()

def xfp_from_xpub(xpub):
    # sometime we need to BIP32 fingerprint value: 4 bytes of ripemd(sha256(pubkey))
    kk = bfh(Xpub.get_pubkey_from_xpub(xpub, []))
    assert len(kk) == 33
    xfp, = unpack('<I', hash_160(kk)[0:4])
    return xfp

def packed_xfp_path(xfp, text_path, int_path=[]):
    # Convert text subkey derivation path into binary format needed for PSBT
    # - binary LE32 values, first one is the fingerprint
    rv = pack('<I', xfp)

    for x in text_path.split('/'):
        if x == 'm': continue
        if x.endswith("'"):
            x = int(x[:-1]) | 0x80000000
        else:
            x = int(x)
        rv += pack('<I', x)

    for x in int_path:
        rv += pack('<I', x)

    return rv

def unpacked_xfp_path(xfp, text_path):
    # Convert text subkey derivation path into format needed for PSBT
    # - binary LE32 values, first one is the fingerprint
    # - but as ints, not bytes yet
    rv = [xfp]

    for x in text_path.split('/'):
        if x == 'm': continue
        if x.endswith("'"):
            x = int(x[:-1]) | 0x80000000
        else:
            x = int(x)
        rv.append(x)

    return rv

def xfp_for_keystore(ks):
    # Need the fingerprint of the MASTER key for a keystore we're playing with.
    xfp = getattr(ks, 'ckcc_xfp', None)

    if xfp is None:
        xfp = xfp_from_xpub(ks.get_master_public_key())
        setattr(ks, 'ckcc_xfp', xfp)

    return xfp

def packed_xfp_path_for_keystore(ks, int_path=[]):
    # Return XFP + common prefix path for keystore, as binary ready for PSBT
    derv = getattr(ks, 'derivation', 'm')
    return packed_xfp_path(xfp_for_keystore(ks), derv[2:] or 'm', int_path=int_path)

# Serialization/deserialization tools
def ser_compact_size(l):
    r = b""
    if l < 253:
        r = struct.pack("B", l)
    elif l < 0x10000:
        r = struct.pack("<BH", 253, l)
    elif l < 0x100000000:
        r = struct.pack("<BI", 254, l)
    else:
        r = struct.pack("<BQ", 255, l)
    return r

def deser_compact_size(f):
    try:
        nit = f.read(1)[0]
    except IndexError:
        return None     # end of file
    
    if nit == 253:
        nit = struct.unpack("<H", f.read(2))[0]
    elif nit == 254:
        nit = struct.unpack("<I", f.read(4))[0]
    elif nit == 255:
        nit = struct.unpack("<Q", f.read(8))[0]
    return nit

def my_var_int(l):
    # Bitcoin serialization of integers... directly into binary!
    if l < 253:
        return pack("B", l)
    elif l < 0x10000:
        return pack("<BH", 253, l)
    elif l < 0x100000000:
        return pack("<BI", 254, l)
    else:
        return pack("<BQ", 255, l)

def build_psbt(tx: Transaction, wallet: Abstract_Wallet):
    # Render a PSBT file, for possible upload to Coldcard.
    # 
    # TODO this should be part of Wallet object, or maybe Transaction?

    if getattr(tx, 'raw_psbt', False):
        _logger.info('PSBT cache hit')
        return tx.raw_psbt

    inputs = tx.inputs()
    if 'prev_tx' not in inputs[0]:
        # fetch info about inputs, if needed?
        # - needed during export PSBT flow, not normal online signing
        wallet.add_hw_info(tx)

    # wallet.add_hw_info installs this attr
    assert tx.output_info is not None, 'need data about outputs'

    # Build a map of all pubkeys needed as derivation from master XFP, in PSBT binary format
    # 1) binary version of the common subpath for all keys
    #       m/ => fingerprint LE32
    #       a/b/c => ints
    #
    # 2) all used keys in transaction:
    #    - for all inputs and outputs (when its change back)
    #    - for all keystores, if multisig
    #
    subkeys = {}
    for ks in wallet.get_keystores():

        # XFP + fixed prefix for this keystore
        ks_prefix = packed_xfp_path_for_keystore(ks)

        # all pubkeys needed for input signing
        for xpubkey, derivation in ks.get_tx_derivations(tx).items():
            pubkey = xpubkey_to_pubkey(xpubkey)

            # assuming depth two, non-harded: change + index
            aa, bb = derivation
            assert 0 <= aa < 0x80000000 and 0 <= bb < 0x80000000

            subkeys[bfh(pubkey)] = ks_prefix + pack('<II', aa, bb)

        # all keys related to change outputs
        for o in tx.outputs():
            if o.address in tx.output_info:
                # this address "is_mine" but might not be change (if I send funds to myself)
                output_info = tx.output_info.get(o.address)
                if not output_info.is_change:
                    continue
                chg_path = output_info.address_index
                assert chg_path[0] == 1 and len(chg_path) == 2, f"unexpected change path: {chg_path}"
                pubkey = ks.derive_pubkey(True, chg_path[1])
                subkeys[bfh(pubkey)] = ks_prefix + pack('<II', *chg_path)

    for txin in inputs:
        assert txin['type'] != 'coinbase', _("Coinbase not supported")

        if txin['type'] in ['p2sh', 'p2wsh-p2sh', 'p2wsh']:
            assert type(wallet) is Multisig_Wallet

    # Construct PSBT from start to finish.
    out_fd = io.BytesIO()
    out_fd.write(b'psbt\xff')

    def write_kv(ktype, val, key=b''):
        # serialize helper: write w/ size and key byte
        out_fd.write(my_var_int(1 + len(key)))
        out_fd.write(bytes([ktype]) + key)

        if isinstance(val, str):
            val = bfh(val)

        out_fd.write(my_var_int(len(val)))
        out_fd.write(val)


    # global section: just the unsigned txn
    class CustomTXSerialization(Transaction):
        @classmethod
        def input_script(cls, txin, estimate_size=False):
            return ''

    unsigned = bfh(CustomTXSerialization(tx.serialize()).serialize_to_network(witness=False))
    write_kv(PSBT_GLOBAL_UNSIGNED_TX, unsigned)

    if type(wallet) is Multisig_Wallet:

        # always put the xpubs into the PSBT, useful at least for checking
        for xp, ks in zip(wallet.get_master_public_keys(), wallet.get_keystores()):
            ks_prefix = packed_xfp_path_for_keystore(ks)

            write_kv(PSBT_GLOBAL_XPUB, ks_prefix, DecodeBase58Check(xp))

    # end globals section
    out_fd.write(b'\x00')

    # inputs section
    for txin in inputs:
        if Transaction.is_segwit_input(txin):
            utxo = txin['prev_tx'].outputs()[txin['prevout_n']]
            spendable = txin['prev_tx'].serialize_output(utxo)
            write_kv(PSBT_IN_WITNESS_UTXO, spendable)
        else:
            write_kv(PSBT_IN_NON_WITNESS_UTXO, str(txin['prev_tx']))

        pubkeys, x_pubkeys = tx.get_sorted_pubkeys(txin)

        pubkeys = [bfh(k) for k in pubkeys]

        if type(wallet) is Multisig_Wallet:
            # always need a redeem script for multisig
            scr = Transaction.get_preimage_script(txin)

            if Transaction.is_segwit_input(txin):
                # needed for both p2wsh-p2sh and p2wsh
                write_kv(PSBT_IN_WITNESS_SCRIPT, bfh(scr))
            else:
                write_kv(PSBT_IN_REDEEM_SCRIPT, bfh(scr))

        sigs = txin.get('signatures')

        for pk_pos, (pubkey, x_pubkey) in enumerate(zip(pubkeys, x_pubkeys)):
            if pubkey in subkeys:
                # faster? case ... calculated above
                write_kv(PSBT_IN_BIP32_DERIVATION, subkeys[pubkey], pubkey)
            else:
                # when an input is partly signed, tx.get_tx_derivations()
                # doesn't include that keystore's value and yet we need it
                # because we need to show a correct keypath... 
                assert x_pubkey[0:2] == 'ff', x_pubkey

                for ks in wallet.get_keystores():
                    d = ks.get_pubkey_derivation(x_pubkey)
                    if d is not None:
                        ks_path = packed_xfp_path_for_keystore(ks, d)
                        write_kv(PSBT_IN_BIP32_DERIVATION, ks_path, pubkey)
                        break
                else:
                    raise AssertionError("no keystore for: %s" % x_pubkey)

            if txin['type'] == 'p2wpkh-p2sh':
                assert len(pubkeys) == 1, 'can be only one redeem script per input'
                pa = hash_160(pubkey)
                assert len(pa) == 20
                write_kv(PSBT_IN_REDEEM_SCRIPT, b'\x00\x14'+pa)

            # optional? insert (partial) signatures that we already have
            if sigs and sigs[pk_pos]:
                write_kv(PSBT_IN_PARTIAL_SIG, bfh(sigs[pk_pos]), pubkey)

        out_fd.write(b'\x00')

    # outputs section
    for o in tx.outputs():
        # can be empty, but must be present, and helpful to show change inputs
        # wallet.add_hw_info() adds some data about change outputs into tx.output_info
        if o.address in tx.output_info:
            # this address "is_mine" but might not be change (if I send funds to myself)
            output_info = tx.output_info.get(o.address)
            if output_info.is_change:
                pubkeys = [bfh(i) for i in wallet.get_public_keys(o.address)]

                # Add redeem/witness script?
                if type(wallet) is Multisig_Wallet:
                    # always need a redeem script for multisig cases
                    scr = bfh(multisig_script([bh2u(i) for i in sorted(pubkeys)], wallet.m))

                    if output_info.script_type == 'p2wsh-p2sh':
                        write_kv(PSBT_OUT_WITNESS_SCRIPT, scr)
                        write_kv(PSBT_OUT_REDEEM_SCRIPT, b'\x00\x20' + sha256(scr))
                    elif output_info.script_type == 'p2wsh':
                        write_kv(PSBT_OUT_WITNESS_SCRIPT, scr)
                    elif output_info.script_type == 'p2sh':
                        write_kv(PSBT_OUT_REDEEM_SCRIPT, scr)
                    else:
                        raise ValueError(output_info.script_type)

                elif output_info.script_type == 'p2wpkh-p2sh':
                    # need a redeem script when P2SH is used to wrap p2wpkh
                    assert len(pubkeys) == 1
                    pa = hash_160(pubkeys[0])
                    write_kv(PSBT_OUT_REDEEM_SCRIPT, b'\x00\x14' + pa)

                # Document change output's bip32 derivation(s)
                for pubkey in pubkeys:
                    sk = subkeys[pubkey]
                    write_kv(PSBT_OUT_BIP32_DERIVATION, sk, pubkey)

        out_fd.write(b'\x00')

    # capture for later use
    tx.raw_psbt = out_fd.getvalue()

    return tx.raw_psbt


def recover_tx_from_psbt(first: BasicPSBT, wallet: Abstract_Wallet) -> Transaction:
    # Take a PSBT object and re-construct the Electrum transaction object.
    # - does not include signatures, see merge_sigs_from_psbt
    # - any PSBT in the group could be used for this purpose; all must share tx details
    
    tx = Transaction(first.txn.hex())
    tx.deserialize(force_full_parse=True)

    # .. add back some data that's been preserved in the PSBT, but isn't part of
    # of the unsigned bitcoin txn
    tx.is_partial_originally = True

    for idx, inp in enumerate(tx.inputs()):
        scr = first.inputs[idx].redeem_script or first.inputs[idx].witness_script

        # XXX should use transaction.py parse_scriptSig() here!
        if scr:
            try:
                M, N, __, pubkeys, __ = parse_redeemScript_multisig(scr)
            except NotRecognizedRedeemScript:
                # limitation: we can only handle M-of-N multisig here
                raise ValueError("Cannot handle non M-of-N multisig input")

            inp['pubkeys'] = pubkeys
            inp['x_pubkeys'] = pubkeys
            inp['num_sig'] = M
            inp['type'] = 'p2wsh' if first.inputs[idx].witness_script else 'p2sh'

            # bugfix: transaction.py:parse_input() puts empty dict here, but need a list
            inp['signatures'] = [None] * N

        if 'prev_tx' not in inp:
            # fetch info about inputs' previous txn
            wallet.add_hw_info(tx)

        if 'value' not in inp:
            # we'll need to know the value of the outpts used as part
            # of the witness data, much later...
            inp['value'] = inp['prev_tx'].outputs()[inp['prevout_n']].value

    return tx

def merge_sigs_from_psbt(tx: Transaction, psbt: BasicPSBT):
    # Take new signatures from PSBT, and merge into in-memory transaction object.
    # - "we trust everyone here" ... no validation/checks

    count = 0
    for inp_idx, inp in enumerate(psbt.inputs):
        if not inp.part_sigs:
            continue

        scr = inp.redeem_script or inp.witness_script

        # need to map from pubkey to signing position in redeem script
        M, N, _, pubkeys, _ = parse_redeemScript_multisig(scr)
        #assert (M, N) == (wallet.m, wallet.n)

        for sig_pk in inp.part_sigs:
            pk_pos = pubkeys.index(sig_pk.hex())
            tx.add_signature_to_txin(inp_idx, pk_pos, inp.part_sigs[sig_pk].hex())
            count += 1

        #print("#%d: sigs = %r" % (inp_idx, tx.inputs()[inp_idx]['signatures']))
    
    # reset serialization of TX
    tx.raw = tx.serialize()
    tx.raw_psbt = None

    return count

# EOF

