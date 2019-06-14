#
# build_psbt.py - create a PSBT from (unsigned) transaction and keystore data.
#
import io, struct
from base64 import b64decode
from binascii import a2b_hex, b2a_hex
from struct import pack, unpack

from electrum.transaction import Transaction, multisig_script

from electrum.logging import get_logger
from electrum.wallet import Standard_Wallet, Multisig_Wallet, Wallet
from electrum.keystore import xpubkey_to_pubkey
from electrum.util import bfh, bh2u
from electrum.crypto import hash_160
from electrum.bitcoin import DecodeBase58Check

from .basic_psbt import (
        PSBT_GLOBAL_UNSIGNED_TX, PSBT_GLOBAL_XPUB, PSBT_IN_NON_WITNESS_UTXO, PSBT_IN_WITNESS_UTXO,
        PSBT_IN_SIGHASH_TYPE, PSBT_IN_REDEEM_SCRIPT, PSBT_IN_WITNESS_SCRIPT,
        PSBT_IN_BIP32_DERIVATION, PSBT_OUT_BIP32_DERIVATION, PSBT_OUT_REDEEM_SCRIPT)

from electrum.logging import get_logger
from electrum.wallet import Standard_Wallet, Multisig_Wallet, Wallet
from electrum.keystore import xpubkey_to_pubkey
from electrum.util import bfh, bh2u
from electrum.crypto import hash_160
from electrum.bitcoin import DecodeBase58Check


_logger = get_logger(__name__)

def xfp2str(xfp):
    # Standardized way to show an xpub's fingerprint... it's a 4-byte string
    # and not really an integer. Used to show as '0x%08x' but that's wrong endian.

    return b2a_hex(pack('>I', xfp)).decode('ascii').upper()

def xfp_from_xpub(xpub):
    # sometime we need to BIP32 fingerprint value: 4 bytes of ripemd(sha256(pubkey))
    kk = bfh(Xpub.get_pubkey_from_xpub(xpub, []))
    assert len(kk) == 33
    xfp, = unpack('<I', hash_160(kk)[0:4])
    return xfp

def packed_xfp_path(xfp, text_path):
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

def build_psbt(tx: Transaction, wallet: Wallet):
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
        ks_prefix = packed_xfp_path(xfp_for_keystore(ks), ks.get_derivation()[2:])

        # all pubkeys needed for input signing
        for xpubkey, derivation in ks.get_tx_derivations(tx).items():
            pubkey = xpubkey_to_pubkey(xpubkey)

            # assuming depth two, non-harded: change + index
            aa, bb = derivation
            assert 0 <= aa < 0x80000000
            assert 0 <= bb < 0x80000000

            subkeys[bfh(pubkey)] = ks_prefix + pack('<II', aa, bb)

        # all keys related to change outputs
        for o in tx.outputs():
            if o.address in tx.output_info:
                # this address "is_mine" but might not be change (if I send funds to myself)
                chg_path = tx.output_info.get(o.address).address_index

                if chg_path[0] != 1 or len(chg_path) != 2:
                    # not change.
                    continue

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
            xfp = xfp_for_keystore(ks)

            dd = getattr(ks, 'derivation', 'm')

            write_kv(PSBT_GLOBAL_XPUB, packed_xfp_path(xfp, dd), DecodeBase58Check(xp))

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
            write_kv(PSBT_IN_REDEEM_SCRIPT, bfh(scr))

        for k in pubkeys:
            write_kv(PSBT_IN_BIP32_DERIVATION, subkeys[k], k)

            if txin['type'] == 'p2wpkh-p2sh':
                assert len(pubkeys) == 1, 'can be only one redeem script per input'
                pa = hash_160(k)
                assert len(pa) == 20
                write_kv(PSBT_IN_REDEEM_SCRIPT, b'\x00\x14'+pa)

        # TODO optional: insert (partial) signatures that we already have!

        out_fd.write(b'\x00')

    # outputs section
    for o in tx.outputs():
        # can be empty, but must be present, and helpful to show change inputs
        # wallet.add_hw_info() adds some data about change outputs into tx.output_info
        if o.address in tx.output_info:
            # this address "is_mine" but might not be change (if I send funds to myself)
            output_info = tx.output_info.get(o.address)
            chg_path, master_xpubs = output_info.address_index, output_info.sorted_xpubs

            if chg_path[0] == 1 and len(chg_path) == 2:
                # it is a change output (based on our standard derivation path)
                pubkeys = [bfh(i) for i in wallet.get_public_keys(o.address)]

                # always need a redeem script for multisig
                if type(wallet) is Multisig_Wallet:
                    scr = multisig_script([bh2u(i) for i in sorted(pubkeys)], wallet.m)
                    write_kv(PSBT_OUT_REDEEM_SCRIPT, bfh(scr))

                # document change output's bip32 derivation(s)
                for pubkey in pubkeys:
                    sk = subkeys[pubkey]
                    write_kv(PSBT_OUT_BIP32_DERIVATION, sk, pubkey)

                    if output_info.script_type == 'p2wpkh-p2sh':
                        assert len(pa) == 20
                        assert len(pubkeys) == 1
                        pa = hash_160(pubkey)
                        write_kv(PSBT_OUT_REDEEM_SCRIPT, b'\x00\x14' + pa)

        out_fd.write(b'\x00')

    # capture for later use
    tx.raw_psbt = out_fd.getvalue()

    return tx.raw_psbt


# EOF

