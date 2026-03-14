import hashlib
from electrum.transaction import TxOutput

def is_silent_payment_output(output: TxOutput) -> bool:
    """
    BIP 352 outputs are P2TR (OP_1 0x20 [32-byte pubkey]).
    A standard P2TR scriptPubKey is 34 bytes long (1 byte OP_1, 1 byte PUSHDATA32, 32 bytes x-only pubkey).
    """
    return len(output.scriptpubkey) == 34 and output.scriptpubkey.startswith(b'\x51\x20')

def sort_outpoints(outpoints):
    """
    Lexicographical sort of outpoints as required by BIP 352.
    Outpoint = txid (32 bytes) + vout (4 bytes, little-endian).
    """
    # Sort primarily by txid, secondarily by vout index
    return sorted(outpoints, key=lambda x: x['txid'] + x['vout'].to_bytes(4, 'little'))

def calculate_integrity_hash(inputs, outputs):
    """
    Calculates the integrity hash of the transaction to detect tampering.
    hash = sha256(sorted_outpoints || sum_of_input_pubkeys)
    """
    # 1. Collect and sort outpoints
    outpoints = [{"txid": i.prevout.txid.hex(), "vout": i.prevout.out_idx} for i in inputs]
    sorted_ops = sort_outpoints(outpoints)
    
    # 2. Serialize and hash
    hasher = hashlib.sha256()
    for op in sorted_ops:
        hasher.update(bytes.fromhex(op['txid']))
        hasher.update(op['vout'].to_bytes(4, 'little'))
    
    # Add input pubkeys sum logic here (requires ecc.point_add)
    # ...
    return hasher.digest()