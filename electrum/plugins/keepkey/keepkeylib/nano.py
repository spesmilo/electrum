import struct

def encode_balance(balance):
    if balance is None:
        return None
    (ih, il) = (balance >> 64, balance & 0xFFFFFFFFFFFFFFFF)
    return struct.pack('>Q', ih) + struct.pack('>Q', il)
