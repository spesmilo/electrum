from electrum import keystore
from electrum.keystore import Old_KeyStore, BIP32_KeyStore
from electrum.mnemonic import seed_type, Mnemonic
from electrum.util import BitcoinException


def from_seed(seed, passphrase, is_p2sh=False):
    t = seed_type(seed)
    if t == 'old':
        keystore = Old_KeyStore({})
        keystore.add_seed(seed)
    elif t in ['standard', 'segwit']:
        keystore = BIP32_KeyStore({})
        keystore.add_seed(seed)
        keystore.passphrase = passphrase
        bip32_seed = Mnemonic.mnemonic_to_seed(seed, passphrase)
        if t == 'standard':
            der = "m/"
            xtype = 'standard'
        else:
            der = "m/1'/" if is_p2sh else "m/0'/"
            xtype = 'p2wsh' if is_p2sh else 'p2wpkh'
        keystore.add_xprv_from_seed(bip32_seed, xtype, der)
    else:
        raise BitcoinException('Unexpected seed type {}'.format(repr(t)))
    return keystore


def from_seed_patch(func):
    def wrapper(*args, **kwargs):
        # monkey patching, only for test purposes
        orignal_function = keystore.from_seed
        keystore.from_seed = from_seed
        try:
            return func(*args, **kwargs)
        finally:
            keystore.from_seed = orignal_function
    return wrapper
