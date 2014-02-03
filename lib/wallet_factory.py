from version import SEED_VERSION
from wallet import OldWallet, Wallet

class WalletFactory(object):
    def __new__(self, storage):

        if storage.get('bitkey', False):
            # if user requested support for Bitkey device,
            # import Bitkey driver
            from wallet_bitkey import WalletBitkey
            return WalletBitkey(config)
        
        seed_version = storage.get('seed_version', SEED_VERSION)
        if seed_version not in [4, 6]:
            msg = "This wallet seed is not supported."
            if seed_version in [5]:
                msg += "\nTo open this wallet, try 'git checkout seed_v%d'"%seed_version
                print msg
                sys.exit(1)


        if seed_version == 4:
            return OldWallet(storage)
        else:
            return Wallet(storage)


    @classmethod
    def from_seed(self, seed, storage):
        import mnemonic
        if not seed:
            return 

        words = seed.strip().split()
        try:
            mnemonic.mn_decode(words)
            uses_electrum_words = True
        except Exception:
            uses_electrum_words = False

        try:
            seed.decode('hex')
            is_hex = True
        except Exception:
            is_hex = False
         
        if is_hex or (uses_electrum_words and len(words) != 13):
            print "old style wallet", len(words), words
            w = OldWallet(storage)
            w.init_seed(seed) #hex
        else:
            #assert is_seed(seed)
            w = Wallet(storage)
            w.init_seed(seed)


        return w
