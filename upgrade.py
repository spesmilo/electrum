import electrum, base64, ast, sys, os, getpass
from version import SEED_VERSION

try:
    from lib.util import print_error
except ImportError:
    from electrum.util import print_error

if __name__ == "__main__":
    try:
        path = sys.argv[1]
    except:
        # backward compatibility: look for wallet file in the default data directory
        if "HOME" in os.environ:
            wallet_dir = os.path.join( os.environ["HOME"], '.electrum')
        elif "LOCALAPPDATA" in os.environ:
            wallet_dir = os.path.join( os.environ["LOCALAPPDATA"], 'Electrum' )
        elif "APPDATA" in os.environ:
            wallet_dir = os.path.join( os.environ["APPDATA"],  'Electrum' )
        else:
            raise BaseException("No home directory found in environment variables.")
        path = os.path.join( wallet_dir, 'electrum.dat')

    try:
        f = open(path,"r")
        data = f.read()
        f.close()
    except:
        print_error("Error: File not found: " + path)
        exit(1)

    try:
        x = ast.literal_eval(data)
    except:
        print_error("Error: Could not parse wallet")
        exit(1)

    # version <= 0.33 uses a tuple
    if type(x) == tuple:
        seed_version, use_encryption, fee, host, port, blocks, seed, all_addresses, private_keys, change_indexes, status, history, labels, addressbook = x

        print "walet path =",path
        print "seed version =", seed_version

        if seed_version == 1 and use_encryption:
            # version 1 used pycrypto for wallet encryption
            import Crypto
            from Crypto.Cipher import AES
            BLOCK_SIZE = 32
            PADDING = '{'
            pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
            EncodeAES = lambda secret, s: base64.b64encode(AES.new(secret).encrypt(pad(s)))
            DecodeAES = lambda secret, e: AES.new(secret).decrypt(base64.b64decode(e)).rstrip(PADDING)

            print "Please enter your password"
            password = getpass.getpass("Password:")
            secret = electrum.Hash(password)
            try:
                seed = DecodeAES( secret, wallet.seed )
                private_keys = ast.literal_eval( DecodeAES( secret, wallet.private_keys ) )
            except:
                print_error("Error: Password does not decrypt this wallet.")
                exit(1)
            seed_version = 2
            s = repr( (seed_version, use_encryption, fee, host, port, blocks, seed, all_addresses, private_keys, change_indexes, status, history, labels, addressbook ))
            f = open(path,"w")
            data = f.read()
            f.close()
            print "Wallet is now unencrypted."

        print """This wallet is deprecated.
Please create a new wallet, open the old wallet with Electrum 0.33, and send your coins to your new wallet.
We apologize for the inconvenience. We try to keep this kind of upgrades as rare as possible."""

    
        

