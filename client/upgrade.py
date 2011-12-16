import electrum, getpass, base64,ast,sys,os
from version import SEED_VERSION



def upgrade_wallet(wallet):
    print "walet path:",wallet.path
    print "seed version:", wallet.seed_version
    if wallet.seed_version == 1 and wallet.use_encryption:
        # version 1 used pycrypto for wallet encryption
        import Crypto
        from Crypto.Cipher import AES
        BLOCK_SIZE = 32
        PADDING = '{'
        pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
        EncodeAES = lambda secret, s: base64.b64encode(AES.new(secret).encrypt(pad(s)))
        DecodeAES = lambda secret, e: AES.new(secret).decrypt(base64.b64decode(e)).rstrip(PADDING)

        print "please enter your password"
        password = getpass.getpass("Password:")
        secret = electrum.Hash(password)
        try:
            seed = DecodeAES( secret, wallet.seed )
            private_keys = ast.literal_eval( DecodeAES( secret, wallet.private_keys ) )
        except:
            print "sorry"
            exit(1)
        wallet.version = 2
        wallet.seed = wallet.pw_encode( seed, password)
        wallet.private_keys = wallet.pw_encode( repr( private_keys ), password)
        wallet.save()
        print "upgraded to version 2"
        exit(1)

    if wallet.seed_version < SEED_VERSION:
        print """Note: your wallet seed is deprecated. Please create a new wallet, and move your coins to the new wallet."""


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
        print "file not found", path
        exit(1)

    try:
        x = ast.literal_eval(data)
    except:
        print "error: could not parse wallet"
        exit(1)

    if type(x) == tuple:
        seed_version, use_encryption, fee, host, port, blocks, seed, all_addresses, private_keys, change_indexes, status, history, labels, addressbook = x
        print """This wallet is deprecated.
Please create a new wallet, open the old wallet with Electrum 0.33, and send your coins to your new wallet.
We apologize for the inconvenience. We try to keep this kind of upgrades as rare as possible."""
        exit(1)
    
    wallet = electrum.Wallet(path)
    try:
        found = wallet.read()
        if found:
            print wallet.path
        else:
            print "wallet not found."
    except BaseException:
        upgrade_wallet(wallet)
        

