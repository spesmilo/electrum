import electrum, getpass, base64,ast,sys



def upgrade_wallet(wallet):
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
    if wallet.version < 3:
        print """
Your wallet is deprecated; its generation seed will not work with versions 0.31 and above.
In order to upgrade, you need to create a new wallet (you may use your current seed), and
to send your bitcoins to the new wallet.

We apologize for the inconvenience. We try to keep this kind of upgrades as rare as possible.
"""


if __name__ == "__main__":
    try:
        path = sys.argv[1]
    except:
        path = None
    wallet = electrum.Wallet(path)
    try:
        found = wallet.read()
        if found:
            print wallet.path
        else:
            print "wallet not found."
    except BaseException:
        upgrade_wallet(wallet)
        

