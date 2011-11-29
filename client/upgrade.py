import electrum, getpass, base64,ast

wallet = electrum.Wallet(None)
try:
    wallet.read()
    print "ok"
except BaseException:
    if wallet.version == 1 and wallet.use_encryption:
        # version 1 used pycrypto for wallet encryption
        import Crypto
        from Crypto.Cipher import AES
        BLOCK_SIZE = 32
        PADDING = '{'
        pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
        EncodeAES = lambda secret, s: base64.b64encode(AES.new(secret).encrypt(pad(s)))
        DecodeAES = lambda secret, e: AES.new(secret).decrypt(base64.b64decode(e)).rstrip(PADDING)

        print "encrypted seed", wallet.seed
        print "please provide your password"
        password = getpass.getpass("Password:")
        secret = electrum.Hash(password)
        try:
            seed = DecodeAES( secret, wallet.seed )
            private_keys = ast.literal_eval( DecodeAES( secret, wallet.private_keys ) )
        except:
            print "sorry"
            exit(1)
        print seed
        print private_keys
        wallet.version = 2
        wallet.seed = wallet.pw_encode( seed, password)
        wallet.private_keys = wallet.pw_encode( repr( private_keys ), password)
        wallet.save()
        print "wallet was upgraded"
