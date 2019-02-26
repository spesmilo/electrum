from smartcard.sw.SWExceptions import SWException

from CardConnector import CardConnector
from CardDataParser import CardDataParser
from JCconstants import JCconstants

from electrum.lib.crypto import hash_160
from electrum.lib.bitcoin import serialize_xpub

if __name__ == "__main__":
    
    
    # static test
    cc= CardConnector()
    parser= CardDataParser()
    
    std_keynbr=0x00;
    bip32_keynbr=0xff;
    
    # test PIN
    pin2_nbr = 2;
    pin2_tries = 3;
    pin2 = [30,30,30,30];
    ublk2 = [31,31,31,31];

    # test message signing
    strmsg= "abcdefghijklmnopqrstuvwxyz0123456789"
    default_bip32path=[0x80, 0x00, 0x00, 0x00]
    
    ###########################
    #        CARD_SELECT      #
    ###########################
    try:
        (response, sw1, sw2)=cc.card_select()
    except SWException as e:
        print(e)
    
    ###########################
    #         CARD_SETUP      #
    ###########################
    
    # setup params done only once
    pin_tries_0= 0x10;
    ublk_tries_0= 0x10;
    pin_0=[0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38]
    ublk_0=[0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38]
    pin_tries_1= 0x10
    ublk_tries_1= 0x10
    pin_1=[0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38]
    ublk_1=[0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38]
    secmemsize= 0x1000
    memsize= 0x1000
    create_object_ACL= 0x01
    create_key_ACL= 0x01
    create_pin_ACL= 0x01
    option_flags= 0x8000 # activate 2fa with hmac challenge-response
    #key= new byte[20]
    amount_limit= 0
    try:
        print("cardSetup:")
        (response, sw1, sw2)=cc.card_setup(pin_tries_0, ublk_tries_0, pin_0, ublk_0,
                    pin_tries_1, ublk_tries_1, pin_1, ublk_1, 
                    secmemsize, memsize, 
                    create_object_ACL, create_key_ACL, create_pin_ACL
                    #,option_flags, key, amount_limit
            )
    except SWException as e:
        if cc.get_sw12(e.sw1,e.sw2)!=0x6d00:
            print("setup already done")
        else:
            print("Unable to set up applet")
    
    ##################################
    #         CARD_VERIFY_PIN        #
    ##################################
    print("card_verify_PIN");
    cc.card_verify_PIN(0, pin_0)
    
    
    ##################################
    #    CARD_BIP32_IMPORT_SEED      #
    ##################################
    
    print("cardBip32ImportSeed")
        
    # import seed to HWchip
    seed= bytes([0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]) # Bip32 test vectors
    #seed= b'1234567812345678' #'31323334353637383132333435363738' # ascii for 1234567812345678
    authentikey= None
    
    seed_ACL= JCconstants.DEFAULT_ACL #{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
    (response,sw1,sw2)= cc.card_bip32_import_seed(seed_ACL, seed)
    
    authentikey= parser.parse_bip32_import_seed(response).authentikey
    print("authentikey (compressed):  "+ authentikey.get_public_key_hex(compressed=True))
    print("authentikey (uncompressed):"+ authentikey.get_public_key_hex(compressed=False))
    
    
    # create SW masterkey equivalent with bitcoinj
    #masterkey= HDKeyDerivation.createMasterPrivateKey(seed); 

    ##################################
    #   CARD_BIP32_GET_AUTHENTIKEY   #
    ##################################
    
    print("cardBip32GetAuthentiKey");
    (response, sw1, sw2)= cc.card_bip32_get_authentikey()
    
    authentikey2= parser.parse_bip32_import_seed(response).authentikey
    print("authentikey (compressed):  "+ authentikey2.get_public_key_hex(compressed=True))
    print("authentikey (uncompressed):"+ authentikey2.get_public_key_hex(compressed=False))
    assert authentikey==authentikey2    
    
    ##################################
    #  CARD_BIP32_GET_EXTENDEDKEY    #
    ##################################
    
    print("cardBip32GetExtendedKey");
    # test vectors from https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#Test_vector_1
    # chain m
    bip32path= []
    (response, sw1, sw2)= cc.card_bip32_get_extendedkey(bip32path)
    (masterkey, chaincode)= parser.parse_bip32_get_extendedkey(response)
    fingerprint= bytes([0,0,0,0])
    depth=0
    child_number= bytes([0,0,0,0])
    xpub= serialize_xpub('standard', chaincode, masterkey.get_public_key_bytes(compressed=True), depth, fingerprint, child_number)
    print("Masterkey (compressed):  "+ masterkey.get_public_key_hex(compressed=True))
    print("Masterkey (uncompressed):"+ masterkey.get_public_key_hex(compressed=False))
    print("Master chaincode: "+parser.chaincode.hex())
    print("xpub: " + xpub)
    xpub_expected="xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
    assert xpub== xpub_expected, "Bip32 error - expected:"+xpub_expected+", got:"+xpub
    print("\n\n")
    
    # chain m/0':
    bip32path= [0x80, 0, 0, 0]
    (response, sw1, sw2)= cc.card_bip32_get_extendedkey(bip32path)
    (key1, chaincode)= parser.parse_bip32_get_extendedkey(response)
    fingerprint= hash_160(masterkey.get_public_key_bytes(compressed=True))[0:4]
    depth=1
    child_number= bytes([0x80,0,0,0])
    xpub= serialize_xpub('standard', chaincode, key1.get_public_key_bytes(compressed=True), depth, fingerprint, child_number)
    print("Extended key for path:" + str(bip32path))
    print("extendedkey (compressed):  "+ key1.get_public_key_hex(compressed=True))
    print("extendedkey (uncompressed):"+ key1.get_public_key_hex(compressed=False))
    print("chaincode: "+parser.chaincode.hex())
    print("xpub: " + xpub)
    xpub_expected="xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"
    assert xpub== xpub_expected, "Bip32 error - expected:"+xpub_expected+", got:"+xpub
    print("\n\n")
    
    # chain m/0'/1
    bip32path= [0x80, 0, 0, 0,  0, 0, 0, 1]
    depth=2
    fingerprint= hash_160(key1.get_public_key_bytes(compressed=True))[0:4]
    child_number= bytes([0,0,0,1])
    (response, sw1, sw2)= cc.card_bip32_get_extendedkey(bip32path)
    (childkey,chaincode)= parser.parse_bip32_get_extendedkey(response)
    xpub= serialize_xpub('standard', chaincode, childkey.get_public_key_bytes(compressed=True), depth, fingerprint, child_number)
    print("Extended key for path:" + str(bip32path))
    print("extendedkey (compressed):  "+ childkey.get_public_key_hex(compressed=True))
    print("extendedkey (uncompressed):"+ childkey.get_public_key_hex(compressed=False))
    print("chaincode: "+parser.chaincode.hex())
    print("xpub: " + xpub)
    print("\n\n")
    xpub_expected="xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ"
    assert xpub== xpub_expected, "Bip32 error - expected:"+xpub_expected+", got:"+xpub

    # valmax=1;
    # depthmax=4;
    # for val in range(valmax):
        # for depth in range(1,depthmax):
            # for child in [0, 0x80]: # normal or hardened child
                # bip32path= depth*[child, 0, 0, val]
                # (response, sw1, sw2)= cc.card_bip32_get_extendedkey(bip32path)
                # keyhw= parser.parse_bip32_get_extendedkey(response).pubkey
                # #keysw=testCardBip32GetExtendedKey_bitcoinj(bip32path)#SW
                # #assert (keyhw==keysw)
                
                # print("Extended key for path:" + str(bip32path))
                # print("extendedkey (compressed):  "+ keyhw.get_public_key_hex(compressed=True))
                # print("extendedkey (uncompressed):"+ keyhw.get_public_key_hex(compressed=False))
                # print("chaincode: "+parser.chaincode.hex())
    
    
    ##################################
    #         CARD_TX        #
    ##################################
    #TODO
        

    
    
