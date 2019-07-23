import unittest
from unittest.mock import MagicMock

#satochip
from .CardConnector import CardConnector
from .CardConnector import UninitializedSeedError
from .CardDataParser import CardDataParser
from .satochip import bip32path2bytes, SatochipClient

class TestCardConnectorMethods(unittest.TestCase):

    def setUp(self):
        plugin= MagicMock()
        handler= MagicMock()
        self.client= SatochipClient(plugin, handler) #SatochipClient
        #self.parser= CardDataParser()
        #self.client.parser= self.parser
        #self.cc= CardConnector(self.client)
        self.parser= self.client.parser
        self.cc= self.client.cc
        
        print(f"[SetUp] SatochipClient: __init__(): cc.card_get_ATR(): {self.cc.card_get_ATR()}")#debugSatochip
        print(f"[SetUp] SatochipClient: __init__(): cc.card_select()")#debugSatochip
        (response, sw1, sw2)=self.cc.card_select()
    
        (response, sw1, sw2, d)=self.cc.card_get_status()
        if (sw1==0x90 and sw2==0x00):
            v_supported= (CardConnector.SATOCHIP_PROTOCOL_MAJOR_VERSION<<8)+CardConnector.SATOCHIP_PROTOCOL_MINOR_VERSION
            v_applet= (d["protocol_major_version"]<<8)+d["protocol_minor_version"] 
            if (v_supported!=v_applet):
                print(f"version_satochip= {str(CardConnector.SATOCHIP_PROTOCOL_MAJOR_VERSION)}.{str(CardConnector.SATOCHIP_PROTOCOL_MINOR_VERSION)}")
                print(f"version-electrum= {str(d['protocol_major_version'])}.{str(d['protocol_minor_version'])}")
        # setup device (done only once)
        elif (sw1==0x9c and sw2==0x04):
            pin_0=[0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38]
            self.cc.set_pin(0, pin_0) #cache PIN value in client
            pin_tries_0= 0x10;
            ublk_tries_0= 0x01;
            ublk_0=[0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38]
            pin_tries_1= 0x01
            ublk_tries_1= 0x01
            pin_1=[0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38]
            ublk_1=[0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38]
            secmemsize= 32 # number of slot reserved in memory cache
            memsize= 0x0000 # RFU
            create_object_ACL= 0x01
            create_key_ACL= 0x01
            create_pin_ACL= 0x01
            #option_flags= 0x8000 # activate 2fa with hmac challenge-response
            #key= new byte[20]
            #amount_limit= 0
            print("[SetUp] perform cardSetup:")#debugSatochip
            (response, sw1, sw2)=self.cc.card_setup(pin_tries_0, ublk_tries_0, pin_0, ublk_0,
                    pin_tries_1, ublk_tries_1, pin_1, ublk_1, 
                    secmemsize, memsize, 
                    create_object_ACL, create_key_ACL, create_pin_ACL
                    #,option_flags, key, amount_limit
                )
            if sw1!=0x90 or sw2!=0x00:                 
                print(f"[satochip] SatochipPlugin: setup_device(): unable to set up applet!  sw12={hex(sw1)} {hex(sw2)}")#debugSatochip
                raise RuntimeError('Unable to setup the device with error code:'+hex(sw1)+' '+hex(sw2))
        else:
            print(f"[satochip] SatochipPlugin: unknown get-status() error! sw12={hex(sw1)} {hex(sw2)}")#debugSatochip
            raise RuntimeError('Unknown get-status() error code:'+hex(sw1)+' '+hex(sw2))
            
        # verify pin:
        while (True):
            pin_0= [0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38]
            (response, sw1, sw2)=self.cc.card_verify_PIN_deprecated(0, pin_0)
            if sw1==0x90 and sw2==0x00: 
                self.cc.set_pin(0, pin_0) #cache PIN value in client
                break
            elif sw1==0x9c and sw2==0x02:
                print("Wrong PIN!")
            elif sw1==0x9c and sw2==0x0c:
                print("Too many failed attempts! Your Satochip has been blocked! You need your PUK code to unblock it.")
                raise RuntimeError('Unknown get-status() error code:'+hex(sw1)+' '+hex(sw2))
                
        # import seed
        try:
            authentikey=self.cc.card_bip32_get_authentikey()
        except UninitializedSeedError:
            # test seed dialog...
            print("[satochip] SatochipPlugin: setup_device(): import seed:") #debugSatochip
            seed= [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15] # Bip32 test vectors
            authentikey= self.cc.card_bip32_import_seed(seed) 
    
    def tearDown(self):
        self.client.close()
    
    #@unittest.skip("debug")
    def test_card_bip32_get_authentikey(self): 
        print("\n\n[test_CardConnector] test_card_bip32_getauthentikey:") #debugSatochip
        seed= [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]
        authentikey= self.cc.card_bip32_import_seed(seed) 
        authentikey_hex=authentikey.get_public_key_bytes(compressed=False).hex()
        
        authentikeyb=self.cc.card_bip32_get_authentikey()
        authentikeyb_hex= authentikeyb.get_public_key_bytes(compressed=False).hex()
        self.assertEqual(authentikey_hex, authentikeyb_hex)
        self.assertEqual(authentikey_hex, "0489a8fc4af602ca1ddbeb8020e4d629e36e655c47ba62313af4f3405b968f0d5e99a61804578c0f7f5096827adb707a8cb625c83dcf0893196d9418b2baf59039")

    #@unittest.skip("debug")
    def test_card_bip32_get_extendedkey_seed_vector1(self):  
        # Bip32 test vectors 1 (https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#Test_Vectors)
        print("\n\n[test_CardConnector] test_card_bip32_get_extendedkey_seed_vector1:") #debugSatochip
        seed= [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]
        authentikey= self.cc.card_bip32_import_seed(seed) 
        paths=[ "m",
                "m/0'",
                "m/0'/1",
                "m/0'/1/2'",
                "m/0'/1/2'/2",
                "m/0'/1/2'/2/1000000000"]
        xpubs=[ "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
                "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw",
                "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ",
                "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5",
                "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV",
                "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy"]        
        #subtests
        for i in range(0, len(paths)):
            with self.subTest(i=i):
                #xpub= get_xpub(self.cc, self.parser, paths[i])
                xpub= self.client.get_xpub(paths[i], 'standard')
                self.assertEqual(xpub, xpubs[i])
    
    #@unittest.skip("debug")
    def test_card_bip32_get_extendedkey_seed_vector2(self):
        print("\n\n[test_CardConnector] test_card_bip32_get_extendedkey_seed_vector2:") #debugSatochip
        seed= list(bytes.fromhex("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"))
        authentikey= self.cc.card_bip32_import_seed(seed) 
        paths=[ "m",
                "m/0",
                "m/0/2147483647'",
                "m/0/2147483647'/1",
                "m/0/2147483647'/1/2147483646'",
                "m/0/2147483647'/1/2147483646'/2"]
        xpubs=[ "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB",
                "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH",
                "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a",
                "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon",
                "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL",
                "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt"]    
        #subtests
        for i in range(0, len(paths)):
            with self.subTest(i=i):
                #xpub= get_xpub(self.cc, self.parser, paths[i])
                xpub= self.client.get_xpub(paths[i], 'standard')
                self.assertEqual(xpub, xpubs[i])

    #@unittest.skip("debug")
    def test_card_bip32_get_extendedkey_seed_vector3(self):
        print("\n\n[test_CardConnector] test_card_bip32_get_extendedkey_seed_vector3:") #debugSatochip
        seed= list(bytes.fromhex("4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be"))
        authentikey= self.cc.card_bip32_import_seed(seed) 
        paths=[ "m",
                "m/0'"]
        xpubs=[ "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13",
                "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y"]
        #subtests
        for i in range(0, len(paths)):
            with self.subTest(i=i):
                #xpub= get_xpub(self.cc, self.parser, paths[i])
                xpub= self.client.get_xpub(paths[i], 'standard')
                self.assertEqual(xpub, xpubs[i])
    
    def test_card_sign_message(self):
        print("\n\n[test_CardConnector] test_card_sign_message:") #debugSatochip
        msgs=[  "",
                " ",
                "Hello World",
                "The quick brown fox jumps over the lazy dog",
                8*"The quick brown fox jumps over the lazy dog"]
        (depth, bytepath)= bip32path2bytes("m/0'")
        (childkey, childchaincode)=self.cc.card_bip32_get_extendedkey(bytepath)
        keynbr= 0xFF
        #subtests
        for i in range(0, len(msgs)):
            with self.subTest(i=i):
                print("Signing message "+str(i)+" : "+msgs[i] + "...")
                msg=msgs[i]
                (response, sw1,sw2)=self.cc.card_sign_message(keynbr, msg)
                self.assertTrue(sw1==0x90 and sw2==0x00)
                compsig= self.parser.parse_message_signature(response, msg, childkey)
                # if we change the message slightly, the key recovery should raise an error
                with self.assertRaises(ValueError):               
                    compsig= self.parser.parse_message_signature(response, msg+' ', childkey)
            
if __name__ == '__main__':
    unittest.main()