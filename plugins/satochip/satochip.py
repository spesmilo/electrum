from struct import pack, unpack
import hashlib
import sys
import traceback

#electrum
from electrum import bitcoin
from electrum.bitcoin import TYPE_ADDRESS, int_to_hex, var_int
from electrum.i18n import _
from electrum.plugins import BasePlugin, Device
from electrum.keystore import Hardware_KeyStore
from electrum.transaction import Transaction
from electrum.wallet import Standard_Wallet
from ..hw_wallet import HW_PluginBase
from ..hw_wallet.plugin import is_any_tx_output_on_change_branch
from electrum.util import print_error, is_verbose, bfh, bh2u, versiontuple
from electrum.base_wizard import ScriptTypeNotSupported

from electrum.crypto import hash_160, Hash
from electrum.bitcoin import serialize_xpub
from electrum.ecc import CURVE_ORDER, der_sig_from_r_and_s, get_r_and_s_from_der_sig, ECPubkey
from electrum.mnemonic import Mnemonic
from electrum.keystore import bip39_to_seed

#pysatochip
from .CardConnector import CardConnector
from .CardDataParser import CardDataParser
from .JCconstants import JCconstants
from .TxParser import TxParser

from smartcard.sw.SWExceptions import SWException
from smartcard.Exceptions import CardConnectionException
from smartcard.CardType import AnyCardType
from smartcard.CardRequest import CardRequest

# debug: smartcard reader ids
SATOCHIP_VID= 0x096E
SATOCHIP_PID= 0x0503

def bip32path2bytes(bip32path:str) -> (int, bytes):
    splitPath = bip32path.split('/')
    splitPath=[x for x in splitPath if x] # removes empty values
    if splitPath[0] == 'm':
        splitPath = splitPath[1:]
        #bip32path = bip32path[2:]
    
    bytePath=b''
    depth= len(splitPath)    
    for index in splitPath:
        if index.endswith("'"):
           bytePath+= pack( ">I", int(index.rstrip("'"))+0x80000000 )   
        else:
           bytePath+=pack( ">I", int(index) )
        
    return (depth, bytePath)

class SatochipClient():
    def __init__(self, plugin, handler):
        print_error("[satochip] SatochipClient: __init__()")#debugSatochip
        self.device = plugin.device
        self.handler = handler
        self.parser= CardDataParser()
        self.cc= CardConnector(self.parser)
        
        # debug 
        try:
            print_error("[satochip] SatochipClient: __init__(): cc.card_get_ATR()")#debugSatochip
            print_error(self.cc.card_get_ATR())
            print_error("[satochip] SatochipClient: __init__(): cc.card_select()")#debugSatochip
            (response, sw1, sw2)=self.cc.card_select()
        except SWException as e:
            print(e)
        
    def __repr__(self):
        return '<SatochipClient TODO>'
        
    def is_pairable(self):
        return True

    def close(self):
        self.cc.card_disconnect()

    def timeout(self, cutoff):
        pass

    def is_initialized(self):
        print_error("[satochip] SatochipClient: is_initialized(): TODO - currently set to true!")#debugSatochip
        return True

    def label(self):
        print_error("[satochip] SatochipClient: label(): TODO - currently empty")#debugSatochip
        return ""

    def i4b(self, x):
        return pack('>I', x)

    def has_usable_connection_with_device(self):
        try:
            #self.cc= CardConnector()
            print_error("[satochip] SatochipClient: has_usable_connection_with_device(): cc.card_get_ATR()"+str(self.cc.card_get_ATR()))#debugSatochip
            print_error("[satochip] SatochipClient: has_usable_connection_with_device(): cc.card_select()")#debugSatochip
            (response, sw1, sw2)=self.cc.card_select()
        except SWException as e:
            print(e)
            return False
        return True

    def get_xpub(self, bip32_path, xtype):
        assert xtype in SatochipPlugin.SUPPORTED_XTYPES
        
        try:
            hex_authentikey= self.handler.win.wallet.storage.get('authentikey')
            print_error("[satochip] SatochipClient: get_xpub(): self.handler.win.wallet.storage.authentikey:"+str(hex_authentikey))#debugSatochip
            if hex_authentikey is not None:
                self.parser.authentikey_from_storage= ECPubkey(bytes.fromhex(hex_authentikey))
        except Exception as e: #attributeError?
            print_error("[satochip] SatochipClient: get_xpub(): exception when getting authentikey from self.handler.win.wallet.storage:"+str(e))#debugSatochip
        
        # bip32_path is of the form 44'/0'/1'
        # S-L-O-W - we don't handle the fingerprint directly, so compute
        # it manually from the previous node
        # This only happens once so it's bearable
        #self.get_client() # prompt for the PIN before displaying the dialog if necessary
        #self.handler.show_message("Computing master public key")
        print_error("[satochip] SatochipClient: get_xpub(): bip32_path="+bip32_path)#debugSatochip
        (depth, bytepath)= bip32path2bytes(bip32_path)
        (response, sw1, sw2)= self.cc.card_bip32_get_extendedkey(bytepath)
        print_error("[satochip] SatochipClient: get_xpub(): response=")#debugSatochip
        print_error(response)
        (childkey, childchaincode)= self.parser.parse_bip32_get_extendedkey(response)
        print_error("[satochip] SatochipClient: get_xpub(): depth="+str(depth))#debugSatochip
        if depth == 0: #masterkey
            fingerprint= bytes([0,0,0,0])
            child_number= bytes([0,0,0,0])
        else: #get parent info
            print_error("[satochip] SatochipClient: get_xpub(): get xpub for parent")#debugSatochip
            (response, sw1, sw2)= self.cc.card_bip32_get_extendedkey(bytepath[0:-4])
            (parentkey, parentchaincode)= self.parser.parse_bip32_get_extendedkey(response)
            fingerprint= hash_160(parentkey.get_public_key_bytes(compressed=True))[0:4]
            child_number= bytepath[-4:]
        xpub= serialize_xpub('standard', childchaincode, childkey.get_public_key_bytes(compressed=True), depth, fingerprint, child_number)
        
        print_error("[satochip] SatochipClient: get_xpub(): xpub="+str(xpub))#debugSatochip
        print_error("[satochip] SatochipClient: get_xpub(): end-of-function!")#debugSatochip
        return xpub        
    
    def ping_check(self):
        #check connection is working
        try: 
            atr= self.cc.card_get_ATR()
        except Exception as e:
            print(e)
            raise RuntimeError("Communication issue with Satochip")
        
    def perform_hw1_preflight(self):
        pass

    def checkDevice(self):
        if not self.preflightDone:
            try:
                self.perform_hw1_preflight()
            except Exception as e:
                print(e)
            self.preflightDone = True

    def PIN_dialog(self, msg):
        while True:
            password = self.handler.get_passphrase(msg, False)
            if password is None:
                return False, None, None
            if len(password) < 4:
                msg = _("PIN must have at least 4 characters.") + \
                      "\n\n" + _("Enter PIN:")
            elif len(password) > 64:
                msg = _("PIN must have less than 64 characters.") + \
                      "\n\n" + _("Enter PIN:")
            else:
                self.PIN = password.encode('utf8')
                return True, self.PIN, self.PIN    

                
class Satochip_KeyStore(Hardware_KeyStore):       
    hw_type = 'satochip'
    device = 'Satochip'
    
    def __init__(self, d):
        Hardware_KeyStore.__init__(self, d)
        print_error("[satochip] Satochip_KeyStore: __init__():")#debugSatochip
        print_error("[satochip] Satochip_KeyStore: __init__(): xpub:"+str(d.get('xpub')) )#debugSatochip
        print_error("[satochip] Satochip_KeyStore: __init__(): derivation"+str(d.get('derivation')))#debugSatochip
        self.force_watching_only = False
        self.ux_busy = False
         
    def dump(self):
        # our additions to the stored data about keystore -- only during creation?
        d = Hardware_KeyStore.dump(self)
        return d

    def get_derivation(self):
        return self.derivation

    def get_client(self):
        # called when user tries to do something like view address, sign something.
        # - not called during probing/setup
        rv = self.plugin.get_client(self)
        return rv
        
    def give_error(self, message, clear_client=False):
        print_error(message)
        if not self.ux_busy:
            self.handler.show_error(message)
        else:
            self.ux_busy = False
        if clear_client:
            self.client = None
        raise Exception(message)
    
    def decrypt_message(self, pubkey, message, password):
        raise RuntimeError(_('Encryption and decryption are currently not supported for {}').format(self.device))
        
    def sign_message(self, sequence, message, password):
        message = message.encode('utf8')
        message_hash = hashlib.sha256(message).hexdigest().upper()
        client = self.get_client()
        address_path = self.get_derivation()[2:] + "/%d/%d"%sequence
        print_error('[satochip] debug: sign_message: path: '+address_path)
        self.handler.show_message("Signing message ...\r\nMessage hash: "+message_hash)
        try:
            #path= self.get_derivation() + ("/%d/%d" % sequence)
            keynbr= 0xFF #for extended key
            (depth, bytepath)= bip32path2bytes(address_path)
            (response, sw1, sw2)=client.cc.card_bip32_get_extendedkey(bytepath)
            (key, chaincode)= client.parser.parse_bip32_get_extendedkey(response)
            (response2, sw1, sw2) = client.cc.card_sign_message(keynbr, message)
            compsig=client.parser.parse_message_signature(response2, message, key)
            
        except Exception as e:
            self.give_error(e, True)
        finally:
            self.handler.finished()
            
        return compsig
        
    def sign_transaction(self, tx, password):
        if password:
            print_error('[satochip] Satochip_KeyStore: sign_transaction(): password: '+ password) #debugSatochip
        else:
            print_error('[satochip] Satochip_KeyStore: sign_transaction(): no password!') #debugSatochip
        print_error('[satochip] Satochip_KeyStore: sign_transaction(): tx: '+ str(tx)) #debugSatochip
        print_error('[satochip] Satochip_KeyStore: sign_transaction(): serialize_preimage(0): '+ tx.serialize_preimage(0)) #debugSatochip
        #####
        
        client = self.get_client()
        segwitTransaction = False
        
        # Fetch inputs of the transaction to sign
        derivations = self.get_tx_derivations(tx)
        for i,txin in enumerate(tx.inputs()):
            print_error('   [satochip] Satochip_KeyStore: sign_transaction(): forloop: i= '+str(i)) #debugSatochip
            print_error('       [satochip] Satochip_KeyStore: sign_transaction(): txin[type]:'+txin['type']) #debugSatochip
            if txin['type'] == 'coinbase':
                self.give_error("Coinbase not supported")     # should never happen

            if txin['type'] in ['p2sh']:
                p2shTransaction = True

            if txin['type'] in ['p2wpkh-p2sh', 'p2wsh-p2sh']:
                #if not self.get_client_electrum().supports_segwit():
                #    self.give_error(MSG_NEEDS_FW_UPDATE_SEGWIT)
                segwitTransaction = True

            if txin['type'] in ['p2wpkh', 'p2wsh']:
                #if not self.get_client_electrum().supports_native_segwit():
                #    self.give_error(MSG_NEEDS_FW_UPDATE_SEGWIT)
                segwitTransaction = True
            
            pubkeys, x_pubkeys = tx.get_sorted_pubkeys(txin)
            for j, x_pubkey in enumerate(x_pubkeys):
                print_error('       [satochip] Satochip_KeyStore: sign_transaction(): forforloop: j= '+str(j)) #debugSatochip
                if tx.is_txin_complete(txin):
                    break
                    
                if x_pubkey in derivations:
                    signingPos = j
                    s = derivations.get(x_pubkey)
                    address_path = "%s/%d/%d" % (self.get_derivation()[2:], s[0], s[1])
                    
                    # get corresponing extended key
                    (depth, bytepath)= bip32path2bytes(address_path)
                    (response, sw1, sw2)=client.cc.card_bip32_get_extendedkey(bytepath)
                    (key, chaincode)= client.parser.parse_bip32_get_extendedkey(response)
                    
                    # parse tx
                    pre_tx_hex= tx.serialize_preimage(i)
                    pre_tx= bytes.fromhex(pre_tx_hex)# hex representation => converted to bytes
                    pre_hash = Hash(bfh(pre_tx_hex))
                    print_error('       [satochip] Satochip_KeyStore: sign_transaction(): forforloop: pre_hash= '+pre_hash.hex()) #debugSatochip
                    (response, sw1, sw2) = client.cc.card_parse_transaction(pre_tx, segwitTransaction)
                    print_error('       [satochip] Satochip_KeyStore: sign_transaction(): forforloop: response= '+str(response)) #debugSatochip
                    print_error('       [satochip] Satochip_KeyStore: sign_transaction(): forforloop: response= '+str(type(response))) #debugSatochip
                    (tx_hash, needs_2fa)= client.parser.parse_parse_transaction(response)
                    print_error('       [satochip] Satochip_KeyStore: sign_transaction(): forforloop: tx_hash= '+bytearray(tx_hash).hex()) #debugSatochip
                    
                    # sign tx
                    keynbr= 0xFF #for extended key
                    if needs_2fa:
                        #todo: chalenge-response...
                        chalresponse= b'0'*20
                    else:
                        chalresponse= None
                    (tx_sig, sw1, sw2) = client.cc.card_sign_transaction(keynbr, tx_hash, chalresponse)
                    print_error('       [satochip] Satochip_KeyStore: sign_transaction(): forforloop: sig= '+bytearray(tx_sig).hex()) #debugSatochip
                    # enforce low-S signature (BIP 62)
                    tx_sig = bytearray(tx_sig)
                    r,s= get_r_and_s_from_der_sig(tx_sig)
                    if s > CURVE_ORDER//2:
                        s = CURVE_ORDER - s
                    tx_sig=der_sig_from_r_and_s(r, s)
                    #update tx with signature
                    tx_sig = tx_sig.hex()+'01'
                    tx.add_signature_to_txin(i,j,tx_sig)
                    break
            else:
                self.give_error("No matching x_key for sign_transaction") # should never happen
            
        print_error("is_complete", tx.is_complete())
        tx.raw = tx.serialize()    
        return
    
    def show_address(self, sequence, txin_type):
        print_error('[satochip] Satochip_KeyStore: show_address(): todo!')
        return
    
        
class SatochipPlugin(HW_PluginBase):        
    libraries_available= True
    minimum_library = (0, 0, 0)
    keystore_class= Satochip_KeyStore
    DEVICE_IDS= [
       (SATOCHIP_VID, SATOCHIP_PID) 
    ]
    SUPPORTED_XTYPES = ('standard', 'p2wpkh-p2sh', 'p2wpkh', 'p2wsh-p2sh', 'p2wsh')
    #SUPPORTED_XTYPES = ('standard')
        
    def __init__(self, parent, config, name):
        
        print_error("[satochip] SatochipPlugin: init()")#debugSatochip
        HW_PluginBase.__init__(self, parent, config, name)

        #self.libraries_available = self.check_libraries_available() #debugSatochip
        #if not self.libraries_available:
        #    return

        self.device_manager().register_devices(self.DEVICE_IDS)
        #self.device_manager().register_enumerate_func(self.detect_simulator)
        self.device_manager().register_enumerate_func(self.detect_smartcard_reader)
        
    def get_library_version(self):
        return '0.0.1'
    
    def detect_smartcard_reader(self):
    
        print_error("[satochip] SatochipPlugin: detect_smartcard_reader")#debugSatochip
        
        # self.cardtype = AnyCardType()
        # try:
            # cardrequest = CardRequest(timeout=10, cardType=self.cardtype)
        # except CardRequestTimeoutException:
            # print('time-out: no card inserted during last 10s')
        # except Exception as exc:
            # print("Error during connection:", exc)
        # if cardrequest:
            # return [Device("/satochip", -1, "/satochip", (SATOCHIP_VID,SATOCHIP_PID), 0)]
        
        #reader= CardConnector() #todo: this resets the smartcard state and invalidates any shared information...
        reader= True
        if reader:
            return [Device("/satochip", -1, "/satochip", (SATOCHIP_VID,SATOCHIP_PID), 0)]
            #return [Device("/satochip", -1, "/satochip", "SATOCHIP", 0)]
        return []
    
    def create_client(self, device, handler):
        print_error("[satochip] SatochipPlugin: create_client()")#debugSatochip
        
        if handler:
            self.handler = handler

        # We are given a HID device, or at least some details about it.
        # Not sure why not we aren't just given a HID library handle, but
        # the 'path' is unabiguous, so we'll use that.
        try:
            self.print_error('[satochip] SatochipPlugin: create_client(): try...')
            rv = SatochipClient(self, handler)
            #rv = CKCCClient(self, handler, device.path, is_simulator=(device.product_key[1] == CKCC_SIMULATED_PID))
            return rv
        except Exception as e:
            self.print_error('[satochip] SatochipPlugin: create_client(): exception:'+str(e))
            return None

    def setup_device(self, device_info, wizard, purpose):
        print_error("[satochip] SatochipPlugin: setup_device()")#debugSatochip
        
        devmgr = self.device_manager()
        device_id = device_info.device.id_
        client = devmgr.client_by_id(device_id)
        if client is None:
            raise Exception(_('Failed to create a client for this device.') + '\n' +
                            _('Make sure it is in the correct state.'))
        client.handler = self.create_handler(wizard)
        
        # check applet version
        while(True):
            (response, sw1, sw2, d)=client.cc.card_get_status()
            if (sw1==0x90 and sw2==0x00):
                v_supported= (CardConnector.SATOCHIP_PROTOCOL_MAJOR_VERSION<<8)+CardConnector.SATOCHIP_PROTOCOL_MINOR_VERSION
                v_applet= (d["protocol_major_version"]<<8)+d["protocol_minor_version"] 
                print_error("version="+str(CardConnector.SATOCHIP_PROTOCOL_MAJOR_VERSION)+" "+str(CardConnector.SATOCHIP_PROTOCOL_MINOR_VERSION))#debugSatochip
                print_error("version="+str(d["protocol_major_version"])+" "+str(d["protocol_minor_version"]))#debugSatochip
                strcmp= 'lower' if (v_applet<v_supported) else 'higher'   
                print_error("[satochip] SatochipPlugin: setup_device(): Satochip version="+hex(v_applet)+ "Electrum suppor version="+hex(v_supported))#debugSatochip
                if (v_supported!=v_applet):
                    msg=_('The version of your Satochip (v{v_applet_maj:x}.{v_applet_min:x}) is {strcmp} than supported by Electrum (v{v_supported_maj:x}.{v_supported_min:x}). You should update Electrum to ensure correct function!').format(strcmp=strcmp, v_applet_maj=d["protocol_major_version"], v_applet_min=d["protocol_minor_version"],  v_supported_maj=CardConnector.SATOCHIP_PROTOCOL_MAJOR_VERSION, v_supported_min=CardConnector.SATOCHIP_PROTOCOL_MINOR_VERSION)
                    client.handler.show_error(msg)
                break
            # setup device (done only once)
            elif (sw1==0x9c and sw2==0x04):
                # PIN dialog
                while (True):
                    msg = _("Enter a new PIN for your Satochip:")
                    (is_PIN, pin_0, pin_0)= client.PIN_dialog(msg)
                    msg = _("Please confirm the PIN code for your Satochip:")
                    (is_PIN, pin_confirm, pin_confirm)= client.PIN_dialog(msg)
                    print_error("[satochip] SatochipPlugin: setup_device(): str(pin)="+str(pin_0))#debugSatochip
                    if (pin_0 != pin_confirm):
                        msg= _("The PIN values do not match! Please type PIN again!")
                        client.handler.show_error(msg)
                    else:
                        break
                pin_0= list(pin_0)
                client.cc.set_pin(0, pin_0) #cache PIN value in client
                print_error("[satochip] SatochipPlugin: setup_device(): NEW PIN="+str(pin_0))#debugSatochip
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
                print("[satochip] SatochipPlugin: setup_device(): perform cardSetup:")#debugSatochip
                (response, sw1, sw2)=client.cc.card_setup(pin_tries_0, ublk_tries_0, pin_0, ublk_0,
                        pin_tries_1, ublk_tries_1, pin_1, ublk_1, 
                        secmemsize, memsize, 
                        create_object_ACL, create_key_ACL, create_pin_ACL
                        #,option_flags, key, amount_limit
                    )
                if sw1!=0x90 or sw2!=0x00:                 
                    print("[satochip] SatochipPlugin: setup_device(): unable to set up applet!  sw12="+hex(sw1)+" "+hex(sw2))#debugSatochip
                    raise RuntimeError('Unable to setup the device with error code:'+hex(sw1)+' '+hex(sw2))
            else:
                print("[satochip] SatochipPlugin: unknown get-status() error! sw12="+hex(sw1)+" "+hex(sw2))#debugSatochip
                raise RuntimeError('Unknown get-status() error code:'+hex(sw1)+' '+hex(sw2))
            
        # verify pin:
        msg = _("Enter the PIN for your Satochip:")
        while (True):
            (is_PIN, pin_0, pin_0)= client.PIN_dialog(msg)
            pin_0= list(pin_0)
            print_error("[satochip] SatochipPlugin: setup_device(): verify PIN...") #debugSatochip
            (response, sw1, sw2)=client.cc.card_verify_PIN(0, pin_0)
            if sw1==0x90 and sw2==0x00: 
                client.cc.set_pin(0, pin_0) #cache PIN value in client
                break
            elif sw1==0x9c and sw2==0x02:
                msg = _("Wrong PIN! Enter the PIN for your Satochip:")
            elif sw1==0x9c and sw2==0x0c:
                msg = _("Too many failed attempts! Your Satochip has been blocked! You need your PUK code to unblock it.")
                raise RuntimeError('Device blocked with error code:'+hex(sw1)+' '+hex(sw2))
        
        # get authentikey
        while(True):
            try:
                authentikey=client.cc.card_bip32_get_authentikey()
            except UninitializedSeedError:
                # test seed dialog...
                print("[satochip] SatochipPlugin: setup_device(): import seed:") #debugSatochip
                self.choose_seed(wizard)
                seed= list(self.bip32_seed)
                #seed= bytes([0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]) # Bip32 test vectors
                authentikey= client.cc.card_bip32_import_seed(seed) 
            hex_authentikey= authentikey.get_public_key_hex(compressed=True)
            print_error("[satochip] SatochipPlugin: setup_device(): authentikey="+hex_authentikey)#debugSatochip
            wizard.storage.put('authentikey', hex_authentikey)
            wizard.storage.write()
            print_error("[satochip] SatochipPlugin: setup_device(): authentikey from storage="+wizard.storage.get('authentikey'))#debugSatochip       
            break
        
            # #oldcode
            # (response, sw1, sw2)=client.cc.card_bip32_get_authentikey()
            # if sw1==0x90 and sw2==0x00: 
                # # save authentikey in storage space
                # client.parser.parse_bip32_get_authentikey(response)
                # hex_authentikey= client.parser.authentikey.get_public_key_hex(compressed=True)
                # print_error("[satochip] SatochipPlugin: setup_device(): authentikey="+hex_authentikey)#debugSatochip
                # wizard.storage.put('authentikey', hex_authentikey)
                # wizard.storage.write()
                # print_error("[satochip] SatochipPlugin: setup_device(): authentikey from storage="+wizard.storage.get('authentikey'))#debugSatochip       
                # break
            # elif sw1==0x9c and sw2==0x14:    #Import seed
                # # test seed dialog...
                # print("[satochip] SatochipPlugin: setup_device(): import seed:") #debugSatochip
                # self.choose_seed(wizard)
                # seed= list(self.bip32_seed)
                # #seed= bytes([0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]) # Bip32 test vectors
                # seed_ACL= JCconstants.DEFAULT_ACL #{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
                # (response, sw1, sw2)= client.cc.card_bip32_import_seed(seed_ACL, seed) 
            # else:
                # print("[satochip] SatochipPlugin: setup_device(): unable to set up applet!  sw12="+hex(sw1)+" "+hex(sw2))#debugSatochip
                # raise RuntimeError('Unable to setup the device with error code:'+hex(sw1)+' '+hex(sw2))
        
    def get_xpub(self, device_id, derivation, xtype, wizard):
        # this seems to be part of the pairing process only, not during normal ops?
        # base_wizard:on_hw_derivation
        print_error("[satochip] SatochipPlugin: get_xpub()")#debugSatochip
        if xtype not in self.SUPPORTED_XTYPES:
            raise ScriptTypeNotSupported(_('This type of script is not supported with {}.').format(self.device))
        devmgr = self.device_manager()
        client = devmgr.client_by_id(device_id)
        client.handler = self.create_handler(wizard)
        client.ping_check()
           
        xpub = client.get_xpub(derivation, xtype)
        return xpub
    
    def get_client(self, keystore, force_pair=True):
        # All client interaction should not be in the main GUI thread
        devmgr = self.device_manager()
        handler = keystore.handler
        with devmgr.hid_lock:
            client = devmgr.client_for_keystore(self, handler, keystore, force_pair)
        # returns the client for a given keystore. can use xpub
        #if client:
        #    client.used()
        if client is not None:
            client.ping_check()
        return client
    
    def show_address(self, wallet, address, keystore=None):
        if keystore is None:
            keystore = wallet.get_keystore()
        if not self.show_address_helper(wallet, address, keystore):
            return

        # Standard_Wallet => not multisig, must be bip32
        if type(wallet) is not Standard_Wallet:
            keystore.handler.show_error(_('This function is only available for standard wallets when using {}.').format(self.device))
            return

        sequence = wallet.get_address_index(address)
        txin_type = wallet.get_txin_type(address)
        keystore.show_address(sequence, txin_type)
    
    # create/restore seed during satochip initialization
    def choose_seed(self, wizard):
        title = _('Create or restore')
        message = _('Do you want to create a new seed, or to restore a wallet using an existing seed?')
        choices = [
            ('create_seed', _('Create a new seed')),
            ('restore_from_seed', _('I already have a seed')),
        ]
        wizard.choice_dialog(title=title, message=message, choices=choices, run_next=wizard.run)
    #create seed
    def create_seed(self, wizard):
        wizard.seed_type = 'standard'
        wizard.opt_bip39 = False
        seed = Mnemonic('en').make_seed(wizard.seed_type)
        f = lambda x: self.request_passphrase(wizard, seed, x)
        wizard.show_seed_dialog(run_next=f, seed_text=seed)

    def request_passphrase(self, wizard, seed, opt_passphrase):
        if opt_passphrase:
            f = lambda x: self.confirm_seed(wizard, seed, x)
            wizard.passphrase_dialog(run_next=f)
        else:
            wizard.run('confirm_seed', seed, '')

    def confirm_seed(self, wizard, seed, passphrase):
        f = lambda x: self.confirm_passphrase(wizard, seed, passphrase)
        wizard.confirm_seed_dialog(run_next=f, test=lambda x: x==seed)

    def confirm_passphrase(self, wizard, seed, passphrase):
        f = lambda x: self.derive_bip32_seed(seed, x)
        #f = lambda x: self.run('create_keystore', seed, x)
        if passphrase:
            title = _('Confirm Seed Extension')
            message = '\n'.join([
                _('Your seed extension must be saved together with your seed.'),
                _('Please type it here.'),
            ])
            wizard.line_dialog(run_next=f, title=title, message=message, default='', test=lambda x: x==passphrase)
        else:
            f('')    
    
    def derive_bip32_seed(self, seed, passphrase):
        self.bip32_seed= Mnemonic('en').mnemonic_to_seed(seed, passphrase)
    
    #restore from seed
    def restore_from_seed(self, wizard):
        wizard.opt_bip39 = True
        wizard.opt_ext = True
        #is_cosigning_seed = lambda x: bitcoin.seed_type(x) in ['standard', 'segwit']
        test = bitcoin.is_seed #if self.wallet_type == 'standard' else is_cosigning_seed
        f= lambda seed, is_bip39, is_ext: self.on_restore_seed(wizard, seed, is_bip39, is_ext)
        wizard.restore_seed_dialog(run_next=f, test=test)
        
    def on_restore_seed(self, wizard, seed, is_bip39, is_ext):
        wizard.seed_type = 'bip39' if is_bip39 else bitcoin.seed_type(seed)
        if wizard.seed_type == 'bip39':
            f = lambda passphrase: self.derive_bip39_seed(seed, passphrase)
            wizard.passphrase_dialog(run_next=f, is_restoring=True) if is_ext else f('')
        elif wizard.seed_type in ['standard', 'segwit']:
            f = lambda passphrase: self.derive_bip32_seed(seed, passphrase)
            wizard.passphrase_dialog(run_next=f, is_restoring=True) if is_ext else f('')
        elif wizard.seed_type == 'old':
            raise Exception('Unsupported seed type', wizard.seed_type)
        elif bitcoin.is_any_2fa_seed_type(wizard.seed_type):
            raise Exception('Unsupported seed type', wizard.seed_type)
        else:
            raise Exception('Unknown seed type', wizard.seed_type)

    def derive_bip39_seed(self, seed, passphrase):
        self.bip32_seed=bip39_to_seed(seed, passphrase)
        
    

    
        
        
    
    
    
    