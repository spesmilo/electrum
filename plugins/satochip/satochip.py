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

from electrum.util import print_stderr, print_error
from electrum.crypto import hash_160, Hash
from electrum.bitcoin import serialize_xpub
from electrum.ecc import CURVE_ORDER, der_sig_from_r_and_s, get_r_and_s_from_der_sig

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
    if splitPath[0] == 'm':
        splitPath = splitPath[1:]
        bip32path = bip32path[2:]
    
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
        self.cc= CardConnector()
        self.parser= CardDataParser()
        
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
        #self.checkDevice() #debugSatochip
        assert xtype in SatochipPlugin.SUPPORTED_XTYPES
        
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

    def password_dialog(self, msg=None):
        response = self.handler.get_word(msg)
        if response is None:
            return False, None, None
        return True, response, response

    
       
class Satochip_KeyStore(Hardware_KeyStore):       
    hw_type = 'satochip'
    device = 'Satochip'
    
    def __init__(self, d):
        Hardware_KeyStore.__init__(self, d)
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
        
        # from ledger.py
        # Fetch inputs of the transaction to sign
        derivations = self.get_tx_derivations(tx)
        for i,txin in enumerate(tx.inputs()):
            print_error('   [satochip] Satochip_KeyStore: sign_transaction(): forloop: i= '+str(i)) #debugSatochip
            
            if txin['type'] == 'coinbase':
                self.give_error("Coinbase not supported")     # should never happen

            if txin['type'] in ['p2sh']:
                p2shTransaction = True

            if txin['type'] in ['p2wpkh-p2sh', 'p2wsh-p2sh']:
                if not self.get_client_electrum().supports_segwit():
                    self.give_error(MSG_NEEDS_FW_UPDATE_SEGWIT)
                segwitTransaction = True

            if txin['type'] in ['p2wpkh', 'p2wsh']:
                if not self.get_client_electrum().supports_native_segwit():
                    self.give_error(MSG_NEEDS_FW_UPDATE_SEGWIT)
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
                    (response, sw1, sw2) = client.cc.card_parse_transaction(pre_tx)
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
    #SUPPORTED_XTYPES = ('standard', 'p2wpkh-p2sh', 'p2wpkh', 'p2wsh-p2sh', 'p2wsh')
    SUPPORTED_XTYPES = ('standard')
        
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
        except:
            self.print_error('[satochip] SatochipPlugin: create_client(): exception!')
            return None

    def setup_device(self, device_info, wizard, purpose):
        print_error("[satochip] SatochipPlugin: setup_device()")#debugSatochip
        devmgr = self.device_manager()
        device_id = device_info.device.id_
        client = devmgr.client_by_id(device_id)
        if client is None:
            raise Exception(_('Failed to create a client for this device.') + '\n' +
                            _('Make sure it is in the correct state.'))
        
        #TODO: check if satochip has been initialized, and perform setup if needed
        (response, sw1, sw2)=client.cc.card_bip32_get_authentikey()
        client.parser.parse_bip32_get_authentikey(response)
        print_error("[satochip] SatochipPlugin: setup_device(): authentikey="+client.parser.authentikey.get_public_key_hex(compressed=True))#debugSatochip
        client.handler = self.create_handler(wizard)
    
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

    
    
    
    
    
    
    