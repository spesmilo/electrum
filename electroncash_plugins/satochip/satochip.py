from struct import pack
from os import urandom
import hashlib
import traceback
import logging

#electroncash
from electroncash import mnemonic
from electroncash import bitcoin
from electroncash import networks
from electroncash.bitcoin import TYPE_ADDRESS, int_to_hex, var_int
from electroncash.i18n import _
from electroncash.plugins import BasePlugin, Device
from electroncash.keystore import Hardware_KeyStore
from electroncash.transaction import Transaction
from electroncash.wallet import Standard_Wallet
from electroncash.util import print_error, bfh, bh2u, versiontuple, PrintError, is_verbose
from electroncash.bitcoin import hash_160, Hash
from electroncash.bitcoin import serialize_xpub
from electroncash_gui.qt.qrcodewidget import QRCodeWidget, QRDialog

from ..hw_wallet import HW_PluginBase

try:
    #pysatochip
    from pysatochip.CardConnector import CardConnector, UninitializedSeedError, logger
    from pysatochip.JCconstants import JCconstants
    from pysatochip.TxParser import TxParser
    from pysatochip.Satochip2FA import Satochip2FA
    from pysatochip.ecc import CURVE_ORDER, der_sig_from_r_and_s, get_r_and_s_from_der_sig, ECPubkey
    from pysatochip.version import SATOCHIP_PROTOCOL_MAJOR_VERSION, SATOCHIP_PROTOCOL_MINOR_VERSION, SATOCHIP_PROTOCOL_VERSION

    #pyscard
    from smartcard.sw.SWExceptions import SWException
    from smartcard.Exceptions import CardConnectionException, CardRequestTimeoutException
    from smartcard.CardType import AnyCardType
    from smartcard.CardRequest import CardRequest
    LIBS_AVAILABLE = True
except:
    LIBS_AVAILABLE = False
    print_error("[satochip] failed to import requisite libraries, please install the 'pyscard' and 'pysatochip' libraries")
    print_error("[satochip] satochip will not not be available")
    raise

logging.basicConfig(level=logging.DEBUG, format='%(levelname)s [%(module)s] %(funcName)s | %(message)s') #debugSatochip

# debug: smartcard reader ids
SATOCHIP_VID= 0x096E
SATOCHIP_PID= 0x0503

MSG_USE_2FA= _("Do you want to use 2-Factor-Authentication (2FA)?\n\nWith 2FA, "
               "any transaction must be confirmed on a second device such as your "
               "smartphone. First you have to install the Satochip-2FA android app on "
               "google play. Then you have to pair your 2FA device with your Satochip "
               "by scanning the qr-code on the next screen. \n\nWARNING: be sure to backup "
               "a copy of the qr-code in a safe place, in case you have to reinstall the app!")

def bip32path2bytes(bip32path:str) -> (int, bytes):
    splitPath = bip32path.split('/')
    splitPath = [x for x in splitPath if x] # removes empty values
    if splitPath and splitPath[0] == 'm':
        splitPath = splitPath[1:]
        #bip32path = bip32path[2:]

    bytePath = b''
    depth = len(splitPath)
    for index in splitPath:
        if index.endswith("'"):
           bytePath += pack( ">I", int(index.rstrip("'"))+0x80000000 )
        else:
           bytePath += pack( ">I", int(index) )

    return depth, bytePath

class SatochipClient(PrintError):
    def __init__(self, plugin, handler):
        if not LIBS_AVAILABLE:
            self.print_error("** No libraries available")
            return
        self.print_error("__init__()")#debugSatochip
        self.device = plugin.device
        self.handler = handler
        #self.parser= CardDataParser()
        #self.cc= CardConnector(self, _logger.getEffectiveLevel())
        self.cc= CardConnector(self)
        if is_verbose:
            logger.setLevel(logging.DEBUG)
        else:
            logger.setLevel(logging.INFO)

    def __repr__(self):
        return '<SatochipClient TODO>'

    def is_pairable(self):
        return LIBS_AVAILABLE

    def close(self):
        self.print_error("close()")#debugSatochip
        self.cc.card_disconnect()
        self.cc.cardmonitor.deleteObserver(self.cc.cardobserver)


    def timeout(self, cutoff):
        pass

    def is_initialized(self):
        return LIBS_AVAILABLE

    def label(self):
        # TODO - currently empty #debugSatochip
        return ""


    def has_usable_connection_with_device(self):
        self.print_error(f"has_usable_connection_with_device()")#debugSatochip
        try:
            atr= self.cc.card_get_ATR() # (response, sw1, sw2)= self.cc.card_select() #TODO: something else? get ATR?
            self.print_error("Card ATR: " + bytes(atr).hex() )
        except Exception as e: #except SWException as e:
            try:
                self.print_error(f"giving more time for the card to get ready...")
                import time
                time.sleep(1) #sometimes the card needs a bit delay to get ready, otherwise it throws "Card not connected"
                atr= self.cc.card_get_ATR() # (response, sw1, sw2)= self.cc.card_select() #TODO: something else? get ATR?
                self.print_error("Card ATR: " + bytes(atr).hex() )
            except Exception as e: 
                self.print_error(f"Exception in has_usable_connection_with_device: {str(e)}")
                return False
        return True

    def get_xpub(self, bip32_path, xtype):
        assert xtype in SatochipPlugin.SUPPORTED_XTYPES

        try:
            hex_authentikey = self.handler.win.wallet.storage.get('authentikey')
            self.print_error("get_xpub(): self.handler.win.wallet.storage.authentikey:", hex_authentikey)#debugSatochip
            if hex_authentikey is not None:
                self.cc.parser.authentikey_from_storage= ECPubkey(bytes.fromhex(hex_authentikey))
        except Exception as e: #attributeError?
            self.print_error("get_xpub(): exception when getting authentikey from self.handler.win.wallet.storage:", str(e))#debugSatochip
        
        try:
            # needs PIN
            self.cc.card_verify_PIN()
            
            # bip32_path is of the form 44'/0'/1'
            self.print_error("[get_xpub(): bip32_path = ", bip32_path)#debugSatochip
            (depth, bytepath)= bip32path2bytes(bip32_path)
            (childkey, childchaincode)= self.cc.card_bip32_get_extendedkey(bytepath)

            if depth == 0: #masterkey
                fingerprint= bytes([0,0,0,0])
                child_number= bytes([0,0,0,0])
            else: #get parent info
                (parentkey, parentchaincode)= self.cc.card_bip32_get_extendedkey(bytepath[0:-4])
                fingerprint= hash_160(parentkey.get_public_key_bytes(compressed=True))[0:4]
                child_number= bytepath[-4:]
            #xpub= serialize_xpub('standard', childchaincode, childkey.get_public_key_bytes(compressed=True), depth, fingerprint, child_number)
            xpub= serialize_xpub(xtype, childchaincode, childkey.get_public_key_bytes(compressed=True), depth, fingerprint, child_number)
            self.print_error("SatochipClient: get_xpub(): xpub=", xpub)#debugSatochip
            return xpub
            # return BIP32Node(xtype=xtype,
                                 # eckey=childkey,
                                 # chaincode=childchaincode,
                                 # depth=depth,
                                 # fingerprint=fingerprint,
                                 # child_number=child_number).to_xpub() 
        except Exception as e:
            self.print_error(repr(e))
            return None
            
    def ping_check(self):
        #check connection is working
        try:
            print('ping_check')#debug
            #atr= self.cc.card_get_ATR()
        except Exception as e:
            self.print_error(repr(e))
            raise RuntimeError("Communication issue with Satochip")

    def request(self, request_type, *args):
        self.print_error('client request: '+ str(request_type))
        
        if self.handler is not None:
            if (request_type=='update_status'):
                reply = self.handler.update_status(*args) 
                return reply 
            elif (request_type=='show_error'):
                reply = self.handler.show_error(*args) 
                return reply 
            elif (request_type=='show_message'):
                reply = self.handler.show_message(*args) 
                return reply 
            else:
                reply = self.handler.show_error('Unknown request: '+str(request_type)) 
                return reply 
        else: 
            self.print_error("self.handler is None! ")
            return None
        # try:
            # method_to_call = getattr(self.handler, request_type)
            # print('Type of method_to_call: '+ str(type(method_to_call)))
            # print('method_to_call: '+ str(method_to_call))
            # reply = method_to_call(*args)
            # return reply 
        # except Exception as e:
            # _logger.exception(f"Exception: {str(e)}")
            # raise RuntimeError("GUI exception")

    def PIN_dialog(self, msg):
        while True:
            password = self.handler.get_passphrase(msg, False)
            if password is None:
                return False, None
            if len(password) < 4:
                msg = _("PIN must have at least 4 characters.") + \
                      "\n\n" + _("Enter PIN:")
            elif len(password) > 16:
                msg = _("PIN must have less than 16 characters.") + \
                      "\n\n" + _("Enter PIN:")
            else:
                password = password.encode('utf8')
                return True, password
                
    def PIN_setup_dialog(self, msg, msg_confirm, msg_error):
        while(True):
            (is_PIN, pin)= self.PIN_dialog(msg)
            if not is_PIN:
                #return (False, None) 
                raise RuntimeError(('A PIN code is required to initialize the Satochip!'))
            (is_PIN, pin_confirm)= self.PIN_dialog(msg_confirm)
            if not is_PIN:
                #return (False, None) 
                raise RuntimeError(('A PIN confirmation is required to initialize the Satochip!'))
            if (pin != pin_confirm):
                self.request('show_error', msg_error)
            else:
                return (is_PIN, pin)
     
    def PIN_change_dialog(self, msg_oldpin, msg_newpin, msg_confirm, msg_error, msg_cancel):
        #old pin
        (is_PIN, oldpin)= self.PIN_dialog(msg_oldpin)
        if (not is_PIN):
            self.request('show_message', msg_cancel)
            return (False, None, None)

        # new pin
        while (True):
            (is_PIN, newpin)= self.PIN_dialog(msg_newpin)
            if (not is_PIN):
                self.request('show_message', msg_cancel)
                return (False, None, None)
            (is_PIN, pin_confirm)= self.PIN_dialog(msg_confirm)
            if (not is_PIN):
                self.request('show_message', msg_cancel)
                return (False, None, None)
            if (newpin != pin_confirm):
                self.request('show_error', msg_error)
            else:
                return (True, oldpin, newpin)

class Satochip_KeyStore(Hardware_KeyStore):
    hw_type = 'satochip'
    device = 'Satochip'

    def __init__(self, d):
        Hardware_KeyStore.__init__(self, d)
        #print_error("[satochip] Satochip_KeyStore: __init__(): xpub:"+str(d.get('xpub')) )#debugSatochip
        #print_error("[satochip] Satochip_KeyStore: __init__(): derivation"+str(d.get('derivation')))#debugSatochip
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
        self.print_error(message)
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

        message_byte = message.encode('utf8')
        message_hash = hashlib.sha256(message_byte).hexdigest().upper()
        client = self.get_client()
        address_path = self.get_derivation()[2:] + "/%d/%d"%sequence
        self.print_error('debug: sign_message: path: '+address_path)
        self.handler.show_message("Signing message ...\r\nMessage hash: "+message_hash)

        # check if 2FA is required
        hmac=b''
        if (client.cc.needs_2FA==None):
            (response, sw1, sw2, d)=client.cc.card_get_status()
        if client.cc.needs_2FA:
            # challenge based on sha256(btcheader+msg)
            # format & encrypt msg
            import json
            msg= {'action':"sign_msg", 'msg':message}
            msg=  json.dumps(msg)
            (id_2FA, msg_out)= client.cc.card_crypt_transaction_2FA(msg, True)

            d={}
            d['msg_encrypt']= msg_out
            d['id_2FA']= id_2FA
            # print_error("encrypted message: "+msg_out)
            self.print_error("id_2FA: "+id_2FA)

            #do challenge-response with 2FA device...
            self.handler.show_message('2FA request sent! Approve or reject request on your second device.')
            Satochip2FA.do_challenge_response(d)
            # decrypt and parse reply to extract challenge response
            try:
                reply_encrypt= d['reply_encrypt']
            except Exception as e:
                # Note the below give_error call will itself raise Message. :/
                self.give_error("No response received from 2FA!", True)
                return
            reply_decrypt= client.cc.card_crypt_transaction_2FA(reply_encrypt, False)
            self.print_error("challenge:response= "+ reply_decrypt)
            reply_decrypt= reply_decrypt.split(":")
            chalresponse=reply_decrypt[1]
            hmac= bytes.fromhex(chalresponse)

        try:
            keynbr= 0xFF #for extended key
            (depth, bytepath)= bip32path2bytes(address_path)
            (pubkey, chaincode)=client.cc.card_bip32_get_extendedkey(bytepath)
            (response2, sw1, sw2, compsig) = client.cc.card_sign_message(keynbr, pubkey, message_byte, hmac)
            if (compsig==b''):
                self.handler.show_error(_("Wrong signature!\nThe 2FA device may have rejected the action.")) 
            
        except Exception as e:
            self.give_error(e, True)
        finally:
            self.handler.finished()

        return compsig

    def sign_transaction(self, tx, password, *, use_cache=False):
        self.print_error('sign_transaction(): tx: '+ str(tx)) #debugSatochip

        client = self.get_client()

        # outputs
        txOutputs= ''.join(tx.serialize_output(o) for o in tx.outputs())
        hashOutputs = bh2u(Hash(bfh(txOutputs)))
        txOutputs = var_int(len(tx.outputs()))+txOutputs
        self.print_error('sign_transaction(): hashOutputs= ', hashOutputs) #debugSatochip
        self.print_error('sign_transaction(): outputs= ', txOutputs) #debugSatochip

        # Fetch inputs of the transaction to sign
        derivations = self.get_tx_derivations(tx)
        for i,txin in enumerate(tx.inputs()):
            self.print_error('sign_transaction(): input =', i) #debugSatochip
            self.print_error('sign_transaction(): input[type]:', txin['type']) #debugSatochip
            if txin['type'] == 'coinbase':
                self.give_error("Coinbase not supported")     # should never happen

            if txin['type'] in ['p2sh']:
                p2shTransaction = True


            pubkeys, x_pubkeys = tx.get_sorted_pubkeys(txin)
            for j, x_pubkey in enumerate(x_pubkeys):
                self.print_error('sign_transaction(): forforloop: j=', j) #debugSatochip
                if tx.is_txin_complete(txin):
                    break

                if x_pubkey in derivations:
                    signingPos = j
                    s = derivations.get(x_pubkey)
                    address_path = "%s/%d/%d" % (self.get_derivation()[2:], s[0], s[1])

                    # get corresponing extended key
                    (depth, bytepath)= bip32path2bytes(address_path)
                    (key, chaincode)=client.cc.card_bip32_get_extendedkey(bytepath)

                    # parse tx
                    pre_tx_hex= tx.serialize_preimage(i)
                    pre_tx= bytes.fromhex(pre_tx_hex)# hex representation => converted to bytes
                    pre_hash = Hash(bfh(pre_tx_hex))
                    pre_hash_hex= pre_hash.hex()
                    self.print_error('sign_transaction(): pre_tx_hex=', pre_tx_hex) #debugSatochip
                    self.print_error('sign_transaction(): pre_hash=', pre_hash_hex) #debugSatochip
                    #(response, sw1, sw2) = client.cc.card_parse_transaction(pre_tx, True) # use 'True' since BCH use BIP143 as in Segwit...
                    #print_error('[satochip] sign_transaction(): response= '+str(response)) #debugSatochip
                    #(tx_hash, needs_2fa) = client.parser.parse_parse_transaction(response)
                    (response, sw1, sw2, tx_hash, needs_2fa) = client.cc.card_parse_transaction(pre_tx, True) # use 'True' since BCH use BIP143 as in Segwit...
                    tx_hash_hex= bytearray(tx_hash).hex()
                    if pre_hash_hex!= tx_hash_hex:
                        raise RuntimeError(f"[Satochip_KeyStore] Tx preimage mismatch: {pre_hash_hex} vs {tx_hash_hex}")
                    
                    # sign tx
                    keynbr= 0xFF #for extended key
                    if needs_2fa:
                        # format & encrypt msg
                        import json
                        coin_type= 145 #see https://github.com/satoshilabs/slips/blob/master/slip-0044.md
                        test_net= networks.net.TESTNET
                        msg= {'action':"sign_tx", 'tx':pre_tx_hex, 'ct':coin_type, 'sw':True, 'tn':test_net, 'txo':txOutputs, 'ty':txin['type']}
                        msg=  json.dumps(msg)
                        (id_2FA, msg_out)= client.cc.card_crypt_transaction_2FA(msg, True)
                        d={}
                        d['msg_encrypt']= msg_out
                        d['id_2FA']= id_2FA
                        # self.print_error("encrypted message: "+msg_out)
                        self.print_error("id_2FA:", id_2FA)

                        #do challenge-response with 2FA device...
                        client.handler.show_message('2FA request sent! Approve or reject request on your second device.')
                        Satochip2FA.do_challenge_response(d)
                        # decrypt and parse reply to extract challenge response
                        try:
                            reply_encrypt= None  # init it in case of exc below
                            reply_encrypt= d['reply_encrypt']
                        except Exception as e:
                            # Note: give_error here will raise again.. :/
                            self.give_error("No response received from 2FA!", True)
                            break
                        if reply_encrypt is None:
                            #todo: abort tx
                            break
                        reply_decrypt= client.cc.card_crypt_transaction_2FA(reply_encrypt, False)
                        self.print_error("challenge:response=", reply_decrypt)
                        reply_decrypt= reply_decrypt.split(":")
                        rep_pre_hash_hex= reply_decrypt[0][0:64]
                        if rep_pre_hash_hex!= pre_hash_hex:
                            #todo: abort tx or retry?
                            self.print_error("Abort transaction: tx mismatch:",rep_pre_hash_hex,"!=",pre_hash_hex)
                            self.give_error("Transaction aborted: wrong 2FA authorization code!", True)
                            break
                        chalresponse=reply_decrypt[1]
                        if chalresponse=="00"*20:
                            #todo: abort tx?
                            self.print_error("Abort transaction: rejected by 2FA!")
                            self.give_error("Transaction aborted: rejected by 2FA!", True)
                            break
                        chalresponse= list(bytes.fromhex(chalresponse))
                    else:
                        chalresponse= None
                    (tx_sig, sw1, sw2) = client.cc.card_sign_transaction(keynbr, tx_hash, chalresponse)
                    #self.print_error('sign_transaction(): sig=', bytes(tx_sig).hex()) #debugSatochip
                    #todo: check sw1sw2 for error (0x9c0b if wrong challenge-response)
                    # enforce low-S signature (BIP 62)
                    tx_sig = bytearray(tx_sig)
                    r,s= get_r_and_s_from_der_sig(tx_sig)
                    if s > CURVE_ORDER//2:
                        s = CURVE_ORDER - s
                    tx_sig=der_sig_from_r_and_s(r, s)
                    #update tx with signature
                    tx_sig = tx_sig.hex()+'41'
                    #tx.add_signature_to_txin(i,j,tx_sig)
                    txin['signatures'][j] = tx_sig
                    break
            else:
                self.give_error("No matching x_key for sign_transaction") # should never happen

        self.print_error("is_complete", tx.is_complete())
        tx.raw = tx.serialize()
        return

    def show_address(self, sequence, txin_type):
        self.print_error('show_address(): todo!')
        return


class SatochipPlugin(HW_PluginBase):
    libraries_available = LIBS_AVAILABLE
    minimum_library = (0, 0, 0)
    keystore_class= Satochip_KeyStore
    DEVICE_IDS= [
       (SATOCHIP_VID, SATOCHIP_PID)
    ]
    SUPPORTED_XTYPES = ('standard')

    def __init__(self, parent, config, name):
        HW_PluginBase.__init__(self, parent, config, name)

        if not LIBS_AVAILABLE:
            return

        self.print_error("init()")#debugSatochip

        #self.libraries_available = self.check_libraries_available() #debugSatochip
        #if not self.libraries_available:
        #    return

        #self.device_manager().register_devices(self.DEVICE_IDS)
        self.device_manager().register_enumerate_func(self.detect_smartcard_reader)

    def get_library_version(self):
        return '0.0.1'

    def detect_smartcard_reader(self):
        self.print_error("detect_smartcard_reader")#debugSatochip
        self.cardtype = AnyCardType()
        try:
            cardrequest = CardRequest(timeout=0, cardType=self.cardtype)
            cardservice = cardrequest.waitforcard()
            self.print_error("detect_smartcard_reader: found card!")#debugSatochip
            return [Device(path="/satochip",
                           interface_number=-1,
                           id_="/satochip",
                           product_key=(SATOCHIP_VID,SATOCHIP_PID),
                           usage_page=0)]
                           #transport_ui_string='ccid')]
        except CardRequestTimeoutException:
            self.print_error('time-out: no card found')
            return []
        except Exception as exc:
            self.print_error("Error during connection:", repr(exc), f"\n{traceback.format_exc()}")
            return []
        return []


    def create_client(self, device, handler):
        self.print_error("create_client()")#debugSatochip

        if handler:
            self.handler = handler
        try:
            rv = SatochipClient(self, handler)
            return rv
        except Exception as e:
            self.print_error('create_client(): exception:'+str(e))
            return None

    def setup_device(self, device_info, wizard):
        self.print_error("setup_device()")#debugSatochip
        if not LIBS_AVAILABLE:
            raise RuntimeError("No libraries available")

        devmgr = self.device_manager()
        device_id = device_info.device.id_
        client = devmgr.client_by_id(device_id)
        if client is None:
            raise Exception(_('Failed to create a client for this device.') + '\n' +
                            _('Make sure it is in the correct state.'))
        client.handler = self.create_handler(wizard)
        client.cc.parser.authentikey_from_storage=None # https://github.com/simpleledger/Electron-Cash-SLP/pull/101#issuecomment-561238614

        # check setup
        while(client.cc.card_present):
            (response, sw1, sw2, d) = client.cc.card_get_status()
            
            # check version
            if  (client.cc.setup_done):
                v_supported= SATOCHIP_PROTOCOL_VERSION 
                v_applet= d["protocol_version"]
                self.print_error(f"[SatochipPlugin] setup_device(): Satochip version={hex(v_applet)} Electrum supported version= {hex(v_supported)}")#debugSatochip
                if (v_supported<v_applet):
                    msg=(_('The version of your Satochip is higher than supported by Electron Cash. You should update Electron Cash to ensure correct functioning!')+ '\n'
                                + f'    Satochip version: {d["protocol_major_version"]}.{d["protocol_minor_version"]}' + '\n'
                                + f'    Supported version: {SATOCHIP_PROTOCOL_MAJOR_VERSION}.{SATOCHIP_PROTOCOL_MINOR_VERSION}')
                    client.handler.show_error(msg)
                
                if (client.cc.needs_secure_channel):
                    client.cc.card_initiate_secure_channel()
                
                break

            # setup device (done only once)
            else:
                # PIN dialog

                msg = _("Enter a new PIN for your Satochip:")
                msg_confirm = _("Please confirm the PIN code for your Satochip:")
                msg_error = _("The PIN values do not match! Please type PIN again!")
                (is_PIN, pin_0)= client.PIN_setup_dialog(msg, msg_confirm, msg_error)
                pin_0= list(pin_0)
                client.cc.set_pin(0, pin_0) #cache PIN value in client
                pin_tries_0= 0x05;
                # PUK code can be used when PIN is unknown and the card is locked
                # We use a random value as the PUK is not used currently in the electrum GUI
                ublk_tries_0= 0x01;
                ublk_0= list(urandom(16));
                pin_tries_1= 0x01
                ublk_tries_1= 0x01
                pin_1= list(urandom(16)); #the second pin is not used currently
                ublk_1= list(urandom(16));
                secmemsize= 32 # number of slot reserved in memory cache
                memsize= 0x0000 # RFU
                create_object_ACL= 0x01 # RFU
                create_key_ACL= 0x01 # RFU
                create_pin_ACL= 0x01 # RFU

                # setup

                (response, sw1, sw2)=client.cc.card_setup(pin_tries_0, ublk_tries_0, pin_0, ublk_0,
                        pin_tries_1, ublk_tries_1, pin_1, ublk_1,
                        secmemsize, memsize,
                        create_object_ACL, create_key_ACL, create_pin_ACL)
                if sw1!=0x90 or sw2!=0x00:
                    self.print_error("setup_device(): unable to set up applet!  sw12="+hex(sw1)+" "+hex(sw2))#debugSatochip
                    raise RuntimeError('Unable to setup the device with error code:'+hex(sw1)+' '+hex(sw2))


        # verify pin:
        client.cc.card_verify_PIN()

        # get authentikey
        while(client.cc.card_present):
            try:
                authentikey=client.cc.card_bip32_get_authentikey()
            except UninitializedSeedError:

                # Option: setup 2-Factor-Authentication (2FA)
                if not client.cc.needs_2FA:
                    #use_2FA= client.handler.yes_no_question(MSG_USE_2FA)
                    use_2FA= False # we put 2FA activation in advanced options as it confuses some users
                    if (use_2FA):
                        secret_2FA= urandom(20)
                        #secret_2FA=b'\0'*20 #for debug purpose
                        secret_2FA_hex=secret_2FA.hex()
                        # the secret must be shared with the second factor app (eg on a smartphone)
                        try:
                            d = QRDialog(secret_2FA_hex, None, "Scan secret 2FA and save a copy", True)
                            d.exec_()
                        except Exception as e:
                            self.print_error("setup_device(): setup 2FA: "+str(e))
                        # further communications will require an id and an encryption key (for privacy).
                        # Both are derived from the secret_2FA using a one-way function inside the Satochip
                        amount_limit= 0 # i.e. always use
                        (response, sw1, sw2)=client.cc.card_set_2FA_key(secret_2FA, amount_limit)
                        if sw1!=0x90 or sw2!=0x00:
                            self.print_error(f"setup_device(): unable to set 2FA!  sw12={hex(sw1)},{hex(sw2)}")#debugSatochip
                            raise RuntimeError(f'Unable to setup 2FA with error code: {hex(sw1)} {hex(sw2)}')

                # seed dialog...
                self.print_error("setup_device(): import seed:") #debugSatochip
                self.choose_seed(wizard)
                seed= list(self.bip32_seed)
                authentikey= client.cc.card_bip32_import_seed(seed)

            hex_authentikey= authentikey.get_public_key_hex(compressed=True)
            self.print_error("setup_device(): authentikey=", hex_authentikey)#debugSatochip
            wizard.storage.put('authentikey', hex_authentikey)
            self.print_error("setup_device(): authentikey from storage=", wizard.storage.get('authentikey'))#debugSatochip
            break

    def get_xpub(self, device_id, derivation, xtype, wizard):
        # this seems to be part of the pairing process only, not during normal ops?
        # base_wizard:on_hw_derivation
        self.print_error("get_xpub()")#debugSatochip
        #if xtype not in self.SUPPORTED_XTYPES:
        #    raise ScriptTypeNotSupported(_('This type of script is not supported with {}.').format(self.device))
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
            ('create_seed', _('Create a new BIP39 seed')),
            ('restore_from_seed', _('I already have a BIP39 seed')),
        ]
        wizard.choice_dialog(title=title, message=message, choices=choices, run_next=wizard.run)

    def create_seed(self, wizard):
        wizard.seed_type = 'bip39'
        wizard.opt_bip39 = True
        #seed = mnemonic.Mnemonic_Electrum('en').make_seed(wizard.seed_type) # Electrum seed
        seed= mnemonic.Mnemonic('en').make_seed() # BIP39
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
        f = lambda x: self.derive_bip39_seed(seed, x) #f = lambda x: self.derive_electrum_seed(seed, x)
        if passphrase:
            title = _('Confirm Seed Extension')
            message = '\n'.join([
                _('Your seed extension must be saved together with your seed.'),
                _('Please type it here.'),
            ])
            wizard.line_dialog(run_next=f, title=title, message=message, default='', test=lambda x: x==passphrase)
        else:
            f('')

    def derive_electrum_seed(self, seed, passphrase):
        self.bip32_seed = mnemonic.Mnemonic_Electrum('en').mnemonic_to_seed(seed, passphrase)
    
    def derive_bip39_seed(self, seed, passphrase):
        self.bip32_seed = mnemonic.Mnemonic('en').mnemonic_to_seed(seed, passphrase)
        
    #restore from seed
    def restore_from_seed(self, wizard):
        wizard.opt_bip39 = True
        wizard.opt_ext = True
        test = mnemonic.is_seed 
        f= lambda seed, is_bip39, is_ext: self.on_restore_seed(wizard, seed, is_bip39, is_ext)
        wizard.restore_seed_dialog(run_next=f, test=test)

    def on_restore_seed(self, wizard, seed, is_bip39, is_ext):
        wizard.seed_type = 'bip39' if is_bip39 else mnemonic.seed_type_name(seed)
        if wizard.seed_type == 'bip39':
            f = lambda passphrase: self.derive_bip39_seed(seed, passphrase)
            wizard.passphrase_dialog(run_next=f) if is_ext else f('')
        elif wizard.seed_type in ['standard', 'electrum']:
            # warning message as Electrum seed on hardware is not standard and incompatible with other hw
            message= '  '.join([
                _("You are trying to import an Electrum seed to a Satochip hardware wallet."),
                _("\n\nElectrum seeds are not compatible with the BIP39 seeds typically used in hardware wallets."), 
                _("This means you may have difficulty to import this seed in another wallet in the future."),
                _("\n\nProceed with caution! If you are not sure, click on 'Back' and introduce a BIP39 seed instead."),
                _("You can also generate a new random BIP39 seed by clicking on 'Back' twice.")
            ])
            wizard.confirm_dialog('Warning', message, run_next=lambda x: None)
            f = lambda passphrase: self.derive_electrum_seed(seed, passphrase)
            wizard.passphrase_dialog(run_next=f) if is_ext else f('')
        elif wizard.seed_type == 'old':
            raise Exception('Unsupported seed type', wizard.seed_type)
        else:
            raise Exception('Unknown seed type', wizard.seed_type)


