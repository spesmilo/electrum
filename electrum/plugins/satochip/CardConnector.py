from smartcard.CardType import AnyCardType
from smartcard.CardRequest import CardRequest
from smartcard.CardConnectionObserver import CardConnectionObserver
from smartcard.CardMonitoring import CardMonitor, CardObserver
from smartcard.Exceptions import CardConnectionException, CardRequestTimeoutException
from smartcard.util import toHexString, toBytes
from smartcard.sw.SWExceptions import SWException

from .JCconstants import JCconstants 
from .TxParser import TxParser

from electrum.ecc import ECPubkey, msg_magic
from electrum.i18n import _
from electrum.logging import get_logger

import base64

_logger = get_logger(__name__)

# simple observer that will print on the console the card connection events.
class LogCardConnectionObserver( CardConnectionObserver ):
    def update( self, cardconnection, ccevent ):    
        if 'connect'==ccevent.type:
            _logger.info(f"connecting to {cardconnection.getReader()}")
        elif 'disconnect'==ccevent.type:
            _logger.info(f"disconnecting from {cardconnection.getReader()}")
        elif 'command'==ccevent.type:
            if (ccevent.args[0][1] in (JCconstants.INS_SETUP, JCconstants.INS_SET_2FA_KEY, 
                                        JCconstants.INS_BIP32_IMPORT_SEED, JCconstants.INS_BIP32_RESET_SEED,
                                        JCconstants.INS_CREATE_PIN, JCconstants.INS_VERIFY_PIN, 
                                        JCconstants.INS_CHANGE_PIN, JCconstants.INS_UNBLOCK_PIN)):
                _logger.info(f"> {toHexString(ccevent.args[0][0:5])}{(len(ccevent.args[0])-5)*' *'}")
            else:        
                _logger.info(f"> {toHexString(ccevent.args[0])}")
        elif 'response'==ccevent.type:
            if []==ccevent.args[0]:
                _logger.info(f"< [] {ccevent.args[-2]:02X} {ccevent.args[-1]:02X}")
            else:
                _logger.info(f"< {toHexString(ccevent.args[0])} {ccevent.args[-2]:02X} {ccevent.args[-1]:02X}")
                                 
# a simple card observer that detects inserted/removed cards
class RemovalObserver(CardObserver):
    """A simple card observer that is notified
    when cards are inserted/removed from the system and
    prints the list of cards
    """
    def __init__(self, parent):
        self.parent=parent
    
    def update(self, observable, actions):
        (addedcards, removedcards) = actions
        for card in addedcards:
            _logger.info(f"+Inserted: {toHexString(card.atr)}")     
            self.parent.client.handler.update_status(True)            
        for card in removedcards:
            _logger.info(f"-Removed: {toHexString(card.atr)}")
            self.parent.pin= None #reset PIN
            self.parent.pin_nbr= None
            self.parent.client.handler.update_status(False)

class CardConnector:
    
    # Satochip supported version tuple
    # v0.4: getBIP32ExtendedKey also returns chaincode
    # v0.5: Support for Segwit transaction
    # v0.6: bip32 optimization: speed up computation during derivation of non-hardened child 
    # v0.7: add 2-Factor-Authentication (2FA) support
    # v0.8: support seed reset and pin change               
    # v0.9: message signing for Litecoin (and other alts)    
    SATOCHIP_PROTOCOL_MAJOR_VERSION=0
    SATOCHIP_PROTOCOL_MINOR_VERSION=9
    
    # define the apdus used in this script
    BYTE_AID= [0x53,0x61,0x74,0x6f,0x43,0x68,0x69,0x70] #SatoChip
    
    def __init__(self, client):
        # request any card type
        self.client=client
        self.parser=client.parser
        self.cardtype = AnyCardType()
        self.needs_2FA = None                     
        try: 
            # request card insertion
            self.cardrequest = CardRequest(timeout=10, cardType=self.cardtype)
            self.cardservice = self.cardrequest.waitforcard()
            # attach the console tracer
            self.observer = LogCardConnectionObserver() #ConsoleCardConnectionObserver()
            self.cardservice.connection.addObserver(self.observer)
            # attach the card removal observer
            self.cardmonitor = CardMonitor()
            self.cardobserver = RemovalObserver(self)
            self.cardmonitor.addObserver(self.cardobserver)
            # connect to the card and perform a few transmits
            self.cardservice.connection.connect()
            # cache PIN
            self.pin_nbr=None
            self.pin=None
        except CardRequestTimeoutException:
            _logger.exception('time-out: no card inserted during last 10s')
        except Exception as exc:
            _logger.exception("Error during connection: {str(exc)}")
        
    def card_transmit(self, apdu):
        try:
            (response, sw1, sw2) = self.cardservice.connection.transmit(apdu)
            if (sw1==0x9C) and (sw2==0x06):
                (response, sw1, sw2)= self.card_verify_PIN() 
                (response, sw1, sw2)= self.cardservice.connection.transmit(apdu)
            return (response, sw1, sw2)
        except CardConnectionException: 
            # may be the card has been removed
            try:
                self.cardrequest = CardRequest(timeout=10, cardType=self.cardtype)
                self.cardservice = self.cardrequest.waitforcard()
                # attach the console tracer
                self.observer = LogCardConnectionObserver()#ConsoleCardConnectionObserver()
                self.cardservice.connection.addObserver(self.observer)
                # connect to the card and perform a few transmits
                self.cardservice.connection.connect()
                # retransmit apdu
                (response, sw1, sw2) = self.cardservice.connection.transmit(apdu)
                if (sw1==0x9C) and (sw2==0x06):
                    (response, sw1, sw2)= self.card_verify_PIN() 
                    (response, sw1, sw2)= self.cardservice.connection.transmit(apdu)
                return (response, sw1, sw2)                                 
            except CardRequestTimeoutException:
                _logger.exception('time-out: no card inserted during last 10s')
            except Exception as exc:
                _logger.exception("Error during connection: {str(exc)}")
        
    def card_get_ATR(self):
        return self.cardservice.connection.getATR()
    
    def card_disconnect(self):
        self.cardservice.connection.disconnect()
    
    def get_sw12(self, sw1, sw2):
        return 16*sw1+sw2
    
    def card_select(self):        
        SELECT = [0x00, 0xA4, 0x04, 0x00, 0x08]
        apdu = SELECT + CardConnector.BYTE_AID
        _logger.info(f"card_select:")#debug
        (response, sw1, sw2) = self.card_transmit(apdu)
        return (response, sw1, sw2)
        
    def card_get_status(self):  
        cla= JCconstants.CardEdge_CLA
        ins= JCconstants.INS_GET_STATUS
        p1= 0x00 
        p2= 0x00
        le= 0x00
        apdu=[cla, ins, p1, p2, le]
        (response, sw1, sw2)= self.card_transmit(apdu)
        d={}
        if (sw1==0x90) and (sw2==0x00):
            d["protocol_major_version"]= response[0]
            d["protocol_minor_version"]= response[1]
            d["applet_major_version"]= response[2]
            d["applet_minor_version"]= response[3]
            if len(response) >=8:
                d["PIN0_remaining_tries"]= response[4]
                d["PUK0_remaining_tries"]= response[5]
                d["PIN1_remaining_tries"]= response[6]
                d["PUK1_remaining_tries"]= response[7]
                self.needs_2FA= d["needs2FA"]= False #default value
            if len(response) >=9:
                self.needs_2FA= d["needs2FA"]= False if response[8]==0X00 else True
                
        return (response, sw1, sw2, d)
    
    def card_setup(self, 
                    pin_tries0, ublk_tries0, pin0, ublk0,
                    pin_tries1, ublk_tries1, pin1, ublk1,
                    memsize, memsize2, 
                    create_object_ACL, create_key_ACL, create_pin_ACL,
                    option_flags=0, hmacsha160_key=None, amount_limit=0):

        # to do: check pin sizes < 256
        pin=[0x4D, 0x75, 0x73, 0x63, 0x6C, 0x65, 0x30, 0x30] # default pin
        cla= JCconstants.CardEdge_CLA
        ins= JCconstants.INS_SETUP        
        p1=0
        p2=0
        apdu=[cla, ins, p1, p2]
        
        # data=[pin_length(1) | pin | 
        #       pin_tries0(1) | ublk_tries0(1) | pin0_length(1) | pin0 | ublk0_length(1) | ublk0 | 
        #       pin_tries1(1) | ublk_tries1(1) | pin1_length(1) | pin1 | ublk1_length(1) | ublk1 | 
        #       memsize(2) | memsize2(2) | ACL(3) |
        #       option_flags(2) | hmacsha160_key(20) | amount_limit(8)]
        if option_flags==0:
            optionsize= 0
        elif option_flags&0x8000==0x8000:
            optionsize= 30
        else:
            optionsize= 2
        le= 16+len(pin)+len(pin0)+len(pin1)+len(ublk0)+len(ublk1)+optionsize
        
        apdu+=[le]
        apdu+=[len(pin)]+pin
        apdu+=[pin_tries0,  ublk_tries0, len(pin0)] + pin0 + [len(ublk0)] + ublk0
        apdu+=[pin_tries1,  ublk_tries1, len(pin1)] + pin1 + [len(ublk1)] + ublk1        
        apdu+=[memsize>>8, memsize&0x00ff, memsize2>>8, memsize2&0x00ff]
        apdu+=[create_object_ACL, create_key_ACL, create_pin_ACL]
        if option_flags!=0:
            apdu+=[option_flags>>8, option_flags&0x00ff]
            apdu+= hmacsha160_key
            for i in reversed(range(8)):
                apdu+=[(amount_limit>>(8*i))&0xff]

        # send apdu (contains sensitive data!)
        (response, sw1, sw2) = self.card_transmit(apdu)    
        return (response, sw1, sw2)        
    
    def card_bip32_import_seed(self, seed):
        cla= JCconstants.CardEdge_CLA
        ins= JCconstants.INS_BIP32_IMPORT_SEED
        p1= len(seed)  
        p2= 0x00
        le= len(seed)
        apdu=[cla, ins, p1, p2, le]+seed
        
        # send apdu (contains sensitive data!)
        response, sw1, sw2 = self.card_transmit(apdu)
        # compute authentikey pubkey and send to chip for future use
        if (sw1==0x90) and (sw2==0x00):
            authentikey= self.card_bip32_set_authentikey_pubkey(response)    
        return authentikey           
    
    def card_reset_seed(self, pin, hmac=[]):
        cla= JCconstants.CardEdge_CLA
        ins= 0x77
        p1= len(pin)  
        p2= 0x00
        le= len(pin)+len(hmac)
        apdu=[cla, ins, p1, p2, le]+pin+hmac
        
        response, sw1, sw2 = self.card_transmit(apdu)
        return (response, sw1, sw2)                                                                                  
    def card_bip32_get_authentikey(self):
        cla= JCconstants.CardEdge_CLA
        ins= JCconstants.INS_BIP32_GET_AUTHENTIKEY
        p1= 0x00 
        p2= 0x00
        le= 0x00
        apdu=[cla, ins, p1, p2, le]
        
        # send apdu 
        response, sw1, sw2 = self.card_transmit(apdu) 
        if sw1==0x9c and sw2==0x14: 
            _logger.info(f"card_bip32_get_authentikey(): Seed is not initialized => Raising error!")
            raise UninitializedSeedError('Seed is not initialized')
        if sw1==0x9c and sw2==0x04: 
            _logger.info("card_bip32_get_authentikey(): Satochip is not initialized => Raising error!")
            raise UninitializedSeedError("Satochip is not initialized! You should create a new wallet!")
        # compute corresponding pubkey and send to chip for future use
        if (sw1==0x90) and (sw2==0x00):
            authentikey = self.card_bip32_set_authentikey_pubkey(response)           
        return authentikey             
    
    ''' Allows to compute coordy of authentikey externally to optimize computation time-out
        coordy value is verified by the chip before being accepted '''
    def card_bip32_set_authentikey_pubkey(self, response):
        cla= JCconstants.CardEdge_CLA
        ins= 0x75
        p1= 0x00 
        p2= 0x00
        
        authentikey= self.parser.parse_bip32_get_authentikey(response)
        coordy= authentikey.get_public_key_bytes(compressed=False)
        coordy= list(coordy[33:])
        data= response + [len(coordy)&0xFF00, len(coordy)&0x00FF] + coordy
        le= len(data)
        apdu=[cla, ins, p1, p2, le]+data
                    
        (response, sw1, sw2) = self.card_transmit(apdu)
        return authentikey
    
    def card_bip32_get_extendedkey(self, path):
        cla= JCconstants.CardEdge_CLA
        ins= JCconstants.INS_BIP32_GET_EXTENDED_KEY
        p1= len(path)//4 
        p2= 0x40 #option flags: 0x80:erase cache memory - 0x40: optimization for non-hardened child derivation
        le= len(path)
        apdu=[cla, ins, p1, p2, le]
        apdu+= path
        
        if self.parser.authentikey is None:
            self.card_bip32_get_authentikey()
        
        # send apdu
        while (True):
            (response, sw1, sw2) = self.card_transmit(apdu)
            
            # if there is no more memory available, erase cache...
            #if self.get_sw12(sw1,sw2)==JCconstants.SW_NO_MEMORY_LEFT:
            if (sw1==0x9C) and (sw2==0x01):
                _logger.info(f"card_bip32_get_extendedkey(): Reset memory...")#debugSatochip
                apdu[3]=apdu[3]^0x80
                response, sw1, sw2 = self.card_transmit(apdu)
                apdu[3]=apdu[3]&0x7f # reset the flag
            # other (unexpected) error
            if (sw1!=0x90) or (sw2!=0x00): 
                raise UnexpectedSW12Error('Unexpected error code SW12='+hex(sw1)+" "+hex(sw2))
            # check for non-hardened child derivation optimization
            elif ( (response[32]&0x80)== 0x80): 
                _logger.info(f"card_bip32_get_extendedkey(): Child Derivation optimization...")#debugSatochip
                (pubkey, chaincode)= self.parser.parse_bip32_get_extendedkey(response)
                coordy= pubkey.get_public_key_bytes(compressed=False)
                coordy= list(coordy[33:])
                authcoordy= self.parser.authentikey.get_public_key_bytes(compressed=False)
                authcoordy= list(authcoordy[33:])
                data= response+[len(coordy)&0xFF00, len(coordy)&0x00FF]+coordy
                apdu_opt= [cla, 0x74, 0x00, 0x00, len(data)]
                apdu_opt= apdu_opt+data
                response_opt, sw1_opt, sw2_opt = self.card_transmit(apdu_opt)
            #at this point, we have successfully received a response from the card 
            else:
                (key, chaincode)= self.parser.parse_bip32_get_extendedkey(response)
                return (key, chaincode)
    
    def card_sign_message(self, keynbr, message, hmac=b''):
        if (type(message)==str):
            message = message.encode('utf8')
        
        # return signature as byte array
        # data is cut into chunks, each processed in a different APDU call
        chunk= 160 # max APDU data=255 => chunk<=255-(4+2)
        buffer_offset=0
        buffer_left=len(message)

        # CIPHER_INIT - no data processed
        cla= JCconstants.CardEdge_CLA
        ins= JCconstants.INS_SIGN_MESSAGE
        p1= keynbr # 0xff=>BIP32 otherwise STD
        p2= JCconstants.OP_INIT
        lc= 0x4
        apdu=[cla, ins, p1, p2, lc]
        for i in reversed(range(4)):
            apdu+= [((buffer_left>>(8*i)) & 0xff)]
        
        # send apdu
        (response, sw1, sw2) = self.card_transmit(apdu)
        
        # CIPHER PROCESS/UPDATE (optionnal)
        while buffer_left>chunk:
            #cla= JCconstants.CardEdge_CLA
            #ins= INS_COMPUTE_CRYPT
            #p1= key_nbr
            p2= JCconstants.OP_PROCESS
            le= 2+chunk
            apdu=[cla, ins, p1, p2, le]
            apdu+=[((chunk>>8) & 0xFF), (chunk & 0xFF)]
            apdu+= message[buffer_offset:(buffer_offset+chunk)]
            buffer_offset+=chunk
            buffer_left-=chunk
            # send apdu
            response, sw1, sw2 = self.card_transmit(apdu)
            
        # CIPHER FINAL/SIGN (last chunk)
        chunk= buffer_left #following while condition, buffer_left<=chunk
        #cla= JCconstants.CardEdge_CLA
        #ins= INS_COMPUTE_CRYPT
        #p1= key_nbr
        p2= JCconstants.OP_FINALIZE
        le= 2+chunk+ len(hmac)
        apdu=[cla, ins, p1, p2, le]
        apdu+=[((chunk>>8) & 0xFF), (chunk & 0xFF)]
        apdu+= message[buffer_offset:(buffer_offset+chunk)]+hmac
        buffer_offset+=chunk
        buffer_left-=chunk
        # send apdu
        response, sw1, sw2 = self.card_transmit(apdu)
        return (response, sw1, sw2)
        
    def card_sign_short_message(self, keynbr, message, hmac=b''):
        if (type(message)==str):
            message = message.encode('utf8')
        
        # for message less than one chunk in size
        cla= JCconstants.CardEdge_CLA
        ins= JCconstants.INS_SIGN_SHORT_MESSAGE
        p1= keynbr # oxff=>BIP32 otherwise STD
        p2= 0x00
        le= message.length+2+ len(hmac)
        apdu=[cla, ins, p1, p2, le]
        apdu+=[(message.length>>8 & 0xFF), (message.length & 0xFF)]
        apdu+=message+hmac
        # send apdu
        response, sw1, sw2 = self.card_transmit(apdu)
        return (response, sw1, sw2)      
    
    def card_parse_transaction(self, transaction, is_segwit=False):
            
        cla= JCconstants.CardEdge_CLA
        ins= JCconstants.INS_PARSE_TRANSACTION
        p1= JCconstants.OP_INIT
        p2= 0X01 if is_segwit else 0x00
        
        # init transaction data and context
        txparser= TxParser(transaction)
        while not txparser.is_parsed():
            
            chunk= txparser.parse_segwit_transaction() if is_segwit else txparser.parse_transaction()
            lc= len(chunk)
            apdu=[cla, ins, p1, p2, lc]
            apdu+=chunk
            
            # log state & send apdu
            #if (txparser.is_parsed():
                #le= 86 # [hash(32) | sigsize(2) | sig | nb_input(4) | nb_output(4) | coord_actif_input(4) | amount(8)] 
                #logCommandAPDU("cardParseTransaction - FINISH",cla, ins, p1, p2, data, le)
            #elif p1== JCconstants.OP_INIT:
                #logCommandAPDU("cardParseTransaction-INIT",cla, ins, p1, p2, data, le)    
            #elif p1== JCconstants.OP_PROCESS:
                #logCommandAPDU("cardParseTransaction - PROCESS",cla, ins, p1, p2, data, le) 
            
            # send apdu
            response, sw1, sw2 = self.card_transmit(apdu)
            
            # switch to process mode after initial call to parse
            p1= JCconstants.OP_PROCESS 
        
        return (response, sw1, sw2)      

    def card_sign_transaction(self, keynbr, txhash, chalresponse):
        #if (type(chalresponse)==str):
        #    chalresponse = list(bytes.fromhex(chalresponse))
        cla= JCconstants.CardEdge_CLA
        ins= JCconstants.INS_SIGN_TRANSACTION
        p1= keynbr
        p2= 0x00
        
        if len(txhash)!=32:
            raise ValueError("Wrong txhash length: " + str(len(txhash)) + "(should be 32)")    
        elif chalresponse==None:
            data= txhash 
        else:
            if len(chalresponse)!=20:
                raise ValueError("Wrong Challenge response length:"+ str(len(chalresponse)) + "(should be 20)")
            data= txhash + list(bytes.fromhex("8000")) + chalresponse  # 2 middle bytes for 2FA flag
        lc= len(data)
        apdu=[cla, ins, p1, p2, lc]+data
        
        # send apdu
        response, sw1, sw2 = self.card_transmit(apdu)
        return (response, sw1, sw2)      
            
    def card_set_2FA_key(self, hmacsha160_key, amount_limit):
        cla= JCconstants.CardEdge_CLA
        ins= 0x79
        p1= 0x00
        p2= 0x00
        le= 28 # data=[ hmacsha160_key(20) | amount_limit(8) ]
        apdu=[cla, ins, p1, p2, le]
        
        apdu+= hmacsha160_key
        for i in reversed(range(8)):
            apdu+=[(amount_limit>>(8*i))&0xff]

        # send apdu (contains sensitive data!)
        (response, sw1, sw2) = self.card_transmit(apdu)    
        return (response, sw1, sw2)            
    
    def card_reset_2FA_key(self, chalresponse):
        cla= JCconstants.CardEdge_CLA
        ins= 0x78
        p1= 0x00
        p2= 0x00
        le= 20 # data=[ hmacsha160_key(20) ]
        apdu=[cla, ins, p1, p2, le]
        apdu+= chalresponse

        # send apdu (contains sensitive data!)
        (response, sw1, sw2) = self.card_transmit(apdu)    
        return (response, sw1, sw2)
    def card_crypt_transaction_2FA(self, msg, is_encrypt=True):
        if (type(msg)==str):
            msg = msg.encode('utf8')
        msg=list(msg)
        msg_out=[]
        
        # CIPHER_INIT - no data processed
        cla= JCconstants.CardEdge_CLA
        ins= 0x76
        p2= JCconstants.OP_INIT
        blocksize=16
        if is_encrypt:
            p1= 0x02 
            lc= 0x00  
            apdu=[cla, ins, p1, p2, lc]
            # for encryption, the data is padded with PKCS#7
            size=len(msg)
            padsize= blocksize - (size%blocksize)
            msg= msg+ [padsize]*padsize
            # send apdu
            (response, sw1, sw2) = self.card_transmit(apdu)
            # extract IV & id_2FA
            IV= response[0:16]
            id_2FA= response[16:36]
            msg_out=IV
            # id_2FA is 20 bytes, should be 32 => use sha256
            from hashlib import sha256
            id_2FA= sha256(bytes(id_2FA)).hexdigest()
        else:
            p1= 0x01
            lc= 0x10 
            apdu=[cla, ins, p1, p2, lc]
            # for decryption, the IV must be provided as part of the msg
            IV= msg[0:16]
            msg=msg[16:]
            apdu= apdu+IV
            if len(msg)%blocksize!=0:
                _logger.info('Padding error!')
            # send apdu
            (response, sw1, sw2) = self.card_transmit(apdu)
            
        chunk= 192 # max APDU data=256 => chunk<=255-(4+2)
        buffer_offset=0
        buffer_left=len(msg)    
        # CIPHER PROCESS/UPDATE (optionnal)
        while buffer_left>chunk:
            p2= JCconstants.OP_PROCESS
            le= 2+chunk
            apdu=[cla, ins, p1, p2, le]
            apdu+=[((chunk>>8) & 0xFF), (chunk & 0xFF)]
            apdu+= msg[buffer_offset:(buffer_offset+chunk)]
            buffer_offset+=chunk
            buffer_left-=chunk
            # send apdu
            response, sw1, sw2 = self.card_transmit(apdu)
            # extract msg
            out_size= (response[0]<<8) + response[1]
            msg_out+= response[2:2+out_size]
            
        # CIPHER FINAL/SIGN (last chunk)
        chunk= buffer_left #following while condition, buffer_left<=chunk
        p2= JCconstants.OP_FINALIZE
        le= 2+chunk
        apdu=[cla, ins, p1, p2, le]
        apdu+=[((chunk>>8) & 0xFF), (chunk & 0xFF)]
        apdu+= msg[buffer_offset:(buffer_offset+chunk)]
        buffer_offset+=chunk
        buffer_left-=chunk
        # send apdu
        response, sw1, sw2 = self.card_transmit(apdu)
        # extract msg
        out_size= (response[0]<<8) + response[1]
        msg_out+= response[2:2+out_size]
        
        if is_encrypt:
            #convert from list to string
            msg_out= base64.b64encode(bytes(msg_out)).decode('ascii')
            return (id_2FA, msg_out)
        else:
            #remove padding
            pad= msg_out[-1]
            msg_out=msg_out[0:-pad]
            msg_out= bytes(msg_out).decode('latin-1')#''.join(chr(i) for i in msg_out) #bytes(msg_out).decode('latin-1')
            return (msg_out)
    
    def card_create_PIN(self, pin_nbr, pin_tries, pin, ublk):
        cla= JCconstants.CardEdge_CLA
        ins= JCconstants.INS_CREATE_PIN
        p1= pin_nbr
        p2= pin_tries
        lc= 1 + len(pin) + 1 + len(ublk)
        apdu=[cla, ins, p1, p2, lc] + [len(pin)] + pin + [len(ublk)] + ublk
        
        # send apdu
        response, sw1, sw2 = self.card_transmit(apdu)
        return (response, sw1, sw2)      
    
    #deprecated but used for testcase
    def card_verify_PIN_deprecated(self, pin_nbr, pin):
        cla= JCconstants.CardEdge_CLA
        ins= JCconstants.INS_VERIFY_PIN
        p1= pin_nbr
        p2= 0x00
        lc= len(pin)
        apdu=[cla, ins, p1, p2, lc] + pin
        # send apdu
        response, sw1, sw2 = self.card_transmit(apdu)
        return (response, sw1, sw2)      
    
    def card_verify_PIN(self):
        #_logger.info(f"card_verify_PIN()") #debugSatochip
        while (True):
            (response, sw1, sw2, d)=self.card_get_status() # get number of pin tries remaining
            if self.pin is None:
                if d.get("PIN0_remaining_tries",-1)==1:
                    msg = _("Enter the PIN for your Satochip: \n WARNING: ONLY ONE ATTEMPT REMAINING!")
                else:
                    msg = _("Enter the PIN for your Satochip:")
                (is_PIN, pin_0, pin_0)= self.client.PIN_dialog(msg)
                if pin_0 is None:
                    raise RuntimeError('Device cannot be unlocked without PIN code!')
                pin_0= list(pin_0)
            else: 
                pin_0= self.pin                
            cla= JCconstants.CardEdge_CLA
            ins= JCconstants.INS_VERIFY_PIN
            apdu=[cla, ins, 0x00, 0x00, len(pin_0)] + pin_0
            response, sw1, sw2 = self.cardservice.connection.transmit(apdu)
            if sw1==0x90 and sw2==0x00: 
                self.set_pin(0, pin_0) #cache PIN value
                return (response, sw1, sw2)     
            elif sw1==0x9c and sw2==0x02:
                self.set_pin(0, None) #reset cached PIN value
                pin_left= d.get("PIN0_remaining_tries",-1)-1
                msg = _("Wrong PIN! {} tries remaining!").format(pin_left)
                self.client.handler.show_error(msg)
            elif sw1==0x9c and sw2==0x0c:
                msg = _("Too many failed attempts! Your Satochip has been blocked! You need your PUK code to unblock it.")
                self.client.handler.show_error(msg)
                raise RuntimeError('Device blocked with error code:'+hex(sw1)+' '+hex(sw2))

    def set_pin(self, pin_nbr, pin):
        self.pin_nbr=pin_nbr
        self.pin=pin
        return
        
    def card_change_PIN(self, pin_nbr, old_pin, new_pin):
        cla= JCconstants.CardEdge_CLA
        ins= JCconstants.INS_CHANGE_PIN
        p1= pin_nbr
        p2= 0x00
        lc= 1 + len(old_pin) + 1 + len(new_pin)
        apdu=[cla, ins, p1, p2, lc] + [len(old_pin)] + old_pin + [len(new_pin)] + new_pin
        # send apdu
        response, sw1, sw2 = self.card_transmit(apdu)
        self.set_pin(0, None)
        return (response, sw1, sw2)      
    
    def card_unblock_PIN(self, pin_nbr, ublk):
        cla= JCconstants.CardEdge_CLA
        ins= JCconstants.INS_UNBLOCK_PIN
        p1= pin_nbr
        p2= 0x00
        lc= len(ublk)
        apdu=[cla, ins, p1, p2, lc] + ublk
        # send apdu
        response, sw1, sw2 = self.card_transmit(apdu)
        return (response, sw1, sw2)      
        
    def card_logout_all(self):
        cla= JCconstants.CardEdge_CLA
        ins= JCconstants.INS_LOGOUT_ALL
        p1= 0x00
        p2= 0x00
        lc=0
        apdu=[cla, ins, p1, p2, lc]
        # send apdu
        response, sw1, sw2 = self.card_transmit(apdu)
        self.set_pin(0, None)                   
        return (response, sw1, sw2)      
    
class AuthenticationError(Exception):    
    """Raised when the command requires authentication first"""
    pass
        
class UninitializedSeedError(Exception):    
    """Raised when the device is not yet seeded"""
    pass      

class UnexpectedSW12Error(Exception):    
    """Raised when the device returns an unexpected error code"""
    pass     
    
if __name__ == "__main__":
    
    cardconnector= CardConnector()
    cardconnector.card_get_ATR()
    cardconnector.card_select()
    #cardconnector.card_setup()
    cardconnector.card_bip32_get_authentikey()
    #cardconnector.card_bip32_get_extendedkey()
    cardconnector.card_disconnect()
    
    
    
    
    