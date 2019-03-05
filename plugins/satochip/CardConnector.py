from smartcard.CardType import AnyCardType
from smartcard.CardRequest import CardRequest
from smartcard.CardConnectionObserver import ConsoleCardConnectionObserver
from smartcard.Exceptions import CardConnectionException, CardRequestTimeoutException
from smartcard.util import toHexString, toBytes
from smartcard.sw.SWExceptions import SWException

from .JCconstants import JCconstants 
from .TxParser import TxParser

from electrum.util import print_error
from electrum.ecc import ECPubkey, msg_magic
from electrum.i18n import _

class CardConnector:
    
    # Satochip supported version tuple
    SATOCHIP_PROTOCOL_MAJOR_VERSION=0
    SATOCHIP_PROTOCOL_MINOR_VERSION=6
    
    # define the apdus used in this script
    BYTE_AID= [0x53,0x61,0x74,0x6f,0x43,0x68,0x69,0x70] #SatoChip
    
    def __init__(self, client):
        # request any card type
        self.client=client
        self.parser=client.parser
        self.cardtype = AnyCardType()
        try: 
            # request card insertion
            self.cardrequest = CardRequest(timeout=10, cardType=self.cardtype)
            self.cardservice = self.cardrequest.waitforcard()
            # attach the console tracer
            self.observer = ConsoleCardConnectionObserver()
            self.cardservice.connection.addObserver(self.observer)
            # connect to the card and perform a few transmits
            self.cardservice.connection.connect()
            # cache PIN
            self.pin_nbr=None
            self.pin=None
        except CardRequestTimeoutException:
            print_error('time-out: no card inserted during last 10s')
        except Exception as exc:
            print_error("Error during connection:", exc)
    
    def set_pin(self, pin_nbr, pin):
        self.pin_nbr=pin_nbr
        self.pin=pin
        return
    
    def card_transmit(self, apdu):
        try:
            (response, sw1, sw2) = self.cardservice.connection.transmit(apdu)
            if (sw1==0x9C) and (sw2==0x06):
                if self.pin is None:
                    print_error("[CardConnector] card_transmit(): prompt for pin..")
                    msg = _("Enter the PIN for your Satochip:")
                    is_pin, pin, pin2 = self.client.PIN_dialog(msg)
                    self.pin_nbr=0
                    self.pin= list(pin)
                (response, sw1, sw2)= self.card_verify_PIN(self.pin_nbr, self.pin) 
                (response, sw1, sw2)= self.cardservice.connection.transmit(apdu)
            return (response, sw1, sw2)
        except CardConnectionException: 
            # may be the card has been removed
            try:
                self.cardrequest = CardRequest(timeout=10, cardType=self.cardtype)
                self.cardservice = self.cardrequest.waitforcard()
                # attach the console tracer
                self.observer = ConsoleCardConnectionObserver()
                self.cardservice.connection.addObserver(self.observer)
                # connect to the card and perform a few transmits
                self.cardservice.connection.connect()
            except CardRequestTimeoutException:
                print_error('time-out: no card inserted during last 10s')
            except Exception as exc:
                print_error("Error during connection:", exc)
        
    def card_get_ATR(self):
        return self.cardservice.connection.getATR()
    
    def card_disconnect(self):
        self.cardservice.connection.disconnect()
    
    def get_sw12(self, sw1, sw2):
        return 16*sw1+sw2
    
    def card_select(self):        
        SELECT = [0x00, 0xA4, 0x04, 0x00, 0x08]
        apdu = SELECT + CardConnector.BYTE_AID
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
            for i in reverse(range(8)):
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
            print_error("[CardConnector] card_bip32_get_authentikey(): Seed is not initialized => Raising error!")
            raise UninitializedSeedError('Seed is not initialized')
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
        
        print_error("[CardConnector] CardConnector: card_bip32_set_authentikey_pubkey(): len(response)="+str(len(response)))#debugSatochip
        print_error("[CardConnector] CardConnector: card_bip32_set_authentikey_pubkey(): len(coordy)="+str(len(coordy)))#debugSatochip
        print_error("[CardConnector] CardConnector: card_bip32_set_authentikey_pubkey(): coordy="+ str(coordy))#debugSatochip
                    
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
                print_error("[CardConnector] CardConnector: card_bip32_get_extendedkey(): Reset memory...")#debugSatochip
                apdu[3]=apdu[3]^0x80
                response, sw1, sw2 = self.card_transmit(apdu)
                apdu[3]=apdu[3]&0x7f # reset the flag
            # other (unexpected) error
            if (sw1!=0x90) or (sw2!=0x00): 
                raise UnexpectedSW12Error('Unexpected error code SW12='+hex(sw1)+" "+hex(sw2))
            # check for non-hardened child derivation optimization
            elif ( (response[32]&0x80)== 0x80): 
                print_error("[CardConnector] CardConnector: card_bip32_get_extendedkey(): Child Derivation optimization...")#debugSatochip
                (pubkey, chaincode)= self.parser.parse_bip32_get_extendedkey(response)
                coordy= pubkey.get_public_key_bytes(compressed=False)
                coordy= list(coordy[33:])
                authcoordy= self.parser.authentikey.get_public_key_bytes(compressed=False)
                authcoordy= list(authcoordy[33:])
                print_error("[CardConnector] CardConnector: card_bip32_get_extendedkey(): len(response)="+str(len(response)))#debugSatochip
                print_error("[CardConnector] CardConnector: card_bip32_get_extendedkey(): len(coordy)="+str(len(coordy)))#debugSatochip
                print_error("[CardConnector] CardConnector: card_bip32_get_extendedkey(): coordy="+ str(coordy))#debugSatochip
                print_error("[CardConnector] CardConnector: card_bip32_get_extendedkey(): len(authcoordy)="+str(len(authcoordy)))#debugSatochip
                print_error("[CardConnector] CardConnector: card_bip32_get_extendedkey(): authcoordy="+ str(authcoordy))#debugSatochip
                data= response+[len(coordy)&0xFF00, len(coordy)&0x00FF]+coordy
                print_error("[CardConnector] CardConnector: card_bip32_get_extendedkey(): len(data)="+ str(len(data)))#debugSatochip
                print_error("[CardConnector] CardConnector: card_bip32_get_extendedkey(): data="+ str(data))#debugSatochip
                apdu_opt= [cla, 0x74, 0x00, 0x00, len(data)]
                apdu_opt= apdu_opt+data
                response_opt, sw1_opt, sw2_opt = self.card_transmit(apdu_opt)
            #at this point, we have successfully received a response from the card 
            else:
                (key, chaincode)= self.parser.parse_bip32_get_extendedkey(response)
                return (key, chaincode)
    
    def card_sign_message(self, keynbr, message):
        if (type(message)==str):
            message = message.encode('utf8')
        
        # return signature as byte array
        # data is cut into chunks, each processed in a different APDU call
        chunk= 160 # max APDU data=256 => chunk<=255-(4+2)
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
        le= 2+chunk
        apdu=[cla, ins, p1, p2, le]
        apdu+=[((chunk>>8) & 0xFF), (chunk & 0xFF)]
        apdu+= message[buffer_offset:(buffer_offset+chunk)]
        buffer_offset+=chunk
        buffer_left-=chunk
        # send apdu
        response, sw1, sw2 = self.card_transmit(apdu)
        return (response, sw1, sw2)
        
    def card_sign_short_message(self, keynbr, message):
        if (type(message)==str):
            message = message.encode('utf8')
        
        # for message less than one chunk in size
        cla= JCconstants.CardEdge_CLA
        ins= JCconstants.INS_SIGN_SHORT_MESSAGE
        p1= keynbr # oxff=>BIP32 otherwise STD
        p2= 0x00
        le= message.length+2
        apdu=[cla, ins, p1, p2, le]
        apdu+=[(message.length>>8 & 0xFF), (message.length & 0xFF)]
        apdu+=message
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
            data= txhash + chalresponse
        lc= len(data)
        apdu=[cla, ins, p1, p2, lc]+data
        
        # send apdu
        response, sw1, sw2 = self.card_transmit(apdu)
        return (response, sw1, sw2)      
    
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
    
    def card_verify_PIN(self, pin_nbr, pin):
        cla= JCconstants.CardEdge_CLA
        ins= JCconstants.INS_VERIFY_PIN
        p1= pin_nbr
        p2= 0x00
        lc= len(pin)
        apdu=[cla, ins, p1, p2, lc] + pin
        # send apdu
        response, sw1, sw2 = self.card_transmit(apdu)
        return (response, sw1, sw2)      
    
    def card_change_PIN(self, pin_nbr, old_pin, new_pin):
        cla= JCconstants.CardEdge_CLA
        ins= JCconstants.INS_CHANGE_PIN
        p1= pin_nbr
        p2= 0x00
        lc= 1 + len(old_pin) + 1 + len(new_pin)
        apdu=[cla, ins, p1, p2, lc] + [len(old_pin)] + old_pin + [len(new_pin)] + new_pin
        # send apdu
        response, sw1, sw2 = self.card_transmit(apdu)
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
    #cardconnector=satochiClient()
    cardconnector.card_get_ATR()
    cardconnector.card_select()
    #cardconnector.card_setup()
    cardconnector.card_bip32_get_authentikey()
    #cardconnector.card_bip32_get_extendedkey()
    cardconnector.card_disconnect()
    
    
    
    
    