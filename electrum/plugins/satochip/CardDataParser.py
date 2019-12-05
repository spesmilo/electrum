"""
 * Python API for the SatoChip Bitcoin Hardware Wallet
 * (c) 2015 by Toporin - 16DMCk4WUaHofchAhpMaQS4UPm4urcy2dN
 * Sources available on https://github.com/Toporin
 * 
 * Copyright 2015 by Toporin (https://github.com/Toporin)
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
"""  
import hashlib
from electrum.ecc import ECPubkey, msg_magic, InvalidECPointException, sig_string_from_der_sig, construct_sig65
from electrum.util import to_bytes, bfh, bh2u
from electrum.crypto import sha256d
from electrum.logging import get_logger

_logger = get_logger(__name__)

MSG_WARNING= ("Before you request bitcoins to be sent to addresses in this "
                    "wallet, ensure you can pair with your device, or that you have "
                    "its seed (and passphrase, if any).  Otherwise all bitcoins you "
                    "receive will be unspendable.")

class CardDataParser:
    
    def __init__(self):
        self.authentikey=None
        self.authentikey_coordx= None
        self.authentikey_from_storage=None
        
    def parse_bip32_get_authentikey(self,response):
        # response= [data_size | data | sig_size | signature]
        # where data is coordx
        data_size = ((response[0] & 0xff)<<8) + ((response[1] & 0xff))
        data= response[2:(2+data_size)]
        msg_size= 2+data_size
        msg= response[0:msg_size]
        sig_size = ((response[msg_size] & 0xff)<<8) + ((response[msg_size+1] & 0xff))
        signature= response[(msg_size+2):(msg_size+2+sig_size)]
        
        if sig_size==0:
           raise ValueError("Signature missing")
        # self-signed
        coordx=data
        self.authentikey= self.get_pubkey_from_signature(coordx, msg, signature)
        self.authentikey_coordx= coordx
        
        # if already initialized, check that authentikey match value retrieved from storage!
        if (self.authentikey_from_storage is not None):
            if  self.authentikey != self.authentikey_from_storage:
                raise ValueError("The seed used to create this wallet file no longer matches the seed of the Satochip device!\n\n"+MSG_WARNING)

        return self.authentikey
        
    def parse_bip32_import_seed(self,response):
        # response= [data_size | data | sig_size | signature]
        # where data is coordx
        return self.parse_bip32_get_authentikey(response)

    def parse_bip32_get_extendedkey(self, response):
        if self.authentikey is None:
            raise ValueError("Authentikey not set!")
        
        # double signature: first is self-signed, second by authentikey
        # firs self-signed sig: data= coordx
        #_logger.info(f'parse_bip32_get_extendedkey: first signature recovery')
        self.chaincode= bytearray(response[0:32])
        data_size = ((response[32] & 0x7f)<<8) + (response[33] & 0xff) # (response[32] & 0x80) is ignored (optimization flag)
        data= response[34:(32+2+data_size)]
        msg_size= 32+2+data_size
        msg= response[0:msg_size]
        sig_size = ((response[msg_size] & 0xff)<<8) + (response[msg_size+1] & 0xff)
        signature= response[(msg_size+2):(msg_size+2+sig_size)]
        if sig_size==0:
           raise ValueError("Signature missing")
        # self-signed
        coordx=data
        self.pubkey= self.get_pubkey_from_signature(coordx, msg, signature)
        self.pubkey_coordx= coordx
        
        # second signature by authentikey
        #_logger.info(f'parse_bip32_get_extendedkey: second signature recovery')
        msg2_size= msg_size+2+sig_size
        msg2= response[0:msg2_size]
        sig2_size = ((response[msg2_size] & 0xff)<<8) + (response[msg2_size+1] & 0xff)  
        signature2= response[(msg2_size+2):(msg2_size+2+sig2_size)] 
        authentikey= self.get_pubkey_from_signature(self.authentikey_coordx, msg2, signature2)
        if authentikey != self.authentikey:
            raise ValueError("The seed used to create this wallet file no longer matches the seed of the Satochip device!\n\n"+MSG_WARNING)

        return (self.pubkey, self.chaincode)
    
    ##############
    def parse_message_signature(self, response, message, pubkey):
        
        # Prepend the message for signing as done inside the card!!
        message = to_bytes(message, 'utf8')
        hash = sha256d(msg_magic(message))
        coordx= pubkey.get_public_key_bytes()
        
        response= bytearray(response)
        recid=-1
        for id in range(4):
            compsig=self.parse_to_compact_sig(response, id, compressed=True)
            # remove header byte
            compsig2= compsig[1:]
            
            try: 
                pk = ECPubkey.from_sig_string(compsig2, id, hash)
                pkbytes= pk.get_public_key_bytes(compressed=True)
            except InvalidECPointException:
                continue
            
            if coordx==pkbytes:
                recid=id
                break
        
        if recid == -1:
            raise ValueError("Unable to recover public key from signature")        
        
        return compsig
        
    ##############
        
    def get_pubkey_from_signature(self, coordx, data, sig):
        data= bytearray(data)
        sig= bytearray(sig)
        coordx= bytearray(coordx)
        
        digest=hashlib.sha256()
        digest.update(data)
        hash=digest.digest()
        
        recid=-1
        pubkey=None
        for id in range(4):
            compsig=self.parse_to_compact_sig(sig, id, compressed=True)
            # remove header byte
            compsig= compsig[1:]
            
            try:
                pk = ECPubkey.from_sig_string(compsig, id, hash)
                pkbytes= pk.get_public_key_bytes(compressed=True)
            except InvalidECPointException:
                continue
            
            pkbytes= pkbytes[1:]
            
            if coordx==pkbytes:
                recid=id
                pubkey=pk
                break
        
        if recid == -1:
            raise ValueError("Unable to recover public key from signature")        
    
        return pubkey            
    
    ######
    
    def parse_parse_transaction(self, response):
        '''Satochip returns: [(hash_size+2)(2b) | tx_hash(32b) | need2fa(2b) | sig_size(2b) | sig(sig_size) | txcontext]'''
        offset=0
        data_size= ((response[offset] & 0xff)<<8) + (response[offset+1] & 0xff)
        txhash_size= data_size-2
        offset+=2
        tx_hash= response[offset:(offset+txhash_size)]
        offset+=txhash_size
        needs_2fa= ((response[offset] & 0xff)<<8) + (response[offset+1] & 0xff)
        needs_2fa= False if (needs_2fa==0) else True
        offset+=2
        sig_size= ((response[offset] & 0xff)<<8) + (response[offset+1] & 0xff)
        sig_data= response[0:data_size+2] # txhash_size+hash+needs_2fa
        offset+=2
        if sig_size>0 and self.authentikey_coordx:
            sig= response[offset:(offset+sig_size)]
            pubkey= self.get_pubkey_from_signature(self.authentikey_coordx, sig_data, sig)
            if pubkey != self.authentikey:
                raise Exception("signing key is not authentikey!")
        #todo: error checking
        
        return (tx_hash, needs_2fa)
    
    def parse_to_compact_sig(self, sigin, recid, compressed):
        ''' convert a DER encoded signature to compact 65-byte format
            input is bytearray in DER format
            output is bytearray in compact 65-byteformat
            http://bitcoin.stackexchange.com/questions/12554/why-the-signature-is-always-65-13232-bytes-long
            https://bitcointalk.org/index.php?topic=215205.0            
        '''
        sig_string = sig_string_from_der_sig(sigin)
        return construct_sig65(sig_string, recid, compressed)

