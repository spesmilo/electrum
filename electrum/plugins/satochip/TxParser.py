'''
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
'''
import hashlib
from enum import Enum, auto

class TxState(Enum):
    TX_START= auto()
    TX_PARSE_INPUT= auto()
    TX_PARSE_INPUT_SCRIPT= auto()
    TX_PARSE_OUTPUT= auto()
    TX_PARSE_OUTPUT_SCRIPT= auto()
    TX_PARSE_FINALIZE= auto()
    TX_END= auto()
    
class TxParser:
    CHUNK_SIZE=128 # max chunk size of a script
    
    def __init__(self, rawTx):
        self.txData= rawTx[:]

        self.txRemainingInput=0
        self.txCurrentInput=0
        self.txRemainingOutput=0
        self.txCurrentOutput=0
        self.txAmount=0
        self.txScriptRemaining=0
        self.txOffset=0
        self.txRemaining=len(rawTx)
        self.txState= TxState.TX_START        
        
        self.txDigest=hashlib.sha256()
        self.singleHash=None
        self.doubleHash=None

        self.txChunk=b''
        
    def set_remaining_output(self, nb_outputs):
        self.txRemainingOutput=nb_outputs
    
    def is_parsed(self):
        return (self.txRemaining==0)

    def get_tx_hash(self):
        return self.singleHash

    def get_tx_double_hash(self):
        return self.doubleHash
    
    def parse_transaction(self):
        self.txChunk=b''
        if self.txState == TxState.TX_START:

            # max 4+9 bytes accumulated
            self.parse_byte(4) # version
            self.txRemainingInput= self.parse_var_int() 
            self.txState= TxState.TX_PARSE_INPUT
            
        if self.txState == TxState.TX_PARSE_INPUT:
            # max 36+9 bytes accumulated
            if self.txRemainingInput==0:
                self.txRemainingOutput= self.parse_var_int()
                self.txState= TxState.TX_PARSE_OUTPUT
                #break
            else: 
                self.parse_byte(32); # txOutHash
                self.parse_byte(4); # txOutIndex
                self.txScriptRemaining= self.parse_var_int();
                self.txState= TxState.TX_PARSE_INPUT_SCRIPT
                self.txRemainingInput-=1
                self.txCurrentInput+=1
                #break
                
        elif self.txState == TxState.TX_PARSE_INPUT_SCRIPT:
            # max MAX_CHUNK_SIZE+4 bytes accumulated
            chunkSize= self.txScriptRemaining if self.txScriptRemaining<self.CHUNK_SIZE else self.CHUNK_SIZE
            self.parse_byte(chunkSize);
            self.txScriptRemaining-=chunkSize
            if self.txScriptRemaining==0:
                self.parse_byte(4); # sequence
                self.txState= TxState.TX_PARSE_INPUT
            #break
            
        elif self.txState == TxState.TX_PARSE_OUTPUT:
            # max 8+9 bytes accumulated    
            if self.txRemainingOutput==0:
                self.parse_byte(4); #locktime
                self.parse_byte(4); #sighash
                self.txState= TxState.TX_END
                #break
            else:
                self.parse_byte(8); # amount
                self.txScriptRemaining= self.parse_var_int();
                self.txState= TxState.TX_PARSE_OUTPUT_SCRIPT
                self.txRemainingOutput-=1
                self.txCurrentOutput+=1
                #//break                    
           
        elif self.txState == TxState.TX_PARSE_OUTPUT_SCRIPT:
            #max MAX_CHUNK_SIZE bytes accumulated 
            chunkSize= self.txScriptRemaining if self.txScriptRemaining<self.CHUNK_SIZE else self.CHUNK_SIZE
            self.parse_byte(chunkSize);
            self.txScriptRemaining-=chunkSize

            if self.txScriptRemaining==0:
                self.txState= TxState.TX_PARSE_OUTPUT
            
        elif self.txState == TxState.TX_END:
            pass
    
        # update hash
        self.txDigest.update(self.txChunk)    
        if self.txState == TxState.TX_END:
            self.singleHash= self.txDigest.digest() 
            self.txDigest= hashlib.sha256()
            self.txDigest.update(self.singleHash)
            self.doubleHash= self.txDigest.digest() 
        
        return self.txChunk

    def parse_outputs(self):
        self.txChunk=b''
        
        if (self.txState == TxState.TX_PARSE_OUTPUT) or (self.txState == TxState.TX_START):
            
            if self.txRemainingOutput==0:
                self.txState == TxState.TX_END
            
            self.parse_byte(8); # amount
            self.txScriptRemaining= self.parse_var_int();
            self.txState= TxState.TX_PARSE_OUTPUT_SCRIPT
            self.txRemainingOutput-=1
            self.txCurrentOutput+=1
           
        elif self.txState == TxState.TX_PARSE_OUTPUT_SCRIPT:
            #max MAX_CHUNK_SIZE bytes accumulated 
            chunkSize= self.txScriptRemaining if self.txScriptRemaining<self.CHUNK_SIZE else self.CHUNK_SIZE
            self.parse_byte(chunkSize);
            self.txScriptRemaining-=chunkSize

            if self.txScriptRemaining==0:
                self.txState= TxState.TX_PARSE_OUTPUT
            
        elif self.txState == TxState.TX_END:
            pass
    
        # update hash
        self.txDigest.update(self.txChunk)    
        if self.txState == TxState.TX_END:
            self.singleHash= self.txDigest.digest() 
            self.txDigest= hashlib.sha256()
            self.txDigest.update(self.singleHash)
            self.doubleHash= self.txDigest.digest() 
        
        return self.txChunk
    
    def parse_segwit_transaction(self):
        
        self.txChunk=b''
        if self.txState == TxState.TX_START:

            self.parse_byte(4) # version
            self.parse_byte(32) # hashPrevouts
            self.parse_byte(32) # hashSequence
            # parse outpoint
            self.parse_byte(32); # txOutHash
            self.parse_byte(4); # txOutIndex
            # scriptcode= varint+script
            self.txScriptRemaining= self.parse_var_int() 
            self.txState= TxState.TX_PARSE_INPUT_SCRIPT
            
        elif self.txState == TxState.TX_PARSE_INPUT_SCRIPT:
            # max MAX_CHUNK_SIZE+4 bytes accumulated
            chunkSize= self.txScriptRemaining if self.txScriptRemaining<self.CHUNK_SIZE else self.CHUNK_SIZE
            self.parse_byte(chunkSize);
            self.txScriptRemaining-=chunkSize
            if self.txScriptRemaining==0:
                self.txState= TxState.TX_PARSE_FINALIZE
            
        elif self.txState == TxState.TX_PARSE_FINALIZE:
            self.parse_byte(8); # amount
            self.parse_byte(4); # nSequence
            self.parse_byte(32); # hashOutputs
            self.parse_byte(4); # nLocktime
            self.parse_byte(4); # nHashType
            
            self.txState= TxState.TX_END
            
        elif self.txState == TxState.TX_END:
            pass
    
        # update hash
        self.txDigest.update(self.txChunk)    
        if self.txState == TxState.TX_END:
            self.singleHash= self.txDigest.digest() 
            self.txDigest= hashlib.sha256()
            self.txDigest.update(self.singleHash)
            self.doubleHash= self.txDigest.digest() 
        
        return self.txChunk
        
    def parse_byte(self, length):
        self.txChunk+=self.txData[self.txOffset:(self.txOffset+length)]
        self.txOffset+=length
        self.txRemaining-=length
        
    def parse_var_int(self):
        
        first = 0xFF & self.txData[self.txOffset];
        val=0
        le=0
        if first < 253:
            # 8 bits
            val = first
            le=1
        elif first == 253:
            # 16 bits
            val = (0xFF & self.txData[self.txOffset+1]) | ((0xFF & self.txData[self.txOffset+2]) << 8);
            le=3
        elif first == 254:
            # 32 bits
            val = read_int32(self.txData, self.txOffset + 1);
            le=5
        else:
            # 64 bits
            val = read_int64(self.txData, self.txOffset + 1);
            le=9
        
        self.txChunk+=self.txData[self.txOffset:(self.txOffset+le)]
        self.txOffset+=le
        self.txRemaining-=le
        return val

        
def read_uint32(bytes, offset):
    out=0
    for i in range(4):
        out|= (bytes[offset] & 0xff)<<(8*i)
        offset+=1
    return out

def read_int64(bytes, offset):
    out=0
    for i in range(8):
        out|= (bytes[offset] & 0xff)<<(8*i)
        offset+=1
    return out
