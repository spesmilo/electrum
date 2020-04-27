from btchip.bitcoinVarint import *
from binascii import hexlify
from collections import namedtuple
from struct import pack, Struct
from electrum.util import bh2u
from electrum.bitcoin import int_to_hex

unpack_int32_from = Struct('<i').unpack_from
unpack_int64_from = Struct('<q').unpack_from
unpack_uint16_from = Struct('<H').unpack_from
unpack_uint32_from = Struct('<I').unpack_from
unpack_uint64_from = Struct('<Q').unpack_from

def hex_to_bytes(val):
    bytearray(val).decode('hex')

# Method decorator.  To be used for calculations that will always                                                                                               
# deliver the same result.  The method cannot take any arguments                                                                                                
# and should be accessed as an attribute.                                                                                                                       
class cachedproperty(object):

    def __init__(self, f):
        self.f = f

    def __get__(self, obj, type):
        obj = obj or type
        value = self.f(obj)
        setattr(obj, self.f.__name__, value)
        return value

import hashlib
import hmac

_sha256 = hashlib.sha256
_sha512 = hashlib.sha512
_new_hash = hashlib.new
_new_hmac = hmac.new
HASHX_LEN = 11


def sha256(x):
    '''Simple wrapper of hashlib sha256.'''
    return _sha256(x).digest()

def double_sha256(x):
    '''SHA-256 of SHA-256, as used extensively in bitcoin.'''
    return sha256(sha256(x))

class Deserializer(object):
    '''Deserializes blocks into transactions.

    External entry points are read_tx(), read_tx_and_hash(),
    read_tx_and_vsize() and read_block().

    This code is performance sensitive as it is executed 100s of
    millions of times during sync.
    '''

    TX_HASH_FN = staticmethod(double_sha256)

    def __init__(self, binary, start=0):
        assert isinstance(binary, bytes)
        self.binary = binary
        assert isinstance(self.binary, bytes)
        self.binary_length = len(binary)
        self.cursor = start

    def read_tx(self):
        '''Return a deserialized transaction.'''
        return Tx(
            self._read_le_int32(),  # version
            self._read_inputs(),    # inputs
            self._read_outputs(),   # outputs
            self._read_le_uint32()  # locktime
        )

    def read_tx_and_hash(self):
        '''Return a (deserialized TX, tx_hash) pair.

        The hash needs to be reversed for human display; for efficiency
        we process it in the natural serialized order.
        '''
        start = self.cursor
        return self.read_tx(), self.TX_HASH_FN(self.binary[start:self.cursor])

    def read_tx_and_vsize(self):
        '''Return a (deserialized TX, vsize) pair.'''
        return self.read_tx(), self.binary_length

    def read_tx_block(self):
        '''Returns a list of (deserialized_tx, tx_hash) pairs.'''
        read = self.read_tx_and_hash
        # Some coins have excess data beyond the end of the transactions
        return [read() for _ in range(self._read_varint())]

    def _read_inputs(self):
        read_input = self._read_input
        n_inputs=self._read_varint()
        return [read_input() for i in range(n_inputs)]

    def _read_input(self):
        return TxInput(
            self._read_nbytes(32),   # prev_hash
            self._read_le_uint32(),  # prev_idx
            self._read_varbytes(),   # script
            self._read_le_uint32()   # sequence
        )

    def _read_outputs(self):
        n=self._read_varint()
        read_output = self._read_output
        return [read_output() for i in range(n)]

    def _read_output(self):
        return TxOutput(
            self._read_le_int64(),  # value
            self._read_varbytes(),  # pk_script
        )

    def _read_byte(self):
        cursor = self.cursor
        self.cursor += 1
        return self.binary[cursor]

    def _read_nbytes(self, n):
        cursor = self.cursor
        self.cursor = end = cursor + n
        assert self.binary_length >= end
        return self.binary[cursor:end]

    def _read_varbytes(self):
        n=self._read_varint()
        return self._read_nbytes(n)

    def _read_varint(self):
        n = int(self.binary[self.cursor])
        self.cursor += 1
        if n < 253:
            return n
        if n == 253:
            return self._read_le_uint16()
        if n == 254:
            return self._read_le_uint32()
        return self._read_le_uint64()

    def _read_le_int32(self):
        result, = unpack_int32_from(self.binary, self.cursor)
        self.cursor += 4
        return result

    def _read_le_int64(self):
        result, = unpack_int64_from(self.binary, self.cursor)
        self.cursor += 8
        return result

    def _read_le_uint16(self):
        result, = unpack_uint16_from(self.binary, self.cursor)
        self.cursor += 2
        return result

    def _read_le_uint32(self):
        result, = unpack_uint32_from(self.binary, self.cursor)
        self.cursor += 4
        return result

    def _read_le_uint64(self):
        result, = unpack_uint64_from(self.binary, self.cursor)
        self.cursor += 8
        return result


class DeserializerOcean(Deserializer):
    WITNESS_SCALE_FACTOR = 4;

    '''
    Ocean Block Header sample
    00000020    version
    f2f7342df785645fc5b28e4db3261eef0b4ef57ee787068374b103854cd65b08    prevhash
    713ccf4863baa2d3cd2ed82b25e866dc660b0e1d9f359147fc968cd2ee074c99    hashMerkleRoot
    5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456    hashContract
    0000000000000000000000000000000000000000000000000000000000000000    hashAttestation
    0000000000000000000000000000000000000000000000000000000000000000    hashMapping
    a4375f5b    nTime
    01000000    nHeight
    69          script challenge
    522103d517f6e9affa60000a08d478970e6bbfa45d63b1967ed1e066dd46b802edb2a62102afc18e8a7ff988ca1ae7b659cb09a79852d301c2283e18cba1faf7a0b020b1a22102edd8080e31f05c68cf68a97782ac97744e86ba19dfd3ba68e597f10868ee5bc453ae
    8e          script proof
    0046304402201a822d9a7f211fbfbf2bb92ead874c71967dbd3c9e0249931cabb7591f36a46602207acbd97989005d0f16b6b6de84b03f3c659de28649a67cf2664e79badadf20c4453043021f5e1e160aa0e6afb078e9e2428d60a146598df03d48ede67799242109c2b690022023253a6381ea8cd07410903e97be730823a48a79bac16c4e097fe3fc54060888
    '''
    def read_header(self, height, static_header_size):
        '''Return the Ocean block header bytes'''
        start = self.cursor
        self.cursor += static_header_size

        challenge_size = self._read_varint() # read challenge size - 2 bytes
        if challenge_size:
            self.cursor += challenge_size # read challenge - challenge_size bytes

        proof_size = self._read_varint() # read proof size - 2 bytes
        if proof_size:
            self.cursor += proof_size # read proof

        header_end = self.cursor
        self.cursor = start
        return self._read_nbytes(header_end)

    '''
    Ocean Transaction sample
    02000000    version
    01          flag

    01          # of vins
    0000000000000000000000000000000000000000000000000000000000000000    vin prevhash
    ffffffff    vin prev_idx
    03  530101  script
    ffffffff    sequence
        - issuance example (if prev_idx & TxInputOcean.OUTPOINT_ISSUANCE_FLAG)
        0000000000000000000000000000000000000000000000000000000000000000    nonce 32bytes
        0000000000000000000000000000000000000000000000000000000000000000    entropy 32bytes
        01  00038d7ea4c68000  amount (confidential value)
        00                    inflation (confidential value)

    02          # of vouts

    01  8f9390e4c7b981e355aed3c5690e17c2e13bb263246a55d8039813cac670c2f1    asset (confidential asset)
    01  000000000000de80    value (confidential value)
    00                      nonce (confidential nonce)
    01  51                  script

    01  8f9390e4c7b981e355aed3c5690e17c2e13bb263246a55d8039813cac670c2f1
    01  0000000000000000
    00
    26  6a24aa21a9ed2127440070600b5e8482e5df5815cc15b8262acf7533136c501f3cb4801faaf6

    00000000 locktime

    # for each vin - CTxInWitness
    00  issuance amount range proof
    00  inflation range proof
    01  num of script witnesses
    20 0000000000000000000000000000000000000000000000000000000000000000 script witness
    00  num of pegin witnesses

    # for each vout - CTxOutWitness
    00  surjection proof
    00  range proof
    00  surjection proof
    00  range proof
    '''
    def read_tx(self):
        return self._read_tx_parts()[0]

    def read_tx_and_hash(self):
        tx, tx_hash, vsize = self._read_tx_parts()
        return tx, tx_hash

    def read_tx_and_vsize(self):
        tx, tx_hash, vsize = self._read_tx_parts()
        return tx, vsize

    def _read_tx_parts(self):
        assert isinstance(self.binary, bytes)
        '''Return a (deserialized TX, tx_hash, vsize) tuple.'''
        start = self.cursor
        version = self._read_le_int32()
        orig_ser = self.binary[start:self.cursor]

        flag = int(self._read_byte())    # for witness

        orig_ser += flag.to_bytes(1, byteorder='little')
        
        start = self.cursor
        inputs = self._read_inputs()
        outputs = self._read_outputs()
        lockTime = int(self._read_le_uint32())

        orig_ser += self.binary[start:self.cursor]

        start = self.cursor
        witness_in = []
        witness_out = []
        if flag & 1:
            witness_in = self._read_witness_in(len(inputs))
            witness_out = self._read_witness_out(len(outputs))
            flag ^= 1

        base_size = len(orig_ser)
        full_size = base_size + len(self.binary[start:self.cursor])
        vsize = ((self.WITNESS_SCALE_FACTOR-1) * base_size + full_size + self.WITNESS_SCALE_FACTOR - 1) // self.WITNESS_SCALE_FACTOR

        return TxOcean(version, flag, inputs, outputs, witness_in, witness_out,
                        lockTime), double_sha256(orig_ser), vsize

    def _read_input(self):
        '''Return a TxInputOcean object'''
        prev_hash = self._read_nbytes(32)
        prev_idx = self._read_le_uint32()
        script = self._read_varbytes()
        sequence = self._read_le_uint32()

        issuance = None
        if prev_idx != TxInputOcean.MINUS_1:
            if prev_idx & TxInputOcean.OUTPOINT_ISSUANCE_FLAG:
                issuance_nonce = self._read_nbytes(32)
                issuance_entropy = self._read_nbytes(32)

                amount = self._read_confidential_value()
                inflation = self._read_confidential_value()

                issuance = TxInputIssuanceOcean(
                    issuance_nonce,
                    issuance_entropy,
                    amount,
                    inflation
                )
            prev_idx &= TxInputOcean.OUTPOINT_INDEX_MASK

        inp = TxInputOcean(
            prev_hash,
            prev_idx,
            script,
            sequence,
            issuance
        )

        return inp
            

    def _read_output(self):
        '''Return a TxOutputOcean object'''
        asset = self._read_confidential_asset()
        value = self._read_confidential_value()
        nonce = self._read_confidential_nonce()
        script = self._read_varbytes()

        return TxOutputOcean(
            asset,
            value,
            nonce,
            script
        )

    # CConfidentialValue size 9, prefixA 8, prefixB 9
    def _read_confidential_value(self):
        version = self._read_byte()
        if version == 1 or version == 0xff:
            return bytes([version]) + self._read_nbytes(TxOcean.CONFIDENTIAL_VALUE-1)
        elif version == 8 or version == 9:
            return bytes([version]) + self._read_nbytes(TxOcean.CONFIDENTIAL_COMMITMENT-1)
        return bytes([version])

    # CConfidentialAsset size 33, prefixA 10, prefixB 11
    def _read_confidential_asset(self):
        version = self._read_byte()
        if version == 1 or version == 0xff:
            return bytes([version]) + self._read_nbytes(TxOcean.CONFIDENTIAL_COMMITMENT-1)
        elif version == 10 or version == 11:
            return bytes([version]) + self._read_nbytes(TxOcean.CONFIDENTIAL_COMMITMENT-1)
        return bytes([version])

    # CConfidentialNonce size 33, prefixA 2, prefixB 3
    def _read_confidential_nonce(self):
        version = self._read_byte()
        if version == 1 or version == 0xff:
            return bytes([version]) + self._read_nbytes(TxOcean.CONFIDENTIAL_COMMITMENT-1)
        elif version == 2 or version == 3:
            return bytes([version]) + self._read_nbytes(TxOcean.CONFIDENTIAL_COMMITMENT-1)
        return bytes([version])

    def _read_witness_in(self, fields):
        read_witness_in_field = self._read_witness_in_field
        return [read_witness_in_field() for i in range(fields)]

    def _read_witness_in_field(self):
        read_varbytes = self._read_varbytes
        issuance_range_proof = read_varbytes()
        inflation_range_proof = read_varbytes()
        script_witness = [read_varbytes() for i in range(self._read_varint())]
        pegin_witness = [read_varbytes() for i in range(self._read_varint())]

        return [issuance_range_proof, inflation_range_proof, script_witness, pegin_witness]

    def _read_witness_out(self, fields):
        read_witness_out_field = self._read_witness_out_field
        return [read_witness_out_field() for i in range(fields)]

    def _read_witness_out_field(self):
        read_varbytes = self._read_varbytes
        surjection_proof = read_varbytes()
        range_proof = read_varbytes()

        return [surjection_proof, range_proof]

class TxOcean():
    def __init__(self, version=None, flag=None, inputs=[], outputs=[], 
                 inwitness=None, outwitness=None, lockTime=None):
        self.name="TxOcean"
        self.version=version
        self.flag=flag 
        self.inputs=inputs 
        self.outputs=outputs 
        self.lockTime=lockTime
        self.inwitness=inwitness
        self.outwitness=outwitness

    '''Class representing an Ocean transaction.'''
    CONFIDENTIAL_COMMITMENT = 33    # default size of confidential commitments (i.e. asset, value, nonce)
    CONFIDENTIAL_VALUE = 9          # explciti size of confidential values

    @cachedproperty
    def is_coinbase(self):
        if len(inputs) is 0 or len(outputs) is 0:
             return False
        return (self.inputs[0].is_coinbase or
                self.inputs[0].is_initial_issuance)

class oceanTransaction(TxOcean):
        def __init__(self, binary=None, orig=None, start=0):
                #Initialize either with a TxOcean object, or deserialize from bytes
                if orig is None:
                        self._non_copy_constructor(binary, start)
                else:
                        self._copy_constructor(orig)
                        
        def _copy_constructor(self, orig):
                self.version = orig.version
                self.flag = orig.flag
                self.lockTime = orig.lockTime
                self.inwitness = orig.inwitness
                self.outwitness = orig.outwitness
                self.inputs=[]
                for inpt in orig.inputs:
                        self.inputs.append(oceanInput(inpt))
                self.outputs=[]
                for outpt in orig.outputs:
                        self.outputs.append(oceanOutput(outpt))


        def _non_copy_constructor(self, binary, start):
                assert binary is not None
                self._copy_constructor(DeserializerOcean(binary, start).read_tx())

        @classmethod
        def serialize_outpoint(self, txin):
            if txin.prev_idx == TxInputOcean.MINUS_1:
                return bh2u(txin.prev_hash) + int_to_hex(txin.prev_idx, 4)
            else:
                prevout = txin.prev_idx & TxInputOcean.OUTPOINT_INDEX_MASK
                if txin.is_issuance:
                    prevout |= TxInputOcean.OUTPOINT_ISSUANCE_FLAG
            result = bh2u(txin.prev_hash) + int_to_hex(prevout, 4)
            return result


        def serialize(self, skipOutputLockTime=False, skipWitness=False):
                if skipWitness or (not self.inwitness and not self.outwitness):
                        useWitness = False
                else:
                        useWitness = True
                result = []
                result.extend(self.version)
                result.extend(self.flag)
                writeVarint(len(self.inputs), result)
                for trinput in self.inputs:
                        result.extend(trinput.serialize())
                if not skipOutputLockTime:
                        writeVarint(len(self.outputs), result)
                        for troutput in self.outputs:
                                result.extend(troutput.serialize())
                        result.extend(self.lockTime)
                        if useWitness:
                                result.extend(self.inwitness)
                                result.extend(self.outwitness)
                return result

            
        def serializeOutputs(self):
            result = []
            writeVarint(len(self.outputs), result)
            for troutput in self.outputs:
                result.extend(troutput.serialize())
            return result

        def serializeOutput(self, index):
            result = []
            if(index < len(self.outputs)):
                writeVarint(1, result)
                result.extend(self.outputs[index].serialize())
            else:
                return None
            return result

class TxInputIssuanceOcean():
    def __init__(self,issuance_nonce=None, issuance_entropy=None,
                 amount=None, inflation=None):
        self.issuance_nonce=issuance_nonce
        self.issuance_entropy=issuance_entropy
        self.amount=amount
        self.inflation=inflation

    def serialize(self):
        result = []
        result.extend(self.issuance_nonce)
        result.extend(self.issuance_entropy)
        result.extend(self.amount)
        result.extend(self.inflation)
        return result

    def __str__(self):
        buf = "Issuance nonce: {}".format(self.issuance_nonce.hex()) + "\r\n"
        buf += "Issuance entropy: {}".format(self.issuance_entropy.hex()) + "\r\n"
        buf += "Issuance amount: {}".format(self.amount.hex()) + "\r\n"
        buf += "Issuance inflation: {}".format(self.inflation.hex()) + "\r\n"
        return buf
        
class TxInputOcean():
    '''Class representing a transaction input.'''
    ZERO = bytes(32)
    MINUS_1 = 4294967295
    OUTPOINT_ISSUANCE_FLAG = (1 << 31)
    OUTPOINT_INDEX_MASK = 0x3fffffff

    def __init__(self,prev_hash=None, prev_idx=None, script=None, 
        sequence=None, issuance=None):
        self.name="TxInputOcean"
        self.prev_hash=prev_hash 
        self.prev_idx=prev_idx 
        self.script=script 
        self.sequence=sequence 
        self.issuance=issuance


    @cachedproperty
    def is_coinbase(self):
        return (self.prev_hash == TxInputOcean.ZERO and
                self.prev_idx == TxInputOcean.MINUS_1)

    ''' MAYBE not the best way of doing this
    Initial issuance should not have a prev_hash but in ocean this is set to
    a dummy commitment to the genesis arguments to be replaced by an actual
    pegin bitcoin hash. Possible solution would be to hardcode prev_hash
    Same treatment with coinbase transactions
    '''
    @cachedproperty
    def is_initial_issuance(self):
        return (self.is_issuance and
                self.sequence == TxInputOcean.MINUS_1)

    @cachedproperty
    def is_issuance(self):
        return (self.issuance is not None)

    def __str__(self):
        script = self.script.hex()
        prev_hash = self.prev_hash.hex()
        return ("Input({}, {:d}, script={}, sequence={:d})"
                .format(prev_hash, self.prev_idx, script, self.sequence))

class TxOutputOcean():
    def __init__(self, asset, value, nonce, script):
        self.name="TxOutputOcean"
        self.asset=asset 
        self.value=value 
        self.nonce=nonce 
        self.script=script


class oceanInput(TxInputOcean):
    def __init__(self, orig=None):
        if orig is None:
            self._non_copy_constructor()
        else:
            self._copy_constructor(orig)

    def _non_copy_constructor(self):
        self.prev_hash = None
        self.prev_idx = None
        self.script = None
        self.sequence = None
        self.issuance = None

    def _copy_constructor(self, orig):
        self.prev_hash = orig.prev_hash
        self.prev_idx = orig.prev_idx
        self.script = orig.script
        self.sequence = orig.sequence
        self.issuance = orig.issuance

    def getScriptLength(self):
        return len(self.script)

    def serialize(self):
        result = []
        #prevout_hash + prevout_n
        result.extend(oceanTransaction.serialize_outpoint(self.prev_idx))
        writeVarint(self.getScriptLength(), result)
        result.extend(self.script)
        result.extend(self.sequence)
        if self.issuance is not None:
            result.extend(self.issuance.serialize())
        return result

    def __str__(self):
        buf =  "PrevHash : {}".format(self.prev_hash.hex()) + "\r\n"
        buf =  "PrevIdx : {}".format(self.prev_idx) + "\r\n"
        buf += "Script : {}".format(self.script.hex()) + "\r\n"
        buf += "Sequence : {}".format(self.sequence) + "\r\n"
        if self.is_issuance:
            buf += "Issuance : {}".format(self.issuance) + "\r\n"
        return buf



class oceanOutput(TxOutputOcean):
        def __init__(self, orig=None):
                if orig is None:
                        self._non_copy_constructor()
                else:
                        self._copy_constructor(orig)

        def _non_copy_constructor(self):
                self.asset = None
                self.value = None
                self.nonce = None
                self.script = None

        def _copy_constructor(self, orig):
                self.asset = orig.asset
                self.value = orig.value
                self.nonce = orig.nonce
                self.script = orig.script
                
        def getScriptLength(self):
                return len(self.script)

        def serialize(self):
                result = []
                result.extend(self.asset)
                result.extend(self.value)        
                result.extend(self.nonce)
                writeVarint(self.getScriptLength(), result)
                result.extend(self.script)
                return result

        def __str__(self):
                buf =  "Asset : " + hexlify(self.asset) + "\r\n"
                buf += "Amount : " + hexlify(self.amount) + "\r\n"
                buf += "Nonce : " + hexlify(self.nonce) + "\r\n"
                buf += "Script : " + hexlify(self.script) + "\r\n"
                return buf
