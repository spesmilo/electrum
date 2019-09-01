from .. import bitcoin
from .. import address  # for ScriptOutput, OpCodes, ScriptError, Script
from .. import caches
from .. import util
from ..transaction import Transaction
from typing import List, Tuple, Set

from .exceptions import *

lokad_id = b"SLP\x00"  # aka protocol code (prefix) -- this appears after the 'OP_RETURN + OP_PUSH(4)' bytes in the ScriptOutput for *ALL* SLP scripts
valid_token_types = frozenset((1, 65, 129))  # any token types not in this set will be rejected

def _i2b(val): return bytes((val,))

class ScriptOutput(address.ScriptOutput):
    ''' Encapsulates a parsed, valid SLP OP_RETURN output script.

    NB: hash(self) just calls superclass hash -- which hashes the script bytes..
    the .message object is ignored from the hash (it is always derived
    from the script bytes anyway in a well formed instance).

    self.message should *NOT* be written-to by outside code! It should
    remain immutable after instance construction. While not enforced, it is
    a required invariant of this class. '''

    _protocol_prefix = _i2b(address.OpCodes.OP_RETURN) + _i2b(4) + lokad_id

    attrs_extra = ('message',)

    # Optimization. In a normal call path cls.protocol_match parses a message and
    # returns a bool.  We save the parsed message in this cache because __new__
    # will be called very soon after on a True return to re-parse the Script,
    # due to the way the protocol_match system works in Electron Cash.
    _script_message_cache = caches.ExpiringCache(maxlen=25, name="SLP Script Message Cache", timeout=60.0)

    def __new__(cls, script):
        '''Instantiate from a script (or address.ScriptOutput) you wish to parse.'''
        script = script if isinstance(script, (bytes, bytearray)) else script.to_script()
        script = bytes(script) if isinstance(script, bytearray) else script
        self = super(__class__, cls).__new__(cls, script)
        self.message = cls._script_message_cache.get(self.script)  # will return a valid object or None
        if self.message is None:
            self.message = Message.parse(self)  # raises on parse error
        return self

    @classmethod
    def protocol_match(cls, script_bytes: bytes) -> bool:
        ''' Returns True if the passed-in bytes are a valid OP_RETURN script
        for SLP. '''
        # fast test -- most ScriptOutputs that aren't SLP will fail here quickly
        if not script_bytes.startswith(cls._protocol_prefix):
            return False
        # fast test passed -- next try the slow test -- attempt to parse and
        # validate OP_RETURN message
        try:
            slf = cls(script_bytes)  # raises on parse error
            if slf.message is not None:  # should always be not None
                cls._script_message_cache.put(slf.script, slf.message)  # save parsed message since likely it will be needed again very soon by class c'tor
                return True
        except Error:
            pass
        except Exception:
            # DEBUG XXX FIXME
            import traceback, sys
            traceback.print_exc(file=sys.stderr)
            pass
        return False
# /ScriptOutput

address.ScriptOutput.protocol_classes.add(ScriptOutput)  # register class with Electron Cash script 'protocol factory' system

class Message:
    ''' This class represents a parsed and valid SLP OP_RETURN message that can
    be used by the validator to examine SLP messages.

    If this class was successfully constructed, then the message is valid
    with valid properties.

    This class raises an Exception subclass if parsing fails and should not
    normally be constructible for invalid SLP OP_RETURN messages.

    The .chunks attribute is a tuple of bytes which are the various OP_RETURN
    fields in an SLP message. .chunks[0] lokad_id prefix, .chunks[1] is the
    token_type, etc.

    However: This class is intended to be accessed via its @property accessors!

    Accesses are parsed upon access and may raise various Exceptions
    if the OP_RETURN message and/or chunks are malformed.  (No real validation
    is done unpon access, for performance).

    However valid instances of Message appearing at Runtime are all valid
    due to the guarded __init__ which validates the chunks and raises upon
    parse errors.'''

    __slots__ = ('chunks',)   # Tuple[bytes]


    # -- FACTORY METHOD(s) and CONSTRUCTOR --
    def __init__(self, chunks: object):
        ''' `chunks` is expected to be a Tuple of parsed chunks *or* a bytes
        *or* ScriptOutput object.

        Iff bytes object and/or a ScriptOutput base, `chunks` will get parsed
        to chunks and then the message will be validated as normal.

        Will raise on bad SLP OP_RETURN script.'''
        if isinstance(chunks, (bytearray, bytes, address.ScriptOutput)):
            script = chunks
            try:
                script = script if isinstance(script, (bytes, bytearray)) else script.to_script()
                chunks = self._parseOpreturnToChunks(script, allow_op_0 = False, allow_op_number = False)
            except OpreturnError as e:
                raise InvalidOutputMessage('Bad OP_RETURN', *e.args) from e
        if isinstance(chunks, list):
            chunks = tuple(chunks)
        if any(not isinstance(b, bytes) for b in chunks):
            # ensure bytes and not bytearray
            chunks = tuple(bytes(b) for b in chunks)
        self.chunks = chunks
        if not self._is_valid_or_raise():
            raise RuntimeError("FIXME -- Should not be reached")

    @classmethod
    def parse(cls, script : object) -> object:
        ''' This method attempts to parse a ScriptOutput or bytes object as an
            SLP message.

            Parameter `script`: may be a ScriptOutput base or a bytes object.

            Bad scripts will throw a subclass of Error; any other exception indicates a bug in this code.
            - Unrecognized SLP versions will throw UnsupportedSlpTokenType.
            - It is a STRICT parser -- consensus-invalid messages will throw InvalidOutputMessage.
            - Non-SLP scripts will also throw InvalidOutputMessage.

            returns a valid Message object on success.
            '''
        return cls(script)  # implicitly calls _is_valid_or_raise

    # -- /FACTORY METHOD(s) & C'TOR --

    def __len__(self):
        return len(self.chunks) if self.chunks is not None else 0

    def __hash__(self):
        return hash(self.chunks)

    @property
    def valid_properties(self) -> Tuple[str]:
        ''' Returns the expected valid properties for this instance
        based on self.transaction_type. Raises Error if unknown
        transaction_type. '''
        tt = self.transaction_type
        if tt == 'GENESIS':
            return ('token_type', 'transaction_type', 'lokad_id', 'nft_flag',
                    'ticker', 'token_name', 'token_doc_url', 'token_doc_hash',
                    'decimals', 'mint_baton_vout', 'initial_token_mint_quantity',)
        elif tt == 'MINT':
            return ('token_type', 'transaction_type', 'lokad_id', 'nft_flag',
                    'token_id', 'token_id_hex', 'mint_baton_vout',
                    'additional_token_quantity')
        elif tt == 'SEND':
            return ('token_type', 'transaction_type', 'lokad_id', 'nft_flag',
                    'token_id', 'token_id_hex', 'token_output', )
        elif tt == 'COMMIT':
            return ('token_type', 'transaction_type', 'lokad_id', 'nft_flag',
                    'info',)
        raise InvalidOutputMessage("Unknown transaction_type", tt)

    def __repr__(self):
        d = {}
        def read(keys):
            for k in keys:
                if k.startswith('_') or k == 'chunks':
                    continue
                try:
                    v = getattr(self, k, None)
                except:
                    continue
                if v is not None and not callable(v):
                    d[k] = v
        try:
            read(self.valid_properties)
        except InvalidOutputMessage:
            read(dir(self))
        return "<{name} object at 0x{loc:0x} fields: {fields}>".format(
            name = type(self).__qualname__,
            loc = id(self),
            fields = ", ".join([f"{k}={v}" for k,v in d.items()])
        )


    # PROPERTIES -- returns values derived from parsing the bytes in self.chunks
    # Note: ALL properties below are only valid if self.chunks is valid and not
    # None!  Not all properties are 'valid' in all contexts: some depend on
    # transaction_type!  No validation is done in the property methods
    # themselves thus they may raise various Exceptions.
    @property
    def lokad_id(self) -> bytes:
        return self.chunks[0]
    @property
    def token_type(self) -> int:
        ''' Returns the SLP token type: one of: 1, 65, 129 '''
        return self._parseChunkToInt(self.chunks[1], 1, 2, True)
    @property
    def transaction_type(self) -> str:
        ''' Returns the transaction type string (chunks[2] as decoded string),
        may rause UnicodeError and/or other Exceptions.

        Will be one of "GENESIS" "SEND" "MINT" "COMMIT"
        '''
        return self.chunks[2].decode('ascii')
    @property
    def nft_flag(self) -> str:
        ''' Returns one of "NFT_PARENT", "NFT_CHILD", or None if non-NFT. '''
        t_type = self.token_type
        if t_type == 65:
            return "NFT_CHILD"
        elif t_type == 129:
            return "NFT_PARENT"
        else:
            return None
    # -- GENESIS PROPERTIES
    @property
    def ticker(self) -> bytes:
        return self.chunks[3]
    @property
    def token_name(self) -> bytes:
        return self.chunks[4]
    @property
    def token_doc_url(self) -> bytes:
        return self.chunks[5]
    @property
    def token_doc_hash(self) -> bytes:
        return self.chunks[6]
    @property
    def decimals(self) -> int:
        ''' decimals -- one byte in range 0-9 -> int '''
        return self._parseChunkToInt(self.chunks[7], 1, 1, True)
    @property
    def mint_baton_vout(self) -> int:
        ''' May return None. Valid for MINT and GENESIS. '''
        if self.transaction_type == 'GENESIS':
            return self._parseChunkToInt(self.chunks[8], 1, 1)
        else:
            # presumably MINT
            return self._parseChunkToInt(self.chunks[4], 1, 1)
    @property
    def initial_token_mint_quantity(self) -> int:
        return self._parseChunkToInt(self.chunks[9], 8, 8, True)
    # -- SEND properties
    @property
    def token_id(self) -> bytes:  # this is *ALSO* a MINT property
        return self.chunks[3]
    @property
    def token_id_hex(self) -> str:  # this is *ALSO* a MINT property
        ''' Returns the self.token_id bytes as a hex-encoded string. '''
        return self.token_id.hex()
    @property
    def token_output(self) -> Tuple[int]:  # ret[0] is always 0
        ''' Returns the token output as a list of ints.
            Note that we put an explicit 0 for self.token_output[0] since it
            corresponds to vout=0, which is the OP_RETURN tx output.
            token_output[1] is the first token output given by the SLP
            message, i.e., the number listed as `token_output_quantity1` in the
            spec, which goes to tx output vout=1.'''
        return (0,) + tuple( self._parseChunkToInt(field, 8, 8, True)
                             for field in self.chunks[4:] )
    # -- MINT properties
    # NOTE:
    # - token_id is also a MINT property here (as well as a SEND property)
    # - token_id_hex is also MINT property here (as well as a SEND property)
    # - mint_baton_vout is also MINT propety here (as well as a GENESIS property)
    @property
    def additional_token_quantity(self) -> int:
        return self._parseChunkToInt(self.chunks[5], 8, 8, True)
    # -- COMMIT properties
    @property
    def info(self) -> str:
        ''' Not really implemented. Returns the same thing each time. '''
        return r'slp.py not parsing yet ¯\_(ツ)_/¯'
    # /End PROPERTIES

    # --- HELPERS ---
    @staticmethod
    def _parseChunkToInt(intBytes: bytes, minByteLen: int, maxByteLen: int, raise_on_Null: bool = False):
        # Parse data as unsigned-big-endian encoded integer.
        # For empty data different possibilities may occur:
        #      minByteLen <= 0 : return 0
        #      raise_on_Null == False and minByteLen > 0: return None
        #      raise_on_Null == True and minByteLen > 0:  raise InvalidOutputMessage
        if len(intBytes) >= minByteLen and len(intBytes) <= maxByteLen:
            return int.from_bytes(intBytes, 'big', signed=False)
        if len(intBytes) == 0 and not raise_on_Null:
            return None
        raise InvalidOutputMessage('Field has wrong length')

    @staticmethod
    def _parseOpreturnToChunks(script: bytes, *,  allow_op_0: bool, allow_op_number: bool) -> List[bytes]:
        """Extract pushed bytes after opreturn. Returns list of bytes() objects,
        one per push.

        Strict refusal of non-push opcodes; bad scripts throw OpreturnError."""
        try:
            ops = address.Script.get_ops(script)
        except address.ScriptError as e:
            raise OpreturnError('Script error') from e

        if ops[0][0] != address.OpCodes.OP_RETURN:
            raise OpreturnError('No OP_RETURN')

        chunks = []
        for opitem in ops[1:]:
            op, data = opitem if isinstance(opitem, tuple) else (opitem, None)
            if op > address.OpCodes.OP_16:
                raise OpreturnError('Non-push opcode')
            if op > address.OpCodes.OP_PUSHDATA4:
                if op == 80:
                    raise OpreturnError('Non-push opcode')
                if not allow_op_number:
                    raise OpreturnError('OP_1NEGATE to OP_16 not allowed')
                if op == address.OpCodes.OP_1NEGATE:
                    data = [0x81]
                else: # OP_1 - OP_16
                    data = [op-80]
            if op == address.OpCodes.OP_0 and not allow_op_0:
                raise OpreturnError('OP_0 not allowed')
            chunks.append(b'' if data is None else bytes(data))
        return chunks
    # --- /HELPERS

    def _is_valid_or_raise(self) -> bool:
        ''' Checks if chunks is a valid SLP OP_RETURN message.

        Returns True or raises if not valid. '''
        if not self.chunks:
            raise InvalidOutputMessage('Empty OP_RETURN')

        if self.lokad_id != lokad_id:
            raise InvalidOutputMessage('Not SLP')

        if len(self) <= 1:
            raise InvalidOutputMessage('Missing token_type')

        # check if the token version is supported
        # 1   = type 1
        # 65  = type 1 as NFT child
        # 129 = type 1 as NFT parent
        token_type = self.token_type
        if token_type not in valid_token_types:
            raise UnsupportedSlpTokenType(token_type)

        if len(self) <= 2:
            raise InvalidOutputMessage('Missing SLP command')

        # (the following logic is all for version 1)
        try:
            transaction_type = self.transaction_type
        except UnicodeDecodeError:
            # This can occur if non-ascii bytes present (byte > 127)
            raise InvalidOutputMessage('Bad transaction type')

        # switch statement to handle different on transaction type
        if transaction_type == 'GENESIS':
            if len(self) != 10:
                raise InvalidOutputMessage('GENESIS with incorrect number of parameters')
            # keep ticker, token name, document url, document hash as bytes
            # (their textual encoding is not relevant for SLP consensus)
            # but do enforce consensus length limits
            dummy = self.ticker  # ensure this parses
            dummy = self.token_name  # ensure parses
            dummy = self.token_doc_url  # ensure parses
            if len(self.token_doc_hash) not in (0, 32):
                raise InvalidOutputMessage('Token document hash is incorrect length')

            # decimals -- one byte in range 0-9
            if self.decimals > 9:
                raise InvalidOutputMessage('Too many decimals')

            ## handle baton for additional minting, but may be empty
            v = self.mint_baton_vout
            if v is not None and v < 2:
                raise InvalidOutputMessage('Mint baton cannot be on vout=0 or 1')
            elif v is not None and self.nft_flag == 'NFT_CHILD':
                raise InvalidOutputMessage('Cannot have a minting baton in a NFT_CHILD token.')

            # handle initial token quantity issuance
            dummy = self.initial_token_mint_quantity  # ensure parses
        elif transaction_type == 'SEND':
            if len(self) < 4:
                raise InvalidOutputMessage('SEND with too few parameters')
            if len(self.token_id) != 32:
                raise InvalidOutputMessage('token_id is wrong length')
            #dummy = chunks.token_id_hex  # ensure parses

            # Note that we put an explicit 0 for token_output[0] since it
            # corresponds to vout=0, which is the OP_RETURN tx output.
            # token_output[1] is the first token output given by the SLP
            # message, i.e., the number listed as `token_output_quantity1` in the
            # spec, which goes to tx output vout=1.
            token_output = self.token_output  # ensure parses
            # maximum 19 allowed token outputs, plus 1 for the explicit [0] we inserted.
            if len(token_output) < 2:
                raise InvalidOutputMessage('Missing output amounts')
            if len(token_output) > 20:
                raise InvalidOutputMessage('More than 19 output amounts')
        elif transaction_type == 'MINT':
            if self.nft_flag == 'NFT_CHILD':
                raise InvalidOutputMessage('Cannot have MINT with NFT_CHILD')
            if len(self) != 6:
                raise InvalidOutputMessage('MINT with incorrect number of parameters')
            if len(self.token_id) != 32:
                raise InvalidOutputMessage('token_id is wrong length')
            #dummy = chunks.token_id_hex  # ensure parse
            v = self.mint_baton_vout
            if v is not None and v < 2:
                raise InvalidOutputMessage('Mint baton cannot be on vout=0 or 1')
            dummy = self.additional_token_quantity  # ensure parse
        elif transaction_type == 'COMMIT':
            # We don't know how to handle this right now, just return slpMsg of 'COMMIT' type
            dummy = self.info  # ensure parse
        else:
            raise InvalidOutputMessage('Bad transaction type')
        return True

#/Message

class Build:
    ''' Namespace of all static methods involved in SLP OP_RETURN message
    building.

    SLP message creation functions below.
    Various exceptions can occur:
       SerializingError / subclass if bad values.
       UnicodeDecodeError if strings are weird (in GENESIS only).
    '''

    @staticmethod
    def pushChunk(chunk: bytes) -> bytes: # allow_op_0 = False, allow_op_number = False
        '''utility for creation: use smallest push except not any of: op_0, op_1negate, op_1 to op_16'''
        length = len(chunk)
        if length == 0:
            return b'\x4c\x00' + chunk
        elif length < 76:
            return bytes((length,)) + chunk
        elif length < 256:
            return bytes((0x4c,length,)) + chunk
        elif length < 65536: # shouldn't happen but eh
            return b'\x4d' + length.to_bytes(2, 'little') + chunk
        elif length < 4294967296: # shouldn't happen but eh
            return b'\x4e' + length.to_bytes(4, 'little') + chunk
        else:
            raise ValueError()

    @staticmethod
    def chunksToOpreturnOutput(chunks: List[bytes]) -> tuple:
        ''' utility for creation '''
        script = bytearray((address.OpCodes.OP_RETURN,)) # start with OP_RETURN
        for c in chunks:
            script.extend(Build.pushChunk(c))

        if len(script) > 223:
            raise OPReturnTooLarge('OP_RETURN message too large, cannot be larger than 223 bytes')

        # Note 'ScriptOutput' is our subclass in this file, not address.py ScriptOutput!
        return (bitcoin.TYPE_SCRIPT, ScriptOutput(bytes(script)), 0)

    @staticmethod
    def GenesisOpReturnOutput_V1(ticker: str, token_name: str, token_document_url: str, token_document_hash_hex: str, decimals: int, baton_vout: int, initial_token_mint_quantity: int, token_type: int = 1) -> tuple:
        ''' Type 1 Token GENESIS Message '''
        chunks = []

        # lokad id
        chunks.append(lokad_id)

        # token version/type
        if token_type in (1, 'SLP1'):
            chunks.append(b'\x01')
        elif token_type in (65, 'SLP65'):
            chunks.append(b'\x41')
        elif token_type in (129, 'SLP129'):
            chunks.append(b'\x81')
        else:
            raise Error('Unsupported token type')

        # transaction type
        chunks.append(b'GENESIS')

        # ticker (can be None)
        if not ticker:
            tickerb = b''
        else:
            tickerb = ticker.encode('utf-8')
        chunks.append(tickerb)

        # name (can be None)
        if not token_name:
            chunks.append(b'')
        else:
            chunks.append(token_name.encode('utf-8'))

        # doc_url (can be None)
        if not token_document_url:
            chunks.append(b'')
        else:
            chunks.append(token_document_url.encode('ascii'))

        # doc_hash (can be None)
        if not token_document_hash_hex:
            chunks.append(b'')
        else:
            dochash = bytes.fromhex(token_document_hash_hex)
            if len(dochash) not in (0, 32):
                raise SerializingError()
            chunks.append(dochash)

        # decimals
        decimals = int(decimals)
        if decimals > 9 or decimals < 0:
            raise SerializingError()
        chunks.append(bytes((decimals,)))

        # baton vout
        if baton_vout is None:
            chunks.append(b'')
        else:
            if baton_vout < 2:
                raise SerializingError()
            chunks.append(bytes((baton_vout,)))

        # init quantity
        qb = int(initial_token_mint_quantity).to_bytes(8,'big')
        chunks.append(qb)

        return Build.chunksToOpreturnOutput(chunks)

    @staticmethod
    def MintOpReturnOutput_V1(token_id_hex: str, baton_vout: int, token_mint_quantity: int, token_type: int = 1) -> tuple:
        ''' Type 1 Token MINT Message '''
        chunks = []

        # lokad id
        chunks.append(lokad_id)

        # token version/type
        if token_type in (1, 'SLP1'):
            chunks.append(b'\x01')
        elif token_type in (129, 'SLP129'):
            chunks.append(b'\x81')
        else:
            raise Error('Unsupported token type')

        # transaction type
        chunks.append(b'MINT')

        # token id
        tokenId = bytes.fromhex(token_id_hex)
        if len(tokenId) != 32:
            raise SerializingError()
        chunks.append(tokenId)

        # baton vout
        if baton_vout is None:
            chunks.append(b'')
        else:
            if baton_vout < 2:
                raise SerializingError()
            chunks.append(bytes((baton_vout,)))

        # init quantity
        qb = int(token_mint_quantity).to_bytes(8,'big')
        chunks.append(qb)

        return Build.chunksToOpreturnOutput(chunks)

    @staticmethod
    def SendOpReturnOutput_V1(token_id_hex: str, output_qty_array: [int], token_type: int = 1) -> tuple:
        ''' Type 1 Token SEND Message '''
        chunks = []

        # lokad id
        chunks.append(lokad_id)

        # token version/type
        if token_type in (1, 'SLP1'):
            chunks.append(b'\x01')
        elif token_type in (65, 'SLP65'):
            chunks.append(b'\x41')
        elif token_type in (129, 'SLP129'):
            chunks.append(b'\x81')
        else:
            raise Error('Unsupported token type')

        # transaction type
        chunks.append(b'SEND')

        # token id
        tokenId = bytes.fromhex(token_id_hex)
        if len(tokenId) != 32:
            raise SerializingError()
        chunks.append(tokenId)

        # output quantities
        if len(output_qty_array) < 1:
            raise SerializingError("Cannot have less than 1 SLP Token output.")
        if len(output_qty_array) > 19:
            raise SerializingError("Cannot have more than 19 SLP Token outputs.")
        for qty in output_qty_array:
            qb = int(qty).to_bytes(8,'big')
            chunks.append(qb)

        return Build.chunksToOpreturnOutput(chunks)

#------------------------------------------------------------------------------
#| WALLET DATA STRUCTURES                                                     |
#------------------------------------------------------------------------------
class WalletData(util.PrintError):
    ''' This lives in wallet instances as the .slp attribute

    This data layout is provisional for now. We will redo it to contain
    more information once we add validation.  See the .clear() method
    which describes each data item. '''

    DATA_VERSION = 0.1  # used by load/save for data storage versioning

    def __init__(self, wallet):
        assert wallet
        self.wallet = wallet
        self.clear()

    def diagnostic_name(self):
        return self.wallet.diagnostic_name() + ".SLP"

    def load(self) -> bool:
        ''' This takes no locks. If calling in multithreaded environment,
        guard with locks. (Currently this is only called in wallet.py setup
        code so locking is not relevant). '''
        data = self.wallet.storage.get('slp')
        try:
            assert isinstance(data, dict), "missing or invalid 'slp' dictionary"
            ver = data['version']
            assert ver == self.DATA_VERSION, f"incompatible or missing slp data version '{ver}', expected '{self.DATA_VERSION}'"
            # dict of txid -> int
            self.validity = {k.lower():int(v) for k,v in data['validity'].items()}
            # dict of "token_id_hex" -> dict of ["txo_name"] -> qty (int)
            self.token_quantities = {k.lower() : { vv0.lower() : int(vv1) for vv0,vv1 in v} for k,v in data['token_quantities'].items()}
            # build the mapping of prevouthash:n (str) -> token_id_hex (str) from self.token_quantities
            self.txo_token_id = dict()
            for token_id_hex, txo_dict in self.token_quantities.items():
                for txo in txo_dict:
                    self.txo_token_id[txo] = token_id_hex
            # dict of Address -> set of txo_name
            self.txo_byaddr = {address.Address.from_string(k) : {vv.lower() for vv in v} for k,v in data['txo_byaddr'].items()}
            self.need_rebuild = False
        except (ValueError, TypeError, AttributeError, address.AddressError, AssertionError, KeyError) as e:
            # Note: We want TypeError/AttributeError/KeyError raised above on
            # missing keys since that indicates data inconsistency, hence why
            # the lookups above do not use .get() (thus ensuring the above
            # should raise on incorrect or missing data).
            self.print_error("Error loading slp data; will flag for rebuild:", repr(e))
            self.clear()
            self.need_rebuild = True
        return not self.need_rebuild

    def save(self):
        '''Caller should hold locks'''
        self.wallet.storage.put('slp_data_version', None)  # clear key of other older formats.
        data = {
            'validity' : self.validity,
            'token_quantities' : {k:list([v0,v1] for v0,v1 in v.items()) for k,v in self.token_quantities.items()},
            'txo_byaddr' : { k.to_storage_string() : list(v) for k,v in self.txo_byaddr.items() },
            'version' : self.DATA_VERSION,
        }
        self.wallet.storage.put('slp', data)

    def clear(self):
        '''Caller should hold locks'''
        self.need_rebuild = False
        self.validity = dict()  # txid -> int
        self.txo_byaddr = dict()  # [address] -> set of "prevouthash:n" for that address
        self.token_quantities = dict() # [token_id_hex] -> dict of ["prevouthash:n"] -> qty (-1 for qty indicates minting baton)
        self.txo_token_id = dict() # ["prevouthash:n"] -> "token_id_hex"

    def rebuild(self):
        '''This takes wallet.lock'''
        with self.wallet.lock:
            self.clear()
            for txid, tx in self.wallet.transactions.items():
                self.add_tx(txid, Transaction(tx.raw))  # we take a copy of the transaction so prevent storing deserialized tx in wallet.transactions dict

    #--- GETTERS / SETTERS from wallet
    def token_info_for_txo(self, txo) -> Tuple[str, int]:
        ''' Returns the (token_id_hex, quantity) tuple for a particular
        txo if it has a token sitting on it.  Returns None if there is no
        token for a particular txo. Takes no locks.

        Note that quantity == -1 indicates a "token baton"
        '''
        token_id_hex = self.txo_token_id.get(txo)
        if token_id_hex is not None:
            return token_id_hex, self.token_quantities[token_id_hex][txo]  # we want this to raise KeyError here if missing as it indicates a programming error
    def txo_has_token(self, txo) -> bool:
        ''' Takes no locks. '''
        return txo in self.txo_token_id
    def get_addr_txo(self, addr) -> Set[str]:
        ''' Note this returns the actual reference to the set.  Returns all
        txos (spend and/or unspent) that have ever received tokens for a
        particular address.
        Call this with locks held and/or copy the set if you want to be thread-safe. '''
        return self.txo_byaddr.get(addr, set())
    def get_batons(self, token_id_hex, *, ret_class = list) -> List[str]:
        ''' Returns the list of txo's containing a token baton for a particular
        token_id_hex, or the empty list if no batons in wallet for said token.
        Takes no locks. Wrap in wallet.lock to make this thread-safe.

        Optional kwarg `ret_class` can be used to return some other container
        besides a list (e.g. 'ret_class = set' would return a set). '''
        return ret_class(txo for txo, qty in
                            self.token_quantities.get(token_id_hex, {}).items()
                            if qty <= -1)
    #--- /GETTERS/SETTERS

    #-- Wallet hooks (rm_tx, add_tx)
    def rm_tx(self, txid):
        ''' Caller should hold wallet.lock
        This is (usually) called by wallet.remove_transaction in the network
        thread with locks held.

        Note: In the case where txid is not in our slp data, this returns
        quickly.  Otherwise if txid is in the slp data, this is a somewhat slow
        operation as it involves a linear search through all data structures to
        eviscerate the tx in question.

        TODO: characterize whether a speedup here is warranted. '''
        try:
            del self.validity[txid]
        except KeyError:
            # The txid in question was not one we manage if it's missing
            # from self.validity. Short-cirtuit early return for performance.
            return
        for txo in list(self.txo_token_id.keys()):
            if txo.rsplit(':', 1)[0] == txid:
                self.txo_token_id.pop(txo, None)
        for addr, txo_set in self.txo_byaddr.copy().items():
            for txo in list(txo_set):
                if txo.rsplit(':', 1)[0] == txid:
                    txo_set.discard(txo)  # this actually points to the real txo_set instance in the dict
            if not txo_set:
                self.txo_byaddr.pop(addr, None)
        for tok_id, txo_dict in self.token_quantities.copy().items():
            for txo in txo_dict.copy():
                if txo.rsplit(':', 1)[0] == txid:
                    txo_dict.pop(txo, None)  # this actually points to the real txo_dict instance in the token_quantities[tok_id] dict
            if not txo_dict:
                self.token_quantities.pop(tok_id, None)
                # this token has no more relevant tx's -- pop it from
                # the validity dict as well
                self.validity.pop(tok_id, None)

    def add_tx(self, txid, tx):
        ''' Caller should hold wallet.lock.
        This is (usually) called by wallet.add_transaction in the network thread
        with locks held.'''
        outputs = tx.outputs()
        so = outputs and outputs[0][1]
        if not isinstance(so, ScriptOutput):  # Note: ScriptOutput here is the subclass defined in this file, not address.ScriptOutput
            return
        transaction_type = so.message.transaction_type
        try:
            if transaction_type == 'GENESIS':
                self._add_genesis_or_mint_tx(so, outputs, txid, tx)
            elif transaction_type == 'MINT':
                self._add_genesis_or_mint_tx(so, outputs, txid, tx)
            elif transaction_type == 'SEND':
                self._add_send_tx(so, outputs, txid, tx)
            elif transaction_type == 'COMMIT':
                return  # ignore COMMIT, they don't produce any tokens
            else:
                raise InvalidOutputMessage('Bad transaction type')
        except (AssertionError, ValueError, KeyError, TypeError, IndexError) as e:
            self.print_error(f"ERROR: tx {txid}; exc =", repr(e))
    #-- /Wallet hooks (rm_tx, add_tx)

    def _add_token_qty(self, token_id_hex, txo_name, qty):
        ''' No checks are done for address, etc. qty is just faithfully added
        for a given token/txo_name combo. '''
        d = self.token_quantities.get(token_id_hex, dict())
        need_insert = not d
        d[txo_name] = qty  # NB: negative quantity indicates mint baton
        if need_insert: self.token_quantities[token_id_hex] = d

    def _add_txo(self, token_id_hex, txid, n, addr, token_qty):
        ''' Adds txid:n to requisite data structures, registering
        this token output, etc. '''
        if not isinstance(addr, address.Address) or not self.wallet.is_mine(addr):
            # ignore txo's for addresses that are not "mine", or that are not TYPE_ADDRESS
            return
        name = f"{txid}:{n}"
        if txid not in self.validity:
            self.validity[txid] = 0
        if token_id_hex not in self.validity:
            self.validity[token_id_hex] = 0
        s = self.txo_byaddr.get(addr, set())
        need_insert = not s
        s.add(name)
        if need_insert: self.txo_byaddr[addr] = s
        self.txo_token_id[name] = token_id_hex
        self._add_token_qty(token_id_hex, name, token_qty)

    def _add_mint_baton(self, token_id_hex, txid, n, addr):
        self._add_txo(token_id_hex, txid, n, addr, -1)

    def _add_genesis_or_mint_tx(self, so, outputs, txid, tx):
        ''' Adds the genesis and/or mint tx and keeps track of the txo's it
        sent coins to in internal data structures '''
        token_type = so.message.token_type
        is_genesis = so.message.transaction_type == "GENESIS"
        token_id_hex = txid if is_genesis else so.message.token_id_hex
        assert token_type in valid_token_types, "Invalid token type: FIXME"  # paranoia
        r_type, r_addr, _dummy = outputs[1]  # may raise

        # Not clear here if we should be rejecting the whole message or
        # just the output.  Comment this out when that becomes clear.
        # For now I'm doing what the EC-SLP wallet did rejecting this
        # genesis message here.
        assert r_type == bitcoin.TYPE_ADDRESS, "Token genesis/mint: output 1 != TYPE_ADDRESS, ignoring tx"

        # neither of the below 2 can ever be negative due to how we read the bytes
        baton_vout = so.message.mint_baton_vout
        token_qty = so.message.initial_token_mint_quantity if is_genesis else so.message.additional_token_quantity
        if baton_vout is not None:
            b_type, b_addr, _dummy = outputs[baton_vout] # may raise
            # SLP wallet silently ignored non-TYPE_ADDRESS, so we do same here.
            #assert b_type == bitcoin.TYPE_ADDRESS, f"Token baton vout ({baton_vout}) != TYPE_ADDRESS, ignoring tx"
            self._add_mint_baton(token_id_hex, txid, baton_vout, b_addr)  # this silently ignores non-TYPE_ADDRESS
        self._add_txo(token_id_hex, txid, 1, r_addr, token_qty)


    def _add_send_tx(self, so, outputs, txid, tx):
        ''' Caller should hold locks. This adds the send for addresses that are
        mine to appropriate internal data structures. '''
        token_type = so.message.token_type
        token_id_hex = so.message.token_id_hex
        assert token_type in valid_token_types, "Invalid token type: FIXME"  # paranoia
        amounts = so.message.token_output
        amounts = amounts[:len(outputs)]  # truncate amounts to match outputs -- shouldn't we reject such malformed messages?
        for n, qty in enumerate(amounts):
            if qty <= 0:  # safely ignore 0 qty as per spec
                continue
            _type, addr, _dummy = outputs[n]  # shouldn't raise since we truncated list above
            self._add_txo(token_id_hex, txid, n, addr, qty)
