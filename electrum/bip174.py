import base64
import io
from copy import deepcopy
from typing import Union, Optional, List

from .bip32 import convert_raw_uint32_to_bip32_path, convert_bip32_path_to_list_of_uint32, convert_uint32_to_bip32_path, \
    xpub_to_bip32_psbt
from .bitcoin import varint_to_int, var_int, int_to_hex
from .transaction import StandardTransaction, Transaction, ImmutableTransaction
from .transaction_utils import get_num_sig, TxOutput, pay_script, PSBT_TXN_HEADER_MAGIC, SerializationError
from .util import bh2u, bfh, BitcoinException, print_error
from .xpubkey_utils import parse_xpubkey

"""
Note that you can check public methods and its verified signatures and return values in test_psbt.py
"""

# BIP174 constants - https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki
# PSBT_TXN_HEADER_MAGIC = b'psbt\xff'
PSBT_GLOBAL_UNSIGNED_TX = b'\x00'
PSBT_IN_NON_WITNESS_UTXO = b'\x00'
PSBT_IN_WITNESS_UTXO = b'\x01'
PSBT_IN_PARTIAL_SIG = b'\x02'
PSBT_IN_SIGHASH_TYPE = b'\x03'
PSBT_IN_REDEEM_SCRIPT = b'\x04'
PSBT_IN_WITNESS_SCRIPT = b'\x05'
PSBT_IN_BIP32_DERIVATION = b'\x06'
PSBT_IN_FINAL_SCRIPTSIG = b'\x07'
PSBT_IN_FINAL_SCRIPTWITNESS = b'\x08'
PSBT_OUT_REDEEM_SCRIPT = b'\x00'
PSBT_OUT_WITNESS_SCRIPT = b'\x01'
PSBT_OUT_BIP32_DERIVATION = b'\x02'

SIGHASH_ALL = '01000000'


def _validate_bip32(bip32_derivation):
    for k, v in bip32_derivation.items():
        if isinstance(v, bytes):
            # v = _validate_bip32(k, v)
            if len(k) not in (66, 130):
                raise SerializationError('Invalid key value')
            fpr, raw_path = v[:4], v[4:]
            bip32_path = convert_raw_uint32_to_bip32_path(raw_path)

            bip32_derivation[k] = {
                'master_fingerprint': bh2u(fpr),
                'bip32_path': bip32_path,
            }
        if isinstance(v, dict):
            if len(k) not in (66, 130):
                raise SerializationError('Invalid key value')
            assert v.get('master_fingerprint')
            assert v.get('bip32_path')
    return bip32_derivation

    # if len(key) != 66:
    #     raise SerializationError('Invalid key value')
    # fpr, raw_path = value[:4], value[4:]
    # bip32_path = convert_raw_uint32_to_bip32_path(raw_path)
    #
    # res = {
    #     'master_fingerprint': bh2u(fpr),
    #     'bip32_path': bip32_path,
    # }
    # return res


_keytypes = {
    'global': {  # (name, has_key)
        PSBT_GLOBAL_UNSIGNED_TX: ('unsigned_tx', False),
    },
    'inputs': {
        PSBT_IN_NON_WITNESS_UTXO: ('non_witness_utxo', False),
        PSBT_IN_WITNESS_UTXO: ('witness_utxo', False),
        PSBT_IN_PARTIAL_SIG: ('partial_sig', True),
        PSBT_IN_SIGHASH_TYPE: ('sighash_type', False),
        PSBT_IN_REDEEM_SCRIPT: ('redeem_script', False),
        PSBT_IN_WITNESS_SCRIPT: ('witness_script', False),
        PSBT_IN_BIP32_DERIVATION: ('bip32_derivation', True),
        PSBT_IN_FINAL_SCRIPTSIG: ('final_scriptsig', False),
        PSBT_IN_FINAL_SCRIPTWITNESS: ('final_scriptwitness', False),
    },
    'outputs': {
        PSBT_OUT_REDEEM_SCRIPT: ('redeem_script', False),
        PSBT_OUT_WITNESS_SCRIPT: ('witness_script', False),
        PSBT_OUT_BIP32_DERIVATION: ('bip32_derivation', True),
    }
}
_keynames2keytypes = {
    'global': {
        'unsigned_tx': PSBT_GLOBAL_UNSIGNED_TX,
    },
    'inputs': {
        'non_witness_utxo': PSBT_IN_NON_WITNESS_UTXO,
        'witness_utxo': PSBT_IN_WITNESS_UTXO,
        'partial_sig': PSBT_IN_PARTIAL_SIG,
        'sighash_type': PSBT_IN_SIGHASH_TYPE,
        'redeem_script': PSBT_IN_REDEEM_SCRIPT,
        'witness_script': PSBT_IN_WITNESS_SCRIPT,
        'bip32_derivation': PSBT_IN_BIP32_DERIVATION,
        'final_scriptsig': PSBT_IN_FINAL_SCRIPTSIG,
        'final_scriptwitness': PSBT_IN_FINAL_SCRIPTWITNESS,
        'unknown': b'',
    },
    'outputs': {
        'redeem_script': PSBT_OUT_REDEEM_SCRIPT,
        'witness_script': PSBT_OUT_WITNESS_SCRIPT,
        'bip32_derivation': PSBT_OUT_BIP32_DERIVATION,
    }
}


def _parse_stream(stream: io.BytesIO):
    out = []
    while 1:
        _len, _ = varint_to_int(stream)
        if _len is None:
            # EOF
            # break
            raise SerializationError('Invalid tx format: missing sections')
        if _len == 0:
            break

        full_key = stream.read(_len)
        key_type, key = full_key[:1], full_key[1:]

        _len, _ = varint_to_int(stream)
        if _len is None:
            raise SerializationError('Invalid tx format: missing sections')
        value = stream.read(_len)

        out.append((key_type, key, value))
    return out


def _construct_args(arr: list, keymap: dict) -> dict:
    d = {'unknown': {}}
    for kt, k, v in arr:
        kname, has_keys = keymap.get(kt, (None, True))
        if kname is None:
            k = bh2u(kt + k)
            d['unknown'][k] = bh2u(v)
            continue
        if has_keys:
            if d.get(kname) is None:
                d[kname] = {}
            if d[kname].get(bh2u(k)) is None:
                d[kname][bh2u(k)] = v
            else:
                raise SerializationError('Duplicate key')

        else:
            # assert that key is empty
            if k != b'':
                raise SerializationError('Invalid key value')
            if d.get(kname) is None:
                d[kname] = v
            else:
                raise SerializationError('Duplicate key')
    if not d['unknown']:
        d.pop('unknown')
    return d


class PSBTSection:
    _section_name = None
    _parent = None  # type: PSBT

    def _serialize_kv(self, keyname: str, key: str, value: str) -> bytes:
        key = _keynames2keytypes[self._section_name][keyname] + bfh(key)
        value = bfh(value)

        out = bfh(var_int(len(key)))
        out += key
        out += bfh(var_int(len(value)))
        out += value
        return out


class PSBTGlobal(PSBTSection):
    unsigned_tx = None  # type: Optional[StandardTransaction]
    num_inputs = None  # type: Optional[int]
    num_outputs = None  # type: Optional[int]

    _section_name = 'global'

    def __init__(self, unsigned_tx, **kw):
        if isinstance(unsigned_tx, bytes):
            unsigned_tx = bh2u(unsigned_tx)
        if isinstance(unsigned_tx, StandardTransaction):
            unsigned_tx = unsigned_tx
        else:
            unsigned_tx = StandardTransaction.from_raw(unsigned_tx)
        self.unsigned_tx = unsigned_tx
        self.unsigned_tx._parent_psbt = self
        # self.unsigned_tx.deserialize()
        # self._raw_unsigned_tx = bfh(self.unsigned_tx.serialize())

        # TODO: check for emptiness and validity
        self.validate()

        self.num_inputs = len(self.unsigned_tx.inputs())
        self.num_outputs = len(self.unsigned_tx.outputs())

    @staticmethod
    def from_raw_stream(stream: io.BytesIO):
        arr = _parse_stream(stream)
        keymap = _keytypes['global']
        d = _construct_args(arr, keymap)

        try:
            section = PSBTGlobal(**d)
        except TypeError:
            raise SerializationError('Invalid tx format: missing sections')
        return section

    def _serialize(self) -> bytes:
        key = PSBT_GLOBAL_UNSIGNED_TX
        key_len = bfh(var_int(len(key)))
        value = bfh(self.unsigned_tx.serialize(witness=False))
        if value.startswith(b'EPTF'):
            raise SerializationError('old format')
        value_len = bfh(var_int(len(value)))
        return key_len + key + value_len + value

    def validate(self):
        utxo = self.unsigned_tx
        for txin in utxo.inputs():
            if txin.get('scriptSig') or (txin.get('witness', '00') != '00'):
                raise SerializationError('Found signed inputs in unsigned tx')


class PSBTInput(PSBTSection):
    non_witness_utxo = None
    witness_utxo = None
    partial_sig = None
    sighash_type = None
    redeem_script = None
    witness_script = None
    bip32_derivation = None
    final_scriptsig = None
    final_scriptwitness = None
    unknown = None

    index = None

    _section_name = 'inputs'

    def __init__(self, **kw):
        """
        PSBTInput contain all metainformation for corresponding global utxo txins
        non_witness_utxo - it's a full network transaction, from which global txin spend money(and which utxos are
        consumed in global transaction)

        You can read and use any of bip174 specified properties of this object(and 'unknown' dict)
        It's forbidden to change properties of this object from outside, only parent PSBT class have such privilege
        """
        kw = deepcopy(kw)
        self.non_witness_utxo = kw.pop('non_witness_utxo', None)
        self.witness_utxo = kw.pop('witness_utxo', None)
        self.partial_sig = kw.pop('partial_sig', {})
        self.sighash_type = kw.pop('sighash_type', None)
        self.redeem_script = kw.pop('redeem_script', None)
        self.witness_script = kw.pop('witness_script', None)
        self.bip32_derivation = kw.pop('bip32_derivation', {})
        self.final_scriptsig = kw.pop('final_scriptsig', None)
        self.final_scriptwitness = kw.pop('final_scriptwitness', None)
        self.unknown = kw.pop('unknown', {})
        self._is_segwit = False

        self.validate()

        self.d = dict()

    def validate(self):
        """
        please note, that we also convert types and properly construct child objects here
        """
        if self.non_witness_utxo:
            if isinstance(self.non_witness_utxo, bytes):
                self.non_witness_utxo = bh2u(self.non_witness_utxo)
            if isinstance(self.non_witness_utxo, str):
                self.non_witness_utxo = ImmutableTransaction(self.non_witness_utxo)
            if isinstance(self.non_witness_utxo, ImmutableTransaction):
                self.non_witness_utxo.deserialize()
                # self._is_segwit = self.non_witness_utxo.is_segwit()
            self.non_witness_utxo._parent_psbt = self

        if self.witness_utxo:
            self._is_segwit = True
            if isinstance(self.witness_utxo, bytes):
                self.witness_utxo = bh2u(self.witness_utxo)

        if self.partial_sig:
            if isinstance(self.partial_sig, bytes):
                pass
            if isinstance(self.partial_sig, dict):
                for k, v in self.partial_sig.items():
                    if len(k) not in (66, 130):
                        raise SerializationError('Invalid key value')
                    if isinstance(v, bytes):
                        self.partial_sig[k] = bh2u(v)

        if self.sighash_type:
            if isinstance(self.sighash_type, bytes):
                self.sighash_type = bh2u(self.sighash_type)

        if self.redeem_script:
            if isinstance(self.redeem_script, bytes):
                self.redeem_script = bh2u(self.redeem_script)

        if self.witness_script:
            if isinstance(self.witness_script, bytes):
                self.witness_script = bh2u(self.witness_script)

        if self.bip32_derivation:
            self.bip32_derivation = _validate_bip32(self.bip32_derivation)

        if self.final_scriptsig:
            if isinstance(self.final_scriptsig, bytes):
                self.final_scriptsig = bh2u(self.final_scriptsig)

        if self.final_scriptwitness:
            if isinstance(self.final_scriptwitness, bytes):
                self.final_scriptwitness = bh2u(self.final_scriptwitness)

    @classmethod
    def from_raw_stream(cls, stream: io.BytesIO):
        arr = _parse_stream(stream)
        keymap = _keytypes[cls._section_name]
        d = _construct_args(arr, keymap)

        return PSBTInput(**d)

    def _serialize(self) -> bytes:
        out = io.BytesIO()

        if self.non_witness_utxo and not self._is_segwit:
            out.write(self._serialize_kv('non_witness_utxo', '', self.non_witness_utxo.serialize_to_network()))

        if self._is_segwit:
            if self.witness_utxo:
                out.write(self._serialize_kv('witness_utxo', '', self.witness_utxo))

        if self.partial_sig:
            for pubkey in sorted(self.partial_sig.keys()):
                sig = self.partial_sig[pubkey]
                out.write(self._serialize_kv('partial_sig', pubkey, sig))

        if self.sighash_type:
            out.write(self._serialize_kv('sighash_type', '', self.sighash_type))

        if self.redeem_script:
            out.write(self._serialize_kv('redeem_script', '', self.redeem_script))

        if self.witness_script:
            out.write(self._serialize_kv('witness_script', '', self.witness_script))

        if self.bip32_derivation:
            for pubkey in sorted(self.bip32_derivation.keys()):
                data = self.bip32_derivation[pubkey]
                # Hack: we use empty values internally for non bip32 wallets, but it shouldn't affect serialization
                if data is None:
                    continue
                path = ''.join([int_to_hex(i, 4) for i in convert_bip32_path_to_list_of_uint32(data['bip32_path'])])
                value = data['master_fingerprint'] + path
                out.write(self._serialize_kv('bip32_derivation', pubkey, value))

        if self.final_scriptsig:
            out.write(self._serialize_kv('final_scriptsig', '', self.final_scriptsig))

        if self.final_scriptwitness:
            out.write(self._serialize_kv('final_scriptwitness', '', self.final_scriptwitness))

        if self.unknown:
            keys = sorted(list(self.unknown.keys()))
            for key in keys:
                out.write(self._serialize_kv('unknown', key, self.unknown[key]))

        return out.getvalue()

    def _as_dict(self):
        """
        json-serializable representation of object for debug or logging purposes
        """
        return {
            'non_witness_utxo': self.non_witness_utxo and self.non_witness_utxo.serialize(),
            'witness_utxo': self.witness_utxo,
            'partial_sig': self.partial_sig,
            'sighash_type': self.sighash_type,
            'redeem_script': self.redeem_script,
            'witness_script': self.witness_script,
            'bip32_derivation': self.bip32_derivation,
            'final_scriptsig': self.final_scriptsig,
            'final_scriptwitness': self.final_scriptwitness,
        }

    def signature_count(self):
        r = 0
        s = 0

        if self.non_witness_utxo:
            for txin in self.non_witness_utxo.inputs():
                if txin['type'] == 'coinbase':
                    continue

                # assuming that Creator provided all necessary keys, always true for transactions created by electrum
                signatures = list(self.partial_sig.keys())
                s += len(signatures)
                num_sig = get_num_sig(self.redeem_script)
                r += num_sig if num_sig is not None else -1
        if self.witness_utxo:
            signatures = list(self.partial_sig.keys())
            s += len(signatures)
            num_sig = get_num_sig(self.redeem_script)
            r += num_sig if num_sig is not None else -1
        return s, r

    def _finalizer_check(self):
        """
        if possible, used to construct final signatures and cleanup
        """

        txin = self._parent.glob.unsigned_tx.inputs()[self.index]
        if self.is_complete():
            if self.final_scriptsig is None:
                script = self._parent.glob.unsigned_tx.input_script(txin, attach_signatures=True)
                self.final_scriptsig = script

            if self.is_segwit() and (self.final_scriptwitness is None):
                script = self._parent.glob.unsigned_tx.serialize_witness(self.index)
                self.final_scriptwitness = script

        if self.final_scriptsig or self.final_scriptwitness:
            self.partial_sig = dict()
            self.sighash_type = None
            self.redeem_script = None
            self.bip32_derivation = dict()

    def is_complete(self) -> bool:
        if self.final_scriptsig or self.final_scriptwitness:
            return True
        s, r = self.signature_count()
        return s == r

    def is_segwit(self):
        if self.witness_utxo:
            return True
        return False


class PSBTOutput(PSBTSection):
    redeem_script = None
    witness_script = None
    bip32_derivation = None

    index = None

    _section_name = 'outputs'

    def __init__(self, **kw):
        kw = deepcopy(kw)
        self.redeem_script = kw.pop('redeem_script', None)
        self.witness_script = kw.pop('witness_script', None)  # TODO: witness
        self.bip32_derivation = kw.pop('bip32_derivation', {})

        self.validate()

    def validate(self):
        if self.bip32_derivation:
            self.bip32_derivation = _validate_bip32(self.bip32_derivation)

    @staticmethod
    def from_raw_stream(stream: io.BytesIO):
        arr = _parse_stream(stream)
        keymap = _keytypes['outputs']
        d = _construct_args(arr, keymap)

        return PSBTOutput(**d)

    def _serialize(self) -> bytes:
        out = io.BytesIO()

        if self.bip32_derivation:
            for pubkey in sorted(self.bip32_derivation.keys(), key=lambda i: int.from_bytes(bfh(i), 'little')):
                data = self.bip32_derivation[pubkey]
                path = ''.join([int_to_hex(i, 4) for i in convert_bip32_path_to_list_of_uint32(data['bip32_path'])])
                value = data['master_fingerprint'] + path
                out.write(self._serialize_kv('bip32_derivation', pubkey, value))

        return out.getvalue()


class PSBT:
    def __init__(self, global_section: PSBTGlobal, input_sections: List[PSBTInput], output_sections: List[PSBTOutput]):
        """
        Do not break consistency, always assume -> len(global_section.unsigned_tx.inputs()) == len(self.inputs_sections)
        Note that BIP69_sort suppressed in child transaction, and should be used only from this object, because
        we preserving section ordering
        """
        self.glob = global_section
        self.input_sections = input_sections
        self.output_sections = output_sections

        self.glob._parent = self
        for i, inp in enumerate(self.input_sections):
            inp._parent = self
            inp.index = i
        for i, out in enumerate(self.output_sections):
            out._parent = self
            out.index = i

        self.validate()
        self.BIP69_sort()

    @staticmethod
    def strip_utxo(tx: Transaction) -> List[dict]:
        """
        returns [{
            'bip32_derivation': {
                <pubkey_hex>: {
                    'bip32_path': "/0/0'",
                    'master_fingerprint': '272469db'
                },
                ...
            }
            'partial_sig': {
                <pubkey_hex>: '<signature_hex>',
                ...
            },
            'redeem_script': '<hex>'
        }]
        """
        # check that this is exact Transaction object, and not any subclass
        if not (type(tx) == Transaction):
            return [{} for _ in range(len(tx.inputs()))]
        tx.deserialize()
        inputs_data = []
        for txin in tx.inputs():
            ctx = {'bip32_derivation': {}, 'partial_sig': {}}
            # txin.get('pubkeys')  # also must remove pubkeys
            x_pubkeys = txin.pop('x_pubkeys', [])
            signatures = txin.pop('signatures', [])
            for i, x_pubkey in enumerate(x_pubkeys):
                # skip old mpk keys, because they not bip32 compatible
                if x_pubkey[:2] == 'fe':
                    continue

                xpub, s = parse_xpubkey(x_pubkey)
                if xpub is None:
                    continue
                pubk, data = xpub_to_bip32_psbt(xpub, convert_uint32_to_bip32_path(s))
                sig = signatures[i]
                txin['pubkeys'] = pubk
                ctx['bip32_derivation'][pubk] = data
                if sig:
                    ctx['partial_sig'][pubk] = sig
            redeem_script = txin.get('redeem_script', None)
            if redeem_script:
                ctx['redeem_script'] = redeem_script

            witness = txin.pop('witness', None)
            if witness:
                ctx['witness'] = witness

            inputs_data.append(ctx)
        return inputs_data

    @classmethod
    def from_raw(cls, raw: Union[str, bytes]):
        """
        Note: performs BIP69 sort by default, because strict ordering not important
        """
        if isinstance(raw, str):
            # guess input encoding
            try:
                raw = bfh(raw)
            except (TypeError, ValueError) as e:
                try:
                    raw = base64.b64decode(raw)
                except (TypeError, ValueError) as e:
                    pass
        stream = io.BytesIO(raw)

        hdr = stream.read(5)
        if hdr != PSBT_TXN_HEADER_MAGIC:
            raise SerializationError('Bad PSBT header')

        global_section = PSBTGlobal.from_raw_stream(stream)
        input_sections = []
        output_sections = []
        for _ in range(global_section.num_inputs):
            input_sections.append(PSBTInput.from_raw_stream(stream))
        for _ in range(global_section.num_outputs):
            output_sections.append(PSBTOutput.from_raw_stream(stream))

        if global_section.num_outputs != len(output_sections):
            raise SerializationError('Invalid tx format: missing sections')

        return PSBT(global_section, input_sections, output_sections)

    @classmethod
    def from_raw_tx(cls, raw: Union[bytes, str, Transaction]):
        """
        In case we got EPTF transaction, populate corresponding PSBT fields with its data
        Must be used to convert old Transaction to PSBT
        """
        tx = None
        if isinstance(raw, str):
            tx = Transaction(raw)
        elif isinstance(raw, bytes):
            tx = Transaction(bh2u(raw))
        elif isinstance(raw, Transaction):
            tx = raw
        else:
            raise SerializationError('Unknown tx type')

        inputs_data = PSBT.strip_utxo(tx)
        # signature data extracted, now can cast to Standard
        tx = StandardTransaction(tx.inputs(), tx.outputs(), locktime=tx.locktime, version=tx.version)

        glob = PSBTGlobal(tx.serialize(witness=False))
        inputs = [PSBTInput(**inputs_data[i]) for i in range(glob.num_inputs)]
        psbt = PSBT(glob, inputs, [PSBTOutput() for _ in range(glob.num_outputs)])

        return psbt

    @classmethod
    def from_io(cls, inputs: List[dict], outputs: List[TxOutput]):
        tx = StandardTransaction(inputs=inputs, outputs=outputs)
        return cls.from_raw_tx(tx)

    def serialize(self) -> str:
        """
        psbt in base64
        """
        out = PSBT_TXN_HEADER_MAGIC
        out += self.glob._serialize() + b'\x00'
        out += b'\x00'.join([section._serialize() for section in self.input_sections]) + b'\x00'
        out += b'\x00'.join([section._serialize() for section in self.output_sections]) + b'\x00'
        out = base64.b64encode(out).decode('ascii')
        return out

    def serialize_final(self) -> Optional[str]:
        """
        return network hex if transaction complete
        """
        if not self.is_complete():
            return None
        inputs = self.glob.unsigned_tx.inputs()
        for i, txin in enumerate(inputs):
            inp = self.input_sections[i]
            txin['scriptSig'] = inp.final_scriptsig
            txin['witness'] = inp.final_scriptwitness

        out = self.glob.unsigned_tx.serialize_to_network(attach_signatures=True)

        for i, txin in enumerate(inputs):
            txin.pop('scriptSig')
            txin.pop('witness')
        self.glob.unsigned_tx.is_segwit()
        return out

    def _as_dict(self):
        out = {
            'global': {
                'unsigned_tx': self.glob.unsigned_tx.serialize()
            },
            'inputs': [inp._as_dict() for inp in self.input_sections],
            'outputs': []
        }
        return out

    @staticmethod
    def deserialize(raw: Union[str, bytes]):
        raise NotImplementedError('Use from_raw method instead')

    def sign(self, keypairs):
        # populate witness in tx, it will need it for signing
        for i, inp in enumerate(self.input_sections):
            if inp.witness_utxo:
                self.glob.unsigned_tx.inputs()[i]['witness'] = inp.witness_utxo

        for i, inp in enumerate(self.input_sections):
            # deepcopy because we need to ensure that detached sign has no side effects
            # remove if stable
            # bip32_derivations = [deepcopy(inp.bip32_derivation) for inp in self.input_sections]
            # partial_sigs = [deepcopy(inp.partial_sig) for inp in self.input_sections]
            partial_sigs = self.glob.unsigned_tx.detached_sign(keypairs, inp.bip32_derivation, inp.partial_sig)
            inp.partial_sig.update(partial_sigs[i])
            txin = self.glob.unsigned_tx.inputs()[i].pop('witness', None)

        self.finalizer_check()
        # BIP174 sign pseudocode
        '''
        def sign_witness(script_code, i):
            for key in psbt.inputs[i].keys:
                if IsMine(key):
                    sign(witness_sighash(script_code, i, input))

        def sign_non_witness(script_code, i):
            for key in psbt.inputs[i].keys:
                if IsMine(key):
                    sign(non_witness_sighash(script_code, i, input))

        for input,i in enumerate(psbt.inputs):
            if non_witness_utxo.exists:
                assert(sha256d(non_witness_utxo) == psbt.tx.innput[i].prevout.hash)
                if redeemScript.exists:
                    assert(non_witness_utxo.vout[psbt.tx.input[i].prevout.n].scriptPubKey == P2SH(redeemScript))
                    sign_non_witness(redeemScript)
                else:
                    sign_non_witness(non_witness_utxo.vout[psbt.tx.input[i].prevout.n].scriptPubKey)
            else if witness_utxo.exists:
                if redeemScript.exists:
                    assert(witness_utxo.scriptPubKey == P2SH(redeemScript))
                    script = redeemScript
                else:
                    script = witness_utxo.scriptPubKey
                if IsP2WPKH(script):
                    sign_witness(P2PKH(script[2:22]))
                else if IsP2WSH(script):
                    assert(script == P2WSH(witnessScript))
                    sign_witness(witnessScript)
            else:
                assert False
        '''

    def get_all_txins(self):
        txins = []
        for inp in self.input_sections:
            if inp.non_witness_utxo:
                txins.extend(inp.non_witness_utxo.inputs())
            # TODO:
            # if inp.witness_utxo:
            #     txins.extend(inp.witness_utxo)
        return txins

    def add_tx_inputs(self, inputs: list):
        # TODO: sanitize inputs
        self.glob.unsigned_tx.add_inputs(inputs)
        self.glob.num_inputs += len(inputs)
        # self.glob = PSBTGlobal.deserialize(io.BytesIO(self.glob.serialize()))
        inputs = [PSBTInput(non_witness_utxo=ImmutableTransaction.from_io(inputs=[utxo], outputs=[])) for utxo in
                  inputs]
        for inp in inputs:
            inp._parent = self
        self.input_sections.extend(inputs)
        self.BIP69_sort()

    def add_tx_outputs(self, outputs):
        self.glob.unsigned_tx.add_outputs(outputs)
        # self.glob = PSBTGlobal.deserialize(io.BytesIO(self.glob.serialize()))
        diff = self.glob.num_outputs - len(self.output_sections)
        outputs = [PSBTOutput() for _ in range(diff)]
        for out in outputs:
            out._parent = self
        self.output_sections.extend(outputs)
        self.BIP69_sort()

    def update_inputs(self, inputs_meta):
        for i, info in enumerate(inputs_meta):
            if not info:
                continue
            inp = self.input_sections[i]
            txin = self.glob.unsigned_tx.inputs()[i]

            inp.partial_sig.update(info.get('partial_sig', {}))
            inp.bip32_derivation.update(info.get('bip32_derivation', {}))
            # TODO: should we reject new values, if old exists?
            if info.get('non_witness_utxo'):
                inp.non_witness_utxo = info.get('non_witness_utxo')
            if info.get('witness_utxo'):
                inp.witness_utxo = info.get('witness_utxo')
            if info.get('redeem_script'):
                inp.redeem_script = info.get('redeem_script')
            if info.get('sighash_type'):
                inp.sighash_type = info.get('sighash_type')

        self.validate()

    def update_outputs(self, outputs_meta):
        for i, info in enumerate(outputs_meta):
            if not info:
                continue
            self.output_sections[i].bip32_derivation.update(info.get('bip32_derivation', {}))

    def is_complete(self, skip_check=False):
        """
        note that psbt object don't change internal state by itself, until finalizer_check called
        calling this method cause side-effects
        """
        if not skip_check:
            self.finalizer_check()

        is_complete = all(inp.is_complete() for inp in self.input_sections)
        return is_complete

    def is_segwit(self):
        self.finalizer_check()

        is_segwit = any(inp.is_segwit() for inp in self.input_sections)

        return is_segwit

    def validate(self):
        """
        Checks that global utxo consistent with all inputs-outputs
        Inputs doesn't contain unrelevant data, or data in wrong format
        """

        self.glob.validate()

        utxo = self.glob.unsigned_tx
        inputs = self.input_sections
        for i, txin in enumerate(utxo.inputs()):
            inp = inputs[i]
            inp.validate()
            if inp.non_witness_utxo and txin['prevout_hash'] != inp.non_witness_utxo.txid():
                raise BitcoinException('Irrelevant transaction in input section found')
            if inp.non_witness_utxo:
                txo = inp.non_witness_utxo.outputs()[txin['prevout_n']]
                txin['value'] = txo.value
            if inp.witness_utxo:
                # TODO: parse segwit value better
                # read uint64 from serialized txo
                txin['value'] = int.from_bytes(bfh(inp.witness_utxo[:16]), 'little')
                pass

    def finalizer_check(self):
        """
        Checks for completion of inputs, and generates 'final_sig'
        calling this method cause side-effects
        """
        self.validate()

        for inp in self.input_sections:
            inp._finalizer_check()

    # Transaction methods
    def generate_redeem_scripts(self):
        """
        calling this method cause side-effects
        """
        utxo = self.glob.unsigned_tx
        inputs_meta = []
        for i, txin in enumerate(utxo.inputs()):
            redeem_script = None
            witness_script = None
            inp = self.input_sections[i]
            if inp.is_segwit():
                witness_script = self.glob.unsigned_tx.input_script(txin)
            if not inp.redeem_script:
                try:
                    redeem_script = utxo.preimage_script(txin)
                except Exception as e:
                    print_error(e)
            inputs_meta.append(
                {'redeem_script': redeem_script, 'witness_script': witness_script})  # remove push_script op
        self.update_inputs(inputs_meta)

    def signature_count(self):
        r = 0
        s = 0

        for inp in self.input_sections:
            _s, _r = inp.signature_count()
            s += _s
            r += _r
        return s, r

    def txid(self):
        if self.is_complete():
            tx = Transaction(self.serialize_final())
            return tx.txid()
        return None

    def wtxid(self):
        if self.is_complete():
            tx = Transaction(self.serialize_final())
            return tx.wtxid()
        return None

    def BIP69_sort(self):
        t = list(zip(self.glob.unsigned_tx.inputs(), self.input_sections))
        t.sort(key=lambda txi_and_section: (txi_and_section[0]['prevout_hash'], txi_and_section[0]['prevout_n']))
        txins, inputs = zip(*t)
        self.glob.unsigned_tx._inputs = txins
        self.input_sections = inputs

        t = list(zip(self.glob.unsigned_tx.outputs(), self.output_sections))
        t.sort(key=lambda txo_and_section: (
            txo_and_section[0][2], pay_script(txo_and_section[0][0], txo_and_section[0][1])))
        txos, outputs = zip(*t)
        self.glob.unsigned_tx._outputs = txos
        self.output_sections = outputs

        for i, inp in enumerate(self.input_sections):
            inp.index = i
        for i, out in enumerate(self.output_sections):
            out.index = i

    def remove_signatures(self):
        for inp in self.input_sections:
            inp.partial_sig = {}
            inp.final_scriptsig = None
            inp.final_scriptwitness = None
        assert not self.is_complete()
