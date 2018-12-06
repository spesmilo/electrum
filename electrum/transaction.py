#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2011 Thomas Voegtlin
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
import base64
import sys
import traceback
from typing import Sequence, Dict

from . import bitcoin
from .bitcoin import *
from .transaction_utils import deserialize, is_segwit_input, serialize_input, \
    serialize_output, pay_script, virtual_size_from_weight, serialize_witness, serialize_outpoint, \
    parse_input, parse_output, parse_witness, is_txin_complete, get_siglist, \
    guess_txintype_from_address, multisig_script, safe_parse_pubkey, get_sorted_pubkeys, TxOutput, \
    is_input_value_needed, construct_witness, TxOutputForUI, PARTIAL_TXN_HEADER_MAGIC, \
    BCDataStream, SerializationError, TxOutputHwInfo
from .util import print_error

# Note: The deserialization code originally comes from ABE.

NO_SIGNATURE = 'ff'


class Transaction:

    def __str__(self):
        if self.raw is None:
            self.raw = self.serialize()
        return self.raw

    def __init__(self, raw):
        if raw is None:
            self.raw = None
        elif isinstance(raw, str):
            self.raw = raw.strip() if raw else None
        elif isinstance(raw, dict):
            self.raw = raw['hex']
        else:
            raise Exception("cannot initialize transaction", raw)
        self._inputs = None
        self._outputs = None  # type: List[TxOutput]
        self.locktime = 0
        self.version = 1
        # by default we assume this is a partial txn;
        # this value will get properly set when deserializing
        self.is_partial_originally = True
        self._segwit_ser = None  # None means "don't know"
        self.output_info = None  # type: Optional[Dict[str, TxOutputHwInfo]]

    def update(self, raw):
        self.raw = raw
        self._inputs = None
        self.deserialize()

    def inputs(self):
        if self._inputs is None:
            self.deserialize()
        return self._inputs

    def outputs(self) -> List[TxOutput]:
        if self._outputs is None:
            self.deserialize()
        return self._outputs

    def update_signatures(self, signatures: Sequence[str]):
        """Add new signatures to a transaction

        `signatures` is expected to be a list of sigs with signatures[i]
        intended for self._inputs[i].
        This is used by the Trezor, KeepKey an Safe-T plugins.
        """
        if self.is_complete():
            return
        if len(self.inputs()) != len(signatures):
            raise Exception('expected {} signatures; got {}'.format(len(self.inputs()), len(signatures)))
        for i, txin in enumerate(self.inputs()):
            pubkeys, x_pubkeys = get_sorted_pubkeys(txin)
            sig = signatures[i]
            if sig in txin.get('signatures'):
                continue
            pre_hash = sha256d(bfh(self.serialize_preimage(i)))
            sig_string = ecc.sig_string_from_der_sig(bfh(sig[:-2]))
            for recid in range(4):
                try:
                    public_key = ecc.ECPubkey.from_sig_string(sig_string, recid, pre_hash)
                except ecc.InvalidECPointException:
                    # the point might not be on the curve for some recid values
                    continue
                pubkey_hex = public_key.get_public_key_hex(compressed=True)
                if pubkey_hex in pubkeys:
                    try:
                        public_key.verify_message_hash(sig_string, pre_hash)
                    except Exception:
                        traceback.print_exc(file=sys.stderr)
                        continue
                    j = pubkeys.index(pubkey_hex)
                    print_error("adding sig", i, j, pubkey_hex, sig)
                    self.add_signature_to_txin(i, j, sig)
                    break
        # redo raw
        self.raw = self.serialize()

    def add_signature_to_txin(self, i, signingPos, sig):
        txin = self._inputs[i]
        txin['signatures'][signingPos] = sig
        txin['scriptSig'] = None  # force re-serialization
        txin['witness'] = None  # force re-serialization
        self.raw = None

    def add_inputs_info(self, wallet):
        if self.is_complete():
            return
        for txin in self.inputs():
            wallet.add_input_info(txin)

    def remove_signatures(self):
        for txin in self.inputs():
            txin['signatures'] = [None] * len(txin['signatures'])
        assert not self.is_complete()

    def deserialize(self, force_full_parse=False):
        if self.raw is None:
            return
            # self.raw = self.serialize()
        if self._inputs is not None:
            return
        d = deserialize(self.raw, force_full_parse)
        self._inputs = d['inputs']
        self._outputs = [TxOutput(x['type'], x['address'], x['value']) for x in d['outputs']]
        self.locktime = d['lockTime']
        self.version = d['version']
        self.is_partial_originally = d['partial']
        self._segwit_ser = d['segwit_ser']
        # self.BIP69_sort()
        return d

    @classmethod
    def from_io(klass, inputs, outputs, locktime=0, version=1):
        self = klass(None)
        self._inputs = inputs[:]
        self._outputs = outputs[:]
        self.locktime = locktime
        self.version = version
        self.BIP69_sort()
        return self

    def set_rbf(self, rbf):
        nSequence = 0xffffffff - (2 if rbf else 1)
        for txin in self.inputs():
            txin['sequence'] = nSequence

    def BIP69_sort(self, inputs=True, outputs=True):
        if inputs:
            self._inputs.sort(key=lambda i: (i['prevout_hash'], i['prevout_n']))
        if outputs:
            self._outputs.sort(key=lambda o: (o[2], pay_script(o[0], o[1])))

    @classmethod
    def preimage_script(cls, txin: dict):
        preimage_script = txin.get('preimage_script', None)
        if preimage_script is not None:
            return preimage_script

        pubkeys, x_pubkeys = get_sorted_pubkeys(txin)
        if txin['type'] == 'p2pkh':
            return bitcoin.address_to_script(txin['address'])
        elif txin['type'] in ['p2sh', 'p2wsh', 'p2wsh-p2sh']:
            return multisig_script(pubkeys, txin['num_sig'])
        elif txin['type'] in ['p2wpkh', 'p2wpkh-p2sh']:
            pubkey = pubkeys[0]
            pkh = bh2u(bitcoin.hash_160(bfh(pubkey)))
            return '76a9' + push_script(pkh) + '88ac'
        elif txin['type'] == 'p2pk':
            pubkey = pubkeys[0]
            return bitcoin.public_key_to_p2pk_script(pubkey)
        else:
            raise TypeError('Unknown txin type', txin['type'])

    def serialize_preimage(self, i):
        nVersion = int_to_hex(self.version, 4)
        nHashType = int_to_hex(1, 4)
        nLocktime = int_to_hex(self.locktime, 4)
        inputs = self.inputs()
        outputs = self.outputs()
        txin = inputs[i]
        preimage_script = self.preimage_script(txin)
        if is_segwit_input(txin):
            hashPrevouts = bh2u(sha256d(bfh(''.join(serialize_outpoint(txin) for txin in inputs))))
            hashSequence = bh2u(
                sha256d(bfh(''.join(int_to_hex(txin.get('sequence', 0xffffffff - 1), 4) for txin in inputs))))
            hashOutputs = bh2u(sha256d(bfh(''.join(serialize_output(o) for o in outputs))))
            outpoint = serialize_outpoint(txin)
            scriptCode = var_int(len(preimage_script) // 2) + preimage_script
            amount = int_to_hex(txin['value'], 8)
            nSequence = int_to_hex(txin.get('sequence', 0xffffffff - 1), 4)
            preimage = nVersion + hashPrevouts + hashSequence + outpoint + scriptCode + amount + nSequence + hashOutputs + nLocktime + nHashType
        else:
            txins = var_int(len(inputs)) + ''.join(
                serialize_input(txin, preimage_script if i == k else '') for k, txin in enumerate(inputs))
            txouts = var_int(len(outputs)) + ''.join(serialize_output(o) for o in outputs)
            preimage = nVersion + txins + txouts + nLocktime + nHashType
        return preimage

    def is_segwit(self, guess_for_address=False):
        if not self.is_partial_originally:
            return self._segwit_ser
        return any(is_segwit_input(x, guess_for_address=guess_for_address) for x in self.inputs())

    def serialize(self, estimate_size=False, witness=True):
        network_ser = self.serialize_to_network(estimate_size, witness)
        if estimate_size:
            return network_ser
        if self.is_partial_originally and not self.is_complete():
            partial_format_version = '00'
            return bh2u(PARTIAL_TXN_HEADER_MAGIC) + partial_format_version + network_ser
        else:
            return network_ser

    def serialize_final(self):
        if not self.is_complete():
            return None
        return self.serialize_to_network()

    def serialize_to_network(self, estimate_size=False, witness=True):
        self.deserialize()
        nVersion = int_to_hex(self.version, 4)
        nLocktime = int_to_hex(self.locktime, 4)
        inputs = self.inputs()
        outputs = self.outputs()
        txins = var_int(len(inputs)) + ''.join(
            serialize_input(txin, self.input_script(txin, estimate_size)) for i, txin in enumerate(inputs))
        txouts = var_int(len(outputs)) + ''.join(serialize_output(o) for o in outputs)
        use_segwit_ser_for_estimate_size = estimate_size and self.is_segwit(guess_for_address=True)
        use_segwit_ser_for_actual_use = not estimate_size and \
                                        (self.is_segwit() or any(txin['type'] == 'address' for txin in inputs))
        use_segwit_ser = use_segwit_ser_for_estimate_size or use_segwit_ser_for_actual_use
        if witness and use_segwit_ser:
            marker = '00'
            flag = '01'
            witness = ''.join(serialize_witness(x, estimate_size) for x in inputs)
            return nVersion + marker + flag + txins + txouts + witness + nLocktime
        else:
            return nVersion + txins + txouts + nLocktime

    def txid(self):
        self.deserialize()
        all_segwit = all(is_segwit_input(x) for x in self.inputs())
        if not all_segwit and not self.is_complete():
            return None
        ser = self.serialize_to_network(witness=False)
        return bh2u(sha256d(bfh(ser))[::-1])

    def wtxid(self):
        self.deserialize()
        if not self.is_complete():
            return None
        ser = self.serialize_to_network(witness=True)
        return bh2u(sha256d(bfh(ser))[::-1])

    def add_inputs(self, inputs):
        self._inputs.extend(inputs)
        self.raw = None
        self.BIP69_sort(outputs=False)

    def add_outputs(self, outputs):
        self._outputs.extend(outputs)
        self.raw = None
        self.BIP69_sort(inputs=False)

    def input_value(self):
        return sum(x['value'] for x in self.inputs())

    def output_value(self):
        return sum(val for tp, addr, val in self.outputs())

    def get_fee(self):
        return self.input_value() - self.output_value()

    def is_final(self):
        return not any([x.get('sequence', 0xffffffff - 1) < 0xffffffff - 1 for x in self.inputs()])

    def estimated_size(self):
        """Return an estimated virtual tx size in vbytes.
        BIP-0141 defines 'Virtual transaction size' to be weight/4 rounded up.
        This definition is only for humans, and has little meaning otherwise.
        If we wanted sub-byte precision, fee calculation should use transaction
        weights, but for simplicity we approximate that with (virtual_size)x4
        """
        weight = self.estimated_weight()
        return virtual_size_from_weight(weight)

    def estimated_total_size(self):
        """Return an estimated total transaction size in bytes."""
        if not self.is_complete() or self.raw is None:
            l = len(self.serialize(True)) // 2
        else:
            l = len(self.raw) // 2  # ASCII hex string
        return l

    def estimated_witness_size(self):
        """Return an estimate of witness size in bytes."""
        estimate = not self.is_complete()
        if not self.is_segwit(guess_for_address=estimate):
            return 0
        inputs = self.inputs()
        witness = ''.join(serialize_witness(x, estimate) for x in inputs)
        witness_size = len(witness) // 2 + 2  # include marker and flag
        return witness_size

    def estimated_base_size(self):
        """Return an estimated base transaction size in bytes."""
        return self.estimated_total_size() - self.estimated_witness_size()

    def estimated_weight(self):
        """Return an estimate of transaction weight."""
        total_tx_size = self.estimated_total_size()
        base_tx_size = self.estimated_base_size()
        return 3 * base_tx_size + total_tx_size

    def signature_count(self):
        r = 0
        s = 0
        for txin in self.inputs():
            if txin['type'] == 'coinbase':
                continue
            signatures = list(filter(None, txin.get('signatures', [])))
            s += len(signatures)
            r += txin.get('num_sig', -1)
        return s, r

    def is_complete(self):
        s, r = self.signature_count()
        return r == s

    def sign(self, keypairs, detached_signatures=False) -> dict:
        # keypairs:  (x_)pubkey -> secret_bytes
        signatures = {}
        for i, txin in enumerate(self.inputs()):
            pubkeys, x_pubkeys = get_sorted_pubkeys(txin)
            for j, (pubkey, x_pubkey) in enumerate(zip(pubkeys, x_pubkeys)):
                if is_txin_complete(txin):
                    break
                if pubkey in keypairs:
                    _pubkey = pubkey
                elif x_pubkey in keypairs:
                    _pubkey = x_pubkey
                else:
                    continue
                print_error("adding signature for", _pubkey)
                sec, compressed = keypairs.get(_pubkey)
                sig = self.sign_txin(i, sec)
                signatures[_pubkey] = sig
                if not detached_signatures:
                    self.add_signature_to_txin(i, j, sig)

        print_error("is_complete", self.is_complete())
        self.raw = self.serialize()
        return signatures

    def sign_txin(self, txin_index, privkey_bytes) -> str:
        pre_hash = sha256d(bfh(self.serialize_preimage(txin_index)))
        privkey = ecc.ECPrivkey(privkey_bytes)
        sig = privkey.sign_transaction(pre_hash)
        sig = bh2u(sig) + '01'
        return sig

    def get_outputs_for_UI(self) -> Sequence[TxOutputForUI]:
        outputs = []
        for o in self.outputs():
            if o.type == TYPE_ADDRESS:
                addr = o.address
            elif o.type == TYPE_PUBKEY:
                addr = 'PUBKEY ' + o.address
            else:
                addr = 'SCRIPT ' + o.address
            outputs.append(TxOutputForUI(addr, o.value))  # consider using yield
        return outputs

    def has_address(self, addr: str) -> bool:
        return (addr in (o.address for o in self.outputs())) \
               or (addr in (txin.get("address") for txin in self.inputs()))

    def as_dict(self):
        if self.raw is None:
            self.raw = self.serialize()
        self.deserialize()
        out = {
            'hex': self.raw,
            'complete': self.is_complete(),
            'final': self.is_final(),
        }
        return out

    @classmethod
    def estimated_input_weight(cls, txin: dict, is_segwit_tx: bool) -> int:
        '''Return an estimate of serialized input weight in weight units.'''
        script = cls.input_script(txin, True)
        input_size = len(serialize_input(txin, script)) // 2

        if is_segwit_input(txin, guess_for_address=True):
            witness_size = len(serialize_witness(txin, True)) // 2
        else:
            witness_size = 1 if is_segwit_tx else 0

        return 4 * input_size + witness_size

    @classmethod
    def input_script(cls, txin: dict, estimate_size=False):
        _type = txin['type']
        if _type == 'coinbase':
            return txin['scriptSig']

        # If there is already a saved scriptSig, just return that.
        # This allows manual creation of txins of any custom type.
        # However, if the txin is not complete, we might have some garbage
        # saved from our partial txn ser format, so we re-serialize then.
        script_sig = txin.get('scriptSig', None)
        if script_sig is not None and is_txin_complete(txin):
            return script_sig

        pubkeys, sig_list = get_siglist(txin, estimate_size)
        script = ''.join(push_script(x) for x in sig_list)
        if _type == 'address' and estimate_size:
            _type = guess_txintype_from_address(txin['address'])
        if _type == 'p2pk':
            pass
        elif _type == 'p2sh':
            # put op_0 before script
            script = '00' + script
            redeem_script = multisig_script(pubkeys, txin['num_sig'])
            script += push_script(redeem_script)
        elif _type == 'p2pkh':
            script += push_script(pubkeys[0])
        elif _type in ['p2wpkh', 'p2wsh']:
            return ''
        elif _type == 'p2wpkh-p2sh':
            pubkey = safe_parse_pubkey(pubkeys[0])
            scriptSig = bitcoin.p2wpkh_nested_script(pubkey)
            return push_script(scriptSig)
        elif _type == 'p2wsh-p2sh':
            if estimate_size:
                witness_script = ''
            else:
                witness_script = cls.preimage_script(txin)
            scriptSig = bitcoin.p2wsh_nested_script(witness_script)
            return push_script(scriptSig)
        elif _type == 'address':
            return 'ff00' + push_script(pubkeys[0])  # fd extended pubkey
        elif _type == 'unknown':
            return txin['scriptSig']
        return script


class ImmutableTransaction(Transaction):
    """
    Used for storing full corresponding tx for selected txin in PSBT input sections
    """

    def update(self, raw):
        raise NotImplementedError('Immutable object')

    def input_script(self, txin: dict, estimate_size=False):
        script_sig = txin.get('scriptSig', '')
        return script_sig

    def get_serialized_output(self, i: int) -> str:
        txo = self.outputs()[i]
        witness = serialize_output(txo)
        return witness

    def sign(self, keypairs, detached_signatures=False) -> dict:
        raise NotImplementedError('Immutable object')

    def sign_txin(self, txin_index, privkey_bytes) -> str:
        raise NotImplementedError('Immutable object')

    def BIP69_sort(self, inputs=True, outputs=True):
        # disable sort
        pass

    def add_inputs(self, inputs):
        raise NotImplementedError('Immutable object')

    def add_outputs(self, outputs):
        raise NotImplementedError('Immutable object')

    # def serialize_to_network(self, estimate_size=False, witness=True):
    #     return Transaction.serialize_to_network(self, estimate_size=estimate_size, witness=False)


class StandardTransaction(Transaction):
    """
    Suppress all electum EPTF serialization hooks and magic
    This transactions should always be serializable as simple bitcoin-core transactions
    Used for PSBT global transaction, because it have strict requirements on allowed data in tx

    Transaction class uses internal state, which not preserved during network serialization, and stored in EPTF data
    But now we have PSBT standard, and this state stored in PSBT object(sometimes in different format), so we
    reimplementing some methods in order to get necessary data from parent psbt object

    More programmer friendly constructor, because we don't have to use explicit raw format(this work done in PSBT class)
    """

    def __init__(
            self,
            inputs: Sequence[dict],
            outputs: Sequence[TxOutput],
            version: int = 2,
            locktime: int = 0,
            segwit_ser: Optional[bool] = None,
            _parent_psbt=None
    ):
        # not calling super init, because it have completely different signature, and we will do this work here
        self._inputs = inputs
        self._outputs = outputs
        self.locktime = locktime
        self.version = version
        self._segwit_ser = segwit_ser  # None means "don't know"

        self._parent_psbt = _parent_psbt

        self.is_partial_originally = False

    @classmethod
    def from_raw(cls, raw: Union[str, bytes], parent_psbt=None):
        if isinstance(raw, str):
            raw = bfh(raw)
        d = {}
        vds = BCDataStream()
        vds.write(raw)
        d['version'] = vds.read_int32()
        n_vin = vds.read_compact_size()
        is_segwit = (n_vin == 0)
        if is_segwit:
            marker = vds.read_bytes(1)
            if marker != b'\x01':
                raise ValueError('invalid txn marker byte: {}'.format(marker))
            n_vin = vds.read_compact_size()
        d['segwit_ser'] = is_segwit
        d['inputs'] = [parse_input(vds, full_parse=False) for _ in range(n_vin)]
        n_vout = vds.read_compact_size()
        d['outputs'] = [parse_output(vds, i, ) for i in range(n_vout)]
        if is_segwit:
            for i in range(n_vin):
                txin = d['inputs'][i]
                parse_witness(vds, txin, full_parse=False)
        d['lockTime'] = vds.read_uint32()
        if vds.can_read_more():
            raise SerializationError('extra junk at the end')
        tx = StandardTransaction(
            inputs=d['inputs'],
            outputs=[TxOutput(x['type'], x['address'], x['value']) for x in d['outputs']],
            version=d['version'],
            locktime=d['lockTime'],
            segwit_ser=is_segwit,
            _parent_psbt=parent_psbt,
        )
        tx.raw = raw
        return tx

    def detached_sign(self, keypairs, bip32_derivation, partial_sig) -> List[dict]:
        # keypairs:  (x_)pubkey -> secret_bytes
        signatures = [{} for _ in range(len(self.inputs()))]
        for i, txin in enumerate(self.inputs()):
            for j, (pubkey, derivation) in enumerate(bip32_derivation.items()):
                if partial_sig.get(pubkey):
                    continue
                if pubkey not in keypairs:
                    continue
                print_error("adding signature for", pubkey)
                sec, compressed = keypairs.get(pubkey)
                sig = self.sign_txin(i, sec)
                signatures[i][pubkey] = sig

        return signatures

    def preimage_script(self, txin: dict):
        i = self._inputs.index(txin)
        inp = self._parent_psbt._parent.input_sections[i]
        preimage_script = txin.get('preimage_script', None)
        if preimage_script is not None:
            return preimage_script

        pubkeys = sorted(list(inp.bip32_derivation.keys()))
        if txin['type'] == 'p2pkh':
            script = bitcoin.address_to_script(txin['address'])
        elif txin['type'] in ['p2sh', 'p2wsh', 'p2wsh-p2sh']:
            script = multisig_script(pubkeys, txin['num_sig'])
        elif txin['type'] in ['p2wpkh', 'p2wpkh-p2sh']:
            pubkey = pubkeys[0]
            pkh = bh2u(bitcoin.hash_160(bfh(pubkey)))
            script = '76a9' + push_script(pkh) + '88ac'
        elif txin['type'] == 'p2pk':
            pubkey = pubkeys[0]
            script = bitcoin.public_key_to_p2pk_script(pubkey)
        else:
            raise TypeError('Unknown txin type', txin['type'])

        txin['preimage_script'] = script
        return script

    # def redeem_script(self, i: int):
    #     txin = self._inputs[i]
    #     inp = self._parent_psbt._parent.input_sections[i]
    #     _type = txin['type']
    #     if _type == 'coinbase':
    #         return txin['redeem_script']
    #
    #     if txin.get('redeem_script') is not None:
    #         return txin['redeem_script']
    #
    #     pubkeys = sorted(list(inp.bip32_derivation.keys()))
    #
    #     script = None
    #     if _type == 'p2pk':
    #         script = ''
    #     elif _type == 'p2sh':
    #         script = multisig_script(pubkeys, txin['num_sig'])
    #     elif _type == 'p2pkh':
    #         script = pubkeys[0]
    #     elif _type in ['p2wpkh', 'p2wsh']:
    #         script = self.preimage_script(txin)
    #     elif _type == 'p2wpkh-p2sh':
    #         pubkey = safe_parse_pubkey(pubkeys[0])
    #         script = bitcoin.p2wpkh_nested_script(pubkey)
    #     elif _type == 'p2wsh-p2sh':
    #         witness_script = self.preimage_script(txin)
    #         script = bitcoin.p2wsh_nested_script(witness_script)
    #     elif _type == 'address':
    #         script = bitcoin.address_to_script(txin['address'])
    #     elif _type == 'unknown':
    #         raise Exception('Cannot generate unknown script')
    #     return script

    def serialize_witness(self, i: int, estimate_size=False) -> str:
        txin = self._inputs[i]
        inp = self._parent_psbt._parent.input_sections[i]
        _type = txin['type']

        if not is_segwit_input(txin) and not is_input_value_needed(txin):
            return '00'
        if _type == 'coinbase':
            return txin['witness']

        # witness = txin.get('witness', None)
        witness = inp.final_scriptwitness
        if witness is None or estimate_size:
            if _type == 'address' and estimate_size:
                _type = guess_txintype_from_address(txin['address'])
            # TODO: estimate size 00 data
            pubkeys = sorted(list(inp.bip32_derivation.keys()))
            if estimate_size:
                signatures = [inp.partial_sig.get(pk, '00' * 0x48) for pk in pubkeys]
            else:
                signatures = [inp.partial_sig.get(pk,) for pk in pubkeys]
            if _type in ['p2wpkh', 'p2wpkh-p2sh']:
                witness = construct_witness([signatures[0], pubkeys[0]])
            elif _type in ['p2wsh', 'p2wsh-p2sh']:
                witness_script = multisig_script(pubkeys, txin['num_sig'])
                witness = construct_witness([0] + list(filter(None, signatures)) + [witness_script])
            else:
                witness = txin.get('witness', '00')

        return witness

    def estimated_witness_size(self):
        """Return an estimate of witness size in bytes."""
        estimate = not self._parent_psbt._parent.is_complete()
        if not self.is_segwit(guess_for_address=estimate):
            return 0
        inputs = self.inputs()
        witness = ''.join(self.serialize_witness(i, estimate) for i, txin in enumerate(inputs))
        witness_size = len(witness) // 2 + 2  # include marker and flag
        return witness_size

    def get_siglist(self, inp, txin, estimate_size):
        keys = sorted(inp.bip32_derivation.keys())
        pubkeys = sorted(list(inp.bip32_derivation.keys()))
        num_sig = txin.get('num_sig', 1)

        if estimate_size:
            pubkey_size = 0x21
            pk_list = ['00' * pubkey_size] * max(len(keys), txin.get('_n', 0))
            sig_list = ["00" * 0x48] * num_sig
        else:
            pk_list = keys
            sig_list = [inp.partial_sig.get(key, '') for key in keys]

        return pk_list, sig_list

    def input_script(self, txin: dict, estimate_size=False, attach_signatures=False):
        i = self._inputs.index(txin)
        if i < 0:
            raise Exception('input not found')

        _type = txin['type']
        if _type == 'coinbase':
            return txin['scriptSig']
        if not self._parent_psbt:
            return ''
        inp = self._parent_psbt._parent.input_sections[i]
        if inp.final_scriptsig:
            return inp.final_scriptsig

        pubkeys, sig_list = self.get_siglist(inp, txin, estimate_size)

        if attach_signatures:
            script = ''.join(push_script(sig) for sig in sig_list if sig)
        else:
            script = ''

        if _type == 'address' and estimate_size:
            _type = guess_txintype_from_address(txin['address'])

        if _type == 'p2pk':
            pass
        elif _type == 'p2sh':
            # put op_0 before script
            if attach_signatures:
                script = '00' + script
            # redeem_script = multisig_script(pubkeys, txin['num_sig'])
            redeem_script = inp.redeem_script
            script += push_script(redeem_script)
        elif _type == 'p2pkh':
            script += push_script(pubkeys[0])
        elif _type in ['p2wpkh', 'p2wsh']:
            return ''
        elif _type == 'p2wpkh-p2sh':
            scriptSig = bitcoin.p2wpkh_nested_script(pubkeys[0])
            return push_script(scriptSig)
        elif _type == 'p2wsh-p2sh':
            if estimate_size:
                witness_script = ''
            else:
                witness_script = self.preimage_script(txin)
            scriptSig = bitcoin.p2wsh_nested_script(witness_script)
            return push_script(scriptSig)
        elif _type == 'address':
            raise NotImplementedError('deprecated')
            return 'ff00' + push_script(pubkeys[0])  # fd extended pubkey
        elif _type == 'unknown':
            # raise NotImplementedError('deprecated')
            return txin.get('scriptSig') or inp.final_scriptsig or ''
        return script

    def serialize_to_network(self, estimate_size=False, witness=True, attach_signatures=False) -> str:
        if estimate_size:
            attach_signatures = True
        nVersion = int_to_hex(self.version, 4)
        nLocktime = int_to_hex(self.locktime, 4)
        inputs = self.inputs()
        outputs = self.outputs()
        if attach_signatures:

            serialized_inputs = []
            for i, txin in enumerate(inputs):
                script = self.input_script(txin, estimate_size=estimate_size, attach_signatures=True)
                ser = serialize_input(txin, script)
                serialized_inputs.append(ser)
            txins = var_int(len(inputs)) + ''.join(serialized_inputs)
        else:
            txins = var_int(len(inputs)) + ''.join(serialize_input(txin, '') for txin in inputs)  # no script sig
        txouts = var_int(len(outputs)) + ''.join(serialize_output(o) for o in outputs)
        use_segwit_ser_for_estimate_size = estimate_size and self.is_segwit(guess_for_address=True)
        use_segwit_ser_for_actual_use = not estimate_size and (
                self.is_segwit() or any(txin['type'] == 'address' for txin in inputs))
        use_segwit_ser = use_segwit_ser_for_estimate_size or use_segwit_ser_for_actual_use
        if witness and use_segwit_ser:
            marker = '00'
            flag = '01'
            if estimate_size:
                witness = ''.join(self.serialize_witness(i, True) for i, _ in enumerate(self.inputs()))
            else:
                witness = ''.join(inp.final_scriptwitness or '' for inp in self._parent_psbt._parent.input_sections)
            return nVersion + marker + flag + txins + txouts + witness + nLocktime
        else:
            return nVersion + txins + txouts + nLocktime

    def BIP69_sort(self, inputs=True, outputs=True):
        # disable sort, must be sorted from corresponding parent psbt
        raise NotImplementedError('Use parent PSBT sort function')

    def txid(self):
        all_segwit = all(is_segwit_input(x) for x in self.inputs())
        if not all_segwit and not self.is_complete():
            return None
        ser = self.serialize_to_network(witness=False, attach_signatures=True)
        return bh2u(sha256d(bfh(ser))[::-1])

    def is_segwit(self, guess_for_address=False):
        return any(is_segwit_input(x, guess_for_address=guess_for_address) for x in self.inputs())

    def is_complete(self):
        if self._parent_psbt._parent.is_complete():
            self.raw = self._parent_psbt._parent.serialize_final()
            return True
        return False


def tx_to_immutable(tx: Transaction) -> ImmutableTransaction:
    return ImmutableTransaction.from_io(tx.inputs(), tx.outputs(), locktime=tx.locktime, version=tx.version)


def tx_from_str(txt):
    "json or raw hexadecimal"
    import json
    txt = txt.strip()
    if not txt:
        raise ValueError("empty string")
    try:
        bfh(txt)
        is_hex = True
    except:
        is_hex = False
        try:
            txt = bh2u(base64.b64decode(txt))
            return txt
        except:
            pass

    if is_hex:
        return txt
    tx_dict = json.loads(str(txt))
    assert "hex" in tx_dict.keys()
    return tx_dict["hex"]
