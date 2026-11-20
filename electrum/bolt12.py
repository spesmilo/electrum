# -*- coding: utf-8 -*-
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2025 The Electrum developers
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

import copy
import io
import time
from dataclasses import dataclass, field, asdict, fields
from functools import cached_property
import re
from typing import Optional, Tuple, Iterable, Type, TypeVar, Any, ClassVar
from abc import ABC, abstractmethod

import electrum_ecc as ecc

from . import constants
from .util import chunks
from .lnmsg import OnionWireSerializer, write_bigsize_int, read_bigsize_int
from .lnutil import LnFeatures, validate_features, MIN_FINAL_CLTV_DELTA_ACCEPTED, NBLOCK_CLTV_DELTA_TOO_FAR_INTO_FUTURE, LnFeatureContexts
from .onion_message import BlindedPath, BlindedPayInfo
from .segwit_addr import (
    bech32_decode, convertbits, bech32_encode, Encoding, INVALID_BECH32,
    CHARSET as BECH32_CHARSET, encode_segwit_address,
)


DEFAULT_INVOICE_EXPIRY = 7200


TBOLT12Base = TypeVar("TBOLT12Base", bound="BOLT12Base")


@dataclass(frozen=True, kw_only=True)
class BOLT12Base(ABC):
    tlv_stream_name: ClassVar[str]
    signing_key_path: ClassVar[Optional[tuple[str, ...]]]
    hrp: ClassVar[str]  # human-readable part of the bech32 encoded string
    _unknown_fields: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def decode(cls: Type[TBOLT12Base], data: str | bytes) -> TBOLT12Base:
        d = bolt12_bech32_to_bytes(data) if isinstance(data, str) else data
        with io.BytesIO(d) as fd:
            protocol_dict = OnionWireSerializer.read_tlv_stream(
                fd=fd,
                tlv_stream_name=cls.tlv_stream_name,
                signing_key_path=cls.signing_key_path,
            )
        return cls.deserialize(protocol_dict)

    def encode(self, *, signing_key: bytes = None, as_bech32: bool = False) -> str | bytes:
        if self.signing_key_path:
            # if no signing_key is passed we keep the existing signature, else a new one is created
            assert signing_key or any(f.name.endswith('_signature') and getattr(self, f.name) for f in fields(self))
        else:
            assert signing_key is None, "cannot sign offer"

        data = self.serialize(with_signature=False if signing_key else True)
        with io.BytesIO() as fd:
            OnionWireSerializer.write_tlv_stream(
                fd=fd,
                tlv_stream_name=self.tlv_stream_name,
                signing_key=signing_key,
                **data,
            )
            if not as_bech32:
                return fd.getvalue()
            return bolt12_tlv_bytes_to_bech32(fd.getvalue(), type(self))

    _ENCODE_MAP = {}
    def serialize(self, *, with_signature: bool = False) -> dict:
        protocol_dict = copy.deepcopy(self._unknown_fields)
        for f in fields(self):
            if f.name.startswith('_'):
                continue
            if f.name.endswith('_signature') and not with_signature:
                continue
            value = getattr(self, f.name)
            if value is None:
                continue
            if isinstance(value, LnFeatures) and value == LnFeatures(0):
                continue
            key = 'signature' if f.name.endswith('_signature') else f.name
            protocol_dict[key] = self._ENCODE_MAP[f.name](value)
        return protocol_dict

    @classmethod
    @abstractmethod
    def deserialize(cls: Type[TBOLT12Base], protocol_dict: dict) -> TBOLT12Base:
        pass

    @property
    def is_expired(self) -> bool:
        now = int(time.time())
        expiry_time = None
        if type(self) == BOLT12Invoice:
            expiry_time = self.invoice_created_at + self.invoice_relative_expiry
        elif type(self) == BOLT12Offer:
            expiry_time = self.offer_absolute_expiry
        return now > expiry_time if expiry_time is not None else False


@dataclass(frozen=True, kw_only=True)
class BOLT12Offer(BOLT12Base):
    """
    https://github.com/lightning/bolts/blob/34455ffe28b308dd7ac7552234d565890af8605b/12-offer-encoding.md?plain=1#L182
    """
    tlv_stream_name = 'offer'
    signing_key_path = None  # offers are not signed
    hrp = 'lno'

    offer_features: Optional[LnFeatures] = None
    offer_chains: Optional[list[bytes]] = None
    offer_metadata: Optional[bytes] = None
    offer_currency: Optional[str] = None
    offer_amount: Optional[int] = None
    offer_description: Optional[str] = None
    offer_absolute_expiry: Optional[int] = None
    offer_paths: Optional[tuple[BlindedPath, ...]] = None
    offer_issuer: Optional[str] = None
    offer_quantity_max: Optional[int] = None
    offer_issuer_id: Optional[bytes] = None

    def __post_init__(self):
        # if the chain for the invoice is not solely bitcoin:
        # MUST specify offer_chains the offer is valid for.
        if not matches_our_chain(self.offer_chains):
            # instance might be offerless invreq, invreq __post_init__ chain check has priority
            if type(self) == BOLT12Offer and 'invreq_chain' not in self._unknown_fields:
                raise NoMatchingChainError()
        if self.offer_chains is not None and not self.offer_chains:
            raise ValueError('empty offer_chains')
        # if offer_features contains unknown even bits that are non-zero: MUST NOT respond to the offer
        if self.offer_features:
            validate_features(self.offer_features, context=LnFeatureContexts.BOLT12_OFFER)
        # if offer_amount is set and offer_description is not set: MUST NOT respond to the offer
        if self.offer_amount is not None:
            if self.offer_amount <= 0: # MUST set `offer_amount` greater than zero.
                raise ValueError(f"offer amount must be > 0")
            if self.offer_description is None:
                raise ValueError('missing offer_description, but has offer_amount')
        # if offer_currency is set and offer_amount is not set: MUST NOT respond to the offer
        if self.offer_currency is not None and self.offer_amount is None:
            raise ValueError('missing offer_amount, but has offer_currency')
        # if neither offer_issuer_id nor offer_paths are set: MUST NOT respond to the offer
        if not self.offer_issuer_id and not self.offer_paths:
            # instance can be offerless invreq, or instantiated in BOLT12InvoiceRequest.deserialize()
            if not getattr(self, 'invreq_payer_id', self._unknown_fields.get('invreq_payer_id')):
                raise ValueError('neither offer_issuer_id nor offer_paths are given')
        if self.offer_issuer_id is not None:
            ecc.ECPubkey(b=self.offer_issuer_id)

    @classmethod
    def deserialize(cls, o: dict) -> 'BOLT12Offer':
        o = copy.deepcopy(o)
        if (offer_features := o.pop('offer_features', {}).get('features')) is not None:
            offer_features = LnFeatures(int.from_bytes(offer_features, byteorder="big", signed=False))
        if (offer_chains := o.pop('offer_chains', {}).get('chains')) is not None:
            offer_chains = [chain for chain in chunks(offer_chains, 32)]
        if (offer_paths := o.pop('offer_paths', {}).get('paths')) is not None:
            offer_paths = tuple(BlindedPath.from_dict(p) for p in offer_paths)

        return BOLT12Offer(
            offer_chains=offer_chains,
            offer_metadata=o.pop('offer_metadata', {}).get('data'),
            offer_currency=o.pop('offer_currency', {}).get('iso4217'),
            offer_amount=o.pop('offer_amount', {}).get('amount'),
            offer_description=o.pop('offer_description', {}).get('description'),
            offer_features=offer_features,
            offer_absolute_expiry=o.pop('offer_absolute_expiry', {}).get('seconds_from_epoch'),
            offer_paths=offer_paths,
            offer_issuer=o.pop('offer_issuer', {}).get('issuer'),
            offer_quantity_max=o.pop('offer_quantity_max', {}).get('max'),
            offer_issuer_id=o.pop('offer_issuer_id', {}).get('id'),
            _unknown_fields=o,
        )

    _ENCODE_MAP = BOLT12Base._ENCODE_MAP | {
        'offer_chains': lambda v: {'chains': b''.join(v)},
        'offer_metadata': lambda v: {'data': v},
        'offer_currency': lambda v: {'iso4217': v},
        'offer_amount': lambda v: {'amount': v},
        'offer_description': lambda v: {'description': v},
        'offer_features': lambda v: {'features': v.to_tlv_bytes()},
        'offer_absolute_expiry': lambda v: {'seconds_from_epoch': v},
        'offer_paths': lambda v: {'paths': [asdict(p) for p in v]},
        'offer_issuer': lambda v: {'issuer': v},
        'offer_quantity_max': lambda v: {'max': v},
        'offer_issuer_id': lambda v: {'id': v},
    }


@dataclass(frozen=True, kw_only=True)
class BOLT12InvoiceRequest(BOLT12Offer):
    """
    https://github.com/lightning/bolts/blob/34455ffe28b308dd7ac7552234d565890af8605b/12-offer-encoding.md?plain=1#L357
    """
    tlv_stream_name = 'invoice_request'
    signing_key_path = ('invreq_payer_id', 'key')
    hrp = 'lnr'

    invreq_metadata: bytes
    invreq_chain: Optional[bytes] = None
    invreq_amount: Optional[int] = None
    invreq_features: Optional[LnFeatures] = None
    invreq_quantity: Optional[int] = None
    invreq_payer_id: bytes
    invreq_payer_note: Optional[str] = None
    invreq_paths: Optional[tuple[BlindedPath, ...]] = None
    invreq_bip_353_name: Optional[Tuple[str, str]] = None  # name, domain
    invreq_signature: Optional[bytes] = None  # sig for incoming req is validated in OnionWireSerializer

    def __post_init__(self):
        super().__post_init__()
        # MUST reject the invoice request if invreq_payer_id or invreq_metadata are not present
        if not self.invreq_payer_id or not self.invreq_metadata:
            raise ValueError(f"{bool(self.invreq_payer_id)=} or {bool(self.invreq_metadata)=} missing")
        if self.invreq_features:
            validate_features(self.invreq_features, context=LnFeatureContexts.BOLT12_INVREQ)
        # if offer_issuer_id or offer_paths are present (response to an offer):
        if self.offer_issuer_id or self.offer_paths:
            # if offer_quantity_max is present:
            if self.offer_quantity_max is not None:
                if self.invreq_quantity is None:
                    # MUST reject the invoice request if there is no invreq_quantity field.
                    raise ValueError(f"{self.offer_quantity_max} is given but no invreq_quantity")
                # if offer_quantity_max is non-zero:
                if self.offer_quantity_max:
                    # MUST reject the invoice request if invreq_quantity is zero, OR greater than offer_quantity_max
                    if not self.invreq_quantity or self.invreq_quantity > self.offer_quantity_max:
                        raise ValueError(f"{self.invreq_quantity=} is zero or greater than offer_quantity_max")
            else:
                # otherwise: MUST reject the invoice request if there is an invreq_quantity field
                if self.invreq_quantity is not None:
                    raise ValueError("invreq_quantity given but no offer_quantity_max")
            # if offer_amount is present:
            if (expected_amount := self.offer_amount) is not None:
                # MUST calculate the expected amount using the offer_amount
                if self.offer_currency and self.offer_currency.upper() != 'BTC':
                    # TODO: if offer_currency is not the invreq_chain currency, convert to the invreq_chain currency
                    #  also adapt invoice_amount_msat property below
                    raise NotImplementedError("no fx conversion support yet, will this be used?")
                # if invreq_quantity is present, multiply by invreq_quantity.quantity
                if self.invreq_quantity:
                    # NOTE: not allowing self.invreq_quantity of 0 here, this seems unsafe?
                    expected_amount *= self.invreq_quantity
                # if invreq_amount is present
                if self.invreq_amount is not None:
                    # MUST reject the invoice request if invreq_amount.msat is less than the expected amount.
                    if self.invreq_amount < expected_amount:
                        raise ValueError(f"{self.invreq_amount=} < {expected_amount=}")
                    # MAY reject the invoice request if invreq_amount.msat greatly exceeds the expected amount
                    elif self.invreq_amount > int(expected_amount * 1.5):
                        raise ValueError(f"{self.invreq_amount=} > {int(expected_amount * 1.5)=}")
            # otherwise (no offer_amount):
            else:
                # MUST reject the invoice request if it does not contain invreq_amount
                if self.invreq_amount is None:
                    raise ValueError("no offer_amount and no invreq_amount")
        # otherwise (no offer_issuer_id or offer_paths, not a response to our offer):
        else:
            # MUST reject the invoice request if any of the following are present:
            if self.offer_chains is not None or self.offer_features is not None or self.offer_quantity_max is not None:
                raise ValueError("offer_chains, offer_features or offer_quantity_max present")
            # MUST reject the invoice request if invreq_amount is not present
            if self.invreq_amount is None:
                raise ValueError("invreq_amount missing")
        if not matches_our_chain([self.invreq_chain] if self.invreq_chain else None):
            raise NoMatchingChainError()
        if self.invreq_bip_353_name is not None:
            name, domain = self.invreq_bip_353_name
            if not validate_bip_353_name(name, domain):
                raise ValueError(f"invalid bip 353 name: {self.invreq_bip_353_name}")

    @property
    def invoice_amount_msat(self) -> int:
        # this relies on the __post_init__ validation
        if isinstance(self, BOLT12Invoice):
            return self.invoice_amount
        assert isinstance(self, BOLT12InvoiceRequest)
        if self.invreq_amount is not None:
            return self.invreq_amount
        expected_amount = self.offer_amount
        assert expected_amount is not None
        if self.invreq_quantity:
            expected_amount *= self.invreq_quantity
        return expected_amount

    @classmethod
    def deserialize(cls, ir: dict) -> 'BOLT12InvoiceRequest':
        ir = copy.deepcopy(ir)
        offer = BOLT12Offer.deserialize(ir)
        d = offer._unknown_fields
        if (invreq_features := d.pop('invreq_features', {}).get('features')) is not None:
            invreq_features = LnFeatures(int.from_bytes(invreq_features, byteorder="big", signed=False))
        if (invreq_paths := d.pop('invreq_paths', {}).get('paths')) is not None:
            invreq_paths = tuple(BlindedPath.from_dict(p) for p in invreq_paths)
        if invreq_bip_353_name := d.pop('invreq_bip_353_name', None):
            name, domain = invreq_bip_353_name['name'], invreq_bip_353_name['domain']
            invreq_bip_353_name = (name, domain)

        offer_fields = {f.name: getattr(offer, f.name) for f in fields(BOLT12Offer) if not f.name.startswith('_')}

        return BOLT12InvoiceRequest(
            **offer_fields,
            invreq_metadata=d.pop('invreq_metadata', {}).get('blob'),
            invreq_chain=d.pop('invreq_chain', {}).get('chain'),
            invreq_amount=d.pop('invreq_amount', {}).get('msat'),
            invreq_features=invreq_features,
            invreq_quantity=d.pop('invreq_quantity', {}).get('quantity'),
            invreq_payer_id=d.pop('invreq_payer_id', {}).get('key'),
            invreq_payer_note=d.pop('invreq_payer_note', {}).get('note'),
            invreq_paths=invreq_paths,
            invreq_bip_353_name=invreq_bip_353_name,
            invreq_signature=d.pop('signature', {}).get('sig'),
            _unknown_fields=d,
        )

    _ENCODE_MAP = BOLT12Offer._ENCODE_MAP | {
        'invreq_metadata': lambda v: {'blob': v},
        'invreq_chain': lambda v: {'chain': v},
        'invreq_amount': lambda v: {'msat': v},
        'invreq_features': lambda v: {'features': v.to_tlv_bytes()},
        'invreq_quantity': lambda v: {'quantity': v},
        'invreq_payer_id': lambda v: {'key': v},
        'invreq_payer_note': lambda v: {'note': v},
        'invreq_paths': lambda v: {'paths': [asdict(p) for p in v]},
        'invreq_bip_353_name': lambda v: {'name': v},
        'invreq_signature': lambda v: {'sig': v},
    }


@dataclass(frozen=True, kw_only=True)
class BOLT12Invoice(BOLT12InvoiceRequest):
    tlv_stream_name = 'invoice'
    signing_key_path = ('invoice_node_id', 'node_id')
    hrp = 'lni'

    invoice_paths: tuple[BlindedPath, ...]
    invoice_blindedpay: tuple[BlindedPayInfo, ...]
    invoice_created_at: int
    invoice_relative_expiry: int = DEFAULT_INVOICE_EXPIRY
    invoice_payment_hash: bytes
    invoice_amount: int
    invoice_fallbacks: Optional[tuple[dict]] = None
    invoice_features: Optional[LnFeatures] = None
    invoice_node_id: bytes
    invoice_signature: Optional[bytes] = None

    def __post_init__(self):
        super().__post_init__()
        # MUST reject the invoice if invoice_amount is not present
        if self.invoice_amount is None:
            raise ValueError("invoice_amount missing")
        # MUST reject the invoice if invoice_created_at is not present
        if self.invoice_created_at is None:
            raise ValueError("invoice_created_at missing")
        elif self.invoice_created_at > int(time.time()) + 100:
            raise ValueError(f"invoice_created_at in the future: {self.invoice_created_at}")
        # MUST reject the invoice if invoice_payment_hash is not present
        if self.invoice_payment_hash is None:
            raise ValueError("invoice_payment_hash missing")
        # MUST reject the invoice if invoice_node_id is not present
        if self.invoice_node_id is None:
            raise ValueError("invoice_node_id missing")
        if self.invoice_features:
            validate_features(self.invoice_features, context=LnFeatureContexts.BOLT12_INVOICE)
        # MUST reject the invoice if invoice_paths is not present or is empty
        if not self.invoice_paths:
            raise ValueError("invoice_paths missing or empty")
        # MUST reject the invoice if invoice_blindedpay is not present.
        if not self.invoice_blindedpay:
            raise ValueError("invoice_blindedpay missing or empty")
        # MUST reject the invoice if invoice_blindedpay does not contain exactly one blinded_payinfo per invoice_paths.blinded_path.
        if len(self.invoice_blindedpay) != len(self.invoice_paths):
            raise ValueError("invoice_blindedpay length mismatch")
        if all(payinfo.requires_unknown_mandatory_features for payinfo in self.invoice_blindedpay):
            # MUST reject the invoice if this leaves no usable paths.
            raise ValueError("no payinfo with sane features")
        if any(p.cltv_expiry_delta > NBLOCK_CLTV_DELTA_TOO_FAR_INTO_FUTURE for p in self.invoice_blindedpay):
            raise ValueError(f"Invoice wants us to risk locking funds for unreasonably long: {self.invoice_blindedpay}")
        # if offer_issuer_id is present (invoice_request for an offer):
        if self.offer_issuer_id is not None:
            # MUST reject the invoice if invoice_node_id is not equal to offer_issuer_id
            if self.invoice_node_id != self.offer_issuer_id:
                raise ValueError(f"{self.offer_issuer_id.hex()=} != {self.invoice_node_id.hex()=}")
        # otherwise, if offer_paths is present (invoice_request for an offer without id):
        elif self.offer_paths is not None:
            # MUST reject the invoice if invoice_node_id is not equal to the final blinded_node_id it sent the invoice request to.
            # NOTE: check is less strict than the spec, but doesn't require us to keep state to
            #       which blinded_node_id we sent the invreq to. The benefit is we can (always, implicitly) check it here.
            if not any(p.path[-1].blinded_node_id == self.invoice_node_id for p in self.offer_paths):
                raise ValueError(f"{self.invoice_node_id=} doesn't match any last blinded node id of offer paths")
        if self.invreq_amount is not None:
            if self.invoice_amount != self.invreq_amount:
                raise ValueError("invoice_amount != invreq_amount")

    @classmethod
    def deserialize(cls, inv: dict) -> 'BOLT12Invoice':
        inv = copy.deepcopy(inv)
        invoice_signature = inv.pop('signature', {}).get('sig')
        invreq = BOLT12InvoiceRequest.deserialize(inv)
        d = invreq._unknown_fields

        if (invoice_features := d.pop('invoice_features', {}).get('features')) is not None:
            invoice_features = LnFeatures(int.from_bytes(invoice_features, byteorder="big", signed=False))
        if (invoice_paths := d.pop('invoice_paths', {}).get('paths')) is not None:
            invoice_paths = tuple(BlindedPath.from_dict(p) for p in invoice_paths)
        if (invoice_blindedpay := d.pop('invoice_blindedpay', {}).get('payinfo')) is not None:
            invoice_blindedpay = tuple(BlindedPayInfo.from_dict(p) for p in invoice_blindedpay)
        if (invoice_fallbacks := d.pop('invoice_fallbacks', {}).get('fallbacks')) is not None:
            invoice_fallbacks = tuple(invoice_fallbacks)

        parent_fields = {f.name: getattr(invreq, f.name) for f in fields(BOLT12InvoiceRequest) if not f.name.startswith('_')}

        return BOLT12Invoice(
            **parent_fields,
            invoice_paths=invoice_paths,
            invoice_blindedpay=invoice_blindedpay,
            invoice_created_at=d.pop('invoice_created_at', {}).get('timestamp'),
            invoice_relative_expiry=d.pop('invoice_relative_expiry', {}).get('seconds_from_creation', DEFAULT_INVOICE_EXPIRY),
            invoice_payment_hash=d.pop('invoice_payment_hash', {}).get('payment_hash'),
            invoice_amount=d.pop('invoice_amount', {}).get('msat'),
            invoice_fallbacks=invoice_fallbacks,
            invoice_features=invoice_features,
            invoice_node_id=d.pop('invoice_node_id', {}).get('node_id'),
            invoice_signature=invoice_signature,
            _unknown_fields=d
        )

    _ENCODE_MAP = BOLT12InvoiceRequest._ENCODE_MAP | {
        'invoice_paths': lambda v: {'paths': [asdict(p) for p in v]},
        'invoice_blindedpay': lambda v: {'payinfo': [p.to_dict() for p in v]},
        'invoice_created_at': lambda v: {'timestamp': v},
        'invoice_relative_expiry': lambda v: {'seconds_from_creation': v},
        'invoice_payment_hash': lambda v: {'payment_hash': v},
        'invoice_amount': lambda v: {'msat': v},
        'invoice_fallbacks': lambda v: {'fallbacks': list(v)},
        'invoice_features': lambda v: {'features': v.to_tlv_bytes()},
        'invoice_node_id': lambda v: {'node_id': v},
        'invoice_signature': lambda v: {'sig': v},
    }

    @cached_property
    def fallback_address(self) -> Optional[str]:
        fallbacks = self.invoice_fallbacks or ()
        for fba in fallbacks:
            version_bytes, witprog = fba.get('version'), fba.get('address', b'')
            if version_bytes is not None and 2 <= len(witprog) <= 40:
                version = int.from_bytes(version_bytes, signed=False, byteorder='big')
                if version <= 16:
                    address = encode_segwit_address(constants.net.SEGWIT_HRP, version, witprog)
                    return address
        return None


def extract_shared_fields(source_instance: BOLT12Invoice | BOLT12InvoiceRequest, target_class: type[TBOLT12Base]) -> TBOLT12Base:
    """
    Allows to extract the fields of a subclass from the given instance,
    e.g. all Offer fields from a given invoice request instance.
    """
    return target_class(**{
        f.name: getattr(source_instance, f.name)
        for f in fields(target_class) if not f.name.startswith('_')
    })


def is_offer(data: str) -> bool:
    try:
        data = remove_bolt12_whitespace(data)
    except ValueError:
        return False
    d = bech32_decode(data, ignore_long_length=True, with_checksum=False)
    if d == INVALID_BECH32:
        return False
    return d.hrp == 'lno'


def matches_our_chain(chains: Optional[Iterable[bytes]]) -> bool:
    # chains is a 32 bytes record list stored in a single bytes object (see TODO above lnmsg._read_field)
    if not chains:
        # empty chains is indicative of only Bitcoin mainnet
        return True if constants.net == constants.BitcoinMainnet else False
    our_chain_hash = constants.net.rev_genesis_bytes()
    return our_chain_hash in chains


def bolt12_bech32_to_bytes(data: str) -> bytes:
    data = remove_bolt12_whitespace(data)
    d = bech32_decode(data, ignore_long_length=True, with_checksum=False)
    if d == INVALID_BECH32:
        raise ValueError(f"Failed to bech32 decode: {data[:64]=}...")
    d = convertbits(d.data, 5, 8, pad=False)
    if d is None:
        raise ValueError(f"Invalid bech32 data: {data[:64]=}...")
    return bytes(d)


def bolt12_tlv_bytes_to_bech32(bolt12_tlv: bytes, bolt12_type: type[BOLT12Base]) -> str:
    bech32_data = convertbits(list(bolt12_tlv), 8, 5, True)
    return bech32_encode(Encoding.BECH32, bolt12_type.hrp, bech32_data, with_checksum=False)


@dataclass(frozen=True, kw_only=True)
class BOLT12InvoicePathIDPayload:
    """
    Payment information embedded into the BOLT12Invoice blinded path's path_id so we can hand out invoices
    statelessly and reconstruct the full payment context when the actual HTLCs arrive.

    TODO: If this is too large some fields might need to be removed (esp the descriptions texts).
          We could also cache some less important things like the description
          in memory, assuming that the Invoice is usually paid right after being requested.
          A filled path_id payload can reach ~270 bytes realistically.
    """
    VERSION: ClassVar[bytes] = b'\x01'

    amount_msat: int
    created_at: int
    relative_expiry: int
    payment_preimage: bytes
    min_final_cltv_expiry_delta: int
    invoice_features: LnFeatures
    payer_id: bytes
    offer_metadata_digest: Optional[bytes] = None  # allows us to associate the payment with an offer (if we'd persist/cache offers)
    quantity: Optional[int] = None
    payer_note: Optional[str] = None
    description: Optional[str] = None

    def __post_init__(self):  # some sanity checks
        assert isinstance(self.payment_preimage, bytes) and len(self.payment_preimage) == 32, self.payment_preimage
        assert isinstance(self.payer_id, bytes) and len(self.payer_id) == 33, self.payer_id
        assert self.amount_msat and self.created_at and self.relative_expiry, (self.amount_msat, self.created_at, self.relative_expiry)
        assert self.min_final_cltv_expiry_delta >= MIN_FINAL_CLTV_DELTA_ACCEPTED
        validate_features(self.invoice_features, context=LnFeatureContexts.BOLT12_INVOICE)

    def encode(self) -> bytes:
        flags = 0
        if self.quantity is not None:
            assert self.quantity >= 0
            flags |= 0b0001
        if self.offer_metadata_digest is not None:  # we could truncate it to save some space?
            assert isinstance(self.offer_metadata_digest, bytes) and len(self.offer_metadata_digest) == 32
            flags |= 0b0010

        payer_note = self.payer_note[:64] if self.payer_note is not None else None
        description = self.description[:64] if self.description is not None else None
        if payer_note is not None:
            flags |= 0b0100
        if description is not None:
            flags |= 0b1000

        with io.BytesIO() as fd:
            fd.write(self.VERSION)
            fd.write(self.payment_preimage)
            fd.write(self.payer_id)
            fd.write(write_bigsize_int(self.amount_msat))
            fd.write(write_bigsize_int(self.created_at))
            fd.write(write_bigsize_int(self.relative_expiry))
            fd.write(write_bigsize_int(self.min_final_cltv_expiry_delta))
            features_bytes = self.invoice_features.to_tlv_bytes()
            fd.write(write_bigsize_int(len(features_bytes)))
            fd.write(features_bytes)
            fd.write(bytes([flags]))
            if self.quantity is not None:
                fd.write(write_bigsize_int(self.quantity))
            if self.offer_metadata_digest is not None:
                fd.write(self.offer_metadata_digest)
            if payer_note is not None:
                payer_note_bytes = payer_note.encode('utf-8')
                fd.write(write_bigsize_int(len(payer_note_bytes)))
                fd.write(payer_note_bytes)
            if description is not None:
                description_bytes = description.encode('utf-8')
                fd.write(write_bigsize_int(len(description_bytes)))
                fd.write(description_bytes)
            return fd.getvalue()

    @classmethod
    def decode(cls, data: bytes) -> 'BOLT12InvoicePathIDPayload':
        with io.BytesIO(data) as fd:
            version = fd.read(1)
            if version != cls.VERSION:
                raise ValueError(f"unsupported version: {version!r}")

            payment_preimage = fd.read(32)
            if len(payment_preimage) != 32:
                raise ValueError("path_id truncated: payment_preimage")
            payer_id = fd.read(33)
            if len(payer_id) != 33:
                raise ValueError("path_id truncated: payer_id")

            amount_msat = read_bigsize_int(fd)
            created_at = read_bigsize_int(fd)
            relative_expiry = read_bigsize_int(fd)
            min_final_cltv_expiry_delta = read_bigsize_int(fd)
            if not amount_msat or not created_at or not relative_expiry or not min_final_cltv_expiry_delta:
                raise ValueError("path_id truncated: amount_msat, created_at, relative_expiry or min_final_cltv_expiry_delta")

            features_len = read_bigsize_int(fd)
            if features_len is None:
                raise ValueError("path_id truncated: features_len")
            features_bytes = fd.read(features_len)
            if len(features_bytes) != features_len:
                raise ValueError("path_id truncated: invoice_features")
            invoice_features = LnFeatures(int.from_bytes(features_bytes, byteorder="big", signed=False))

            flags_byte = fd.read(1)
            if len(flags_byte) != 1:
                raise ValueError("path_id truncated: flags")
            flags = flags_byte[0]

            quantity: Optional[int] = None
            offer_metadata_digest: Optional[bytes] = None
            payer_note: Optional[str] = None
            description: Optional[str] = None

            if flags & 0b0001:
                quantity = read_bigsize_int(fd)
                if quantity is None:
                    raise ValueError("path_id truncated: quantity")
            if flags & 0b0010:
                offer_metadata_digest = fd.read(32)
                if len(offer_metadata_digest) != 32:
                    raise ValueError("path_id truncated: offer_metadata_digest")
            if flags & 0b0100:
                note_len = read_bigsize_int(fd)
                if note_len is None:
                    raise ValueError("path_id truncated: payer_note_len")
                note_bytes = fd.read(note_len)
                if len(note_bytes) != note_len:
                    raise ValueError("path_id truncated: payer_note")
                payer_note = note_bytes.decode('utf-8')
            if flags & 0b1000:
                desc_len = read_bigsize_int(fd)
                if desc_len is None:
                    raise ValueError("path_id truncated: description_len")
                desc_bytes = fd.read(desc_len)
                if len(desc_bytes) != desc_len:
                    raise ValueError("path_id truncated: description")
                description = desc_bytes.decode('utf-8')

            if fd.read(1):
                raise ValueError("trailing bytes in path_id?")

        return cls(
            amount_msat=amount_msat,
            created_at=created_at,
            relative_expiry=relative_expiry,
            payment_preimage=payment_preimage,
            min_final_cltv_expiry_delta=min_final_cltv_expiry_delta,
            invoice_features=invoice_features,
            payer_id=payer_id,
            offer_metadata_digest=offer_metadata_digest,
            quantity=quantity,
            payer_note=payer_note,
            description=description,
        )


# offer/request/invoice uses different chain than we do
class NoMatchingChainError(Exception): pass


# wraps invoice_error
class Bolt12InvoiceError(Exception):
    def __init__(self, msg: str, *, erroneous_field: Optional[int] = None, suggested_value: Optional[bytes] = None):
        assert msg
        assert suggested_value is None if erroneous_field is None else True

        super().__init__(msg)
        self.message = msg
        self.erroneous_field = erroneous_field
        self.suggested_value = suggested_value

    @classmethod
    def from_tlv(cls, tlv: bytes) -> 'Bolt12InvoiceError':
        try:
            with io.BytesIO(tlv) as fd:
                invoice_error = OnionWireSerializer.read_tlv_stream(fd=fd, tlv_stream_name='invoice_error')
        except Exception:
            return cls(msg="malformed invoice error")
        return cls(
            msg=invoice_error.get('error', {}).get('msg', "received invoice_error without message"),
            erroneous_field=invoice_error.get('erroneous_field', {}).get('tlv_fieldnum'),
            suggested_value=invoice_error.get('suggested_value', {}).get('value'),
        )

    def to_tlv(self):
        data = {'error': {'msg': self.message}}
        if self.erroneous_field is not None:
            data.update({'erroneous_field': {'tlv_fieldnum': self.erroneous_field}})
        if self.suggested_value is not None:
            data.update({'suggested_value': {'value': self.suggested_value}})
        with io.BytesIO() as fd:
            OnionWireSerializer.write_tlv_stream(fd=fd, tlv_stream_name='invoice_error', **data)
            return fd.getvalue()


def remove_bolt12_whitespace(bolt12_bech32: str) -> str:
    """
    Readers of a bolt12 string:
    if it encounters a + followed by zero or more whitespace characters between two bech32 characters:
        MUST remove the + and whitespace.
    """
    assert isinstance(bolt12_bech32, str)
    res = re.sub(
        r'(?<=[' + BECH32_CHARSET + r'])\+\s*(?=[' + BECH32_CHARSET + r'])',
        '',
        bolt12_bech32,
        flags=re.IGNORECASE,
    )
    if '+' in res:
        raise ValueError('Invalid bolt 12 whitespace')
    return res


def validate_bip_353_name(name: str, domain: str) -> bool:
    """
    MUST reject the (invoice request) if name or domain contain any bytes
    which are not 0-9, a-z, A-Z, -, _ or .
    """
    for s in (name, domain):
        if not re.match(r'^[a-zA-Z0-9._-]+$', s):
            return False
    return True
