# Copyright (C) 2026 The Electrum developers
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://www.opensource.org/licenses/mit-license.php
"""Provider-neutral Taproot swap contracts and cooperative signing."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional

from electrum_ecc import ECPrivkey, ECPubkey, InvalidECPointException, musig

from .bitcoin import (
    LEAF_VERSION_TAPSCRIPT,
    NLOCKTIME_BLOCKHEIGHT_MAX,
    TapTree,
    construct_script,
    control_block_for_taproot_script_spend,
    opcodes,
    script_num_to_bytes,
    script_to_address,
    taproot_output_script,
    taproot_tree_helper,
    taproot_tweak_hash,
)
from .crypto import ripemd


__all__ = (
    "MuSig2Session",
    "SwapDirection",
    "SwapLeaf",
    "TaprootSwapContract",
)

_SESSION_INTERNAL = object()


class SwapDirection(Enum):
    """Swap direction from the user's perspective."""

    FORWARD = "forward"  # user funds, provider claims, user refunds
    REVERSE = "reverse"  # provider funds, user claims, provider refunds


class SwapLeaf(Enum):
    CLAIM = "claim"
    REFUND = "refund"


def _require_bytes(value: object, *, name: str, length: int) -> bytes:
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes")
    if len(value) != length:
        raise ValueError(f"{name} must be {length} bytes")
    return value


def _validate_pubkey(pubkey: object, *, name: str) -> bytes:
    pubkey = _require_bytes(pubkey, name=name, length=33)
    if pubkey[0] not in (0x02, 0x03):
        raise ValueError(f"{name} must be a compressed public key")
    try:
        ECPubkey(pubkey)
    except InvalidECPointException as e:
        raise ValueError(f"{name} is not a valid public key") from e
    return pubkey


@dataclass(frozen=True)
class TaprootSwapContract:
    """Canonical two-leaf, single-provider Taproot swap contract.

    MuSig key aggregation is always ordered provider first, user second. Leaf
    ownership follows :class:`SwapDirection` and cannot be supplied separately.
    """

    direction: SwapDirection
    payment_hash: bytes
    locktime: int
    provider_pubkey: bytes
    user_pubkey: bytes

    def __post_init__(self) -> None:
        if type(self.direction) is not SwapDirection:
            raise TypeError("direction must be a SwapDirection")
        _require_bytes(self.payment_hash, name="payment_hash", length=32)
        if type(self.locktime) is not int:
            raise TypeError("locktime must be int")
        if not 0 < self.locktime <= NLOCKTIME_BLOCKHEIGHT_MAX:
            raise ValueError("locktime must be a positive block height")
        _validate_pubkey(self.provider_pubkey, name="provider_pubkey")
        _validate_pubkey(self.user_pubkey, name="user_pubkey")
        if self.provider_pubkey[1:] == self.user_pubkey[1:]:
            raise ValueError("provider and user x-only keys must be distinct")

    @property
    def claim_pubkey(self) -> bytes:
        if self.direction is SwapDirection.FORWARD:
            return self.provider_pubkey
        return self.user_pubkey

    @property
    def refund_pubkey(self) -> bytes:
        if self.direction is SwapDirection.FORWARD:
            return self.user_pubkey
        return self.provider_pubkey

    @property
    def claim_leaf_script(self) -> bytes:
        items = []
        if self.direction is SwapDirection.REVERSE:
            items.extend((opcodes.OP_SIZE, 32, opcodes.OP_EQUALVERIFY))
        items.extend((
            opcodes.OP_HASH160,
            ripemd(self.payment_hash),
            opcodes.OP_EQUALVERIFY,
            self.claim_pubkey[1:],
            opcodes.OP_CHECKSIG,
        ))
        return construct_script(items)

    @property
    def refund_leaf_script(self) -> bytes:
        return construct_script((
            self.refund_pubkey[1:],
            opcodes.OP_CHECKSIGVERIFY,
            script_num_to_bytes(self.locktime),
            opcodes.OP_CHECKLOCKTIMEVERIFY,
        ))

    @property
    def tap_tree(self) -> TapTree:
        return [
            (LEAF_VERSION_TAPSCRIPT, self.claim_leaf_script),
            (LEAF_VERSION_TAPSCRIPT, self.refund_leaf_script),
        ]

    @property
    def merkle_root(self) -> bytes:
        _, root = taproot_tree_helper(self.tap_tree)
        return root

    def _keyagg_cache(self) -> musig.KeyAggCache:
        return musig.KeyAggCache.from_pubkeys(
            [self.provider_pubkey, self.user_pubkey]
        )

    @property
    def internal_pubkey(self) -> bytes:
        return self._keyagg_cache().aggregate_xonly_pubkey()

    @property
    def output_script(self) -> bytes:
        return taproot_output_script(
            self.internal_pubkey, script_tree=self.tap_tree
        )

    def address(self, *, net=None) -> str:
        address = script_to_address(self.output_script, net=net)
        if address is None:
            raise RuntimeError("could not derive Taproot swap address")
        return address

    def script_path(self, leaf: SwapLeaf) -> tuple[bytes, bytes]:
        """Return the leaf script and control block for a unilateral spend."""
        if type(leaf) is not SwapLeaf:
            raise TypeError("leaf must be a SwapLeaf")
        return control_block_for_taproot_script_spend(
            internal_pubkey=self.internal_pubkey,
            script_tree=self.tap_tree,
            script_num=0 if leaf is SwapLeaf.CLAIM else 1,
        )

    def serialized_tree(self) -> dict[str, dict[str, int | str]]:
        return {
            "claimLeaf": {
                "version": LEAF_VERSION_TAPSCRIPT,
                "output": self.claim_leaf_script.hex(),
            },
            "refundLeaf": {
                "version": LEAF_VERSION_TAPSCRIPT,
                "output": self.refund_leaf_script.hex(),
            },
        }

    def validate_provider_data(
        self,
        *,
        serialized_tree: object,
        address: str,
        net=None,
    ) -> None:
        """Validate provider data against this contract's full semantics."""
        if type(serialized_tree) is not dict:
            raise ValueError("swap tree must be an object")
        expected_scripts = {
            "claimLeaf": self.claim_leaf_script,
            "refundLeaf": self.refund_leaf_script,
        }
        if set(serialized_tree) != set(expected_scripts):
            raise ValueError(
                "swap tree must contain only claimLeaf and refundLeaf"
            )
        for name, expected_script in expected_scripts.items():
            leaf = serialized_tree[name]
            if type(leaf) is not dict:
                raise ValueError(f"{name} must be an object")
            if set(leaf) != {"version", "output"}:
                raise ValueError(
                    f"{name} must contain only version and output"
                )
            if leaf["version"] != LEAF_VERSION_TAPSCRIPT:
                raise ValueError(f"{name} has an unsupported tapleaf version")
            output = leaf["output"]
            if not isinstance(output, str):
                raise ValueError(f"{name} output must be hex")
            if len(output) > 20_000:
                raise ValueError(f"{name} script exceeds 10,000 bytes")
            try:
                script = bytes.fromhex(output)
            except ValueError as e:
                raise ValueError(f"{name} output must be hex") from e
            if script != expected_script:
                raise ValueError(
                    f"{name} does not match the expected contract"
                )

        if not isinstance(address, str):
            raise TypeError("address must be str")
        if address != self.address(net=net):
            raise ValueError(
                "swap address does not match the expected contract"
            )


class MuSig2Session:
    """One participant's single-message cooperative MuSig2 signing session."""

    def __init__(
        self,
        *,
        contract: TaprootSwapContract,
        local_seckey: bytes,
        local_pubkey: bytes,
        counterparty_pubkey: bytes,
        msg32: bytes,
        keyagg_cache: musig.KeyAggCache,
        secnonce: musig.SecNonce,
        pubnonce: musig.PubNonce,
        _token: object = None,
    ) -> None:
        if _token is not _SESSION_INTERNAL:
            raise TypeError(
                "MuSig2Session instances must be created with create"
            )
        self._contract = contract
        self._local_seckey: Optional[bytes] = local_seckey
        self._local_pubkey = local_pubkey
        self._counterparty_pubkey = counterparty_pubkey
        self._msg32 = msg32
        self._cache = keyagg_cache
        self._secnonce: Optional[musig.SecNonce] = secnonce
        self._pubnonce = pubnonce
        self._counterparty_pubnonce: Optional[musig.PubNonce] = None
        self._session: Optional[musig.Session] = None
        self._local_partial_sig: Optional[musig.PartialSig] = None
        self._aggregate_signature: Optional[bytes] = None

    @classmethod
    def create(
        cls,
        *,
        contract: TaprootSwapContract,
        local_seckey: bytes,
        msg32: bytes,
        session_id32: Optional[bytes] = None,
    ) -> "MuSig2Session":
        if type(contract) is not TaprootSwapContract:
            raise TypeError("contract must be a TaprootSwapContract")
        local_seckey = _require_bytes(
            local_seckey, name="local_seckey", length=32
        )
        msg32 = _require_bytes(msg32, name="msg32", length=32)
        if session_id32 is not None:
            session_id32 = _require_bytes(
                session_id32, name="session_id32", length=32
            )
        try:
            local_pubkey = ECPrivkey(local_seckey).get_public_key_bytes(
                compressed=True
            )
        except InvalidECPointException as e:
            raise ValueError(
                "local_seckey is not a valid secret scalar"
            ) from e
        if local_pubkey == contract.provider_pubkey:
            counterparty_pubkey = contract.user_pubkey
        elif local_pubkey == contract.user_pubkey:
            counterparty_pubkey = contract.provider_pubkey
        else:
            raise ValueError(
                "local_seckey does not belong to the swap contract"
            )

        cache = contract._keyagg_cache()
        cache.apply_xonly_tweak(
            taproot_tweak_hash(
                cache.aggregate_xonly_pubkey(), contract.merkle_root
            )
        )
        secnonce, pubnonce = musig.nonce_gen(
            pubkey=local_pubkey,
            seckey=local_seckey,
            msg32=msg32,
            keyagg_cache=cache,
            extra_input32=session_id32,
        )
        return cls(
            contract=contract,
            local_seckey=local_seckey,
            local_pubkey=local_pubkey,
            counterparty_pubkey=counterparty_pubkey,
            msg32=msg32,
            keyagg_cache=cache,
            secnonce=secnonce,
            pubnonce=pubnonce,
            _token=_SESSION_INTERNAL,
        )

    @property
    def public_nonce(self) -> bytes:
        return self._pubnonce.to_bytes()

    def sign_partial(self, counterparty_public_nonce: bytes) -> bytes:
        """Create one partial signature and irrevocably consume the nonce."""
        if self._session is not None:
            raise RuntimeError("this MuSig2 session has already signed")
        counterparty = musig.PubNonce(counterparty_public_nonce)
        if self._local_pubkey == self._contract.provider_pubkey:
            pubnonces = [self._pubnonce, counterparty]
        else:
            pubnonces = [counterparty, self._pubnonce]
        session = musig.nonce_process(
            aggnonce=musig.nonce_agg(pubnonces),
            msg32=self._msg32,
            keyagg_cache=self._cache,
        )
        self._counterparty_pubnonce = counterparty
        self._session = session
        secnonce, self._secnonce = self._secnonce, None
        local_seckey, self._local_seckey = self._local_seckey, None
        assert secnonce is not None
        assert local_seckey is not None
        try:
            partial_sig = musig.partial_sign(
                secnonce=secnonce,
                seckey=local_seckey,
                keyagg_cache=self._cache,
                session=session,
            )
        finally:
            del secnonce, local_seckey
        self._local_partial_sig = partial_sig
        return partial_sig.to_bytes()

    def aggregate(self, counterparty_partial_signature: bytes) -> bytes:
        """Verify and aggregate the two partials into a BIP340 signature."""
        if self._aggregate_signature is not None:
            raise RuntimeError("this MuSig2 session has already aggregated")
        if (
            self._session is None
            or self._counterparty_pubnonce is None
            or self._local_partial_sig is None
        ):
            raise RuntimeError("sign_partial must be called before aggregate")
        counterparty_partial = musig.PartialSig(counterparty_partial_signature)
        if not musig.partial_sig_verify(
            partial_sig=counterparty_partial,
            pubnonce=self._counterparty_pubnonce,
            pubkey=self._counterparty_pubkey,
            keyagg_cache=self._cache,
            session=self._session,
        ):
            raise ValueError("counterparty partial signature is invalid")

        if self._local_pubkey == self._contract.provider_pubkey:
            partials = [self._local_partial_sig, counterparty_partial]
        else:
            partials = [counterparty_partial, self._local_partial_sig]
        signature = musig.partial_sig_agg(
            session=self._session, partial_sigs=partials
        )
        output_pubkey = ECPubkey(b"\x02" + self._contract.output_script[2:])
        if not output_pubkey.schnorr_verify(signature, self._msg32):
            raise ValueError(
                "aggregate signature does not verify for the swap output"
            )
        self._aggregate_signature = signature
        return signature
