from collections import defaultdict

from electrum_ecc import ECPubkey, ECPrivkey
from electrum_ecc.util import bip340_tagged_hash

from . import segwit_addr, constants
from .crypto import sha256
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .transaction import TxOutpoint
import electrum_ecc as ecc

SILENT_PAYMENT_DUMMY_SPK = bytes(2) + sha256("SilentPaymentDummySpk") # match length of taproot output script

class SilentPaymentUnsupportedWalletException(Exception): pass

class SilentPaymentAddress:
    """
        Takes a silent payment address and decodes into keys. Raises if address is invalid.
    """
    def __init__(self, address: str, *, net=None):
        if net is None: net = constants.net
        self._encoded = address
        self._B_Scan, self._B_Spend = _decode_silent_payment_addr(net.BIP352_HRP, address)

    @property
    def encoded(self) -> str:
        return self._encoded

    @property
    def B_Scan(self) -> ecc.ECPubkey:
        return self._B_Scan

    @property
    def B_Spend(self) -> ecc.ECPubkey:
        return self._B_Spend

    def __eq__(self, other):
        if not isinstance(other, SilentPaymentAddress):
            return NotImplemented
        return self.encoded == other.encoded

    def __hash__(self):
        return hash(self.encoded)

class SilentPaymentException(Exception):
    def __init__(self, message: str):
        self.message = message
        super().__init__(message)

class SilentPaymentReuseException(SilentPaymentException):
    def __init__(self, reused_address: str):
        short_addr = reused_address[:8] + "…" + reused_address[-8:]
        message = (
            f"Detected reuse of a previously derived silent payment address: ({short_addr})\n\n"
            f"Never send funds to an address that was previously derived from a Silent Payment address. "
            f"Doing so can lead to loss of funds, as these addresses are intended to be single-use and unlinkable."
        )
        super().__init__(message)

class SilentPaymentDerivationFailure(SilentPaymentException):
    def __init__(self):
        message = (
            "Unable to complete silent payment derivation due to an extremely rare edge case.\n\n"
            "Try using a different set of coins. You can adjust the inputs manually using coin control."
        )
        super().__init__(message)

class SilentPaymentInputsNotOwnedException(SilentPaymentException):
    def __init__(self):
        msg = (
            "Silent Payment derivation failed because one or more transaction inputs "
            "do not belong to this wallet.\n\n"
            f"To make Silent Payments, all transaction inputs must be owned by this wallet."
        )
        super().__init__(msg)

def create_silent_payment_outputs(input_privkeys: list[ECPrivkey],
                                  outpoints: list['TxOutpoint'],
                                  recipients: list[SilentPaymentAddress],
                                  ) -> dict[SilentPaymentAddress, list[bytes]]:
    """
    Derives silent payment taproot scriptPubKeys for a list of recipients.

    Args:
        input_privkeys (list[ECPrivkey]): The private keys corresponding to the transaction inputs.
        outpoints (list[TxOutpoint]): The transaction outpoints used for shared secret derivation.
        recipients (list[SilentPaymentAddress]): The recipient silent payment addresses.

    Returns:
        dict[SilentPaymentAddress, list[bytes]]: A mapping of recipients to their corresponding
        derived taproot scriptPubKeys

    Raises:
        ValueError: If `input_privkeys`, `outpoints`, or `recipients` are empty.
        SilentPaymentDerivationFailure: If the sum of input private keys is zero (negligible probability).

    Warning:
        This function does **not** handle Taproot key negation. The caller is responsible for
        negating any private keys corresponding to Taproot inputs, if required.
    """
    for name, value in [("input_privkeys", input_privkeys), ("outpoints", outpoints), ("recipients", recipients)]:
        if not value:
            raise ValueError(f"{name} must not be empty")

    lowest_outpoint: bytes = min([o.serialize_to_network() for o in outpoints])
    a_sum: int = sum([ecc.string_to_number(pk.get_secret_bytes()) for pk in input_privkeys]) % ecc.CURVE_ORDER
    # This edge-case extremely unlikely, but still has to be taken care of.
    if a_sum == 0: raise SilentPaymentDerivationFailure()

    # electrum-ecc takes care of error handling in EC-Multiplication
    A_sum: ECPubkey = a_sum * ecc.GENERATOR

    input_hash = bip340_tagged_hash(b"BIP0352/Inputs", lowest_outpoint + A_sum.get_public_key_bytes())

    # store the sp_addr along with B_m so we can connect the calculated spk to the correct output later
    silent_payment_groups: dict[ECPubkey, list[tuple[ECPubkey, SilentPaymentAddress]]] = defaultdict(list)

    for recipient in recipients:
        B_Scan, B_m = recipient.B_Scan, recipient.B_Spend
        silent_payment_groups[B_Scan].append((B_m, recipient))

    outputs_dict: dict[SilentPaymentAddress, list[bytes]] = defaultdict(list)

    for B_scan, B_m_values in silent_payment_groups.items():
        ecdh_shared_secret = ecc.string_to_number(input_hash) * a_sum * B_scan
        k = 0
        for B_m, sp_addr in B_m_values:
            t_k = bip340_tagged_hash(b"BIP0352/SharedSecret",
                                     ecdh_shared_secret.get_public_key_bytes() + k.to_bytes(4, "big"))
            # ECPrivKey(t_k) checks (1 < t_k < n), multiplies it by G and behaves like a pub key for addition
            P_km = B_m + ECPrivkey(t_k) # B_m + t_k * G
            # append spk and corresponding output index in transaction
            taproot_spk = b'\x51\x20' + P_km.get_public_key_bytes()[1:]
            outputs_dict[sp_addr].append(taproot_spk)
            k += 1

    return outputs_dict


def is_silent_payment_address(addr: str, *, net=None) -> bool:
    if net is None: net = constants.net
    try:
        _decode_silent_payment_addr(net.BIP352_HRP, addr)
        return True
    except Exception:
        return False

def _decode_silent_payment_addr(hrp: str, address: str) -> tuple[ecc.ECPubkey, ecc.ECPubkey]:
    """Decodes a Silent Payment address (version 0 only) and returns (B_scan, B_spend) pubkeys."""
    dec = segwit_addr.bech32_decode(address, ignore_long_length=True)
    if dec.hrp != hrp or dec.data is None:
        raise ValueError(f"Invalid HRP or malformed silent payment address: {address}")

    version = dec.data[0]
    decoded = segwit_addr.convertbits(dec.data[1:], 5, 8, False)
    if decoded is None:
        raise ValueError("Bech32 conversion failed")

    if version == 0:
        if len(decoded) != 66:
            raise ValueError("Silent payment v0 must contain exactly 66 bytes")
    elif 1 <= version <= 30:
        raise NotImplementedError(f"Silent payment version {version} not yet supported")
    elif version == 31:
        raise ValueError("Silent payment version 31 is reserved and invalid")
    else:
        raise ValueError(f"Unknown silent payment version: {version}")

    try:
        B_scan = ecc.ECPubkey(bytes(decoded[:33]))
        B_spend = ecc.ECPubkey(bytes(decoded[33:]))
    except Exception as e:
        raise ValueError(f"Invalid public key(s) in silent payment address: {e}")

    return B_scan, B_spend


