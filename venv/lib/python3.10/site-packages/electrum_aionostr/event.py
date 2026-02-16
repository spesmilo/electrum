"""
forked from https://github.com/jeffthibault/python-nostr.git
"""
import copy
import dataclasses
import time
import functools
from enum import IntEnum
from hashlib import sha256
from typing import Optional

import electrum_ecc as ecc
from electrum_ecc import ECPrivkey, ECPubkey


try:
    import rapidjson

    loads = rapidjson.loads
    dumps = functools.partial(rapidjson.dumps, ensure_ascii=False)
except ImportError:
    import json

    loads = json.loads
    dumps = functools.partial(json.dumps, separators=(",", ":"), ensure_ascii=False)


class EventKind(IntEnum):
    SET_METADATA = 0
    TEXT_NOTE = 1
    RECOMMEND_RELAY = 2
    CONTACTS = 3
    ENCRYPTED_DIRECT_MESSAGE = 4
    DELETE = 5


class InvalidEvent(ValueError):
    pass


@dataclasses.dataclass(frozen=True, kw_only=True, slots=True)
class Event:
    id: Optional[str] = None
    pubkey: str
    content: str = ""
    created_at: int = dataclasses.field(default_factory=lambda: int(time.time()))
    kind: int = EventKind.TEXT_NOTE
    tags: list[list[str]] = dataclasses.field(default_factory=list)  # supposed to be immutable!
    sig: Optional[str] = None

    def __post_init__(self):
        if not isinstance(self.content, str):
            raise TypeError("'content' must be a str")
        if not (isinstance(self.pubkey, str) and len(self.pubkey) == 64):
            raise TypeError(f"got pubkey with unexpected type or len={len(self.pubkey)}, expected 64 char x-only hex")
        for inner_list in self.tags:
            if not all(isinstance(x, str) for x in inner_list):
                raise TypeError(f"tags must be list[list[str]]: {self.tags=!r}")
        if not isinstance(self.created_at, int):
            raise TypeError("'created_at' must be an int")
        if not isinstance(self.kind, int):
            raise TypeError("Argument 'kind' must be an int")
        if not (0 <= self.kind <= 65535):
            raise ValueError(f"event.kind out of range: {self.kind}")
        # id
        # note: we don't validate the original self.id, just always overwrite it
        computed_id = self.compute_id(
            pubkey=self.pubkey,
            created_at=self.created_at,
            kind=self.kind,
            tags=self.tags,
            content=self.content,
        )
        object.__setattr__(self, 'id', computed_id)
        # sigcheck.
        # We enforce sig is either None or a valid signature.
        if self.sig is not None:
            if not (isinstance(self.sig, str) and len(self.sig) == 128):
                raise TypeError(f"got sig with unexpected type or len={len(self.sig)}, expected 128 char hex")
            if not self.verify():
                raise InvalidEvent("invalid signature")

    @property
    def id_bytes(self):
        return bytes.fromhex(self.id)

    @property
    def is_ephemeral(self):
        return 20000 <= self.kind < 30000

    @property
    def is_replaceable(self):
        return (10000 <= self.kind < 20000) or self.kind in (0, 3,)

    @property
    def is_parameterized_replaceable(self):
        return 30000 <= self.kind < 40000

    @staticmethod
    def serialize(
        *,
        pubkey: str,
        created_at: int,
        kind: int,
        tags: "list[list[str]]",
        content: str,
    ) -> bytes:
        data = [0, pubkey, created_at, kind, tags, content]
        data_str = dumps(data)
        return data_str.encode()

    @staticmethod
    def compute_id(
        *,
        pubkey: str,
        created_at: int,
        kind: int,
        tags: "list[list[str]]",
        content: str,
    ) -> str:
        return sha256(
            Event.serialize(pubkey=pubkey, created_at=created_at, kind=kind, tags=tags, content=content)
        ).hexdigest()

    def expires_at(self) -> Optional[int]:
        for tag in self.tags:
            if len(tag) >= 2 and tag[0] == 'expiration':
                try:
                    return int(tag[1])
                except Exception:
                    continue
        return None

    def is_expired(self) -> bool:
        if (expiration_ts := self.expires_at()) is not None:
            return expiration_ts < time.time()
        return False

    def add_expiration_tag(self, expiration_ts: int) -> "Event":
        assert self.expires_at() is None, "Duplicate expiration tags"
        assert expiration_ts >= int(time.time()), f"Expiration is in the past: {expiration_ts=}"
        tags = copy.deepcopy(self.tags)
        tags.append(['expiration', str(expiration_ts)])
        return dataclasses.replace(self, tags=tags, sig=None)

    def sign(self, private_key_hex: str) -> "Event":
        sig = self._sign_event_id(private_key_hex=private_key_hex, event_id=self.id)
        return dataclasses.replace(self, sig=sig)

    @classmethod
    def _sign_event_id(cls, *, private_key_hex: str, event_id: str) -> str:
        sk = ECPrivkey(bytes.fromhex(private_key_hex))
        sig = sk.schnorr_sign(bytes.fromhex(event_id))
        return sig.hex()

    def verify(self) -> bool:
        if not self.sig:
            return False
        try:
            pub_key = ECPubkey(bytes.fromhex("02" + self.pubkey))
        except Exception as e:
            return False
        event_id = Event.compute_id(
            pubkey=self.pubkey, created_at=self.created_at, kind=self.kind, tags=self.tags, content=self.content,
        )
        assert self.id == event_id

        verified = pub_key.schnorr_verify(
            bytes.fromhex(self.sig),
            bytes.fromhex(event_id),
        )
        for tag in self.tags:
            if tag[0] == "delegation":
                # verify delegation signature
                _, delegator, conditions, sig = tag
                to_sign = (
                    ":".join(["nostr", "delegation", self.pubkey, conditions])
                ).encode("utf8")
                delegation_verified = ECPubkey(bytes.fromhex("02" + delegator)).schnorr_verify(
                    bytes.fromhex(sig),
                    sha256(to_sign).digest(),
                )
                if not delegation_verified:
                    return False
        return verified

    def has_tag(self, tag_name: str, matches: list = None) -> tuple[bool, str]:
        """
        Given a tag name and optional list of matches to find, return (found, match)
        """
        found_tag = False
        match = None
        for tag in self.tags:
            if tag[0] == tag_name:
                found_tag = True
                if matches and len(tag) > 1 and tag[1] in matches:
                    match = tag[1]
        return found_tag, match

    def to_message(self, sub_id: str = None):
        message = ["EVENT"]
        if sub_id:
            message.append(sub_id)
        message.append(self.to_json_object())
        return dumps(message)

    def __str__(self):
        return dumps(self.to_json_object())

    def to_json_object(self) -> dict:
        return {
            "id": self.id,
            "pubkey": self.pubkey,
            "created_at": self.created_at,
            "kind": self.kind,
            "tags": self.tags,
            "content": self.content,
            "sig": self.sig,
        }

    @classmethod
    def from_json(cls, d: dict, *, verify_sig: bool = True) -> "Event":
        sig = None
        if verify_sig:  # we just check we were given a sig, the sigcheck itself is in Event.__init__
            sig = d.get("sig")
            if not sig:
                raise ValueError("missing sig")
        return Event(
            pubkey=d["pubkey"],
            created_at=d["created_at"],
            kind=d["kind"],
            tags=d["tags"],
            content=d["content"],
            sig=sig,
        )
