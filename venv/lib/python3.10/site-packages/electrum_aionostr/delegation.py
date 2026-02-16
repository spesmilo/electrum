"""
forked from https://github.com/jeffthibault/python-nostr.git
"""
import time
from dataclasses import dataclass

from typing import List

@dataclass
class Delegation:
    delegator_pubkey: str
    delegatee_pubkey: str
    event_kind: int
    duration_secs: int = 30*24*60  # default to 30 days
    signature: str = None  # set in PrivateKey.sign_delegation

    @property
    def expires(self) -> int:
        return int(time.time()) + self.duration_secs
    
    @property
    def conditions(self) -> str:
        return f"kind={self.event_kind}&created_at<{self.expires}"
    
    @property
    def delegation_token(self) -> str:
        return f"nostr:delegation:{self.delegatee_pubkey}:{self.conditions}"

    def get_tag(self) -> List[str]:
        """ Called by Event """
        return [
            "delegation",
            self.delegator_pubkey,
            self.conditions,
            self.signature,
        ]
