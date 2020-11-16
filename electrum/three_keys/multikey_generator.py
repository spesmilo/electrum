from abc import ABC, abstractmethod

from typing import List


class MultiKeyScriptGenerator(ABC):

    @abstractmethod
    def get_redeem_script(self, public_keys: List[str]) -> str:
        pass

    @abstractmethod
    def get_script_sig(self, signatures: List[str], public_keys: List[str]) -> str:
        pass
