import random
import os
from hashlib import sha256
from typing import NamedTuple, Optional, Dict, Tuple

from electrum.plugin import BasePlugin
from electrum.util import to_bytes, bh2u, bfh

from .hmac_drbg import DRBG


class VersionedSeed(NamedTuple):
    version: str
    seed: str
    checksum: str

    def get_ui_string_version_plus_seed(self):
        version, seed = self.version, self.seed
        assert isinstance(version, str) and len(version) == 1, version
        assert isinstance(seed, str) and len(seed) >= 32
        ret = version + seed
        ret = ret.upper()
        return ' '.join(ret[i : i+4] for i in range(0, len(ret), 4))


class RevealerPlugin(BasePlugin):

    LATEST_VERSION = '1'
    KNOWN_VERSIONS = ('0', '1')
    assert LATEST_VERSION in KNOWN_VERSIONS

    SIZE = (159, 97)

    def __init__(self, parent, config, name):
        BasePlugin.__init__(self, parent, config, name)

    @classmethod
    def code_hashid(cls, txt: str) -> str:
        txt = txt.lower()
        x = to_bytes(txt, 'utf8')
        hash = sha256(x).hexdigest()
        return hash[-3:].upper()

    @classmethod
    def get_versioned_seed_from_user_input(cls, txt: str) -> Optional[VersionedSeed]:
        if len(txt) < 34:
            return None
        try:
            int(txt, 16)
        except:
            return None
        version = txt[0]
        if version not in cls.KNOWN_VERSIONS:
            return None
        checksum = cls.code_hashid(txt[:-3])
        if txt[-3:].upper() != checksum.upper():
            return None
        return VersionedSeed(version=version.upper(),
                             seed=txt[1:-3].upper(),
                             checksum=checksum.upper())

    @classmethod
    def get_noise_map(cls, versioned_seed: VersionedSeed) -> Dict[Tuple[int, int], int]:
        """Returns a map from (x,y) coordinate to pixel value 0/1, to be used as rawnoise."""
        w, h = cls.SIZE
        version  = versioned_seed.version
        hex_seed = versioned_seed.seed
        checksum = versioned_seed.checksum
        noise_map = {}
        if version == '0':
            random.seed(int(hex_seed, 16))
            for x in range(w):
                for y in range(h):
                    noise_map[(x, y)] = random.randint(0, 1)
        elif version == '1':
            prng_seed = bfh(hex_seed + version + checksum)
            drbg = DRBG(prng_seed)
            num_noise_bytes = 1929  # ~ w*h
            noise_array = bin(int.from_bytes(drbg.generate(num_noise_bytes), 'big'))[2:]
            # there's an approx 1/1024 chance that the generated number is 'too small'
            # and we would get IndexError below. easiest backwards compat fix:
            noise_array += '0' * (w * h - len(noise_array))
            i = 0
            for x in range(w):
                for y in range(h):
                    noise_map[(x, y)] = int(noise_array[i])
                    i += 1
        else:
            raise Exception(f"unexpected revealer version: {version}")
        return noise_map

    @classmethod
    def gen_random_versioned_seed(cls):
        version = cls.LATEST_VERSION
        hex_seed = bh2u(os.urandom(16))
        checksum = cls.code_hashid(version + hex_seed)
        return VersionedSeed(version=version.upper(),
                             seed=hex_seed.upper(),
                             checksum=checksum.upper())


if __name__ == '__main__':
    for i in range(10**4):
        vs = RevealerPlugin.gen_random_versioned_seed()
        nm = RevealerPlugin.get_noise_map(vs)
