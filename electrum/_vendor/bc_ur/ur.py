#
# ur.py
#
# Copyright (C) 2020 Foundation Devices, Inc.
# Licensed under the "BSD-2-Clause Plus Patent License"
#

from .utils import is_ur_type


class InvalidType(Exception):
    pass


class UR:

    def __init__(self, type: str, cbor: bytes) -> None:
        if not is_ur_type(type):
            raise InvalidType()

        self.type = type
        self.cbor = cbor

    def __eq__(self, obj: object) -> bool:
        if not isinstance(obj, UR):
            return False
        return self.type == obj.type and self.cbor == obj.cbor
