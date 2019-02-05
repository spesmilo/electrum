import json
import os
from typing import Callable, Tuple
from collections import OrderedDict

def handlesingle(x, ma: dict) -> int:
    """
    Evaluate a term of the simple language used
    to specify lightning message field lengths.

    If `x` is an integer, it is returned as is,
    otherwise it is treated as a variable and
    looked up in `ma`.

    If the value in `ma` was no integer, it is
    assumed big-endian bytes and decoded.

    Returns int
    """
    try:
        x = int(x)
    except ValueError:
        x = ma[x]
    try:
        x = int(x)
    except ValueError:
        x = int.from_bytes(x, byteorder='big')
    return x

def calcexp(exp, ma: dict) -> int:
    """
    Evaluate simple mathematical expression given
    in `exp` with variables assigned in the dict `ma`

    Returns int
    """
    exp = str(exp)
    if "*" in exp:
        assert "+" not in exp
        result = 1
        for term in exp.split("*"):
            result *= handlesingle(term, ma)
        return result
    return sum(handlesingle(x, ma) for x in exp.split("+"))

def make_handler(k: str, v: dict) -> Callable[[bytes], Tuple[str, dict]]:
    """
    Generate a message handler function (taking bytes)
    for message type `k` with specification `v`

    Check lib/lightning.json, `k` could be 'init',
    and `v` could be

      { type: 16, payload: { 'gflen': ..., ... }, ... }

    Returns function taking bytes
    """
    def handler(data: bytes) -> Tuple[str, dict]:
        nonlocal k, v
        ma = {}
        pos = 0
        for fieldname in v["payload"]:
            poslenMap = v["payload"][fieldname]
            if "feature" in poslenMap and pos == len(data):
                continue
            #print(poslenMap["position"], ma)
            assert pos == calcexp(poslenMap["position"], ma)
            length = poslenMap["length"]
            length = calcexp(length, ma)
            ma[fieldname] = data[pos:pos+length]
            pos += length
        assert pos == len(data), (k, pos, len(data))
        return k, ma
    return handler

def _decode_msg(message_types : dict, data: bytes) -> Tuple[str, dict]:
    """
    Decode Lightning message by reading the first
    two bytes to determine message type.

    Returns message type string and parsed message contents dict
    """
    typ = data[:2]
    k, parsed = message_types[typ](data[2:])
    return k, parsed

def _gen_msg(structured : dict, msg_type: str, **kwargs) -> bytes:
    """
    Encode kwargs into a Lightning message (bytes)
    of the type given in the msg_type string
    """
    typ = structured[msg_type]
    data = int(typ["type"]).to_bytes(2, 'big')
    lengths = {}
    for k in typ["payload"]:
        poslenMap = typ["payload"][k]
        if "feature" in poslenMap: continue
        leng = calcexp(poslenMap["length"], lengths)
        try:
            clone = dict(lengths)
            clone.update(kwargs)
            leng = calcexp(poslenMap["length"], clone)
        except KeyError:
            pass
        try:
            param = kwargs[k]
        except KeyError:
            param = 0
        try:
            if not isinstance(param, bytes):
                assert isinstance(param, int), "field {} is neither bytes or int".format(k)
                param = param.to_bytes(leng, 'big')
        except ValueError:
            raise Exception("{} does not fit in {} bytes".format(k, leng))
        lengths[k] = len(param)
        if lengths[k] != leng:
            raise Exception("field {} is {} bytes long, should be {} bytes long".format(k, lengths[k], leng))
        data += param
    return data

class LNSerializer:
    def __init__(self):
        message_types = {}
        path = os.path.join(os.path.dirname(__file__), 'lightning.json')
        with open(path) as f:
            structured = json.loads(f.read(), object_pairs_hook=OrderedDict)

        for k in structured:
            v = structured[k]
            # these message types are skipped since their types collide
            # (for example with pong, which also uses type=19)
            # we don't need them yet
            if k in ["final_incorrect_cltv_expiry", "final_incorrect_htlc_amount"]:
                continue
            if len(v["payload"]) == 0:
                continue
            try:
                num = int(v["type"])
            except ValueError:
                #print("skipping", k)
                continue
            byts = num.to_bytes(2, 'big')
            assert byts not in message_types, (byts, message_types[byts].__name__, k)
            names = [x.__name__ for x in message_types.values()]
            assert k + "_handler" not in names, (k, names)
            message_types[byts] = make_handler(k, v)
            message_types[byts].__name__ = k + "_handler"

        assert message_types[b"\x00\x10"].__name__ == "init_handler"
        self.structured = structured
        self.message_types = message_types

    def gen_msg(self, msg_type, **kwargs):
        return _gen_msg(self.structured, msg_type, **kwargs)

    def decode_msg(self, data):
        return _decode_msg(self.message_types, data)
