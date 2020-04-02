import os
import csv
import io
from typing import Callable, Tuple, Any, Dict, List, Sequence, Union, Optional
from collections import OrderedDict

from .lnutil import OnionFailureCodeMetaFlag


class MalformedMsg(Exception): pass
class UnknownMsgFieldType(MalformedMsg): pass
class UnexpectedEndOfStream(MalformedMsg): pass
class FieldEncodingNotMinimal(MalformedMsg): pass
class UnknownMandatoryTLVRecordType(MalformedMsg): pass
class MsgTrailingGarbage(MalformedMsg): pass
class MsgInvalidFieldOrder(MalformedMsg): pass
class UnexpectedFieldSizeForEncoder(MalformedMsg): pass


def _num_remaining_bytes_to_read(fd: io.BytesIO) -> int:
    cur_pos = fd.tell()
    end_pos = fd.seek(0, io.SEEK_END)
    fd.seek(cur_pos)
    return end_pos - cur_pos


def _assert_can_read_at_least_n_bytes(fd: io.BytesIO, n: int) -> None:
    # note: it's faster to read n bytes and then check if we read n, than
    #       to assert we can read at least n and then read n bytes.
    nremaining = _num_remaining_bytes_to_read(fd)
    if nremaining < n:
        raise UnexpectedEndOfStream(f"wants to read {n} bytes but only {nremaining} bytes left")


def write_bigsize_int(i: int) -> bytes:
    assert i >= 0, i
    if i < 0xfd:
        return int.to_bytes(i, length=1, byteorder="big", signed=False)
    elif i < 0x1_0000:
        return b"\xfd" + int.to_bytes(i, length=2, byteorder="big", signed=False)
    elif i < 0x1_0000_0000:
        return b"\xfe" + int.to_bytes(i, length=4, byteorder="big", signed=False)
    else:
        return b"\xff" + int.to_bytes(i, length=8, byteorder="big", signed=False)


def read_bigsize_int(fd: io.BytesIO) -> Optional[int]:
    try:
        first = fd.read(1)[0]
    except IndexError:
        return None  # end of file
    if first < 0xfd:
        return first
    elif first == 0xfd:
        buf = fd.read(2)
        if len(buf) != 2:
            raise UnexpectedEndOfStream()
        val = int.from_bytes(buf, byteorder="big", signed=False)
        if not (0xfd <= val < 0x1_0000):
            raise FieldEncodingNotMinimal()
        return val
    elif first == 0xfe:
        buf = fd.read(4)
        if len(buf) != 4:
            raise UnexpectedEndOfStream()
        val = int.from_bytes(buf, byteorder="big", signed=False)
        if not (0x1_0000 <= val < 0x1_0000_0000):
            raise FieldEncodingNotMinimal()
        return val
    elif first == 0xff:
        buf = fd.read(8)
        if len(buf) != 8:
            raise UnexpectedEndOfStream()
        val = int.from_bytes(buf, byteorder="big", signed=False)
        if not (0x1_0000_0000 <= val):
            raise FieldEncodingNotMinimal()
        return val
    raise Exception()


# TODO: maybe if field_type is not "byte", we could return a list of type_len sized chunks?
#       if field_type is a numeric, we could return a list of ints?
def _read_field(*, fd: io.BytesIO, field_type: str, count: Union[int, str]) -> Union[bytes, int]:
    if not fd: raise Exception()
    if isinstance(count, int):
        assert count >= 0, f"{count!r} must be non-neg int"
    elif count == "...":
        pass
    else:
        raise Exception(f"unexpected field count: {count!r}")
    if count == 0:
        return b""
    type_len = None
    if field_type == 'byte':
        type_len = 1
    elif field_type in ('u8', 'u16', 'u32', 'u64'):
        if field_type == 'u8':
            type_len = 1
        elif field_type == 'u16':
            type_len = 2
        elif field_type == 'u32':
            type_len = 4
        else:
            assert field_type == 'u64'
            type_len = 8
        assert count == 1, count
        buf = fd.read(type_len)
        if len(buf) != type_len:
            raise UnexpectedEndOfStream()
        return int.from_bytes(buf, byteorder="big", signed=False)
    elif field_type in ('tu16', 'tu32', 'tu64'):
        if field_type == 'tu16':
            type_len = 2
        elif field_type == 'tu32':
            type_len = 4
        else:
            assert field_type == 'tu64'
            type_len = 8
        assert count == 1, count
        raw = fd.read(type_len)
        if len(raw) > 0 and raw[0] == 0x00:
            raise FieldEncodingNotMinimal()
        return int.from_bytes(raw, byteorder="big", signed=False)
    elif field_type == 'varint':
        assert count == 1, count
        val = read_bigsize_int(fd)
        if val is None:
            raise UnexpectedEndOfStream()
        return val
    elif field_type == 'chain_hash':
        type_len = 32
    elif field_type == 'channel_id':
        type_len = 32
    elif field_type == 'sha256':
        type_len = 32
    elif field_type == 'signature':
        type_len = 64
    elif field_type == 'point':
        type_len = 33
    elif field_type == 'short_channel_id':
        type_len = 8

    if count == "...":
        total_len = -1  # read all
    else:
        if type_len is None:
            raise UnknownMsgFieldType(f"unknown field type: {field_type!r}")
        total_len = count * type_len

    buf = fd.read(total_len)
    if total_len >= 0 and len(buf) != total_len:
        raise UnexpectedEndOfStream()
    return buf


# TODO: maybe for "value" we could accept a list with len "count" of appropriate items
def _write_field(*, fd: io.BytesIO, field_type: str, count: Union[int, str],
                 value: Union[bytes, int]) -> None:
    if not fd: raise Exception()
    if isinstance(count, int):
        assert count >= 0, f"{count!r} must be non-neg int"
    elif count == "...":
        pass
    else:
        raise Exception(f"unexpected field count: {count!r}")
    if count == 0:
        return
    type_len = None
    if field_type == 'byte':
        type_len = 1
    elif field_type == 'u8':
        type_len = 1
    elif field_type == 'u16':
        type_len = 2
    elif field_type == 'u32':
        type_len = 4
    elif field_type == 'u64':
        type_len = 8
    elif field_type in ('tu16', 'tu32', 'tu64'):
        if field_type == 'tu16':
            type_len = 2
        elif field_type == 'tu32':
            type_len = 4
        else:
            assert field_type == 'tu64'
            type_len = 8
        assert count == 1, count
        if isinstance(value, int):
            value = int.to_bytes(value, length=type_len, byteorder="big", signed=False)
        if not isinstance(value, (bytes, bytearray)):
            raise Exception(f"can only write bytes into fd. got: {value!r}")
        while len(value) > 0 and value[0] == 0x00:
            value = value[1:]
        nbytes_written = fd.write(value)
        if nbytes_written != len(value):
            raise Exception(f"tried to write {len(value)} bytes, but only wrote {nbytes_written}!?")
        return
    elif field_type == 'varint':
        assert count == 1, count
        if isinstance(value, int):
            value = write_bigsize_int(value)
        if not isinstance(value, (bytes, bytearray)):
            raise Exception(f"can only write bytes into fd. got: {value!r}")
        nbytes_written = fd.write(value)
        if nbytes_written != len(value):
            raise Exception(f"tried to write {len(value)} bytes, but only wrote {nbytes_written}!?")
        return
    elif field_type == 'chain_hash':
        type_len = 32
    elif field_type == 'channel_id':
        type_len = 32
    elif field_type == 'sha256':
        type_len = 32
    elif field_type == 'signature':
        type_len = 64
    elif field_type == 'point':
        type_len = 33
    elif field_type == 'short_channel_id':
        type_len = 8
    total_len = -1
    if count != "...":
        if type_len is None:
            raise UnknownMsgFieldType(f"unknown field type: {field_type!r}")
        total_len = count * type_len
        if isinstance(value, int) and (count == 1 or field_type == 'byte'):
            value = int.to_bytes(value, length=total_len, byteorder="big", signed=False)
    if not isinstance(value, (bytes, bytearray)):
        raise Exception(f"can only write bytes into fd. got: {value!r}")
    if count != "..." and total_len != len(value):
        raise UnexpectedFieldSizeForEncoder(f"expected: {total_len}, got {len(value)}")
    nbytes_written = fd.write(value)
    if nbytes_written != len(value):
        raise Exception(f"tried to write {len(value)} bytes, but only wrote {nbytes_written}!?")


def _read_tlv_record(*, fd: io.BytesIO) -> Tuple[int, bytes]:
    if not fd: raise Exception()
    tlv_type = _read_field(fd=fd, field_type="varint", count=1)
    tlv_len = _read_field(fd=fd, field_type="varint", count=1)
    tlv_val = _read_field(fd=fd, field_type="byte", count=tlv_len)
    return tlv_type, tlv_val


def _write_tlv_record(*, fd: io.BytesIO, tlv_type: int, tlv_val: bytes) -> None:
    if not fd: raise Exception()
    tlv_len = len(tlv_val)
    _write_field(fd=fd, field_type="varint", count=1, value=tlv_type)
    _write_field(fd=fd, field_type="varint", count=1, value=tlv_len)
    _write_field(fd=fd, field_type="byte", count=tlv_len, value=tlv_val)


def _resolve_field_count(field_count_str: str, *, vars_dict: dict, allow_any=False) -> Union[int, str]:
    """Returns an evaluated field count, typically an int.
    If allow_any is True, the return value can be a str with value=="...".
    """
    if field_count_str == "":
        field_count = 1
    elif field_count_str == "...":
        if not allow_any:
            raise Exception("field count is '...' but allow_any is False")
        return field_count_str
    else:
        try:
            field_count = int(field_count_str)
        except ValueError:
            field_count = vars_dict[field_count_str]
            if isinstance(field_count, (bytes, bytearray)):
                field_count = int.from_bytes(field_count, byteorder="big")
    assert isinstance(field_count, int)
    return field_count


def _parse_msgtype_intvalue_for_onion_wire(value: str) -> int:
    msg_type_int = 0
    for component in value.split("|"):
        try:
            msg_type_int |= int(component)
        except ValueError:
            msg_type_int |= OnionFailureCodeMetaFlag[component]
    return msg_type_int


class LNSerializer:

    def __init__(self, *, for_onion_wire: bool = False):
        # TODO msg_type could be 'int' everywhere...
        self.msg_scheme_from_type = {}  # type: Dict[bytes, List[Sequence[str]]]
        self.msg_type_from_name = {}  # type: Dict[str, bytes]

        self.in_tlv_stream_get_tlv_record_scheme_from_type = {}  # type: Dict[str, Dict[int, List[Sequence[str]]]]
        self.in_tlv_stream_get_record_type_from_name = {}  # type: Dict[str, Dict[str, int]]
        self.in_tlv_stream_get_record_name_from_type = {}  # type: Dict[str, Dict[int, str]]

        if for_onion_wire:
            path = os.path.join(os.path.dirname(__file__), "lnwire", "onion_wire.csv")
        else:
            path = os.path.join(os.path.dirname(__file__), "lnwire", "peer_wire.csv")
        with open(path, newline='') as f:
            csvreader = csv.reader(f)
            for row in csvreader:
                #print(f">>> {row!r}")
                if row[0] == "msgtype":
                    # msgtype,<msgname>,<value>[,<option>]
                    msg_type_name = row[1]
                    if for_onion_wire:
                        msg_type_int = _parse_msgtype_intvalue_for_onion_wire(str(row[2]))
                    else:
                        msg_type_int = int(row[2])
                    msg_type_bytes = msg_type_int.to_bytes(2, 'big')
                    assert msg_type_bytes not in self.msg_scheme_from_type, f"type collision? for {msg_type_name}"
                    assert msg_type_name not in self.msg_type_from_name, f"type collision? for {msg_type_name}"
                    row[2] = msg_type_int
                    self.msg_scheme_from_type[msg_type_bytes] = [tuple(row)]
                    self.msg_type_from_name[msg_type_name] = msg_type_bytes
                elif row[0] == "msgdata":
                    # msgdata,<msgname>,<fieldname>,<typename>,[<count>][,<option>]
                    assert msg_type_name == row[1]
                    self.msg_scheme_from_type[msg_type_bytes].append(tuple(row))
                elif row[0] == "tlvtype":
                    # tlvtype,<tlvstreamname>,<tlvname>,<value>[,<option>]
                    tlv_stream_name = row[1]
                    tlv_record_name = row[2]
                    tlv_record_type = int(row[3])
                    row[3] = tlv_record_type
                    if tlv_stream_name not in self.in_tlv_stream_get_tlv_record_scheme_from_type:
                        self.in_tlv_stream_get_tlv_record_scheme_from_type[tlv_stream_name] = OrderedDict()
                        self.in_tlv_stream_get_record_type_from_name[tlv_stream_name] = {}
                        self.in_tlv_stream_get_record_name_from_type[tlv_stream_name] = {}
                    assert tlv_record_type not in self.in_tlv_stream_get_tlv_record_scheme_from_type[tlv_stream_name], f"type collision? for {tlv_stream_name}/{tlv_record_name}"
                    assert tlv_record_name not in self.in_tlv_stream_get_record_type_from_name[tlv_stream_name], f"type collision? for {tlv_stream_name}/{tlv_record_name}"
                    assert tlv_record_type not in self.in_tlv_stream_get_record_type_from_name[tlv_stream_name], f"type collision? for {tlv_stream_name}/{tlv_record_name}"
                    self.in_tlv_stream_get_tlv_record_scheme_from_type[tlv_stream_name][tlv_record_type] = [tuple(row)]
                    self.in_tlv_stream_get_record_type_from_name[tlv_stream_name][tlv_record_name] = tlv_record_type
                    self.in_tlv_stream_get_record_name_from_type[tlv_stream_name][tlv_record_type] = tlv_record_name
                    if max(self.in_tlv_stream_get_tlv_record_scheme_from_type[tlv_stream_name].keys()) > tlv_record_type:
                        raise Exception(f"tlv record types must be listed in monotonically increasing order for stream. "
                                        f"stream={tlv_stream_name}")
                elif row[0] == "tlvdata":
                    # tlvdata,<tlvstreamname>,<tlvname>,<fieldname>,<typename>,[<count>][,<option>]
                    assert tlv_stream_name == row[1]
                    assert tlv_record_name == row[2]
                    self.in_tlv_stream_get_tlv_record_scheme_from_type[tlv_stream_name][tlv_record_type].append(tuple(row))
                else:
                    pass  # TODO

    def write_tlv_stream(self, *, fd: io.BytesIO, tlv_stream_name: str, **kwargs) -> None:
        scheme_map = self.in_tlv_stream_get_tlv_record_scheme_from_type[tlv_stream_name]
        for tlv_record_type, scheme in scheme_map.items():  # note: tlv_record_type is monotonically increasing
            tlv_record_name = self.in_tlv_stream_get_record_name_from_type[tlv_stream_name][tlv_record_type]
            if tlv_record_name not in kwargs:
                continue
            with io.BytesIO() as tlv_record_fd:
                for row in scheme:
                    if row[0] == "tlvtype":
                        pass
                    elif row[0] == "tlvdata":
                        # tlvdata,<tlvstreamname>,<tlvname>,<fieldname>,<typename>,[<count>][,<option>]
                        assert tlv_stream_name == row[1]
                        assert tlv_record_name == row[2]
                        field_name = row[3]
                        field_type = row[4]
                        field_count_str = row[5]
                        field_count = _resolve_field_count(field_count_str,
                                                           vars_dict=kwargs[tlv_record_name],
                                                           allow_any=True)
                        field_value = kwargs[tlv_record_name][field_name]
                        _write_field(fd=tlv_record_fd,
                                     field_type=field_type,
                                     count=field_count,
                                     value=field_value)
                    else:
                        raise Exception(f"unexpected row in scheme: {row!r}")
                _write_tlv_record(fd=fd, tlv_type=tlv_record_type, tlv_val=tlv_record_fd.getvalue())

    def read_tlv_stream(self, *, fd: io.BytesIO, tlv_stream_name: str) -> Dict[str, Dict[str, Any]]:
        parsed = {}  # type: Dict[str, Dict[str, Any]]
        scheme_map = self.in_tlv_stream_get_tlv_record_scheme_from_type[tlv_stream_name]
        last_seen_tlv_record_type = -1  # type: int
        while _num_remaining_bytes_to_read(fd) > 0:
            tlv_record_type, tlv_record_val = _read_tlv_record(fd=fd)
            if not (tlv_record_type > last_seen_tlv_record_type):
                raise MsgInvalidFieldOrder(f"TLV records must be monotonically increasing by type. "
                                           f"cur: {tlv_record_type}. prev: {last_seen_tlv_record_type}")
            last_seen_tlv_record_type = tlv_record_type
            try:
                scheme = scheme_map[tlv_record_type]
            except KeyError:
                if tlv_record_type % 2 == 0:
                    # unknown "even" type: hard fail
                    raise UnknownMandatoryTLVRecordType(f"{tlv_stream_name}/{tlv_record_type}") from None
                else:
                    # unknown "odd" type: skip it
                    continue
            tlv_record_name = self.in_tlv_stream_get_record_name_from_type[tlv_stream_name][tlv_record_type]
            parsed[tlv_record_name] = {}
            with io.BytesIO(tlv_record_val) as tlv_record_fd:
                for row in scheme:
                    #print(f"row: {row!r}")
                    if row[0] == "tlvtype":
                        pass
                    elif row[0] == "tlvdata":
                        # tlvdata,<tlvstreamname>,<tlvname>,<fieldname>,<typename>,[<count>][,<option>]
                        assert tlv_stream_name == row[1]
                        assert tlv_record_name == row[2]
                        field_name = row[3]
                        field_type = row[4]
                        field_count_str = row[5]
                        field_count = _resolve_field_count(field_count_str,
                                                           vars_dict=parsed[tlv_record_name],
                                                           allow_any=True)
                        #print(f">> count={field_count}. parsed={parsed}")
                        parsed[tlv_record_name][field_name] = _read_field(fd=tlv_record_fd,
                                                                          field_type=field_type,
                                                                          count=field_count)
                    else:
                        raise Exception(f"unexpected row in scheme: {row!r}")
                if _num_remaining_bytes_to_read(tlv_record_fd) > 0:
                    raise MsgTrailingGarbage(f"TLV record ({tlv_stream_name}/{tlv_record_name}) has extra trailing garbage")
        return parsed

    def encode_msg(self, msg_type: str, **kwargs) -> bytes:
        """
        Encode kwargs into a Lightning message (bytes)
        of the type given in the msg_type string
        """
        #print(f">>> encode_msg. msg_type={msg_type}, payload={kwargs!r}")
        msg_type_bytes = self.msg_type_from_name[msg_type]
        scheme = self.msg_scheme_from_type[msg_type_bytes]
        with io.BytesIO() as fd:
            fd.write(msg_type_bytes)
            for row in scheme:
                if row[0] == "msgtype":
                    pass
                elif row[0] == "msgdata":
                    # msgdata,<msgname>,<fieldname>,<typename>,[<count>][,<option>]
                    field_name = row[2]
                    field_type = row[3]
                    field_count_str = row[4]
                    #print(f">>> encode_msg. msgdata. field_name={field_name!r}. field_type={field_type!r}. field_count_str={field_count_str!r}")
                    field_count = _resolve_field_count(field_count_str, vars_dict=kwargs)
                    if field_name == "tlvs":
                        tlv_stream_name = field_type
                        if tlv_stream_name in kwargs:
                            self.write_tlv_stream(fd=fd, tlv_stream_name=tlv_stream_name, **(kwargs[tlv_stream_name]))
                        continue
                    try:
                        field_value = kwargs[field_name]
                    except KeyError:
                        if len(row) > 5:
                            break  # optional feature field not present
                        else:
                            field_value = 0  # default mandatory fields to zero
                    #print(f">>> encode_msg. writing field: {field_name}. value={field_value!r}. field_type={field_type!r}. count={field_count!r}")
                    _write_field(fd=fd,
                                 field_type=field_type,
                                 count=field_count,
                                 value=field_value)
                    #print(f">>> encode_msg. so far: {fd.getvalue().hex()}")
                else:
                    raise Exception(f"unexpected row in scheme: {row!r}")
            return fd.getvalue()

    def decode_msg(self, data: bytes) -> Tuple[str, dict]:
        """
        Decode Lightning message by reading the first
        two bytes to determine message type.

        Returns message type string and parsed message contents dict
        """
        #print(f"decode_msg >>> {data.hex()}")
        assert len(data) >= 2
        msg_type_bytes = data[:2]
        msg_type_int = int.from_bytes(msg_type_bytes, byteorder="big", signed=False)
        scheme = self.msg_scheme_from_type[msg_type_bytes]
        assert scheme[0][2] == msg_type_int
        msg_type_name = scheme[0][1]
        parsed = {}
        with io.BytesIO(data[2:]) as fd:
            for row in scheme:
                #print(f"row: {row!r}")
                if row[0] == "msgtype":
                    pass
                elif row[0] == "msgdata":
                    field_name = row[2]
                    field_type = row[3]
                    field_count_str = row[4]
                    field_count = _resolve_field_count(field_count_str, vars_dict=parsed)
                    if field_name == "tlvs":
                        tlv_stream_name = field_type
                        d = self.read_tlv_stream(fd=fd, tlv_stream_name=tlv_stream_name)
                        parsed[tlv_stream_name] = d
                        continue
                    #print(f">> count={field_count}. parsed={parsed}")
                    try:
                        parsed[field_name] = _read_field(fd=fd,
                                                         field_type=field_type,
                                                         count=field_count)
                    except UnexpectedEndOfStream as e:
                        if len(row) > 5:
                            break  # optional feature field not present
                        else:
                            raise
                else:
                    raise Exception(f"unexpected row in scheme: {row!r}")
        return msg_type_name, parsed


_inst = LNSerializer()
encode_msg = _inst.encode_msg
decode_msg = _inst.decode_msg


OnionWireSerializer = LNSerializer(for_onion_wire=True)
