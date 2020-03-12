import os
import csv
import io
from typing import Callable, Tuple, Any, Dict, List, Sequence, Union, Optional


class MalformedMsg(Exception):
    pass


class UnknownMsgFieldType(MalformedMsg):
    pass


class UnexpectedEndOfStream(MalformedMsg):
    pass


def _assert_can_read_at_least_n_bytes(fd: io.BytesIO, n: int) -> None:
    cur_pos = fd.tell()
    end_pos = fd.seek(0, io.SEEK_END)
    fd.seek(cur_pos)
    if end_pos - cur_pos < n:
        raise UnexpectedEndOfStream(f"cur_pos={cur_pos}. end_pos={end_pos}. wants to read: {n}")


def _read_field(*, fd: io.BytesIO, field_type: str, count: int) -> Union[bytes, int]:
    if not fd: raise Exception()
    assert isinstance(count, int) and count >= 0, f"{count!r} must be non-neg int"
    if count == 0:
        return b""
    type_len = None
    if field_type == 'byte':
        type_len = 1
    elif field_type == 'u16':
        type_len = 2
        assert count == 1, count
        _assert_can_read_at_least_n_bytes(fd, type_len)
        return int.from_bytes(fd.read(type_len), byteorder="big", signed=False)
    elif field_type == 'u32':
        type_len = 4
        assert count == 1, count
        _assert_can_read_at_least_n_bytes(fd, type_len)
        return int.from_bytes(fd.read(type_len), byteorder="big", signed=False)
    elif field_type == 'u64':
        type_len = 8
        assert count == 1, count
        _assert_can_read_at_least_n_bytes(fd, type_len)
        return int.from_bytes(fd.read(type_len), byteorder="big", signed=False)
    # TODO tu16/tu32/tu64
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
    if type_len is None:
        raise UnknownMsgFieldType(f"unexpected field type: {field_type!r}")
    total_len = count * type_len
    _assert_can_read_at_least_n_bytes(fd, total_len)
    return fd.read(total_len)


def _write_field(*, fd: io.BytesIO, field_type: str, count: int,
                 value: Union[bytes, int]) -> None:
    if not fd: raise Exception()
    assert isinstance(count, int) and count >= 0, f"{count!r} must be non-neg int"
    if count == 0:
        return
    type_len = None
    if field_type == 'byte':
        type_len = 1
    elif field_type == 'u16':
        type_len = 2
    elif field_type == 'u32':
        type_len = 4
    elif field_type == 'u64':
        type_len = 8
    # TODO tu16/tu32/tu64
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
    if type_len is None:
        raise UnknownMsgFieldType(f"unexpected fundamental type: {field_type!r}")
    total_len = count * type_len
    if isinstance(value, int) and (count == 1 or field_type == 'byte'):
        value = int.to_bytes(value, length=total_len, byteorder="big", signed=False)
    if not isinstance(value, (bytes, bytearray)):
        raise Exception(f"can only write bytes into fd. got: {value!r}")
    if total_len != len(value):
        raise Exception(f"unexpected field size. expected: {total_len}, got {len(value)}")
    nbytes_written = fd.write(value)
    if nbytes_written != len(value):
        raise Exception(f"tried to write {len(value)} bytes, but only wrote {nbytes_written}!?")


class LNSerializer:
    def __init__(self):
        self.msg_scheme_from_type = {}  # type: Dict[bytes, List[Sequence[str]]]
        self.msg_type_from_name = {}  # type: Dict[str, bytes]
        path = os.path.join(os.path.dirname(__file__), "lnwire", "peer_wire.csv")
        with open(path, newline='') as f:
            csvreader = csv.reader(f)
            for row in csvreader:
                #print(f">>> {row!r}")
                if row[0] == "msgtype":
                    msg_type_name = row[1]
                    msg_type_int = int(row[2])
                    msg_type_bytes = msg_type_int.to_bytes(2, 'big')
                    assert msg_type_bytes not in self.msg_scheme_from_type, f"type collision? for {msg_type_name}"
                    assert msg_type_name not in self.msg_type_from_name, f"type collision? for {msg_type_name}"
                    row[2] = msg_type_int
                    self.msg_scheme_from_type[msg_type_bytes] = [tuple(row)]
                    self.msg_type_from_name[msg_type_name] = msg_type_bytes
                elif row[0] == "msgdata":
                    assert msg_type_name == row[1]
                    self.msg_scheme_from_type[msg_type_bytes].append(tuple(row))
                else:
                    pass  # TODO

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
                    field_name = row[2]
                    field_type = row[3]
                    field_count_str = row[4]
                    #print(f">>> encode_msg. msgdata. field_name={field_name!r}. field_type={field_type!r}. field_count_str={field_count_str!r}")
                    if field_count_str == "":
                        field_count = 1
                    else:
                        try:
                            field_count = int(field_count_str)
                        except ValueError:
                            field_count = kwargs[field_count_str]
                            if isinstance(field_count, (bytes, bytearray)):
                                field_count = int.from_bytes(field_count, byteorder="big")
                    assert isinstance(field_count, int)
                    try:
                        field_value = kwargs[field_name]
                    except KeyError:
                        if len(row) > 5:
                            break  # optional feature field not present
                        else:
                            field_value = 0  # default mandatory fields to zero
                    #print(f">>> encode_msg. writing field: {field_name}. value={field_value!r}. field_type={field_type!r}. count={field_count!r}")
                    try:
                        _write_field(fd=fd,
                                     field_type=field_type,
                                     count=field_count,
                                     value=field_value)
                        #print(f">>> encode_msg. so far: {fd.getvalue().hex()}")
                    except UnknownMsgFieldType as e:
                        pass  # TODO
                else:
                    pass  # TODO
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
                    if field_count_str == "":
                        field_count = 1
                    else:
                        try:
                            field_count = int(field_count_str)
                        except ValueError:
                            field_count = parsed[field_count_str]
                    assert isinstance(field_count, int)
                    #print(f">> count={field_count}. parsed={parsed}")
                    try:
                        parsed[field_name] = _read_field(fd=fd,
                                                         field_type=field_type,
                                                         count=field_count)
                    except UnknownMsgFieldType as e:
                        pass  # TODO
                    except UnexpectedEndOfStream as e:
                        if len(row) > 5:
                            break  # optional feature field not present
                        else:
                            raise
                else:
                    pass  # TODO
        return msg_type_name, parsed


_inst = LNSerializer()
encode_msg = _inst.encode_msg
decode_msg = _inst.decode_msg
