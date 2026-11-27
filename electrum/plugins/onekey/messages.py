"""OneKey Protocol V2 management messages.

Wire IDs and fields follow OneKey's messages_common, messages_device_info,
messages_device_status and messages_device_session protobuf definitions.
Bitcoin messages retain the Trezor wire format; management messages do not.
"""

from trezorlib import messages
from trezorlib.mapping import ProtobufMapping
from trezorlib.protobuf import Field, MessageType


class ProtocolInfoRequest(MessageType):
    MESSAGE_WIRE_TYPE = 60200
    FIELDS = {1: Field("eventless_wallet_session", "bool")}


class ProtocolInfo(MessageType):
    MESSAGE_WIRE_TYPE = 60201
    FIELDS = {
        1: Field("version", "uint32", required=True),
        2: Field("build_fingerprint", "string", required=True),
        3: Field("supported_messages", "uint32", repeated=True),
    }


class Success(MessageType):
    MESSAGE_WIRE_TYPE = 60207
    FIELDS = {1: Field("message", "string")}


class Failure(MessageType):
    MESSAGE_WIRE_TYPE = 60208
    FIELDS = {
        1: Field("code", "uint32", required=True),
        2: Field("subcode", "uint32"),
        3: Field("message", "string"),
    }


class DeviceInfoTargets(MessageType):
    FIELDS = {100: Field("hw", "bool")}


class DeviceInfoTypes(MessageType):
    FIELDS = {40: Field("specific", "bool")}


class DeviceHardwareInfo(MessageType):
    FIELDS = {
        10: Field("device_type", "uint32"),
        20: Field("serial_no", "string"),
    }


class DeviceInfoGet(MessageType):
    MESSAGE_WIRE_TYPE = 60600
    FIELDS = {
        1: Field("targets", "DeviceInfoTargets"),
        2: Field("types", "DeviceInfoTypes"),
    }


class DeviceInfo(MessageType):
    MESSAGE_WIRE_TYPE = 60601
    FIELDS = {
        1: Field("protocol_version", "uint32", required=True),
        100: Field("hw", "DeviceHardwareInfo"),
    }


class DeviceStatusGet(MessageType):
    MESSAGE_WIRE_TYPE = 60602


class DeviceStatus(MessageType):
    MESSAGE_WIRE_TYPE = 60603
    FIELDS = {
        1: Field("device_id", "string"),
        2: Field("unlocked", "bool"),
        3: Field("init_states", "bool"),
        10: Field("passphrase_enabled", "bool"),
        12: Field("unlocked_by_attach_to_pin", "bool"),
    }


class DeviceSessionGet(MessageType):
    MESSAGE_WIRE_TYPE = 61200
    FIELDS = {
        1: Field("session_id", "bytes"),
        2: Field("btc_test_address", "string"),
    }


class DeviceSession(MessageType):
    MESSAGE_WIRE_TYPE = 61201
    FIELDS = {
        1: Field("session_id", "bytes"),
        2: Field("btc_test_address", "string"),
        3: Field("seed_domains", "uint32", repeated=True),
    }


class DeviceSessionAskPin(MessageType):
    MESSAGE_WIRE_TYPE = 61202
    FIELDS = {1: Field("type", "uint32")}


class DeviceSessionAskPassphrase(MessageType):
    MESSAGE_WIRE_TYPE = 61203
    FIELDS = {
        1: Field("passphrase", "string"),
        2: Field("on_device", "bool", required=True),
        3: Field("seed_domains", "uint32", repeated=True),
    }


MAPPING = ProtobufMapping()
for message in (
    ProtocolInfoRequest, ProtocolInfo, Success, Failure,
    DeviceInfoGet, DeviceInfo, DeviceStatusGet, DeviceStatus,
    DeviceSessionGet, DeviceSession, DeviceSessionAskPin, DeviceSessionAskPassphrase,
    messages.GetPublicKey, messages.PublicKey, messages.GetAddress, messages.Address,
    messages.SignTx, messages.TxAck, messages.TxRequest,
    messages.ButtonRequest, messages.ButtonAck, messages.Cancel,
):
    MAPPING.register(message)
