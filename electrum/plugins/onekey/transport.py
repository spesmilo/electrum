import struct
import time

import usb1

from electrum.util import UserCancelled, UserFacingException


USB_IDS = (0x1209, 0x4F4C)


def crc8(data):
    crc = 0x30
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0x8C if crc & 1 else 0)
    return crc


def encode_frame(wire_type, payload, sequence):
    length = len(payload) + 10
    if length > 0xFFFF:
        raise ValueError("OneKey frame too large")
    header = struct.pack("<BH", 0x5A, length)
    frame = header + bytes([crc8(header), 0, 0, sequence])
    frame += struct.pack("<H", wire_type) + payload
    return frame + bytes([crc8(frame)])


def device_path(device):
    return f"onekey:{device.getBusNumber()}:{device.getDeviceAddress()}"


class Transport:
    def __init__(self, path):
        self.context = usb1.USBContext()
        self.handle = None
        self.interface = None
        self.buffer = bytearray()
        self.sequence = 0
        try:
            for device in self.context.getDeviceIterator(skip_on_error=True):
                if (device.getVendorID(), device.getProductID()) != USB_IDS:
                    continue
                if device_path(device) != path:
                    continue
                for setting in device.iterSettings():
                    if setting.getClass() != 0xFF or setting.getAlternateSetting() != 0:
                        continue
                    endpoints = [ep.getAddress() for ep in setting.iterEndpoints()
                                 if ep.getAttributes() & 3 == usb1.TRANSFER_TYPE_BULK]
                    incoming = [ep for ep in endpoints if ep & 0x80]
                    outgoing = [ep for ep in endpoints if not ep & 0x80]
                    if len(incoming) != 1 or len(outgoing) != 1:
                        continue
                    self.handle = device.open()
                    interface = setting.getNumber()
                    self.handle.claimInterface(interface)
                    self.interface = interface
                    self.ep_in, self.ep_out = incoming[0], outgoing[0]
                    self._drain()
                    return
            raise UserFacingException("OneKey USB device not found.")
        except BaseException:
            self.close()
            raise

    def _drain(self):
        deadline = time.monotonic() + 1
        while time.monotonic() < deadline:
            try:
                self.handle.bulkRead(self.ep_in, 4096, timeout=50)
            except usb1.USBErrorTimeout:
                return
        raise UserFacingException("OneKey USB connection is busy.")

    def close(self):
        try:
            if self.handle is not None:
                try:
                    if self.interface is not None:
                        self.handle.releaseInterface(self.interface)
                finally:
                    self.handle.close()
        finally:
            self.handle = None
            self.interface = None
            self.context.close()
            self.buffer.clear()

    def write(self, wire_type, payload):
        self.sequence = self.sequence % 255 + 1
        frame = encode_frame(wire_type, payload, self.sequence)
        if self.handle.bulkWrite(self.ep_out, frame, timeout=5000) != len(frame):
            raise UserFacingException("Incomplete OneKey USB write.")

    def read(self, *, cancelled=None, timeout=120):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if cancelled is not None and cancelled():
                raise UserCancelled()
            if len(self.buffer) >= 4:
                if self.buffer[0] != 0x5A or crc8(self.buffer[:3]) != self.buffer[3]:
                    raise UserFacingException("Invalid OneKey frame header.")
                length = int.from_bytes(self.buffer[1:3], "little")
                if length < 8:
                    raise UserFacingException("Invalid OneKey frame length.")
                if len(self.buffer) >= length:
                    frame = self.buffer[:length]
                    del self.buffer[:length]
                    if crc8(frame[:-1]) != frame[-1]:
                        raise UserFacingException("Invalid OneKey frame checksum.")
                    if frame[4] != 0 or frame[5] >> 2 != 0:
                        raise UserFacingException("Unexpected OneKey frame channel.")
                    if frame[5] & 3 == 1:  # link-layer acknowledgement
                        continue
                    if frame[5] & 3 != 0 or length < 10:
                        raise UserFacingException("Invalid OneKey data frame.")
                    return int.from_bytes(frame[7:9], "little"), bytes(frame[9:-1])
            try:
                self.buffer.extend(self.handle.bulkRead(self.ep_in, 4096, timeout=200))
            except usb1.USBErrorTimeout:
                continue
        raise UserFacingException("OneKey USB request timed out.")
