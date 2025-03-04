from __future__ import print_function

'''SerialTransport implements wire transport over serial port.'''

# Local serial port loopback: socat PTY,link=COM8 PTY,link=COM9

from select import select
import serial
from select import select
from .transport import Transport

class SerialTransport(Transport):
    def __init__(self, device, *args, **kwargs):
        self.serial = None
        super(SerialTransport, self).__init__(device, *args, **kwargs)

    def _open(self):
        self.serial = serial.Serial(self.device, 115200, timeout=10, writeTimeout=10)

    def _close(self):
        self.serial.close()
        self.serial = None

    def ready_to_read(self):
        rlist, _, _ = select([self.serial], [], [], 0)
        return len(rlist) > 0

    def _write(self, msg, protobuf_msg):
        try:
            self.serial.write(msg)
            self.serial.flush()
        except serial.SerialException:
            print("Error while writing to socket")
            raise

    def _read(self):
        try:
            (msg_type, datalen) = self._read_headers(self.serial)
            return (msg_type, self.serial.read(datalen))
        except serial.SerialException:
            print("Failed to read from device")
            raise
