from __future__ import print_function

'''SocketTransport implements TCP socket interface for Transport.'''

import socket
from select import select
from .transport import Transport

class FakeRead(object):
    # Let's pretend we have a file-like interface
    def __init__(self, func):
        self.func = func

    def read(self, size):
        return self.func(size)


class UDPTransport(Transport):
    def __init__(self, device, *args, **kwargs):
        self.buffer = b''
        device = device.split(':')
        if len(device) < 2:
            device = ('0.0.0.0', int(device[0]))
        else:
            device = (device[0], int(device[1]))

        self.socket = None

        super(UDPTransport, self).__init__(device, *args, **kwargs)

    def _open(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.connect(self.device)

    def _close(self):
        self.socket.close()
        self.socket = None
        self.buffer = ''

    def ready_to_read(self):
        rlist, _, _ = select([self.socket], [], [], 0)
        return len(rlist) > 0

    def _write(self, msg, protobuf_msg):

        for chunk in [msg[i:i+63] for i in range(0, len(msg), 63)]:
            chunk = chunk + b'\0' * (63 - len(chunk))
            self.socket.send(b'?' + chunk)

    def _read(self):
        try:
            (msg_type, datalen) = self._read_headers(FakeRead(self._raw_read))
            return (msg_type, self._raw_read(datalen))
        except socket.error:
            print("Failed to read from device")
            return None

    def _raw_read(self, length):
        while len(self.buffer) < length:
            data = self.socket.recv(64)
            self.buffer += data[1:]

        ret = self.buffer[:length]
        self.buffer = self.buffer[length:]
        return ret
