import socket
import logging


logger = logging.getLogger(__name__)


#
# Low-level Serial-via-TCP backend interface to Jade
# Calls to send and receive bytes over the interface.
# Intended for use via JadeInterface wrapper.
#
# Either:
#  a) use via JadeInterface.create_serial() (see JadeInterface)
# (recommended)
# or:
#  b) use JadeTCPImpl() directly, and call connect() before
#     using, and disconnect() when finished,
# (caveat cranium)
#
class JadeTCPImpl:
    PROTOCOL_PREFIX = 'tcp:'

    @classmethod
    def isSupportedDevice(cls, device):
        return device is not None and device.startswith(cls.PROTOCOL_PREFIX)

    def __init__(self, device, timeout):
        assert self.isSupportedDevice(device)
        self.device = device
        self.timeout = timeout
        self.tcp_sock = None

    def connect(self):
        assert self.isSupportedDevice(self.device)
        assert self.tcp_sock is None

        logger.info('Connecting to {}'.format(self.device))
        self.tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp_sock.settimeout(self.timeout)

        url = self.device[len(self.PROTOCOL_PREFIX):].split(':')
        self.tcp_sock.connect((url[0], int(url[1])))
        assert self.tcp_sock is not None

        self.tcp_sock.__enter__()
        logger.info('Connected')

    def disconnect(self):
        assert self.tcp_sock is not None
        self.tcp_sock.__exit__()

        # Reset state
        self.tcp_sock = None

    def write(self, bytes_):
        assert self.tcp_sock is not None
        return self.tcp_sock.send(bytes_)

    def read(self, n):
        assert self.tcp_sock is not None
        buf = self.tcp_sock.recv(n)
        while len(buf) < n:
            buf += self.tcp_sock.recv(n - len(buf))
        return buf
