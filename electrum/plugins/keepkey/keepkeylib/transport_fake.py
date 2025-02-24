'''FakeTransport implements dummy interface for Transport.'''

# Local serial port loopback: socat PTY,link=COM8 PTY,link=COM9

from .transport import Transport, NotImplementedException

class FakeTransport(Transport):
    def __init__(self, device, *args, **kwargs):
        super(FakeTransport, self).__init__(device, *args, **kwargs)

    def _open(self):
        pass

    def _close(self):
        pass

    def ready_to_read(self):
        return False

    def _write(self, msg, protobuf_msg):
        pass

    def _read(self):
        raise NotImplementedException("Not implemented")
