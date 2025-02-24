from __future__ import print_function
import os
from select import select
from .transport import Transport

"""PipeTransport implements fake wire transport over local named pipe.
Use this transport for talking with trezor simulator."""

class PipeTransport(Transport):
    def __init__(self, device, is_device, *args, **kwargs):
        self.is_device = is_device # Set True if act as device

        super(PipeTransport, self).__init__(device, *args, **kwargs)

    def _open(self):
        if self.is_device:
            self.filename_read = self.device+'.to'
            self.filename_write = self.device+'.from'

            os.mkfifo(self.filename_read, 0o600)
            os.mkfifo(self.filename_write, 0o600)
        else:
            self.filename_read = self.device+'.from'
            self.filename_write = self.device+'.to'

            if not os.path.exists(self.filename_write):
                raise Exception("Not connected")

        self.write_fd = os.open(self.filename_write, os.O_RDWR)#|os.O_NONBLOCK)
        self.write_f = os.fdopen(self.write_fd, 'w+b', 0)

        self.read_fd = os.open(self.filename_read, os.O_RDWR)#|os.O_NONBLOCK)
        self.read_f = os.fdopen(self.read_fd, 'rb', 0)

    def _close(self):
        self.read_f.close()
        self.write_f.close()
        if self.is_device:
            os.unlink(self.filename_read)
            os.unlink(self.filename_write)

    def ready_to_read(self):
        rlist, _, _ = select([self.read_f], [], [], 0)
        return len(rlist) > 0

    def _write(self, msg, protobuf_msg):
        try:
            self.write_f.write(msg)
            self.write_f.flush()
        except OSError:
            print("Error while writing to socket")
            raise

    def _read(self):
        try:
            (msg_type, datalen) = self._read_headers(self.read_f)
            return (msg_type, self.read_f.read(datalen))
        except IOError:
            print("Failed to read from device")
            raise
