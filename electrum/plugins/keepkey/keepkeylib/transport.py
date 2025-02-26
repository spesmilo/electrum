import struct
from . import mapping

class NotImplementedException(Exception):
    pass

class ConnectionError(Exception):
    pass

class Transport(object):
    def __init__(self, device, *args, **kwargs):
        self.device = device
        self.session_depth = 0
        self._open()

    def _open(self):
        raise NotImplementedException("Not implemented")

    def _close(self):
        raise NotImplementedException("Not implemented")

    def _write(self, msg, protobuf_msg):
        raise NotImplementedException("Not implemented")

    def _read(self):
        raise NotImplementedException("Not implemented")

    def _session_begin(self):
        pass

    def _session_end(self):
        pass

    def ready_to_read(self):
        """
        Returns True if there is data to be read from the transport.  Otherwise, False.
        """
        raise NotImplementedException("Not implemented")

    def session_begin(self):
        """
        Apply a lock to the device in order to preform synchronous multistep "conversations" with the device.  For example, before entering the transaction signing workflow, one begins a session.  After the transaction is complete, the session may be ended.
        """
        if self.session_depth == 0:
            self._session_begin()
        self.session_depth += 1

    def session_end(self):
        """
        End a session.  Se session_begin for an in depth description of TREZOR sessions.
        """
        self.session_depth -= 1
        self.session_depth = max(0, self.session_depth)
        if self.session_depth == 0:
            self._session_end()

    def close(self):
        """
        Close the connection to the physical device or file descriptor represented by the Transport.
        """
        self._close()

    def write(self, msg):
        """
        Write mesage to tansport.  msg should be a member of a valid `protobuf class <https://developers.google.com/protocol-buffers/docs/pythontutorial>`_ with a SerializeToString() method.
        """
        ser = msg.SerializeToString()
        header = struct.pack(">HL", mapping.get_type(msg), len(ser))
        self._write(b"##" + header + ser, msg)

    def read(self):
        """
        If there is data available to be read from the transport, reads the data and tries to parse it as a protobuf message.  If the parsing succeeds, return a protobuf object.
        Otherwise, returns None.
        """
        if not self.ready_to_read():
            return None

        data = self._read()
        if data is None:
            return None

        return self._parse_message(data)

    def read_blocking(self):
        """
        Same as read, except blocks untill data is available to be read.
        """
        while True:
            data = self._read()
            if data != None:
                break

        return self._parse_message(data)

    def _parse_message(self, data):
        (msg_type, data) = data
        if msg_type == 'protobuf':
            return data
        else:
            inst = mapping.get_class(msg_type)()
            inst.ParseFromString(data)
            return inst

    def _read_headers(self, read_f):
        # Try to read headers until some sane value are detected
        is_ok = False
        while not is_ok:

            # Align cursor to the beginning of the header ("##")
            c = read_f.read(1)
            i = 0
            while c != b"#":
                i += 1
                if i >= 64:
                    # timeout
                    raise Exception("Timed out while waiting for the magic character")
                c = read_f.read(1)

            if read_f.read(1) != b"#":
                # Second character must be # to be valid header
                raise Exception("Second magic character is broken")

            # Now we're most likely on the beginning of the header
            try:
                headerlen = struct.calcsize(">HL")
                (msg_type, datalen) = struct.unpack(">HL", read_f.read(headerlen))
                break
            except:
                raise Exception("Cannot parse header length")

        return (msg_type, datalen)
