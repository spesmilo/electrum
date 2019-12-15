import socket, ssl, threading, queue, time, requests, select, errno
from electrum.network import Network
from electrum.interface import Connection
from electrum.util import print_error, PrintError

# urllib3 may be missing from requests namespace in older requests versions. safe to ignore. See Electron-Cash#1172
if hasattr(requests, 'urllib3'):
    # Temporary hack to suppress InsecureRequestWarning. Need to actually do a
    # whole song and dance to verify SSL certs. Blergh.
    # https://urllib3.readthedocs.io/en/latest/user-guide.html#ssl
    #
    # Note: We do end up verifying SSL certs per-socket, but we do it explicitly
    # in verify_ssl_socket() in this fiile, and not necessarily for _every_ urllib3
    # request.
    requests.urllib3.disable_warnings(requests.urllib3.exceptions.InsecureRequestWarning)


class Channel(queue.Queue):
    """ simple Queue wrapper for using recv and send """

    def __init__(self, switch_timeout=None):
        queue.Queue.__init__(self)
        self.switch_timeout = switch_timeout

    def send(self, message):
        self.put(message, True, timeout=self.switch_timeout)

    def send_nowait(self, m):
        self.put_nowait(m)

    def recv(self):
        return self.get(timeout=self.switch_timeout)

    def recv_nowait(self):
        return self.get_nowait()


class ChannelWithPrint(Channel, PrintError):
    """ Simple channel for logging """
    def __init__(self, switch_timeout = None):
        super().__init__(switch_timeout)

    def send(self, message):
        self.logger.error(message)
        super().send(message)

    def send_nowait(self, message):
        self.logger.error(message)
        super().send_nowait(message)


class ChannelSendLambda:
    ''' Channel work-alike that just forwards sends to a lambda x '''
    def __init__(self, func):
        self.func = func

    def send(self, message):
        self.func(message)

class BadServerPacketError(Exception):
    pass

class Comm(PrintError):

    MAX_MSG_LENGTH = 64*1024 # 64kb message length limit on server-side. If we get anything longer it's a malicious server


    def __init__(self, host, port, bufsize = 32768, timeout = 60.0, ssl = False,
                 infoText = None):
        self.host = host
        self.port = port
        self.socket = None
        self.magic = bytes.fromhex("42bcc32669467873")
        self.MAX_BLOCK_SIZE = bufsize
        self.timeout = timeout
        self.recvbuf = bytearray()
        self.ssl = ssl
        self.infoText = infoText
        self._connected = False
        self.lock = threading.Lock()

    def connect(self, ctimeout = 5.0):
        ''' Not thread safe. Call this from a single thread at a time. '''
        try:
            self._connected = False
            if self.ssl and not verify_ssl_socket(self.host, self.port, timeout = ctimeout):
                raise OSError(errno.EINVAL, "Failed to verify SSL certificate for {}, aborting".format(self.host))
            bare_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            bare_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            bare_socket.settimeout(ctimeout)
            bare_socket.connect((self.host, self.port))
            if self.ssl:
                self.socket = ssl.wrap_socket(bare_socket, ssl_version=ssl.PROTOCOL_TLSv1_2,
                                              ciphers="ECDHE-RSA-AES128-GCM-SHA256")
            else:
                self.socket = bare_socket
            self.socket.settimeout(self.timeout) # blocking socket with a timeout -- when recv times out the enclosing protocol thread exits
            self._connected = True
        except OSError as error:
            self.logger.error("Socket Error on connect: {}".format(str(error)))
            raise error

    def send(self, msg):
        ''' Not thread safe. '''
        message_length = len(msg).to_bytes(4, byteorder='big')
        message = self.magic + message_length + msg
        if self.is_connected(): self.socket.sendall(message)

    def recv(self):
        ''' Not thread safe. '''

        def LEN():
            return len(self.recvbuf)
        def READ():
            try:
                self.recvbuf.extend( self._recv() ) # will always return non-zero data or will raise
            except socket.timeout as e:
                self.logger.error("Socket timeout ({}): {}".format(self.socket.gettimeout(), str(e)))
                raise e

        msg_length, magic = None, None

        while self.is_connected():
            if magic is None or msg_length is None:
                if LEN() <= 12:
                    READ()
                else:
                    magic = self.recvbuf[:8]
                    if magic != self.magic:
                        raise BadServerPacketError("Bad magic in message: 0x{}".format(magic.hex()))
                    msg_length = int.from_bytes(self.recvbuf[8:12], byteorder='big')
                    if msg_length > self.MAX_MSG_LENGTH:
                        raise BadServerPacketError("Got a packet with msg_length={} > {} (max)".format(msg_length, self.MAX_MSG_LENGTH))
                    elif msg_length <= 0:
                        raise BadServerPacketError("Got a packet with msg_length={}".format(msg_length))
                    del self.recvbuf[:12] # consume packet header, loop will now spend its time in the else clause below..
            else:
                if LEN() < msg_length:
                    READ()
                else:
                    ret = bytes( self.recvbuf[:msg_length] ) # return a copy of the message as bytes
                    del self.recvbuf[:msg_length] # consume data
                    return ret
        raise OSError(errno.ENOTCONN, "Not connected")

    def _recv(self):
        if self.is_connected():
            ret = self.socket.recv(self.MAX_BLOCK_SIZE)
            if not ret:
                raise OSError(errno.ECONNABORTED, "Connection reset by peer")
            return ret
        raise OSError(errno.EINVAL, "_recv called with closed/disconnected socket!")

    def close(self):
        ''' Thread safe. '''
        with self.lock:
            if self.socket and self.socket.fileno() > -1:
                self.logger.error("Closing comm (subsequent socket errors are to be expected)")
                try:
                    self._connected = False
                    self.socket.shutdown(socket.SHUT_RDWR)
                except OSError:
                    # Socket was not actually connected
                    pass
                finally:
                    del self.recvbuf[:]  # just to be safe, clear out recvbuf data, if any
                    try: self.socket.close()  # fileno() is now -1
                    except OSError: pass

    def is_connected(self):
        ''' Thread safe. '''
        with self.lock:
            return bool(self._connected and self.socket and self.socket.fileno() > -1)

    def diagnostic_name(self):
        n = super().diagnostic_name() or ""
        n += " <{}:{}>".format(self.host, self.port)
        if self.infoText: n += " <{}>".format(self.infoText)
        return n

def query_server_for_stats(host : str, stat_port : int, ssl : bool, timeout = None):
    ''' May raise OSError, ValueError, TypeError if there are connectivity or other issues '''

    proxies = (Network.get_instance() and Network.get_instance().get_proxies()) or None

    if timeout is None:
        timeout = 3.0 if not proxies else 10.0
    secure = "s" if ssl else ""
    stat_endpoint = "http{}://{}:{}/stats".format(secure, host, stat_port)
    res = requests.get(stat_endpoint, verify=False, timeout=timeout, proxies=proxies)
    json = res.json()
    return (int(json["shufflePort"]), int(json["poolSize"]),
            int(json["connections"]), json['pools'],
            int(json.get('banScore',0)), bool(json.get('banned',False)))

def verify_ssl_socket(host, port, timeout = 5.0):
    path = (Network.get_instance() and Network.get_instance().config and Network.get_instance().config.path) or None
    if not path:
        print_error("verify_ssl_socket: no config path!")
        return False
    server = "{}:{}:s".format(host, port)
    q = queue.Queue()
    c = Connection(server, q, path)
    socket = None
    try:
        server, socket = q.get(timeout=timeout)
    except queue.Empty:
        pass
    ret = bool(socket and socket.fileno() > -1)
    if socket: socket.close()
    del (q,c,socket,server)
    return ret
