import socket, ssl, threading, queue, time, requests, select, errno
from .client import PrintErrorThread
from electroncash.network import deserialize_proxy
from electroncash.interface import Connection

# Temporary hack to suppress InsecureRequestWarning. Need to actually do a whole song and dance
# To verify SSL certs. Blergh.  https://urllib3.readthedocs.io/en/latest/user-guide.html#ssl
requests.urllib3.disable_warnings(requests.urllib3.exceptions.InsecureRequestWarning)

class Channel(queue.Queue):
    "simple Queue wrapper for using recv and send"

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


class ChannelWithPrint(Channel, PrintErrorThread):
    "Simple channel for logging"
    def __init__(self, switch_timeout = None):
        super().__init__(switch_timeout)

    def send(self, message):
        self.print_error(message)
        super().send(message)

    def send_nowait(self, message):
        self.print_error(message)
        super().send_nowait(message)


class ChannelSendLambda:
    ''' Channel work-alike that just forwards sends to a lambda x '''
    def __init__(self, func):
        self.func = func

    def send(self, message):
        self.func(message)

class BadServerPacketError(Exception):
    pass

class Comm(PrintErrorThread):
    
    MAX_MSG_LENGTH = 64*1024 # 64kb message length limit on server-side. If we get anything longer it's a malicious server


    def __init__(self, host, port, config, bufsize = 32768, timeout = 60.0, ssl = False):
        self.host = host
        self.port = port
        self.config = config
        self.socket = None
        self.magic = bytes.fromhex("42bcc32669467873")
        self.MAX_BLOCK_SIZE = bufsize
        self.timeout = timeout
        self.recvbuf = b''
        self.ssl = ssl
        self.connected = False

    def connect(self, ctimeout = 5.0):
        try:
            if self.ssl and not verify_ssl_socket(self.host, self.port, self.config, timeout = ctimeout):
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
            self.connected = True
        except OSError as error:
            self.print_error("Socket Error on connect: {}".format(str(error)))
            raise error

    def send(self, msg):
        message_length = len(msg).to_bytes(4, byteorder='big')
        message = self.magic + message_length + msg
        if self.connected: self.socket.sendall(message)

    def recv(self):

        def LEN():
            return len(self.recvbuf)
        def READ():
            try:
                self.recvbuf += self._recv() # will always return non-zero data or will raise
            except socket.timeout as e:
                self.print_error("Socket timeout ({}): {}".format(self.socket.gettimeout(), str(e)))
                raise e

        msg_length, magic = None, None

        while self.connected:
            if magic is None or msg_length is None:
                if LEN() <= 12:
                    READ()
                else:
                    magic = self.recvbuf[0:8]
                    if magic != self.magic:
                        raise BadServerPacketError("Bad magic in message: '{}'".format(str(self.recvbuf)))
                    msg_length = int.from_bytes(self.recvbuf[8:12], byteorder='big')
                    if msg_length > self.MAX_MSG_LENGTH:
                        raise BadServerPacketError("Got a packet with msg_length={} > {} (max)".format(msg_length,self.MAX_MSG_LENGTH))
                    elif msg_length <= 0:
                        raise BadServerPacketError("Got a packet with msg_length={}".format(msg_length))
                    self.recvbuf = self.recvbuf[12:] # consume packet header, loop will now spend its time in the else clause below..
            else:
                if LEN() < msg_length:
                    READ()
                else:
                    ret = self.recvbuf[:msg_length]
                    self.recvbuf = self.recvbuf[msg_length:] # consume data
                    return ret
        raise OSError(errno.ENOTCONN, "Not connected")

    def _recv(self):
        if self.connected and self.socket:
            ret = self.socket.recv(self.MAX_BLOCK_SIZE)
            if not ret:
                raise OSError(errno.ECONNABORTED, "Connection reset by peer")
            return ret
        raise OSError(errno.EINVAL, "_recv called with closed/disconnected socket!")

    def close(self):
        if self.socket and self.connected:
            self.print_error("Closing comm -- subsequent socket errors are to be expected. :)")
            try:
                self.connected = False
                self.socket.shutdown(socket.SHUT_RDWR)
                self.socket.close()
            except OSError:
                # Socket was already closed
                pass

    def diagnostic_name(self):
        n = super().diagnostic_name() or ""
        n += " <{}:{}>".format(self.host, self.port)
        return n

def query_server_for_stats(host : str, stat_port : int, ssl : bool, timeout = None, config = None):
    ''' May raise OSError, ValueError, TypeError if there are connectivity or other issues '''

    proxy = (config and config.get('proxy')) or None

    if proxy:
        proxy = deserialize_proxy(proxy)
        pre = ''
        # proxies format for requests lib is eg:
        # {
        #   'http'  : 'socks[45]://user:password@host:port',
        #   'https' : 'socks[45]://user:password@host:port'
        # }
        # with user:password@ being omitted if no user/password.
        if proxy.get('user') and proxy.get('password'):
            pre = '{}:{}@'.format(proxy.get('user'), proxy.get('password'))
        mode = proxy.get('mode')
        if mode and mode.lower() == "socks5":
            mode += 'h' # socks5 with hostname resolution on the server side so it works with tor
        socks = '{}://{}{}:{}'.format(mode, pre, proxy.get('host'), proxy.get('port'))
        proxy = { # transform it to requests format
            'http' : socks,
            'https' : socks
        }
    if timeout is None:
        timeout = 3.0 if not proxy else 10.0
    secure = "s" if ssl else ""
    stat_endpoint = "http{}://{}:{}/stats".format(secure, host, stat_port)
    res = requests.get(stat_endpoint, verify=False, timeout=timeout, proxies=proxy)
    json = res.json()
    return int(json["shufflePort"]), int(json["poolSize"]), int(json["connections"]), json['pools']

def verify_ssl_socket(host, port, config, timeout = 5.0):
    server = "{}:{}:s".format(host, port)
    q = queue.Queue()
    c = Connection(server, q, config.path)
    socket = None
    try:
        server, socket = q.get(timeout=timeout)
    except queue.Empty:
        pass
    ret = bool(socket and socket.fileno() > -1)
    if socket: socket.close()
    del (q,c,socket,server)
    return ret

