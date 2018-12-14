import socket, ssl, threading, queue, time, requests, select, errno
from .client import PrintErrorThread
from electroncash.network import deserialize_proxy

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

class Comm(PrintErrorThread):
    def __init__(self, host, port, bufsize = 32768, timeout = 300.0, ssl = False):
        self.host = host
        self.port = port
        self.socket = None
        self.magic = bytes.fromhex("42bcc32669467873")
        self.MAX_BLOCK_SIZE = bufsize
        self.timeout = timeout
        self.recvbuf = b''
        self.ssl = ssl
        self.connected = False

    def connect(self, ctimeout = 5.0):
        try:
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
        while self.connected:
            if len(self.recvbuf) > 12:
                magic = self.recvbuf[0:8]
                if magic == self.magic:
                    msg_length = int.from_bytes(self.recvbuf[8:12], byteorder='big')
                    if len(self.recvbuf[12:]) >= msg_length:
                        result = self.recvbuf[12: 12 + msg_length]
                        self.recvbuf = self.recvbuf[12 + msg_length:]
                        return result
                else:
                    raise RuntimeError("Bad magic in message: '{}'".format(str(self.recvbuf)))
            else:
                try:
                    message_part = self._recv()
                    if message_part:
                        self.recvbuf += message_part
                except socket.timeout as e:
                    self.print_error("Socket timeout ({}): {}".format(self.socket.gettimeout(), str(e)))
                    raise e

    def _recv(self):
        if self.connected and self.socket:
            rd, wr, ex = select.select([self.socket.fileno()], [], [self.socket.fileno()], self.timeout)
            assert not wr, "Non-empty write file descriptor returned from select!"
            if ex:
                self.print_error("Socket exception returned from select!")
                raise OSError(errno.EIO, "Socket exception returned from select")
            if rd:
                ret = self.socket.recv(self.MAX_BLOCK_SIZE) # may raise socket.timeout which calling code catches.
                if not ret:
                    # 0 bytes returned means connection reset by peer, as per man 2 recv()
                    raise OSError(errno.ECONNABORTED, "Connection reset by peer")
                return ret
            # else...
            raise socket.timeout("Socket timeout in select")
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
        socks = '{}://{}{}:{}'.format(proxy.get('mode'), pre, proxy.get('host'), proxy.get('port'))
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
