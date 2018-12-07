import socket, ssl, threading, queue, time, requests
from .client import PrintErrorThread

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

    def connect(self):
        try:
            bare_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            bare_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            if self.ssl:
                self.socket = ssl.wrap_socket(bare_socket, ssl_version=ssl.PROTOCOL_TLSv1_2,
                                              ciphers="ECDHE-RSA-AES128-GCM-SHA256")
            else:
                self.socket = bare_socket
            self.socket.settimeout(5.0)
            self.socket.connect((self.host, self.port))
            self.socket.settimeout(self.timeout) # blocking socket with a timeout -- when recv times out the enclosing protocol thread exits
        except OSError as error:
            self.print_error("Socket Error on connect: {}".format(str(error)))
            raise error

    def send(self, msg):
        message_length = len(msg).to_bytes(4, byteorder='big')
        message = self.magic + message_length + msg
        self.socket.sendall(message)

    def recv(self):
        while True:
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
                    message_part = self.socket.recv(self.MAX_BLOCK_SIZE)
                    if message_part:
                        self.recvbuf += message_part
                except socket.timeout as e:
                    self.print_error("Socket timeout ({}): {}".format(self.socket.gettimeout(), str(e)))
                    raise e

    def close(self):
        if self.socket:
            self.socket.close()


def query_server_for_shuffle_port(host : str, stat_port : int, ssl : bool, timeout : float = 3.0) -> int:
    ''' May raise OSError, ValueError, TypeError if there are connectivity or other issues '''
    secure = "s" if ssl else ""
    stat_endpoint = "http{}://{}:{}/stats".format(secure, host, stat_port)
    res = requests.get(stat_endpoint, verify=False, timeout=timeout)
    return int(res.json()["shufflePort"])
