import socket
import ssl
import threading
import queue
import time

class Channel(queue.Queue):
    "simple Queue wrapper for using recv and send"

    def __init__(self, switch_timeout=None):
        queue.Queue.__init__(self)
        self.switch_timeout = switch_timeout

    def send(self, message):
        self.put(message, True, timeout=self.switch_timeout)

    def recv(self):
        return self.get(timeout=self.switch_timeout)

class ChannelWithPrint(queue.Queue):
    "Simple channel for logging"
    def send(self, message):
        print(message)
        self.put(message)

    def recv(self):
        return self.get()

class Commutator(threading.Thread):
    """Class for decoupling of send and recv ops."""
    def __init__(self, income, outcome, logger=ChannelWithPrint(),
                 buffsize=4096, timeout=1, switch_timeout=0.1, ssl=False):
        super(Commutator, self).__init__()
        self.daemon = True
        self.income = income
        self.outcome = outcome
        self.logger = logger
        self.alive = threading.Event()
        self.alive.set()
        self.socket = None
        self.magic = bytes.fromhex("42bcc32669467873")
        self.MAX_BLOCK_SIZE = buffsize
        self.timeout = timeout
        self.switch_timeout = switch_timeout
        self.ssl = ssl
        self.response = b''
        # self.debug = True

    def debug(self, obj):
        if self.logger:
            self.logger.put(str(obj))

    def run(self):
        while self.alive.isSet():
            if not self.income.empty():
                msg = self.income.get_nowait()
                if msg is not None:
                    self._send(msg)
                    self.debug('send!')
            else:
                # FIXME: this code is quite problematic and wastes resources by polling the socket. -Calin
                response = self._recv()
                if response:
                    self.outcome.put_nowait(response)
                    self.debug('recv')
                else:
                    # FIXME:
                    # Aside from wasting resources to poll, this spends 100ms sleeping meaning latency to socket receives is up to 100ms.
                    # If each client wastes an average of 50ms of time on socket receives for each protocol message
                    # -- then all that wasted time will add up collectively and make all cashshuffles take longer for all users.
                    # Consider a large transaction with 20 or 30 shuffles in it -- 50 ms * 30 = 1.5 seconds of JUST WAITING that could be
                    # avoided.
                    # -Calin
                    time.sleep(self.switch_timeout)
                    continue

    def join(self, timeout=None):
        self.alive.clear()
        if self.is_alive():
            super().join()
        if self.socket:
            self.socket.close()


    def connect(self, host, port):
        try:
            bare_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            bare_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            if self.ssl:
                self.socket = ssl.wrap_socket(bare_socket, ssl_version=ssl.PROTOCOL_TLSv1_2,
                                              ciphers="ECDHE-RSA-AES128-GCM-SHA256")
            else:
                self.socket = bare_socket
            self.socket.settimeout(self.timeout)
            self.socket.connect((host, port))
            self.socket.settimeout(0)
            self.socket.setblocking(0)
            self.debug('connected')
        except IOError as error:
            self.logger.put(str(error))
            raise error

    def _send(self, msg):
        message_length = len(msg).to_bytes(4, byteorder='big')
        message = self.magic + message_length + msg
        self.socket.sendall(message)

    def close(self):
        self.socket.close()
        self.debug('closed')

    def _recv(self):
        while True:
            if len(self.response) > 12:
                magic = self.response[0:8]
                if magic == self.magic:
                    msg_length = int.from_bytes(self.response[8:12], byteorder='big')
                    if len(self.response[12:]) >= msg_length:
                        result = self.response[12: 12 + msg_length]
                        self.response = self.response[12 + msg_length:]
                        return result
                else:
                    return None
            else:
                try:
                    message_part = self.socket.recv(self.MAX_BLOCK_SIZE)
                    if message_part:
                        self.response += message_part
                except socket.error:
                    return None
