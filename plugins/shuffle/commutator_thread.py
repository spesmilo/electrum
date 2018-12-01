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
                self._send(msg)
                self.debug('send!')
            else:
                response = self._recv()
                if response:
                    self.outcome.put_nowait(response)
                    self.debug('recv')
                else:
                    time.sleep(self.switch_timeout)
                    continue

    def join(self, timeout=None):
        self.alive.clear()
        self.socket.close()
        super().join(timeout)


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
