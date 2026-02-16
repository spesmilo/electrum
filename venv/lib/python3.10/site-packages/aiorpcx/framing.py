# Copyright (c) 2018, Neil Booth
#
# All rights reserved.
#
# The MIT License (MIT)
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

'''RPC message framing in a byte stream.'''

__all__ = ('FramerBase', 'NewlineFramer', 'BinaryFramer', 'BitcoinFramer',
           'OversizedPayloadError', 'BadChecksumError', 'BadMagicError', )

from hashlib import sha256 as _sha256
from struct import Struct

from .curio import Queue


class FramerBase:
    '''Abstract base class for a framer.

    A framer breaks an incoming byte stream into protocol messages,
    buffering if necesary.  It also frames outgoing messages into
    a byte stream.
    '''

    def frame(self, message):
        '''Return the framed message.'''
        raise NotImplementedError

    def received_bytes(self, data):
        '''Pass incoming network bytes.'''
        raise NotImplementedError

    async def receive_message(self):
        '''Wait for a complete unframed message to arrive, and return it.'''
        raise NotImplementedError

    def fail(self, exception):
        '''Raise exception to receive_message.'''
        raise NotImplementedError


class NewlineFramer(FramerBase):
    '''A framer for a protocol where messages are separated by newlines.'''

    # The default max_size value is motivated by JSONRPC, where a
    # normal request will be 250 bytes or less, and a reasonable
    # batch may contain 4000 requests.
    def __init__(self, max_size=250 * 4000):
        '''max_size - an anti-DoS measure.  If, after processing an incoming message, buffered
        data would exceed max_size bytes, that buffered data is dropped entirely and the
        framer waits for a newline character to re-synchronize the stream.
        Set to zero to not limit the buffer size.
        '''
        self.max_size = max_size
        self.queue = Queue()
        self.received_bytes = self.queue.put_nowait
        self.synchronizing = False
        self.residual = b''
        self.exception = None

    def frame(self, message):
        return message + b'\n'

    def fail(self, exception):
        self.exception = exception
        self.received_bytes(b'')

    async def receive_message(self):
        parts = []
        buffer_size = 0
        while True:
            part = self.residual
            self.residual = b''
            if not part:
                part = await self.queue.get()
                if self.exception:
                    raise self.exception

            npos = part.find(b'\n')
            if npos == -1:
                parts.append(part)
                buffer_size += len(part)
                # Ignore over-sized messages; re-synchronize
                if buffer_size <= self.max_size or self.max_size == 0:
                    continue
                self.synchronizing = True
                raise MemoryError(f'dropping message over {self.max_size:,d} '
                                  f'bytes and re-synchronizing')

            tail, self.residual = part[:npos], part[npos + 1:]
            if self.synchronizing:
                self.synchronizing = False
                return await self.receive_message()
            else:
                parts.append(tail)
                return b''.join(parts)


class ByteQueue(object):
    '''A producer-comsumer queue.  Incoming network data is put as it
    arrives, and the consumer calls an async method waiting for data of
    a specific length.'''

    def __init__(self):
        self.queue = Queue()
        self.parts = []
        self.parts_len = 0
        self.put_nowait = self.queue.put_nowait
        self.exception = None

    def fail(self, exception):
        self.exception = exception
        self.put_nowait(b'')

    async def receive(self, size):
        if self.exception:
            raise self.exception
        while self.parts_len < size:
            part = await self.queue.get()
            if self.exception:
                raise self.exception
            self.parts.append(part)
            self.parts_len += len(part)
        self.parts_len -= size
        whole = b''.join(self.parts)
        self.parts = [whole[size:]]
        return whole[:size]


class BinaryFramer(object):
    '''A framer for binary messaging protocols.'''

    def __init__(self):
        self.byte_queue = ByteQueue()
        self.message_queue = Queue()
        self.received_bytes = self.byte_queue.put_nowait
        self.fail = self.byte_queue.fail

    def frame(self, message):
        command, payload = message
        return b''.join((
            self._build_header(command, payload),
            payload
        ))

    async def receive_message(self):
        command, payload_len, checksum = await self._receive_header()
        payload = await self.byte_queue.receive(payload_len)
        payload_checksum = self._checksum(payload)
        if payload_checksum != checksum:
            raise BadChecksumError(payload_checksum, checksum)
        return command, payload

    def _checksum(self, payload):
        raise NotImplementedError

    def _build_header(self, command, payload):
        raise NotImplementedError

    async def _receive_header(self):
        raise NotImplementedError


# Helpers
struct_le_I = Struct('<I')
pack_le_uint32 = struct_le_I.pack


def sha256(x):
    '''Simple wrapper of hashlib sha256.'''
    return _sha256(x).digest()


def double_sha256(x):
    '''SHA-256 of SHA-256, as used extensively in bitcoin.'''
    return sha256(sha256(x))


class BadChecksumError(Exception):
    cost = 100


class BadMagicError(Exception):
    cost = 1000


class OversizedPayloadError(Exception):
    cost = 500


BITCOIN_MAGIC = bytes.fromhex('e3e1f3e8')
MAX_BLOCK_SIZE = 128_000_000


class BitcoinFramer(BinaryFramer):
    '''Provides a framer of binary message payloads in the style of the
    Bitcoin network protocol.

    Each binary message has the following elements, in order:

       Magic    - to confirm network (currently unused for stream sync)
       Command  - padded command
       Length   - payload length in bytes
       Checksum - checksum of the payload
       Payload  - binary payload

    Call frame(command, payload) to get a framed message.
    Pass incoming network bytes to received_bytes().
    Wait on receive_message() to get incoming (command, payload) pairs.
    '''
    max_payload_size = 2_000_000

    def __init__(self, magic=BITCOIN_MAGIC, max_block_size=MAX_BLOCK_SIZE):
        def pad_command(command):
            fill = 12 - len(command)
            if fill < 0:
                raise ValueError(f'command {command} too long')
            return command + bytes(fill)

        super().__init__()
        self._magic = magic
        self._max_block_size = max_block_size
        self._pad_command = pad_command
        self._unpack = Struct('<4s12sI4s').unpack

    def _checksum(self, payload):
        return double_sha256(payload)[:4]

    def _build_header(self, command, payload):
        return b''.join((
            self._magic,
            self._pad_command(command),
            pack_le_uint32(len(payload)),
            self._checksum(payload)
        ))

    async def _receive_header(self):
        header = await self.byte_queue.receive(24)
        magic, command, payload_len, checksum = self._unpack(header)
        if magic != self._magic:
            raise BadMagicError(magic, self._magic)
        command = command.rstrip(b'\0')
        if payload_len > self.max_payload_size:
            if command != b'block' or payload_len > self._max_block_size:
                # Might be better to remove the payload
                raise OversizedPayloadError(command, payload_len)
        return command, payload_len, checksum
