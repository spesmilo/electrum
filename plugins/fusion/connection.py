#!/usr/bin/env python3
#
# Electron Cash - a lightweight Bitcoin Cash client
# CashFusion - an advanced coin anonymizer
#
# Copyright (C) 2020 Mark B. Lundeberg
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
"""
Message-based communications system for CashFusion.

This only implements a framing protocol:

    <8 byte magic><4 byte length (big endian) of message><message>
    <8 byte magic><4 byte length (big endian) of message><message>
    ...
    <8 byte magic><4 byte length (big endian) of message><message>
"""

import certifi
import socket
import socks
import ssl
import time
from contextlib import suppress

sslcontext = ssl.create_default_context(cafile=certifi.where())

class BadFrameError(Exception):
    pass

def open_connection(host, port, conn_timeout = 5.0, default_timeout = 5.0, ssl = False, socks_opts=None):
    """Open a connection as client to the specified server.

    If `socks_opts` is None, a direct connection will be made using
    `socket.create_connection`. Otherwise, a proxied connection will be
    made using `socks.create_connection`, including socks_opts as keyword
    arguments. Within that connection, an SSL tunnel will be established
    if `ssl` is True.
    """

    if socks_opts is None:
        bare_socket = socket.create_connection((host, port), timeout=conn_timeout)
    else:
        bare_socket = socks.create_connection((host, port), timeout=conn_timeout, **socks_opts)

    if ssl:
        try:
            conn_socket = sslcontext.wrap_socket(bare_socket, server_hostname=host)
        except:
            bare_socket.close()
            raise
    else:
        conn_socket = bare_socket

    try:
        return Connection(conn_socket, default_timeout)
    except:
        conn_socket.close()
        raise

class Connection:
    # Message length limit. Anything longer is considered to be a malicious server.
    # The all-initial-commitments and all-components messages can be big (~100 kB in large fusions).
    MAX_MSG_LENGTH = 200*1024
    magic = bytes.fromhex("765be8b4e4396dcf")

    def __init__(self, socket, timeout):
        self.socket = socket
        self.timeout = timeout

        socket.settimeout(timeout)
        self.recvbuf = bytearray()

    def __enter__(self):
        self.socket.__enter__()

    def __exit__(self, etype, evalue, traceback):
        self.socket.__exit__(etype, evalue, traceback)

    def send_message(self, msg, timeout = None):
        """ Sends message; if this times out, the connection should be
        abandoned since it's not possible to know how much data was sent.
        """
        lengthbytes = len(msg).to_bytes(4, byteorder='big')
        frame = self.magic + lengthbytes + msg

        if timeout is None:
            timeout = self.timeout
        self.socket.settimeout(timeout)
        try:
            self.socket.sendall(frame)
        except (ssl.SSLWantWriteError, ssl.SSLWantReadError) as e:
            raise socket.timeout from e

    def recv_message(self, timeout = None):
        """ Read message, default timeout is self.timeout.

        If it times out, behaviour is well defined in that no data is lost,
        and the next call will functions properly.
        """
        if timeout is None:
            timeout = self.timeout

        if timeout is None:
            max_time = None
            self.socket.settimeout(timeout)
        else:
            max_time = time.monotonic() + timeout

        recvbuf = self.recvbuf

        def fillbuf(n):
            # read until recvbuf contains at least n bytes
            while True:
                if len(recvbuf) >= n:
                    return

                if max_time is not None:
                    remtime = max_time - time.monotonic()
                    if remtime < 0:
                        raise socket.timeout
                    self.socket.settimeout(remtime)

                try:
                    data = self.socket.recv(65536)
                except (ssl.SSLWantWriteError, ssl.SSLWantReadError) as e:
                    # these SSL errors should be reported as a timeout
                    raise socket.timeout from e

                if not data:
                    if self.recvbuf:
                        raise ConnectionError("Connection ended mid-message.")
                    else:
                        raise ConnectionError("Connection ended while awaiting message.")
                recvbuf.extend(data)

        try:
            fillbuf(12)
            magic = recvbuf[:8]
            if magic != self.magic:
                raise BadFrameError("Bad magic in frame: {}".format(magic.hex()))
            message_length = int.from_bytes(recvbuf[8:12], byteorder='big')
            if message_length > self.MAX_MSG_LENGTH:
                raise BadFrameError("Got a frame with msg_length={} > {} (max)".format(message_length, self.MAX_MSG_LENGTH))
            fillbuf(12 + message_length)

            # we have a complete message
            message = bytes(recvbuf[12:12 + message_length])
            del recvbuf[:12 + message_length]
            return message
        finally:
            with suppress(OSError):
                self.socket.settimeout(self.timeout)

    def close(self):
        with suppress(OSError):
            self.socket.settimeout(self.timeout)
            self.socket.shutdown(socket.SHUT_RDWR)
        with suppress(OSError):
            self.socket.close()
