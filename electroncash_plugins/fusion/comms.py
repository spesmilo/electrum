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
Protobuf communications system and a generic server+client
"""
import queue
import socket
import sys
import threading
import traceback

from . import fusion_pb2 as pb
from .connection import Connection, BadFrameError
from .util import FusionError
from .validation import ValidationError
from google.protobuf.message import DecodeError

from weakref import WeakSet

from electroncash import networks
from electroncash.util import PrintError

# Make a small patch to the generated protobuf:
# We have some "outer" message types that simply contain a "oneof", with various
# submessages having unique types. So, we create an inverse mapping here from the
# submessage's type (its MessageDescriptor) to the field name.
for mtype in pb.ClientMessage, pb.ServerMessage, pb.CovertMessage, pb.CovertResponse:
    mtype._messagedescriptor_names = {d.message_type : n for n,d in mtype.DESCRIPTOR.fields_by_name.items()}

def send_pb(connection, pb_class, submsg, timeout=None):
    # Wrap the submessage into an outer message.
    # note - _messagedescriptor_names is patched in, see above
    fieldname = pb_class._messagedescriptor_names[submsg.DESCRIPTOR]
    msg = pb_class(**{fieldname: submsg})
    msgbytes = msg.SerializeToString()
    try:
        connection.send_message(msgbytes, timeout=timeout)
    except ConnectionError as e:
        raise FusionError('connection closed by remote') from e
    except socket.timeout as e:
        raise FusionError('timed out during send') from e
    except OSError as exc:
        raise FusionError('Communications error: {}: {}'.format(type(exc).__name__, exc)) from exc
    # Other exceptions propagate up

def recv_pb(connection, pb_class, *expected_field_names, timeout=None):
    try:
        blob = connection.recv_message(timeout = timeout)
    except ConnectionError as e:
        raise FusionError('connection closed by remote') from e
    except BadFrameError as e:
        raise FusionError('corrupted communication: ' + e.args[0]) from e
    except socket.timeout as e:
        raise FusionError('timed out during receive') from e
    except OSError as exc:
        if exc.errno == 9:
            raise FusionError('connection closed by local') from exc
        else:
            raise FusionError('Communications error: {}: {}'.format(type(exc).__name__, exc)) from exc
    # Other exceptions propagate up

    msg = pb_class()
    try:
        length = msg.ParseFromString(blob)
    except DecodeError as e:
        raise FusionError('message decoding error') from e

    if not msg.IsInitialized():
        raise FusionError('incomplete message received')

    mtype = msg.WhichOneof('msg')
    if mtype is None:
        raise FusionError('unrecognized message')
    submsg = getattr(msg, mtype)

    if mtype not in expected_field_names:
        raise FusionError('got {} message, expecting {}'.format(mtype, expected_field_names))

    return submsg, mtype

_last_net = None
_last_genesis_hash = None
def get_current_genesis_hash() -> bytes:
    """Returns the genesis_hash of this Electron Cash install's current chain.
    Note that it detects if the chain has changed, and otherwise caches the raw
    32-bytes value.  This is suitable for putting into the ClientHello message.
    Both server and client call this function."""
    global _last_net, _last_genesis_hash
    if not _last_genesis_hash or _last_net != networks.net:
        _last_genesis_hash = bytes(reversed(bytes.fromhex(networks.net.GENESIS)))
        _last_net = networks.net
    return _last_genesis_hash

# Below stuff is used in the test server

class ClientHandlerThread(threading.Thread, PrintError):
    """A per-connection thread for running a series of queued jobs.
    (this should be slaved to a controller)

    In case of ValidationError during a job, this will call `send_error` before
    closing the connection. You can implement this in subclasses.
    """
    noisy = True
    class Disconnect(Exception):
        pass

    def __init__(self, connection):
        super().__init__(name=f"Fusion {type(self).__name__}")
        self.connection = connection
        self.dead = False
        self.jobs = queue.Queue()
        self.peername = None

    def diagnostic_name(self):
        if self.peername is None and self.connection and self.connection.socket:
            try: self.peername = ':'.join(str(x) for x in self.connection.socket.getpeername())
            except: pass  # on some systems socket.getpeername() is not supported
        peername = self.peername or '???'
        return f'Client {peername}'

    def addjob(self, job, *args):
        try:
            self.jobs.put((job, args))
        except AttributeError:
            pass # if tried to put job after cleanup

    def run(self,):
        try:
            while True:
                try:
                    job, args = self.jobs.get(timeout=60)
                except queue.Empty:
                    raise FusionError('timed out due to lack of work (BUG)')
                try:
                    job(self, *args)
                except ValidationError as e:
                    self.print_error(str(e))
                    self.send_error(str(e))
                    return
        except self.Disconnect:
            pass
        except FusionError as exc:
            if self.noisy:
                self.print_error('failed: {}'.format(exc))
        except Exception:
            self.print_error('failed with exception')
            traceback.print_exc(file=sys.stderr)
        finally:
            self.dead = True
            del self.jobs # gc
            self.connection.close()

    def send_error(self, errormsg):
        pass

    @staticmethod
    def _killjob(c, reason):
        if reason is not None:
            c.send_error(reason)
            raise FusionError(f'killed: {reason}')
        raise FusionError(f'killed')

    def kill(self, reason = None):
        """ Kill this connection. If no reason provided then the connection
        will be closed immediately, otherwise job a with 'send_error' will
        be eventually run (after current job finishes) then the connection
        will be closed. """
        self.dead = True
        # clear any other jobs
        while True:
            try:
                self.jobs.get_nowait()
            except (AttributeError, queue.Empty):
                break

        if reason is None:
            self.connection.close()

        self.addjob(self._killjob, reason)

class GenericServer(threading.Thread, PrintError):
    client_default_timeout = 5
    noisy = True

    def diagnostic_name(self):
        return f'{type(self).__name__}({self.host}:{self.port})'

    def __init__(self, bindhost, port, clientclass, upnp = None):
        """ If `port` is 0, then an ephemeral OS-selected port will be assigned.

        `bindhost` may be '0.0.0.0' in which case external connections will be
        accepted. (use at your own risk of DoS attacks!)

        if `upnp` is provided it should be a miniupnpc.UPnP object which has
        already been initialized with .discover() and .selectigd().

        `clientclass` should be a subclass of `ClientHandlerThread`."""
        super().__init__()
        self.daemon = True
        self.clientclass = clientclass
        self.bindhost = bindhost
        self.upnp = upnp

        listensock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        listensock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listensock.bind((bindhost, port))
        listensock.listen(20)
        listensock.settimeout(1)
        self.listensock = listensock

        self.local_port = listensock.getsockname()[1]

        if upnp is not None:
            eport = self.local_port
            # find a free port for the redirection
            r = upnp.getspecificportmapping(eport, 'TCP')
            while r != None and eport < 65536:
                eport = eport + 1
                r = upnp.getspecificportmapping(eport, 'TCP')

            b = upnp.addportmapping(eport, 'TCP', upnp.lanaddr, self.local_port,
                                    'CashFusion', '')

            self.local_host = upnp.lanaddr
            self.host = upnp.externalipaddress()
            self.port = eport
        else:
            if bindhost == '0.0.0.0':
                # discover local IP by making a 'connection' to internet.
                # (no packets sent, it's UDP)
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    s.connect(('8.8.8.8', 1))
                    host = s.getsockname()[0]
                except:
                    host = '127.0.0.1'
                finally:
                    s.close()
            else:
                host = bindhost
            self.host = self.local_host = host
            self.port = self.local_port

        self.name = self.diagnostic_name()

        self.stopping = False
        self.lock = threading.RLock()
        self.spawned_clients = WeakSet()

    def stop(self, reason = None):
        with self.lock:
            self.stopping = True
            for c in self.spawned_clients:
                c.kill(reason = reason)

    def run(self,):
        self.print_error("started")
        try:
            while True:
                if self.stopping:
                    break
                try:
                    sock, src = self.listensock.accept()
                except socket.timeout:
                    continue
                with self.lock:
                    if self.stopping:
                        sock.close()
                        break
                    if self.noisy:
                        srcstr = ':'.join(str(x) for x in src)
                        self.print_error(f'new client: {srcstr}')
                        del srcstr
                    connection = Connection(sock, self.client_default_timeout)
                    client = self.clientclass(connection)
                    client.noisy = self.noisy
                    self.spawned_clients.add(client)
                    client.addjob(self.new_client_job)
                    client.start()
        except:
            self.print_error('failed with exception')
            traceback.print_exc(file=sys.stderr)
        try:
            self.listensock.close()
        except:
            pass
        try:
            self.upnp.deleteportmapping(self.port, 'TCP')
        except:
            pass
        self.print_error("stopped")

    def new_client_job(self, client):
        raise FusionError("client handler not implemented")
