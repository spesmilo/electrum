# Electrum - Lightweight Bitcoin Client
# Copyright (c) 2011-2016 Thomas Voegtlin
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

import time
import queue
import os
import stat
import errno
import random
import re
import select
from collections import defaultdict
import threading
import socket
import json

import socks
from . import util
from . import bitcoin
from .bitcoin import *
from .networks import NetworkConstants
from .i18n import _
from .interface import Connection, Interface
from . import blockchain
from .version import PACKAGE_VERSION, PROTOCOL_VERSION


NODES_RETRY_INTERVAL = 60
SERVER_RETRY_INTERVAL = 10


def parse_servers(result):
    """ parse servers list into dict format"""
    from .version import PROTOCOL_VERSION
    servers = {}
    for item in result:
        host = item[1]
        out = {}
        version = None
        pruning_level = '-'
        if len(item) > 2:
            for v in item[2]:
                if re.match("[st]\d*", v):
                    protocol, port = v[0], v[1:]
                    if port == '': port = bitcoin.NetworkConstants.DEFAULT_PORTS[protocol]
                    out[protocol] = port
                elif re.match("v(.?)+", v):
                    version = v[1:]
                elif re.match("p\d*", v):
                    pruning_level = v[1:]
                if pruning_level == '': pruning_level = '0'
        if out:
            out['pruning'] = pruning_level
            out['version'] = version
            servers[host] = out
    return servers

def filter_version(servers):
    def is_recent(version):
        try:
            return util.normalize_version(version) >= util.normalize_version(PROTOCOL_VERSION)
        except Exception as e:
            return False
    return {k: v for k, v in servers.items() if is_recent(v.get('version'))}


def filter_protocol(hostmap, protocol = 's'):
    '''Filters the hostmap for those implementing protocol.
    The result is a list in serialized form.'''
    eligible = []
    for host, portmap in hostmap.items():
        port = portmap.get(protocol)
        if port:
            eligible.append(serialize_server(host, port, protocol))
    return eligible

def pick_random_server(hostmap = None, protocol = 's', exclude_set = set()):
    if hostmap is None:
        hostmap = bitcoin.NetworkConstants.DEFAULT_SERVERS
    eligible = list(set(filter_protocol(hostmap, protocol)) - exclude_set)
    return random.choice(eligible) if eligible else None

from .simple_config import SimpleConfig

proxy_modes = ['socks4', 'socks5', 'http']


def serialize_proxy(p):
    if not isinstance(p, dict):
        return None
    return ':'.join([p.get('mode'), p.get('host'), p.get('port'),
                     p.get('user', ''), p.get('password', '')])


def deserialize_proxy(s):
    if not isinstance(s, str):
        return None
    if s.lower() == 'none':
        return None
    proxy = { "mode":"socks5", "host":"localhost" }
    args = s.split(':')
    n = 0
    if proxy_modes.count(args[n]) == 1:
        proxy["mode"] = args[n]
        n += 1
    if len(args) > n:
        proxy["host"] = args[n]
        n += 1
    if len(args) > n:
        proxy["port"] = args[n]
        n += 1
    else:
        proxy["port"] = "8080" if proxy["mode"] == "http" else "1080"
    if len(args) > n:
        proxy["user"] = args[n]
        n += 1
    if len(args) > n:
        proxy["password"] = args[n]
    return proxy


def deserialize_server(server_str):
    host, port, protocol = str(server_str).rsplit(':', 2)
    assert protocol in 'st'
    int(port)    # Throw if cannot be converted to int
    return host, port, protocol


def serialize_server(host, port, protocol):
    return str(':'.join([host, port, protocol]))


class Network(util.DaemonThread):
    """The Network class manages a set of connections to remote electrum
    servers, each connected socket is handled by an Interface() object.
    Connections are initiated by a Connection() thread which stops once
    the connection succeeds or fails.

    Our external API:

    - Member functions get_header(), get_interfaces(), get_local_height(),
          get_parameters(), get_server_height(), get_status_value(),
          is_connected(), set_parameters(), stop()
    """

    def __init__(self, config=None):
        if config is None:
            config = {}  # Do not use mutables as default values!
        util.DaemonThread.__init__(self)
        self.config = SimpleConfig(config) if isinstance(config, dict) else config
        self.num_server = 10 if not self.config.get('oneserver') else 0
        self.blockchains = blockchain.read_blockchains(self.config)
        self.print_error("blockchains", self.blockchains.keys())
        self.blockchain_index = config.get('blockchain_index', 0)
        if self.blockchain_index not in self.blockchains.keys():
            self.blockchain_index = 0
        # Server for addresses and transactions
        self.default_server = self.config.get('server', None)
        # Sanitize default server
        if self.default_server:
            try:
                deserialize_server(self.default_server)
            except:
                self.print_error('Warning: failed to parse server-string; falling back to random.')
                self.default_server = None
        if not self.default_server:
            self.default_server = pick_random_server()

        self.lock = threading.Lock()
        # locks: if you need to take multiple ones, acquire them in the order they are defined here!
        self.interface_lock = threading.RLock()            # <- re-entrant
        self.pending_sends_lock = threading.Lock()

        self.pending_sends = []
        self.message_id = 0
        self.verified_checkpoint = False
        self.verifications_required = 1
        # If the height is cleared from the network constants, we're
        # taking looking to get 3 confirmations of the first verification.
        if bitcoin.NetworkConstants.VERIFICATION_BLOCK_HEIGHT is None:
            self.verifications_required = 3
        self.checkpoint_servers_verified = {}
        self.debug = False
        self.irc_servers = {} # returned by interface (list from irc)
        self.recent_servers = self.read_recent_servers()

        self.banner = ''
        self.donation_address = ''
        self.relay_fee = None
        # callbacks passed with subscriptions
        self.subscriptions = defaultdict(list)
        self.sub_cache = {}                     # note: needs self.interface_lock
        # callbacks set by the GUI
        self.callbacks = defaultdict(list)

        dir_path = os.path.join( self.config.path, 'certs')
        if not os.path.exists(dir_path):
            os.mkdir(dir_path)
            os.chmod(dir_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)

        # subscriptions and requests
        self.subscribed_addresses = set()
        # Requests from client we've not seen a response to
        self.unanswered_requests = {}
        # retry times
        self.server_retry_time = time.time()
        self.nodes_retry_time = time.time()
        # kick off the network.  interface is the main server we are currently
        # communicating with.  interfaces is the set of servers we are connecting
        # to or have an ongoing connection with
        self.interface = None                   # note: needs self.interface_lock
        self.interfaces = {}                    # note: needs self.interface_lock
        self.auto_connect = self.config.get('auto_connect', True)
        self.connecting = set()
        self.requested_chunks = set()
        self.socket_queue = queue.Queue()
        self.start_network(deserialize_server(self.default_server)[2],
                           deserialize_proxy(self.config.get('proxy')))

    def register_callback(self, callback, events):
        with self.lock:
            for event in events:
                self.callbacks[event].append(callback)

    def unregister_callback(self, callback):
        with self.lock:
            for callbacks in self.callbacks.values():
                if callback in callbacks:
                    callbacks.remove(callback)

    def trigger_callback(self, event, *args):
        with self.lock:
            callbacks = self.callbacks[event][:]
        [callback(event, *args) for callback in callbacks]

    def recent_servers_file(self):
        return os.path.join(self.config.path, "recent-servers")

    def read_recent_servers(self):
        if not self.config.path:
            return []
        try:
            with open(self.recent_servers_file(), "r", encoding='utf-8') as f:
                data = f.read()
                return json.loads(data)
        except:
            return []

    def save_recent_servers(self):
        if not self.config.path:
            return
        s = json.dumps(self.recent_servers, indent=4, sort_keys=True)
        try:
            with open(self.recent_servers_file(), "w", encoding='utf-8') as f:
                f.write(s)
        except:
            pass

    def get_server_height(self):
        return self.interface.tip if self.interface else 0

    def server_is_lagging(self):
        sh = self.get_server_height()
        if not sh:
            self.print_error('no height for main interface')
            return True
        lh = self.get_local_height()
        result = (lh - sh) > 1
        if result:
            self.print_error('%s is lagging (%d vs %d)' % (self.default_server, sh, lh))
        return result

    def set_status(self, status):
        self.connection_status = status
        self.notify('status')

    def is_connected(self):
        return self.interface is not None

    def is_connecting(self):
        return self.connection_status == 'connecting'

    def is_up_to_date(self):
        return self.unanswered_requests == {}

    def queue_request(self, method, params, interface=None):
        # If you want to queue a request on any interface it must go
        # through this function so message ids are properly tracked
        if interface is None:
            interface = self.interface
        message_id = self.message_id
        self.message_id += 1
        if self.debug:
            self.print_error(interface.host, "-->", method, params, message_id)
        interface.queue_request(method, params, message_id)
        return message_id

    def send_subscriptions(self):
        self.print_error('sending subscriptions to', self.interface.server, len(self.unanswered_requests), len(self.subscribed_addresses))
        self.sub_cache.clear()
        # Resend unanswered requests
        requests = self.unanswered_requests.values()
        self.unanswered_requests = {}
        for request in requests:
            message_id = self.queue_request(request[0], request[1])
            self.unanswered_requests[message_id] = request
        self.queue_request('server.banner', [])
        self.queue_request('server.donation_address', [])
        self.queue_request('server.peers.subscribe', [])
        self.request_fee_estimates()
        self.queue_request('blockchain.relayfee', [])
        for h in self.subscribed_addresses:
            self.queue_request('blockchain.scripthash.subscribe', [h])

    def request_fee_estimates(self):
        self.config.requested_fee_estimates()
        for i in bitcoin.FEE_TARGETS:
            self.queue_request('blockchain.estimatefee', [i])

    def get_status_value(self, key):
        if key == 'status':
            value = self.connection_status
        elif key == 'banner':
            value = self.banner
        elif key == 'fee':
            value = self.config.fee_estimates
        elif key == 'updated':
            value = (self.get_local_height(), self.get_server_height())
        elif key == 'servers':
            value = self.get_servers()
        elif key == 'interfaces':
            value = self.get_interfaces()
        return value

    def notify(self, key):
        if key in ['status', 'updated']:
            self.trigger_callback(key)
        else:
            self.trigger_callback(key, self.get_status_value(key))

    def get_parameters(self):
        host, port, protocol = deserialize_server(self.default_server)
        return host, port, protocol, self.proxy, self.auto_connect

    def get_donation_address(self):
        if self.is_connected():
            return self.donation_address

    def get_interfaces(self):
        '''The interfaces that are in connected state'''
        return list(self.interfaces.keys())

    def get_servers(self):
        out = bitcoin.NetworkConstants.DEFAULT_SERVERS
        if self.irc_servers:
            out.update(filter_version(self.irc_servers.copy()))
        else:
            for s in self.recent_servers:
                try:
                    host, port, protocol = deserialize_server(s)
                except:
                    continue
                if host not in out:
                    out[host] = { protocol:port }
        return out

    def start_interface(self, server):
        if (not server in self.interfaces and not server in self.connecting):
            if server == self.default_server:
                self.print_error("connecting to %s as new interface" % server)
                self.set_status('connecting')
            self.connecting.add(server)
            c = Connection(server, self.socket_queue, self.config.path)

    def start_random_interface(self):
        exclude_set = self.disconnected_servers.union(set(self.interfaces))
        server = pick_random_server(self.get_servers(), self.protocol, exclude_set)
        if server:
            self.start_interface(server)

    def start_interfaces(self):
        self.start_interface(self.default_server)
        for i in range(self.num_server - 1):
            self.start_random_interface()

    def set_proxy(self, proxy):
        self.proxy = proxy
        # Store these somewhere so we can un-monkey-patch
        if not hasattr(socket, "_socketobject"):
            socket._socketobject = socket.socket
            socket._getaddrinfo = socket.getaddrinfo
        if proxy:
            self.print_error('setting proxy', proxy)
            proxy_mode = proxy_modes.index(proxy["mode"]) + 1
            socks.setdefaultproxy(proxy_mode,
                                  proxy["host"],
                                  int(proxy["port"]),
                                  # socks.py seems to want either None or a non-empty string
                                  username=(proxy.get("user", "") or None),
                                  password=(proxy.get("password", "") or None))
            socket.socket = socks.socksocket
            # prevent dns leaks, see http://stackoverflow.com/questions/13184205/dns-over-proxy
            socket.getaddrinfo = lambda *args: [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (args[0], args[1]))]
        else:
            socket.socket = socket._socketobject
            socket.getaddrinfo = socket._getaddrinfo

    def start_network(self, protocol, proxy):
        assert not self.interface and not self.interfaces
        assert not self.connecting and self.socket_queue.empty()
        self.print_error('starting network')
        self.disconnected_servers = set([])
        self.protocol = protocol
        self.set_proxy(proxy)
        self.start_interfaces()

    def stop_network(self):
        self.print_error("stopping network")
        for interface in list(self.interfaces.values()):
            self.close_interface(interface)
        if self.interface:
            self.close_interface(self.interface)
        assert self.interface is None
        assert not self.interfaces
        self.connecting = set()
        # Get a new queue - no old pending connections thanks!
        self.socket_queue = queue.Queue()

    def set_parameters(self, host, port, protocol, proxy, auto_connect):
        proxy_str = serialize_proxy(proxy)
        server = serialize_server(host, port, protocol)
        # sanitize parameters
        try:
            deserialize_server(serialize_server(host, port, protocol))
            if proxy:
                proxy_modes.index(proxy["mode"]) + 1
                int(proxy['port'])
        except:
            return
        self.config.set_key('auto_connect', auto_connect, False)
        self.config.set_key("proxy", proxy_str, False)
        self.config.set_key("server", server, True)
        # abort if changes were not allowed by config
        if self.config.get('server') != server or self.config.get('proxy') != proxy_str:
            return
        self.auto_connect = auto_connect
        if self.proxy != proxy or self.protocol != protocol:
            # Restart the network defaulting to the given server
            self.stop_network()
            self.default_server = server
            self.start_network(protocol, proxy)
        elif self.default_server != server:
            self.switch_to_interface(server)
        else:
            self.switch_lagging_interface()
            self.notify('updated')

    def switch_to_random_interface(self):
        '''Switch to a random connected server other than the current one'''
        servers = self.get_interfaces()    # Those in connected state
        if self.default_server in servers:
            servers.remove(self.default_server)
        if servers:
            self.switch_to_interface(random.choice(servers))

    def switch_lagging_interface(self):
        '''If auto_connect and lagging, switch interface'''
        if self.server_is_lagging() and self.auto_connect:
            # switch to one that has the correct header (not height)
            header = self.blockchain().read_header(self.get_local_height())
            filtered = list(map(lambda x:x[0], filter(lambda x: x[1].tip_header==header, self.interfaces.items())))
            if filtered:
                choice = random.choice(filtered)
                self.switch_to_interface(choice)

    def switch_to_interface(self, server):
        '''Switch to server as our interface.  If no connection exists nor
        being opened, start a thread to connect.  The actual switch will
        happen on receipt of the connection notification.  Do nothing
        if server already is our interface.'''
        self.default_server = server
        if server not in self.interfaces:
            self.interface = None
            self.start_interface(server)
            return
        i = self.interfaces[server]
        if self.interface != i:
            self.print_error("switching to", server)
            # stop any current interface in order to terminate subscriptions
            # fixme: we don't want to close headers sub
            #self.close_interface(self.interface)
            self.interface = i
            self.send_subscriptions()
            self.set_status('connected')
            self.notify('updated')

    def close_interface(self, interface):
        if interface:
            if interface.server in self.interfaces:
                self.interfaces.pop(interface.server)
            if interface.server == self.default_server:
                self.interface = None
            interface.close()

    def add_recent_server(self, server):
        # list is ordered
        if server in self.recent_servers:
            self.recent_servers.remove(server)
        self.recent_servers.insert(0, server)
        self.recent_servers = self.recent_servers[0:20]
        self.save_recent_servers()

    def process_response(self, interface, request, response, callbacks):
        if self.debug:
            self.print_error("<--", response)
        error = response.get('error')
        result = response.get('result')
        method = response.get('method')
        params = response.get('params')

        # We handle some responses; return the rest to the client.
        if method == 'server.version':
            self.on_server_version(interface, result)
        elif method == 'blockchain.headers.subscribe':
            if error is None:
                self.on_notify_header(interface, result)
        elif method == 'server.peers.subscribe':
            if error is None:
                self.irc_servers = parse_servers(result)
                self.notify('servers')
        elif method == 'server.banner':
            if error is None:
                self.banner = result
                self.notify('banner')
        elif method == 'server.donation_address':
            if error is None:
                self.donation_address = result
        elif method == 'blockchain.estimatefee':
            if error is None and result > 0:
                i = params[0]
                fee = int(result*COIN)
                self.config.update_fee_estimates(i, fee)
                self.print_error("fee_estimates[%d]" % i, fee)
                self.notify('fee')
        elif method == 'blockchain.relayfee':
            if error is None:
                self.relay_fee = int(result * COIN)
                self.print_error("relayfee", self.relay_fee)
        elif method == 'blockchain.block.headers':
            self.on_block_headers(interface, request, response)
        elif method == 'blockchain.block.header':
            self.on_header(interface, request, response)

        for callback in callbacks:
            callback(response)

    def get_index(self, method, params):
        """ hashable index for subscriptions and cache"""
        return str(method) + (':' + str(params[0]) if params else '')

    def process_responses(self, interface):
        responses = interface.get_responses()
        for request, response in responses:
            if request:
                method, params, message_id = request
                k = self.get_index(method, params)
                # client requests go through self.send() with a
                # callback, are only sent to the current interface,
                # and are placed in the unanswered_requests dictionary
                client_req = self.unanswered_requests.pop(message_id, None)
                if client_req:
                    assert interface == self.interface
                    callbacks = [client_req[2]]
                else:
                    # fixme: will only work for subscriptions
                    k = self.get_index(method, params)
                    callbacks = self.subscriptions.get(k, [])

                # Copy the request method and params to the response
                response['method'] = method
                response['params'] = params
                # Only once we've received a response to an addr subscription
                # add it to the list; avoids double-sends on reconnection
                if method == 'blockchain.scripthash.subscribe':
                    self.subscribed_addresses.add(params[0])
            else:
                if not response:  # Closed remotely / misbehaving
                    self.connection_down(interface.server)
                    break
                # Rewrite response shape to match subscription request response
                method = response.get('method')
                params = response.get('params')
                k = self.get_index(method, params)
                if method == 'blockchain.headers.subscribe':
                    response['result'] = params[0]
                    response['params'] = []
                elif method == 'blockchain.scripthash.subscribe':
                    response['params'] = [params[0]]  # addr
                    response['result'] = params[1]
                callbacks = self.subscriptions.get(k, [])

            # update cache if it's a subscription
            if method.endswith('.subscribe'):
                with self.interface_lock:
                    self.sub_cache[k] = response
            # Response is now in canonical form
            self.process_response(interface, request, response, callbacks)

    def subscribe_to_scripthashes(self, scripthashes, callback):
        msgs = [('blockchain.scripthash.subscribe', [sh])
                for sh in scripthashes]
        self.send(msgs, callback)

    def request_scripthash_history(self, sh, callback):
        self.send([('blockchain.scripthash.get_history', [sh])], callback)

    def send(self, messages, callback):
        '''Messages is a list of (method, params) tuples'''
        messages = list(messages)
        with self.pending_sends_lock:
            self.pending_sends.append((messages, callback))

    def process_pending_sends(self):
        # Requests needs connectivity.  If we don't have an interface,
        # we cannot process them.
        if not self.interface:
            return

        with self.pending_sends_lock:
            sends = self.pending_sends
            self.pending_sends = []

        for messages, callback in sends:
            for method, params in messages:
                r = None
                if method.endswith('.subscribe'):
                    k = self.get_index(method, params)
                    # add callback to list
                    l = self.subscriptions.get(k, [])
                    if callback not in l:
                        l.append(callback)
                    self.subscriptions[k] = l
                    # check cached response for subscriptions
                    r = self.sub_cache.get(k)
                if r is not None:
                    util.print_error("cache hit", k)
                    callback(r)
                else:
                    message_id = self.queue_request(method, params)
                    self.unanswered_requests[message_id] = method, params, callback

    def unsubscribe(self, callback):
        '''Unsubscribe a callback to free object references to enable GC.'''
        # Note: we can't unsubscribe from the server, so if we receive
        # subsequent notifications process_response() will emit a harmless
        # "received unexpected notification" warning
        with self.lock:
            for v in self.subscriptions.values():
                if callback in v:
                    v.remove(callback)

    def connection_down(self, server):
        '''A connection to server either went down, or was never made.
        We distinguish by whether it is in self.interfaces.'''
        self.disconnected_servers.add(server)
        if server == self.default_server:
            self.set_status('disconnected')
        if server in self.interfaces:
            self.close_interface(self.interfaces[server])
            self.notify('interfaces')
        for b in self.blockchains.values():
            if b.catch_up == server:
                b.catch_up = None

    def new_interface(self, server, socket):
        self.add_recent_server(server)

        interface = Interface(server, socket)
        interface.blockchain = None
        interface.tip_header = None
        interface.tip = 0
        if self.verified_checkpoint:
            interface.set_mode('default')
        else:
            interface.set_mode('verification')
        with self.interface_lock:
            self.interfaces[server] = interface

        # server.version should be the first message
        params = [PACKAGE_VERSION, PROTOCOL_VERSION]
        self.queue_request('server.version', params, interface)
        # The interface will immediately respond with it's last known header.
        self.queue_request('blockchain.headers.subscribe', [], interface)

        if server == self.default_server:
            self.switch_to_interface(server)

    def maintain_sockets(self):
        '''Socket maintenance.'''
        # Responses to connection attempts?
        while not self.socket_queue.empty():
            server, socket = self.socket_queue.get()
            if server in self.connecting:
                self.connecting.remove(server)
            if socket:
                self.new_interface(server, socket)
            else:
                self.connection_down(server)

        # Send pings and shut down stale interfaces
        # must use copy of values
        with self.interface_lock:
            interfaces = list(self.interfaces.values())
        for interface in interfaces:
            if interface.has_timed_out():
                self.connection_down(interface.server)
            elif interface.ping_required():
                self.queue_request('server.ping', [], interface)

        now = time.time()
        # nodes
        with self.interface_lock:
            if len(self.interfaces) + len(self.connecting) < self.num_server:
                self.start_random_interface()
                if now - self.nodes_retry_time > NODES_RETRY_INTERVAL:
                    self.print_error('network: retrying connections')
                    self.disconnected_servers = set([])
                    self.nodes_retry_time = now

        # main interface
        with self.interface_lock:
            if not self.is_connected():
                if self.auto_connect:
                    if not self.is_connecting():
                        self.switch_to_random_interface()
                else:
                    if self.default_server in self.disconnected_servers:
                        if now - self.server_retry_time > SERVER_RETRY_INTERVAL:
                            self.disconnected_servers.remove(self.default_server)
                            self.server_retry_time = now
                    else:
                        self.switch_to_interface(self.default_server)
            else:
                if self.config.is_fee_estimates_update_required():
                    self.request_fee_estimates()

    def request_chunk(self, interface, chunk_index):
        if chunk_index in self.requested_chunks:
            return False
        self.requested_chunks.add(chunk_index)

        interface.print_msg("requesting chunk {}".format(chunk_index))
        chunk_base_height = chunk_index * 2016
        chunk_count = 2016
        self.request_headers(interface, chunk_base_height, chunk_count, silent=True)
        return True

    def request_headers(self, interface, base_height, count, silent=False):
        if not silent:
            interface.print_msg("requesting multiple consecutive headers, from {} count {}".format(base_height, count))
        if count > 2016:
            raise Exception("Server does not support requesting more than 2016 consecutive headers")

        top_height = base_height + count - 1
        if top_height > bitcoin.NetworkConstants.VERIFICATION_BLOCK_HEIGHT:
            if base_height < bitcoin.NetworkConstants.VERIFICATION_BLOCK_HEIGHT:
                # As part of the verification process, we fetched the set of headers that allowed manual verification of the post-checkpoint headers that were fetched
                # as part of the "catch-up" process.  This requested header batch overlaps the checkpoint, so we know we have the post-checkpoint segment from the
                # "catch-up".  This leaves us needing some header preceding the checkpoint, and we can clip the batch to the checkpoint to ensure we can verify the
                # fetched batch, which we wouldn't otherwise be able to do manually as we cannot guarantee we have the headers preceding the batch.
                interface.print_msg("clipping request across checkpoint height {} ({} -> {})".format(bitcoin.NetworkConstants.VERIFICATION_BLOCK_HEIGHT, base_height, top_height))
                verified_count = bitcoin.NetworkConstants.VERIFICATION_BLOCK_HEIGHT - base_height + 1
                self._request_headers(interface, base_height, verified_count, bitcoin.NetworkConstants.VERIFICATION_BLOCK_HEIGHT)
            else:
                self._request_headers(interface, base_height, count)
        else:
            self._request_headers(interface, base_height, count, bitcoin.NetworkConstants.VERIFICATION_BLOCK_HEIGHT)

    def _request_headers(self, interface, base_height, count, checkpoint_height=0):
        params = [base_height, count, checkpoint_height]
        self.queue_request('blockchain.block.headers', params, interface)

    def on_block_headers(self, interface, request, response):
        '''Handle receiving a chunk of block headers'''
        error = response.get('error')
        result = response.get('result')
        params = response.get('params')
        if not request or result is None or params is None or error is not None:
            interface.print_error(error or 'bad response')
            # Ensure the chunk can be rerequested, but only if the request originated from us.
            if request and request[1][0] // 2016 in self.requested_chunks:
                self.requested_chunks.remove(request[1][0] // 2016)
            return

        # Ignore unsolicited chunks
        request_params = request[1]
        request_base_height = request_params[0]
        expected_header_count = request_params[1]
        index = request_base_height // 2016
        if request_params != params:
            interface.print_error("unsolicited chunk base_height={} count={}".format(request_base_height, expected_header_count))
            return
        if index in self.requested_chunks:
            self.requested_chunks.remove(index)

        header_hexsize = 80 * 2
        hexdata = result['hex']
        actual_header_count = len(hexdata) // header_hexsize
        # We accept less headers than we asked for, to cover the case where the distance to the tip was unknown.
        if actual_header_count > expected_header_count:
            interface.print_error("chunk data size incorrect expected_size={} actual_size={}".format(expected_header_count * header_hexsize, len(hexdata)))
            return

        proof_was_provided = False
        if 'root' in result and 'branch' in result:
            header_height = request_base_height + actual_header_count - 1
            header_offset = (actual_header_count - 1) * header_hexsize
            header = hexdata[header_offset : header_offset + header_hexsize]
            if not self.validate_checkpoint_result(interface, result["root"], result["branch"], header, header_height):
                # Got checkpoint validation data, server failed to provide proof.
                self.connection_down(interface.server)
                return

            data = bfh(hexdata)
            try:
                blockchain.verify_proven_chunk(request_base_height, data)
            except blockchain.VerifyError as e:
                interface.print_error('verify_proven_chunk failed: {}'.format(e))
                self.connection_down(interface.server)
                return

            proof_was_provided = True
        elif len(request_params) == 3 and request_params[2] != 0:
            # Expected checkpoint validation data, did not receive it.
            self.connection_down(interface.server)
            return

        verification_top_height = self.checkpoint_servers_verified.get(interface.server, {}).get('height', None)
        was_verification_request = verification_top_height and request_base_height == verification_top_height - 147 + 1 and actual_header_count == 147

        if interface.mode == 'verification':
            if not proof_was_provided or not was_verification_request:
                self.connection_down(interface.server)
                return

            self.apply_successful_verification(interface, request_params[2], result['root'])
            # If this is not the final verification, we throw it away.
            if interface.mode == 'verification':
                return

        connect = interface.blockchain.connect_chunk(request_base_height, hexdata, proof_was_provided)
        if not connect:
            interface.print_msg("discarded unconnected chunk, height={} count={}".format(request_base_height, actual_header_count))
            self.connection_down(interface.server)
            return
        else:
            interface.print_msg("connected chunk, height={} count={} proof_was_provided={}".format(request_base_height, actual_header_count, proof_was_provided))

        # If not finished, get the next chunk.
        if proof_was_provided and not was_verification_request:
            # the verifier must have asked for this chunk.  It has been overlaid into the file.
            pass
        else:
            if interface.blockchain.height() < interface.tip:
                self.request_headers(interface, request_base_height + actual_header_count, 2016)
            else:
                interface.set_mode('default')
                interface.print_msg('catch up done', interface.blockchain.height())
                interface.blockchain.catch_up = None
        self.notify('updated')

    def request_header(self, interface, height):
        '''
        This works for all modes except for 'default'.

        If it is to be used for piecemeal filling of the sparse blockchain
        headers file before the checkpoint height, it needs extra
        handling for the 'default' mode.

        A server interface does not get associated with a blockchain
        until it gets handled in the response to it's first header
        request.
        '''
        #interface.print_msg("requesting header %d" % height)
        if height > bitcoin.NetworkConstants.VERIFICATION_BLOCK_HEIGHT:
            params = [height]
        else:
            params = [height, bitcoin.NetworkConstants.VERIFICATION_BLOCK_HEIGHT]
        self.queue_request('blockchain.block.header', params, interface)
        return True

    def on_header(self, interface, request, response):
        '''Handle receiving a single block header'''
        result = response.get('result')
        if not result:
            interface.print_error(response)
            self.connection_down(interface.server)
            return

        if not request:
            interface.print_error("unsolicited header, no request, params={}".format(response['params']))
            self.connection_down(interface.server)
            return
        request_params = request[1]
        height = request_params[0]

        response_height = response['params'][0]
        # This check can be removed if request/response params are reconciled in some sort of rewrite.
        if height != response_height:
            interface.print_error("unsolicited header request={} request_height={} response_height={}".format(request_params, height, response_height))
            self.connection_down(interface.server)
            return

        proof_was_provided = False
        hexheader = None
        if 'root' in result and 'branch' in result and 'header' in result:
            hexheader = result["header"]
            if not self.validate_checkpoint_result(interface, result["root"], result["branch"], hexheader, height):
                # Got checkpoint validation data, failed to provide proof.
                interface.print_error("unprovable header request={} height={}".format(request_params, height))
                self.connection_down(interface.server)
                return
            proof_was_provided = True
        else:
            hexheader = result

        # Simple header request.
        header = blockchain.deserialize_header(bfh(hexheader), height)
        # Is there a blockchain that already includes this header?
        chain = blockchain.check_header(header)
        if interface.mode == 'backward':
            if chain:
                interface.print_error("binary search")
                interface.set_mode('binary')
                interface.blockchain = chain
                interface.good = height
                next_height = (interface.bad + interface.good) // 2
            else:
                if height == 0:
                    self.connection_down(interface.server)
                    next_height = None
                else:
                    interface.bad = height
                    interface.bad_header = header
                    delta = interface.tip - height
                    next_height = max(0, interface.tip - 2 * delta)

        elif interface.mode == 'binary':
            if chain:
                interface.good = height
                interface.blockchain = chain
            else:
                interface.bad = height
                interface.bad_header = header
            if interface.bad != interface.good + 1:
                next_height = (interface.bad + interface.good) // 2
            elif not interface.blockchain.can_connect(interface.bad_header, check_height=False):
                self.connection_down(interface.server)
                next_height = None
            else:
                branch = self.blockchains.get(interface.bad)
                if branch is not None:
                    if branch.check_header(interface.bad_header):
                        interface.print_error('joining chain', interface.bad)
                        next_height = None
                    elif branch.parent().check_header(header):
                        interface.print_error('reorg', interface.bad, interface.tip)
                        interface.blockchain = branch.parent()
                        next_height = None
                    else:
                        interface.print_error('checkpoint conflicts with existing fork', branch.path())
                        branch.write(b'', 0)
                        branch.save_header(interface.bad_header)
                        interface.set_mode('catch_up')
                        interface.blockchain = branch
                        next_height = interface.bad + 1
                        interface.blockchain.catch_up = interface.server
                else:
                    bh = interface.blockchain.height()
                    next_height = None
                    if bh > interface.good:
                        if not interface.blockchain.check_header(interface.bad_header):
                            b = interface.blockchain.fork(interface.bad_header)
                            self.blockchains[interface.bad] = b
                            interface.blockchain = b
                            interface.print_error("new chain", b.base_height)
                            interface.set_mode('catch_up')
                            next_height = interface.bad + 1
                            interface.blockchain.catch_up = interface.server
                    else:
                        assert bh == interface.good
                        if interface.blockchain.catch_up is None and bh < interface.tip:
                            interface.print_error("catching up from %d"% (bh + 1))
                            interface.set_mode('catch_up')
                            next_height = bh + 1
                            interface.blockchain.catch_up = interface.server

                self.notify('updated')

        elif interface.mode == 'catch_up':
            can_connect = interface.blockchain.can_connect(header)
            if can_connect:
                interface.blockchain.save_header(header)
                next_height = height + 1 if height < interface.tip else None
            else:
                # go back
                interface.print_error("cannot connect", height)
                interface.set_mode('backward')
                interface.bad = height
                interface.bad_header = header
                next_height = height - 1

            if next_height is None:
                # exit catch_up state
                interface.print_error('catch up done', interface.blockchain.height())
                interface.blockchain.catch_up = None
                self.switch_lagging_interface()
                self.notify('updated')
        elif interface.mode == 'default':
            raise BaseException(interface.mode)

        # If not finished, get the next header
        if next_height:
            if interface.mode == 'catch_up' and interface.tip > next_height:
                self.request_headers(interface, next_height, 2016)
            else:
                self.request_header(interface, next_height)
        else:
            interface.set_mode('default')
            self.notify('updated')
        # refresh network dialog
        self.notify('interfaces')

    def maintain_requests(self):
        with self.interface_lock:
            interfaces = list(self.interfaces.values())
        for interface in interfaces:
            if interface.unanswered_requests and time.time() - interface.request_time > 20:
                # The last request made is still outstanding, and was over 20 seconds ago.
                interface.print_error("blockchain request timed out")
                self.connection_down(interface.server)
                continue

    def wait_on_sockets(self):
        # Python docs say Windows doesn't like empty selects.
        # Sleep to prevent busy looping
        if not self.interfaces:
            time.sleep(0.1)
            return
        with self.interface_lock:
            interfaces = list(self.interfaces.values())
        rin = [i for i in interfaces]
        win = [i for i in interfaces if i.num_requests()]
        try:
            rout, wout, xout = select.select(rin, win, [], 0.1)
        except socket.error as e:
            # TODO: py3, get code from e
            code = None
            if code == errno.EINTR:
                return
            raise
        assert not xout
        for interface in wout:
            interface.send_requests()
        for interface in rout:
            self.process_responses(interface)

    def init_headers_file(self):
        b = self.blockchains[0]
        filename = b.path()
        length = 80 * (bitcoin.NetworkConstants.VERIFICATION_BLOCK_HEIGHT - 1)
        if not os.path.exists(filename) or os.path.getsize(filename) < length:
            with open(filename, 'wb') as f:
                if length>0:
                    f.seek(length-1)
                    f.write(b'\x00')
        util.ensure_sparse_file(filename)
        with b.lock:
            b.update_size()

    def run(self):
        b = self.blockchains[0]
        header = None
        if bitcoin.NetworkConstants.VERIFICATION_BLOCK_HEIGHT is not None:
            self.init_headers_file()
            header = b.read_header(bitcoin.NetworkConstants.VERIFICATION_BLOCK_HEIGHT)
        if header is not None:
            self.verified_checkpoint = True

        while self.is_running():
            self.maintain_sockets()
            self.wait_on_sockets()
            self.maintain_requests()
            if self.verified_checkpoint:
                self.run_jobs()    # Synchronizer and Verifier and Fx
            self.process_pending_sends()
        self.stop_network()
        self.on_stop()

    def on_server_version(self, interface, version_data):
        interface.server_version = version_data

    def on_notify_header(self, interface, header_dict):
        '''
        When we subscribe for 'blockchain.headers.subscribe', a server will send
        us it's topmost header.  After that, it will forward on any additional
        headers as it receives them.
        '''
        if 'hex' not in header_dict or 'height' not in header_dict:
            self.connection_down(interface.server)
            return

        header_hex = header_dict['hex']
        height = header_dict['height']
        header = blockchain.deserialize_header(bfh(header_hex), height)

        if bitcoin.NetworkConstants.VERIFICATION_BLOCK_HEIGHT is not None:
            if height <= bitcoin.NetworkConstants.VERIFICATION_BLOCK_HEIGHT:
                self.connection_down(interface.server)
                return

        interface.tip_header = header
        interface.tip = height

        if interface.mode == 'verification':
            self.request_initial_proof_and_headers(interface)
            return

        if interface.mode != 'default':
            return

        b = blockchain.check_header(header) # Does it match the hash of a known header.
        if b:
            interface.blockchain = b
            self.switch_lagging_interface()
            self.notify('updated')
            self.notify('interfaces')
            return
        b = blockchain.can_connect(header) # Is it the next header on a given blockchain.
        if b:
            interface.blockchain = b
            b.save_header(header)
            self.switch_lagging_interface()
            self.notify('updated')
            self.notify('interfaces')
            return
        tip = max([x.height() for x in self.blockchains.values()])
        if tip >=0:
            interface.set_mode('backward')
            interface.bad = height
            interface.bad_header = header
            self.request_header(interface, min(tip, height - 1))
        else:
            chain = self.blockchains[0]
            if chain.catch_up is None:
                chain.catch_up = interface
                interface.set_mode('catch_up')
                interface.blockchain = chain
                interface.print_msg("switching to catchup mode", tip)
                self.request_header(interface, 0)
            else:
                interface.print_error("chain already catching up with", chain.catch_up.server)

    def request_initial_proof_and_headers(self, interface):
        # This will be the initial topmost header response.  But we might get new blocks.
        if interface.server not in self.checkpoint_servers_verified:
            top_height = bitcoin.NetworkConstants.VERIFICATION_BLOCK_HEIGHT
            # If there is no known checkpoint height for this network, we look to get
            # a given number of confirmations for the same conservative height.
            if top_height is None:
                # We want to make sure we ask for the same checkpoint height.
                if len(self.checkpoint_servers_verified):
                    top_height = next(iter(self.checkpoint_servers_verified.values()))['height']
                else:
                    top_height = interface.tip - 100
            self.checkpoint_servers_verified[interface.server] = { 'root': None, 'height': top_height }
            # We need at least 147 headers before the post checkpoint headers for daa calculations.
            self._request_headers(interface, top_height - 147 + 1, 147, top_height)

    def apply_successful_verification(self, interface, checkpoint_height, checkpoint_root):
        known_roots = [ v['root'] for v in self.checkpoint_servers_verified.values() if v['root'] is not None ]
        if len(known_roots) > 0 and checkpoint_root != known_roots[0]:
            interface.print_error("server sent inconsistent root {}".format(checkpoint_root))
            return
        self.checkpoint_servers_verified[interface.server]['root'] = checkpoint_root

        self.verifications_required -= 1
        if self.verifications_required > 0:
            interface.print_msg("received verification {}".format(self.verifications_required + 1))
            return
        interface.print_msg("received verification {}".format(self.verifications_required + 1))

        if bitcoin.NetworkConstants.VERIFICATION_BLOCK_HEIGHT is None:
            bitcoin.NetworkConstants.VERIFICATION_BLOCK_HEIGHT = checkpoint_height
            bitcoin.NetworkConstants.VERIFICATION_BLOCK_MERKLE_ROOT = checkpoint_root

            network_name = "TESTNET" if bitcoin.NetworkConstants.TESTNET else "MAINNET"
            self.print_msg("Found verified checkpoint for {} at height {} with merkle root {!r}".format(network_name, checkpoint_height, checkpoint_root))

        self.init_headers_file()
        self.verified_checkpoint = True

        with self.interface_lock:
            interfaces = list(self.interfaces.values())
        for interface_entry in interfaces:
            interface_entry.blockchain = self.blockchains[0]
            interface_entry.set_mode('default')

    def validate_checkpoint_result(self, interface, merkle_root, merkle_branch, header, header_height):
        '''
        header: hex representation of the block header.
        merkle_root: hex representation of the server's calculated merkle root.
        branch: list of hex representations of the server's calculated merkle root branches.

        Returns a boolean to represent whether the server's proof is correct.
        '''
        received_merkle_root = bytes(reversed(bfh(merkle_root)))
        if bitcoin.NetworkConstants.VERIFICATION_BLOCK_MERKLE_ROOT:
            expected_merkle_root = bytes(reversed(bfh(bitcoin.NetworkConstants.VERIFICATION_BLOCK_MERKLE_ROOT)))
        else:
            expected_merkle_root = received_merkle_root

        if received_merkle_root != expected_merkle_root:
            interface.print_error("Sent unexpected merkle root, expected: {}, got: {}".format(bitcoin.NetworkConstants.VERIFICATION_BLOCK_MERKLE_ROOT, merkle_root))
            return False

        header_hash = Hash(bfh(header))
        byte_branches = [ bytes(reversed(bfh(v))) for v in merkle_branch ]
        proven_merkle_root = blockchain.root_from_proof(header_hash, byte_branches, header_height)
        if proven_merkle_root != expected_merkle_root:
            interface.print_error("Sent incorrect merkle branch, expected: {}, proved: {}".format(bitcoin.NetworkConstants.VERIFICATION_BLOCK_MERKLE_ROOT, util.hfu(reversed(proven_merkle_root))))
            return False

        return True

    def blockchain(self):
        if self.interface and self.interface.blockchain is not None:
            self.blockchain_index = self.interface.blockchain.base_height
        return self.blockchains[self.blockchain_index]

    def get_blockchains(self):
        out = {}
        for k, b in self.blockchains.items():
            r = list(filter(lambda i: i.blockchain==b, list(self.interfaces.values())))
            if r:
                out[k] = r
        return out

    def follow_chain(self, index):
        blockchain = self.blockchains.get(index)
        if blockchain:
            self.blockchain_index = index
            self.config.set_key('blockchain_index', index)
            with self.interface_lock:
                interfaces = list(self.interfaces.values())
            for i in interfaces:
                if i.blockchain == blockchain:
                    self.switch_to_interface(i.server)
                    break
        else:
            raise BaseException('blockchain not found', index)

        with self.interface_lock:
            if self.interface:
                server = self.interface.server
                host, port, protocol, proxy, auto_connect = self.get_parameters()
                host, port, protocol = server.split(':')
                self.set_parameters(host, port, protocol, proxy, auto_connect)

    def get_local_height(self):
        return self.blockchain().height()

    def synchronous_get(self, request, timeout=30):
        q = queue.Queue()
        self.send([request], q.put)
        try:
            r = q.get(True, timeout)
        except queue.Empty:
            raise BaseException('Server did not answer')
        if r.get('error'):
            raise BaseException(r.get('error'))
        return r.get('result')

    @staticmethod
    def __wait_for(it):
        """Wait for the result of calling lambda `it`."""
        q = queue.Queue()
        it(q.put)
        try:
            result = q.get(block=True, timeout=30)
        except queue.Empty:
            raise util.TimeoutException(_('Server did not answer'))

        if result.get('error'):
            raise Exception(result.get('error'))

        return result.get('result')

    @staticmethod
    def __with_default_synchronous_callback(invocation, callback):
        """ Use this method if you want to make the network request
        synchronous. """
        if not callback:
            return Network.__wait_for(invocation)

        invocation(callback)

    # NOTE this method handles exceptions and a special edge case, counter to
    # what the other ElectrumX methods do. This is unexpected.
    def broadcast_transaction(self, transaction, callback=None):
        command = 'blockchain.transaction.broadcast'
        invocation = lambda c: self.send([(command, [str(transaction)])], c)

        if callback:
            invocation(callback)
            return

        try:
            out = Network.__wait_for(invocation)
        except BaseException as e:
            return False, "error: " + str(e)

        if out != transaction.txid():
            return False, "error: " + out

        return True, out

    # Used by the verifier job.
    def get_merkle_for_transaction(self, tx_hash, tx_height, callback=None):
        command = 'blockchain.transaction.get_merkle'
        invocation = lambda c: self.send([(command, [tx_hash, tx_height])], c)

        return Network.__with_default_synchronous_callback(invocation, callback)
