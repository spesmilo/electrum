
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
from .interface import Connection, Interface
from . import blockchain
from .version import ELECTRUM_VERSION, PROTOCOL_VERSION


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
    host, port, protocol = str(server_str).split(':')
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
        self.default_server = self.config.get('server')
        # Sanitize default server
        try:
            deserialize_server(self.default_server)
        except:
            self.default_server = None
        if not self.default_server:
            self.default_server = pick_random_server()

        self.lock = threading.Lock()
        self.pending_sends = []
        self.message_id = 0
        self.debug = False
        self.irc_servers = {} # returned by interface (list from irc)
        self.recent_servers = self.read_recent_servers()

        self.banner = ''
        self.donation_address = ''
        self.relay_fee = None
        # callbacks passed with subscriptions
        self.subscriptions = defaultdict(list)
        self.sub_cache = {}
        # callbacks set by the GUI
        self.callbacks = defaultdict(list)

        dir_path = os.path.join( self.config.path, 'certs')
        if not os.path.exists(dir_path):
            os.mkdir(dir_path)
            os.chmod(dir_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)

        # subscriptions and requests
        self.subscribed_addresses = set()
        self.h2addr = {}
        # Requests from client we've not seen a response to
        self.unanswered_requests = {}
        # retry times
        self.server_retry_time = time.time()
        self.nodes_retry_time = time.time()
        # kick off the network.  interface is the main server we are currently
        # communicating with.  interfaces is the set of servers we are connecting
        # to or have an ongoing connection with
        self.interface = None
        self.interfaces = {}
        self.auto_connect = self.config.get('auto_connect', True)
        self.connecting = set()
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

    def read_recent_servers(self):
        if not self.config.path:
            return []
        path = os.path.join(self.config.path, "recent_servers")
        try:
            with open(path, "r") as f:
                data = f.read()
                return json.loads(data)
        except:
            return []

    def save_recent_servers(self):
        if not self.config.path:
            return
        path = os.path.join(self.config.path, "recent_servers")
        s = json.dumps(self.recent_servers, indent=4, sort_keys=True)
        try:
            with open(path, "w") as f:
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
        if self.interface.ping_required():
            params = [ELECTRUM_VERSION, PROTOCOL_VERSION]
            self.queue_request('server.version', params, self.interface)
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

    def process_response(self, interface, response, callbacks):
        if self.debug:
            self.print_error("<--", response)
        error = response.get('error')
        result = response.get('result')
        method = response.get('method')
        params = response.get('params')

        # We handle some responses; return the rest to the client.
        if method == 'server.version':
            interface.server_version = result
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
        elif method == 'blockchain.block.get_chunk':
            self.on_get_chunk(interface, response)
        elif method == 'blockchain.block.get_header':
            self.on_get_header(interface, response)

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
                elif method == 'blockchain.address.subscribe':
                    response['params'] = [params[0]]
                    response['result'] = params[1]
                callbacks = self.subscriptions.get(k, [])

            # update cache if it's a subscription
            if method.endswith('.subscribe'):
                self.sub_cache[k] = response
            # Response is now in canonical form
            self.process_response(interface, response, callbacks)

    def addr_to_scripthash(self, addr):
        h = bitcoin.address_to_scripthash(addr)
        if h not in self.h2addr:
            self.h2addr[h] = addr
        return h

    def overload_cb(self, callback):
        def cb2(x):
            x2 = x.copy()
            p = x2.pop('params')
            addr = self.h2addr[p[0]]
            x2['params'] = [addr]
            callback(x2)
        return cb2

    def subscribe_to_addresses(self, addresses, callback):
        hashes = [self.addr_to_scripthash(addr) for addr in addresses]
        msgs = [('blockchain.scripthash.subscribe', [x]) for x in hashes]
        self.send(msgs, self.overload_cb(callback))

    def request_address_history(self, address, callback):
        h = self.addr_to_scripthash(address)
        self.send([('blockchain.scripthash.get_history', [h])], self.overload_cb(callback))

    def send(self, messages, callback):
        '''Messages is a list of (method, params) tuples'''
        messages = list(messages)
        with self.lock:
            self.pending_sends.append((messages, callback))

    def process_pending_sends(self):
        # Requests needs connectivity.  If we don't have an interface,
        # we cannot process them.
        if not self.interface:
            return

        with self.lock:
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
        # todo: get tip first, then decide which checkpoint to use.
        self.add_recent_server(server)
        interface = Interface(server, socket)
        interface.blockchain = None
        interface.tip_header = None
        interface.tip = 0
        interface.mode = 'default'
        interface.request = None
        self.interfaces[server] = interface
        self.queue_request('blockchain.headers.subscribe', [], interface)
        if server == self.default_server:
            self.switch_to_interface(server)
        #self.notify('interfaces')

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
        for interface in list(self.interfaces.values()):
            if interface.has_timed_out():
                self.connection_down(interface.server)
            elif interface.ping_required():
                params = [ELECTRUM_VERSION, PROTOCOL_VERSION]
                self.queue_request('server.version', params, interface)

        now = time.time()
        # nodes
        if len(self.interfaces) + len(self.connecting) < self.num_server:
            self.start_random_interface()
            if now - self.nodes_retry_time > NODES_RETRY_INTERVAL:
                self.print_error('network: retrying connections')
                self.disconnected_servers = set([])
                self.nodes_retry_time = now

        # main interface
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

    def request_chunk(self, interface, idx):
        interface.print_error("requesting chunk %d" % idx)
        self.queue_request('blockchain.block.get_chunk', [idx], interface)
        interface.request = idx
        interface.req_time = time.time()

    def on_get_chunk(self, interface, response):
        '''Handle receiving a chunk of block headers'''
        error = response.get('error')
        result = response.get('result')
        params = response.get('params')
        if result is None or params is None or error is not None:
            interface.print_error(error or 'bad response')
            return
        # Ignore unsolicited chunks
        index = params[0]
        if interface.request != index:
            return
        connect = interface.blockchain.connect_chunk(index, result)
        # If not finished, get the next chunk
        if not connect:
            self.connection_down(interface.server)
            return
        if interface.blockchain.height() < interface.tip:
            self.request_chunk(interface, index+1)
        else:
            interface.request = None
            interface.mode = 'default'
            interface.print_error('catch up done', interface.blockchain.height())
            interface.blockchain.catch_up = None
        self.notify('updated')

    def request_header(self, interface, height):
        #interface.print_error("requesting header %d" % height)
        self.queue_request('blockchain.block.get_header', [height], interface)
        interface.request = height
        interface.req_time = time.time()

    def on_get_header(self, interface, response):
        '''Handle receiving a single block header'''
        header = response.get('result')
        if not header:
            interface.print_error(response)
            self.connection_down(interface.server)
            return
        height = header.get('block_height')
        if interface.request != height:
            interface.print_error("unsolicited header",interface.request, height)
            self.connection_down(interface.server)
            return

        chain = blockchain.check_header(header)
        if interface.mode == 'backward':
            if chain:
                interface.print_error("binary search")
                interface.mode = 'binary'
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
                        branch.write('', 0)
                        branch.save_header(interface.bad_header)
                        interface.mode = 'catch_up'
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
                            interface.print_error("new chain", b.checkpoint)
                            interface.mode = 'catch_up'
                            next_height = interface.bad + 1
                            interface.blockchain.catch_up = interface.server
                    else:
                        assert bh == interface.good
                        if interface.blockchain.catch_up is None and bh < interface.tip:
                            interface.print_error("catching up from %d"% (bh + 1))
                            interface.mode = 'catch_up'
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
                interface.mode = 'backward'
                interface.bad = height
                interface.bad_header = header
                next_height = height - 1

            if next_height is None:
                # exit catch_up state
                interface.print_error('catch up done', interface.blockchain.height())
                interface.blockchain.catch_up = None
                self.switch_lagging_interface()
                self.notify('updated')

        else:
            raise BaseException(interface.mode)
        # If not finished, get the next header
        if next_height:
            if interface.mode == 'catch_up' and interface.tip > next_height + 50:
                self.request_chunk(interface, next_height // 2016)
            else:
                self.request_header(interface, next_height)
        else:
            interface.mode = 'default'
            interface.request = None
            self.notify('updated')
        # refresh network dialog
        self.notify('interfaces')

    def maintain_requests(self):
        for interface in list(self.interfaces.values()):
            if interface.request and time.time() - interface.request_time > 20:
                interface.print_error("blockchain request timed out")
                self.connection_down(interface.server)
                continue

    def wait_on_sockets(self):
        # Python docs say Windows doesn't like empty selects.
        # Sleep to prevent busy looping
        if not self.interfaces:
            time.sleep(0.1)
            return
        rin = [i for i in self.interfaces.values()]
        win = [i for i in self.interfaces.values() if i.num_requests()]
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
        if b.get_hash(0) == bitcoin.NetworkConstants.GENESIS:
            self.downloading_headers = False
            return
        filename = b.path()
        def download_thread():
            try:
                import urllib.request, socket
                socket.setdefaulttimeout(30)
                self.print_error("downloading ", bitcoin.NetworkConstants.HEADERS_URL)
                urllib.request.urlretrieve(bitcoin.NetworkConstants.HEADERS_URL, filename + '.tmp')
                os.rename(filename + '.tmp', filename)
                self.print_error("done.")
            except Exception:
                self.print_error("download failed. creating file", filename)
                open(filename, 'wb+').close()
            b = self.blockchains[0]
            with b.lock: b.update_size()
            self.downloading_headers = False
        self.downloading_headers = True
        t = threading.Thread(target = download_thread)
        t.daemon = True
        t.start()

    def run(self):
        self.init_headers_file()
        while self.is_running() and self.downloading_headers:
            time.sleep(1)
        while self.is_running():
            self.maintain_sockets()
            self.wait_on_sockets()
            self.maintain_requests()
            self.run_jobs()    # Synchronizer and Verifier
            self.process_pending_sends()
        self.stop_network()
        self.on_stop()

    def on_notify_header(self, interface, header):
        height = header.get('block_height')
        if not height:
            return
        interface.tip_header = header
        interface.tip = height
        if interface.mode != 'default':
            return
        b = blockchain.check_header(header)
        if b:
            interface.blockchain = b
            self.switch_lagging_interface()
            self.notify('updated')
            self.notify('interfaces')
            return
        b = blockchain.can_connect(header)
        if b:
            interface.blockchain = b
            b.save_header(header)
            self.switch_lagging_interface()
            self.notify('updated')
            self.notify('interfaces')
            return
        tip = max([x.height() for x in self.blockchains.values()])
        if tip >=0:
            interface.mode = 'backward'
            interface.bad = height
            interface.bad_header = header
            self.request_header(interface, min(tip, height - 1))
        else:
            chain = self.blockchains[0]
            if chain.catch_up is None:
                chain.catch_up = interface
                interface.mode = 'catch_up'
                interface.blockchain = chain
                self.request_header(interface, 0)

    def blockchain(self):
        if self.interface and self.interface.blockchain is not None:
            self.blockchain_index = self.interface.blockchain.checkpoint
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
            for i in self.interfaces.values():
                if i.blockchain == blockchain:
                    self.switch_to_interface(i.server)
                    break
        else:
            raise BaseException('blockchain not found', index)

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

    def broadcast(self, tx, timeout=30):
        tx_hash = tx.txid()
        try:
            out = self.synchronous_get(('blockchain.transaction.broadcast', [str(tx)]), timeout)
        except BaseException as e:
            return False, "error: " + str(e)
        if out != tx_hash:
            return False, "error: " + out
        return True, out
