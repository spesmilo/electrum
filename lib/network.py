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
import Queue
import os
import errno
import sys
import random
import select
import traceback
from collections import defaultdict, deque
from threading import Lock

import socks
import socket
import json

import util
import bitcoin
from bitcoin import *
from interface import Connection, Interface
from blockchain import Blockchain
from version import ELECTRUM_VERSION, PROTOCOL_VERSION

DEFAULT_PORTS = {'t':'50001', 's':'50002'}

#There is a schedule to move the default list to e-x (electrumx) by Jan 2018
#Schedule is as follows:
#move ~3/4 to e-x by 1.4.17
#then gradually switch remaining nodes to e-x nodes

DEFAULT_SERVERS = {
    'elec.luggs.co': {'s':'444'},
    'electrum-ltc.bysh.me': DEFAULT_PORTS,
    'electrum-ltc.ddns.net': DEFAULT_PORTS,
    'electrum-ltc.petrkr.net': {'t':'60001', 's':'60002'},
    'electrum.cryptomachine.com': DEFAULT_PORTS,
    'electrum.ltc.xurious.com': DEFAULT_PORTS,
    'electrum.snicter.com': DEFAULT_PORTS,
    'us11.einfachmalnettsein.de': {'t':'50007', 's':'50008'},
}

def set_testnet():
    global DEFAULT_PORTS, DEFAULT_SERVERS
    DEFAULT_PORTS = {'t':'51001', 's':'51002'}
    DEFAULT_SERVERS = {
        'electrum-ltc.bysh.me': DEFAULT_PORTS,
        'electrum.ltc.xurious.com': DEFAULT_PORTS,
    }

def set_nolnet():
    global DEFAULT_PORTS, DEFAULT_SERVERS
    DEFAULT_PORTS = {'t':'52001', 's':'52002'}
    DEFAULT_SERVERS = {
        '14.3.140.101': DEFAULT_PORTS,
    }

NODES_RETRY_INTERVAL = 60
SERVER_RETRY_INTERVAL = 10


def parse_servers(result):
    """ parse servers list into dict format"""
    from version import PROTOCOL_VERSION
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
                    if port == '': port = DEFAULT_PORTS[protocol]
                    out[protocol] = port
                elif re.match("v(.?)+", v):
                    version = v[1:]
                elif re.match("p\d*", v):
                    pruning_level = v[1:]
                if pruning_level == '': pruning_level = '0'
        try:
            is_recent = cmp(util.normalize_version(version), util.normalize_version(PROTOCOL_VERSION)) >= 0
        except Exception:
            is_recent = False

        if out and is_recent:
            out['pruning'] = pruning_level
            servers[host] = out

    return servers

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
        hostmap = DEFAULT_SERVERS
    eligible = list(set(filter_protocol(hostmap, protocol)) - exclude_set)
    return random.choice(eligible) if eligible else None

from simple_config import SimpleConfig

proxy_modes = ['socks4', 'socks5', 'http']

def serialize_proxy(p):
    if type(p) != dict:
        return None
    return ':'.join([p.get('mode'),p.get('host'), p.get('port'), p.get('user'), p.get('password')])

def deserialize_proxy(s):
    if type(s) not in [str, unicode]:
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
        self.config = SimpleConfig(config) if type(config) == type({}) else config
        self.num_server = 8 if not self.config.get('oneserver') else 0
        self.blockchain = Blockchain(self.config, self)
        # Server for addresses and transactions
        self.default_server = self.config.get('server')
        # Sanitize default server
        try:
            deserialize_server(self.default_server)
        except:
            self.default_server = None
        if not self.default_server:
            self.default_server = pick_random_server()

        self.lock = Lock()
        self.pending_sends = []
        self.message_id = 0
        self.debug = False
        self.irc_servers = {} # returned by interface (list from irc)
        self.recent_servers = self.read_recent_servers()

        self.banner = ''
        self.donation_address = ''
        self.relay_fee = None
        self.headers = {}
        # callbacks passed with subscriptions
        self.subscriptions = defaultdict(list)
        self.sub_cache = {}
        # callbacks set by the GUI
        self.callbacks = defaultdict(list)

        dir_path = os.path.join( self.config.path, 'certs')
        if not os.path.exists(dir_path):
            os.mkdir(dir_path)

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
        self.interface = None
        self.interfaces = {}
        self.auto_connect = self.config.get('auto_connect', True)
        self.connecting = set()
        self.socket_queue = Queue.Queue()
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
        h = self.headers.get(self.default_server)
        return h['block_height'] if h else 0

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
        for i in bitcoin.FEE_TARGETS:
            self.queue_request('blockchain.estimatefee', [i])
        self.queue_request('blockchain.relayfee', [])
        for addr in self.subscribed_addresses:
            self.queue_request('blockchain.address.subscribe', [addr])

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
        return self.interfaces.keys()

    def get_servers(self):
        if self.irc_servers:
            out = self.irc_servers.copy()
            out.update(DEFAULT_SERVERS)
        else:
            out = DEFAULT_SERVERS
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
            socket.getaddrinfo = socket._socket.getaddrinfo

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
        for interface in self.interfaces.values():
            self.close_interface(interface)
        if self.interface:
            self.close_interface(self.interface)
        assert self.interface is None
        assert not self.interfaces
        self.connecting = set()
        # Get a new queue - no old pending connections thanks!
        self.socket_queue = Queue.Queue()

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

    def switch_to_random_interface(self):
        '''Switch to a random connected server other than the current one'''
        servers = self.get_interfaces()    # Those in connected state
        if self.default_server in servers:
            servers.remove(self.default_server)
        if servers:
            self.switch_to_interface(random.choice(servers))

    def switch_lagging_interface(self, suggestion = None):
        '''If auto_connect and lagging, switch interface'''
        if self.server_is_lagging() and self.auto_connect:
            if suggestion and self.protocol == deserialize_server(suggestion)[2]:
                self.switch_to_interface(suggestion)
            else:
                # switch to one that has the correct header (not height)
                header = self.get_header(self.get_local_height())
                filtered = map(lambda x:x[0], filter(lambda x: x[1]==header, self.headers.items()))
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
            self.close_interface(self.interface)
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
                self.config.fee_estimates[i] = fee
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
        return str(method) + (':' + str(params[0]) if params  else '')

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
                    callbacks = []
                # Copy the request method and params to the response
                response['method'] = method
                response['params'] = params
                # Only once we've received a response to an addr subscription
                # add it to the list; avoids double-sends on reconnection
                if method == 'blockchain.address.subscribe':
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
                elif method == 'blockchain.address.subscribe':
                    response['params'] = [params[0]]  # addr
                    response['result'] = params[1]
                callbacks = self.subscriptions.get(k, [])

            # update cache if it's a subscription
            if method.endswith('.subscribe'):
                self.sub_cache[k] = response
            # Response is now in canonical form
            self.process_response(interface, response, callbacks)

    def send(self, messages, callback):
        '''Messages is a list of (method, params) tuples'''
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
            self.headers.pop(server, None)
            self.notify('interfaces')

    def new_interface(self, server, socket):
        self.add_recent_server(server)
        interface = Interface(server, socket)
        interface.mode = 'checkpoint'
        self.interfaces[server] = interface
        self.request_header(interface, self.blockchain.checkpoint_height)
        if server == self.default_server:
            self.switch_to_interface(server)
        self.notify('interfaces')

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
        for interface in self.interfaces.values():
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

    def request_chunk(self, interface, idx):
        interface.print_error("requesting chunk %d" % idx)
        self.queue_request('blockchain.block.get_chunk', [idx], interface)
        interface.request = idx
        interface.req_time = time.time()

    def on_get_chunk(self, interface, response):
        '''Handle receiving a chunk of block headers'''
        if response.get('error'):
            interface.print_error(response.get('error'))
            return
        # Ignore unsolicited chunks
        index = response['params'][0]
        if interface.request != index:
            return
        connect = self.blockchain.connect_chunk(index, response['result'])
        # If not finished, get the next chunk
        if not connect:
            return
        if self.get_local_height() < interface.tip:
            self.request_chunk(interface, index+1)
        else:
            interface.request = None
        self.notify('updated')

    def request_header(self, interface, height):
        interface.print_error("requesting header %d" % height)
        self.queue_request('blockchain.block.get_header', [height], interface)
        interface.request = height
        interface.req_time = time.time()

    def on_get_header(self, interface, response):
        '''Handle receiving a single block header'''
        if self.blockchain.downloading_headers:
            return
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
        self.on_header(interface, header)

    def on_header(self, interface, header):
        height = header.get('block_height')
        if interface.mode == 'checkpoint':
            if self.blockchain.pass_checkpoint(header):
                interface.mode = 'default'
                self.queue_request('blockchain.headers.subscribe', [], interface)
            else:
                if interface != self.interface or self.auto_connect:
                    interface.print_error("checkpoint failed")
                    self.connection_down(interface.server)
            interface.request = None
            return
        can_connect = self.blockchain.can_connect(header)
        if interface.mode == 'backward':
            if can_connect:
                interface.good = height
                interface.mode = 'binary'
                interface.print_error("binary search")
                next_height = (interface.bad + interface.good) // 2
            else:
                interface.bad = height
                delta = interface.tip - height
                next_height = interface.tip - 2 * delta
                if next_height < 0:
                    interface.print_error("header didn't connect, dismissing interface")
                    self.connection_down(interface.server)
        elif interface.mode == 'binary':
            if can_connect:
                interface.good = height
            else:
                interface.bad = height
            if interface.good == interface.bad - 1:
                interface.print_error("catching up from %d"% interface.good)
                interface.mode = 'default'
                next_height = interface.good
            else:
                next_height = (interface.bad + interface.good) // 2
        elif interface.mode == 'default':
            if can_connect:
                if height > self.get_local_height():
                    self.blockchain.save_header(header)
                    self.notify('updated')
                if height < interface.tip:
                    next_height = height + 1
                else:
                    next_height = None
            else:
                interface.mode = 'backward'
                interface.bad = height
                next_height = height - 1
        else:
            raise BaseException(interface.mode)
        # If not finished, get the next header
        if next_height:
            if interface.mode != 'default':
                self.request_header(interface, next_height)
            else:
                local_height = self.get_local_height()
                if interface.tip > local_height + 50:
                    self.request_chunk(interface, (local_height + 1) // 2016)
                else:
                    self.request_header(interface, next_height)
        else:
            interface.request = None

    def maintain_requests(self):
        for interface in self.interfaces.values():
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
        except socket.error as (code, msg):
            if code == errno.EINTR:
                return
            raise
        assert not xout
        for interface in wout:
            interface.send_requests()
        for interface in rout:
            self.process_responses(interface)

    def run(self):
        self.blockchain.init()
        while self.is_running():
            self.maintain_sockets()
            self.wait_on_sockets()
            self.maintain_requests()
            self.run_jobs()    # Synchronizer and Verifier
            self.process_pending_sends()
        self.stop_network()
        self.on_stop()

    def on_notify_header(self, i, header):
        height = header.get('block_height')
        if not height:
            return
        self.headers[i.server] = header
        i.tip = height
        local_height = self.get_local_height()

        if i.tip > local_height:
            i.print_error("better height", height)
            # if I can connect, do it right away
            if self.blockchain.can_connect(header):
                self.blockchain.save_header(header)
                self.notify('updated')
            # otherwise trigger a search
            elif i.request is None:
                self.on_header(i, header)

        if i == self.interface:
            self.switch_lagging_interface()
            self.notify('updated')


    def get_header(self, tx_height):
        return self.blockchain.read_header(tx_height)

    def get_local_height(self):
        return self.blockchain.height()

    def synchronous_get(self, request, timeout=30):
        queue = Queue.Queue()
        self.send([request], queue.put)
        try:
            r = queue.get(True, timeout)
        except Queue.Empty:
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
