import time
import Queue
import os
import sys
import random
import traceback

import socks
import socket
import json

import util
from bitcoin import *
import interface
from blockchain import Blockchain

DEFAULT_PORTS = {'t':'50001', 's':'50002', 'h':'8081', 'g':'8082'}

DEFAULT_SERVERS = {
    'electrum.be':DEFAULT_PORTS,
    'electrum.drollette.com':{'t':'50001', 's':'50002'},
    'erbium1.sytes.net':{'t':'50001', 's':'50002'},
    'ecdsa.net':{'t':'50001', 's':'110'},
    'eco-electrum.ddns.net':{'t': '50001', 's': '50002', 'h': '80', 'g': '443'},
    'electrum0.electricnewyear.net':{'t':'50001', 's':'50002'},
    'kirsche.emzy.de':{'t':'50001', 's':'50002', 'h':'8081'},
    'electrum2.hachre.de':DEFAULT_PORTS,
    'electrum.hsmiths.com':DEFAULT_PORTS,
    'EAST.electrum.jdubya.info':DEFAULT_PORTS,
    'WEST.electrum.jdubya.info':DEFAULT_PORTS,
    'electrum.no-ip.org':{'t':'50001', 's':'50002', 'h':'80', 'g':'443'},
    'electrum.thwg.org':DEFAULT_PORTS,
    'us.electrum.be':DEFAULT_PORTS,
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
                if re.match("[stgh]\d*", v):
                    protocol, port = v[0], v[1:]
                    if port == '': port = DEFAULT_PORTS[protocol]
                    out[protocol] = port
                elif re.match("v(.?)+", v):
                    version = v[1:]
                elif re.match("p\d*", v):
                    pruning_level = v[1:]
                if pruning_level == '': pruning_level = '0'
        try:
            is_recent = float(version)>=float(PROTOCOL_VERSION)
        except Exception:
            is_recent = False

        if out and is_recent:
            out['pruning'] = pruning_level
            servers[host] = out

    return servers

def filter_protocol(hostmap = DEFAULT_SERVERS, protocol = 's'):
    '''Filters the hostmap for those implementing protocol.
    The result is a list in serialized form.'''
    eligible = []
    for host, portmap in hostmap.items():
        port = portmap.get(protocol)
        if port:
            eligible.append(serialize_server(host, port, protocol))
    return eligible

def pick_random_server(hostmap = DEFAULT_SERVERS, protocol = 's', exclude_set = set()):
    eligible = list(set(filter_protocol(hostmap, protocol)) - exclude_set)
    return random.choice(eligible) if eligible else None

from simple_config import SimpleConfig

proxy_modes = ['socks4', 'socks5', 'http']

def serialize_proxy(p):
    if type(p) != dict:
        return None
    return ':'.join([p.get('mode'),p.get('host'), p.get('port')])

def deserialize_proxy(s):
    if s is None:
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
    else:
        proxy["port"] = "8080" if proxy["mode"] == "http" else "1080"
    return proxy

def deserialize_server(server_str):
    host, port, protocol = str(server_str).split(':')
    assert protocol in 'st'
    int(port)    # Throw if cannot be converted to int
    return host, port, protocol

def serialize_server(host, port, protocol):
    return str(':'.join([host, port, protocol]))


class Network(util.DaemonThread):
    """The Network class manages a set of connections to remote
    electrum servers, each connection is handled by its own
    thread object returned from Interface().  Its external API:

    - Member functions get_header(), get_parameters(), get_status_value(),
                       new_blockchain_height(), set_parameters(), start(),
                       stop()
    """

    def __init__(self, pipe, config=None):
        if config is None:
            config = {}  # Do not use mutables as default values!
        util.DaemonThread.__init__(self)
        self.config = SimpleConfig(config) if type(config) == type({}) else config
        self.num_server = 8 if not self.config.get('oneserver') else 0
        self.blockchain = Blockchain(self.config, self)
        self.queue = Queue.Queue()
        self.requests_queue = pipe.send_queue
        self.response_queue = pipe.get_queue
        # Server for addresses and transactions
        self.default_server = self.config.get('server')
        # Sanitize default server
        try:
            deserialize_server(self.default_server)
        except:
            self.default_server = None
        if not self.default_server:
            self.default_server = pick_random_server()

        self.irc_servers = {} # returned by interface (list from irc)
        self.recent_servers = self.read_recent_servers()

        self.banner = ''
        self.heights = {}
        self.merkle_roots = {}
        self.utxo_roots = {}

        dir_path = os.path.join( self.config.path, 'certs')
        if not os.path.exists(dir_path):
            os.mkdir(dir_path)

        # subscriptions and requests
        self.subscribed_addresses = set()
        # cached address status
        self.addr_responses = {}
        # unanswered requests
        self.unanswered_requests = {}
        # retry times
        self.server_retry_time = time.time()
        self.nodes_retry_time = time.time()
        # kick off the network.  interface is the main server we are currently
        # communicating with.  interfaces is the set of servers we are connecting
        # to or have an ongoing connection with
        self.interface = None
        self.interfaces = {}
        self.start_network(deserialize_server(self.default_server)[2],
                           deserialize_proxy(self.config.get('proxy')))

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
        return self.heights.get(self.default_server, 0)

    def server_is_lagging(self):
        sh = self.get_server_height()
        if not sh:
            self.print_error('no height for main interface')
            return False
        lh = self.get_local_height()
        result = (lh - sh) > 1
        if result:
            self.print_error('%s is lagging (%d vs %d)' % (self.default_server, sh, lh))
        return result

    def set_status(self, status):
        self.connection_status = status
        self.notify('status')

    def is_connected(self):
        return self.interface and self.interface.is_connected()

    def send_subscriptions(self):
        # clear cache
        self.cached_responses = {}
        self.print_error('sending subscriptions to', self.interface.server, len(self.unanswered_requests), len(self.subscribed_addresses))
        for r in self.unanswered_requests.values():
            self.interface.send_request(r)
        for addr in self.subscribed_addresses:
            self.interface.send_request({'method':'blockchain.address.subscribe','params':[addr]})
        self.interface.send_request({'method':'server.banner','params':[]})
        self.interface.send_request({'method':'server.peers.subscribe','params':[]})

    def get_status_value(self, key):
        if key == 'status':
            value = self.connection_status
        elif key == 'banner':
            value = self.banner
        elif key == 'updated':
            value = (self.get_local_height(), self.get_server_height())
        elif key == 'servers':
            value = self.get_servers()
        elif key == 'interfaces':
            value = self.get_interfaces()
        return value

    def notify(self, key):
        value = self.get_status_value(key)
        self.response_queue.put({'method':'network.status', 'params':[key, value]})

    def get_parameters(self):
        host, port, protocol = deserialize_server(self.default_server)
        return host, port, protocol, self.proxy, self.auto_connect()

    def auto_connect(self):
        return self.config.get('auto_connect', False)

    def get_interfaces(self):
        return self.interfaces.keys()

    def get_servers(self):
        if self.irc_servers:
            out = self.irc_servers
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
        if not server in self.interfaces.keys():
            if server == self.default_server:
                self.set_status('connecting')
            i = interface.Interface(server, self.queue, self.config)
            self.interfaces[i.server] = i
            i.start()

    def start_random_interface(self):
        exclude_set = self.disconnected_servers.union(set(self.interfaces))
        server = pick_random_server(self.get_servers(), self.protocol, exclude_set)
        if server:
            self.start_interface(server)

    def start_interfaces(self):
        self.start_interface(self.default_server)
        for i in range(self.num_server - 1):
            self.start_random_interface()

    def start(self):
        self.running = True
        self.blockchain.start()
        util.DaemonThread.start(self)

    def set_proxy(self, proxy):
        self.proxy = proxy
        if proxy:
            proxy_mode = proxy_modes.index(proxy["mode"]) + 1
            socks.setdefaultproxy(proxy_mode, proxy["host"], int(proxy["port"]))
            socket.socket = socks.socksocket
            # prevent dns leaks, see http://stackoverflow.com/questions/13184205/dns-over-proxy
            socket.getaddrinfo = lambda *args: [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (args[0], args[1]))]
        else:
            socket.socket = socket._socketobject
            socket.getaddrinfo = socket._socket.getaddrinfo

    def start_network(self, protocol, proxy):
        assert not self.interface and not self.interfaces
        self.print_error('starting network')
        self.disconnected_servers = set([])
        self.protocol = protocol
        self.set_proxy(proxy)
        self.start_interfaces()

    def stop_network(self):
        self.print_error("stopping network")
        for i in self.interfaces.values():
            i.stop()
        self.interface = None
        self.interfaces = {}

    def set_parameters(self, host, port, protocol, proxy, auto_connect):
        server = serialize_server(host, port, protocol)
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
        if self.interfaces:
            server = random.choice(self.interfaces.keys())
            self.switch_to_interface(server)

    def switch_lagging_interface(self, suggestion = None):
        '''If auto_connect and lagging, switch interface'''
        if self.server_is_lagging() and self.auto_connect():
            if suggestion and self.protocol == deserialize_server(suggestion)[2]:
                self.switch_to_interface(suggestion)
            else:
                self.switch_to_random_interface()

    def switch_to_interface(self, server):
        '''Switch to server as our interface.  If no connection exists nor
        being opened, start a thread to connect.  The actual switch will
        happen on receipt of the connection notification.  Do nothing
        if server already is our interface.'''
        self.default_server = server
        if server in self.interfaces:
            if self.interface != self.interfaces[server]:
                self.print_error("switching to", server)
                # stop any current interface in order to terminate subscriptions
                self.stop_interface()
                self.interface = self.interfaces[server]
                self.send_subscriptions()
                self.set_status('connected')
                self.notify('updated')
        else:
            self.print_error("starting %s; will switch once connected" % server)
            self.start_interface(server)

    def stop_interface(self):
        if self.interface:
            self.interface.stop()
            self.interface = None

    def add_recent_server(self, i):
        # list is ordered
        s = i.server
        if s in self.recent_servers:
            self.recent_servers.remove(s)
        self.recent_servers.insert(0,s)
        self.recent_servers = self.recent_servers[0:20]
        self.save_recent_servers()

    def new_blockchain_height(self, blockchain_height, i):
        self.switch_lagging_interface(i.server)
        self.notify('updated')

    def process_if_notification(self, i):
        '''Handle interface addition and removal through notifications'''
        if i.is_connected():
            self.add_recent_server(i)
            i.send_request({'method':'blockchain.headers.subscribe','params':[]})
            if i.server == self.default_server:
                self.switch_to_interface(i.server)
        else:
            self.interfaces.pop(i.server, None)
            self.heights.pop(i.server, None)
            if i == self.interface:
                self.set_status('disconnected')
            self.disconnected_servers.add(i.server)
        # Our set of interfaces changed
        self.notify('interfaces')


    def process_response(self, i, response):
        # the id comes from the daemon or the network proxy
        _id = response.get('id')
        if _id is not None:
            if i != self.interface:
                return
            self.unanswered_requests.pop(_id)

        method = response.get('method')
        result = response.get('result')
        if method == 'blockchain.headers.subscribe':
            self.on_header(i, response)
        elif method == 'server.peers.subscribe':
            self.irc_servers = parse_servers(result)
            self.notify('servers')
        elif method == 'server.banner':
            self.banner = result
            self.notify('banner')
        elif method == 'blockchain.address.subscribe':
            addr = response.get('params')[0]
            self.addr_responses[addr] = result
            self.response_queue.put(response)
        else:
            self.response_queue.put(response)

    def handle_requests(self):
        while True:
            try:
                request = self.requests_queue.get_nowait()
            except Queue.Empty:
                break
            self.process_request(request)

    def process_request(self, request):
        method = request['method']
        params = request['params']
        _id = request['id']

        if method.startswith('network.'):
            out = {'id':_id}
            try:
                f = getattr(self, method[8:])
                out['result'] = f(*params)
            except AttributeError:
                out['error'] = "unknown method"
            except BaseException as e:
                out['error'] = str(e)
                traceback.print_exc(file=sys.stdout)
                self.print_error("network error", str(e))
            self.response_queue.put(out)
            return

        if method == 'blockchain.address.subscribe':
            addr = params[0]
            self.subscribed_addresses.add(addr)
            if addr in self.addr_responses:
                self.response_queue.put({'id':_id, 'result':self.addr_responses[addr]})
                return

        # store unanswered request
        self.unanswered_requests[_id] = request
        self.interface.send_request(request)

    def check_interfaces(self):
        now = time.time()
        # nodes
        if len(self.interfaces) < self.num_server:
            self.start_random_interface()
            if now - self.nodes_retry_time > NODES_RETRY_INTERVAL:
                self.print_error('network: retrying connections')
                self.disconnected_servers = set([])
                self.nodes_retry_time = now
        # main interface
        if not self.is_connected():
            if self.auto_connect():
                self.switch_to_random_interface()
            else:
                if self.default_server in self.disconnected_servers:
                    if now - self.server_retry_time > SERVER_RETRY_INTERVAL:
                        self.disconnected_servers.remove(self.default_server)
                        self.server_retry_time = now
                else:
                    self.switch_to_interface(self.default_server)

    def run(self):
        while self.is_running():
            self.check_interfaces()
            self.handle_requests()
            try:
                i, response = self.queue.get(timeout=0.1)
            except Queue.Empty:
                continue

            # if response is None it is a notification about the interface
            if response is None:
                self.process_if_notification(i)
            else:
                self.process_response(i, response)

        self.stop_network()
        self.print_error("stopped")


    def on_header(self, i, r):
        result = r.get('result')
        if not result:
            return
        height = result.get('block_height')
        if not height:
            return
        self.heights[i.server] = height
        self.merkle_roots[i.server] = result.get('merkle_root')
        self.utxo_roots[i.server] = result.get('utxo_root')
        # notify blockchain about the new height
        self.blockchain.queue.put((i,result))

        if i == self.interface:
            self.switch_lagging_interface()
            self.notify('updated')


    def get_header(self, tx_height):
        return self.blockchain.read_header(tx_height)

    def get_local_height(self):
        return self.blockchain.height()
