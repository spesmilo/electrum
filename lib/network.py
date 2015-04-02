import threading
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

DISCONNECTED_RETRY_INTERVAL = 60


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



def filter_protocol(servers, p):
    l = []
    for k, protocols in servers.items():
        if p in protocols:
            s = serialize_server(k, protocols[p], p)
            l.append(s)
    return l


def pick_random_server(p='s'):
    return random.choice( filter_protocol(DEFAULT_SERVERS,p) )

from simple_config import SimpleConfig

proxy_modes = ['socks4', 'socks5', 'http']

def serialize_proxy(p):
    if type(p) != dict:
        return None
    return ':'.join([p.get('mode'),p.get('host'), p.get('port')])

def deserialize_proxy(s):
    if type(s) != str:
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
    int(port)
    return host, port, protocol

def serialize_server(host, port, protocol):
    return str(':'.join([host, port, protocol]))


class Network(util.DaemonThread):

    def __init__(self, config=None):
        if config is None:
            config = {}  # Do not use mutables as default values!
        util.DaemonThread.__init__(self)
        self.config = SimpleConfig(config) if type(config) == type({}) else config
        self.lock = threading.Lock()
        self.num_server = 8 if not self.config.get('oneserver') else 0
        self.blockchain = Blockchain(self.config, self)
        self.interfaces = {}
        self.queue = Queue.Queue()
        # Server for addresses and transactions
        self.default_server = self.config.get('server')
        # Sanitize default server
        try:
            deserialize_server(self.default_server)
        except:
            self.default_server = None
        if not self.default_server:
            self.default_server = pick_random_server('s')

        self.protocol = deserialize_server(self.default_server)[2]
        self.irc_servers = {} # returned by interface (list from irc)

        self.disconnected_servers = set([])

        self.recent_servers = self.read_recent_servers()
        self.pending_servers = set()

        self.banner = ''
        self.interface = None
        self.heights = {}
        self.merkle_roots = {}
        self.utxo_roots = {}

        dir_path = os.path.join( self.config.path, 'certs')
        if not os.path.exists(dir_path):
            os.mkdir(dir_path)

        # address subscriptions and cached results
        self.addresses = {}
        self.connection_status = 'connecting'
        self.requests_queue = Queue.Queue()
        self.set_proxy(deserialize_proxy(self.config.get('proxy')))

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
        h = self.get_server_height()
        if not h:
            self.print_error('no height for main interface')
            return False
        lag = self.get_local_height() - self.get_server_height()
        return lag > 1

    def set_status(self, status):
        self.connection_status = status
        self.notify('status')

    def is_connected(self):
        return self.interface and self.interface.is_connected

    def send_subscriptions(self):
        for addr in self.addresses:
            self.interface.send_request({'method':'blockchain.address.subscribe', 'params':[addr]})
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

    def random_server(self):
        choice_list = []
        l = filter_protocol(self.get_servers(), self.protocol)
        for s in l:
            if s in self.pending_servers or s in self.disconnected_servers or s in self.interfaces.keys():
                continue
            else:
                choice_list.append(s)

        if not choice_list:
            return

        server = random.choice( choice_list )
        return server

    def get_parameters(self):
        host, port, protocol = deserialize_server(self.default_server)
        auto_connect = self.config.get('auto_cycle', True)
        return host, port, protocol, self.proxy, auto_connect

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
        if server in self.interfaces.keys():
            return
        i = interface.Interface(server, self.config)
        self.pending_servers.add(server)
        i.start(self.queue)
        return i

    def start_random_interface(self):
        server = self.random_server()
        if server:
            self.start_interface(server)

    def start_interfaces(self):
        self.interface = self.start_interface(self.default_server)
        for i in range(self.num_server):
            self.start_random_interface()

    def start(self, response_queue):
        self.running = True
        self.response_queue = response_queue
        self.start_interfaces()
        t = threading.Thread(target=self.process_requests_thread)
        t.start()
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


    def set_parameters(self, host, port, protocol, proxy, auto_connect):
        proxy_str = serialize_proxy(proxy)
        server_str = serialize_server(host, port, protocol)
        self.config.set_key('auto_cycle', auto_connect, True)
        self.config.set_key("proxy", proxy_str, True)
        self.config.set_key("server", server_str, True)
        # abort if changes were not allowed by config
        if self.config.get('server') != server_str or self.config.get('proxy') != proxy_str:
            return

        if self.proxy != proxy or self.protocol != protocol:
            self.print_error('restarting network')
            for i in self.interfaces.values():
                i.stop()
                self.interfaces.pop(i.server)
            self.set_proxy(proxy)
            self.protocol = protocol
            self.disconnected_servers = set([])
            if auto_connect:
                #self.interface = None
                return

        if auto_connect:
            if not self.interface.is_connected:
                self.switch_to_random_interface()
            else:
                if self.server_is_lagging():
                    self.stop_interface()
        else:
            self.set_server(server_str)


    def switch_to_random_interface(self):
        while self.interfaces:
            i = random.choice(self.interfaces.values())
            if i.is_connected:
                self.switch_to_interface(i)
                break
            else:
                self.remove_interface(i)

    def switch_to_interface(self, interface):
        server = interface.server
        self.print_error("switching to", server)
        self.interface = interface
        self.config.set_key('server', server, False)
        self.default_server = server
        self.send_subscriptions()
        self.set_status('connected')
        self.notify('updated')


    def stop_interface(self):
        self.interface.stop()


    def set_server(self, server):
        if self.default_server == server and self.interface.is_connected:
            return

        if self.protocol != deserialize_server(server)[2]:
            return

        # stop the interface in order to terminate subscriptions
        if self.interface.is_connected:
            self.stop_interface()

        # notify gui
        self.set_status('connecting')
        # start interface
        self.default_server = server
        self.config.set_key("server", server, True)

        if server in self.interfaces.keys():
            self.switch_to_interface( self.interfaces[server] )
        else:
            self.interface = self.start_interface(server)


    def add_recent_server(self, i):
        # list is ordered
        s = i.server
        if s in self.recent_servers:
            self.recent_servers.remove(s)
        self.recent_servers.insert(0,s)
        self.recent_servers = self.recent_servers[0:20]
        self.save_recent_servers()

    def add_interface(self, i):
        self.interfaces[i.server] = i
        self.notify('interfaces')

    def remove_interface(self, i):
        self.interfaces.pop(i.server)
        self.notify('interfaces')

    def new_blockchain_height(self, blockchain_height, i):
        if self.is_connected():
            if self.server_is_lagging():
                self.print_error("Server is lagging", blockchain_height, self.get_server_height())
                if self.config.get('auto_cycle'):
                    self.set_server(i.server)
        self.notify('updated')


    def process_response(self, i, response):
        method = response['method']
        if method == 'blockchain.address.subscribe':
            self.on_address(i, response)
        elif method == 'blockchain.headers.subscribe':
            self.on_header(i, response)
        elif method == 'server.peers.subscribe':
            self.on_peers(i, response)
        elif method == 'server.banner':
            self.on_banner(i, response)
        else:
            self.response_queue.put(response)

    def process_requests_thread(self):
        while self.is_running():
            try:
                request = self.requests_queue.get(timeout=0.1)
            except Queue.Empty:
                continue
            self.process_request(request)

    def process_request(self, request):
        method = request['method']
        params = request['params']
        _id = request['id']

        if method.startswith('network.'):
            out = {'id':_id}
            try:
                f = getattr(self, method[8:])
            except AttributeError:
                out['error'] = "unknown method"
            try:
                out['result'] = f(*params)
            except BaseException as e:
                out['error'] = str(e)
                traceback.print_exc(file=sys.stdout)
                self.print_error("network error", str(e))

            self.response_queue.put(out)
            return

        if method == 'blockchain.address.subscribe':
            addr = params[0]
            if addr in self.addresses:
                self.response_queue.put({'id':_id, 'result':self.addresses[addr]})
                return

        try:
            self.interface.send_request(request)
        except:
            # put it back in the queue
            self.print_error("warning: interface not ready for", request)
            self.requests_queue.put(request)
            time.sleep(0.1)

    def run(self):
        disconnected_time = time.time()
        while self.is_running():
            try:
                i, response = self.queue.get(timeout=0.1)
            except Queue.Empty:
                if len(self.interfaces) + len(self.pending_servers) < self.num_server:
                    self.start_random_interface()
                if not self.interfaces:
                    if time.time() - disconnected_time > DISCONNECTED_RETRY_INTERVAL:
                        self.print_error('network: retrying connections')
                        self.disconnected_servers = set([])
                        disconnected_time = time.time()
                if not self.interface.is_connected:
                    if self.config.get('auto_cycle'):
                        if self.interfaces:
                            self.switch_to_random_interface()
                    else:
                        if self.default_server in self.interfaces.keys():
                            self.switch_to_interface(self.interfaces[self.default_server])
                        else:
                            if self.default_server not in self.disconnected_servers and self.default_server not in self.pending_servers:
                                self.print_error("forcing reconnection")
                                self.interface = self.start_interface(self.default_server)
                continue

            if response is not None:
                self.process_response(i, response)
                continue

            # if response is None it is a notification about the interface
            if i.server in self.pending_servers:
                self.pending_servers.remove(i.server)

            if i.is_connected:
                self.add_interface(i)
                self.add_recent_server(i)
                i.send_request({'method':'blockchain.headers.subscribe','params':[]})
                if i == self.interface:
                    self.print_error('sending subscriptions to', self.interface.server)
                    self.send_subscriptions()
                    self.set_status('connected')
            else:
                if i.server in self.interfaces:
                    self.remove_interface(i)
                if i.server in self.heights:
                    self.heights.pop(i.server)
                if i == self.interface:
                    self.set_status('disconnected')
                self.disconnected_servers.add(i.server)

        self.print_error("stopping interfaces")
        for i in self.interfaces.values():
            i.stop()

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
            if self.server_is_lagging() and self.config.get('auto_cycle'):
                self.print_error("Server lagging, stopping interface")
                self.stop_interface()
            self.notify('updated')

    def on_peers(self, i, r):
        if not r: return
        self.irc_servers = parse_servers(r.get('result'))
        self.notify('servers')

    def on_banner(self, i, r):
        self.banner = r.get('result')
        self.notify('banner')

    def on_address(self, i, r):
        addr = r.get('params')[0]
        result = r.get('result')
        self.addresses[addr] = result
        self.response_queue.put(r)

    def get_header(self, tx_height):
        return self.blockchain.read_header(tx_height)

    def get_local_height(self):
        return self.blockchain.height()
