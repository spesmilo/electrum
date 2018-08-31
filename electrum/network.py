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
import concurrent.futures
import time
import queue
import os
import random
import re
from collections import defaultdict
import threading
import socket
import json
import sys
import ipaddress

import dns
import dns.resolver

from . import util
from .util import PrintError, print_error, bfh
from .bitcoin import COIN
from . import constants
from . import blockchain
from .interface import Interface

import asyncio
import concurrent.futures
from .version import PROTOCOL_VERSION

NODES_RETRY_INTERVAL = 60
SERVER_RETRY_INTERVAL = 10


def parse_servers(result):
    """ parse servers list into dict format"""
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
                    if port == '': port = constants.net.DEFAULT_PORTS[protocol]
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


def filter_noonion(servers):
    return {k: v for k, v in servers.items() if not k.endswith('.onion')}


def filter_protocol(hostmap, protocol='s'):
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
        hostmap = constants.net.DEFAULT_SERVERS
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
    if protocol not in 'st':
        raise ValueError('invalid network protocol: {}'.format(protocol))
    int(port)    # Throw if cannot be converted to int
    return host, port, protocol


def serialize_server(host, port, protocol):
    return str(':'.join([host, port, protocol]))

class Network(PrintError):
    """The Network class manages a set of connections to remote electrum
    servers, each connected socket is handled by an Interface() object.
    Connections are initiated by a Connection() thread which stops once
    the connection succeeds or fails.

    Our external API:

    - Member functions get_header(), get_interfaces(), get_local_height(),
          get_parameters(), get_server_height(), get_status_value(),
          is_connected(), set_parameters(), stop()
    """
    verbosity_filter = 'n'

    def __init__(self, config=None):
        if config is None:
            config = {}  # Do not use mutables as default values!
        self.config = SimpleConfig(config) if isinstance(config, dict) else config
        self.num_server = 10 if not self.config.get('oneserver') else 0
        blockchain.blockchains = blockchain.read_blockchains(self.config)  # note: needs self.blockchains_lock
        self.print_error("blockchains", list(blockchain.blockchains.keys()))
        self.blockchain_index = config.get('blockchain_index', 0)
        if self.blockchain_index not in blockchain.blockchains.keys():
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

        # locks: if you need to take multiple ones, acquire them in the order they are defined here!
        self.bhi_lock = asyncio.Lock()
        self.interface_lock = threading.RLock()            # <- re-entrant
        self.callback_lock = threading.Lock()
        self.pending_sends_lock = threading.Lock()
        self.recent_servers_lock = threading.RLock()       # <- re-entrant
        self.blockchains_lock = threading.Lock()

        self.pending_sends = []
        self.message_id = 0
        self.debug = False
        self.irc_servers = {}  # returned by interface (list from irc)
        self.recent_servers = self.read_recent_servers()  # note: needs self.recent_servers_lock

        self.banner = ''
        self.donation_address = ''
        self.relay_fee = None
        # callbacks passed with subscriptions
        self.subscriptions = defaultdict(list)  # note: needs self.callback_lock
        self.sub_cache = {}                     # note: needs self.interface_lock
        # callbacks set by the GUI
        self.callbacks = defaultdict(list)      # note: needs self.callback_lock

        dir_path = os.path.join(self.config.path, 'certs')
        util.make_dir(dir_path)

        # subscriptions and requests
        self.h2addr = {}
        # Requests from client we've not seen a response to
        self.unanswered_requests = {}
        # retry times
        self.server_retry_time = time.time()
        self.nodes_retry_time = time.time()
        # kick off the network.  interface is the main server we are currently
        # communicating with.  interfaces is the set of servers we are connecting
        # to or have an ongoing connection with
        self.interface = None              # note: needs self.interface_lock
        self.interfaces = {}               # note: needs self.interface_lock
        self.auto_connect = self.config.get('auto_connect', True)
        self.connecting = set()
        self.requested_chunks = set()
        self.socket_queue = queue.Queue()
        self.start_network(deserialize_server(self.default_server)[2],
                           deserialize_proxy(self.config.get('proxy')))
        self.asyncio_loop = asyncio.get_event_loop()
        self.futures = []
        self.server_info_job = asyncio.Future()
        # just to not trigger a warning from switch_to_interface the first time we change default_server
        self.server_info_job.set_result(1)

    def with_interface_lock(func):
        def func_wrapper(self, *args, **kwargs):
            with self.interface_lock:
                return func(self, *args, **kwargs)
        return func_wrapper

    def with_recent_servers_lock(func):
        def func_wrapper(self, *args, **kwargs):
            with self.recent_servers_lock:
                return func(self, *args, **kwargs)
        return func_wrapper

    def register_callback(self, callback, events):
        with self.callback_lock:
            for event in events:
                self.callbacks[event].append(callback)

    def unregister_callback(self, callback):
        with self.callback_lock:
            for callbacks in self.callbacks.values():
                if callback in callbacks:
                    callbacks.remove(callback)

    def trigger_callback(self, event, *args):
        with self.callback_lock:
            callbacks = self.callbacks[event][:]
        [callback(event, *args) for callback in callbacks]

    def read_recent_servers(self):
        if not self.config.path:
            return []
        path = os.path.join(self.config.path, "recent_servers")
        try:
            with open(path, "r", encoding='utf-8') as f:
                data = f.read()
                return json.loads(data)
        except:
            return []

    @with_recent_servers_lock
    def save_recent_servers(self):
        if not self.config.path:
            return
        path = os.path.join(self.config.path, "recent_servers")
        s = json.dumps(self.recent_servers, indent=4, sort_keys=True)
        try:
            with open(path, "w", encoding='utf-8') as f:
                f.write(s)
        except:
            pass

    @with_interface_lock
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
        return self.interface is not None and self.interface.ready.done()

    def is_connecting(self):
        return self.connection_status == 'connecting'

    @util.aiosafe
    async def request_server_info(self, interface):
        await interface.ready
        session = interface.session
        self.banner = await session.send_request('server.banner')
        self.notify('banner')
        self.donation_address = await session.send_request('server.donation_address')
        self.irc_servers = parse_servers(await session.send_request('server.peers.subscribe'))
        self.notify('servers')
        await self.request_fee_estimates(interface)
        relayfee = await session.send_request('blockchain.relayfee')
        self.relay_fee = int(relayfee * COIN) if relayfee is not None else None

    async def request_fee_estimates(self, interface):
        session = interface.session
        from .simple_config import FEE_ETA_TARGETS
        self.config.requested_fee_estimates()
        histogram = await session.send_request('mempool.get_fee_histogram')
        fees = []
        for i in FEE_ETA_TARGETS:
            fees.append((i, await session.send_request('blockchain.estimatefee', [i])))
        self.config.mempool_fees = histogram
        self.notify('fee_histogram')
        for i, result in fees:
            fee = int(result * COIN)
            self.config.update_fee_estimates(i, fee)
            self.print_error("fee_estimates[%d]" % i, fee)
        self.notify('fee')

    def get_status_value(self, key):
        if key == 'status':
            value = self.connection_status
        elif key == 'banner':
            value = self.banner
        elif key == 'fee':
            value = self.config.fee_estimates
        elif key == 'fee_histogram':
            value = self.config.mempool_fees
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

    @with_interface_lock
    def get_interfaces(self):
        '''The interfaces that are in connected state'''
        return list(self.interfaces.keys())

    @with_recent_servers_lock
    def get_servers(self):
        out = constants.net.DEFAULT_SERVERS
        if self.irc_servers:
            out.update(filter_version(self.irc_servers.copy()))
        else:
            for s in self.recent_servers:
                try:
                    host, port, protocol = deserialize_server(s)
                except:
                    continue
                if host not in out:
                    out[host] = {protocol: port}
        if self.config.get('noonion'):
            out = filter_noonion(out)
        return out

    @with_interface_lock
    def start_interface(self, server):
        if (not server in self.interfaces and not server in self.connecting):
            if server == self.default_server:
                self.print_error("connecting to %s as new interface" % server)
                self.set_status('connecting')
            self.connecting.add(server)
            self.socket_queue.put(server)

    def start_random_interface(self):
        with self.interface_lock:
            exclude_set = self.disconnected_servers.union(set(self.interfaces))
        server = pick_random_server(self.get_servers(), self.protocol, exclude_set)
        if server:
            self.start_interface(server)
        return server

    def set_proxy(self, proxy):
        self.proxy = proxy
        # Store these somewhere so we can un-monkey-patch
        if not hasattr(socket, "_socketobject"):
            socket._getaddrinfo = socket.getaddrinfo
        if proxy:
            self.print_error('setting proxy', proxy)
            proxy_mode = proxy_modes.index(proxy["mode"]) + 1
            # prevent dns leaks, see http://stackoverflow.com/questions/13184205/dns-over-proxy
            socket.getaddrinfo = lambda *args: [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (args[0], args[1]))]
        else:
            if sys.platform == 'win32':
                # On Windows, socket.getaddrinfo takes a mutex, and might hold it for up to 10 seconds
                # when dns-resolving. To speed it up drastically, we resolve dns ourselves, outside that lock.
                # see #4421
                socket.getaddrinfo = self._fast_getaddrinfo
            else:
                socket.getaddrinfo = socket._getaddrinfo

    @staticmethod
    def _fast_getaddrinfo(host, *args, **kwargs):
        def needs_dns_resolving(host2):
            try:
                ipaddress.ip_address(host2)
                return False  # already valid IP
            except ValueError:
                pass  # not an IP
            if str(host) in ('localhost', 'localhost.',):
                return False
            return True
        try:
            if needs_dns_resolving(host):
                answers = dns.resolver.query(host)
                addr = str(answers[0])
            else:
                addr = host
        except dns.exception.DNSException:
            # dns failed for some reason, e.g. dns.resolver.NXDOMAIN
            # this is normal. Simply report back failure:
            raise socket.gaierror(11001, 'getaddrinfo failed')
        except BaseException as e:
            # Possibly internal error in dnspython :( see #4483
            # Fall back to original socket.getaddrinfo to resolve dns.
            print_error('dnspython failed to resolve dns with error:', e)
            addr = host
        return socket._getaddrinfo(addr, *args, **kwargs)

    @with_interface_lock
    def start_network(self, protocol, proxy):
        assert not self.interface and not self.interfaces
        assert not self.connecting and self.socket_queue.empty()
        self.print_error('starting network')
        self.disconnected_servers = set([])  # note: needs self.interface_lock
        self.protocol = protocol
        self.set_proxy(proxy)
        self.start_interface(self.default_server)

    @with_interface_lock
    def stop_network(self):
        self.print_error("stopping network")
        for interface in list(self.interfaces.values()):
            self.close_interface(interface)
        if self.interface:
            self.close_interface(self.interface)
        assert self.interface is None
        assert not self.interfaces
        self.connecting.clear()
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
            with self.interface_lock:
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

    @with_interface_lock
    def switch_lagging_interface(self):
        '''If auto_connect and lagging, switch interface'''
        if self.server_is_lagging() and self.auto_connect:
            # switch to one that has the correct header (not height)
            header = self.blockchain().read_header(self.get_local_height())
            filtered = list(map(lambda x: x[0], filter(lambda x: x[1].tip_header == header, self.interfaces.items())))
            if filtered:
                choice = random.choice(filtered)
                self.switch_to_interface(choice)

    @with_interface_lock
    def switch_to_interface(self, server):
        '''Switch to server as our interface.  If no connection exists nor
        being opened, start a thread to connect.  The actual switch will
        happen on receipt of the connection notification.  Do nothing
        if server already is our interface.'''
        old_default_server = self.default_server
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
            if not self.server_info_job.done():
                self.print_error('cancelled previous request_server_info job, was it too slow? server was:', old_default_server)
                self.server_info_job.cancel()
            self.server_info_job = asyncio.get_event_loop().create_task(self.request_server_info(i))
            self.trigger_callback('default_server_changed')
            self.set_status('connected')
            self.notify('updated')
            self.notify('interfaces')

    @with_interface_lock
    def close_interface(self, interface):
        if interface:
            if interface.server in self.interfaces:
                self.interfaces.pop(interface.server)
            if interface.server == self.default_server:
                self.interface = None
            interface.close()

    @with_recent_servers_lock
    def add_recent_server(self, server):
        # list is ordered
        if server in self.recent_servers:
            self.recent_servers.remove(server)
        self.recent_servers.insert(0, server)
        self.recent_servers = self.recent_servers[0:20]
        self.save_recent_servers()

    def process_response(self, interface, response, callbacks):
        if self.debug:
            self.print_error(interface.host, "<--", response)
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
            else:
                # no point in keeping this connection without headers sub
                self.connection_down(interface.server)
                return
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
        elif method == 'mempool.get_fee_histogram':
            if error is None:
                self.print_error('fee_histogram', result)
                self.config.mempool_fees = result
                self.notify('fee_histogram')
        elif method == 'blockchain.estimatefee':
            if error is None and result > 0:
                i = params[0]
                fee = int(result*COIN)
                self.config.update_fee_estimates(i, fee)
                self.print_error("fee_estimates[%d]" % i, fee)
                self.notify('fee')
        elif method == 'blockchain.relayfee':
            if error is None:
                self.relay_fee = int(result * COIN) if result is not None else None
                self.print_error("relayfee", self.relay_fee)
        elif method == 'blockchain.block.headers':
            self.on_block_headers(interface, response)
        elif method == 'blockchain.block.get_header':
            self.on_get_header(interface, response)

        for callback in callbacks:
            callback(response)

    @classmethod
    def get_index(cls, method, params):
        """ hashable index for subscriptions and cache"""
        return str(method) + (':' + str(params[0]) if params else '')

    def unsubscribe(self, callback):
        '''Unsubscribe a callback to free object references to enable GC.'''
        # Note: we can't unsubscribe from the server, so if we receive
        # subsequent notifications process_response() will emit a harmless
        # "received unexpected notification" warning
        with self.callback_lock:
            for v in self.subscriptions.values():
                if callback in v:
                    v.remove(callback)

    @with_interface_lock
    def connection_down(self, server):
        '''A connection to server either went down, or was never made.
        We distinguish by whether it is in self.interfaces.'''
        self.disconnected_servers.add(server)
        if server == self.default_server:
            self.set_status('disconnected')
        if server in self.interfaces:
            self.close_interface(self.interfaces[server])
            self.notify('interfaces')
        with self.blockchains_lock:
            for b in blockchain.blockchains.values():
                if b.catch_up == server:
                    b.catch_up = None

    @util.aiosafe
    async def new_interface(self, server):
        # todo: get tip first, then decide which checkpoint to use.
        self.add_recent_server(server)

        interface = Interface(self, server, self.config.path, self.proxy)
        try:
            await asyncio.wait_for(interface.ready, 5)
        except BaseException as e:
            import traceback
            traceback.print_exc()
            self.print_error(interface.server, "couldn't launch because", str(e), str(type(e)))
            self.connection_down(interface.server)
            return
        finally:
            self.connecting.remove(server)

        with self.interface_lock:
            self.interfaces[server] = interface

        if server == self.default_server:
            self.switch_to_interface(server)

        #self.notify('interfaces')

    def init_headers_file(self):
        b = blockchain.blockchains[0]
        filename = b.path()
        length = 80 * len(constants.net.CHECKPOINTS) * 2016
        if not os.path.exists(filename) or os.path.getsize(filename) < length:
            with open(filename, 'wb') as f:
                if length>0:
                    f.seek(length-1)
                    f.write(b'\x00')
        with b.lock:
            b.update_size()

    def _run(self):
        self.init_headers_file()
        self.gat = self.asyncio_loop.create_task(self.maintain_sessions())
        try:
            self.asyncio_loop.run_until_complete(self.gat)
        except concurrent.futures.CancelledError:
            pass

    @with_interface_lock
    def blockchain(self):
        if self.interface and self.interface.blockchain is not None:
            self.blockchain_index = self.interface.blockchain.forkpoint
        return blockchain.blockchains[self.blockchain_index]

    @with_interface_lock
    def get_blockchains(self):
        out = {}
        with self.blockchains_lock:
            blockchain_items = list(blockchain.blockchains.items())
        for k, b in blockchain_items:
            r = list(filter(lambda i: i.blockchain==b, list(self.interfaces.values())))
            if r:
                out[k] = r
        return out

    def follow_chain(self, index):
        bc = blockchain.blockchains.get(index)
        if bc:
            self.blockchain_index = index
            self.config.set_key('blockchain_index', index)
            with self.interface_lock:
                interfaces = list(self.interfaces.values())
            for i in interfaces:
                if i.blockchain == bc:
                    self.switch_to_interface(i.server)
                    break
        else:
            raise Exception('blockchain not found', index)

        with self.interface_lock:
            if self.interface:
                server = self.interface.server
                host, port, protocol, proxy, auto_connect = self.get_parameters()
                host, port, protocol = server.split(':')
                self.set_parameters(host, port, protocol, proxy, auto_connect)

    def get_local_height(self):
        return self.blockchain().height()

    def export_checkpoints(self, path):
        # run manually from the console to generate checkpoints
        cp = self.blockchain().get_checkpoints()
        with open(path, 'w', encoding='utf-8') as f:
            f.write(json.dumps(cp, indent=4))

    @classmethod
    def max_checkpoint(cls):
        return max(0, len(constants.net.CHECKPOINTS) * 2016 - 1)

    def start(self):
        self.fut = threading.Thread(target=self._run)
        self.fut.start()

    def stop(self):
        async def stop():
            self.gat.cancel()
        asyncio.run_coroutine_threadsafe(stop(), self.asyncio_loop)

    def join(self):
        return self.fut.join(1)

    async def maintain_sessions(self):
        while True:
            while self.socket_queue.qsize() > 0:
                server = self.socket_queue.get()
                asyncio.get_event_loop().create_task(self.new_interface(server))
            remove = []
            for k, i in self.interfaces.items():
                if i.fut.done():
                    if i.exception:
                        try:
                            raise i.exception
                        except BaseException as e:
                            self.print_error(i.server, "errored because", str(e), str(type(e)))
                    else:
                        assert False, "interface future should not finish without exception"
                    remove.append(k)
            changed = False
            for k in remove:
                self.connection_down(k)
                changed = True

            # nodes
            now = time.time()
            for i in range(self.num_server - len(self.interfaces) - len(self.connecting)):
                if self.start_random_interface():
                    changed = True
                    if now - self.nodes_retry_time > NODES_RETRY_INTERVAL:
                        self.print_error('network: retrying connections')
                        self.disconnected_servers = set([])
                        self.nodes_retry_time = now

            # main interface
            if not self.is_connected():
                if self.auto_connect:
                    if not self.is_connecting():
                        self.switch_to_random_interface()
                        changed = True
                else:
                    if self.default_server in self.disconnected_servers:
                        if now - self.server_retry_time > SERVER_RETRY_INTERVAL:
                            self.disconnected_servers.remove(self.default_server)
                            self.server_retry_time = now
                            changed = True
                    else:
                        self.switch_to_interface(self.default_server)
                        changed = True
            else:
                if self.config.is_fee_estimates_update_required():
                    asyncio.get_event_loop().create_task(self.attempt_fee_estimate_update())

            if changed:
                self.notify('updated')
            await asyncio.sleep(1)

    @util.aiosafe
    async def attempt_fee_estimate_update(self):
        await asyncio.wait_for(self.request_fee_estimates(self.interface), 5)
