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
import random
import re
from collections import defaultdict
import threading
import socket
import json
import sys
import ipaddress
import asyncio
from typing import NamedTuple, Optional, Sequence

import dns
import dns.resolver
from aiorpcx import TaskGroup

from . import util
from .util import PrintError, print_error, aiosafe, bfh
from .bitcoin import COIN
from . import constants
from . import blockchain
from .blockchain import Blockchain
from .interface import Interface, serialize_server, deserialize_server
from .version import PROTOCOL_VERSION
from .simple_config import SimpleConfig

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
                if re.match(r"[st]\d*", v):
                    protocol, port = v[0], v[1:]
                    if port == '': port = constants.net.DEFAULT_PORTS[protocol]
                    out[protocol] = port
                elif re.match("v(.?)+", v):
                    version = v[1:]
                elif re.match(r"p\d*", v):
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
            return util.versiontuple(version) >= util.versiontuple(PROTOCOL_VERSION)
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


NetworkParameters = NamedTuple("NetworkParameters", [("host", str),
                                                     ("port", str),
                                                     ("protocol", str),
                                                     ("proxy", Optional[dict]),
                                                     ("auto_connect", bool)])


proxy_modes = ['socks4', 'socks5']


def serialize_proxy(p):
    if not isinstance(p, dict):
        return None
    return ':'.join([p.get('mode'), p.get('host'), p.get('port'),
                     p.get('user', ''), p.get('password', '')])


def deserialize_proxy(s: str) -> Optional[dict]:
    if not isinstance(s, str):
        return None
    if s.lower() == 'none':
        return None
    proxy = { "mode":"socks5", "host":"localhost" }
    # FIXME raw IPv6 address fails here
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


INSTANCE = None


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
        global INSTANCE
        INSTANCE = self
        if config is None:
            config = {}  # Do not use mutables as default values!
        self.config = SimpleConfig(config) if isinstance(config, dict) else config
        self.num_server = 10 if not self.config.get('oneserver') else 0
        blockchain.blockchains = blockchain.read_blockchains(self.config)
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
        self.recent_servers_lock = threading.RLock()       # <- re-entrant

        self.server_peers = {}  # returned by interface (servers that the main interface knows about)
        self.recent_servers = self.read_recent_servers()  # note: needs self.recent_servers_lock

        self.banner = ''
        self.donation_address = ''
        self.relay_fee = None
        # callbacks set by the GUI
        self.callbacks = defaultdict(list)      # note: needs self.callback_lock

        dir_path = os.path.join(self.config.path, 'certs')
        util.make_dir(dir_path)

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
        self.server_queue = None
        self.server_queue_group = None
        self.asyncio_loop = asyncio.get_event_loop()
        self.start_network(deserialize_server(self.default_server)[2],
                           deserialize_proxy(self.config.get('proxy')))

    @staticmethod
    def get_instance():
        return INSTANCE

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
        for callback in callbacks:
            # FIXME: if callback throws, we will lose the traceback
            if asyncio.iscoroutinefunction(callback):
                asyncio.run_coroutine_threadsafe(callback(event, *args), self.asyncio_loop)
            else:
                self.asyncio_loop.call_soon_threadsafe(callback, event, *args)

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
        interface = self.interface
        return interface is not None and interface.ready.done()

    def is_connecting(self):
        return self.connection_status == 'connecting'

    async def request_server_info(self, interface):
        await interface.ready
        session = interface.session

        async def get_banner():
            self.banner = await session.send_request('server.banner')
            self.notify('banner')
        async def get_donation_address():
            self.donation_address = await session.send_request('server.donation_address')
        async def get_server_peers():
            self.server_peers = parse_servers(await session.send_request('server.peers.subscribe'))
            self.notify('servers')
        async def get_relay_fee():
            relayfee = await session.send_request('blockchain.relayfee')
            if relayfee is None:
                self.relay_fee = None
            else:
                relayfee = int(relayfee * COIN)
                self.relay_fee = max(0, relayfee)

        async with TaskGroup() as group:
            await group.spawn(get_banner)
            await group.spawn(get_donation_address)
            await group.spawn(get_server_peers)
            await group.spawn(get_relay_fee)
            await group.spawn(self.request_fee_estimates(interface))

    async def request_fee_estimates(self, interface):
        session = interface.session
        from .simple_config import FEE_ETA_TARGETS
        self.config.requested_fee_estimates()
        async with TaskGroup() as group:
            histogram_task = await group.spawn(session.send_request('mempool.get_fee_histogram'))
            fee_tasks = []
            for i in FEE_ETA_TARGETS:
                fee_tasks.append((i, await group.spawn(session.send_request('blockchain.estimatefee', [i]))))
        self.config.mempool_fees = histogram = histogram_task.result()
        self.print_error('fee_histogram', histogram)
        self.notify('fee_histogram')
        for i, task in fee_tasks:
            fee = int(task.result() * COIN)
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
        elif key == 'servers':
            value = self.get_servers()
        else:
            raise Exception('unexpected trigger key {}'.format(key))
        return value

    def notify(self, key):
        if key in ['status', 'updated']:
            self.trigger_callback(key)
        else:
            self.trigger_callback(key, self.get_status_value(key))

    def get_parameters(self) -> NetworkParameters:
        host, port, protocol = deserialize_server(self.default_server)
        return NetworkParameters(host, port, protocol, self.proxy, self.auto_connect)

    def get_donation_address(self):
        if self.is_connected():
            return self.donation_address

    @with_interface_lock
    def get_interfaces(self):
        '''The interfaces that are in connected state'''
        return list(self.interfaces.keys())

    @with_recent_servers_lock
    def get_servers(self):
        # start with hardcoded servers
        out = constants.net.DEFAULT_SERVERS
        # add recent servers
        for s in self.recent_servers:
            try:
                host, port, protocol = deserialize_server(s)
            except:
                continue
            if host not in out:
                out[host] = {protocol: port}
        # add servers received from main interface
        if self.server_peers:
            out.update(filter_version(self.server_peers.copy()))
        # potentially filter out some
        if self.config.get('noonion'):
            out = filter_noonion(out)
        return out

    @with_interface_lock
    def start_interface(self, server):
        if server not in self.interfaces and server not in self.connecting:
            if server == self.default_server:
                self.print_error("connecting to %s as new interface" % server)
                self.set_status('connecting')
            self.connecting.add(server)
            self.server_queue.put(server)

    def start_random_interface(self):
        with self.interface_lock:
            exclude_set = self.disconnected_servers | set(self.interfaces) | self.connecting
        server = pick_random_server(self.get_servers(), self.protocol, exclude_set)
        if server:
            self.start_interface(server)
        return server

    def set_proxy(self, proxy: Optional[dict]):
        self.proxy = proxy
        # Store these somewhere so we can un-monkey-patch
        if not hasattr(socket, "_getaddrinfo"):
            socket._getaddrinfo = socket.getaddrinfo
        if proxy:
            self.print_error('setting proxy', proxy)
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
        self.trigger_callback('proxy_set', self.proxy)

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
    def start_network(self, protocol: str, proxy: Optional[dict]):
        assert not self.interface and not self.interfaces
        assert not self.connecting and not self.server_queue
        assert not self.server_queue_group
        self.print_error('starting network')
        self.disconnected_servers = set([])  # note: needs self.interface_lock
        self.protocol = protocol
        self._init_server_queue()
        self.set_proxy(proxy)
        self.start_interface(self.default_server)
        self.trigger_callback('network_updated')

    def _init_server_queue(self):
        self.server_queue = queue.Queue()
        self.server_queue_group = server_queue_group = TaskGroup()
        async def job():
            forever = asyncio.Event()
            async with server_queue_group as group:
                await group.spawn(forever.wait())
        asyncio.run_coroutine_threadsafe(job(), self.asyncio_loop)

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
        self._stop_server_queue()
        self.trigger_callback('network_updated')

    def _stop_server_queue(self):
        # Get a new queue - no old pending connections thanks!
        self.server_queue = None
        asyncio.run_coroutine_threadsafe(self.server_queue_group.cancel_remaining(), self.asyncio_loop)
        self.server_queue_group = None

    def set_parameters(self, net_params: NetworkParameters):
        proxy = net_params.proxy
        proxy_str = serialize_proxy(proxy)
        host, port, protocol = net_params.host, net_params.port, net_params.protocol
        server_str = serialize_server(host, port, protocol)
        # sanitize parameters
        try:
            deserialize_server(serialize_server(host, port, protocol))
            if proxy:
                proxy_modes.index(proxy["mode"]) + 1
                int(proxy['port'])
        except:
            return
        self.config.set_key('auto_connect', net_params.auto_connect, False)
        self.config.set_key("proxy", proxy_str, False)
        self.config.set_key("server", server_str, True)
        # abort if changes were not allowed by config
        if self.config.get('server') != server_str or self.config.get('proxy') != proxy_str:
            return
        self.auto_connect = net_params.auto_connect
        if self.proxy != proxy or self.protocol != protocol:
            # Restart the network defaulting to the given server
            with self.interface_lock:
                self.stop_network()
                self.default_server = server_str
                self.start_network(protocol, proxy)
        elif self.default_server != server_str:
            self.switch_to_interface(server_str)
        else:
            self.switch_lagging_interface()

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
            def filt(x):
                a = x[1].tip_header
                b = header
                assert type(a) is type(b)
                return a == b
            filtered = list(map(lambda x: x[0], filter(filt, self.interfaces.items())))
            if filtered:
                choice = random.choice(filtered)
                self.switch_to_interface(choice)

    @with_interface_lock
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
            blockchain_updated = False
            if self.interface is not None:
                blockchain_updated = i.blockchain != self.interface.blockchain
                # Stop any current interface in order to terminate subscriptions,
                # and to cancel tasks in interface.group.
                # However, for headers sub, give preference to this interface
                # over unknown ones, i.e. start it again right away.
                old_server = self.interface.server
                self.close_interface(self.interface)
                if old_server != server and len(self.interfaces) <= self.num_server:
                    self.start_interface(old_server)

            self.interface = i
            asyncio.run_coroutine_threadsafe(
                i.group.spawn(self.request_server_info(i)), self.asyncio_loop)
            self.trigger_callback('default_server_changed')
            self.set_status('connected')
            self.trigger_callback('network_updated')
            if blockchain_updated: self.trigger_callback('blockchain_updated')

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

    @with_interface_lock
    def connection_down(self, server):
        '''A connection to server either went down, or was never made.
        We distinguish by whether it is in self.interfaces.'''
        self.disconnected_servers.add(server)
        if server == self.default_server:
            self.set_status('disconnected')
        if server in self.interfaces:
            self.close_interface(self.interfaces[server])
            self.trigger_callback('network_updated')

    @aiosafe
    async def new_interface(self, server):
        interface = Interface(self, server, self.config.path, self.proxy)
        timeout = 10 if not self.proxy else 20
        try:
            await asyncio.wait_for(interface.ready, timeout)
        except BaseException as e:
            #import traceback
            #traceback.print_exc()
            self.print_error(server, "couldn't launch because", str(e), str(type(e)))
            # note: connection_down will not call interface.close() as
            # interface is not yet in self.interfaces. OTOH, calling
            # interface.close() here will sometimes raise deep inside the
            # asyncio internal select.select... instead, interface will close
            # itself when it detects the cancellation of interface.ready;
            # however this might take several seconds...
            self.connection_down(server)
            return
        else:
            with self.interface_lock:
                self.interfaces[server] = interface
        finally:
            with self.interface_lock:
                try: self.connecting.remove(server)
                except KeyError: pass

        if server == self.default_server:
            self.switch_to_interface(server)

        self.add_recent_server(server)
        self.trigger_callback('network_updated')

    def init_headers_file(self):
        b = blockchain.blockchains[0]
        filename = b.path()
        length = 80 * len(constants.net.CHECKPOINTS) * 2016
        if not os.path.exists(filename) or os.path.getsize(filename) < length:
            with open(filename, 'wb') as f:
                if length > 0:
                    f.seek(length-1)
                    f.write(b'\x00')
            util.ensure_sparse_file(filename)
        with b.lock:
            b.update_size()

    async def get_merkle_for_transaction(self, tx_hash, tx_height):
        return await self.interface.session.send_request('blockchain.transaction.get_merkle', [tx_hash, tx_height])

    def broadcast_transaction_from_non_network_thread(self, tx, timeout=10):
        # note: calling this from the network thread will deadlock it
        fut = asyncio.run_coroutine_threadsafe(self.broadcast_transaction(tx, timeout=timeout), self.asyncio_loop)
        return fut.result()

    async def broadcast_transaction(self, tx, timeout=10):
        try:
            out = await self.interface.session.send_request('blockchain.transaction.broadcast', [str(tx)], timeout=timeout)
        except asyncio.TimeoutError as e:
            return False, "error: operation timed out"
        except Exception as e:
            return False, "error: " + str(e)

        if out != tx.txid():
            return False, "error: " + out
        return True, out

    async def request_chunk(self, height, tip=None, *, can_return_early=False):
        return await self.interface.request_chunk(height, tip=tip, can_return_early=can_return_early)

    @with_interface_lock
    def blockchain(self):
        if self.interface and self.interface.blockchain is not None:
            self.blockchain_index = self.interface.blockchain.forkpoint
        return blockchain.blockchains[self.blockchain_index]

    @with_interface_lock
    def get_blockchains(self):
        out = {}  # blockchain_id -> list(interfaces)
        with blockchain.blockchains_lock: blockchain_items = list(blockchain.blockchains.items())
        for chain_id, bc in blockchain_items:
            r = list(filter(lambda i: i.blockchain==bc, list(self.interfaces.values())))
            if r:
                out[chain_id] = r
        return out

    @with_interface_lock
    def disconnect_from_interfaces_on_given_blockchain(self, chain: Blockchain) -> Sequence[Interface]:
        chain_id = chain.forkpoint
        ifaces = self.get_blockchains().get(chain_id) or []
        for interface in ifaces:
            self.connection_down(interface.server)
        return ifaces

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
                net_params = self.get_parameters()
                host, port, protocol = deserialize_server(self.interface.server)
                net_params = net_params._replace(host=host, port=port, protocol=protocol)
                self.set_parameters(net_params)

    def get_local_height(self):
        return self.blockchain().height()

    def export_checkpoints(self, path):
        # run manually from the console to generate checkpoints
        cp = self.blockchain().get_checkpoints()
        with open(path, 'w', encoding='utf-8') as f:
            f.write(json.dumps(cp, indent=4))

    def start(self, fx=None):
        self.main_taskgroup = TaskGroup()
        async def main():
            self.init_headers_file()
            async with self.main_taskgroup as group:
                await group.spawn(self.maintain_sessions())
                if fx: await group.spawn(fx)
        self._wrapper_thread = threading.Thread(target=self.asyncio_loop.run_until_complete, args=(main(),))
        self._wrapper_thread.start()

    def stop(self):
        asyncio.run_coroutine_threadsafe(self.main_taskgroup.cancel_remaining(), self.asyncio_loop)

    def join(self):
        self._wrapper_thread.join(1)

    async def maintain_sessions(self):
        while True:
            while self.server_queue.qsize() > 0:
                server = self.server_queue.get()
                await self.server_queue_group.spawn(self.new_interface(server))
            remove = []
            for k, i in self.interfaces.items():
                if i.fut.done() and not i.exception:
                    assert False, "interface future should not finish without exception"
                if i.exception:
                    if not i.fut.done():
                        try: i.fut.cancel()
                        except Exception as e: self.print_error('exception while cancelling fut', e)
                    try:
                        raise i.exception
                    except BaseException as e:
                        self.print_error(i.server, "errored because:", str(e), str(type(e)))
                    remove.append(k)
            for k in remove:
                self.connection_down(k)

            # nodes
            now = time.time()
            for i in range(self.num_server - len(self.interfaces) - len(self.connecting)):
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
                    await self.interface.group.spawn(self.request_fee_estimates, self.interface)

            await asyncio.sleep(0.1)
