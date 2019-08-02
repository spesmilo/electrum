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
from typing import NamedTuple, Optional, Sequence, List, Dict, Tuple
import traceback

import dns
import dns.resolver
import aiorpcx
from aiorpcx import TaskGroup
from aiohttp import ClientResponse

from . import util
from .util import (log_exceptions, ignore_exceptions,
                   bfh, SilentTaskGroup, make_aiohttp_session, send_exception_to_crash_reporter,
                   is_hash256_str, is_non_negative_integer)

from .bitcoin import COIN
from . import constants
from . import blockchain
from . import bitcoin
from .blockchain import Blockchain, HEADER_SIZE
from .interface import (Interface, serialize_server, deserialize_server,
                        RequestTimedOut, NetworkTimeout, BUCKET_NAME_OF_ONION_SERVERS)
from .version import PROTOCOL_VERSION
from .simple_config import SimpleConfig
from .i18n import _
from .logging import get_logger, Logger


_logger = get_logger(__name__)


NODES_RETRY_INTERVAL = 60
SERVER_RETRY_INTERVAL = 10
NUM_TARGET_CONNECTED_SERVERS = 10
NUM_RECENT_SERVERS = 20


def parse_servers(result: Sequence[Tuple[str, str, List[str]]]) -> Dict[str, dict]:
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


def pick_random_server(hostmap=None, protocol='s', exclude_set=None):
    if hostmap is None:
        hostmap = constants.net.DEFAULT_SERVERS
    if exclude_set is None:
        exclude_set = set()
    eligible = list(set(filter_protocol(hostmap, protocol)) - exclude_set)
    return random.choice(eligible) if eligible else None


class NetworkParameters(NamedTuple):
    host: str
    port: str
    protocol: str
    proxy: Optional[dict]
    auto_connect: bool
    oneserver: bool = False


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


class BestEffortRequestFailed(Exception): pass


class TxBroadcastError(Exception):
    def get_message_for_gui(self):
        raise NotImplementedError()


class TxBroadcastHashMismatch(TxBroadcastError):
    def get_message_for_gui(self):
        return "{}\n{}\n\n{}" \
            .format(_("The server returned an unexpected transaction ID when broadcasting the transaction."),
                    _("Consider trying to connect to a different server, or updating Electrum."),
                    str(self))


class TxBroadcastServerReturnedError(TxBroadcastError):
    def get_message_for_gui(self):
        return "{}\n{}\n\n{}" \
            .format(_("The server returned an error when broadcasting the transaction."),
                    _("Consider trying to connect to a different server, or updating Electrum."),
                    str(self))


class TxBroadcastUnknownError(TxBroadcastError):
    def get_message_for_gui(self):
        return "{}\n{}" \
            .format(_("Unknown error when broadcasting the transaction."),
                    _("Consider trying to connect to a different server, or updating Electrum."))


class UntrustedServerReturnedError(Exception):
    def __init__(self, *, original_exception):
        self.original_exception = original_exception

    def __str__(self):
        return _("The server returned an error.")

    def __repr__(self):
        return f"<UntrustedServerReturnedError original_exception: {repr(self.original_exception)}>"


INSTANCE = None


class Network(Logger):
    """The Network class manages a set of connections to remote electrum
    servers, each connected socket is handled by an Interface() object.
    """

    LOGGING_SHORTCUT = 'n'

    def __init__(self, config: SimpleConfig=None):
        global INSTANCE
        INSTANCE = self

        Logger.__init__(self)

        self.asyncio_loop = asyncio.get_event_loop()
        assert self.asyncio_loop.is_running(), "event loop not running"
        self._loop_thread = None  # type: threading.Thread  # set by caller; only used for sanity checks

        if config is None:
            config = {}  # Do not use mutables as default values!
        self.config = SimpleConfig(config) if isinstance(config, dict) else config  # type: SimpleConfig
        blockchain.read_blockchains(self.config)
        self.logger.info(f"blockchains {list(map(lambda b: b.forkpoint, blockchain.blockchains.values()))}")
        self._blockchain_preferred_block = self.config.get('blockchain_preferred_block', None)  # type: Optional[Dict]
        self._blockchain = blockchain.get_best_chain()
        # Server for addresses and transactions
        self.default_server = self.config.get('server', None)
        # Sanitize default server
        if self.default_server:
            try:
                deserialize_server(self.default_server)
            except:
                self.logger.warning('failed to parse server-string; falling back to random.')
                self.default_server = None
        if not self.default_server:
            self.default_server = pick_random_server()

        self.main_taskgroup = None  # type: TaskGroup

        # locks
        self.restart_lock = asyncio.Lock()
        self.bhi_lock = asyncio.Lock()
        self.callback_lock = threading.Lock()
        self.recent_servers_lock = threading.RLock()       # <- re-entrant
        self.interfaces_lock = threading.Lock()            # for mutating/iterating self.interfaces

        self.server_peers = {}  # returned by interface (servers that the main interface knows about)
        self.recent_servers = self._read_recent_servers()  # note: needs self.recent_servers_lock

        self.banner = ''
        self.donation_address = ''
        self.relay_fee = None  # type: Optional[int]
        # callbacks set by the GUI
        self.callbacks = defaultdict(list)      # note: needs self.callback_lock

        dir_path = os.path.join(self.config.path, 'certs')
        util.make_dir(dir_path)

        # retry times
        self.server_retry_time = time.time()
        self.nodes_retry_time = time.time()
        # the main server we are currently communicating with
        self.interface = None  # type: Interface
        # set of servers we have an ongoing connection with
        self.interfaces = {}  # type: Dict[str, Interface]
        self.auto_connect = self.config.get('auto_connect', True)
        self.connecting = set()
        self.server_queue = None
        self.proxy = None

        # Dump network messages (all interfaces).  Set at runtime from the console.
        self.debug = False

        self._set_status('disconnected')

    def run_from_another_thread(self, coro):
        assert self._loop_thread != threading.current_thread(), 'must not be called from network thread'
        fut = asyncio.run_coroutine_threadsafe(coro, self.asyncio_loop)
        return fut.result()

    @staticmethod
    def get_instance() -> Optional["Network"]:
        return INSTANCE

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

    def _read_recent_servers(self):
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
    def _save_recent_servers(self):
        if not self.config.path:
            return
        path = os.path.join(self.config.path, "recent_servers")
        s = json.dumps(self.recent_servers, indent=4, sort_keys=True)
        try:
            with open(path, "w", encoding='utf-8') as f:
                f.write(s)
        except:
            pass

    def get_server_height(self):
        interface = self.interface
        return interface.tip if interface else 0

    async def _server_is_lagging(self):
        sh = self.get_server_height()
        if not sh:
            self.logger.info('no height for main interface')
            return True
        lh = self.get_local_height()
        result = (lh - sh) > 1
        if result:
            self.logger.info(f'{self.default_server} is lagging ({sh} vs {lh})')
        return result

    def _set_status(self, status):
        self.connection_status = status
        self.notify('status')

    def is_connected(self):
        interface = self.interface
        return interface is not None and interface.ready.done()

    def is_connecting(self):
        return self.connection_status == 'connecting'

    async def _request_server_info(self, interface):
        await interface.ready
        session = interface.session

        async def get_banner():
            self.banner = await session.send_request('server.banner')
            self.notify('banner')
        async def get_donation_address():
            addr = await session.send_request('server.donation_address')
            if not bitcoin.is_address(addr):
                if addr:  # ignore empty string
                    self.logger.info(f"invalid donation address from server: {repr(addr)}")
                addr = ''
            self.donation_address = addr
        async def get_server_peers():
            server_peers = await session.send_request('server.peers.subscribe')
            random.shuffle(server_peers)
            max_accepted_peers = len(constants.net.DEFAULT_SERVERS) + NUM_RECENT_SERVERS
            server_peers = server_peers[:max_accepted_peers]
            self.server_peers = parse_servers(server_peers)
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
            await group.spawn(self._request_fee_estimates(interface))

    async def _request_fee_estimates(self, interface):
        session = interface.session
        from .simple_config import FEE_ETA_TARGETS
        self.config.requested_fee_estimates()
        async with TaskGroup() as group:
            histogram_task = await group.spawn(session.send_request('mempool.get_fee_histogram'))
            fee_tasks = []
            for i in FEE_ETA_TARGETS:
                fee_tasks.append((i, await group.spawn(session.send_request('blockchain.estimatefee', [i]))))
        self.config.mempool_fees = histogram = histogram_task.result()
        self.logger.info(f'fee_histogram {histogram}')
        self.notify('fee_histogram')
        fee_estimates_eta = {}
        for nblock_target, task in fee_tasks:
            fee = int(task.result() * COIN)
            fee_estimates_eta[nblock_target] = fee
            if fee < 0: continue
            self.config.update_fee_estimates(nblock_target, fee)
        self.logger.info(f'fee_estimates {fee_estimates_eta}')
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
        return NetworkParameters(host=host,
                                 port=port,
                                 protocol=protocol,
                                 proxy=self.proxy,
                                 auto_connect=self.auto_connect,
                                 oneserver=self.oneserver)

    def get_donation_address(self):
        if self.is_connected():
            return self.donation_address

    def get_interfaces(self) -> List[str]:
        """The list of servers for the connected interfaces."""
        with self.interfaces_lock:
            return list(self.interfaces)

    @with_recent_servers_lock
    def get_servers(self):
        # note: order of sources when adding servers here is crucial!
        # don't let "server_peers" overwrite anything,
        # otherwise main server can eclipse the client
        out = dict()
        # add servers received from main interface
        server_peers = self.server_peers
        if server_peers:
            out.update(filter_version(server_peers.copy()))
        # hardcoded servers
        out.update(constants.net.DEFAULT_SERVERS)
        # add recent servers
        for s in self.recent_servers:
            try:
                host, port, protocol = deserialize_server(s)
            except:
                continue
            if host in out:
                out[host].update({protocol: port})
            else:
                out[host] = {protocol: port}
        # potentially filter out some
        if self.config.get('noonion'):
            out = filter_noonion(out)
        return out

    def _start_interface(self, server: str):
        if server not in self.interfaces and server not in self.connecting:
            if server == self.default_server:
                self.logger.info(f"connecting to {server} as new interface")
                self._set_status('connecting')
            self.connecting.add(server)
            self.server_queue.put(server)

    def _start_random_interface(self):
        with self.interfaces_lock:
            exclude_set = self.disconnected_servers | set(self.interfaces) | self.connecting
        server = pick_random_server(self.get_servers(), self.protocol, exclude_set)
        if server:
            self._start_interface(server)
        return server

    def _set_proxy(self, proxy: Optional[dict]):
        self.proxy = proxy
        # Store these somewhere so we can un-monkey-patch
        if not hasattr(socket, "_getaddrinfo"):
            socket._getaddrinfo = socket.getaddrinfo
        if proxy:
            self.logger.info(f'setting proxy {proxy}')
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
        def needs_dns_resolving(host):
            try:
                ipaddress.ip_address(host)
                return False  # already valid IP
            except ValueError:
                pass  # not an IP
            if str(host) in ('localhost', 'localhost.',):
                return False
            return True
        def resolve_with_dnspython(host):
            addrs = []
            # try IPv6
            try:
                answers = dns.resolver.query(host, dns.rdatatype.AAAA)
                addrs += [str(answer) for answer in answers]
            except dns.exception.DNSException as e:
                pass
            except BaseException as e:
                _logger.info(f'dnspython failed to resolve dns (AAAA) with error: {e}')
            # try IPv4
            try:
                answers = dns.resolver.query(host, dns.rdatatype.A)
                addrs += [str(answer) for answer in answers]
            except dns.exception.DNSException as e:
                # dns failed for some reason, e.g. dns.resolver.NXDOMAIN this is normal.
                # Simply report back failure; except if we already have some results.
                if not addrs:
                    raise socket.gaierror(11001, 'getaddrinfo failed') from e
            except BaseException as e:
                # Possibly internal error in dnspython :( see #4483
                _logger.info(f'dnspython failed to resolve dns (A) with error: {e}')
            if addrs:
                return addrs
            # Fall back to original socket.getaddrinfo to resolve dns.
            return [host]
        addrs = [host]
        if needs_dns_resolving(host):
            addrs = resolve_with_dnspython(host)
        list_of_list_of_socketinfos = [socket._getaddrinfo(addr, *args, **kwargs) for addr in addrs]
        list_of_socketinfos = [item for lst in list_of_list_of_socketinfos for item in lst]
        return list_of_socketinfos

    @log_exceptions
    async def set_parameters(self, net_params: NetworkParameters):
        proxy = net_params.proxy
        proxy_str = serialize_proxy(proxy)
        host, port, protocol = net_params.host, net_params.port, net_params.protocol
        server_str = serialize_server(host, port, protocol)
        # sanitize parameters
        try:
            deserialize_server(serialize_server(host, port, protocol))
            if proxy:
                proxy_modes.index(proxy['mode']) + 1
                int(proxy['port'])
        except:
            return
        self.config.set_key('auto_connect', net_params.auto_connect, False)
        self.config.set_key('oneserver', net_params.oneserver, False)
        self.config.set_key('proxy', proxy_str, False)
        self.config.set_key('server', server_str, True)
        # abort if changes were not allowed by config
        if self.config.get('server') != server_str \
                or self.config.get('proxy') != proxy_str \
                or self.config.get('oneserver') != net_params.oneserver:
            return

        async with self.restart_lock:
            self.auto_connect = net_params.auto_connect
            if self.proxy != proxy or self.protocol != protocol or self.oneserver != net_params.oneserver:
                # Restart the network defaulting to the given server
                await self._stop()
                self.default_server = server_str
                await self._start()
            elif self.default_server != server_str:
                await self.switch_to_interface(server_str)
            else:
                await self.switch_lagging_interface()

    def _set_oneserver(self, oneserver: bool):
        self.num_server = NUM_TARGET_CONNECTED_SERVERS if not oneserver else 0
        self.oneserver = bool(oneserver)

    async def _switch_to_random_interface(self):
        '''Switch to a random connected server other than the current one'''
        servers = self.get_interfaces()    # Those in connected state
        if self.default_server in servers:
            servers.remove(self.default_server)
        if servers:
            await self.switch_to_interface(random.choice(servers))

    async def switch_lagging_interface(self):
        '''If auto_connect and lagging, switch interface'''
        if self.auto_connect and await self._server_is_lagging():
            # switch to one that has the correct header (not height)
            best_header = self.blockchain().read_header(self.get_local_height())
            with self.interfaces_lock: interfaces = list(self.interfaces.values())
            filtered = list(filter(lambda iface: iface.tip_header == best_header, interfaces))
            if filtered:
                chosen_iface = random.choice(filtered)
                await self.switch_to_interface(chosen_iface.server)

    async def switch_unwanted_fork_interface(self):
        """If auto_connect and main interface is not on preferred fork,
        try to switch to preferred fork.
        """
        if not self.auto_connect or not self.interface:
            return
        with self.interfaces_lock: interfaces = list(self.interfaces.values())
        # try to switch to preferred fork
        if self._blockchain_preferred_block:
            pref_height = self._blockchain_preferred_block['height']
            pref_hash   = self._blockchain_preferred_block['hash']
            if self.interface.blockchain.check_hash(pref_height, pref_hash):
                return  # already on preferred fork
            filtered = list(filter(lambda iface: iface.blockchain.check_hash(pref_height, pref_hash),
                                   interfaces))
            if filtered:
                self.logger.info("switching to preferred fork")
                chosen_iface = random.choice(filtered)
                await self.switch_to_interface(chosen_iface.server)
                return
            else:
                self.logger.info("tried to switch to preferred fork but no interfaces are on it")
        # try to switch to best chain
        if self.blockchain().parent is None:
            return  # already on best chain
        filtered = list(filter(lambda iface: iface.blockchain.parent is None,
                               interfaces))
        if filtered:
            self.logger.info("switching to best chain")
            chosen_iface = random.choice(filtered)
            await self.switch_to_interface(chosen_iface.server)
        else:
            # FIXME switch to best available?
            self.logger.info("tried to switch to best chain but no interfaces are on it")

    async def switch_to_interface(self, server: str):
        """Switch to server as our main interface. If no connection exists,
        queue interface to be started. The actual switch will
        happen when the interface becomes ready.
        """
        self.default_server = server
        old_interface = self.interface
        old_server = old_interface.server if old_interface else None

        # Stop any current interface in order to terminate subscriptions,
        # and to cancel tasks in interface.group.
        # However, for headers sub, give preference to this interface
        # over unknown ones, i.e. start it again right away.
        if old_server and old_server != server:
            await self._close_interface(old_interface)
            if len(self.interfaces) <= self.num_server:
                self._start_interface(old_server)

        if server not in self.interfaces:
            self.interface = None
            self._start_interface(server)
            return

        i = self.interfaces[server]
        if old_interface != i:
            self.logger.info(f"switching to {server}")
            blockchain_updated = i.blockchain != self.blockchain()
            self.interface = i
            await i.group.spawn(self._request_server_info(i))
            self.trigger_callback('default_server_changed')
            self._set_status('connected')
            self.trigger_callback('network_updated')
            if blockchain_updated: self.trigger_callback('blockchain_updated')

    async def _close_interface(self, interface):
        if interface:
            with self.interfaces_lock:
                if self.interfaces.get(interface.server) == interface:
                    self.interfaces.pop(interface.server)
            if interface.server == self.default_server:
                self.interface = None
            await interface.close()

    @with_recent_servers_lock
    def _add_recent_server(self, server):
        # list is ordered
        if server in self.recent_servers:
            self.recent_servers.remove(server)
        self.recent_servers.insert(0, server)
        self.recent_servers = self.recent_servers[:NUM_RECENT_SERVERS]
        self._save_recent_servers()

    async def connection_down(self, interface: Interface):
        '''A connection to server either went down, or was never made.
        We distinguish by whether it is in self.interfaces.'''
        if not interface: return
        server = interface.server
        self.disconnected_servers.add(server)
        if server == self.default_server:
            self._set_status('disconnected')
        await self._close_interface(interface)
        self.trigger_callback('network_updated')

    def get_network_timeout_seconds(self, request_type=NetworkTimeout.Generic) -> int:
        if self.oneserver and not self.auto_connect:
            return request_type.MOST_RELAXED
        if self.proxy:
            return request_type.RELAXED
        return request_type.NORMAL

    @ignore_exceptions  # do not kill main_taskgroup
    @log_exceptions
    async def _run_new_interface(self, server):
        interface = Interface(self, server, self.proxy)
        # note: using longer timeouts here as DNS can sometimes be slow!
        timeout = self.get_network_timeout_seconds(NetworkTimeout.Generic)
        try:
            await asyncio.wait_for(interface.ready, timeout)
        except BaseException as e:
            self.logger.info(f"couldn't launch iface {server} -- {repr(e)}")
            await interface.close()
            return
        else:
            with self.interfaces_lock:
                assert server not in self.interfaces
                self.interfaces[server] = interface
        finally:
            try: self.connecting.remove(server)
            except KeyError: pass

        if server == self.default_server:
            await self.switch_to_interface(server)

        self._add_recent_server(server)
        self.trigger_callback('network_updated')

    def check_interface_against_healthy_spread_of_connected_servers(self, iface_to_check) -> bool:
        # main interface is exempt. this makes switching servers easier
        if iface_to_check.is_main_server():
            return True
        if not iface_to_check.bucket_based_on_ipaddress():
            return True
        # bucket connected interfaces
        with self.interfaces_lock:
            interfaces = list(self.interfaces.values())
        if iface_to_check in interfaces:
            interfaces.remove(iface_to_check)
        buckets = defaultdict(list)
        for iface in interfaces:
            buckets[iface.bucket_based_on_ipaddress()].append(iface)
        # check proposed server against buckets
        onion_servers = buckets[BUCKET_NAME_OF_ONION_SERVERS]
        if iface_to_check.is_tor():
            # keep number of onion servers below half of all connected servers
            if len(onion_servers) > NUM_TARGET_CONNECTED_SERVERS // 2:
                return False
        else:
            bucket = iface_to_check.bucket_based_on_ipaddress()
            if len(buckets[bucket]) > 0:
                return False
        return True

    async def _init_headers_file(self):
        b = blockchain.get_best_chain()
        filename = b.path()
        length = HEADER_SIZE * len(constants.net.CHECKPOINTS) * 2016
        if not os.path.exists(filename) or os.path.getsize(filename) < length:
            with open(filename, 'wb') as f:
                if length > 0:
                    f.seek(length-1)
                    f.write(b'\x00')
            util.ensure_sparse_file(filename)
        with b.lock:
            b.update_size()

    def best_effort_reliable(func):
        async def make_reliable_wrapper(self, *args, **kwargs):
            for i in range(10):
                iface = self.interface
                # retry until there is a main interface
                if not iface:
                    await asyncio.sleep(0.1)
                    continue  # try again
                # wait for it to be usable
                iface_ready = iface.ready
                iface_disconnected = iface.got_disconnected
                await asyncio.wait([iface_ready, iface_disconnected], return_when=asyncio.FIRST_COMPLETED)
                if not iface_ready.done() or iface_ready.cancelled():
                    await asyncio.sleep(0.1)
                    continue  # try again
                # try actual request
                success_fut = asyncio.ensure_future(func(self, *args, **kwargs))
                await asyncio.wait([success_fut, iface_disconnected], return_when=asyncio.FIRST_COMPLETED)
                if success_fut.done() and not success_fut.cancelled():
                    if success_fut.exception():
                        try:
                            raise success_fut.exception()
                        except RequestTimedOut:
                            await iface.close()
                            await iface_disconnected
                            continue  # try again
                    return success_fut.result()
                # otherwise; try again
            raise BestEffortRequestFailed('no interface to do request on... gave up.')
        return make_reliable_wrapper

    def catch_server_exceptions(func):
        async def wrapper(self, *args, **kwargs):
            try:
                return await func(self, *args, **kwargs)
            except aiorpcx.jsonrpc.CodeMessageError as e:
                raise UntrustedServerReturnedError(original_exception=e) from e
        return wrapper

    @best_effort_reliable
    @catch_server_exceptions
    async def get_merkle_for_transaction(self, tx_hash: str, tx_height: int) -> dict:
        if not is_hash256_str(tx_hash):
            raise Exception(f"{repr(tx_hash)} is not a txid")
        if not is_non_negative_integer(tx_height):
            raise Exception(f"{repr(tx_height)} is not a block height")
        return await self.interface.session.send_request('blockchain.transaction.get_merkle', [tx_hash, tx_height])

    @best_effort_reliable
    async def broadcast_transaction(self, tx, *, timeout=None) -> None:
        if timeout is None:
            timeout = self.get_network_timeout_seconds(NetworkTimeout.Urgent)
        try:
            out = await self.interface.session.send_request('blockchain.transaction.broadcast', [str(tx)], timeout=timeout)
            # note: both 'out' and exception messages are untrusted input from the server
        except (RequestTimedOut, asyncio.CancelledError, asyncio.TimeoutError):
            raise  # pass-through
        except aiorpcx.jsonrpc.CodeMessageError as e:
            self.logger.info(f"broadcast_transaction error [DO NOT TRUST THIS MESSAGE]: {repr(e)}")
            raise TxBroadcastServerReturnedError(self.sanitize_tx_broadcast_response(e.message)) from e
        except BaseException as e:  # intentional BaseException for sanity!
            self.logger.info(f"broadcast_transaction error2 [DO NOT TRUST THIS MESSAGE]: {repr(e)}")
            send_exception_to_crash_reporter(e)
            raise TxBroadcastUnknownError() from e
        if out != tx.txid():
            self.logger.info(f"unexpected txid for broadcast_transaction [DO NOT TRUST THIS MESSAGE]: {out} != {tx.txid()}")
            raise TxBroadcastHashMismatch(_("Server returned unexpected transaction ID."))

    @staticmethod
    def sanitize_tx_broadcast_response(server_msg) -> str:
        # Unfortunately, bitcoind and hence the Electrum protocol doesn't return a useful error code.
        # So, we use substring matching to grok the error message.
        # server_msg is untrusted input so it should not be shown to the user. see #4968
        server_msg = str(server_msg)
        server_msg = server_msg.replace("\n", r"\n")
        # https://github.com/bitcoin/bitcoin/blob/cd42553b1178a48a16017eff0b70669c84c3895c/src/policy/policy.cpp
        # grep "reason ="
        policy_error_messages = {
            r"version": _("Transaction uses non-standard version."),
            r"tx-size": _("The transaction was rejected because it is too large (in bytes)."),
            r"scriptsig-size": None,
            r"scriptsig-not-pushonly": None,
            r"scriptpubkey": None,
            r"bare-multisig": None,
            r"dust": _("Transaction could not be broadcast due to dust outputs."),
            r"multi-op-return": _("The transaction was rejected because it contains multiple OP_RETURN outputs."),
        }
        for substring in policy_error_messages:
            if substring in server_msg:
                msg = policy_error_messages[substring]
                return msg if msg else substring
        # https://github.com/bitcoin/bitcoin/blob/cd42553b1178a48a16017eff0b70669c84c3895c/src/script/script_error.cpp
        script_error_messages = {
            r"Script evaluated without error but finished with a false/empty top stack element",
            r"Script failed an OP_VERIFY operation",
            r"Script failed an OP_EQUALVERIFY operation",
            r"Script failed an OP_CHECKMULTISIGVERIFY operation",
            r"Script failed an OP_CHECKSIGVERIFY operation",
            r"Script failed an OP_NUMEQUALVERIFY operation",
            r"Script is too big",
            r"Push value size limit exceeded",
            r"Operation limit exceeded",
            r"Stack size limit exceeded",
            r"Signature count negative or greater than pubkey count",
            r"Pubkey count negative or limit exceeded",
            r"Opcode missing or not understood",
            r"Attempted to use a disabled opcode",
            r"Operation not valid with the current stack size",
            r"Operation not valid with the current altstack size",
            r"OP_RETURN was encountered",
            r"Invalid OP_IF construction",
            r"Negative locktime",
            r"Locktime requirement not satisfied",
            r"Signature hash type missing or not understood",
            r"Non-canonical DER signature",
            r"Data push larger than necessary",
            r"Only non-push operators allowed in signatures",
            r"Non-canonical signature: S value is unnecessarily high",
            r"Dummy CHECKMULTISIG argument must be zero",
            r"OP_IF/NOTIF argument must be minimal",
            r"Signature must be zero for failed CHECK(MULTI)SIG operation",
            r"NOPx reserved for soft-fork upgrades",
            r"Witness version reserved for soft-fork upgrades",
            r"Public key is neither compressed or uncompressed",
            r"Extra items left on stack after execution",
            r"Witness program has incorrect length",
            r"Witness program was passed an empty witness",
            r"Witness program hash mismatch",
            r"Witness requires empty scriptSig",
            r"Witness requires only-redeemscript scriptSig",
            r"Witness provided for non-witness script",
            r"Using non-compressed keys in segwit",
            r"Using OP_CODESEPARATOR in non-witness script",
            r"Signature is found in scriptCode",
        }
        for substring in script_error_messages:
            if substring in server_msg:
                return substring
        # https://github.com/bitcoin/bitcoin/blob/cd42553b1178a48a16017eff0b70669c84c3895c/src/validation.cpp
        # grep "REJECT_"
        # should come after script_error.cpp (due to e.g. non-mandatory-script-verify-flag)
        validation_error_messages = {
            r"coinbase",
            r"tx-size-small",
            r"non-final",
            r"txn-already-in-mempool",
            r"txn-mempool-conflict",
            r"txn-already-known",
            r"non-BIP68-final",
            r"bad-txns-nonstandard-inputs",
            r"bad-witness-nonstandard",
            r"bad-txns-too-many-sigops",
            r"mempool min fee not met",
            r"min relay fee not met",
            r"absurdly-high-fee",
            r"too-long-mempool-chain",
            r"bad-txns-spends-conflicting-tx",
            r"insufficient fee",
            r"too many potential replacements",
            r"replacement-adds-unconfirmed",
            r"mempool full",
            r"non-mandatory-script-verify-flag",
            r"mandatory-script-verify-flag-failed",
        }
        for substring in validation_error_messages:
            if substring in server_msg:
                return substring
        # https://github.com/bitcoin/bitcoin/blob/cd42553b1178a48a16017eff0b70669c84c3895c/src/rpc/rawtransaction.cpp
        # grep "RPC_TRANSACTION"
        # grep "RPC_DESERIALIZATION_ERROR"
        # https://github.com/bitcoin/bitcoin/blob/d7d7d315060620446bd363ca50f95f79d3260db7/src/util/error.cpp
        rawtransaction_error_messages = {
            r"Missing inputs",
            r"transaction already in block chain",
            r"Transaction already in block chain",
            r"TX decode failed",
            r"Peer-to-peer functionality missing or disabled",
            r"Transaction rejected by AcceptToMemoryPool",
            r"AcceptToMemoryPool failed",
        }
        for substring in rawtransaction_error_messages:
            if substring in server_msg:
                return substring
        # https://github.com/bitcoin/bitcoin/blob/cd42553b1178a48a16017eff0b70669c84c3895c/src/consensus/tx_verify.cpp
        # grep "REJECT_"
        tx_verify_error_messages = {
            r"bad-txns-vin-empty",
            r"bad-txns-vout-empty",
            r"bad-txns-oversize",
            r"bad-txns-vout-negative",
            r"bad-txns-vout-toolarge",
            r"bad-txns-txouttotal-toolarge",
            r"bad-txns-inputs-duplicate",
            r"bad-cb-length",
            r"bad-txns-prevout-null",
            r"bad-txns-inputs-missingorspent",
            r"bad-txns-premature-spend-of-coinbase",
            r"bad-txns-inputvalues-outofrange",
            r"bad-txns-in-belowout",
            r"bad-txns-fee-outofrange",
        }
        for substring in tx_verify_error_messages:
            if substring in server_msg:
                return substring
        # otherwise:
        return _("Unknown error")

    @best_effort_reliable
    @catch_server_exceptions
    async def request_chunk(self, height: int, tip=None, *, can_return_early=False):
        if not is_non_negative_integer(height):
            raise Exception(f"{repr(height)} is not a block height")
        return await self.interface.request_chunk(height, tip=tip, can_return_early=can_return_early)

    @best_effort_reliable
    @catch_server_exceptions
    async def get_transaction(self, tx_hash: str, *, timeout=None) -> str:
        if not is_hash256_str(tx_hash):
            raise Exception(f"{repr(tx_hash)} is not a txid")
        return await self.interface.session.send_request('blockchain.transaction.get', [tx_hash],
                                                         timeout=timeout)

    @best_effort_reliable
    @catch_server_exceptions
    async def get_history_for_scripthash(self, sh: str) -> List[dict]:
        if not is_hash256_str(sh):
            raise Exception(f"{repr(sh)} is not a scripthash")
        return await self.interface.session.send_request('blockchain.scripthash.get_history', [sh])

    @best_effort_reliable
    @catch_server_exceptions
    async def listunspent_for_scripthash(self, sh: str) -> List[dict]:
        if not is_hash256_str(sh):
            raise Exception(f"{repr(sh)} is not a scripthash")
        return await self.interface.session.send_request('blockchain.scripthash.listunspent', [sh])

    @best_effort_reliable
    @catch_server_exceptions
    async def get_balance_for_scripthash(self, sh: str) -> dict:
        if not is_hash256_str(sh):
            raise Exception(f"{repr(sh)} is not a scripthash")
        return await self.interface.session.send_request('blockchain.scripthash.get_balance', [sh])

    def blockchain(self) -> Blockchain:
        interface = self.interface
        if interface and interface.blockchain is not None:
            self._blockchain = interface.blockchain
        return self._blockchain

    def get_blockchains(self):
        out = {}  # blockchain_id -> list(interfaces)
        with blockchain.blockchains_lock: blockchain_items = list(blockchain.blockchains.items())
        with self.interfaces_lock: interfaces_values = list(self.interfaces.values())
        for chain_id, bc in blockchain_items:
            r = list(filter(lambda i: i.blockchain==bc, interfaces_values))
            if r:
                out[chain_id] = r
        return out

    def _set_preferred_chain(self, chain: Blockchain):
        height = chain.get_max_forkpoint()
        header_hash = chain.get_hash(height)
        self._blockchain_preferred_block = {
            'height': height,
            'hash': header_hash,
        }
        self.config.set_key('blockchain_preferred_block', self._blockchain_preferred_block)

    async def follow_chain_given_id(self, chain_id: str) -> None:
        bc = blockchain.blockchains.get(chain_id)
        if not bc:
            raise Exception('blockchain {} not found'.format(chain_id))
        self._set_preferred_chain(bc)
        # select server on this chain
        with self.interfaces_lock: interfaces = list(self.interfaces.values())
        interfaces_on_selected_chain = list(filter(lambda iface: iface.blockchain == bc, interfaces))
        if len(interfaces_on_selected_chain) == 0: return
        chosen_iface = random.choice(interfaces_on_selected_chain)
        # switch to server (and save to config)
        net_params = self.get_parameters()
        host, port, protocol = deserialize_server(chosen_iface.server)
        net_params = net_params._replace(host=host, port=port, protocol=protocol)
        await self.set_parameters(net_params)

    async def follow_chain_given_server(self, server_str: str) -> None:
        # note that server_str should correspond to a connected interface
        iface = self.interfaces.get(server_str)
        if iface is None:
            return
        self._set_preferred_chain(iface.blockchain)
        # switch to server (and save to config)
        net_params = self.get_parameters()
        host, port, protocol = deserialize_server(server_str)
        net_params = net_params._replace(host=host, port=port, protocol=protocol)
        await self.set_parameters(net_params)

    def get_local_height(self):
        return self.blockchain().height()

    def export_checkpoints(self, path):
        """Run manually to generate blockchain checkpoints.
        Kept for console use only.
        """
        cp = self.blockchain().get_checkpoints()
        with open(path, 'w', encoding='utf-8') as f:
            f.write(json.dumps(cp, indent=4))

    async def _start(self):
        assert not self.main_taskgroup
        self.main_taskgroup = main_taskgroup = SilentTaskGroup()
        assert not self.interface and not self.interfaces
        assert not self.connecting and not self.server_queue
        self.logger.info('starting network')
        self.disconnected_servers = set([])
        self.protocol = deserialize_server(self.default_server)[2]
        self.server_queue = queue.Queue()
        self._set_proxy(deserialize_proxy(self.config.get('proxy')))
        self._set_oneserver(self.config.get('oneserver', False))
        self._start_interface(self.default_server)

        async def main():
            try:
                await self._init_headers_file()
                # note: if a task finishes with CancelledError, that
                # will NOT raise, and the group will keep the other tasks running
                async with main_taskgroup as group:
                    await group.spawn(self._maintain_sessions())
                    [await group.spawn(job) for job in self._jobs]
            except Exception as e:
                self.logger.exception('')
                raise e
        asyncio.run_coroutine_threadsafe(main(), self.asyncio_loop)

        self.trigger_callback('network_updated')

    def start(self, jobs: List=None):
        self._jobs = jobs or []
        asyncio.run_coroutine_threadsafe(self._start(), self.asyncio_loop)

    @log_exceptions
    async def _stop(self, full_shutdown=False):
        self.logger.info("stopping network")
        try:
            await asyncio.wait_for(self.main_taskgroup.cancel_remaining(), timeout=2)
        except (asyncio.TimeoutError, asyncio.CancelledError) as e:
            self.logger.info(f"exc during main_taskgroup cancellation: {repr(e)}")
        self.main_taskgroup = None  # type: TaskGroup
        self.interface = None  # type: Interface
        self.interfaces = {}  # type: Dict[str, Interface]
        self.connecting.clear()
        self.server_queue = None
        if not full_shutdown:
            self.trigger_callback('network_updated')

    def stop(self):
        assert self._loop_thread != threading.current_thread(), 'must not be called from network thread'
        fut = asyncio.run_coroutine_threadsafe(self._stop(full_shutdown=True), self.asyncio_loop)
        try:
            fut.result(timeout=2)
        except (asyncio.TimeoutError, asyncio.CancelledError): pass

    async def _ensure_there_is_a_main_interface(self):
        if self.is_connected():
            return
        now = time.time()
        # if auto_connect is set, try a different server
        if self.auto_connect and not self.is_connecting():
            await self._switch_to_random_interface()
        # if auto_connect is not set, or still no main interface, retry current
        if not self.is_connected() and not self.is_connecting():
            if self.default_server in self.disconnected_servers:
                if now - self.server_retry_time > SERVER_RETRY_INTERVAL:
                    self.disconnected_servers.remove(self.default_server)
                    self.server_retry_time = now
            else:
                await self.switch_to_interface(self.default_server)

    async def _maintain_sessions(self):
        async def launch_already_queued_up_new_interfaces():
            while self.server_queue.qsize() > 0:
                server = self.server_queue.get()
                await self.main_taskgroup.spawn(self._run_new_interface(server))
        async def maybe_queue_new_interfaces_to_be_launched_later():
            now = time.time()
            for i in range(self.num_server - len(self.interfaces) - len(self.connecting)):
                # FIXME this should try to honour "healthy spread of connected servers"
                self._start_random_interface()
            if now - self.nodes_retry_time > NODES_RETRY_INTERVAL:
                self.logger.info('network: retrying connections')
                self.disconnected_servers = set([])
                self.nodes_retry_time = now
        async def maintain_healthy_spread_of_connected_servers():
            with self.interfaces_lock: interfaces = list(self.interfaces.values())
            random.shuffle(interfaces)
            for iface in interfaces:
                if not self.check_interface_against_healthy_spread_of_connected_servers(iface):
                    self.logger.info(f"disconnecting from {iface.server}. too many connected "
                                     f"servers already in bucket {iface.bucket_based_on_ipaddress()}")
                    await self._close_interface(iface)
        async def maintain_main_interface():
            await self._ensure_there_is_a_main_interface()
            if self.is_connected():
                if self.config.is_fee_estimates_update_required():
                    await self.interface.group.spawn(self._request_fee_estimates, self.interface)

        while True:
            try:
                await launch_already_queued_up_new_interfaces()
                await maybe_queue_new_interfaces_to_be_launched_later()
                await maintain_healthy_spread_of_connected_servers()
                await maintain_main_interface()
            except asyncio.CancelledError:
                # suppress spurious cancellations
                group = self.main_taskgroup
                if not group or group._closed:
                    raise
            await asyncio.sleep(0.1)

    @classmethod
    async def _send_http_on_proxy(cls, method: str, url: str, params: str = None,
                                  body: bytes = None, json: dict = None, headers=None,
                                  on_finish=None, timeout=None):
        async def default_on_finish(resp: ClientResponse):
            resp.raise_for_status()
            return await resp.text()
        if headers is None:
            headers = {}
        if on_finish is None:
            on_finish = default_on_finish
        network = cls.get_instance()
        proxy = network.proxy if network else None
        async with make_aiohttp_session(proxy, timeout=timeout) as session:
            if method == 'get':
                async with session.get(url, params=params, headers=headers) as resp:
                    return await on_finish(resp)
            elif method == 'post':
                assert body is not None or json is not None, 'body or json must be supplied if method is post'
                if body is not None:
                    async with session.post(url, data=body, headers=headers) as resp:
                        return await on_finish(resp)
                elif json is not None:
                    async with session.post(url, json=json, headers=headers) as resp:
                        return await on_finish(resp)
            else:
                assert False

    @classmethod
    def send_http_on_proxy(cls, method, url, **kwargs):
        network = cls.get_instance()
        if network:
            assert network._loop_thread is not threading.currentThread()
            loop = network.asyncio_loop
        else:
            loop = asyncio.get_event_loop()
        coro = asyncio.run_coroutine_threadsafe(cls._send_http_on_proxy(method, url, **kwargs), loop)
        # note: _send_http_on_proxy has its own timeout, so no timeout here:
        return coro.result()

    # methods used in scripts
    async def get_peers(self):
        while not self.is_connected():
            await asyncio.sleep(1)
        session = self.interface.session
        return parse_servers(await session.send_request('server.peers.subscribe'))

    async def send_multiple_requests(self, servers: List[str], method: str, params: Sequence):
        responses = dict()
        async def get_response(server):
            interface = Interface(self, server, self.proxy)
            timeout = self.get_network_timeout_seconds(NetworkTimeout.Urgent)
            try:
                await asyncio.wait_for(interface.ready, timeout)
            except BaseException as e:
                await interface.close()
                return
            try:
                res = await interface.session.send_request(method, params, timeout=10)
            except Exception as e:
                res = e
            responses[interface.server] = res
        async with TaskGroup() as group:
            for server in servers:
                await group.spawn(get_response(server))
        return responses
