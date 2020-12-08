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
import asyncio
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
import asyncio
from typing import NamedTuple, Optional, Sequence, List, Dict, Tuple, TYPE_CHECKING, Iterable, Set, Any
import traceback
import concurrent
from concurrent import futures

import aiorpcx
from aiorpcx import TaskGroup
from aiohttp import ClientResponse

from . import util
from .util import (log_exceptions, ignore_exceptions,
                   bfh, SilentTaskGroup, make_aiohttp_session, send_exception_to_crash_reporter,
                   is_hash256_str, is_non_negative_integer, MyEncoder, NetworkRetryManager)

from .bitcoin import COIN
from . import constants
from . import blockchain
from . import bitcoin
from . import dns_hacks
from .transaction import Transaction
from .blockchain import Blockchain, HEADER_SIZE
from .interface import (Interface, PREFERRED_NETWORK_PROTOCOL,
                        RequestTimedOut, NetworkTimeout, BUCKET_NAME_OF_ONION_SERVERS,
                        NetworkException, RequestCorrupted, ServerAddr)
from .version import PROTOCOL_VERSION
from .simple_config import SimpleConfig
from .i18n import _
from .logging import get_logger, Logger

if TYPE_CHECKING:
    from .channel_db import ChannelDB
    from .lnworker import LNGossip
    from .lnwatcher import WatchTower
    from .daemon import Daemon


_logger = get_logger(__name__)


NUM_TARGET_CONNECTED_SERVERS = 10
NUM_STICKY_SERVERS = 4
NUM_RECENT_SERVERS = 20


def parse_servers(result: Sequence[Tuple[str, str, List[str]]]) -> Dict[str, dict]:
    """Convert servers list (from protocol method "server.peers.subscribe") into dict format.
    Also validate values, such as IP addresses and ports.
    """
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
                    ServerAddr(host, port, protocol=protocol)  # check if raises
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


def filter_protocol(hostmap, *, allowed_protocols: Iterable[str] = None) -> Sequence[ServerAddr]:
    """Filters the hostmap for those implementing protocol."""
    if allowed_protocols is None:
        allowed_protocols = {PREFERRED_NETWORK_PROTOCOL}
    eligible = []
    for host, portmap in hostmap.items():
        for protocol in allowed_protocols:
            port = portmap.get(protocol)
            if port:
                eligible.append(ServerAddr(host, port, protocol=protocol))
    return eligible


def pick_random_server(hostmap=None, *, allowed_protocols: Iterable[str],
                       exclude_set: Set[ServerAddr] = None) -> Optional[ServerAddr]:
    if hostmap is None:
        hostmap = constants.net.DEFAULT_SERVERS
    if exclude_set is None:
        exclude_set = set()
    servers = set(filter_protocol(hostmap, allowed_protocols=allowed_protocols))
    eligible = list(servers - exclude_set)
    return random.choice(eligible) if eligible else None


class NetworkParameters(NamedTuple):
    server: ServerAddr
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


class BestEffortRequestFailed(NetworkException): pass


class TxBroadcastError(NetworkException):
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


class UntrustedServerReturnedError(NetworkException):
    def __init__(self, *, original_exception):
        self.original_exception = original_exception

    def get_message_for_gui(self) -> str:
        return str(self)

    def __str__(self):
        return _("The server returned an error.")

    def __repr__(self):
        return (f"<UntrustedServerReturnedError "
                f"[DO NOT TRUST THIS MESSAGE] original_exception: {repr(self.original_exception)}>")


_INSTANCE = None


class Network(Logger, NetworkRetryManager[ServerAddr]):
    """The Network class manages a set of connections to remote electrum
    servers, each connected socket is handled by an Interface() object.
    """

    LOGGING_SHORTCUT = 'n'

    taskgroup: Optional[TaskGroup]
    interface: Optional[Interface]
    interfaces: Dict[ServerAddr, Interface]
    _connecting: Set[ServerAddr]
    default_server: ServerAddr
    _recent_servers: List[ServerAddr]

    def __init__(self, config: SimpleConfig, *, daemon: 'Daemon' = None):
        global _INSTANCE
        assert _INSTANCE is None, "Network is a singleton!"
        _INSTANCE = self

        Logger.__init__(self)
        NetworkRetryManager.__init__(
            self,
            max_retry_delay_normal=600,
            init_retry_delay_normal=15,
            max_retry_delay_urgent=10,
            init_retry_delay_urgent=1,
        )

        self.asyncio_loop = asyncio.get_event_loop()
        assert self.asyncio_loop.is_running(), "event loop not running"
        try:
            self._loop_thread = self.asyncio_loop._mythread  # type: threading.Thread  # only used for sanity checks
        except AttributeError as e:
            self.logger.warning(f"asyncio loop does not have _mythread set: {e!r}")
            self._loop_thread = None

        assert isinstance(config, SimpleConfig), f"config should be a SimpleConfig instead of {type(config)}"
        self.config = config

        self.daemon = daemon

        blockchain.read_blockchains(self.config)
        blockchain.init_headers_file_for_best_chain()
        self.logger.info(f"blockchains {list(map(lambda b: b.forkpoint, blockchain.blockchains.values()))}")
        self._blockchain_preferred_block = self.config.get('blockchain_preferred_block', None)  # type: Dict[str, Any]
        if self._blockchain_preferred_block is None:
            self._set_preferred_chain(None)
        self._blockchain = blockchain.get_best_chain()

        self._allowed_protocols = {PREFERRED_NETWORK_PROTOCOL}

        # Server for addresses and transactions
        self.default_server = self.config.get('server', None)
        # Sanitize default server
        if self.default_server:
            try:
                self.default_server = ServerAddr.from_str(self.default_server)
            except:
                self.logger.warning('failed to parse server-string; falling back to localhost:1:s.')
                self.default_server = ServerAddr.from_str("localhost:1:s")
        else:
            self.default_server = pick_random_server(allowed_protocols=self._allowed_protocols)
        assert isinstance(self.default_server, ServerAddr), f"invalid type for default_server: {self.default_server!r}"

        self.taskgroup = None

        # locks
        self.restart_lock = asyncio.Lock()
        self.bhi_lock = asyncio.Lock()
        self.recent_servers_lock = threading.RLock()       # <- re-entrant
        self.interfaces_lock = threading.Lock()            # for mutating/iterating self.interfaces

        self.server_peers = {}  # returned by interface (servers that the main interface knows about)
        self._recent_servers = self._read_recent_servers()  # note: needs self.recent_servers_lock

        self.banner = ''
        self.donation_address = ''
        self.relay_fee = None  # type: Optional[int]

        dir_path = os.path.join(self.config.path, 'certs')
        util.make_dir(dir_path)

        # the main server we are currently communicating with
        self.interface = None
        self.default_server_changed_event = asyncio.Event()
        # set of servers we have an ongoing connection with
        self.interfaces = {}
        self.auto_connect = self.config.get('auto_connect', True)
        self._connecting = set()
        self.proxy = None
        self._maybe_set_oneserver()

        # Dump network messages (all interfaces).  Set at runtime from the console.
        self.debug = False

        self._set_status('disconnected')
        self._has_ever_managed_to_connect_to_server = False

        # lightning network
        self.channel_db = None  # type: Optional[ChannelDB]
        self.lngossip = None  # type: Optional[LNGossip]
        self.local_watchtower = None  # type: Optional[WatchTower]
        if self.config.get('run_local_watchtower', False):
            from . import lnwatcher
            self.local_watchtower = lnwatcher.WatchTower(self)
            self.local_watchtower.start_network(self)
            asyncio.ensure_future(self.local_watchtower.start_watching())

    def has_internet_connection(self) -> bool:
        """Our guess whether the device has Internet-connectivity."""
        return self._has_ever_managed_to_connect_to_server

    def has_channel_db(self):
        return self.channel_db is not None

    def init_channel_db(self):
        if self.channel_db is None:
            from . import lnrouter
            from . import channel_db
            self.channel_db = channel_db.ChannelDB(self)
            self.path_finder = lnrouter.LNPathFinder(self.channel_db)
            self.channel_db.load_data()

    def start_gossip(self):
        if self.lngossip is None:
            from . import lnworker
            self.lngossip = lnworker.LNGossip()
            self.lngossip.start_network(self)

    def stop_gossip(self):
        self.lngossip.stop()

    def run_from_another_thread(self, coro, *, timeout=None):
        assert self._loop_thread != threading.current_thread(), 'must not be called from network thread'
        fut = asyncio.run_coroutine_threadsafe(coro, self.asyncio_loop)
        return fut.result(timeout)

    @staticmethod
    def get_instance() -> Optional["Network"]:
        return _INSTANCE

    def with_recent_servers_lock(func):
        def func_wrapper(self, *args, **kwargs):
            with self.recent_servers_lock:
                return func(self, *args, **kwargs)
        return func_wrapper

    def _read_recent_servers(self) -> List[ServerAddr]:
        if not self.config.path:
            return []
        path = os.path.join(self.config.path, "recent_servers")
        try:
            with open(path, "r", encoding='utf-8') as f:
                data = f.read()
                servers_list = json.loads(data)
            return [ServerAddr.from_str(s) for s in servers_list]
        except:
            return []

    @with_recent_servers_lock
    def _save_recent_servers(self):
        if not self.config.path:
            return
        path = os.path.join(self.config.path, "recent_servers")
        s = json.dumps(self._recent_servers, indent=4, sort_keys=True, cls=MyEncoder)
        try:
            with open(path, "w", encoding='utf-8') as f:
                f.write(s)
        except:
            pass

    async def _server_is_lagging(self) -> bool:
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

    async def _request_server_info(self, interface: 'Interface'):
        await interface.ready
        session = interface.session

        async def get_banner():
            self.banner = await interface.get_server_banner()
            self.notify('banner')
        async def get_donation_address():
            self.donation_address = await interface.get_donation_address()
        async def get_server_peers():
            server_peers = await session.send_request('server.peers.subscribe')
            random.shuffle(server_peers)
            max_accepted_peers = len(constants.net.DEFAULT_SERVERS) + NUM_RECENT_SERVERS
            server_peers = server_peers[:max_accepted_peers]
            # note that 'parse_servers' also validates the data (which is untrusted input!)
            self.server_peers = parse_servers(server_peers)
            self.notify('servers')
        async def get_relay_fee():
            self.relay_fee = await interface.get_relay_fee()

        async with TaskGroup() as group:
            await group.spawn(get_banner)
            await group.spawn(get_donation_address)
            await group.spawn(get_server_peers)
            await group.spawn(get_relay_fee)
            await group.spawn(self._request_fee_estimates(interface))

    async def _request_fee_estimates(self, interface):
        self.config.requested_fee_estimates()
        histogram = await interface.get_fee_histogram()
        self.config.mempool_fees = histogram
        self.logger.info(f'fee_histogram {histogram}')
        self.notify('fee_histogram')

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
            util.trigger_callback(key)
        else:
            util.trigger_callback(key, self.get_status_value(key))

    def get_parameters(self) -> NetworkParameters:
        return NetworkParameters(server=self.default_server,
                                 proxy=self.proxy,
                                 auto_connect=self.auto_connect,
                                 oneserver=self.oneserver)

    def get_donation_address(self):
        if self.is_connected():
            return self.donation_address

    def get_interfaces(self) -> List[ServerAddr]:
        """The list of servers for the connected interfaces."""
        with self.interfaces_lock:
            return list(self.interfaces)

    def get_fee_estimates(self):
        from statistics import median
        from .simple_config import FEE_ETA_TARGETS
        if self.auto_connect:
            with self.interfaces_lock:
                out = {}
                for n in FEE_ETA_TARGETS:
                    try:
                        out[n] = int(median(filter(None, [i.fee_estimates_eta.get(n) for i in self.interfaces.values()])))
                    except:
                        continue
                return out
        else:
            if not self.interface:
                return {}
            return self.interface.fee_estimates_eta

    def update_fee_estimates(self):
        e = self.get_fee_estimates()
        for nblock_target, fee in e.items():
            self.config.update_fee_estimates(nblock_target, fee)
        self.logger.info(f'fee_estimates {e}')
        self.notify('fee')

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
        for server in self._recent_servers:
            port = str(server.port)
            if server.host in out:
                out[server.host].update({server.protocol: port})
            else:
                out[server.host] = {server.protocol: port}
        # potentially filter out some
        if self.config.get('noonion'):
            out = filter_noonion(out)
        return out

    def _get_next_server_to_try(self) -> Optional[ServerAddr]:
        now = time.time()
        with self.interfaces_lock:
            connected_servers = set(self.interfaces) | self._connecting
        # First try from recent servers. (which are persisted)
        # As these are servers we successfully connected to recently, they are
        # most likely to work. This also makes servers "sticky".
        # Note: with sticky servers, it is more difficult for an attacker to eclipse the client,
        #       however if they succeed, the eclipsing would persist. To try to balance this,
        #       we only give priority to recent_servers up to NUM_STICKY_SERVERS.
        with self.recent_servers_lock:
            recent_servers = list(self._recent_servers)
        recent_servers = [s for s in recent_servers if s.protocol in self._allowed_protocols]
        if len(connected_servers & set(recent_servers)) < NUM_STICKY_SERVERS:
            for server in recent_servers:
                if server in connected_servers:
                    continue
                if not self._can_retry_addr(server, now=now):
                    continue
                return server
        # try all servers we know about, pick one at random
        hostmap = self.get_servers()
        servers = list(set(filter_protocol(hostmap, allowed_protocols=self._allowed_protocols)) - connected_servers)
        random.shuffle(servers)
        for server in servers:
            if not self._can_retry_addr(server, now=now):
                continue
            return server
        return None

    def _set_proxy(self, proxy: Optional[dict]):
        self.proxy = proxy
        dns_hacks.configure_dns_depending_on_proxy(bool(proxy))
        self.logger.info(f'setting proxy {proxy}')
        util.trigger_callback('proxy_set', self.proxy)

    @log_exceptions
    async def set_parameters(self, net_params: NetworkParameters):
        proxy = net_params.proxy
        proxy_str = serialize_proxy(proxy)
        server = net_params.server
        # sanitize parameters
        try:
            if proxy:
                proxy_modes.index(proxy['mode']) + 1
                int(proxy['port'])
        except:
            return
        self.config.set_key('auto_connect', net_params.auto_connect, False)
        self.config.set_key('oneserver', net_params.oneserver, False)
        self.config.set_key('proxy', proxy_str, False)
        self.config.set_key('server', str(server), True)
        # abort if changes were not allowed by config
        if self.config.get('server') != str(server) \
                or self.config.get('proxy') != proxy_str \
                or self.config.get('oneserver') != net_params.oneserver:
            return

        async with self.restart_lock:
            self.auto_connect = net_params.auto_connect
            if self.proxy != proxy or self.oneserver != net_params.oneserver:
                # Restart the network defaulting to the given server
                await self._stop()
                self.default_server = server
                await self._start()
            elif self.default_server != server:
                await self.switch_to_interface(server)
            else:
                await self.switch_lagging_interface()

    def _maybe_set_oneserver(self) -> None:
        oneserver = bool(self.config.get('oneserver', False))
        self.oneserver = oneserver
        self.num_server = NUM_TARGET_CONNECTED_SERVERS if not oneserver else 0

    async def _switch_to_random_interface(self):
        '''Switch to a random connected server other than the current one'''
        servers = self.get_interfaces()    # Those in connected state
        if self.default_server in servers:
            servers.remove(self.default_server)
        if servers:
            await self.switch_to_interface(random.choice(servers))

    async def switch_lagging_interface(self):
        """If auto_connect and lagging, switch interface (only within fork)."""
        if self.auto_connect and await self._server_is_lagging():
            # switch to one that has the correct header (not height)
            best_header = self.blockchain().header_at_tip()
            with self.interfaces_lock: interfaces = list(self.interfaces.values())
            filtered = list(filter(lambda iface: iface.tip_header == best_header, interfaces))
            if filtered:
                chosen_iface = random.choice(filtered)
                await self.switch_to_interface(chosen_iface.server)

    async def switch_unwanted_fork_interface(self) -> None:
        """If auto_connect, maybe switch to another fork/chain."""
        if not self.auto_connect or not self.interface:
            return
        with self.interfaces_lock: interfaces = list(self.interfaces.values())
        pref_height = self._blockchain_preferred_block['height']
        pref_hash   = self._blockchain_preferred_block['hash']
        # shortcut for common case
        if pref_height == 0:
            return
        # maybe try switching chains; starting with most desirable first
        matching_chains = blockchain.get_chains_that_contain_header(pref_height, pref_hash)
        chains_to_try = list(matching_chains) + [blockchain.get_best_chain()]
        for rank, chain in enumerate(chains_to_try):
            # check if main interface is already on this fork
            if self.interface.blockchain == chain:
                return
            # switch to another random interface that is on this fork, if any
            filtered = [iface for iface in interfaces
                        if iface.blockchain == chain]
            if filtered:
                self.logger.info(f"switching to (more) preferred fork (rank {rank})")
                chosen_iface = random.choice(filtered)
                await self.switch_to_interface(chosen_iface.server)
                return
        self.logger.info("tried to switch to (more) preferred fork but no interfaces are on any")

    async def switch_to_interface(self, server: ServerAddr):
        """Switch to server as our main interface. If no connection exists,
        queue interface to be started. The actual switch will
        happen when the interface becomes ready.
        """
        self.default_server = server
        old_interface = self.interface
        old_server = old_interface.server if old_interface else None

        # Stop any current interface in order to terminate subscriptions,
        # and to cancel tasks in interface.taskgroup.
        # However, for headers sub, give preference to this interface
        # over unknown ones, i.e. start it again right away.
        if old_server and old_server != server:
            await self._close_interface(old_interface)
            if len(self.interfaces) <= self.num_server:
                await self.taskgroup.spawn(self._run_new_interface(old_server))

        if server not in self.interfaces:
            self.interface = None
            await self.taskgroup.spawn(self._run_new_interface(server))
            return

        i = self.interfaces[server]
        if old_interface != i:
            self.logger.info(f"switching to {server}")
            assert i.ready.done(), "interface we are switching to is not ready yet"
            blockchain_updated = i.blockchain != self.blockchain()
            self.interface = i
            await i.taskgroup.spawn(self._request_server_info(i))
            util.trigger_callback('default_server_changed')
            self.default_server_changed_event.set()
            self.default_server_changed_event.clear()
            self._set_status('connected')
            util.trigger_callback('network_updated')
            if blockchain_updated:
                util.trigger_callback('blockchain_updated')

    async def _close_interface(self, interface: Interface):
        if interface:
            with self.interfaces_lock:
                if self.interfaces.get(interface.server) == interface:
                    self.interfaces.pop(interface.server)
            if interface.server == self.default_server:
                self.interface = None
            await interface.close()

    @with_recent_servers_lock
    def _add_recent_server(self, server: ServerAddr) -> None:
        self._on_connection_successfully_established(server)
        # list is ordered
        if server in self._recent_servers:
            self._recent_servers.remove(server)
        self._recent_servers.insert(0, server)
        self._recent_servers = self._recent_servers[:NUM_RECENT_SERVERS]
        self._save_recent_servers()

    async def connection_down(self, interface: Interface):
        '''A connection to server either went down, or was never made.
        We distinguish by whether it is in self.interfaces.'''
        if not interface: return
        server = interface.server
        if server == self.default_server:
            self._set_status('disconnected')
        await self._close_interface(interface)
        util.trigger_callback('network_updated')

    def get_network_timeout_seconds(self, request_type=NetworkTimeout.Generic) -> int:
        if self.oneserver and not self.auto_connect:
            return request_type.MOST_RELAXED
        if self.proxy:
            return request_type.RELAXED
        return request_type.NORMAL

    @ignore_exceptions  # do not kill outer taskgroup
    @log_exceptions
    async def _run_new_interface(self, server: ServerAddr):
        if server in self.interfaces or server in self._connecting:
            return
        self._connecting.add(server)
        if server == self.default_server:
            self.logger.info(f"connecting to {server} as new interface")
            self._set_status('connecting')
        self._trying_addr_now(server)

        interface = Interface(network=self, server=server, proxy=self.proxy)
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
            try: self._connecting.remove(server)
            except KeyError: pass

        if server == self.default_server:
            await self.switch_to_interface(server)

        self._has_ever_managed_to_connect_to_server = True
        self._add_recent_server(server)
        util.trigger_callback('network_updated')

    def check_interface_against_healthy_spread_of_connected_servers(self, iface_to_check: Interface) -> bool:
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

    def best_effort_reliable(func):
        async def make_reliable_wrapper(self: 'Network', *args, **kwargs):
            for i in range(10):
                iface = self.interface
                # retry until there is a main interface
                if not iface:
                    try:
                        await asyncio.wait_for(self.default_server_changed_event.wait(), 1)
                    except asyncio.TimeoutError:
                        pass
                    continue  # try again
                assert iface.ready.done(), "interface not ready yet"
                # try actual request
                success_fut = asyncio.ensure_future(func(self, *args, **kwargs))
                await asyncio.wait([success_fut, iface.got_disconnected], return_when=asyncio.FIRST_COMPLETED)
                if success_fut.done() and not success_fut.cancelled():
                    if success_fut.exception():
                        try:
                            raise success_fut.exception()
                        except RequestTimedOut:
                            await iface.close()
                            await iface.got_disconnected
                            continue  # try again
                        except RequestCorrupted as e:
                            # TODO ban server?
                            iface.logger.exception(f"RequestCorrupted: {e}")
                            await iface.close()
                            await iface.got_disconnected
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
        return await self.interface.get_merkle_for_transaction(tx_hash=tx_hash, tx_height=tx_height)

    @best_effort_reliable
    async def broadcast_transaction(self, tx: 'Transaction', *, timeout=None) -> None:
        if timeout is None:
            timeout = self.get_network_timeout_seconds(NetworkTimeout.Urgent)
        try:
            out = await self.interface.session.send_request('blockchain.transaction.broadcast', [tx.serialize()], timeout=timeout)
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

    async def try_broadcasting(self, tx, name):
        try:
            await self.broadcast_transaction(tx)
        except Exception as e:
            self.logger.info(f'error: could not broadcast {name} {tx.txid()}, {str(e)}')
        else:
            self.logger.info(f'success: broadcasting {name} {tx.txid()}')

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
            r"Only push operators allowed in signatures",
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
        return await self.interface.request_chunk(height, tip=tip, can_return_early=can_return_early)

    @best_effort_reliable
    @catch_server_exceptions
    async def get_transaction(self, tx_hash: str, *, timeout=None) -> str:
        return await self.interface.get_transaction(tx_hash=tx_hash, timeout=timeout)

    @best_effort_reliable
    @catch_server_exceptions
    async def get_history_for_scripthash(self, sh: str) -> List[dict]:
        return await self.interface.get_history_for_scripthash(sh)

    @best_effort_reliable
    @catch_server_exceptions
    async def listunspent_for_scripthash(self, sh: str) -> List[dict]:
        return await self.interface.listunspent_for_scripthash(sh)

    @best_effort_reliable
    @catch_server_exceptions
    async def get_balance_for_scripthash(self, sh: str) -> dict:
        return await self.interface.get_balance_for_scripthash(sh)

    @best_effort_reliable
    @catch_server_exceptions
    async def get_txid_from_txpos(self, tx_height, tx_pos, merkle):
        return await self.interface.get_txid_from_txpos(tx_height, tx_pos, merkle)

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

    def _set_preferred_chain(self, chain: Optional[Blockchain]):
        if chain:
            height = chain.get_max_forkpoint()
            header_hash = chain.get_hash(height)
        else:
            height = 0
            header_hash = constants.net.GENESIS
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
        chosen_iface = random.choice(interfaces_on_selected_chain)  # type: Interface
        # switch to server (and save to config)
        net_params = self.get_parameters()
        net_params = net_params._replace(server=chosen_iface.server)
        await self.set_parameters(net_params)

    async def follow_chain_given_server(self, server: ServerAddr) -> None:
        # note that server_str should correspond to a connected interface
        iface = self.interfaces.get(server)
        if iface is None:
            return
        self._set_preferred_chain(iface.blockchain)
        # switch to server (and save to config)
        net_params = self.get_parameters()
        net_params = net_params._replace(server=server)
        await self.set_parameters(net_params)

    def get_server_height(self) -> int:
        """Length of header chain, as claimed by main interface."""
        interface = self.interface
        return interface.tip if interface else 0

    def get_local_height(self):
        """Length of header chain, POW-verified.
        In case of a chain split, this is for the branch the main interface is on,
        but it is the tip of that branch (even if main interface is behind).
        """
        return self.blockchain().height()

    def export_checkpoints(self, path):
        """Run manually to generate blockchain checkpoints.
        Kept for console use only.
        """
        cp = self.blockchain().get_checkpoints()
        with open(path, 'w', encoding='utf-8') as f:
            f.write(json.dumps(cp, indent=4))

    async def _start(self):
        assert not self.taskgroup
        self.taskgroup = taskgroup = SilentTaskGroup()
        assert not self.interface and not self.interfaces
        assert not self._connecting
        self.logger.info('starting network')
        self._clear_addr_retry_times()
        self._set_proxy(deserialize_proxy(self.config.get('proxy')))
        self._maybe_set_oneserver()
        await self.taskgroup.spawn(self._run_new_interface(self.default_server))

        async def main():
            self.logger.info("starting taskgroup.")
            try:
                # note: if a task finishes with CancelledError, that
                # will NOT raise, and the group will keep the other tasks running
                async with taskgroup as group:
                    await group.spawn(self._maintain_sessions())
                    [await group.spawn(job) for job in self._jobs]
            except asyncio.CancelledError:
                raise
            except Exception as e:
                self.logger.exception("taskgroup died.")
            finally:
                self.logger.info("taskgroup stopped.")
        asyncio.run_coroutine_threadsafe(main(), self.asyncio_loop)

        util.trigger_callback('network_updated')

    def start(self, jobs: Iterable = None):
        """Schedule starting the network, along with the given job co-routines.

        Note: the jobs will *restart* every time the network restarts, e.g. on proxy
        setting changes.
        """
        self._jobs = jobs or []
        asyncio.run_coroutine_threadsafe(self._start(), self.asyncio_loop)

    @log_exceptions
    async def _stop(self, full_shutdown=False):
        self.logger.info("stopping network")
        try:
            await asyncio.wait_for(self.taskgroup.cancel_remaining(), timeout=2)
        except (asyncio.TimeoutError, asyncio.CancelledError) as e:
            self.logger.info(f"exc during main_taskgroup cancellation: {repr(e)}")
        self.taskgroup = None
        self.interface = None
        self.interfaces = {}
        self._connecting.clear()
        if not full_shutdown:
            util.trigger_callback('network_updated')

    def stop(self):
        assert self._loop_thread != threading.current_thread(), 'must not be called from network thread'
        fut = asyncio.run_coroutine_threadsafe(self._stop(full_shutdown=True), self.asyncio_loop)
        try:
            fut.result(timeout=2)
        except (concurrent.futures.TimeoutError, concurrent.futures.CancelledError): pass

    async def _ensure_there_is_a_main_interface(self):
        if self.is_connected():
            return
        # if auto_connect is set, try a different server
        if self.auto_connect and not self.is_connecting():
            await self._switch_to_random_interface()
        # if auto_connect is not set, or still no main interface, retry current
        if not self.is_connected() and not self.is_connecting():
            if self._can_retry_addr(self.default_server, urgent=True):
                await self.switch_to_interface(self.default_server)

    async def _maintain_sessions(self):
        async def maybe_start_new_interfaces():
            for i in range(self.num_server - len(self.interfaces) - len(self._connecting)):
                # FIXME this should try to honour "healthy spread of connected servers"
                server = self._get_next_server_to_try()
                if server:
                    await self.taskgroup.spawn(self._run_new_interface(server))
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
                    await self.interface.taskgroup.spawn(self._request_fee_estimates, self.interface)

        while True:
            try:
                await maybe_start_new_interfaces()
                await maintain_healthy_spread_of_connected_servers()
                await maintain_main_interface()
            except asyncio.CancelledError:
                # suppress spurious cancellations
                group = self.taskgroup
                if not group or group.closed():
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

    async def send_multiple_requests(self, servers: Sequence[ServerAddr], method: str, params: Sequence):
        responses = dict()
        async def get_response(server: ServerAddr):
            interface = Interface(network=self, server=server, proxy=self.proxy)
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
