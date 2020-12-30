# Electrum - Lightweight Bitcoin Client
# Copyright (c) 2011-2016 Thomas Voegtlin
# Copyright (C) 2017-2020 The Electron Cash Developers
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
from typing import Dict

import socks
from . import util
from . import bitcoin
from .bitcoin import *
from . import networks
from .i18n import _
from .interface import Connection, Interface
from . import blockchain
from . import version
from .tor import TorController, check_proxy_bypass_tor_control
from .utils import Event

DEFAULT_AUTO_CONNECT = True
# Versions prior to 4.0.15 had this set to True, but we opted for False to
# promote network health by allowing clients to connect to new servers easily.
DEFAULT_WHITELIST_SERVERS_ONLY = False

def parse_servers(result):
    """ parse servers list into dict format"""
    servers = {}
    for item in result:
        try:
            host = item[1]
            out = {}
            version = None
            pruning_level = '-'
            if len(item) > 2:
                for v in item[2]:
                    if re.match(r"[st]\d*", v):
                        protocol, port = v[0], v[1:]
                        if port == '': port = networks.net.DEFAULT_PORTS[protocol]
                        out[protocol] = port
                    elif re.match(r"v(.?)+", v):
                        version = v[1:]
                    elif re.match(r"p\d*", v):
                        pruning_level = v[1:]
                    if pruning_level == '': pruning_level = '0'
            if out:
                out['pruning'] = pruning_level
                out['version'] = version
                servers[host] = out
        except (TypeError, ValueError, IndexError, KeyError) as e:
            util.print_error("parse_servers:", item, repr(e))
    return servers

def filter_version(servers):
    def is_recent(vv):
        try:
            return version.normalize_version(vv) >= version.normalize_version(version.PROTOCOL_VERSION)
        except Exception as e:
            util.print_error("filter_version:", repr(e))
            return False
    return {k: v for k, v in servers.items() if is_recent(v.get('version'))}


def filter_protocol(hostmap, protocol = 's'):
    '''Filters the hostmap for those implementing protocol.
    Protocol may be: 's', 't', or 'st' for both.
    The result is a list in serialized form.'''
    eligible = []
    for host, portmap in hostmap.items():
        for proto in protocol:
            port = portmap.get(proto)
            if port:
                eligible.append(serialize_server(host, port, proto))
    return eligible

def get_eligible_servers(hostmap=None, protocol="s", exclude_set=set()):
    if hostmap is None:
        hostmap = networks.net.DEFAULT_SERVERS
    return list(set(filter_protocol(hostmap, protocol)) - exclude_set)

def pick_random_server(hostmap = None, protocol = 's', exclude_set = set()):
    eligible = get_eligible_servers(hostmap, protocol, exclude_set)
    return random.choice(eligible) if eligible else None

def servers_to_hostmap(servers):
    ''' Takes an iterable of HOST:PORT:PROTOCOL strings and breaks them into
    a hostmap dict of host -> { protocol : port } suitable to be passed to
    pick_random_server() and get_eligible_servers() above.'''
    ret = dict()
    for s in servers:
        try:
            host, port, protocol = deserialize_server(s)
        except (AssertionError, ValueError, TypeError) as e:
            util.print_error("[servers_to_hostmap] deserialization failure for server:", s, "error:", str(e))
            continue # deserialization error
        m = ret.get(host, dict())
        need_add = len(m) == 0
        m[protocol] = port
        if need_add:
            m['pruning'] = '-' # hmm. this info is missing, so give defaults just to make the map complete.
            m['version'] = version.PROTOCOL_VERSION
            ret[host] = m
    return ret

def hostmap_to_servers(hostmap):
    ''' The inverse of servers_to_hostmap '''
    return filter_protocol(hostmap, protocol = 'st')

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
    try:
        # Fix for #1182 -- bad proxy can end up in config file
        int(proxy['port'])
    except (ValueError, TypeError):
        return None
    return proxy


def deserialize_server(server_str):
    host, port, protocol = str(server_str).rsplit(':', 2)
    assert protocol in 'st'
    int(port)    # Throw if cannot be converted to int
    return host, port, protocol


def serialize_server(host, port, protocol):
    return str(':'.join([host, port, protocol]))


bypass_proxy_filters = [check_proxy_bypass_tor_control]


def _socksocket_filtered(*args, **kwargs):
    """
    This function checks bypass_proxy_filters and if any of the filters returns true
    a raw socket will be returned, otherwise a socks socket will be returned.
    """
    if any(f(*args, **kwargs) for f in bypass_proxy_filters):
        if socket._socketobject:
            return socket._socketobject(*args, **kwargs)
        else:
            return socket.socket(*args, **kwargs)
    else:
        return socks.socksocket(*args, **kwargs)


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

    INSTANCE = None # Only 1 Network instance is ever alive during app lifetime (it's a singleton)

    # These defaults are decent for the desktop app. Other platforms may
    # override these at any time (iOS sets these to lower values).
    NODES_RETRY_INTERVAL = 60  # How often to retry a node we know about in secs, if we are connected to less than 10 nodes
    SERVER_RETRY_INTERVAL = 10  # How often to reconnect when server down in secs
    MAX_MESSAGE_BYTES = 1024*1024*32 # = 32MB. The message size limit in bytes. This is to prevent a DoS vector whereby the server can fill memory with garbage data.

    tor_controller: TorController = None

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
        self.blacklisted_servers = set(self.config.get('server_blacklist', []))
        self.whitelisted_servers, self.whitelisted_servers_hostmap = self._compute_whitelist()
        self.print_error("server blacklist: {} server whitelist: {}".format(self.blacklisted_servers, self.whitelisted_servers))
        self.default_server = self.get_config_server()
        self.bad_certificate_servers: Dict[str, str] = dict()
        self.server_list_updated = Event()

        self.tor_controller = TorController(self.config)
        self.tor_controller.active_port_changed.append(self.on_tor_port_changed)
        self.tor_controller.start()

        self.lock = threading.Lock()
        # locks: if you need to take multiple ones, acquire them in the order they are defined here!
        self.interface_lock = threading.RLock()            # <- re-entrant
        self.pending_sends_lock = threading.Lock()

        self.pending_sends = []
        self.message_id = util.Monotonic(locking=True)
        self.verified_checkpoint = False
        self.verifications_required = 1
        # If the height is cleared from the network constants, we're
        # taking looking to get 3 confirmations of the first verification.
        if networks.net.VERIFICATION_BLOCK_HEIGHT is None:
            self.verifications_required = 3
        self.checkpoint_servers_verified = {}
        self.checkpoint_height = networks.net.VERIFICATION_BLOCK_HEIGHT
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
        self.auto_connect = self.config.get('auto_connect', DEFAULT_AUTO_CONNECT)
        self.connecting = set()
        self.requested_chunks = set()
        self.socket_queue = queue.Queue()
        if Network.INSTANCE:
            # This happens on iOS which kills and restarts the daemon on app sleep/wake
            self.print_error("A new instance has started and is replacing the old one.")
        Network.INSTANCE = self # This implicitly should force stale instances to eventually del
        self.start_network(deserialize_server(self.default_server)[2], deserialize_proxy(self.config.get('proxy')))

    def on_tor_port_changed(self, controller: TorController):
        if not controller.active_socks_port or not controller.is_enabled() or not self.config.get('tor_use', False):
            return

        proxy = deserialize_proxy(self.config.get('proxy'))
        port = str(controller.active_socks_port)
        if proxy["port"] == port:
            return
        proxy["port"] = port
        self.config.set_key('proxy', serialize_proxy(proxy))
        # This handler can run before `proxy` is present and `load_parameters` needs it
        if hasattr(self, "proxy"):
            self.load_parameters()

    def __del__(self):
        """ NB: due to Network.INSTANCE keeping the singleton instance alive,
            this code isn't normally reached, except for in the iOS
            implementation, which kills the daemon and the network before app
            sleep, and creates a new daemon and netwok on app awake. """
        if Network.INSTANCE is self: # This check is important for iOS
            Network.INSTANCE = None # <--- Not normally reached, but here for completeness.
        else:
            self.print_error("Stale instance deallocated")
        if hasattr(super(), '__del__'):
            super().__del__()

    @staticmethod
    def get_instance():
        """ Returns the extant Network singleton, if any, or None if in offline mode """
        return Network.INSTANCE

    def callback_listener_count(self, event):
        return len(self.callbacks.get(event, []))  # we intentionally don't take any locks here as a performance optimization

    def register_callback(self, callback, events):
        with self.lock:
            for event in events:
                self.callbacks[event].append(callback)
                if event in self._deprecated_alternatives:
                    self._warn_deprecated_callback(event)

    def unregister_callback(self, callback):
        with self.lock:
            for callbacks in self.callbacks.values():
                try:
                    callbacks.remove(callback)
                except ValueError:
                    pass

    def trigger_callback(self, event, *args):
        with self.lock:
            callbacks = self.callbacks[event][:]
        [callback(event, *args) for callback in callbacks]
        self._legacy_callback_detector_and_mogrifier(event, *args)

    def _legacy_callback_detector_and_mogrifier(self, event, *args):
        if (event in ('blockchain_updated', 'wallet_updated')
                and 'updated' in self.callbacks):
            # Translate the blockchain_updated and wallet_updated events
            # into the legacy 'updated' event for old external plugins that
            # still rely on this event existing. There are some external
            # electron cash plugins that still use this event, and we need
            # to keep this hack here so they don't break on new EC
            # versions.  "Technical debt" :)
            self.trigger_callback('updated')  # we will re-enter this function with event == 'updated' (triggering the warning in the elif clause below)
        elif event == 'verified2' and 'verified' in self.callbacks:
            # pop off the 'wallet' arg as the old bad 'verified' callback lacked it.
            self.trigger_callback('verified', args[1:])  # we will re-enter this function with event == 'verified' (triggering the warning in the elif clause below)
        elif event in self._deprecated_alternatives:
            # If we see updated or verified events come through here, warn:
            # deprecated. Note that the above 2 clauses will also trigger this
            # execution path.
            self._warn_deprecated_callback(event)

    _deprecated_alternatives = {
        'updated' : "'blockchain_updated' and/or 'wallet_updated'",
        'verified': "'verified2'",
    }
    def _warn_deprecated_callback(self, which):
        alt = self._deprecated_alternatives.get(which)
        if alt:
            self.print_error("Warning: Legacy '{}' callback is deprecated, it is recommended that you instead use: {}. Please update your code.".format(which, alt))
        else:
            self.print_error("Warning: Legacy '{}' callback is deprecated. Please update your code.".format(which))

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

    def queue_request(self, method, params, interface=None, *, callback=None, max_qlen=None):
        """ If you want to queue a request on any interface it must go through
        this function so message ids are properly tracked.
        Returns the monotonically increasing message id for this request.
        May return None if queue is too full (max_qlen). (max_qlen is only
        considered if callback is not None.)

        Note that the special argument interface='random' will queue the request
        on a random, currently active (connected) interface.  Otherwise
        `interface` should be None or a valid Interface instance.


        If no interface is available:
            - If `callback` is supplied: the request will be enqueued and sent
              later when an interface becomes available
            - If callback is not supplied: an AssertionError exception is raised
        """
        if interface is None:
            interface = self.interface
        elif interface == 'random':
            interface = random.choice(self.get_interfaces(interfaces=True)
                                      or (None,))  # may set interface to None if no interfaces
        message_id = self.message_id() # Note: self.message_id is a Monotonic (thread-safe) counter-object, see util.Monotonic
        if callback:
            if max_qlen and len(self.unanswered_requests) >= max_qlen:
                # Indicate to client code we are busy
                return None
            self.unanswered_requests[message_id] = [method, params, callback]
            if not interface:
                # Request was queued -- it should get sent if/when we get
                # an interface in the future
                return message_id
        # Now, if no interface, we will raise AssertionError
        assert isinstance(interface, Interface), "queue_request: No interface! (request={} params={})".format(method, params)
        if self.debug:
            self.print_error(interface.host, "-->", method, params, message_id)
        interface.queue_request(method, params, message_id)
        if self is not Network.INSTANCE:
            self.print_error("*** WARNING: queueing request on a stale instance!")
        return message_id

    def send_subscriptions(self):
        self.sub_cache.clear()
        # Resend unanswered requests
        old_reqs = self.unanswered_requests
        self.unanswered_requests = {}
        for m_id, request in old_reqs.items():
            message_id = self.queue_request(request[0], request[1], callback = request[2])
            assert message_id is not None
        self.queue_request('server.banner', [])
        self.queue_request('server.donation_address', [])
        self.queue_request('server.peers.subscribe', [])
        #self.request_fee_estimates()  # We disable fee estimates globally in this app for now. BCH doesn't need them and they create more user confusion than anything.
        self.queue_request('blockchain.relayfee', [])
        n_defunct = 0
        method = 'blockchain.scripthash.subscribe'
        for h in self.subscribed_addresses.copy():
            params = [h]
            k = self.get_index(method, params)
            if self.subscriptions.get(k, None):
                self.queue_request(method, params)
            else:
                # If a wallet was closed, we stayed subscribed to its scripthashes
                # (there is no way to unsubscribe from a scripthash, unfortunately)
                # However, now that we are connecting to a new server, use this
                # opportunity to clean house and not subscribe to scripthashes
                # for closed wallets.  We know a scripthash is defunct if it is
                # missing a callback (no entry in self.subscriptions dict).
                #self.print_error("removing defunct subscription", h)
                self.subscribed_addresses.discard(h)
                self.subscriptions.pop(k, None)  # it may be an empty list (or missing), so pop it just in case it's a list.
                n_defunct += 1
        self.print_error('sent subscriptions to', self.interface.server, len(old_reqs),"reqs", len(self.subscribed_addresses), "subs", n_defunct, "defunct subs")

    def request_fee_estimates(self):
        self.print_error("request_fee_estimates called: DISABLED in network.py")
        return
        # We disable fee estimates. BCH doesn't need this code. For now 1 sat/B
        # is enough.
        self.config.requested_fee_estimates()
        try:
            for i in bitcoin.FEE_TARGETS:
                self.queue_request('blockchain.estimatefee', [i])
        except AssertionError:
            '''No interface available.'''

    def get_status_value(self, key):
        if key == 'status':
            value = self.connection_status
        elif key == 'banner':
            value = self.banner
        elif key == 'fee':
            value = self.config.fee_estimates
        elif key == 'blockchain_updated':
            value = (self.get_local_height(), self.get_server_height())
        elif key == 'updated':
            value = (self.get_local_height(), self.get_server_height())
            self._warn_deprecated_callback(key)
        elif key == 'servers':
            value = self.get_servers()
        elif key == 'interfaces':
            value = self.get_interfaces()
        elif key == 'proxy':
            value = (self.proxy and self.proxy.copy()) or None
        else:
            raise RuntimeError('unexpected trigger key {}'.format(key))
        return value

    def notify(self, key):
        if key in ('updated',):
            # Legacy support.  Will warn that updated is deprecated.
            self.trigger_callback(key)
        else:
            self.trigger_callback(key, self.get_status_value(key))

    def get_parameters(self):
        host, port, protocol = deserialize_server(self.default_server)
        return host, port, protocol, self.proxy, self.auto_connect

    def get_donation_address(self):
        if self.is_connected():
            return self.donation_address

    def get_interfaces(self, *, interfaces=False):
        """Returns the servers that are in connected state. Despite its name,
        this method does not return the actual interfaces unless interfaces=True,
        but rather returns the server:50002:s style string. """
        with self.interface_lock:
            return list(self.interfaces.values() if interfaces
                        else self.interfaces.keys())

    def get_servers(self):
        out = networks.net.DEFAULT_SERVERS.copy()
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

    def start_interface(self, server_key):
        """Start the given server if it is not already active or being connected to.

        Arguments:
        server_key --- server specifier in the form of '<host>:<port>:<protocol>'
        """
        if (not server_key in self.interfaces and not server_key in self.connecting):
            if server_key == self.default_server:
                self.print_error("connecting to %s as new interface" % server_key)
                self.set_status('connecting')
            self.connecting.add(server_key)
            c = Connection(server_key, self.socket_queue, self.config.path,
                           lambda x: x.bad_certificate.append_weak(self.on_bad_certificate))

    def get_unavailable_servers(self):
        exclude_set = set(self.interfaces)
        exclude_set = exclude_set.union(self.connecting)
        exclude_set = exclude_set.union(self.disconnected_servers)
        exclude_set = exclude_set.union(self.blacklisted_servers)
        return exclude_set

    def start_random_interface(self):
        exclude_set = self.get_unavailable_servers()
        hostmap = self.get_servers() if not self.is_whitelist_only() else self.whitelisted_servers_hostmap
        server_key = pick_random_server(hostmap, self.protocol, exclude_set)
        if server_key:
            self.start_interface(server_key)

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
            socket.socket = _socksocket_filtered
            # prevent dns leaks, see http://stackoverflow.com/questions/13184205/dns-over-proxy
            socket.getaddrinfo = lambda *args: [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (args[0], args[1]))]
        else:
            socket.socket = socket._socketobject
            socket.getaddrinfo = socket._getaddrinfo
        self.notify('proxy')

    def start_network(self, protocol, proxy):
        assert not self.interface and not self.interfaces
        assert not self.connecting and self.socket_queue.empty()
        self.print_error('starting network')
        self.disconnected_servers = set([])
        self.protocol = protocol
        self.set_proxy(proxy)
        self.start_interfaces()

    def stop_network(self):
        with self.interface_lock:
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
        with self.interface_lock:
            try:
                self.save_parameters(host, port, protocol, proxy, auto_connect)
            except ValueError:
                return
            self.load_parameters()

    def save_parameters(self, host, port, protocol, proxy, auto_connect):
        proxy_str = serialize_proxy(proxy)
        server = serialize_server(host, port, protocol)
        # sanitize parameters
        try:
            deserialize_server(serialize_server(host, port, protocol))
            if proxy:
                proxy_modes.index(proxy["mode"]) + 1
                int(proxy['port'])
        except:
            raise ValueError("invalid server or proxy")

        self.config.set_key('auto_connect', auto_connect, False)
        self.config.set_key("proxy", proxy_str, False)
        self.config.set_key("server", server, True)
        if self.config.get('server') != server or self.config.get('proxy') != proxy_str:
            raise ValueError("changes were not allowed by config")

    def load_parameters(self):
        server = self.get_config_server()
        protocol = deserialize_server(server)[2]
        proxy = deserialize_proxy(self.config.get('proxy'))
        self.auto_connect = self.config.get('auto_connect', DEFAULT_AUTO_CONNECT)
        if self.proxy != proxy or self.protocol != protocol:
            # Restart the network defaulting to the given server
            self.stop_network()
            self.default_server = server
            self.start_network(protocol, proxy)
        elif self.default_server != server:
            self.switch_to_interface(server, self.SWITCH_SET_PARAMETERS)
        else:
            self.switch_lagging_interface()
            self.notify('blockchain_updated')

    def get_config_server(self):
        server = self.config.get('server', None)
        if server:
            try:
                deserialize_server(server)
            except:
                self.print_error('Warning: failed to parse server-string; falling back to random.')
                server = None
        wl_only = self.is_whitelist_only()
        if (not server) or (server in self.blacklisted_servers) or (wl_only and server not in self.whitelisted_servers):
            hostmap = None if not wl_only else self.whitelisted_servers_hostmap
            server = pick_random_server(hostmap, exclude_set=self.blacklisted_servers)
        return server

    def switch_to_random_interface(self):
        """Switch to a random connected server other than the current one"""
        servers = self.get_interfaces()    # Those in connected state
        if self.default_server in servers:
            servers.remove(self.default_server)
        if servers:
            self.switch_to_interface(random.choice(servers))

    def switch_lagging_interface(self):
        """If auto_connect and lagging, switch interface"""
        if self.server_is_lagging() and self.auto_connect:
            # switch to one that has the correct header (not height)
            header = self.blockchain().read_header(self.get_local_height())
            filtered = list(map(lambda x:x[0], filter(lambda x: x[1].tip_header==header, self.interfaces.items())))
            if filtered:
                choice = random.choice(filtered)
                self.switch_to_interface(choice, self.SWITCH_LAGGING)

    SWITCH_DEFAULT = 'SWITCH_DEFAULT'
    SWITCH_RANDOM = 'SWITCH_RANDOM'
    SWITCH_LAGGING = 'SWITCH_LAGGING'
    SWITCH_SOCKET_LOOP = 'SWITCH_SOCKET_LOOP'
    SWITCH_FOLLOW_CHAIN = 'SWITCH_FOLLOW_CHAIN'
    SWITCH_SET_PARAMETERS = 'SWITCH_SET_PARAMETERS'

    def switch_to_interface(self, server, switch_reason=None):
        """Switch to server as our interface.  If no connection exists nor
        being opened, start a thread to connect.  The actual switch will
        happen on receipt of the connection notification.  Do nothing
        if server already is our interface."""
        self.default_server = server
        if server not in self.interfaces:
            self.interface = None
            self.start_interface(server)
            return
        i = self.interfaces[server]
        if self.interface != i:
            self.print_error("switching to '{}' reason '{}'".format(server, switch_reason))
            # stop any current interface in order to terminate subscriptions
            # fixme: we don't want to close headers sub
            #self.close_interface(self.interface)
            self.interface = i
            self.send_subscriptions()
            self.set_status('connected')
            self.notify('blockchain_updated')

    def close_interface(self, interface):
        if interface:
            with self.interface_lock:
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

        # FIXME:
        # Do more to enforce result correctness, has the right data type, etc.
        # This code as it stands has been superficially audited for that but I
        # suspect it's still possible for  a malicious server to cause clients
        # to throw up a crash reporter by sending unexpected JSON data types
        # or garbage data in the server response.

        # We handle some responses; return the rest to the client.
        if method == 'server.version':
            if isinstance(result, list):
                self.on_server_version(interface, result)
        elif method == 'blockchain.headers.subscribe':
            if error is None:
                # on_notify_header below validates result is right type or format
                self.on_notify_header(interface, result)
        elif method == 'server.peers.subscribe':
            if error is None and isinstance(result, list):
                self.irc_servers = parse_servers(result)
                self.notify('servers')
        elif method == 'server.banner':
            if error is None and isinstance(result, str):
                # limit banner results to 16kb to avoid minor DoS vector whereby
                # server sends a huge block of slow-to-render emojis which
                # brings some platforms to thier knees for a few minutes.
                self.banner = result[:16384]
                self.notify('banner')
        elif method == 'server.donation_address':
            if error is None and isinstance(result, str):
                self.donation_address = result
        elif method == 'blockchain.estimatefee':
            try:
                if error is None and isinstance(result, (int, float)) and result > 0:
                    i = params[0]
                    fee = int(result*COIN)
                    self.config.update_fee_estimates(i, fee)
                    self.print_error("fee_estimates[%d]" % i, fee)
                    self.notify('fee')
            except (TypeError, ValueError) as e:
                self.print_error("bad server data in blockchain.estimatefee:", result, "error:", repr(e))
        elif method == 'blockchain.relayfee':
            try:
                if error is None and isinstance(result, (int, float)):
                    self.relay_fee = int(result * COIN)
                    self.print_error("relayfee", self.relay_fee)
            except (TypeError, ValueError) as e:
                self.print_error("bad server data in blockchain.relayfee:", result, "error:", repr(e))
        elif method == 'blockchain.block.headers':
            try:
                self.on_block_headers(interface, request, response)
            except Exception as e:
                self.print_error(f"bad server response for {method}: {repr(e)} / {response}")
                self.connection_down(interface.server)
        elif method == 'blockchain.block.header':
            try:
                self.on_header(interface, request, response)
            except Exception as e:
                self.print_error(f"bad server response for {method}: {repr(e)} / {response}")
                self.connection_down(interface.server)

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
                    if interface != self.interface:
                        self.print_error("advisory: response from non-primary {}".format(interface))
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
        """Messages is a list of (method, params) tuples"""
        messages = list(messages)
        if messages: # Guard against empty message-list which is a no-op and just wastes CPU to enque/dequeue (not even callback is called). I've seen the code send empty message lists before in synchronizer.py
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
                    l = self.subscriptions[k] # <-- it's a defaultdict(list)
                    if callback not in l:
                        l.append(callback)
                    # check cached response for subscriptions
                    r = self.sub_cache.get(k)
                if r is not None:
                    util.print_error("cache hit", k)
                    callback(r)
                else:
                    self.queue_request(method, params, callback = callback)

    def _cancel_pending_sends(self, callback):
        ct = 0
        with self.pending_sends_lock:
            for item in self.pending_sends.copy():
                messages, _callback = item
                if callback == _callback:
                    self.pending_sends.remove(item)
                    ct += 1
        return ct

    def unsubscribe(self, callback):
        '''Unsubscribe a callback to free object references to enable GC.
        It is advised that this function only be called from the network thread
        to avoid race conditions.'''
        # Note: we can't unsubscribe from the server, so if we receive
        # subsequent notifications, they will be safely ignored as
        # no callbacks will exist to process them. For subscriptions we will
        # however cache the 'result' hash and feed it back in case a wallet that
        # was closed gets reopened (self.sub_cache).
        ct = 0
        with self.lock:
            for k,v in self.subscriptions.copy().items():
                if callback in v:
                    v.remove(callback)
                    if not v:
                        # remove empty list
                        self.subscriptions.pop(k, None)
                    ct += 1
        ct2 = self._cancel_pending_sends(callback)
        if ct or ct2:
            qname = getattr(callback, '__qualname__', '<unknown>')
            self.print_error("Removed {} subscription callbacks and {} pending sends for callback: {}".format(ct, ct2, qname))

    def cancel_requests(self, callback):
        '''Remove a callback to free object references to enable GC.
        It is advised that this function only be called from the network thread
        to avoid race conditions.'''
        # If the interface ends up answering these requests, they will just
        # be safely ignored. This is better than the alternative which is to
        # keep references to an object that declared itself defunct.
        ct = 0
        for message_id, client_req in self.unanswered_requests.copy().items():
            if callback == client_req[2]:
                self.unanswered_requests.pop(message_id, None) # guard against race conditions here. Note: this usually is called from the network thread but who knows what future programmers may do. :)
                ct += 1
        ct2 = self._cancel_pending_sends(callback)
        if ct or ct2:
            qname = getattr(callback, '__qualname__', repr(callback))
            self.print_error("Removed {} unanswered client requests and {} pending sends for callback: {}".format(ct, ct2, qname))

    def connection_down(self, server, blacklist=False):
        '''A connection to server either went down, or was never made.
        We distinguish by whether it is in self.interfaces.'''
        if blacklist:
            self.server_set_blacklisted(server, True, save=True, skip_connection_logic=True)
        else:
            self.disconnected_servers.add(server)
        if server == self.default_server:
            self.set_status('disconnected')
        if server in self.interfaces:
            self.close_interface(self.interfaces[server])
            self.notify('interfaces')
        for b in self.blockchains.values():
            if b.catch_up == server:
                b.catch_up = None

    def new_interface(self, server_key, socket):
        self.add_recent_server(server_key)

        interface = Interface(server_key, socket, max_message_bytes=self.MAX_MESSAGE_BYTES, config=self.config)
        interface.blockchain = None
        interface.tip_header = None
        interface.tip = 0
        interface.set_mode(Interface.MODE_VERIFICATION)

        with self.interface_lock:
            self.interfaces[server_key] = interface

        # server.version should be the first message
        params = [version.PACKAGE_VERSION, version.PROTOCOL_VERSION]
        self.queue_request('server.version', params, interface)
        # The interface will immediately respond with it's last known header.
        self.queue_request('blockchain.headers.subscribe', [], interface)

        if server_key == self.default_server:
            self.switch_to_interface(server_key, self.SWITCH_DEFAULT)

    def maintain_sockets(self):
        '''Socket maintenance.'''
        # Responses to connection attempts?
        while not self.socket_queue.empty():
            server, socket = self.socket_queue.get()
            if server in self.connecting:
                self.connecting.remove(server)
            if socket:
                self.remove_bad_certificate(server)
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
            server_count = len(self.interfaces) + len(self.connecting)
            if server_count < self.num_server:
                self.start_random_interface()
                if now - self.nodes_retry_time > self.NODES_RETRY_INTERVAL:
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
                        if now - self.server_retry_time > self.SERVER_RETRY_INTERVAL:
                            self.disconnected_servers.remove(self.default_server)
                            self.server_retry_time = now
                    else:
                        self.switch_to_interface(self.default_server, self.SWITCH_SOCKET_LOOP)
            else:
                if self.config.is_fee_estimates_update_required():
                    self.request_fee_estimates()

    def request_chunk(self, interface, chunk_index):
        if chunk_index in self.requested_chunks:
            return False
        self.requested_chunks.add(chunk_index)

        interface.print_error("requesting chunk {}".format(chunk_index))
        chunk_base_height = chunk_index * 2016
        chunk_count = 2016
        return self.request_headers(interface, chunk_base_height, chunk_count, silent=True)

    def request_headers(self, interface, base_height, count, silent=False):
        if not silent:
            interface.print_error("requesting multiple consecutive headers, from {} count {}".format(base_height, count))
        if count > 2016:
            raise Exception("Server does not support requesting more than 2016 consecutive headers")

        top_height = base_height + count - 1
        if top_height > networks.net.VERIFICATION_BLOCK_HEIGHT:
            if base_height < networks.net.VERIFICATION_BLOCK_HEIGHT:
                # As part of the verification process, we fetched the set of headers that allowed manual verification of the post-checkpoint headers that were fetched
                # as part of the "catch-up" process.  This requested header batch overlaps the checkpoint, so we know we have the post-checkpoint segment from the
                # "catch-up".  This leaves us needing some header preceding the checkpoint, and we can clip the batch to the checkpoint to ensure we can verify the
                # fetched batch, which we wouldn't otherwise be able to do manually as we cannot guarantee we have the headers preceding the batch.
                interface.print_error("clipping request across checkpoint height {} ({} -> {})".format(networks.net.VERIFICATION_BLOCK_HEIGHT, base_height, top_height))
                verified_count = networks.net.VERIFICATION_BLOCK_HEIGHT - base_height + 1
                return self._request_headers(interface, base_height, verified_count, networks.net.VERIFICATION_BLOCK_HEIGHT)
            else:
                return self._request_headers(interface, base_height, count)
        else:
            return self._request_headers(interface, base_height, count, networks.net.VERIFICATION_BLOCK_HEIGHT)

    def _request_headers(self, interface, base_height, count, checkpoint_height=0):
        params = [base_height, count, checkpoint_height]
        return self.queue_request('blockchain.block.headers', params, interface) is not None

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

        header_hexsize = blockchain.HEADER_SIZE * 2
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
                interface.print_error("disconnecting server for incorrect checkpoint proof")
                self.connection_down(interface.server, blacklist=True)
                return

            data = bfh(hexdata)
            try:
                blockchain.verify_proven_chunk(request_base_height, data)
            except blockchain.VerifyError as e:
                interface.print_error('disconnecting server for failed verify_proven_chunk: {}'.format(e))
                self.connection_down(interface.server, blacklist=True)
                return

            proof_was_provided = True
        elif len(request_params) == 3 and request_params[2] != 0:
            # Expected checkpoint validation data, did not receive it.
            self.connection_down(interface.server)
            return

        verification_top_height = self.checkpoint_servers_verified.get(interface.server, {}).get('height', None)
        was_verification_request = verification_top_height and request_base_height == verification_top_height - 147 + 1 and actual_header_count == 147

        initial_interface_mode = interface.mode
        if interface.mode == Interface.MODE_VERIFICATION:
            if not was_verification_request:
                interface.print_error("disconnecting unverified server for sending unrelated header chunk")
                self.connection_down(interface.server, blacklist=True)
                return
            if not proof_was_provided:
                interface.print_error("disconnecting unverified server for sending verification header chunk without proof")
                self.connection_down(interface.server, blacklist=True)
                return

            if not self.apply_successful_verification(interface, request_params[2], result['root']):
                return
            # We connect this verification chunk into the longest chain.
            target_blockchain = self.blockchains[0]
        else:
            target_blockchain = interface.blockchain

        chunk_data = bfh(hexdata)
        connect_state = (target_blockchain.connect_chunk(request_base_height, chunk_data, proof_was_provided)
                         if target_blockchain
                         else blockchain.CHUNK_BAD)  # fix #1079 -- invariant is violated here due to extant bugs, so rather than raise an exception, just trigger a connection_down below...
        if connect_state == blockchain.CHUNK_ACCEPTED:
            interface.print_error("connected chunk, height={} count={} proof_was_provided={}".format(request_base_height, actual_header_count, proof_was_provided))
        elif connect_state == blockchain.CHUNK_FORKS:
            interface.print_error("identified forking chunk, height={} count={}".format(request_base_height, actual_header_count))
            # We actually have all the headers up to the bad point. In theory we
            # can use them to detect a fork point in some cases. But that's bonus
            # work for someone later.
            # Discard the chunk and do a normal search for the fork point.
            # Note that this will not give us the right blockchain, the
            # syncing does not work that way historically.  That might
            # wait until either a new block appears, or
            if False:
                interface.blockchain = None
                interface.set_mode(Interface.MODE_BACKWARD)
                interface.bad = request_base_height + actual_header_count - 1
                interface.bad_header = blockchain.HeaderChunk(request_base_height, chunk_data).get_header_at_height(interface.bad)
                self.request_header(interface, min(interface.tip, interface.bad - 1))
            return
        else:
            interface.print_error("discarded bad chunk, height={} count={} reason={}".format(request_base_height, actual_header_count, connect_state))
            self.connection_down(interface.server)
            return

        # This interface was verified above. Get it syncing.
        if initial_interface_mode == Interface.MODE_VERIFICATION:
            self._process_latest_tip(interface)
            return

        # If not finished, get the next chunk.
        if proof_was_provided and not was_verification_request:
            # the verifier must have asked for this chunk.  It has been overlaid into the file.
            pass
        else:
            if interface.blockchain.height() < interface.tip:
                self.request_headers(interface, request_base_height + actual_header_count, 2016)
            else:
                interface.set_mode(Interface.MODE_DEFAULT)
                interface.print_error('catch up done', interface.blockchain.height())
                interface.blockchain.catch_up = None
        self.notify('blockchain_updated')

    def request_header(self, interface, height):
        """
        This works for all modes except for 'default'.

        If it is to be used for piecemeal filling of the sparse blockchain
        headers file before the checkpoint height, it needs extra
        handling for the 'default' mode.

        A server interface does not get associated with a blockchain
        until it gets handled in the response to its first header
        request.
        """
        interface.print_error(f"requesting header {height}")
        if height > networks.net.VERIFICATION_BLOCK_HEIGHT:
            params = [height]
        else:
            params = [height, networks.net.VERIFICATION_BLOCK_HEIGHT]
        self.queue_request('blockchain.block.header', params, interface)
        return True

    def on_header(self, interface, request, response):
        """Handle receiving a single block header"""
        result = response.get('result')
        if not result:
            interface.print_error(response)
            self.connection_down(interface.server)
            return

        if not request:
            interface.print_error("disconnecting server for sending unsolicited header, no request, params={}".format(response['params']), blacklist=True)
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
        if interface.mode == Interface.MODE_BACKWARD:
            if chain:
                interface.print_error("binary search")
                interface.set_mode(Interface.MODE_BINARY)
                interface.blockchain = chain
                interface.good = height
                next_height = (interface.bad + interface.good) // 2
            else:
                # A backwards header request should not happen before the
                # checkpoint height. It isn't requested in this context, and it
                # isn't requested anywhere else. If this happens it is an error.
                # Additionally, if the checkpoint height header was requested
                # and it does not connect, then there's not much Electron Cash
                # can do about it (that we're going to bother). We depend on the
                # checkpoint being relevant for the blockchain the user is
                # running against.
                if height <= networks.net.VERIFICATION_BLOCK_HEIGHT:
                    self.connection_down(interface.server)
                    next_height = None
                else:
                    interface.bad = height
                    interface.bad_header = header
                    delta = interface.tip - height
                    # If the longest chain does not connect at any point we check to the chain this interface is
                    # serving, then we fall back on the checkpoint height which is expected to work.
                    next_height = max(networks.net.VERIFICATION_BLOCK_HEIGHT, interface.tip - 2 * delta)

        elif interface.mode == Interface.MODE_BINARY:
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
                        interface.set_mode(Interface.MODE_CATCH_UP)
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
                            interface.set_mode(Interface.MODE_CATCH_UP)
                            next_height = interface.bad + 1
                            interface.blockchain.catch_up = interface.server
                    else:
                        assert bh == interface.good
                        if interface.blockchain.catch_up is None and bh < interface.tip:
                            interface.print_error("catching up from %d"% (bh + 1))
                            interface.set_mode(Interface.MODE_CATCH_UP)
                            next_height = bh + 1
                            interface.blockchain.catch_up = interface.server

                self.notify('blockchain_updated')

        elif interface.mode == Interface.MODE_CATCH_UP:
            can_connect = interface.blockchain.can_connect(header)
            if can_connect:
                interface.blockchain.save_header(header)
                next_height = height + 1 if height < interface.tip else None
            else:
                # go back
                interface.print_error("cannot connect", height)
                interface.set_mode(Interface.MODE_BACKWARD)
                interface.bad = height
                interface.bad_header = header
                next_height = height - 1

            if next_height is None:
                # exit catch_up state
                interface.print_error('catch up done', interface.blockchain.height())
                interface.blockchain.catch_up = None
                self.switch_lagging_interface()
                self.notify('blockchain_updated')
        elif interface.mode == Interface.MODE_DEFAULT:
            interface.print_error("ignored header {} received in default mode".format(height))
            return

        # If not finished, get the next header
        if next_height:
            if interface.mode == Interface.MODE_CATCH_UP and interface.tip > next_height:
                self.request_headers(interface, next_height, 2016)
            else:
                self.request_header(interface, next_height)
        else:
            interface.set_mode(Interface.MODE_DEFAULT)
            self.notify('blockchain_updated')
        # refresh network dialog
        self.notify('interfaces')

    def find_bad_fds_and_kill(self):
        bad = []
        with self.interface_lock:
            for s,i in self.interfaces.copy().items():
                try:
                    r, w, x = select.select([i],[i],[],0) # non-blocking select to test if fd's are good.
                except (OSError, ValueError):
                    i.print_error("Bad file descriptor {}, closing".format(i.fileno()))
                    self.connection_down(s)
                    bad.append(i)
        if bad:
            self.print_error("{} bad file descriptors detected and shut down: {}".format(len(bad), bad))
        return bad

    def wait_on_sockets(self):
        def try_to_recover(err):
            self.print_error("wait_on_sockets: {} raised by select() call.. trying to recover...".format(err))
            self.find_bad_fds_and_kill()

        rin = []
        win = []
        r_immed = []
        with self.interface_lock:
            interfaces = list(self.interfaces.values())
            for interface in interfaces:
                if interface.fileno() < 0:
                    continue
                read_pending, write_pending = interface.pipe.get_selectloop_info()
                if read_pending:
                    r_immed.append(interface)
                else:
                    rin.append(interface)
                if write_pending or interface.num_requests():
                    win.append(interface)

        timeout = 0 if r_immed else 0.1

        try:
            # Python docs say Windows doesn't like empty selects.
            if win or rin:
                rout, wout, xout = select.select(rin, win, [], timeout)
            else:
                rout = wout = xout = ()
                if timeout:
                    # Sleep to prevent busy looping
                    time.sleep(timeout)
        except socket.error as e:
            code = None
            if isinstance(e, OSError): # Should always be the case unless ancient python3
                code = e.errno
            if code == errno.EINTR:
                return # calling loop will try again later
            elif code == errno.EBADF:
                # A filedescriptor was closed from underneath us because we have race conditions in this class. :(
                # Note that due to race conditions with the gui thread even with the checks above it's entirely possible
                # for the socket fd to become -1, or to be not -1 but still be invalid/closed.
                try_to_recover("EBADF")
                return # calling loop will try again later
            raise # ruh ruh. user will get a crash dialog screen and network will die. FIXME: figure out a  way to restart network..
        except ValueError:
            # Note sometimes select() ends up getting a file descriptor that's -1 because race conditions, in which case it raises
            # ValueError
            try_to_recover("ValueError")
            return # calling loop will try again later

        assert not xout
        for interface in wout:
            if not interface.send_requests():
                self.connection_down(interface.server)
        for interface in r_immed:
            self.process_responses(interface)
        for interface in rout:
            self.process_responses(interface)

    def init_headers_file(self):
        b = self.blockchains[0]
        filename = b.path()
        # NB: HEADER_SIZE = 80 bytes
        length = blockchain.HEADER_SIZE * (networks.net.VERIFICATION_BLOCK_HEIGHT + 1)
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
        if networks.net.VERIFICATION_BLOCK_HEIGHT is not None:
            self.init_headers_file()
            header = b.read_header(networks.net.VERIFICATION_BLOCK_HEIGHT)
        if header is not None:
            self.verified_checkpoint = True

        while self.is_running():
            self.maintain_sockets()
            self.wait_on_sockets()
            if self.verified_checkpoint:
                self.run_jobs()    # Synchronizer and Verifier and Fx
            self.process_pending_sends()
        self.stop_network()

        self.tor_controller.active_port_changed.remove(self.on_tor_port_changed)
        self.tor_controller.stop()
        self.tor_controller = None

        self.on_stop()

    def on_server_version(self, interface, version_data):
        interface.server_version = version_data

    def on_notify_header(self, interface, header_dict):
        """
        When we subscribe for 'blockchain.headers.subscribe', a server will send
        us it's topmost header.  After that, it will forward on any additional
        headers as it receives them.
        """
        if (not isinstance(header_dict, dict)
            or 'hex' not in header_dict or 'height' not in header_dict):
            # bad and/or unexpected response from server.
            self.connection_down(interface.server)
            return

        header_hex = header_dict['hex']
        height = header_dict['height']
        header = blockchain.deserialize_header(bfh(header_hex), height)

        # If the server is behind the verification height, then something is wrong with it.  Drop it.
        if networks.net.VERIFICATION_BLOCK_HEIGHT is not None and height <= networks.net.VERIFICATION_BLOCK_HEIGHT:
            self.connection_down(interface.server)
            return

        # We will always update the tip for the server.
        interface.tip_header = header
        interface.tip = height

        if interface.mode == Interface.MODE_VERIFICATION:
            # If the server has already had this requested, this will be a no-op.
            self.request_initial_proof_and_headers(interface)
            return

        self._process_latest_tip(interface)

    def _process_latest_tip(self, interface):
        if interface.mode != Interface.MODE_DEFAULT:
            return

        header = interface.tip_header
        height = interface.tip

        b = blockchain.check_header(header) # Does it match the hash of a known header.
        if b:
            interface.blockchain = b
            self.switch_lagging_interface()
            self.notify('blockchain_updated')
            self.notify('interfaces')
            return
        b = blockchain.can_connect(header) # Is it the next header on a given blockchain.
        if b:
            interface.blockchain = b
            b.save_header(header)
            self.switch_lagging_interface()
            self.notify('blockchain_updated')
            self.notify('interfaces')
            return

        heights = [x.height() for x in self.blockchains.values()]
        tip = max(heights)
        if tip > networks.net.VERIFICATION_BLOCK_HEIGHT:
            interface.print_error("attempt to reconcile longest chain tip={} heights={}".format(tip, heights))
            interface.set_mode(Interface.MODE_BACKWARD)
            interface.bad = height
            interface.bad_header = header
            self.request_header(interface, min(tip, height - 1))
        else:
            interface.print_error("attempt to catch up tip={} heights={}".format(tip, heights))
            chain = self.blockchains[0]
            if chain.catch_up is None:
                chain.catch_up = interface
                interface.set_mode(Interface.MODE_CATCH_UP)
                interface.blockchain = chain
                interface.print_error("switching to catchup mode", tip)
                self.request_header(interface, networks.net.VERIFICATION_BLOCK_HEIGHT + 1)
            else:
                interface.print_error("chain already catching up with", chain.catch_up.server)

    def request_initial_proof_and_headers(self, interface):
        # This will be the initial topmost header response.  But we might get new blocks.
        if interface.server not in self.checkpoint_servers_verified:
            interface.print_error("request_initial_proof_and_headers pending")

            top_height = self.checkpoint_height
            # If there is no known checkpoint height for this network, we look to get
            # a given number of confirmations for the same conservative height.
            if self.checkpoint_height is None:
                self.checkpoint_height = interface.tip - 100
            self.checkpoint_servers_verified[interface.server] = { 'root': None, 'height': self.checkpoint_height }
            # We need at least 147 headers before the post checkpoint headers for daa calculations.
            self._request_headers(interface, self.checkpoint_height - 147 + 1, 147, self.checkpoint_height)
        else:
            # We already have them verified, maybe we got disconnected.
            interface.print_error("request_initial_proof_and_headers bypassed")
            interface.set_mode(Interface.MODE_DEFAULT)
            self._process_latest_tip(interface)

    def apply_successful_verification(self, interface, checkpoint_height, checkpoint_root):
        known_roots = [ v['root'] for v in self.checkpoint_servers_verified.values() if v['root'] is not None ]
        if len(known_roots) > 0 and checkpoint_root != known_roots[0]:
            interface.print_error("server sent inconsistent root '{}'".format(checkpoint_root))
            self.connection_down(interface.server)
            return False
        self.checkpoint_servers_verified[interface.server]['root'] = checkpoint_root

        # rt12 --- checkpoint generation currently disabled.
        if False:
            interface.print_error("received verification {}".format(self.verifications_required))
            self.verifications_required -= 1
            if self.verifications_required > 0:
                return False

            if networks.net.VERIFICATION_BLOCK_HEIGHT is None:
                networks.net.VERIFICATION_BLOCK_HEIGHT = checkpoint_height
                networks.net.VERIFICATION_BLOCK_MERKLE_ROOT = checkpoint_root

                network_name = "TESTNET" if networks.net.TESTNET else "MAINNET"
                self.print_error("found verified checkpoint for {} at height {} with merkle root {!r}".format(network_name, checkpoint_height, checkpoint_root))

        if not self.verified_checkpoint:
            self.init_headers_file()
            self.verified_checkpoint = True

        # rt12 --- checkpoint generation currently disabled.
        if False:
            with self.interface_lock:
                interfaces = list(self.interfaces.values())
            for interface_entry in interfaces:
                interface_entry.blockchain = self.blockchains[0]
                interface_entry.set_mode(Interface.MODE_DEFAULT)

        interface.print_error("server was verified correctly")
        interface.set_mode(Interface.MODE_DEFAULT)
        return True

    def validate_checkpoint_result(self, interface, merkle_root, merkle_branch, header, header_height):
        """
        header: hex representation of the block header.
        merkle_root: hex representation of the server's calculated merkle root.
        branch: list of hex representations of the server's calculated merkle root branches.

        Returns a boolean to represent whether the server's proof is correct.
        """
        received_merkle_root = bytes(reversed(bfh(merkle_root)))
        if networks.net.VERIFICATION_BLOCK_MERKLE_ROOT:
            expected_merkle_root = bytes(reversed(bfh(networks.net.VERIFICATION_BLOCK_MERKLE_ROOT)))
        else:
            expected_merkle_root = received_merkle_root

        if received_merkle_root != expected_merkle_root:
            interface.print_error("Sent unexpected merkle root, expected: {}, got: {}".format(networks.net.VERIFICATION_BLOCK_MERKLE_ROOT, merkle_root))
            return False

        header_hash = Hash(bfh(header))
        byte_branches = [ bytes(reversed(bfh(v))) for v in merkle_branch ]
        proven_merkle_root = blockchain.root_from_proof(header_hash, byte_branches, header_height)
        if proven_merkle_root != expected_merkle_root:
            interface.print_error("Sent incorrect merkle branch, expected: {}, proved: {}".format(networks.net.VERIFICATION_BLOCK_MERKLE_ROOT, util.hfu(reversed(proven_merkle_root))))
            return False

        return True

    def blockchain(self):
        with self.interface_lock:
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
                    self.switch_to_interface(i.server, self.SWITCH_FOLLOW_CHAIN)
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
            raise util.TimeoutException('Server did not answer')
        if r.get('error'):
            raise util.ServerError(r.get('error'))
        return r.get('result')

    def get_raw_tx_for_txid(self, txid, timeout=30):
        """ Used by UI code to retrieve a transaction from the blockchain by
        txid.  (Qt Gui: Tools -> Load transaction -> From the blockchain)

        param: txid, a transaction hash
        returns: tuple(True, raw_tx) on success
                 tuple(False, error_msg) on failure.

                 error_msg is suitable to be displayed in a UI as it is not
                 a server string, but rather an error based on what the server
                 replied with (with a generic fallback message is used
                 if the server message is not recognized). """
        txid = str(txid).strip()
        try:
            r = self.synchronous_get(('blockchain.transaction.get',[txid]), timeout=timeout)
            return True, r
        except BaseException as e:
            self.print_error("Exception retrieving transaction for '{}': {}".format(txid, repr(e)))
            msg = str(e).lower().strip()
            if 'should be a transaction hash' in msg:
                msg = _("Input data is not a transaction hash.")
            elif 'still in the process of being indexed' in msg:
                msg = _("This server is still indexing transactions. You should switch to another server for now.")
            elif 'no such' in msg:
                msg = _("No such mempool or blockchain transaction exists.")
            elif 'did not answer' in msg:
                msg = _("The server did not answer; network may be down.")
            else:
                # fall back to something generic.
                msg = _("Could not retrieve transaction for the specified hash.")
            return False, msg

    @staticmethod
    def __wait_for(it, timeout=30):
        """Wait for the result of calling lambda `it`.
           Will raise util.TimeoutException or util.ServerErrorResponse on failure."""
        q = queue.Queue()
        it(q.put)
        try:
            result = q.get(block=True, timeout=(timeout or 0.010)) # does not support non-blocking
        except queue.Empty:
            raise util.TimeoutException(_('Server did not answer'))

        if result.get('error'):
            raise util.ServerErrorResponse(_("Server returned an error response"), result.get('error'))

        return result.get('result')

    @staticmethod
    def __with_default_synchronous_callback(invocation, callback):
        """ Use this method if you want to make the network request
        synchronous. """
        if not callback:
            return Network.__wait_for(invocation)

        invocation(callback)

    def broadcast_transaction(self, transaction, callback=None):
        """ This is the legacy EC/Electrum API that we still need to support
        for plugins and other code, but it has been improved to not allow for
        phishing attacks by calling broadcast_transaction2 which actually
        deduces a more intelligent and phishing-proof error message.
        If you want the actual server response, use broadcast_transaction2 and
        catch exceptions. """

        if callback:
            command = 'blockchain.transaction.broadcast'
            self.send([(command, [str(transaction)])], callback)
            return

        try:
            out = self.broadcast_transaction2(transaction)
        except BaseException as e: #catch-all. May be util.TimeoutException, util.ServerError subclass or other.
            return False, "error: " + str(e) # Ergh. To remain compatible with old code we prepend this ugly "error: "

        return True, out

    def broadcast_transaction2(self, transaction, timeout=30):
        """ Very similar to broadcast_transation() but it actually tells calling
        code what the nature of the error was in a more explicit manner by
        raising an Exception. Normally a util.TimeoutException,
        util.TxHashMismatch, or util.ServerErrorResonse is raised on broadcast
        error or warning. TxHashMismatch indicates the broadcast succeeded
        but that the tx hash returned by the server does not match the tx hash
        of the specified transaction. All other exceptions indicate no broadcast
        has successfully occurred.
        Does not support using a callback function."""

        command = 'blockchain.transaction.broadcast'
        invocation = lambda c: self.send([(command, [str(transaction)])], c)

        try:
            out = Network.__wait_for(invocation, timeout=timeout) # may raise util.TimeoutException, util.ServerErrorResponse
        except util.ServerErrorResponse as e:
            # rephrase the generic message to something more suitable
            self.print_error("Server error response was:", str(e.server_msg))
            raise util.ServerErrorResponse(Network.transmogrify_broadcast_response_for_gui(e.server_msg), e.server_msg)

        if out != transaction.txid():
            self.print_error("Server replied with a mismatching txid:", str(out))
            raise util.TxHashMismatch(_("Server response does not match signed transaction ID."), str(out))

        return out

    @staticmethod
    def transmogrify_broadcast_response_for_gui(server_msg):
        # NB: the server_msg is usually a dict but not always.
        # Unfortunately, ElectrumX doesn't return a good error code. It's always '1'.
        # So, we must use substring matching to grok the error message.
        # We do NOT ever want to print to the user the server message as this has potential for a phishing exploit.
        # See: https://github.com/spesmilo/electrum/issues/4968
        # So.. these messages mostly come from groking the source code of BU and Bitcoin ABC. If that fails,
        # a generic error string is returned.
        if not isinstance(server_msg, str):
            server_msg = str(server_msg)
        server_msg = server_msg.replace("\n", r"\n") # replace \n with slash-n because dict does this.
        if r'dust' in server_msg:
            dust_thold = 546
            try:
                from .wallet import dust_threshold
                dust_thold = dust_threshold(Network.get_instance())
            except: pass
            return _("Transaction could not be broadcast due to dust outputs (dust threshold is {} satoshis).").format(dust_thold)
        elif r'Missing inputs' in server_msg or r'Inputs unavailable' in server_msg or r"bad-txns-inputs-spent" in server_msg or r"bad-txns-inputs-missingorspent" in server_msg:
            return _("Transaction could not be broadcast due to missing, already-spent, or otherwise invalid inputs.")
        elif r"transaction already in block chain" in server_msg:
            # We get this message whenever any of this transaction's outputs are already in confirmed utxo set (and are unspent).
            # For confirmed txn with all outputs already spent, we will see "missing inputs" instead.
            return _("The transaction already exists in the blockchain.")
        elif r'insufficient priority' in server_msg or r'rate limited free transaction' in server_msg or r'min relay fee not met' in server_msg:
            return _("The transaction was rejected due to paying insufficient fees.")
        elif r'mempool min fee not met' in server_msg or r"mempool full" in server_msg:
            return _("The transaction was rejected due to paying insufficient fees (possibly due to network congestion).")
        elif r'bad-txns-premature-spend-of-coinbase' in server_msg:
            return _("Transaction could not be broadcast due to an attempt to spend a coinbase input before maturity.")
        elif r"txn-already-in-mempool" in server_msg or r"txn-already-known" in server_msg:
            return _("The transaction already exists in the server's mempool.")
        elif r"txn-mempool-conflict" in server_msg:
            return _("The transaction conflicts with a transaction already in the server's mempool.")
        elif r'too-long-mempool-chain' in server_msg:
            return _("The transaction was rejected due to having too many mempool ancestors. Wait for confirmations and try again.")
        elif r"bad-txns-nonstandard-inputs" in server_msg:
            return _("The transaction was rejected due to its use of non-standard inputs.")
        elif r"absurdly-high-fee" in server_msg:
            return _("The transaction was rejected because it specifies an absurdly high fee.")
        elif r"non-mandatory-script-verify-flag" in server_msg or r"mandatory-script-verify-flag-failed" in server_msg or r"upgrade-conditional-script-failure" in server_msg:
            return _("The transaction was rejected due to an error in script execution.")
        elif r"tx-size" in server_msg or r"bad-txns-oversize" in server_msg:
            return _("The transaction was rejected because it is too large (in bytes).")
        elif r"scriptsig-size" in server_msg:
            return _("The transaction was rejected because it contains a script that is too large.")
        elif r"scriptpubkey" in server_msg:
            return _("The transaction was rejected because it contains a non-standard output script.")
        elif r"bare-multisig" in server_msg:
            return _("The transaction was rejected because it contains a bare multisig output.")
        elif r"multi-op-return" in server_msg:
            return _("The transaction was rejected because it contains multiple OP_RETURN outputs.")
        elif r"scriptsig-not-pushonly" in server_msg:
            return _("The transaction was rejected because it contains non-push-only script sigs.")
        elif r'bad-txns-nonfinal' in server_msg or r'non-BIP68-final' in server_msg:
            return _("The transaction was rejected because it is not considered final according to network rules.")
        elif r"bad-txns-too-many-sigops" in server_msg or r"bad-txn-sigops" in server_msg:
            # std limit is 4000; this is basically impossible to reach on mainnet using normal txes, due to the 100kB size limit.
            return _("The transaction was rejected because it contains too many signature-check opcodes.")
        elif r"bad-txns-inputvalues-outofrange" in server_msg or r"bad-txns-vout-negative" in server_msg or r"bad-txns-vout-toolarge" in server_msg or r"bad-txns-txouttotal-toolarge" in server_msg:
            return _("The transaction was rejected because its amounts are out of range.")
        elif r"bad-txns-in-belowout" in server_msg or r"bad-txns-fee-outofrange" in server_msg:
            return _("The transaction was rejected because it pays a negative or huge fee.")
        elif r"bad-tx-coinbase" in server_msg:
            return _("The transaction was rejected because it is a coinbase transaction.")
        elif r"bad-txns-prevout-null" in server_msg or r"bad-txns-inputs-duplicate" in server_msg:
            return _("The transaction was rejected because it contains null or duplicate inputs.")
        elif r"bad-txns-vin-empty" in server_msg or r"bad-txns-vout-empty" in server_msg:
            return _("The transaction was rejected because it is has no inputs or no outputs.")
        elif r"bad-txns-undersize" in server_msg:
            return _("The transaction was rejected because it is too small.")
        elif r'version' in server_msg:
            return _("The transaction was rejected because it uses a non-standard version.")
        elif r'TX decode failed' in server_msg:
            return _("The transaction could not be decoded.")
        return _("An error occurred broadcasting the transaction")

    # Used by the verifier job.
    def get_merkle_for_transaction(self, tx_hash, tx_height, callback, max_qlen=10):
        """ Asynchronously enqueue a request for a merkle proof for a tx.
            Note that the callback param is required.
            May return None if too many requests were enqueued (max_qlen) or
            if there is no interface.
            Client code should handle the None return case appropriately. """
        return self.queue_request('blockchain.transaction.get_merkle',
                                  [tx_hash, tx_height],
                                  callback=callback, max_qlen=max_qlen)

    def get_proxies(self):
        """ Returns a proxies dictionary suitable to be passed to the requests
            module, or None if no proxy is set for this instance. """
        proxy = self.proxy and self.proxy.copy() # retain a copy in case another thread messes with it
        if proxy:
            pre = ''
            # proxies format for requests lib is eg:
            # {
            #   'http'  : 'socks[45]://user:password@host:port',
            #   'https' : 'socks[45]://user:password@host:port'
            # }
            # with user:password@ being omitted if no user/password.
            if proxy.get('user') and proxy.get('password'):
                pre = '{}:{}@'.format(proxy.get('user'), proxy.get('password'))
            mode = proxy.get('mode')
            if mode and mode.lower() == "socks5":
                mode += 'h' # socks5 with hostname resolution on the server side so it works with tor & even onion!
            socks = '{}://{}{}:{}'.format(mode, pre, proxy.get('host'), proxy.get('port'))
            proxies = { # transform it to requests format
                'http' : socks,
                'https' : socks
            }
            return proxies
        return None

    def on_bad_certificate(self, server, certificate):
        if server in self.bad_certificate_servers:
            return
        self.bad_certificate_servers[server] = certificate
        self.server_list_updated()

    def remove_bad_certificate(self, server):
        if server not in self.bad_certificate_servers:
            return
        del self.bad_certificate_servers[server]
        self.server_list_updated()

    def remove_pinned_certificate(self, server):
        cert_file = self.bad_certificate_servers.get(server)
        if not cert_file:
            return False

        try:
            os.unlink(cert_file)
            self.print_error("Removed pinned certificate:", cert_file)
        except OSError as e:
            self.print_error("Could not remove pinned certificate:", cert_file, repr(e))
            if os.path.exists(cert_file):
                # Don't remove from bad certificate list if we failed to unpin
                return False
        self.remove_bad_certificate(server)
        return True


    def server_is_bad_certificate(self, server): return server in self.bad_certificate_servers

    def server_set_blacklisted(self, server, b, save=True, skip_connection_logic=False):
        assert isinstance(server, str)
        if b:
            self.blacklisted_servers |= {server}
        else:
            self.blacklisted_servers -= {server}
        self.config.set_key("server_blacklist", list(self.blacklisted_servers), save)
        if b and not skip_connection_logic and server in self.interfaces:
            self.connection_down(server, False) # if blacklisting, this disconnects (if we were connected)

    def server_is_blacklisted(self, server): return server in self.blacklisted_servers

    def server_set_whitelisted(self, server, b, save=True):
        assert isinstance(server, str)
        adds = set(self.config.get('server_whitelist_added', []))
        rems = set(self.config.get('server_whitelist_removed', []))
        is_hardcoded = server in self._hardcoded_whitelist
        s = {server} # make a set so |= and -= work
        len0 = len(self.whitelisted_servers)
        if b:
            # the below logic keeps the adds list from containing redundant 'whitelisted' servers that are already defined in servers.json
            # it also makes it so that if the developers remove a server from servers.json, it goes away from the whitelist automatically.
            if is_hardcoded:
                adds -= s # it's in the hardcoded list anyway, remove it from adds to keep adds from being redundant
            else:
                adds |= s # it's not a hardcoded server, add it to 'adds'
            rems -= s
            self.whitelisted_servers |= s
        else:
            adds -= s
            if is_hardcoded:
                rems |= s # it's in the hardcoded set, so it needs to explicitly be added to the 'rems' set to be taken out of the dynamically computed whitelist (_compute_whitelist())
            else:
                rems -= s # it's not in the hardcoded list, so no need to add it to the rems as it will be not whitelisted on next run since it's gone from 'adds'
            self.whitelisted_servers -= s
        if len0 != len(self.whitelisted_servers):
            # it changed. So re-cache hostmap which we use as an argument to pick_random_server() elsewhere in this class
            self.whitelisted_servers_hostmap = servers_to_hostmap(self.whitelisted_servers)
        self.config.set_key('server_whitelist_added', list(adds), save)
        self.config.set_key('server_whitelist_removed', list(rems), save)

    def server_is_whitelisted(self, server): return server in self.whitelisted_servers

    def _compute_whitelist(self):
        if not hasattr(self, '_hardcoded_whitelist'):
            self._hardcoded_whitelist = frozenset(hostmap_to_servers(networks.net.DEFAULT_SERVERS))
        ret = set(self._hardcoded_whitelist)
        ret |= set(self.config.get('server_whitelist_added', [])) # this key is all the servers that weren't in the hardcoded whitelist that the user explicitly added
        ret -= set(self.config.get('server_whitelist_removed', [])) # this key is all the servers that were hardcoded in the whitelist that the user explicitly removed
        return ret, servers_to_hostmap(ret)

    def is_whitelist_only(self):
        return bool(self.config.get('whitelist_servers_only', DEFAULT_WHITELIST_SERVERS_ONLY))

    def set_whitelist_only(self, b):
        if bool(b) == self.is_whitelist_only():
            return # disallow redundant/noop calls
        self.config.set_key('whitelist_servers_only', b, True)
        if b:
            with self.interface_lock:
                # now, disconnect from all non-whitelisted servers
                for s in self.interfaces.copy():
                    if s not in self.whitelisted_servers:
                        self.connection_down(s)
