import threading, time, Queue, os, sys, shutil, random
from util import user_dir, appdata_dir, print_error, print_msg
from bitcoin import *
import interface
from blockchain import Blockchain

DEFAULT_PORTS = {'t':'50001', 's':'50002', 'h':'8081', 'g':'8082'}

DEFAULT_SERVERS = {
    'ecdsa.org': DEFAULT_PORTS,
    'ecdsa.net': DEFAULT_PORTS,
    'electrum.hachre.de': DEFAULT_PORTS,
    'electrum.novit.ro': DEFAULT_PORTS,
    'electrum.coinwallet.me': DEFAULT_PORTS,
    'cube.l0g.in': DEFAULT_PORTS,
    'bitcoin.epicinet.net': DEFAULT_PORTS,
    'h.1209k.com': DEFAULT_PORTS,
    'electrum.electricnewyear.net': DEFAULT_PORTS,
    'erbium.sytes.net': DEFAULT_PORTS,
    'e2.pdmc.net':DEFAULT_PORTS,
    'electrum.no-ip.org':{'h': '80', 's': '50002', 't': '50001', 'g': '443'},
    'electrum.thwg.org':DEFAULT_PORTS,
    'electrum.stepkrav.pw':DEFAULT_PORTS,
}


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
            l.append( ':'.join([k, protocols[p], p]) )
    return l
    

def pick_random_server(p='s'):
    return random.choice( filter_protocol(DEFAULT_SERVERS,p) )

from simple_config import SimpleConfig

class Network(threading.Thread):

    def __init__(self, config = {}):
        threading.Thread.__init__(self)
        self.daemon = True
        self.config = SimpleConfig(config) if type(config) == type({}) else config
        self.lock = threading.Lock()
        self.num_server = 8 if not self.config.get('oneserver') else 0
        self.blockchain = Blockchain(self.config, self)
        self.interfaces = {}
        self.queue = Queue.Queue()
        self.callbacks = {}
        self.protocol = self.config.get('protocol','s')
        self.running = False

        # Server for addresses and transactions
        self.default_server = self.config.get('server')
        if not self.default_server:
            self.default_server = pick_random_server(self.protocol)

        self.irc_servers = [] # returned by interface (list from irc)
        self.pending_servers = set([])
        self.disconnected_servers = set([])
        self.recent_servers = self.config.get('recent_servers',[]) # successful connections

        self.banner = ''
        self.interface = None
        self.proxy = self.config.get('proxy')
        self.heights = {}
        self.merkle_roots = {}
        self.utxo_roots = {}
        self.server_lag = 0

        dir_path = os.path.join( self.config.path, 'certs')
        if not os.path.exists(dir_path):
            os.mkdir(dir_path)

        # default subscriptions
        self.subscriptions = {}
        self.subscriptions[self.on_banner] = [('server.banner',[])]
        self.subscriptions[self.on_peers] = [('server.peers.subscribe',[])]


    def is_connected(self):
        return self.interface and self.interface.is_connected


    def is_up_to_date(self):
        return self.interface.is_up_to_date()


    def main_server(self):
        return self.interface.server


    def send_subscriptions(self):
        for cb, sub in self.subscriptions.items():
            self.interface.send(sub, cb)


    def subscribe(self, messages, callback):
        with self.lock:
            if self.subscriptions.get(callback) is None: 
                self.subscriptions[callback] = []
            for message in messages:
                if message not in self.subscriptions[callback]:
                    self.subscriptions[callback].append(message)

        if self.is_connected():
            self.interface.send( messages, callback )


    def send(self, messages, callback):
        if self.is_connected():
            self.interface.send( messages, callback )
            return True
        else:
            return False


    def register_callback(self, event, callback):
        with self.lock:
            if not self.callbacks.get(event):
                self.callbacks[event] = []
            self.callbacks[event].append(callback)


    def trigger_callback(self, event):
        with self.lock:
            callbacks = self.callbacks.get(event,[])[:]
        if callbacks:
            [callback() for callback in callbacks]


    def random_server(self):
        choice_list = []
        l = filter_protocol(self.get_servers(), self.protocol)
        for s in l:
            if s in self.pending_servers or s in self.disconnected_servers or s in self.interfaces.keys():
                continue
            else:
                choice_list.append(s)
        
        if not choice_list: 
            if not self.interfaces:
                # we are probably offline, retry later
                self.disconnected_servers = set([])
            return
        
        server = random.choice( choice_list )
        return server


    def get_servers(self):
        if self.irc_servers:
            out = self.irc_servers  
        else:
            out = DEFAULT_SERVERS
            for s in self.recent_servers:
                host, port, protocol = s.split(':')
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
            

    def start(self, wait=False):
        self.start_interfaces()
        threading.Thread.start(self)
        if wait:
            return self.wait_until_connected()

    def wait_until_connected(self):
        "wait until connection status is known"
        if self.config.get('auto_cycle'): 
            # self.random_server() returns None if all servers have been tried
            while not self.is_connected() and self.random_server():
                time.sleep(0.1)
        else:
            self.interface.connect_event.wait()

        return self.interface.is_connected


    def set_parameters(self, host, port, protocol, proxy, auto_connect):

        self.config.set_key('auto_cycle', auto_connect, True)
        self.config.set_key("proxy", proxy, True)
        self.config.set_key("protocol", protocol, True)
        server = ':'.join([ host, port, protocol ])
        self.config.set_key("server", server, True)

        if self.proxy != proxy or self.protocol != protocol:
            self.proxy = proxy
            self.protocol = protocol
            for i in self.interfaces.values(): i.stop()
            if auto_connect:
                #self.interface = None
                return

        if auto_connect:
            if not self.interface.is_connected:
                self.switch_to_random_interface()
            else:
                if self.server_lag > 0:
                    self.stop_interface()
        else:
            self.set_server(server)


    def switch_to_random_interface(self):
        if self.interfaces:
            self.switch_to_interface(random.choice(self.interfaces.values()))

    def switch_to_interface(self, interface):
        assert not self.interface.is_connected
        server = interface.server
        print_error("switching to", server)
        self.interface = interface
        h =  self.heights.get(server)
        if h:
            self.server_lag = self.blockchain.height() - h
        self.config.set_key('server', server, False)
        self.default_server = server
        self.send_subscriptions()
        self.trigger_callback('connected')


    def stop_interface(self):
        self.interface.stop() 


    def set_server(self, server):
        if self.default_server == server and self.interface.is_connected:
            return

        if self.protocol != server.split(':')[2]:
            return

        # stop the interface in order to terminate subscriptions
        if self.interface.is_connected:
            self.stop_interface()

        # notify gui
        self.trigger_callback('disconnecting')
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
        self.config.set_key('recent_servers', self.recent_servers)


    def new_blockchain_height(self, blockchain_height, i):
        if self.is_connected():
            h = self.heights.get(self.interface.server)
            if h:
                self.server_lag = blockchain_height - h
                if self.server_lag > 1:
                    print_error( "Server is lagging", blockchain_height, h)
                    if self.config.get('auto_cycle'):
                        self.set_server(i.server)
            else:
                print_error('no height for main interface')
        
        self.trigger_callback('updated')


    def run(self):
        self.blockchain.start()

        with self.lock:
            self.running = True

        while self.is_running():
            try:
                i = self.queue.get(timeout = 30 if self.interfaces else 3)
            except Queue.Empty:
                if len(self.interfaces) < self.num_server:
                    self.start_random_interface()
                continue

            if i.server in self.pending_servers:
                self.pending_servers.remove(i.server)

            if i.is_connected:
                #if i.server in self.interfaces: raise
                self.interfaces[i.server] = i
                self.add_recent_server(i)
                i.send([ ('blockchain.headers.subscribe',[])], self.on_header)
                if i == self.interface:
                    print_error('sending subscriptions to', self.interface.server)
                    self.send_subscriptions()
                    self.trigger_callback('connected')
            else:
                self.disconnected_servers.add(i.server)
                if i.server in self.interfaces:
                    self.interfaces.pop(i.server)
                if i.server in self.heights:
                    self.heights.pop(i.server)
                if i == self.interface:
                    #self.interface = None
                    self.trigger_callback('disconnected')

            if not self.interface.is_connected and self.config.get('auto_cycle'):
                self.switch_to_random_interface()


    def on_header(self, i, r):
        result = r.get('result')
        if not result: return
        height = result.get('block_height')
        self.heights[i.server] = height
        self.merkle_roots[i.server] = result.get('merkle_root')
        self.utxo_roots[i.server] = result.get('utxo_root')
        # notify blockchain about the new height
        self.blockchain.queue.put((i,result))

        if i == self.interface:
            self.server_lag = self.blockchain.height() - height
            if self.server_lag > 1 and self.config.get('auto_cycle'):
                print_error( "Server lagging, stopping interface")
                self.stop_interface()

            self.trigger_callback('updated')


    def on_peers(self, i, r):
        if not r: return
        self.irc_servers = parse_servers(r.get('result'))
        self.trigger_callback('peers')

    def on_banner(self, i, r):
        self.banner = r.get('result')
        self.trigger_callback('banner')

    def stop(self):
        with self.lock: self.running = False

    def is_running(self):
        with self.lock: return self.running

    
    def synchronous_get(self, requests, timeout=100000000):
        return self.interface.synchronous_get(requests)


    def get_header(self, tx_height):
        return self.blockchain.read_header(tx_height)

    def get_local_height(self):
        return self.blockchain.height()



    #def retrieve_transaction(self, tx_hash, tx_height=0):
    #    import transaction
    #    r = self.synchronous_get([ ('blockchain.transaction.get',[tx_hash, tx_height]) ])[0]
    #    if r:
    #        return transaction.Transaction(r)





if __name__ == "__main__":
    network = NetworkProxy({})
    network.start()
    print network.get_servers()

    q = Queue.Queue()
    network.send([('blockchain.headers.subscribe',[])], q.put)
    while True:
        r = q.get(timeout=10000)
        print r

