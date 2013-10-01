import threading, time, Queue, os, sys, shutil, random
from util import user_dir, appdata_dir, print_error, print_msg
from bitcoin import *
import interface
from blockchain import Blockchain

DEFAULT_PORTS = {'t':'50001', 's':'50002', 'h':'8081', 'g':'8082'}

DEFAULT_SERVERS = {
    'the9ull.homelinux.org': {'h': '8082', 't': '50001'},
    'electrum.coinwallet.me': {'h': '8081', 's': '50002', 't': '50001', 'g': '8082'},
    'electrum.dynaloop.net': {'h': '8081', 's': '50002', 't': '50001', 'g': '8082'},
    'electrum.koh.ms': {'h': '8081', 's': '50002', 't': '50001', 'g': '8082'},
    'electrum.novit.ro': {'h': '8081', 's': '50002', 't': '50001', 'g': '8082'},
    'electrum.stepkrav.pw': {'h': '8081', 's': '50002', 't': '50001', 'g': '8082'},
    'ecdsa.org': {'h': '8081', 's': '50002', 't': '50001', 'g': '8082'},
    'electrum.mooo.com': {'h': '8081', 't': '50001'},
    'electrum.bitcoins.sk': {'h': '8081', 's': '50002', 't': '50001', 'g': '8'},
    'electrum.no-ip.org': {'h': '80', 's': '50002', 't': '50001', 'g': '443'},
    'electrum.drollette.com': {'h': '8081', 's': '50002', 't': '50001', 'g': '8082'},
    'btc.it-zone.org': {'h': '80', 's': '110', 't': '50001', 'g': '443'},
    'electrum.yacoin.com': {'h': '8081', 's': '50002', 't': '50001', 'g': '8082'},
    'electrum.be': {'h': '8081', 's': '50002', 't': '50001', 'g': '8082'}
}



def filter_protocol(servers, p):
    l = []
    for k, protocols in servers.items():
        if p in protocols:
            l.append( ':'.join([k, protocols[p], p]) )
    return l
    

def pick_random_server():
    return random.choice( filter_protocol(DEFAULT_SERVERS,'s') )


class Network(threading.Thread):

    def __init__(self, config):
        threading.Thread.__init__(self)
        self.daemon = True
        self.config = config
        self.lock = threading.Lock()
        self.blockchain = Blockchain(config, self)
        self.interfaces = {}
        self.queue = Queue.Queue()
        self.default_server = self.config.get('server')
        self.disconnected_servers = []
        self.callbacks = {}
        self.servers = []
        self.banner = ''
        self.interface = None
        self.proxy = self.config.get('proxy')
        self.heights = {}


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
        l = filter_protocol(self.get_servers(), 's')
        for s in l:
            if s in self.disconnected_servers or s in self.interfaces.keys():
                continue
            else:
                choice_list.append(s)
        
        if not choice_list: return
        
        server = random.choice( choice_list )
        return server


    def get_servers(self):
        if not self.servers:
            return DEFAULT_SERVERS
        else:
            return self.servers


    def start_interface(self, server):
        if server in self.interfaces.keys():
            return
        i = interface.Interface({'server':server, 'path':self.config.path, 'proxy':self.proxy})
        self.interfaces[server] = i
        i.start(self.queue)

    def start_random_interface(self):
        server = self.random_server()
        if server:
            self.start_interface(server)

    def start_interfaces(self):
        if self.default_server:
            self.start_interface(self.default_server)
            self.interface = self.interfaces[self.default_server]

        for i in range(8):
            self.start_random_interface()
            
        if not self.interface:
            self.interface = self.interfaces.values()[0]


    def start(self, wait=False):
        self.start_interfaces()
        threading.Thread.start(self)
        if wait:
            self.interface.connect_event.wait()
            return self.interface.is_connected


    def set_server(self, server, proxy):
        if self.default_server == server:
            return

        i = self.interface
        self.default_server = server
        self.proxy = proxy
        self.start_interface(server)
        self.interface = self.interfaces[server]
        i.stop_subscriptions() # fixme: it should not stop all subscriptions, and send 'unsubscribe'
        self.trigger_callback('disconnecting') # for actively disconnecting


    def run(self):
        self.blockchain.start()

        with self.lock:
            self.running = True

        while self.is_running():
            i = self.queue.get()

            if i.is_connected:
                i.send([ ('blockchain.headers.subscribe',[])], self.on_header)
                if i == self.interface:
                    i.send([('server.banner',[])], self.on_banner)
                    i.send([('server.peers.subscribe',[])], self.on_peers)
                    self.trigger_callback('connected')
            else:
                self.disconnected_servers.append(i.server)
                self.interfaces.pop(i.server)
                self.start_random_interface()
                
                if i == self.interface:
                    if self.config.get('auto_cycle'):
                        self.interface = random.choice(self.interfaces.values())
                        self.config.set_key('server', self.interface.server, False)
                    else:
                        self.trigger_callback('disconnected')
                
    def on_header(self, i, r):
        result = r.get('result')
        if not result: return
        self.heights[i.server] = result.get('block_height')
        self.blockchain.queue.put((i,result))

    def on_peers(self, i, r):
        if not r: return
        self.servers = self.parse_servers(r.get('result'))
        self.trigger_callback('peers')

    def on_banner(self, i, r):
        self.banner = r.get('result')
        self.trigger_callback('banner')

    def stop(self):
        with self.lock: self.running = False

    def is_running(self):
        with self.lock: return self.running

    
    def retrieve_transaction(self, tx_hash, tx_height=0):
        import transaction
        r = self.interface.synchronous_get([ ('blockchain.transaction.get',[tx_hash, tx_height]) ])[0]
        if r:
            return transaction.Transaction(r)


    def parse_servers(self, result):
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
            except:
                is_recent = False

            if out and is_recent:
                out['pruning'] = pruning_level
                servers[host] = out

        return servers




if __name__ == "__main__":
    import simple_config
    config = simple_config.SimpleConfig({'verbose':True, 'server':'ecdsa.org:50002:s'})
    network = Network(config)
    network.start()

    while 1:
        time.sleep(1)



