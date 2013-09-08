import interface
from blockchain import Blockchain
import threading, time, Queue, os, sys, shutil
from util import user_dir, appdata_dir, print_error
from bitcoin import *


class Network(threading.Thread):

    def __init__(self, config):
        threading.Thread.__init__(self)
        self.daemon = True
        self.config = config
        self.lock = threading.Lock()
        self.blockchain = Blockchain(config)
        self.interfaces = {}
        self.queue = Queue.Queue()
        self.default_server = self.config.get('server')
        self.servers_list = interface.filter_protocol(interface.DEFAULT_SERVERS,'s')



    def start_interfaces(self):

        for server in self.servers_list:
            self.interfaces[server] = interface.Interface({'server':server})

        for i in self.interfaces.values():
            i.start(self.queue)

        if self.default_server:
            self.interface = interface.Interface({'server':self.default_server})
            self.interface.start(self.queue)
        else:
            self.interface = self.interfaces[0]






    def run(self):
        self.blockchain.start()
        self.start_interfaces()

        with self.lock:
            self.running = True

        while self.is_running():
            i = self.queue.get()

            if i.is_connected:
                i.register_channel('verifier', self.blockchain.queue)
                i.register_channel('get_header')
                i.send([ ('blockchain.headers.subscribe',[])], 'verifier')
                if i == self.interface:
                    i.send([('server.banner',[])])
                    i.send([('server.peers.subscribe',[])])
            else:
                self.interfaces.pop(i.server)
                if i == self.interface:
                    if self.default_server is None:
                        print_msg("Using random server...")
                        server = random.choice( self.servers_list )
                        self.interface = interface.Interface({'server':self.default_server})
                    else:
                        #i.trigger_callback('disconnected')
                        pass

    def on_peers(self, resut):
        pass

    def on_banner(self, result):
        pass

    def stop(self):
        with self.lock: self.running = False

    def is_running(self):
        with self.lock: return self.running


    def resend_subscriptions(self):
        for channel, messages in self.subscriptions.items():
            if messages:
                self.send(messages, channel)


    def auto_cycle(self):
        if not self.is_connected and self.config.get('auto_cycle'):
            print_msg("Using random server...")
            servers = filter_protocol(DEFAULT_SERVERS, 's')
            while servers:
                server = random.choice( servers )
                servers.remove(server)
                print server
                self.config.set_key('server', server, False)
                self.init_with_server(self.config)
                if self.is_connected: break

            if not self.is_connected:
                print 'no server available'
                self.connect_event.set() # to finish start
                self.server = 'ecdsa.org:50001:t'
                self.proxy = None
                return




if __name__ == "__main__":
    import simple_config
    config = simple_config.SimpleConfig({'verbose':True})
    network = Network(config)
    network.start()

    while 1:
        time.sleep(1)



