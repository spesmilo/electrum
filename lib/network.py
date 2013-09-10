import threading, time, Queue, os, sys, shutil, random
from util import user_dir, appdata_dir, print_error, print_msg
from bitcoin import *
import interface
from blockchain import Blockchain


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
        self.callbacks = {}


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
        if len(self.servers_list) <= len(self.interfaces.keys()):
            return
        
        while True:
            server = random.choice( self.servers_list )
            if server not in self.interfaces.keys(): break

        return server


    def start_interface(self, server):
        if server in self.interfaces.keys():
            return
        i = interface.Interface({'server':server})
        i.network = self # fixme
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


    def run(self):
        self.blockchain.start()

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
                self.servers_list.remove(i.server)
                self.interfaces.pop(i.server)
                self.start_random_interface()
                
                if i == self.interface:
                    if self.config.get('auto_cycle'):
                        self.interface = random.choice(self.interfaces.values())
                        self.config.set_key('server', self.interface.server, False)
                    else:
                        self.trigger_callback('disconnected')
                

    def on_peers(self, result):
        # populate servers list here
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




if __name__ == "__main__":
    import simple_config
    config = simple_config.SimpleConfig({'verbose':True})
    network = Network(config)
    network.start()

    while 1:
        time.sleep(1)



