#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2011 thomasv@gitorious
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.


import random, socket, ast

        
import thread, traceback, sys, time, json

DEFAULT_TIMEOUT=5

class Interface:
    def __init__(self):
        self.default_servers = ['ecdsa.org','electrum.novit.ro']  # list of default servers
        self.host = random.choice( self.default_servers )         # random choice when the wallet is created
        self.servers = self.default_servers                       # actual list from IRC
        self.rtime = 0
        self.blocks = 0 
        self.message = ''
        self.is_connected = False
        self.was_updated = True # fixme: use a semaphore
        self.is_up_to_date = False # True after the first poll

    def send_tx(self, data):
        out = self.handler('blockchain.transaction.broadcast', data )
        return out

    def retrieve_history(self, address):
        out = self.handler('blockchain.address.get_history', address )
        return out

    def get_servers(self):
        thread.start_new_thread(self.update_servers_thread, ())

    def set_server(self, host, port):
        if host!= self.host or port!=self.port:
            self.host = host
            self.port = port
            self.is_connected = False

    def update_servers_thread(self):
        pass


class NativeInterface(Interface):
    """This is the original Electrum protocol. It uses polling, and a non-persistent tcp connection"""

    def __init__(self, host=None, port=50000):
        Interface.__init__(self)
        if host: self.host = host
        self.port = port

    def new_session(self, addresses, version):
        self.is_up_to_date = False
        out = self.handler('session.new', [ version, addresses ] )
        self.session_id, self.message = ast.literal_eval( out )

    def update_session(self, addresses):
        out = self.handler('session.update', [ self.session_id, addresses ] )
        return out    

    def handler(self, method, params = ''):
        import time
        cmds = {'session.new':'new_session',
                'peers':'peers',
                'session.poll':'poll',
                'session.update':'update_session',
                'blockchain.transaction.broadcast':'tx',
                'blockchain.address.get_history':'h'
                }
        cmd = cmds[method]
        if type(params) != type(''): params = repr( params )
        t1 = time.time()
        request = repr ( (cmd, params) ) + "#"
        s = socket.socket( socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(DEFAULT_TIMEOUT)
        s.connect(( self.host if cmd!='peers' else self.peers_server, self.port) )
        s.send( request )
        out = ''
        while 1:
            msg = s.recv(1024)
            if msg: out += msg
            else: break
        s.close()
        self.rtime = time.time() - t1
        self.is_connected = True
        if cmd in[ 'peers','h']:
            out = ast.literal_eval( out )
        return out

    def poll_interval(self):
        return 5

    def update_wallet(self, wallet):
        is_new = False
        changed_addresses = self.poll()
        for addr, blk_hash in changed_addresses.items():
            if wallet.status.get(addr) != blk_hash:
                print "updating history for", addr
                wallet.history[addr] = self.retrieve_history(addr)
                wallet.status[addr] = blk_hash
                is_new = True

        if is_new or wallet.remote_url:
            is_new = wallet.synchronize()
            wallet.update_tx_history()
            wallet.save()
            return is_new
        else:
            return False

    def poll(self):
        out = self.handler('session.poll', self.session_id )
        blocks, changed_addr = ast.literal_eval( out )
        if blocks == -1: raise BaseException("session not found")
        self.blocks = int(blocks)
        if changed_addr: self.was_updated = True
        self.is_up_to_date = True
        return changed_addr

    def update_wallet_thread(self, wallet):
        while True:
            try:
                self.is_connected = False
                self.new_session(wallet.all_addresses(), wallet.electrum_version)
            except socket.error:
                print "Not connected"
                time.sleep(self.poll_interval())
                continue
            except:
                traceback.print_exc(file=sys.stdout)
                time.sleep(self.poll_interval())
                continue

            while True:
                try:
                    if self.update_wallet(wallet):
                        self.update_session( wallet.all_addresses() )

                    time.sleep(self.poll_interval())
                except BaseException:
                    traceback.print_exc(file=sys.stdout)
                    print "starting new session"
                    break
                except socket.gaierror:
                    self.is_connected = False
                    break
                except socket.error:
                    print "socket.error"
                    self.is_connected = False
                    break
                except:
                    self.is_connected = False
                    print "error"
                    traceback.print_exc(file=sys.stdout)
                    break
                
    def start(self, wallet):
        thread.start_new_thread(self.update_wallet_thread, (wallet,))

    def update_servers_thread(self):
        # if my server is not reachable, I should get the list from one of the default servers
        # requesting servers could be an independent process
        while True:
            for server in self.default_servers:
                try:
                    self.peers_server = server
                    out = self.handler('peers')
                    self.servers = map( lambda x:x[1], out )
                    # print "Received server list from %s" % self.peers_server, out
                    break
                except socket.timeout:
                    continue
                except socket.error:
                    continue
                except:
                    traceback.print_exc(file=sys.stdout)

            time.sleep(5*60)




class TCPInterface(Interface):
    """json-rpc over persistent TCP connection"""

    def __init__(self, host=None, port=50001):
        Interface.__init__(self)
        if host: self.host = host
        self.port = 50001
        self.s = socket.socket( socket.AF_INET, socket.SOCK_STREAM )
        self.s.connect(( self.host, self.port))

    def send(self, cmd, params = []):
        request = json.dumps( { 'method':cmd, 'params':params } )
        self.s.send( request + '\n' )

    def send_tx(self, data):
        out = self.send('transaction.broadcast', data )
        return out

    def listen_thread(self, wallet):
        try:
            self.is_connected = True
            out = ''
            while True:
                msg = self.s.recv(1024)
                out += msg
                if msg == '': 
                    self.is_connected = False
                    raise BaseException('Socket was disconnected')
                while True:
                    s = out.find('\n')
                    if s==-1: break
                    c = out[0:s]
                    out = out[s+1:]
                    c = json.loads(c)
                    cmd = c.get('method')
                    if cmd == 'server.banner':
                        self.message = c.get('result')
                    elif cmd == 'numblocks.subscribe':
                        self.blocks = c.get('result')
                        print "num blocks",self.blocks
                    elif cmd =='address.subscribe':
                        addr = c.get('address')
                        status = c.get('status')
                        if wallet.status.get(addr) != status:
                            self.send('address.get_history', addr)
                            wallet.status[addr] = status
                            self.is_up_to_date = False
                        else:
                            self.is_up_to_date = True
                    elif cmd == 'address.get_history':
                        addr = c.get('address')
                        print "updating history for", addr
                        wallet.history[addr] = c.get('result')
                        wallet.synchronize()
                        wallet.update_tx_history()
                        wallet.save()
                        self.was_updated = True
                else:
                    print "received message:", c
        except:
            traceback.print_exc(file=sys.stdout)
            self.is_connected = False


    def subscribe(self,address):
        self.send('address.subscribe', address)


    def start(self, wallet):
        thread.start_new_thread(self.listen_thread, (wallet,))
        self.send('client.version', wallet.electrum_version)
        self.send('server.banner')
        self.send('numblocks.subscribe')
        for address in wallet.all_addresses():
            self.subscribe(address)


class HttpInterface(Interface):

    def __init__(self):
        self.port = 8081

    def handler(self, method, params = []):
        import urllib2, json, time
        if type(params) != type([]): params = [ params ]
        t1 = time.time()
        data = { 'method':method, 'id':'jsonrpc', 'params':params }
        data_json = json.dumps(data)
        host = 'http://%s:%d'%( self.host if cmd!='peers' else self.peers_server, self.port )
        req = urllib2.Request(host, data_json, {'content-type': 'application/json'})
        response_stream = urllib2.urlopen(req)
        response = json.loads( response_stream.read() )
        out = response.get('result')
        if not out:
            print response
        self.rtime = time.time() - t1
        self.is_connected = True
        return out
