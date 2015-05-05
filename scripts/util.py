import time, electrum_ltc as electrum, Queue
from electrum_ltc import Interface, SimpleConfig
from electrum_ltc.network import filter_protocol, parse_servers

# electrum.util.set_verbosity(1)

def get_peers():
    # 1. start interface and wait for connection
    q = Queue.Queue()
    interface = electrum.Interface('electrum-ltc.bysh.me:50002:s', q)
    interface.start()
    i, r = q.get()
    if not interface.is_connected():
        raise BaseException("not connected")
    # 2. get list of peers
    interface.send_request({'id':0, 'method':'server.peers.subscribe','params':[]})
    i, r = q.get(timeout=10000)
    peers = parse_servers(r.get('result'))
    peers = filter_protocol(peers,'s')
    i.stop()
    return peers

def send_request(peers, request):
    print "Contacting %d servers"%len(peers)
    # start interfaces
    q2 = Queue.Queue()
    config = SimpleConfig()
    interfaces = map(lambda server: Interface(server, q2, config), peers)
    reached_servers = []
    for i in interfaces:
        i.start()
    t0 = time.time()
    while peers:
        try:
            i, r = q2.get(timeout=1)
        except:
            if time.time() - t0 > 10:
                print "timeout"
                break
            else:
                continue
        if i.server in peers:
            peers.remove(i.server)
        if i.is_connected():
            reached_servers.append(i)
        else:
            print "Connection failed:", i.server

    print "%d servers could be reached"%len(reached_servers)

    results_queue = Queue.Queue()
    for i in reached_servers:
        i.send_request(request, results_queue)
    results = {}
    t0 = time.time()
    while reached_servers:
        try:
            i, r = results_queue.get(timeout=1)
        except:
            if time.time() - t0 > 10:
                break
            else:
                continue
        results[i.server] = r.get('result')
        reached_servers.remove(i)
        i.stop()

    for i in reached_servers:
        print i.server, "did not answer"
    print "%d answers"%len(results)
    return results
