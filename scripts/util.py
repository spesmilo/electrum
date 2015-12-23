import select, time, electrum, Queue
from electrum import Connection, Interface, SimpleConfig
from electrum.network import filter_protocol, parse_servers
from collections import defaultdict

# electrum.util.set_verbosity(1)
def get_interfaces(servers, timeout=10):
    '''Returns a map of servers to connected interfaces.  If any
    connections fail or timeout, they will be missing from the map.
    '''
    socket_queue = Queue.Queue()
    config = SimpleConfig()
    connecting = {}
    for server in servers:
        if server not in connecting:
            connecting[server] = Connection(server, socket_queue, config.path)
    interfaces = {}
    timeout = time.time() + timeout
    count = 0
    while time.time() < timeout and count < len(servers):
        try:
            server, socket = socket_queue.get(True, 0.3)
        except Queue.Empty:
            continue
        if socket:
            interfaces[server] = Interface(server, socket)
        count += 1
    return interfaces

def wait_on_interfaces(interfaces, timeout=10):
    '''Return a map of servers to a list of (request, response) tuples.
    Waits timeout seconds, or until each interface has a response'''
    result = defaultdict(list)
    timeout = time.time() + timeout
    while len(result) < len(interfaces) and time.time() < timeout:
        rin = [i for i in interfaces.values()]
        win = [i for i in interfaces.values() if i.unsent_requests]
        rout, wout, xout = select.select(rin, win, [], 1)
        for interface in wout:
            interface.send_requests()
        for interface in rout:
            responses = interface.get_responses()
            if responses:
                result[interface.server].extend(responses)
    return result

def get_peers():
    peers = []
    # 1. get connected interfaces
    server = 'ecdsa.net:110:s'
    interfaces = get_interfaces([server])
    if not interfaces:
        print "No connection to", server
        return []
    # 2. get list of peers
    interface = interfaces[server]
    interface.queue_request('server.peers.subscribe', [], 0)
    responses = wait_on_interfaces(interfaces).get(server)
    if responses:
        response = responses[0][1]  # One response, (req, response) tuple
        peers = parse_servers(response.get('result'))
        peers = filter_protocol(peers,'s')
    return peers

def send_request(peers, method, params):
    print "Contacting %d servers"%len(peers)
    interfaces = get_interfaces(peers)
    print "%d servers could be reached" % len(interfaces)
    for peer in peers:
        if not peer in interfaces:
            print "Connection failed:", peer
    for msg_id, i in enumerate(interfaces.values()):
        i.queue_request(method, params, msg_id)
    responses = wait_on_interfaces(interfaces)
    for peer in interfaces:
        if not peer in responses:
            print peer, "did not answer"
    results = dict(zip(responses.keys(), [t[0][1].get('result') for t in responses.values()]))
    print "%d answers"%len(results)
    return results
