#!/usr/bin/env python3
#
# Electron Cash - a lightweight Bitcoin Cash client
# CashFusion - an advanced coin anonymizer
#
# Copyright (C) 2020 Mark B. Lundeberg
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
"""
A basic server implementation for CashFusion. Does not natively offer SSL
support, however a server admin may run an SSL server proxy such as nginx for
that purpose.
"""

import secrets
import sys
import threading
import time
import traceback
from collections import defaultdict

import electroncash.schnorr as schnorr
from electroncash.address import Address
from electroncash.util import PrintError, ServerError, TimeoutException
from . import fusion_pb2 as pb
from . import compatibility
from .comms import send_pb, recv_pb, ClientHandlerThread, GenericServer, get_current_genesis_hash
from .protocol import Protocol
from .util import (FusionError, sha256, calc_initial_hash, calc_round_hash, gen_keypair, tx_from_components,
                   rand_position)
from .validation import (check_playercommit, check_covert_component, validate_blame, ValidationError,
                         check_input_electrumx)

# Resistor "E series" values -- round numbers that are almost geometrically uniform
E6  = [1.0, 1.5, 2.2, 3.3, 4.7, 6.8]
E12 = [1.0, 1.2, 1.5, 1.8, 2.2, 2.7, 3.3, 3.9, 4.7, 5.6, 6.8, 8.2]
E24 = [1.0, 1.1, 1.2, 1.3, 1.5, 1.6, 1.8, 2.0, 2.2, 2.4, 2.7, 3.0, 3.3, 3.6, 3.9, 4.3, 4.7, 5.1, 5.6, 6.2, 6.8, 7.5, 8.2, 9.1]

# TODO - make these configurable
class Params:
    num_components = 23
    component_feerate = 1000 # sats/kB
    max_excess_fee = 300000 # sats
    tiers = [round(b*s) for b in [10000, 100000, 1000000, 10000000, 100000000] for s in E12]

    # How many clients do we want before starting a fusion?
    min_clients = 8
    # If all clients submitted largest possible component (uncompressed p2pkh input), how many could we take until the result would exceed 100 kB standard tx size limitation?
    max_clients = (100000 - 12) // (num_components * 173)

    # Every round, clients leave ... How many clients do we need as an absolute minimum (for privacy)?
    min_safe_clients = 6

    # Choose the minimum excess fee based on dividing the overhead amongst players, in the smallest fusion
    # (these overhead numbers assume op_return script size of 1 + 5 (lokad) + 33 (session hash) )
    if min_safe_clients * num_components >= 2 * 0xfc:
        # the smallest fusion could require 3-byte varint for both inputs and outputs lists
        overhead = 62
    elif min_safe_clients * num_components >= 0xfc:
        # the smallest fusion could require 3-byte varint for either inputs or outputs lists
        overhead = 60
    else:
        # the smallest fusion will use 1-byte varint for both inputs and outputs lists
        overhead = 58
    min_excess_fee = (overhead + min_safe_clients - 1) // min_safe_clients

    # How many clients can share same tag on a given tier (if more try to join, reject)
    max_tier_client_tags = 100

    # For a given IP, how many players can they represent in the same fuse?
    ip_max_simul_fuse = 3

    # Guaranteed time to launch a fusion if the pool has stayed at or above min_clients for this long.
    start_time_max = 1200
    # Inter-fusion delay -- after starting any fusion, wait this long before starting the next one (unless hit max time or pool is full).
    start_time_spacing = 120
    # But don't start a fusion if it has only been above min_clients for a short time (unless pool is full).
    start_time_min = 400

    # whether to print a lot of logs
    noisy = False


# How long covert connections are allowed to stay open without activity.
# note this needs to consider the maximum interval between messages:
# - how long from first connection to last possible Tor component submission?
# - how long from one round's component submission to the next round's component submission?
COVERT_CLIENT_TIMEOUT = 40

# used for non-cryptographic purposes
import random
rng = random.Random()
rng.seed(secrets.token_bytes(32))

def clientjob_send(client, msg, timeout = Protocol.STANDARD_TIMEOUT):
    client.send(msg, timeout=timeout)
def clientjob_goodbye(client, text):
    # a gentler goodbye than killing
    if text is not None:
        client.send_error(text)
    raise client.Disconnect

class ClientThread(ClientHandlerThread):
    """Basic thread per connected client."""
    def recv(self, *expected_msg_names, timeout=Protocol.STANDARD_TIMEOUT):
        submsg, mtype = recv_pb(self.connection, pb.ClientMessage, *expected_msg_names, timeout=timeout)
        return submsg

    def send(self, submsg, timeout=Protocol.STANDARD_TIMEOUT):
        send_pb(self.connection, pb.ServerMessage, submsg, timeout=timeout)

    def send_error(self, msg):
        self.send(pb.Error(message = msg), timeout=Protocol.STANDARD_TIMEOUT)

    def error(self, msg):
        self.send_error(msg)
        raise FusionError(f'Rejected client: {msg}')

class ClientTag(bytes):
    """ enhanced bytes object to represent a pool tag """
    __slots__ = ()
    def __new__(cls, ipstr, tagbytes, maxsimul):
        ipb = ipstr.encode()
        b = bytes([maxsimul, len(ipb)]) + ipb + tagbytes
        return super().__new__(cls, b)
    @property
    def maxsimul(self):
        return self[0]
class TagStatus:
    __slots__ = ('pool', 'all_')
    def __init__(self):
        self.pool = 0
        self.all_ = 0

class WaitingPool:
    """ a waiting pool for a specific tier """
    def __init__(self, fill_threshold, tag_max):
        self.pool = set() # clients who will be put into fusion round if started at this tier
        self.queue = list() # clients who are waiting due to tags being full
        self.tags = defaultdict(TagStatus) # how are the various tags
        self.fill_threshold = fill_threshold # minimum number of pool clients to trigger setting fill_time
        self.fill_time = None # when did pool exceed fill_threshold
        self.tag_max = tag_max # how many clients can share same tag (in pool and queue)
    def check_add(self, client):
        for t in client.tags:
            ts = self.tags.get(t)
            if ts is not None and ts.all_ >= self.tag_max:
                return "too many clients with same tag"
    def _add_pool(self, client):
        self.pool.add(client)
        for t in client.tags:
            ts = self.tags[t]
            ts.pool += 1
        if len(self.pool) == self.fill_threshold:
            self.fill_time = time.monotonic()
    def add(self, client):
        can_pool = True
        for t in client.tags:
            ts = self.tags[t]
            ts.all_ += 1
            if ts.pool >= t.maxsimul:
                can_pool = False
        if can_pool:
            self._add_pool(client)
        else:
            self.queue.append(client)
        return can_pool
    def remove(self, client):
        # make sure to call try_move_from_queue() after calling this
        try:
            self.pool.remove(client)
        except KeyError:
            in_pool = False
            try:
                self.queue.remove(client)
            except ValueError:
                return False
        else:
            in_pool = True
            if len(self.pool) < self.fill_threshold:
                self.fill_time = None

        for t in client.tags:
            ts = self.tags[t]
            ts.all_ -= 1
            if in_pool:
                ts.pool -= 1
            if ts.all_ == 0: # cleanup for no-longer-used tags
                del self.tags[t]
        return True
    def try_move_from_queue(self):
        # attempt to move clients from queue into pool
        moved = []
        for client in self.queue:
            for t in client.tags:
                ts = self.tags[t]
                if ts.pool >= t.maxsimul:
                    break
            else:
                self._add_pool(client)
                moved.append(client)
        for client in moved:
            self.queue.remove(client)

class FusionServer(GenericServer):
    """Server for clients waiting to start a fusion. New clients get a
    ClientThread made for them, and they are put into the waiting pools.
    Once a Fusion thread is started, the ClientThreads are passed over to
    a FusionController to run the rounds."""
    def __init__(self, config, network, bindhost, port, upnp = None, announcehost = None, donation_address = None):
        assert network
        assert isinstance(donation_address, (Address, type(None)))
        compatibility.check()
        super().__init__(bindhost, port, ClientThread, upnp = upnp)
        self.config = config
        self.network = network
        self.announcehost = announcehost
        self.donation_address = donation_address
        self.waiting_pools = {t: WaitingPool(Params.min_clients, Params.max_tier_client_tags) for t in Params.tiers}
        self.t_last_fuse = time.monotonic() # when the last fuse happened; as a placeholder, set this to startup time.
        self.reset_timer()

    def run(self):
        try:
            super().run()
        finally:
            self.waiting_pools.clear() # gc clean

    def reset_timer(self, ):
        """ Scan pools for the favoured fuse:
        - Out of the pool(s) with the most number of players,
        - Choose the pool with the earliest fill time;
        - If no pools are filled then there is no favoured fuse.
        (since fill time is a float, this will almost always be unique)
        """
        with self.lock:
            time_best = None
            tier_best = None
            size_best = 0
            for t, pool in self.waiting_pools.items():
                ft = pool.fill_time
                if ft is None:
                    continue
                size = len(pool.pool)
                if size >= size_best:
                    if time_best is None or ft < time_best or size > size_best:
                        time_best = ft
                        tier_best = t
                        size_best = size
            if time_best is None:
                self.tier_best_starttime = None
            else:
                self.tier_best_starttime = max(time_best + Params.start_time_min, self.t_last_fuse + Params.start_time_spacing)
            self.tier_best = tier_best

    def start_fuse(self, tier):
        """ Immediately launch Fusion at the selected tier. """
        with self.lock:
            chosen_clients = list(self.waiting_pools[tier].pool)

            # Notify that we will start.
            for c in chosen_clients:
                c.start_ev.set()

            # Remove those clients from all pools
            for t, pool in self.waiting_pools.items():
                for c in chosen_clients:
                    pool.remove(c)
                pool.try_move_from_queue()

            # Update timing info
            self.t_last_fuse = time.monotonic()
            self.reset_timer()

            # Uncomment the following to: Remove from spawned clients list, so that the fusion can continue independently of waiting server.
            # self.spawned_clients.difference_update(chosen_clients)

            # Kick off the fusion.
            rng.shuffle(chosen_clients)
            fusion = FusionController(self. network, tier, chosen_clients, self.bindhost, upnp = self.upnp, announcehost = self.announcehost)
            fusion.start()
            return len(chosen_clients)

    def new_client_job(self, client):
        client_ip = client.connection.socket.getpeername()[0]

        msg = client.recv('clienthello')
        if msg.version != Protocol.VERSION:
            client.error("Mismatched protocol version, please upgrade")

        if msg.genesis_hash:
            if msg.genesis_hash != get_current_genesis_hash():
                # For now, msg.genesis_hash is optional and we tolerate it
                # missing. However, if the client declares the genesis_hash, we
                # do indeed disallow them connecting if they are e.g. on testnet
                # and we are mainnet, etc.
                client.error("This server is on a different chain, please switch servers")
        else:
            client.print_error("👀 No genesis hash declared by client, we'll let them slide...")


        if self.stopping:
            return

        donation_address = ''
        if isinstance(self.donation_address, Address):
            donation_address = self.donation_address.to_full_ui_string()

        client.send(pb.ServerHello( num_components = Params.num_components,
                                    component_feerate = Params.component_feerate,
                                    min_excess_fee = Params.min_excess_fee,
                                    max_excess_fee = Params.max_excess_fee,
                                    tiers = Params.tiers,
                                    donation_address = donation_address
                                    ))

        # We allow a long timeout for clients to choose their pool.
        msg = client.recv('joinpools', timeout=120)
        if len(msg.tiers) == 0:
            client.error("No tiers")
        if len(msg.tags) > 5:
            client.error("Too many tags")

        # Event for signalling us that a pool started.
        start_ev = threading.Event()
        client.start_ev = start_ev

        if client_ip.startswith('127.'):
            # localhost is whitelisted to allow unlimited access
            client.tags = []
        else:
            # Default tag: this IP cannot be present in too many fuses.
            client.tags = [ClientTag(client_ip, b'', Params.ip_max_simul_fuse)]

        for tag in msg.tags:
            if len(tag.id) > 20:
                client.error("Tag id too long")
            if not (0 < tag.limit < 6):
                client.error("Tag limit out of range")
            ip = '' if tag.no_ip else client_ip
            client.tags.append(ClientTag(ip, tag.id, tag.limit))

        try:
            mytierpools = {t: self.waiting_pools[t] for t in msg.tiers}
        except KeyError:
            if self.stopping:
                return
            client.error(f"Invalid tier selected: {t}")
        try:
            mytiers = list(mytierpools)
            rng.shuffle(mytiers) # shuffle the adding order so that if filling more than one pool, we don't have bias towards any particular tier
            with self.lock:
                if self.stopping:
                    return
                # add this client to waiting pools
                for pool in mytierpools.values():
                    res = pool.check_add(client)
                    if res is not None:
                        client.error(res)
                for t in mytiers:
                    pool = mytierpools[t]
                    pool.add(client)
                    if len(pool.pool) >= Params.max_clients:
                        # pool filled up to the maximum size, so start immediately
                        self.start_fuse(t)
                        return

            # we have added to pools, which may have changed the favoured tier
            self.reset_timer()

            inftime = float('inf')

            while True:
                with self.lock:
                    if self.stopping or start_ev.is_set():
                        return
                    tnow = time.monotonic()

                    # scan through tiers and collect statuses, also check start times.
                    statuses = dict()
                    tfill_thresh = tnow - Params.start_time_max
                    for t, pool in mytierpools.items():
                        if client not in pool.pool:
                            continue
                        status = pb.TierStatusUpdate.TierStatus(players = len(pool.pool), min_players = Params.min_clients)

                        remtime = inftime
                        if pool.fill_time is not None:
                            # a non-favoured pool will start eventually
                            remtime = pool.fill_time - tfill_thresh
                        if t == self.tier_best:
                            # this is the favoured pool, can start at a special time
                            remtime = min(remtime, self.tier_best_starttime - tnow)
                        if remtime <= 0:
                            self.start_fuse(t)
                            return
                        elif remtime != inftime:
                            status.time_remaining = round(remtime)
                        statuses[t] = status
                client.send(pb.TierStatusUpdate(statuses = statuses))
                start_ev.wait(2)
        except:
            # Remove client from waiting pools on failure (on success, we are already removed; on stop we don't care.)
            with self.lock:
                for t, pool in mytierpools.items():
                    if pool.remove(client):
                        pool.try_move_from_queue()
                if self.tier_best in mytierpools:
                    # we left from best pool, so it might not be best anymore.
                    self.reset_timer()
            raise

class ResultsCollector:
    # Collect submissions from different sources, with a deadline.
    def __init__(self, num_results, done_on_fail = True):
        self.num_results = int(num_results)
        self.done_on_fail = bool(done_on_fail)
        self.done_ev = threading.Event()
        self.lock = threading.Lock()
        self.results = []
        self.fails = []
    def __enter__(self, ):
        return self
    def __exit__(self, exc_type, exc_value, traceback):
        if exc_type is not None:
            self.fails.append(exc_value)
            if self.done_on_fail:
                self.done_ev.set()
            elif len(self.fails) + len(getattr(self, 'results', ())) >= self.num_results:
                self.done_ev.set()
    def gather(self, *, deadline):
        remtime = deadline - time.monotonic()
        self.done_ev.wait(max(0., remtime))
        with self.lock:
            ret = self.results
            del self.results
            return ret
    def add(self, result):
        with self.lock:
            try:
                self.results.append(result)
            except AttributeError:
                return False
            else:
                if len(self.fails) + len(self.results) >= self.num_results:
                    self.done_ev.set()
                return True

class FusionController(threading.Thread, PrintError):
    """ This controls the Fusion rounds running from server side. """
    def __init__(self, network, tier, clients, bindhost, upnp = None, announcehost = None):
        super().__init__(name="FusionController")
        self.network = network
        self.tier = tier
        self.clients = list(clients)
        self.bindhost = bindhost
        self.upnp = upnp
        self.announcehost = announcehost
        self.daemon = True

    def sendall(self, msg, timeout = Protocol.STANDARD_TIMEOUT):
        for client in self.clients:
            client.addjob(clientjob_send, msg, timeout)

    def check_client_count(self,):
        live = [c for c in self.clients if not c.dead]
        if len(live) < Params.min_safe_clients:
            for c in live:
                c.kill("too few remaining live players")
            raise FusionError("too few remaining live players")

    def run (self, ):
        self.print_error(f'Starting fusion with {len(self.clients)} players at tier={self.tier}')
        covert_server = CovertServer(self.bindhost, upnp = self.upnp)
        try:
            annhost = covert_server.host if self.announcehost is None else self.announcehost
            annhost_b = annhost.encode('ascii')
            annport = covert_server.port
            covert_server.noisy = Params.noisy
            covert_server.start()

            self.print_error(f'Covert server started @ {covert_server.host}:{covert_server.port} (announcing as: {annhost_b}:{annport})')

            begin_time = round(time.time())
            self.sendall(pb.FusionBegin(tier = self.tier,
                                        covert_domain = annhost_b,
                                        covert_port = annport,
                                        covert_ssl = False,
                                        server_time = begin_time))

            self.last_hash = calc_initial_hash(self.tier, annhost_b, annport, False, begin_time)

            time.sleep(Protocol.WARMUP_TIME)

            # repeatedly run rounds until successful or exception
            while True:
                covert_server.reset()
                # Clean up dead clients
                self.clients = [c for c in self.clients if not c.dead]
                self.check_client_count()
                if self.run_round(covert_server):
                    break

            self.print_error('Ended successfully!')
        except FusionError as e:
            self.print_error(f"Ended with error: {e}")
        except Exception as e:
            self.print_error('Failed with exception!')
            traceback.print_exc(file=sys.stderr)
            for c in self.clients:
                c.addjob(clientjob_goodbye, 'internal server error')
        finally:
            covert_server.stop()
        for c in self.clients:
            c.addjob(clientjob_goodbye, None)
        self.clients = [] # gc

    def kick_missing_clients(self, goodclients, reason = None):
        baddies = set(self.clients).difference(goodclients)
        for c in baddies:
            c.kill(reason)

    def run_round(self, covert_server):
        covert_priv, covert_Upub, covert_Cpub = gen_keypair()
        round_pubkey = covert_Cpub

        # start to accept covert components
        covert_server.start_components(round_pubkey, Params.component_feerate)

        # generate blind nonces (slow!)
        for c in self.clients:
            c.blinds = [schnorr.BlindSigner() for _co in range(Params.num_components)]

        lock = threading.Lock()
        seen_salthashes = set()

        # Send start message to players; record the time we did this
        round_time = round(time.time())

        collector = ResultsCollector(len(self.clients), done_on_fail = False)
        def client_start(c, collector):
            with collector:
                c.send(pb.StartRound(round_pubkey = round_pubkey,
                                     blind_nonce_points = [b.get_R() for b in c.blinds],
                                     server_time = round_time
                                     ))
                msg = c.recv('playercommit')

                commit_messages = check_playercommit(msg, Params.min_excess_fee, Params.max_excess_fee, Params.num_components)

                newhashes = set(m.salted_component_hash for m in commit_messages)
                with lock:
                    expected_len = len(seen_salthashes) + len(newhashes)
                    seen_salthashes.update(newhashes)
                    if len(seen_salthashes) != expected_len:
                        c.error('duplicate component commitment')

                if not collector.add((c, msg.initial_commitments, msg.excess_fee)):
                    c.error("late commitment")

            # record for later
            c.blind_sig_requests = msg.blind_sig_requests
            c.random_number_commitment = msg.random_number_commitment

        for client in self.clients:
            client.addjob(client_start, collector)

        # Record the time that we sent 'startround' message to players; this
        # will form the basis of our covert timeline.
        covert_T0 = time.monotonic()
        self.print_error(f"startround sent at {time.time()}; accepting covert components")

        # Await commitment messages then process results
        results = collector.gather(deadline = covert_T0 + Protocol.TS_EXPECTING_COMMITMENTS)

        # Filter clients who didn't manage to give a good commitment.
        prev_client_count = len(self.clients)
        self.clients = [c for c, _, _ in results]
        self.check_client_count()
        self.print_error(f"got commitments from {len(self.clients)} clients (dropped {prev_client_count - len(self.clients)})")

        total_excess_fees = sum(f for _,_,f in results)
        # Generate scrambled commitment list, but remember exactly where each commitment originated.
        commitment_master_list = [(commit, ci, cj) for ci, (_, commitments, _) in enumerate(results) for cj,commit in enumerate(commitments)]
        rng.shuffle(commitment_master_list)
        all_commitments = tuple(commit for commit,ci,cj in commitment_master_list)

        # Send blind signatures
        for c in self.clients:
            scalars = [b.sign(covert_priv, e) for b,e in zip(c.blinds, c.blind_sig_requests)]
            c.addjob(clientjob_send, pb.BlindSigResponses(scalars = scalars))
            del c.blinds, c.blind_sig_requests
        del results, collector

        # Sleep a bit before uploading commitments, as clients are doing this.
        remtime = covert_T0 + Protocol.T_START_COMPS - time.monotonic()
        if remtime > 0:
            time.sleep(remtime)

        # Upload the full commitment list; we're a bit generous with the timeout but that's OK.
        self.sendall(pb.AllCommitments(initial_commitments = all_commitments),
                     timeout=Protocol.TS_EXPECTING_COVERT_SIGNATURES)

        # Sleep until end of covert components phase
        remtime = covert_T0 + Protocol.TS_EXPECTING_COVERT_COMPONENTS - time.monotonic()
        assert remtime > 0, "timings set up incorrectly"
        time.sleep(remtime)

        component_master_list = list(covert_server.end_components().items())
        self.print_error(f"ending covert component acceptance. {len(component_master_list)} received.")

        # Sort the components & contribs list, then separate it out.
        component_master_list.sort(key=lambda x:x[1][0])
        all_components = [comp for comp, (sort_key, contrib) in component_master_list]
        component_contribs = [contrib for comp, (sort_key, contrib) in component_master_list]
        del component_master_list

        # Do some preliminary checks to see whether we should just skip the
        # signing phase and go directly to blame, or maybe even restart / end
        # without sharing components.

        skip_signatures = False
        if len(all_components) != len(self.clients)*Params.num_components:
            skip_signatures = True
            self.print_error("problem detected: too few components submitted")
        if total_excess_fees != sum(component_contribs):
            skip_signatures = True
            self.print_error("problem detected: excess fee mismatch")

        self.last_hash = session_hash = calc_round_hash(self.last_hash, round_pubkey, round_time, all_commitments, all_components)

        #TODO : Check the inputs and outputs to see if we even have reasonable
        # privacy with what we have.

        bad_components = set()
        ###
        if skip_signatures:
            self.print_error("skipping covert signature acceptance")
            self.sendall(pb.ShareCovertComponents(components = all_components, skip_signatures = True))
        else:
            self.print_error("starting covert signature acceptance")

            tx, input_indices = tx_from_components(all_components, session_hash)

            sighashes = [sha256(sha256(bytes.fromhex(tx.serialize_preimage(i, 0x41, use_cache = True))))
                         for i in range(len(tx.inputs()))]
            pubkeys = [bytes.fromhex(inp['pubkeys'][0]) for inp in tx.inputs()]

            covert_server.start_signatures(sighashes,pubkeys)

            self.sendall(pb.ShareCovertComponents(components = all_components, session_hash = session_hash))

            # Sleep until end of covert signatures phase
            remtime = covert_T0 + Protocol.TS_EXPECTING_COVERT_SIGNATURES - time.monotonic()
            if remtime < 0:
                # really shouldn't happen, we had plenty of time
                raise FusionError("way too slow")
            time.sleep(remtime)

            signatures = list(covert_server.end_signatures())
            missing_sigs = len([s for s in signatures if s is None])

            ###
            self.print_error(f"ending covert signature acceptance. {missing_sigs} missing :{'(' if missing_sigs else ')'}")

            # mark all missing-signature components as bad.
            bad_inputs = set(i for i,sig in enumerate(signatures) if sig is None)

            # further, search for duplicated inputs (through matching the prevout and claimed pubkey).
            prevout_spenders = defaultdict(list)
            for i, inp in enumerate(tx.inputs()):
                prevout_spenders[f"{inp['prevout_hash']}:{inp['prevout_n']} {inp['pubkeys'][0]}"].append(i)
            for prevout, spenders in prevout_spenders.items():
                if len(spenders) == 1:
                    continue
                self.print_error(f"multi-spend of f{prevout} detected")
                # If exactly one of the inputs is signed, we don't punish him
                # because he's the honest guy and all the other components were
                # just imposters who didn't have private key. If more than one
                # signed, then it's malicious behaviour!
                if sum((signatures[i] is not None) for i in spenders) != 1:
                    bad_inputs.update(spenders)

            if bad_inputs:
                bad_components.update(input_indices[i] for i in bad_inputs)
            else:
                for i, (inp, sig) in enumerate(zip(tx.inputs(), signatures)):
                    inp['signatures'][0] = sig.hex() + '41'

                assert tx.is_complete()
                txid = tx.txid()
                self.print_error("completed the transaction! " + txid)

                try:
                    self.network.broadcast_transaction2(tx, timeout=3)
                except ServerError as e:
                    nice_msg, = e.args
                    server_msg = e.server_msg
                    self.print_error(f"could not broadcast the transaction! {nice_msg}")
                except TimeoutException:
                    self.print_error("timed out while trying to broadcast transaction! misconfigured?")
                    # This probably indicates misconfiguration since fusion server ought
                    # to have a good connection to the EC server. Report this back to clients
                    # as an 'internal server error'.
                    raise
                else:
                    self.print_error("broadcast was successful!")
                    # Give our transaction a small head start in relaying, before sharing the
                    # signatures. This makes it slightly harder for one of the players to
                    # broadcast a malleated version by re-signing one of their inputs.
                    time.sleep(2)
                    self.sendall(pb.FusionResult(ok = True, txsignatures = signatures))
                    return True

            self.sendall(pb.FusionResult(ok = False, bad_components = sorted(bad_components)))

        ###
        self.print_error(f"entering blame phase. bad components: {bad_components}")

        if len(self.clients) < 2:
            # Sanity check for testing -- the proof sharing thing doesn't even make sense with one player.
            for c in self.clients:
                c.kill('blame yourself!')
                return

        # scan the commitment list and note where each client's commitments ended up
        client_commit_indexes = [[None]*Params.num_components for _ in self.clients]
        for i, (commit, ci, cj) in enumerate(commitment_master_list):
            client_commit_indexes[ci][cj] = i

        collector = ResultsCollector(len(self.clients), done_on_fail = False)
        def client_get_proofs(client, collector):
            with collector:
                msg = client.recv('myproofslist')
                seed = msg.random_number
                if sha256(seed) != client.random_number_commitment:
                    client.error("seed did not match commitment")
                proofs = msg.encrypted_proofs
                if len(proofs) != Params.num_components:
                    client.error("wrong number of proofs")
                if any(len(p) > 200 for p in proofs):
                    client.error("too-long proof")  # they should only be 129 bytes long.

                # generate the possible destinations list (all commitments, but leaving out the originating client's commitments).
                myindex = self.clients.index(client)
                possible_commitment_destinations = [(ci,cj) for commit, ci, cj in commitment_master_list if ci != myindex]
                N = len(possible_commitment_destinations)
                assert N == len(all_commitments) - Params.num_components

                # calculate the randomly chosen destinations, same way as client did.
                relays = []
                for i, proof in enumerate(proofs):
                    dest_client_idx, dest_key_idx = possible_commitment_destinations[rand_position(seed, N, i)]
                    src_commitment_idx = client_commit_indexes[myindex][i]
                    relays.append((proof, src_commitment_idx, dest_client_idx, dest_key_idx))
                if not collector.add((client, relays)):
                    client.error("late proofs")
        for client in self.clients:
            client.addjob(client_get_proofs, collector)
        results = collector.gather(deadline = time.monotonic() + Protocol.STANDARD_TIMEOUT)

        # Now, repackage the proofs according to destination.
        proofs_to_relay = [list() for _ in self.clients]
        for src_client, relays in results:
            for proof, src_commitment_idx, dest_client_idx, dest_key_idx in relays:
                proofs_to_relay[dest_client_idx].append((proof, src_commitment_idx, dest_key_idx, src_client))

        live_clients = len(results)
        collector = ResultsCollector(live_clients, done_on_fail = False)
        def client_get_blames(client, myindex, proofs, collector):
            with collector:
                # an in-place sort by source commitment idx removes ordering correlations about which client sent which proof
                proofs.sort(key = lambda x:x[1])
                client.send(pb.TheirProofsList(proofs = [
                                    dict(encrypted_proof=x, src_commitment_idx=y, dst_key_idx=z)
                                    for x,y,z, _ in proofs]))
                msg = client.recv('blames', timeout = Protocol.STANDARD_TIMEOUT + Protocol.BLAME_VERIFY_TIME)

                # More than one blame per proof is malicious. Boot client
                # immediately since client may be trying to DoS us by
                # making us check many inputs against blockchain.
                if len(msg.blames) > len(proofs):
                    client.error('too many blames')
                if len(set(blame.which_proof for blame in msg.blames)) != len(msg.blames):
                    client.error('multiple blames point to same proof')

                # Note, the rest of this function might run for a while if many
                # checks against blockchain need to be done, perhaps even still
                # running after run_round has exited. For this reason we try to
                # not reference self.<variables> that may change.
                for blame in msg.blames:
                    try:
                        encproof, src_commitment_idx, dest_key_idx, src_client = proofs[blame.which_proof]
                    except IndexError:
                        client.kill(f'bad proof index {blame.which_proof} / {len(proofs)}')
                        continue
                    src_commit_blob, src_commit_client_idx, _ = commitment_master_list[src_commitment_idx]
                    dest_commit_blob = all_commitments[client_commit_indexes[myindex][dest_key_idx]]

                    try:
                        ret = validate_blame(blame, encproof, src_commit_blob, dest_commit_blob, all_components, bad_components, Params.component_feerate)
                    except ValidationError as e:
                        self.print_error("got bad blame; clamed reason was: "+repr(blame.blame_reason))
                        client.kill(f'bad blame message: {e} (you claimed: {blame.blame_reason!r})')
                        continue

                    if isinstance(ret, str):
                        self.print_error(f"verified a bad proof (for {src_commitment_idx}): {ret}")
                        src_client.kill(f'bad proof (for {src_commitment_idx}): {ret}')
                        continue

                    if src_client.dead:
                        # If the blamed client is already dead, don't waste more time.
                        # Since nothing after this point can report back to the
                        # verifier, there is no privacy leak by the ommission.
                        continue

                    assert ret, 'expecting input component'
                    outpoint = ret.prev_txid[::-1].hex() + ':' + str(ret.prev_index)
                    try:
                        check_input_electrumx(self.network, ret)
                    except ValidationError as e:
                        reason = f'{e.args[0]} ({outpoint})'
                        self.print_error(f"blaming[{src_commitment_idx}] for bad input: {reason}")
                        src_client.kill('you provided a bad input: ' + reason)
                        continue
                    except Exception as e:
                        self.print_error(f"player indicated bad input but checking failed with exception {repr(e)}  ({outpoint})")
                    else:
                        self.print_error(f"player indicated bad input but it was fine ({outpoint})")
                        # At this point we could blame the originator, however
                        # blockchain checks are somewhat subjective. It would be
                        # appropriate to add some 'ban score' to the player.

                # we aren't collecting any results, rather just marking that
                # 'checking finished' so that if all blames are checked, we
                # can start next round right away.
                collector.add(None)

        for idx, (client, proofs) in enumerate(zip(self.clients, proofs_to_relay)):
            client.addjob(client_get_blames, idx, proofs, collector)
        _ = collector.gather(deadline = time.monotonic() + Protocol.STANDARD_TIMEOUT + Protocol.BLAME_VERIFY_TIME * 2)

        self.sendall(pb.RestartRound())


class CovertClientThread(ClientHandlerThread):
    def recv(self, *expected_msg_names, timeout=None):
        submsg, mtype = recv_pb(self.connection, pb.CovertMessage, *expected_msg_names, timeout=timeout)
        return submsg, mtype

    def send(self, submsg, timeout=None):
        send_pb(self.connection, pb.CovertResponse, submsg, timeout=timeout)

    def send_ok(self,):
        self.send(pb.OK(), timeout=5)

    def send_error(self, msg):
        self.send(pb.Error(message = msg), timeout=5)

    def error(self, msg):
        self.send_error(msg)
        raise FusionError(f'Rejected client: {msg}')


class CovertServer(GenericServer):
    """
    Server for covert submissions. How it works:
    - Launch the server at any time. By default, will bind to an ephemeral port.
    - Before start of covert components phase, call start_components.
    - To signal the end of covert components phase, owner calls end_components, which returns a dict of {component: contrib}, where contrib is (+- amount - fee).
    - Before start of covert signatures phase, owner calls start_signatures.
    - To signal the end of covert signatures phase, owner calls end_signatures, which returns a list of signatures (which will have None at positions of missing signatures).
    - To reset the server for a new round, call .reset(); to kill all connections, call .stop().
    """
    def __init__(self, bindhost, port=0, upnp = None):
        super().__init__(bindhost, port, CovertClientThread, upnp = upnp)
        self.round_pubkey = None

    def start_components(self, round_pubkey, feerate):
        self.components = dict()
        self.feerate = feerate
        self.round_pubkey = round_pubkey
        for c in self.spawned_clients:
            c.got_submit = False

    def end_components(self):
        with self.lock:
            ret = self.components
            del self.components
        return ret

    def start_signatures(self, sighashes, pubkeys):
        num_inputs = len(sighashes)
        assert num_inputs == len(pubkeys)
        self.signatures = [None]*num_inputs
        self.sighashes = sighashes
        self.pubkeys = pubkeys
        for c in self.spawned_clients:
            c.got_submit = False

    def end_signatures(self):
        with self.lock:
            ret = self.signatures
            del self.signatures
        return ret

    def reset(self):
        try:
            del self.round_pubkey
            del self.components
            del self.feerate
        except AttributeError:
            pass
        try:
            del self.sighashes
            del self.pubkeys
        except AttributeError:
            pass

    def new_client_job(self, client):
        client.got_submit = False
        while True:
            msg, mtype = client.recv('component', 'signature', 'ping', timeout = COVERT_CLIENT_TIMEOUT)
            if mtype == 'ping':
                continue

            if client.got_submit:
                # We got a second submission before a new phase started. As
                # an anti-spam measure we only allow one submission per connection
                # per phase.
                client.error('multiple submission in same phase')

            if mtype == 'component':
                try:
                    round_pubkey = self.round_pubkey
                    feerate = self.feerate
                    _ = self.components
                except AttributeError:
                    client.error('component submitted at wrong time')
                sort_key, contrib = check_covert_component(msg, round_pubkey, feerate)

                with self.lock:
                    try:
                        self.components[msg.component] = (sort_key, contrib)
                    except AttributeError:
                        client.error('component submitted at wrong time')

            else:
                assert mtype == 'signature'
                try:
                    sighash = self.sighashes[msg.which_input]
                    pubkey = self.pubkeys[msg.which_input]
                    existing_sig = self.signatures[msg.which_input]
                except AttributeError:
                    client.error('signature submitted at wrong time')
                except IndexError:
                    raise ValidationError('which_input too high')

                sig = msg.txsignature
                if len(sig) != 64:
                    raise ValidationError('signature length is wrong')

                # It might be we already have this signature. This is fine
                # since it might be a resubmission after ack failed delivery,
                # but we don't allow it to consume our CPU power.

                if sig != existing_sig:
                    if not schnorr.verify(pubkey, sig, sighash):
                        raise ValidationError('bad transaction signature')
                    if existing_sig:
                        # We received a distinct valid signature. This is not
                        # allowed and we break the connection as a result.
                        # Note that we could have aborted earlier but this
                        # way third parties can't abuse us to find out the
                        # timing of a given input's signature submission.
                        raise ValidationError('conflicting valid signature')

                    with self.lock:
                        try:
                            self.signatures[msg.which_input] = sig
                        except AttributeError:
                            client.error('signature submitted at wrong time')

            client.send_ok()
            client.got_submit = True
