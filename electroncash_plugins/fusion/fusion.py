#!/usr/bin/#!/usr/bin/env python3
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
Client-side fusion logic. See `class Fusion` for the main exposed API.

This module has no GUI dependency.
"""

from electroncash import networks, schnorr
from electroncash.bitcoin import public_key_from_private_key
from electroncash.i18n import _, ngettext, pgettext
from electroncash.util import format_satoshis, do_in_main_thread, PrintError, ServerError, TxHashMismatch, TimeoutException
from electroncash.wallet import Standard_Wallet, Multisig_Wallet

from . import encrypt
from . import fusion_pb2 as pb
from . import pedersen
from .comms import send_pb, recv_pb, get_current_genesis_hash
from . import compatibility
from .connection import open_connection
from .conf import Conf
from .covert import CovertSubmitter, is_tor_port
from .protocol import Protocol
from .util import (FusionError, sha256, calc_initial_hash, calc_round_hash, size_of_input, size_of_output,
                   component_fee, gen_keypair, tx_from_components, rand_position)
from .validation import validate_proof_internal, ValidationError, check_input_electrumx

from google.protobuf.message import DecodeError

import copy
import itertools
import secrets
import sys
import threading
import time
import weakref
from collections import defaultdict
from math import ceil

# used for tagging fusions in a way privately derived from wallet name
tag_seed = secrets.token_bytes(16)

# Safety limits to prevent loss of funds / limit fees:
# (Note that if we enter multiply into the same fusion, our limits apply
# separately for each "player".)
#
# Deny server that asks for more than this component feerate (sat/kbyte).
MAX_COMPONENT_FEERATE = 5000
# The largest 'excess fee' that we are willing to pay in a fusion (fees beyond
# those needed to pay for our components' inclusion)
MAX_EXCESS_FEE = 10000
# Even if the server allows more, put at most this many inputs+outputs+blanks
MAX_COMPONENTS = 40
# The largest total fee we are willing to pay (our contribution to transaction
# size should not exceed 7 kB even with 40 largest components).
MAX_FEE = MAX_COMPONENT_FEERATE * 7 + MAX_EXCESS_FEE

# For privacy reasons, don't submit less than this many distinct tx components.
# (distinct tx inputs, and tx outputs)
MIN_TX_COMPONENTS = 11

def can_fuse_from(wallet):
    """We can only fuse from wallets that are p2pkh, and where we are able
    to extract the private key."""
    return (not (wallet.is_watching_only() or wallet.is_hardware() or isinstance(wallet, Multisig_Wallet))
            and networks.net is not networks.TaxCoinNet)

def can_fuse_to(wallet):
    """We can only fuse to wallets that are p2pkh with HD generation. We do
    *not* need the private keys."""
    return isinstance(wallet, Standard_Wallet) and networks.net is not networks.TaxCoinNet



# Some internal stuff

# not cryptographically secure!
# we only use it to generate a few floating point numbers, with cryptographically secure seed.
from random import Random

def random_outputs_for_tier(rng, input_amount, scale, offset, max_count, allow_extra_change=False):
    """ Make up to `max_number` random output values, chosen using exponential
    distribution function. All parameters should be positive `int`s.

    None can be returned for expected types of failures, which will often occur
    when the input_amount is too small or too large, since it becomes uncommon
    to find a random assortment of values that satisfy the desired constraints.

    On success, this returns a list of length 1 to max_count, of non-negative
    integer values that sum up to exactly input_amount.

    The returned values will always exactly sum up to input_amount. This is done
    by renormalizing them, which means the actual effective `scale` will vary
    depending on random conditions.

    If `allow_extra_change` is passed (this is abnormal!) then this may return
    max_count+1 outputs; the last output will be the leftover change if all
    max_counts outputs were exhausted.
    """
    if input_amount < offset:
        return None

    lambd = 1./scale

    remaining = input_amount
    values = []  # list of fractional random values without offset
    for _ in range(max_count+1):
        val = rng.expovariate(lambd)
        # A ceil here makes sure rounding errors won't sometimes put us over the top.
        # Provided that scale is much larger than 1, the impact is negligible.
        remaining -= ceil(val) + offset
        if remaining < 0:
            break
        values.append(val)
    else:
        if allow_extra_change:
            result = [(round(v) + offset) for v in values[:-1]]
            result.append(input_amount - sum(result))
            return result
        # Fail because we would need too many outputs
        # (most likely, scale was too small)
        return None
    assert len(values) <= max_count

    if not values:
        # Our first try put us over the limit, so we have nothing to work with.
        # (most likely, scale was too large)
        return None

    desired_random_sum = input_amount - len(values) * offset
    assert desired_random_sum >= 0

    # Now we need to rescale and round the values so they fill up the desired.
    # input amount exactly. We perform rounding in cumulative space so that the
    # sum is exact, and the rounding is distributed fairly.
    cumsum = list(itertools.accumulate(values))
    rescale = desired_random_sum / cumsum[-1]
    normed_cumsum = [round(rescale * v) for v in cumsum]
    assert normed_cumsum[-1] == desired_random_sum

    differences = ((a - b) for a,b in zip(normed_cumsum, itertools.chain((0,),normed_cumsum)))
    result = [(offset + d) for d in differences]
    assert sum(result) == input_amount

    return result

def gen_components(num_blanks, inputs, outputs, feerate):
    """
    Generate a full set of fusion components, commitments, keys, and proofs.

    count: int
    inputs: dict of {(prevout_hash, prevout_n): (pubkey, integer value in sats)}
    outputs: list of [(value, addr), (value, addr) ...]
    feerate: int (sat/kB)

    Returns:
        list of InitialCommitment,
        list of component original indices (inputs then outputs then blanks),
        list of serialized Component,
        list of Proof,
        list of communication privkey,
        Pedersen amount for total, (== excess fee)
        Pedersen nonce for total,
    """
    assert num_blanks >= 0

    components = []
    for (phash, pn), (pubkey, value) in inputs:
        fee = component_fee(size_of_input(pubkey), feerate)
        comp = pb.Component()
        comp.input.prev_txid = bytes.fromhex(phash)[::-1]
        comp.input.prev_index = pn
        comp.input.pubkey = pubkey
        comp.input.amount = value
        components.append((comp, +value-fee))
    for value, addr in outputs:
        script = addr.to_script()
        fee = component_fee(size_of_output(script), feerate)
        comp = pb.Component()
        comp.output.scriptpubkey = script
        comp.output.amount = value
        components.append((comp, -value-fee))
    for _ in range(num_blanks):
        comp = pb.Component(blank={})
        components.append((comp, 0))

    # Generate commitments and (partial) proofs
    resultlist = []
    sum_nonce = 0
    sum_amounts = 0
    for cnum, (comp, commitamount) in enumerate(components):
        salt = secrets.token_bytes(32)
        comp.salt_commitment = sha256(salt)
        compser = comp.SerializeToString()

        pedersencommitment = Protocol.PEDERSEN.commit(commitamount)
        sum_nonce += pedersencommitment.nonce
        sum_amounts += commitamount

        privkey, pubkeyU, pubkeyC = gen_keypair()

        commitment = pb.InitialCommitment()
        commitment.salted_component_hash = sha256(salt+compser)
        commitment.amount_commitment = pedersencommitment.P_uncompressed
        commitment.communication_key = pubkeyC

        commitser = commitment.SerializeToString()

        proof = pb.Proof()
        # proof.component_idx = <to be filled in later>
        proof.salt = salt
        proof.pedersen_nonce = int(pedersencommitment.nonce).to_bytes(32, 'big')

        resultlist.append((commitser, cnum, compser, proof, privkey))

    # Sort by the commitment bytestring, in order to forget the original order.
    resultlist.sort(key=lambda x:x[0])

    sum_nonce = sum_nonce % pedersen.order
    pedersen_total_nonce = int(sum_nonce).to_bytes(32, 'big')

    return zip(*resultlist), sum_amounts, pedersen_total_nonce


class Fusion(threading.Thread, PrintError):
    """ Represents a single connection to the fusion server and a fusion attempt.
    This happens in its own thread, in the background.

    Usage:

    1. Create Fusion object.
    2. Use add_coins* methods to add inputs.
    3. Call .start() -- this will connect, register, and fuse.
    4. To request stopping the fusion before completion, call .stop(). then wait
       for the thread to stop (call .join() to wait). This may take some time.
    """
    stopping=False
    stopping_if_not_running=False
    max_outputs = None
    status=('setup', None) # will always be 2-tuple; second param has extra details

    def __init__(self, plugin, target_wallet, server_host, server_port, server_ssl, tor_host, tor_port):
        super().__init__()

        assert can_fuse_to(target_wallet)
        self.weak_plugin = weakref.ref(plugin)
        self.target_wallet = target_wallet
        self.network = target_wallet.network
        assert self.network

        self.server_host = server_host
        self.server_port = server_port
        self.server_ssl = server_ssl
        self.tor_host = tor_host
        self.tor_port = tor_port

        self.coins = dict() # full input info
        self.keypairs = dict()
        self.outputs = []
        # for detecting spends (and finally unfreezing coins) we remember for each wallet:
        # - which coins we have from that wallet ("txid:n"),
        # - which coin txids we have, and
        # - which txids we've already scanned for spends of our coins.
        self.source_wallet_info = defaultdict(lambda:(set(), set(), set()))
        self.distinct_inputs = 0
        self.roundcount = 0
        self.txid = None  # set iff completed ok

    @property
    def strong_plugin(self):
        return self.weak_plugin and self.weak_plugin()

    def add_coins(self, coins, keypairs):
        """ Add given P2PKH coins to be used as inputs in a fusion.

        - coins: dict of {(prevout_hash, prevout_n): (bytes pubkey, integer value in sats)}

        - keypairs: dict of {hex pubkey: bytes privkey}
        """
        assert self.status[0] == 'setup'
        for hpub, priv in keypairs.items():
            assert isinstance(hpub, str)
            assert isinstance(priv, tuple) and len(priv) == 2
            sec, compressed = priv
            assert isinstance(sec, bytes) and len(sec) == 32
        self.keypairs.update(keypairs)
        for coin, (pub, value) in coins.items():
            assert pub[0] in (2,3,4), "expecting a realized pubkey"
            assert coin not in self.coins, "already added"
            assert pub.hex() in self.keypairs, f"missing private key for {pub.hex()}"
        self.coins.update(coins)

    def add_coins_from_wallet(self, wallet, password, coins):
        """
        Add coins from given wallet. `coins` should be an iterable like that
        returned from `wallet.get_utxos`. No checks are done that the coins are
        unfrozen, confirmed, matured, etc...

        The coins will be set to frozen in the wallet, and a subsequent call to
        `clear_coins` will unfreeze them. Once the fusion is started using
        .start(), it is guaranteed to unfreeze the coins when it finishes. But,
        if the wallet is closed first or crashes then coins will remain frozen.
        """
        assert can_fuse_from(wallet)
        if len(self.source_wallet_info) >= 5 and wallet not in self.source_wallet_info:
            raise RuntimeError("too many source wallets")
        if not hasattr(wallet, 'cashfusion_tag'):
            wallet.cashfusion_tag = sha256(tag_seed + wallet.diagnostic_name().encode())[:20]
        xpubkeys_set = set()
        for c in coins:
            wallet.add_input_info(c)
            xpubkey, = c['x_pubkeys']
            xpubkeys_set.add(xpubkey)

        # get private keys and convert x_pubkeys to real pubkeys
        keypairs = dict()
        pubkeys = dict()
        for xpubkey in xpubkeys_set:
            derivation = wallet.keystore.get_pubkey_derivation(xpubkey)
            privkey = wallet.keystore.get_private_key(derivation, password)
            pubkeyhex = public_key_from_private_key(*privkey)
            pubkey = bytes.fromhex(pubkeyhex)
            keypairs[pubkeyhex] = privkey
            pubkeys[xpubkey] = pubkey

        coindict = {(c['prevout_hash'], c['prevout_n']): (pubkeys[c['x_pubkeys'][0]], c['value']) for c in coins}
        self.add_coins(coindict, keypairs)

        coinstrs = set(t + ':' + str(i) for t,i in coindict)
        txids = set(t for t,i in coindict)
        self.source_wallet_info[wallet][0].update(coinstrs)
        self.source_wallet_info[wallet][1].update(txids)
        wallet.set_frozen_coin_state(coinstrs, True, temporary = True)
        self.notify_coins_ui(wallet)

    def check_coins(self):
        for wallet, (coins, mytxids, checked_txids) in self.source_wallet_info.items():
            with wallet.lock:
                wallet_txids = frozenset(wallet.transactions.keys())
                txids_to_scan = wallet_txids.difference(checked_txids)
                for txid in txids_to_scan:
                    txi = wallet.txi.get(txid, None)
                    if not txi:
                        continue
                    txspends = (c for addrtxi in txi.values() for c,v in addrtxi)
                    spent = coins.intersection(txspends)
                    if spent:
                        raise FusionError(f"input spent: {spent.pop()} spent in {txid}")

            checked_txids.update(txids_to_scan)

            missing = mytxids.difference(wallet_txids)
            if missing:
                raise FusionError(f"input missing: {missing.pop()}")

    def clear_coins(self):
        """ Clear the inputs list and release frozen coins. """
        for wallet, (coins, mytxids, checked_txids) in self.source_wallet_info.items():
            wallet.set_frozen_coin_state(coins, False)
            self.notify_coins_ui(wallet)
        self.source_wallet_info.clear() # save some memory as the checked_txids set can be big
        self.coins.clear()
        self.keypairs.clear()

    def notify_coins_ui(self, wallet):
        strong_plugin = self.strong_plugin  # property get from self.weak_plugin
        if strong_plugin:
            strong_plugin.update_coins_ui(wallet)

    def notify_server_status(self, b, tup=None):
        '''True means server is good, False it's bad. This ultimately makes
        its way to the UI to tell the user there is a connectivity or other
        problem. '''
        strong_plugin = self.strong_plugin  # hold strong ref for duration of function
        if strong_plugin:
            if not isinstance(tup, (tuple, list)) or len(tup) != 2:
                tup = "Ok" if b else "Error", ''
            strong_plugin.notify_server_status(b, tup)

    def start(self, inactive_timeout = None):
        if inactive_timeout is None:
            self.inactive_time_limit = None
        else:
            self.inactive_time_limit = time.monotonic() + inactive_timeout
        assert self.coins
        super().start()

    def run(self):
        server_connected_and_greeted = False
        try:
            try:
                compatibility.check()
            except RuntimeError as e:
                raise FusionError("Incompatible: " + str(e))
            if (self.tor_host is not None and self.tor_port is not None
                    and not is_tor_port(self.tor_host, self.tor_port)):
                raise FusionError(f"Can't connect to Tor proxy at {self.tor_host}:{self.tor_port}")

            self.check_stop(running = False)
            self.check_coins()

            # Connect to the server
            self.status = ('connecting', '')
            try:
                self.connection = open_connection(self.server_host, self.server_port, conn_timeout=5.0, default_timeout=5.0, ssl=self.server_ssl)
            except OSError as e:
                self.print_error("Connect failed:", repr(e))
                sslstr = ' SSL ' if self.server_ssl else ''
                raise FusionError(f'Could not connect to {sslstr}{self.server_host}:{self.server_port}') from e

            with self.connection:
                # Version check and download server params.
                self.greet()

                server_connected_and_greeted = True
                self.notify_server_status(True)

                # In principle we can hook a pause in here -- user can insert coins after seeing server params.

                if not self.coins:
                    raise FusionError('Started with no coins')
                self.allocate_outputs()

                # In principle we can hook a pause in here -- user can tweak tier_outputs, perhaps cancelling some unwanted tiers.

                # Register for tiers, wait for a pool.
                self.register_and_wait()

                # launch the covert submitter
                covert = self.start_covert()
                try:
                    # Pool started. Keep running rounds until fail or complete.
                    while True:
                        self.roundcount += 1
                        if self.run_round(covert):
                            break
                finally:
                    covert.stop()

            self.status = ('complete', 'time_wait')

            # The server has told us the fusion is complete but we might not
            # have seen the tx show up in our wallets. So we can't unfreeze
            # coins or unreserve addresses yet, else they might be used in
            # another fusion. Wait up to a minute for this to happen.
            wallets = set(self.source_wallet_info.keys())
            wallets.add(self.target_wallet)
            for _ in range(60):
                if self.stopping:
                    break # not an error
                for w in wallets:
                    if self.txid not in w.transactions:
                        break
                else:
                    break
                time.sleep(1)

            self.status = ('complete', 'txid: ' + self.txid)
        except FusionError as err:
            self.print_error('Failed: {}'.format(err))
            self.status = ('failed', err.args[0] if err.args else 'Unknown error')
        except Exception as exc:
            import traceback
            traceback.print_exc(file=sys.stderr)
            self.status = ('failed', 'Exception {}: {}'.format(type(exc).__name__, exc))
        finally:
            self.clear_coins()
            if self.status[0] != 'complete':
                for amount, addr in self.outputs:
                    self.target_wallet.unreserve_change_address(addr)
                if not server_connected_and_greeted:
                    self.notify_server_status(False, self.status)

    def stop(self, reason = 'stopped', not_if_running = False):
        if self.stopping:
            return
        if not_if_running:
            if self.stopping_if_not_running:
                return
            self.stop_reason = reason
            self.stopping_if_not_running = True
        else:
            self.stop_reason = reason
            self.stopping = True
        # note the reason is only overwritten if we were not already stopping this way.

    def check_stop(self, running=True):
        """ Gets called occasionally from fusion thread to allow a stop point. """
        if self.stopping or (not running and self.stopping_if_not_running):
            raise FusionError(self.stop_reason)

    def recv(self, *expected_msg_names, timeout=None):
        submsg, mtype = recv_pb(self.connection, pb.ServerMessage, 'error', *expected_msg_names, timeout=timeout)

        if mtype == 'error':
            raise FusionError('server error: {!r}'.format(submsg.message))

        return submsg

    def send(self, submsg, timeout=None):
        send_pb(self.connection, pb.ClientMessage, submsg, timeout=timeout)

    ## Rough phases of protocol

    def greet(self,):
        self.print_error('greeting server')
        self.send(pb.ClientHello(version=Protocol.VERSION, genesis_hash=get_current_genesis_hash()))
        reply = self.recv('serverhello')
        self.num_components = reply.num_components
        self.component_feerate = reply.component_feerate
        self.min_excess_fee = reply.min_excess_fee
        self.max_excess_fee = reply.max_excess_fee
        self.available_tiers = tuple(reply.tiers)
        strong_plugin = self.strong_plugin
        if strong_plugin:
            strong_plugin.set_remote_donation_address(reply.donation_address)

        # Enforce some sensible limits, in case server is crazy
        if self.component_feerate > MAX_COMPONENT_FEERATE:
            raise FusionError('excessive component feerate from server')
        if self.min_excess_fee > 400:
            # note this threshold should be far below MAX_EXCESS_FEE
            raise FusionError('excessive min excess fee from server')
        if self.min_excess_fee > self.max_excess_fee:
            raise FusionError('bad config on server: fees')
        if self.num_components < MIN_TX_COMPONENTS * 1.5:
            raise FusionError('bad config on server: num_components')

    def allocate_outputs(self,):
        assert self.status[0] in ('setup', 'connecting')

        # fix the input selection
        self.inputs = tuple(self.coins.items())
        num_inputs = len(self.inputs)

        maxcomponents = min(self.num_components, MAX_COMPONENTS)
        max_outputs = maxcomponents - num_inputs
        if max_outputs < 1:
            raise FusionError('Too many inputs (%d >= %d)'%(num_inputs, maxcomponents))

        if self.max_outputs is not None:
            assert self.max_outputs >= 1
            max_outputs = min(self.max_outputs, max_outputs)

        # For obfuscation, when there are few distinct inputs we want to have many
        # outputs.
        # Calculate the number of distinct inputs as the number of distinct pubkeys
        # (i.e. extra inputs from same address don't count as distinct)
        num_distinct = len(set(pub for (_,_), (pub,_) in self.inputs))
        min_outputs = max(MIN_TX_COMPONENTS - num_distinct, 1)
        if max_outputs < min_outputs:
            raise FusionError('Too few distinct inputs selected (%d); cannot satisfy output count constraint (>=%d, <=%d)'%(num_distinct, min_outputs, max_outputs))

        # how much input value do we bring to the table (after input & player fees)
        sum_inputs_value = sum(v for (_,_), (p,v) in self.inputs)
        input_fees = sum(component_fee(size_of_input(p), self.component_feerate) for (_,_), (p,v) in self.inputs)
        avail_for_outputs = (sum_inputs_value
                             - input_fees
                             - self.min_excess_fee)

        # each P2PKH output will need at least this much allocated to it.
        fee_per_output = component_fee(34, self.component_feerate)
        offset_per_output = Protocol.MIN_OUTPUT + fee_per_output

        if avail_for_outputs < offset_per_output:
            # our input amounts are so small that we can't even manage a single output.
            raise FusionError('Selected inputs had too little value')

        rng = Random()
        rng.seed(secrets.token_bytes(32))

        tier_outputs = {}
        excess_fees = {}
        for scale in self.available_tiers:
            ### Fuzzing fee range selection ###
            # To keep privacy at higher tiers, we need to randomize our input-output
            # linkage somehow, which means throwing away some sats as extra fees beyond
            # the minimum requirement.

            # For now, just throw on a few unobtrusive extra sats at the higher tiers, at most 9.
            # TODO: smarter selection for high tiers (how much will users be comfortable paying?)
            fuzz_fee_max = min(9, scale // 1000000)

            ### End fuzzing fee range selection ###

            # Now choose a random fuzz fee. Uniform random is best for obfuscation.
            # But before we do, there is a maximum fuzzing fee that is admitted by server, and
            # a safety maximum that we have ourselves.
            fuzz_fee_max_reduced = min(fuzz_fee_max,
                                       MAX_EXCESS_FEE - self.min_excess_fee,
                                       self.max_excess_fee - self.min_excess_fee)
            assert fuzz_fee_max_reduced >= 0
            fuzz_fee = secrets.randbelow(fuzz_fee_max_reduced + 1)
            assert fuzz_fee <= fuzz_fee_max_reduced and fuzz_fee_max_reduced <= fuzz_fee_max

            # TODO: this can be removed when the above is updated
            assert fuzz_fee < 100, 'sanity check: example fuzz fee should be small'

            reduced_avail_for_outputs = avail_for_outputs - fuzz_fee
            if reduced_avail_for_outputs < offset_per_output:
                continue

            outputs = random_outputs_for_tier(rng, reduced_avail_for_outputs, scale, offset_per_output, max_outputs)
            if not outputs or len(outputs) < min_outputs:
                # this tier is no good for us.
                continue
            # subtract off the per-output fees that we provided for, above.
            outputs = tuple(o - fee_per_output for o in outputs)

            assert len(self.inputs) + len(outputs) <= MAX_COMPONENTS
            excess_fees[scale] = sum_inputs_value - input_fees - reduced_avail_for_outputs
            tier_outputs[scale] = outputs

        self.tier_outputs = tier_outputs
        self.print_error(f"Possible tiers: {tier_outputs}")

        # remember these for safety check later on
        self.safety_sum_in = sum_inputs_value
        self.safety_excess_fees = excess_fees

    def register_and_wait(self,):
        tier_outputs = self.tier_outputs
        tiers_sorted = sorted(tier_outputs.keys())

        if not tier_outputs:
            raise FusionError('No outputs available at any tier (selected inputs were too small / too large).')

        self.print_error(f'registering for tiers: {tiers_sorted}')

        tags = []
        for wallet in self.source_wallet_info:
            selffuse = Conf(wallet).self_fuse_players
            tags.append(pb.JoinPools.PoolTag(id = wallet.cashfusion_tag, limit = selffuse))

        ## Join waiting pools
        self.check_stop(running=False)
        self.check_coins()
        self.send(pb.JoinPools(tiers = tiers_sorted, tags=tags))

        self.status = ('waiting', 'Registered for tiers')

        # make nicer strings for UI
        tiers_strings = {t: '{:.8f}'.format(t * 1e-8).rstrip('0') for t, s in tier_outputs.items()}

        while True:
            # We should get a status update every 5 seconds.
            msg = self.recv('tierstatusupdate', 'fusionbegin', timeout=10)

            if isinstance(msg, pb.FusionBegin):
                break

            self.check_stop(running=False)
            self.check_coins()

            assert isinstance(msg, pb.TierStatusUpdate)

            statuses = msg.statuses
            maxfraction = 0.
            maxtiers = []
            besttime = None
            besttimetier = None
            for t,s in statuses.items():
                try:
                    frac = s.players / s.min_players
                except ZeroDivisionError:
                    frac = -1.
                if frac >= maxfraction:
                    if frac > maxfraction:
                        maxfraction = frac
                        maxtiers.clear()
                    maxtiers.append(t)
                if s.HasField('time_remaining'):
                    tr = s.time_remaining
                    if besttime is None or tr < besttime:
                        besttime = tr
                        besttimetier = t

            maxtiers = set(maxtiers)

            display_best = []
            display_mid = []
            display_queued = []
            for t in tiers_sorted:
                try:
                    ts = tiers_strings[t]
                except KeyError:
                    raise FusionError('server reported status on tier we are not registered for')
                if t in statuses:
                    if t == besttimetier:
                        display_best.insert(0, '**' + ts + '**')
                    elif t in maxtiers:
                        display_best.append('[' + ts + ']')
                    else:
                        display_mid.append(ts)
                else:
                    display_queued.append(ts)

            parts = []
            if display_best or display_mid:
                parts.append(_("Tiers:") + ' ' + ', '.join(display_best + display_mid))
            if display_queued:
                parts.append(_("Queued:") + ' ' + ', '.join(display_queued))
            tiers_string = ' '.join(parts)

            if besttime is None and self.inactive_time_limit is not None:
                if time.monotonic() > self.inactive_time_limit:
                    raise FusionError('stopping due to inactivity')

            if besttime is not None:
                self.status = ('waiting', 'Starting in {}s. {}'.format(besttime, tiers_string))
            elif maxfraction >= 1:
                self.status = ('waiting', 'Starting soon. {}'.format(tiers_string))
            elif display_best or display_mid:
                self.status = ('waiting', '{:d}% full. {}'.format(round(maxfraction*100), tiers_string))
            else:
                self.status = ('waiting', tiers_string)

        assert isinstance(msg, pb.FusionBegin)
        # Record the time we got FusionBegin. Later in run_round we will check that the
        # first round comes at a very particular time relative to this message.
        self.t_fusionbegin = time.monotonic()

        # Check the server's declared unix time, which will be committed.
        clock_mismatch = msg.server_time - time.time()
        if abs(clock_mismatch) > Protocol.MAX_CLOCK_DISCREPANCY:
            raise FusionError(f"Clock mismatch too large: {clock_mismatch:+.3f}.")

        self.tier = msg.tier
        self.covert_domain_b = msg.covert_domain
        self.covert_port = msg.covert_port
        self.covert_ssl = msg.covert_ssl
        self.begin_time = msg.server_time

        self.last_hash = calc_initial_hash(self.tier, msg.covert_domain, msg.covert_port, msg.covert_ssl, msg.server_time)

        out_amounts = tier_outputs[self.tier]
        out_addrs = self.target_wallet.reserve_change_addresses(len(out_amounts), temporary=True)
        self.reserved_addresses = out_addrs
        self.outputs = list(zip(out_amounts, out_addrs))
        self.safety_excess_fee = self.safety_excess_fees[self.tier]
        self.print_error(f"starting fusion rounds at tier {self.tier}: {len(self.inputs)} inputs and {len(self.outputs)} outputs")

    def start_covert(self, ):
        self.status = ('running', 'Setting up Tor connections')
        try:
            covert_domain = self.covert_domain_b.decode('ascii')
        except:
            raise FusionError('badly encoded covert domain')
        covert = CovertSubmitter(covert_domain, self.covert_port, self.covert_ssl, self.tor_host, self.tor_port, self.num_components, Protocol.COVERT_SUBMIT_WINDOW, Protocol.COVERT_SUBMIT_TIMEOUT)
        try:
            covert.schedule_connections(self.t_fusionbegin, Protocol.COVERT_CONNECT_WINDOW, Protocol.COVERT_CONNECT_SPARES, Protocol.COVERT_CONNECT_TIMEOUT)

            # loop until a just a bit before we're expecting startround, watching for status updates
            tend = self.t_fusionbegin + (Protocol.WARMUP_TIME - Protocol.WARMUP_SLOP - 1)
            while time.monotonic() < tend:
                num_connected = sum(1 for s in covert.slots if s.covconn.connection is not None)
                num_spare_connected = sum(1 for c in tuple(covert.spare_connections) if c.connection is not None)
                self.status = ('running', f'Setting up Tor connections ({num_connected}+{num_spare_connected} out of {self.num_components})')
                time.sleep(1)

                covert.check_ok()
                self.check_stop()
                self.check_coins()

        except:
            covert.stop()
            raise

        return covert

    def run_round(self, covert):
        self.status = ('running', 'Starting round {}'.format(self.roundcount))
        msg = self.recv('startround', timeout = 2 * Protocol.WARMUP_SLOP + Protocol.STANDARD_TIMEOUT)
        # record the time we got this message; it forms the basis time for all
        # covert activities.
        clock = time.monotonic
        covert_T0 = clock()
        covert_clock = lambda: clock() - covert_T0

        round_time = msg.server_time

        # Check the server's declared unix time, which will be committed.
        clock_mismatch = msg.server_time - time.time()
        if abs(clock_mismatch) > Protocol.MAX_CLOCK_DISCREPANCY:
            raise FusionError(f"Clock mismatch too large: {clock_mismatch:+.3f}.")

        if self.t_fusionbegin is not None:
            # On the first startround message, check that the warmup time
            # was within acceptable bounds.
            lag = covert_T0 - self.t_fusionbegin - Protocol.WARMUP_TIME
            if abs(lag) > Protocol.WARMUP_SLOP:
                raise FusionError(f"Warmup period too different from expectation (|{lag:.3f}s| > {Protocol.WARMUP_SLOP:.3f}s).")
            self.t_fusionbegin = None

        self.print_error(f"round starting at {time.time()}")

        # Safety against funds loss: re-check our calculations for consistency and
        # impose sanity limits.
        input_fees = sum(component_fee(size_of_input(p), self.component_feerate) for (_,_), (p,v) in self.inputs)
        output_fees = len(self.outputs) * component_fee(34, self.component_feerate)
        sum_in = sum(amt for (_, _), (pub, amt) in self.inputs)
        sum_out = sum(amt for amt, addr in self.outputs)
        total_fee = sum_in - sum_out
        excess_fee = total_fee - input_fees - output_fees
        safeties = (
                sum_in     == self.safety_sum_in,
                excess_fee == self.safety_excess_fee,
                excess_fee <= MAX_EXCESS_FEE,
                total_fee  <= MAX_FEE,
                )
        if not all(safeties):
            # Don't use assert for funds-loss check. We want this check active always.
            raise RuntimeError(f"(BUG!) Funds re-check failed -- aborting for safety. {safeties}")

        round_pubkey = msg.round_pubkey

        blind_nonce_points = msg.blind_nonce_points
        if len(blind_nonce_points) != self.num_components:
            raise FusionError('blind nonce miscount')

        num_blanks = self.num_components - len(self.inputs) - len(self.outputs)
        (mycommitments, mycomponentslots, mycomponents, myproofs, privkeys), pedersen_amount, pedersen_nonce = gen_components(num_blanks, self.inputs, self.outputs, self.component_feerate)

        assert excess_fee == pedersen_amount # sanity check that we didn't mess up the above
        assert len(set(mycomponents)) == len(mycomponents) # no duplicates

        blindsigrequests = [schnorr.BlindSignatureRequest(round_pubkey, R, sha256(m))
                            for R,m in zip(blind_nonce_points, mycomponents)]

        random_number = secrets.token_bytes(32)

        # our final chance to leave in the nicest way possible: before sending commitments / requesting signatures.
        covert.check_ok()
        self.check_stop()
        self.check_coins()

        self.send(pb.PlayerCommit(initial_commitments = mycommitments,
                                  excess_fee = excess_fee,
                                  pedersen_total_nonce = pedersen_nonce,
                                  random_number_commitment = sha256(random_number),
                                  blind_sig_requests = [r.get_request() for r in blindsigrequests],
                                  ))

        msg = self.recv('blindsigresponses', timeout=Protocol.T_START_COMPS)
        assert len(msg.scalars) == len(blindsigrequests)
        blindsigs = [r.finalize(sbytes, check=True)
                     for r,sbytes in zip(blindsigrequests, msg.scalars)]

        # sleep until the covert component phase really starts, to catch covert connection failures.
        remtime = Protocol.T_START_COMPS - covert_clock()
        if remtime < 0:
            raise FusionError('Arrived at covert-component phase too slowly.')
        time.sleep(remtime)

        # Our final check to leave the fusion pool, before we start telling our
        # components. This is much more annoying since it will cause the round
        # to fail, but since we would end up killing the round anyway then it's
        # best for our privacy if we just leave now.
        # (This also is our first call to check_connected.)
        covert.check_connected()
        self.check_coins()

        ### Start covert component submissions
        self.print_error("starting covert component submission")
        self.status = ('running', 'covert submission: components')

        # If we fail after this point, we want to stop connections gradually and
        # randomly. We don't want to stop them
        # all at once, since if we had already provided our input components
        # then it would be a leak to have them all drop at once.
        covert.set_stop_time(covert_T0 + Protocol.T_START_CLOSE)

        # Schedule covert submissions.
        messages = [None] * len(mycomponents)
        for i, (comp, sig) in enumerate(zip(mycomponents, blindsigs)):
            messages[mycomponentslots[i]] = pb.CovertComponent(round_pubkey = round_pubkey, signature = sig, component = comp)
        assert all(messages)
        covert.schedule_submissions(covert_T0 + Protocol.T_START_COMPS, messages)

        # While submitting, we download the (large) full commitment list.
        msg = self.recv('allcommitments', timeout=Protocol.T_START_SIGS)
        all_commitments = tuple(msg.initial_commitments)

        # Quick check on the commitment list.
        if len(set(all_commitments)) != len(all_commitments):
            raise FusionError('Commitments list includes duplicates.')
        try:
            my_commitment_idxes = [all_commitments.index(c) for c in mycommitments]
        except ValueError:
            raise FusionError('One or more of my commitments missing.')

        remtime = Protocol.T_START_SIGS - covert_clock()
        if remtime < 0:
            raise FusionError('took too long to download commitments list')

        # Once all components are received, the server shares them with us:
        msg = self.recv('sharecovertcomponents', timeout=Protocol.T_START_SIGS)
        all_components = tuple(msg.components)
        skip_signatures = bool(msg.skip_signatures)

        # Critical check on server's response timing.
        if covert_clock() > Protocol.T_START_SIGS:
            raise FusionError('Shared components message arrived too slowly.')

        covert.check_done()

        # Find my components
        try:
            mycomponent_idxes = [all_components.index(c) for c in mycomponents]
        except ValueError:
            raise FusionError('One or more of my components missing.')


        # TODO: check the components list and see if there are enough inputs/outputs
        # for there to be significant privacy.


        # The session hash includes all relevant information that the server
        # should have told equally to all the players. If the server tries to
        # sneakily spy on players by saying different things to them, then the
        # users will sign different transactions and the fusion will fail.
        self.last_hash = session_hash = calc_round_hash(self.last_hash, round_pubkey, round_time, all_commitments, all_components)
        if msg.HasField('session_hash') and msg.session_hash != session_hash:
            raise FusionError('Session hash mismatch (bug!)')

        ### Start covert signature submissions (or skip)

        if not skip_signatures:
            self.print_error("starting covert signature submission")
            self.status = ('running', 'covert submission: signatures')

            if len(set(all_components)) != len(all_components):
                raise FusionError('Server component list includes duplicates.')

            tx, input_indices = tx_from_components(all_components, session_hash)

            # iterate over my inputs and sign them
            # We don't use tx.sign() here since:
            # - it doesn't currently allow us to use sighash cache.
            # - it's a bit dangerous to sign all inputs since this invites
            #   attackers to try to get us to sign coins we own but that we
            #   didn't submit. (with other bugs, could lead to funds loss!).
            # - we'd need to extract out the result anyway, so doesn't win
            #   anything in simplicity.
            messages = [None] * len(mycomponents)
            for i, (cidx, inp) in enumerate(zip(input_indices, tx.inputs())):
                try:
                    mycompidx = mycomponent_idxes.index(cidx)
                except ValueError:
                    continue # not my input
                sec, compressed = self.keypairs[inp['pubkeys'][0]]
                sighash = sha256(sha256(bytes.fromhex(tx.serialize_preimage(i, 0x41, use_cache = True))))
                sig = schnorr.sign(sec, sighash)

                messages[mycomponentslots[mycompidx]] = pb.CovertTransactionSignature(txsignature = sig, which_input = i)
            covert.schedule_submissions(covert_T0 + Protocol.T_START_SIGS, messages)

            # wait for result
            msg = self.recv('fusionresult', timeout=Protocol.T_EXPECTING_CONCLUSION - Protocol.TS_EXPECTING_COVERT_COMPONENTS)

            # Critical check on server's response timing.
            if covert_clock() > Protocol.T_EXPECTING_CONCLUSION:
                raise FusionError('Fusion result message arrived too slowly.')

            covert.check_done()

            if msg.ok:
                allsigs = msg.txsignatures
                # assemble the transaction.
                if len(allsigs) != len(tx.inputs()):
                    raise FusionError('Server gave wrong number of signatures.')
                for i, (sig, inp) in enumerate(zip(allsigs, tx.inputs())):
                    if len(sig) != 64:
                        raise FusionError('server relayed bad signature')
                    inp['signatures'] = [sig.hex() + '41']

                assert tx.is_complete()
                txhex = tx.serialize()

                self.txid = txid = tx.txid()
                sum_in_str = format_satoshis(sum_in, num_zeros=8)
                fee_str = str(total_fee)
                feeloc = _('fee')
                label = f"CashFusion {len(self.inputs)}⇢{len(self.outputs)}, {sum_in_str} BCH (−{fee_str} sats {feeloc})"
                wallets = set(self.source_wallet_info.keys())
                wallets.add(self.target_wallet)
                if len(wallets) > 1:
                    label += f" {sorted(str(w) for w in self.source_wallet_info.keys())!r} ➡ {str(self.target_wallet)!r}"
                # If we have any sweep-inputs, should also modify label
                # If we have any send-outputs, should also modify label
                def update_wallet_label_in_main_thread_paranoia(wallets, txid, label):
                    '''We do it this way because run_hook may be invoked as a
                    result of set_label and that's not well defined if not done
                    in the main (GUI) thread. '''
                    for w in wallets:
                        with w.lock:
                            existing_label = w.labels.get(txid, None)
                            if existing_label is not None:
                                label = existing_label + '; ' + label
                            w.set_label(txid, label)

                do_in_main_thread(update_wallet_label_in_main_thread_paranoia,
                                  wallets, txid, label)

                try:
                    # deep copy here is extra (possibly unnecessary) paranoia to
                    # freeze the tx that is broadcast and not allow it to point
                    # to our all_components data, etc.
                    self.network.broadcast_transaction2(copy.deepcopy(tx),)
                except ServerError as e:
                    nice_msg, = e.args
                    server_msg = str(e.server_msg)
                    if isinstance(e, TxHashMismatch):
                        # This should never actually happen. The TxHashMismatch
                        # bug is believed to have been fixed as of
                        # commit 4582391276a377c7a91a7a4285f4336abce2014b.
                        self.print_error("Server responded with:", server_msg, ", we expected:", txid)
                    acceptable_substrings = (
                        r"txn-already-in-mempool", r"txn-already-known",
                        r"transaction already in block chain",
                    )
                    if not any(s in server_msg for s in acceptable_substrings):
                        server_msg = server_msg.replace(txhex, "<...tx hex...>")
                        self.print_error("tx broadcast failed:", repr(server_msg))
                        raise FusionError(f"could not broadcast the transaction: {nice_msg}") from e
                except TimeoutException:
                    raise FusionError("could not broadcast the transaction due to timeout")

                self.print_error(f"successful broadcast of {txid}")
                return True

            else:
                bad_components = set(msg.bad_components)
                if not bad_components.isdisjoint(mycomponent_idxes):
                    self.print_error(f"bad components: {sorted(bad_components)} mine: {sorted(mycomponent_idxes)}")
                    raise FusionError("server thinks one of my components is bad!")
        else: # skip_signatures True
            bad_components = set()


        ### Blame phase ###

        covert.set_stop_time(covert_T0 + Protocol.T_START_CLOSE_BLAME)
        self.print_error("sending proofs")
        self.status = ('running', 'round failed - sending proofs')

        # create a list of commitment indexes, but leaving out mine.
        others_commitment_idxes = [i for i in range(len(all_commitments)) if i not in my_commitment_idxes]
        N = len(others_commitment_idxes)
        assert N == len(all_commitments) - len(mycommitments)
        if N == 0:
            raise FusionError("Fusion failed with only me as player -- I can only blame myself.")

        # where should I send my proofs?
        dst_commits = [all_commitments[others_commitment_idxes[rand_position(random_number, N, i)]] for i in range(len(mycommitments))]
        # generate the encrypted proofs
        encproofs = [b'']*len(mycommitments)
        for i, (dst_commit, proof) in enumerate(zip(dst_commits, myproofs)):
            msg = pb.InitialCommitment()
            try:
                msg.ParseFromString(dst_commit)
            except DecodeError:
                raise FusionError("Server relayed a bad commitment; can't proceed with blame.")
            proof.component_idx = mycomponent_idxes[i]
            try:
                encproofs[i] = encrypt.encrypt(proof.SerializeToString(), msg.communication_key, pad_to_length = 80)
            except encrypt.EncryptionFailed:
                # The communication key was bad (probably invalid x coordinate).
                # We will just send a blank. They can't even blame us since there is no private key! :)
                continue

        self.send(pb.MyProofsList(encrypted_proofs = encproofs,
                                  random_number = random_number,
                                  ))

        self.status = ('running', 'round failed - checking proofs')

        self.print_error("receiving proofs")
        msg = self.recv('theirproofslist', timeout = 2 * Protocol.STANDARD_TIMEOUT)
        blames = []
        count_inputs = 0
        for i, rp in enumerate(msg.proofs):
            try:
                privkey = privkeys[rp.dst_key_idx]
                commitmentblob = all_commitments[rp.src_commitment_idx]
            except IndexError:
                raise FusionError("Server relayed bad proof indices")
            try:
                proofblob, skey = encrypt.decrypt(rp.encrypted_proof, privkey)
            except encrypt.DecryptionFailed:
                self.print_error("found an undecryptable proof")
                blames.append(pb.Blames.BlameProof(which_proof = i, privkey = privkey, blame_reason = 'undecryptable'))
                continue
            try:
                commitment = pb.InitialCommitment()
                commitment.ParseFromString(commitmentblob)
            except DecodeError:
                raise FusionError("Server relayed bad commitment")
            try:
                inpcomp = validate_proof_internal(proofblob, commitment, all_components, bad_components, self.component_feerate)
            except ValidationError as e:
                self.print_error(f"found an erroneous proof: {e.args[0]}")
                blames.append(pb.Blames.BlameProof(which_proof = i, session_key = skey, blame_reason = e.args[0]))
                continue

            if inpcomp is not None:
                count_inputs += 1
                try:
                    check_input_electrumx(self.network, inpcomp)
                except ValidationError as e:
                    self.print_error(f"found a bad input [{rp.src_commitment_idx}]: {e.args[0]} ({inpcomp.prev_txid[::-1].hex()}:{inpcomp.prev_index})")
                    blames.append(pb.Blames.BlameProof(which_proof = i, session_key = skey, blame_reason = 'input does not match blockchain: ' + e.args[0],
                                                       need_lookup_blockchain = True))
                except Exception as e:
                    self.print_error(f"verified an input internally, but was unable to check it against blockchain: {repr(e)}")
        self.print_error(f"checked {len(msg.proofs)} proofs, {count_inputs} of them inputs")

        self.print_error("sending blames")
        self.send(pb.Blames(blames = blames))

        self.status = ('running', 'awaiting restart')

        # Await the final 'restartround' message. It might take some time
        # to arrive since other players might be slow, and then the server
        # itself needs to check blockchain.
        self.recv('restartround', timeout = 2 * (Protocol.STANDARD_TIMEOUT + Protocol.BLAME_VERIFY_TIME))
