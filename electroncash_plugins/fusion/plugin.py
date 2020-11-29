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
Base plugin (non-GUI)
"""
import math
import threading
import time
import weakref

from typing import Optional, Tuple

from electroncash.address import Address
from electroncash.bitcoin import COINBASE_MATURITY
from electroncash.plugins import BasePlugin, hook, daemon_command
from electroncash.i18n import _, ngettext, pgettext
from electroncash.util import profiler, PrintError, InvalidPassword
from electroncash import Network, networks

from .conf import Conf, Global
from .fusion import Fusion, can_fuse_from, can_fuse_to, is_tor_port, MIN_TX_COMPONENTS
from .server import FusionServer
from .covert import limiter

import random  # only used to select random coins

TOR_PORTS = [9050, 9150]
# if more than <N> tor connections have been made recently (see covert.py) then don't start auto-fuses.
AUTOFUSE_RECENT_TOR_LIMIT_LOWER = 60
# if more than <N> tor connections have been made recently (see covert.py) then shut down auto-fuses that aren't yet started
AUTOFUSE_RECENT_TOR_LIMIT_UPPER = 120

# heuristic factor: guess that expected number of coins in wallet in equilibrium is = (this number) / fraction
COIN_FRACTION_FUDGE_FACTOR = 10
# for semi-linked addresses (that share txids in their history), allow linking them with this probability:
KEEP_LINKED_PROBABILITY = 0.1

# how long an auto-fusion may stay in 'waiting' state (without starting-soon) before it cancels itself
AUTOFUSE_INACTIVE_TIMEOUT = 600

# how many random coins to select max in 1 batch -- used by select_random_coins
DEFAULT_MAX_COINS = 20
assert DEFAULT_MAX_COINS > 10

# how many autofusions can be running per-wallet
MAX_AUTOFUSIONS_PER_WALLET = 10

CONSOLIDATE_MAX_OUTPUTS = MIN_TX_COMPONENTS // 3

pnp = None
def get_upnp():
    """ return an initialized UPnP singleton """
    global pnp
    if pnp is not None:
        return pnp
    try:
        import miniupnpc
    except ImportError:
        raise RuntimeError("python miniupnpc module not installed")
    u = miniupnpc.UPnP()
    if u.discover() < 1:
        raise RuntimeError("can't find UPnP server")
    try:
        u.selectigd()
    except Exception as e:
        raise RuntimeError("failed to connect to UPnP IGD")
    pnp = u
    return u

def select_coins(wallet):
    """ Sort the wallet's coins into address buckets, returning two lists:
    - Eligible addresses and their coins.
    - Ineligible addresses and their coins.

    An address is eligible if it satisfies all conditions:
    - the address is unfrozen
    - has 1, 2, or 3 utxo
    - all utxo are confirmed (or matured in case of coinbases)
    - has no SLP utxo or frozen utxo
    """
    # First, select all the coins
    eligible = []
    ineligible = []
    has_unconfirmed = False
    has_coinbase = False
    sum_value = 0
    mincbheight = (wallet.get_local_height() + 1 - COINBASE_MATURITY if Conf(wallet).autofuse_coinbase
                   else -1)  # -1 here causes coinbase coins to always be rejected
    for addr in wallet.get_addresses():
        acoins = list(wallet.get_addr_utxo(addr).values())
        if not acoins:
            continue  # prevent inserting empty lists into eligible/ineligible
        good = True
        if addr in wallet.frozen_addresses:
            good = False
        for i,c in enumerate(acoins):
            sum_value += c['value']  # tally up values regardless of eligibility
            # If too many coins, any SLP tokens, any frozen coins, or any
            # immature coinbase on the address -> flag all address coins as
            # ineligible if not already flagged as such.
            good = good and (
                i < 3  # must not have too many coins on the same address*
                and not c['slp_token']  # must not be SLP
                and not c['is_frozen_coin']  # must not be frozen
                and (not c['coinbase'] or c['height'] <= mincbheight)  # if coinbase -> must be mature coinbase
            )
            # * = We skip addresses with too many coins, since they take up lots
            #     of 'space' for consolidation. TODO: there is possibility of
            #     disruption here, if we get dust spammed. Need to deal with
            #     'dusty' addresses by ignoring / consolidating dusty coins.

            # Next, detect has_unconfirmed & has_coinbase:
            if c['height'] <= 0:
                # Unconfirmed -> Flag as not eligible and set the has_unconfirmed flag.
                good = False
                has_unconfirmed = True
            # Update has_coinbase flag if not already set
            has_coinbase = has_coinbase or c['coinbase']
        if good:
            eligible.append((addr,acoins))
        else:
            ineligible.append((addr,acoins))

    return eligible, ineligible, int(sum_value), bool(has_unconfirmed), bool(has_coinbase)

def select_random_coins(wallet, fraction, eligible):
    """
    Grab wallet coins with a certain probability, while also paying attention
    to obvious linkages and possible linkages.
    Returns list of list of coins (bucketed by obvious linkage).
    """
    # First, we want to bucket coins together when they have obvious linkage.
    # Coins that are linked together should be spent together.
    # Currently, just look at address.
    addr_coins = eligible
    random.shuffle(addr_coins)

    # While fusing we want to pay attention to semi-correlations among coins.
    # When we fuse semi-linked coins, it increases the linkage. So we try to
    # avoid doing that (but rarely, we just do it anyway :D).
    # Currently, we just look at all txids touched by the address.
    # (TODO this is a disruption vector: someone can spam multiple fusions'
    #  output addrs with massive dust transactions (2900 outputs in 100 kB)
    #  that make the plugin think that all those addresses are linked.)
    result_txids = set()

    result = []
    num_coins = 0
    for addr, acoins in addr_coins:
        if num_coins >= DEFAULT_MAX_COINS:
            break
        elif num_coins + len(acoins) > DEFAULT_MAX_COINS:
            continue

        # For each bucket, we give a separate chance of joining.
        if random.random() > fraction:
            continue

        # Semi-linkage check:
        # We consider all txids involving the address, historical and current.
        ctxids = {txid for txid, height in wallet.get_address_history(addr)}
        collisions = ctxids.intersection(result_txids)
        # Note each collision gives a separate chance of discarding this bucket.
        if random.random() > KEEP_LINKED_PROBABILITY**len(collisions):
            continue
        # OK, no problems: let's include this bucket.
        num_coins += len(acoins)
        result.append(acoins)
        result_txids.update(ctxids)

    if not result:
        # nothing was selected, just try grabbing first nonempty bucket
        try:
            res = next(coins for addr,coins in addr_coins if coins)
            result = [res]
        except StopIteration:
            # all eligible buckets were cleared.
            pass

    return result

def get_target_params_1(wallet, wallet_conf, active_autofusions, eligible):
    """ WIP -- TODO: Rename this function. """
    wallet_conf = Conf(wallet)
    mode = wallet_conf.fusion_mode

    # Note each fusion 'consumes' a certain number of coins by freezing them,
    # so that the next fusion has less eligible coins to work with. So each
    # call to this may see a smaller n_buckets.
    n_buckets = len(eligible)
    if mode == 'normal':
        return max(2, round(n_buckets / DEFAULT_MAX_COINS)), False
    elif mode == 'fan-out':
        return max(4, math.ceil(n_buckets / (COIN_FRACTION_FUDGE_FACTOR*0.65))), False
    elif mode == 'consolidate':
        if n_buckets < MIN_TX_COMPONENTS - CONSOLIDATE_MAX_OUTPUTS:
            # Too few eligible buckets to make an effective consolidation.
            return 0, False

        # In the latter stages of consolidation, only do one fusion
        # at a time with all-confirmed rule, to make sure each fusion's outputs
        # may be consumed by the subsequent one.
        # To avoid weird loops, try to calculate the TOTAL number of coins
        # that are either 1) eligible or 2) being fused. (Should stay constant
        # as fusions are added/cancelled)
        n_coins = sum(len(acoins) for addr,acoins in eligible)
        n_total = n_coins + sum(len(getattr(f, 'inputs', ())) for f in active_autofusions)
        if n_total < DEFAULT_MAX_COINS*3:
            return 1, True

        # If coins are scarce then don't make more autofusions unless we
        # have none.
        if n_buckets < DEFAULT_MAX_COINS*2:
            return 1, False

        # We still have lots of coins left, so request another autofusion.
        return MAX_AUTOFUSIONS_PER_WALLET, False
    else:  # 'custom'
        target_num_auto = wallet_conf.queued_autofuse
        confirmed_only = wallet_conf.autofuse_confirmed_only
        return int(target_num_auto), bool(confirmed_only)


def get_target_params_2(wallet_conf, sum_value):
    """ WIP -- TODO: Rename this function. """
    mode = wallet_conf.fusion_mode

    fraction = 0.1

    if mode == 'custom':
        # Determine the fraction that should be used
        select_type, select_amount = wallet_conf.selector

        if select_type == 'size' and int(sum_value) != 0:
            # user wants to get a typical output of this size (in sats)
            fraction = COIN_FRACTION_FUDGE_FACTOR * select_amount / sum_value
        elif select_type == 'count' and int(select_amount) != 0:
            # user wants this number of coins
            fraction = COIN_FRACTION_FUDGE_FACTOR / select_amount
        elif select_type == 'fraction':
            # user wants this fraction
            fraction = select_amount
        # note: fraction at this point could be <0 or >1 but doesn't matter.
    elif mode == 'consolidate':
        fraction = 1.0
    elif mode == 'normal':
        fraction = 0.5
    elif mode == 'fan-out':
        fraction = 0.1

    return fraction


class FusionPlugin(BasePlugin):
    fusion_server = None
    active = True
    _run_iter = 0

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs) # gives us self.config
        # Do an initial check on the tor port
        self.tor_port_good = None
        t = threading.Thread(name = 'Fusion-scan_torport_initial', target = self.scan_torport)
        t.start()

        # quick lock for the following two WeakKeyDictionary variables
        # Locking order wallet.lock -> plugin.lock.
        self.lock = threading.Lock()

        self.fusions = weakref.WeakKeyDictionary()
        self.autofusing_wallets = weakref.WeakKeyDictionary()  # wallet -> password

        self.t_last_net_ok = time.monotonic()

        self.remote_donation_address: str = ''  # optionally announced by the remote server in 'serverhello' message

        if tuple(self.config.get('cashfusion_server', ())) == ('cashfusion.electroncash.dk', 8787, False):
            # User's config has the old default non-SSL server. If we see this,
            # just wipe the config key so that the new default is used.
            # But only reset once, after that let them go back if that is what
            # they truly desire.
            if self.config.get('cashfusion_server_defaultresetted', 0) < 1:
                self.config.set_key('cashfusion_server', None)
                self.config.set_key('cashfusion_server_defaultresetted', 1)

    def on_close(self,):
        super().on_close()
        self.stop_fusion_server()
        self.active = False

    def fullname(self):
        return 'CashFusion'

    def description(self):
        return _("CashFusion Protocol")

    def is_available(self):
        return networks.net is not networks.TaxCoinNet

    def set_remote_donation_address(self, address : str):
        self.remote_donation_address = ((isinstance(address, str) and address) or '')[:100]

    def get_server(self, ):
        return Global(self.config).server

    def set_server(self, host, port, ssl):
        gconf = Global(self.config)
        old = gconf.server
        gconf.server = (host, port, ssl)  # type/sanity checking done in setter
        if old != gconf.server:
            self.on_server_changed()

    def get_torhost(self):
        if self.has_auto_torport():
            return Global.Defaults.TorHost
        else:
            return Global(self.config).tor_host

    def set_torhost(self, host):
        ''' host should be a valid hostname '''
        if not host: return
        Global(self.config).tor_host = host

    def has_auto_torport(self, ):
        return Global(self.config).tor_port_auto

    def get_torport(self, ):
        ''' Retreive either manual port or autodetected port; may return None
        if 'auto' mode and no Tor port has been autodetected. (this is non-blocking) '''
        if self.has_auto_torport():
            return self.tor_port_good
        else:
            return Global(self.config).tor_port_manual

    def set_torport(self, port):
        # port may be 'auto' or 'manual' or an int
        gconf = Global(self.config)
        if port == 'auto':
            gconf.tor_port_auto = True
            return
        else:
            gconf.tor_port_auto = False
        if port == 'manual':
            return # we're simply going to use whatever manual port was already set
        assert isinstance(port, int)
        gconf.tor_port_manual = port

    def scan_torport(self, ):
        ''' Scan for Tor proxy on either the manual port or on a series of
        automatic ports. This is blocking. Returns port if it's up, or None if
        down / can't find. '''
        host = self.get_torhost()

        if self.has_auto_torport():
            portlist = []

            network = Network.get_instance()
            if network:
                tc = network.tor_controller
                if tc and tc.is_enabled() and tc.active_socks_port:
                    portlist.append(tc.active_socks_port)

            portlist.extend(TOR_PORTS)
        else:
            portlist = [ Global(self.config).tor_port_manual ]

        for port in portlist:
            if is_tor_port(host, port):
                self.tor_port_good = port
                break
        else:
            self.tor_port_good = None
        return self.tor_port_good

    def on_server_changed(self):
        """ When the server is changed, we stop all extant fusions that are not
        already 'running' in order to allow for the new change to take effect
        immediately. """
        self.remote_donation_address = ''
        self.stop_all_fusions('Server changed', not_if_running=True)

    def get_all_fusions(self, ):
        """ Return all still-live fusion objects that have been created using .start_fusion(),
        including autofusions and any other fusions. """
        with self.lock:
            fusions_and_times = list(self.fusions.items())
        fusions_and_times.sort(key=lambda x:x[1])
        return [f for f,t in fusions_and_times]

    def stop_all_fusions(self, reason, *, not_if_running=True):
        with self.lock:
            for f in list(self.fusions):
                f.stop(reason, not_if_running = not_if_running)

    @staticmethod
    def stop_autofusions(wallet, reason, *, not_if_running=True):
        with wallet.lock:
            try:
                fusion_weakset = wallet._fusions_auto
            except AttributeError:
                return []
            running = []
            for f in list(fusion_weakset):
                if not f.is_alive():
                    fusion_weakset.discard(f)
                    continue
                f.stop(reason, not_if_running = not_if_running)
                if f.status[0] == 'running':
                    running.append(f)
            return running

    def disable_autofusing(self, wallet):
        with self.lock:
            self.autofusing_wallets.pop(wallet, None)
        Conf(wallet).autofuse = False
        return self.stop_autofusions(wallet, 'Autofusing disabled', not_if_running=True)

    def enable_autofusing(self, wallet, password):
        if password is None and wallet.has_password():
            raise InvalidPassword()
        else:
            wallet.check_password(password)
        with self.lock:
            self.autofusing_wallets[wallet] = password
        Conf(wallet).autofuse = True

    def is_autofusing(self, wallet):
        with self.lock:
            return (wallet in self.autofusing_wallets)

    def add_wallet(self, wallet, password=None):
        ''' Attach the given wallet to fusion plugin, allowing it to be used in
        fusions with clean shutdown. Also start auto-fusions for wallets that want
        it (if no password).
        '''
        with wallet.lock:
            # Generate wallet._fusions and wallet._fusions_auto; these must
            # only be accessed with wallet.lock held.

            # all fusions relating to this wallet, either as source or target
            # or both.
            wallet._fusions = weakref.WeakSet()
            # fusions that were auto-started.
            wallet._fusions_auto = weakref.WeakSet()
            # all accesses to the above must be protected by wallet.lock

        if Conf(wallet).autofuse:
            try:
                self.enable_autofusing(wallet, password)
            except InvalidPassword:
                self.disable_autofusing(wallet)

    def remove_wallet(self, wallet):
        ''' Detach the provided wallet; returns list of active fusion threads. '''
        with self.lock:
            self.autofusing_wallets.pop(wallet, None)
        fusions = ()
        try:
            with wallet.lock:
                fusions = list(wallet._fusions)
                del wallet._fusions
                del wallet._fusions_auto
        except AttributeError:
            pass
        return [f for f in fusions if f.is_alive()]

    def start_fusion(self, source_wallet, password, coins, target_wallet = None, max_outputs = None, inactive_timeout = None):
        """ Create and start a new Fusion object with current server/tor settings.

        Both source_wallet.lock and target_wallet.lock must be held.
        FIXME: this condition is begging for a deadlock to happen when the two wallets
        are different. Need to find a better way if inter-wallet fusing actually happens.
        """
        if target_wallet is None:
            target_wallet = source_wallet # self-fuse
        assert can_fuse_from(source_wallet)
        assert can_fuse_to(target_wallet)
        host, port, ssl = self.get_server()
        if host == 'localhost':
            # as a special exemption for the local fusion server, we don't use Tor.
            torhost = None
            torport = None
        else:
            torhost = self.get_torhost()
            torport = self.get_torport()
            if torport is None:
                torport = self.scan_torport() # may block for a very short time ...
            if torport is None:
                self.notify_server_status(False, ("failed", _("Invalid Tor proxy or no Tor proxy found")))
                raise RuntimeError("can't find tor port")
        fusion = Fusion(self, target_wallet, host, port, ssl, torhost, torport)
        fusion.add_coins_from_wallet(source_wallet, password, coins)
        fusion.max_outputs = max_outputs
        with self.lock:
            fusion.start(inactive_timeout = inactive_timeout)
            self.fusions[fusion] = time.time()
        target_wallet._fusions.add(fusion)
        source_wallet._fusions.add(fusion)
        return fusion

    def thread_jobs(self, ):
        return [self]
    def run(self, ):
        # this gets called roughly every 0.1 s in the Plugins thread; downclock it to 5 s.
        run_iter = self._run_iter + 1
        if run_iter < 50:
            self._run_iter = run_iter
            return
        else:
            self._run_iter = 0

        if not self.active:
            return

        dont_start_fusions = False

        network = Network.get_instance()
        if network and network.is_connected():
            self.t_last_net_ok = time.monotonic()
        else:
            # Cashfusion needs an accurate picture of the wallet's coin set, so
            # that we don't reuse addresses and we don't submit already-spent coins.
            # Currently the network is not synced so we won't start new fusions.
            dont_start_fusions = True
            if time.monotonic() - self.t_last_net_ok > 31:
                # If the network is disconnected for an extended period, we also
                # shut down all waiting fusions. We can't wait too long because
                # one fusion might succeed but then enter the 'time_wait' period
                # where it is waiting to see the transaction on the network.
                # After 60 seconds it gives up and then will unreserve addresses,
                # and currently-waiting fusions would then grab those addresses when
                # they begin rounds.
                self.stop_all_fusions('Lost connection to Electron Cash server', not_if_running = True)
                return

        # Snapshot of autofusing list; note that remove_wallet may get
        # called on one of the wallets, after lock is released.
        with self.lock:
            wallets_and_passwords = list(self.autofusing_wallets.items())

        torcount = limiter.count
        if torcount > AUTOFUSE_RECENT_TOR_LIMIT_UPPER:
            # need tor cooldown, stop the waiting autofusions
            for wallet, password in wallets_and_passwords:
                self.stop_autofusions(wallet, 'Tor cooldown', not_if_running = True)
            return
        if torcount > AUTOFUSE_RECENT_TOR_LIMIT_LOWER:
            # no urgent need to stop fusions, but don't queue up any more.
            dont_start_fusions = True

        for wallet, password in wallets_and_passwords:
            with wallet.lock:
                if not hasattr(wallet, '_fusions'):
                    continue
                if not wallet.up_to_date:
                    # We want a good view of the wallet so we know which coins
                    # are unspent and confirmed, and we know which addrs are
                    # used. Note: this `continue` will bypass the potential .stop()
                    # below.
                    continue
                for f in list(wallet._fusions_auto):
                    if not f.is_alive():
                        wallet._fusions_auto.discard(f)
                active_autofusions = list(wallet._fusions_auto)
                if dont_start_fusions and not active_autofusions:
                    continue
                num_auto = len(active_autofusions)
                wallet_conf = Conf(wallet)
                eligible, ineligible, sum_value, has_unconfirmed, has_coinbase = select_coins(wallet)
                target_num_auto, confirmed_only = get_target_params_1(wallet, wallet_conf, active_autofusions, eligible)
                if confirmed_only and has_unconfirmed:
                    for f in list(wallet._fusions_auto):
                        f.stop('Wallet has unconfirmed coins... waiting.', not_if_running = True)
                    continue
                if not dont_start_fusions and num_auto < min(target_num_auto, MAX_AUTOFUSIONS_PER_WALLET):
                    # we don't have enough auto-fusions running, so start one
                    fraction = get_target_params_2(wallet_conf, sum_value)
                    chosen_buckets = select_random_coins(wallet, fraction, eligible)
                    coins = [c for l in chosen_buckets for c in l]
                    if not coins:
                        self.print_error("auto-fusion skipped due to lack of coins")
                        continue
                    if wallet_conf.fusion_mode == 'consolidate':
                        max_outputs = CONSOLIDATE_MAX_OUTPUTS
                        if len(chosen_buckets) < (MIN_TX_COMPONENTS - max_outputs):
                            self.print_error("consolidating auto-fusion skipped due to lack of unrelated coins")
                            continue
                    else:
                        max_outputs = None
                    try:
                        f = self.start_fusion(wallet, password, coins, max_outputs = max_outputs, inactive_timeout = AUTOFUSE_INACTIVE_TIMEOUT)
                        self.print_error("started auto-fusion")
                    except RuntimeError as e:
                        self.print_error(f"auto-fusion skipped due to error: {e}")
                        return
                    wallet._fusions_auto.add(f)

    def start_fusion_server(self, network, bindhost, port, upnp = None, announcehost = None, donation_address = None):
        if self.fusion_server:
            raise RuntimeError("server already running")
        donation_address = (isinstance(donation_address, Address) and donation_address) or None
        self.fusion_server = FusionServer(self.config, network, bindhost, port, upnp = upnp, announcehost = announcehost, donation_address = donation_address)
        self.fusion_server.start()
        return self.fusion_server.host, self.fusion_server.port

    def stop_fusion_server(self):
        try:
            self.fusion_server.stop('server stopped by operator')
            self.fusion_server = None
        except Exception:
            pass

    def update_coins_ui(self, wallet):
        ''' Default implementation does nothing. Qt plugin subclass overrides
        this, which sends a signal to the main thread to update the coins tab.
        This is called by the Fusion thread (in its thread context) when it
        freezes & unfreezes coins. '''

    def notify_server_status(self, b, tup : tuple = None):
        ''' The Qt plugin subclass implements this to tell the GUI about bad
        servers. '''
        if not b: self.print_error("notify_server_status:", b, str(tup))

    @hook
    def donation_address(self, window) -> Optional[Tuple[str,Address]]:
        ''' Plugin API: Returns a tuple of (description, Address) or None. This
        is the donation address that we as a client got from the remote server
        (as opposed to the donation address we announce if we are a server). '''
        if self.remote_donation_address and Address.is_valid(self.remote_donation_address):
            return (self.fullname() + " " + _("Server") + ": " + self.get_server()[0], Address.from_string(self.remote_donation_address))

    @daemon_command
    def fusion_server_start(self, daemon, config):
        # Usage:
        #   ./electron-cash daemon fusion_server_start <bindhost>(,<announcehost>) <port>
        #   ./electron-cash daemon fusion_server_start <bindhost>(,<announcehost>) <port> upnp
        #   ./electron-cash daemon fusion_server_start <bindhost>(,<announcehost>) <port> <donation_addr>
        #   ./electron-cash daemon fusion_server_start <bindhost>(,<announcehost>) <port> upnp <donation_addr>
        # e.g.:
        #   ./electron-cash daemon fusion_server_start 0.0.0.0,myfusionserver.com 8787 upnp bitcoincash:qpxiweuqoiweweqeweqw
        #
        # The main server port will be bound on <bindhost>:<port>.
        # Covert submissions will be bound on <bindhost>:<ephemeral_port> (the port is chosen by the OS)
        # The main server will tell clients to connect to <announcehost>:<ephemeral_port> .
        # The default announcehost is based on an autodetection system, which may not work for some server networking setups.
        network = daemon.network
        if not network:
            return "error: cannot run fusion server without an SPV server connection"
        def invoke(firstarg = '0.0.0.0', sport='8787', upnp_str = None, addr_str = None):
            bindhost, *extrahosts = firstarg.split(',')
            if len(extrahosts) > 1:
                raise Exception("too many hosts")
            elif len(extrahosts) == 1:
                [announcehost,] = extrahosts
            else:
                announcehost = None
            port = int(sport)
            pnp = get_upnp() if upnp_str == 'upnp' else None
            if not pnp and not addr_str:
                # third arg may be addr_str, so swap the args
                addr_str = upnp_str
                upnp_str = None
            addr = None
            if addr_str:
                assert Address.is_valid(addr_str), "Invalid donation address specified"
                addr = Address.from_string(addr_str)
            return self.start_fusion_server(network, bindhost, port, upnp = pnp, announcehost = announcehost, donation_address = addr)

        try:
            host, port = invoke(*config.get('subargs', ()))
        except Exception as e:
            import traceback, sys;  traceback.print_exc(file=sys.stderr)
            return f'error: {str(e)}'
        return (host, port)

    @daemon_command
    def fusion_server_stop(self, daemon, config):
        self.stop_fusion_server()
        return 'ok'

    @daemon_command
    def fusion_server_status(self, daemon, config):
        if not self.fusion_server:
            return "fusion server not running"
        return dict(poolsizes = {t: len(pool.pool) for t,pool in self.fusion_server.waiting_pools.items()})

    @daemon_command
    def fusion_server_fuse(self, daemon, config):
        if self.fusion_server is None:
            return
        subargs = config.get('subargs', ())
        if len(subargs) != 1:
            return "expecting tier"
        tier = int(subargs[0])
        num_clients = self.fusion_server.start_fuse(tier)
        return num_clients
