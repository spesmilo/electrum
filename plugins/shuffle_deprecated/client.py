import ecdsa, threading, time, queue, traceback, sys
from collections import namedtuple
from electroncash.bitcoin import deserialize_privkey, regenerate_key, EC_KEY, generator_secp256k1, number_to_string
from electroncash.address import Address
from electroncash.util import PrintError, InvalidPassword
from electroncash.network import Network
from electroncash import networks
from electroncash.wallet import dust_threshold
from electroncash.simple_config import get_config

ERR_SERVER_CONNECT = "Error: cannot connect to server"
ERR_BAD_SERVER_PREFIX = "Error: Bad server:"
MSG_SERVER_OK = "Ok: Server is ok"

from .coin_utils import CoinUtils
from .crypto import Crypto
from .messages import Messages, AbortProtocol
from .round import Round
from .comms import Channel, ChannelWithPrint, ChannelSendLambda, Comm, query_server_for_stats, verify_ssl_socket, BadServerPacketError
from .conf_keys import ConfKeys  # config keys per wallet and global

class ProtocolThread(threading.Thread, PrintError):
    """
    Thread encapsulating a particular shuffle of a particular coin. There are
    from 0 up to len(BackgroundShufflingThread.scales) of these active at any
    time per wallet. BackgroundShufflingThread creates/kills these in
    _make_protocol_thread. (The actual shuffle logic and rules are implemented
    in class 'Round' in round.py which this class wraps and calls into).
    """
    def __init__(self, *, host, port, coin,
                 scale, fee, sk, sks, inputs, pubk,
                 addr_new_addr, change_addr, version, coin_value,
                 logger=None, ssl=False,
                 comm_timeout=60.0, ctimeout=5.0,
                 typ=Messages.DEFAULT  # NB: For now only 'DEFAULT' type is supported
                 ):

        super(ProtocolThread, self).__init__()
        self.daemon = True
        self.version = version
        self.type = typ
        self.messages = Messages()
        self.comm = Comm(host, port, ssl=ssl, timeout = comm_timeout, infoText = "Scale: {}".format(scale))
        self.ctimeout = ctimeout
        if not logger:
            self.logger = ChannelWithPrint()
        else:
            self.logger = logger
        self.vk = pubk
        self.session = None
        self.number = None
        self.number_of_players = None
        self.players = {}
        self.scale = scale
        self.coin = coin
        self.fee = fee
        self.sk = sk
        self.sks = sks
        self.inputs = inputs
        assert coin_value > 0, "Coin value must be > 0!"
        self.coin_value = coin_value
        self.all_inputs = {}
        self.addr_new_addr = addr_new_addr # used by outside code
        self.addr_new = addr_new_addr.to_storage_string() # used by internal protocol code
        self.change_addr = change_addr #outside
        self.change = change_addr.to_storage_string() #inside
        self.protocol = None
        self.tx = None
        self.ts = time.time()
        self.done = threading.Event()
        self.already_did_cleanup = False  # if this flag is set, stop_protocol_thread should avoid doing any cleanup

    def not_time_to_die(func):
        "Check if 'done' event appear"
        def wrapper(self):
            if not self.done.is_set():
                func(self)
            else:
                pass
        return wrapper

    @not_time_to_die
    def register_on_the_pool(self):
        "Register the player on the pool"
        self.messages.make_greeting(self.vk, int(self.scale), self.type, self.version)
        msg = self.messages.packets.SerializeToString()
        self.comm.send(msg)
        req = self.comm.recv()
        self.messages.packets.ParseFromString(req)
        self.session = self.messages.packets.packet[-1].packet.session
        self.number = self.messages.packets.packet[-1].packet.number
        if self.session != '':
            self.logger.send("Player "  + str(self.number)+" get session number.\n")

    @not_time_to_die
    def wait_for_announcment(self):
        "This method waits for announcement messages from other pool"
        while self.number_of_players is None:
            req = self.comm.recv()
            if self.done.is_set():
                break
            try:
                self.messages.packets.ParseFromString(req)
            except BaseException as e:
                self.print_error("Error parsing packet:", repr(e))
                continue  # shouldn't we bail here? this is not a normal condition is it? -Calin
            if self.messages.get_phase() == self.messages.ANNOUNCEMENT:
                self.number_of_players = self.messages.get_number()
                break
            else:
                self.logger.send("Player " + str(self.messages.get_number()) + " joined the pool!")

    @not_time_to_die
    def share_the_key(self):
        "This method shares the verification keys among the players in the pool"
        self.logger.send("Player " + str(self.number) + " is about to share verification key with "
                         + str(self.number_of_players) +" players.\n")
        #Share the keys
        self.messages.clear_packets()
        self.messages.add_inputs(self.inputs)
        self.messages.packets.packet[-1].packet.from_key.key = self.vk
        self.messages.packets.packet[-1].packet.session = self.session
        self.messages.packets.packet[-1].packet.number = self.number
        shared_key_message = self.messages.packets.SerializeToString()
        self.comm.send(shared_key_message)

    @not_time_to_die
    def gather_the_keys(self):
        "This method gathers the verification keys from other players in the pool"
        self.players.clear()
        self.all_inputs.clear()
        messages = b''
        for __ in range(self.number_of_players):
            messages += self.comm.recv()
        self.messages.packets.ParseFromString(messages)
        seen_utxos = set()
        seen_pubkeys = set()
        for packet in self.messages.packets.packet:
            player_number = packet.packet.number
            player_key = str(packet.packet.from_key.key)
            self.players[player_number] = player_key
            self.all_inputs[player_key] = {}
            for pk, inp in packet.packet.message.inputs.items():
                coins = set(inp.coins) # ensure unique set of inputs
                dupes = seen_utxos & coins
                if dupes:
                    raise AbortProtocol("Dupe input for player {}; dupe utxo(s): {} ".format(player_number, str(dupes)))
                seen_utxos.update(coins)
                if len(coins) != 1:
                    # enforce 1 input per player, to do more breaks fee model.
                    # we need a dynamic fee model: see issue tracker #74
                    raise AbortProtocol('Extra or missing input for player {}; each player must have exactly 1 input!'.format(player_number))
                if pk in seen_pubkeys:
                    raise AbortProtocol("Dupe pubkey for player {}; dupe pubkey: {} ".format(player_number, pk))
                seen_pubkeys.add(pk)
                self.all_inputs[player_key][pk] = list(coins)
        if self.players:
            self.logger.send('Player {} get {}.'.format(self.number, len(self.players)))
        if self.number_of_players < 3:
            self.logger.send('{} Refusing to play with {} players. Minimum 3 required.'.format(ERR_BAD_SERVER_PREFIX,self.number_of_players))
            self.done.set()
        #check if all keys are different
        elif len(self.all_inputs) != self.number_of_players:
            self.logger.send('Error: Duplicate or extra keys in player list!')
            self.done.set()
        elif sum(len(v) for k,v in self.all_inputs.items()) != self.number_of_players:
            # Note: for now we only support 1 input per player. To lift this restriction we would need
            # to implement the proposed dynamic fee scheme. See github issue tracker #74
            self.logger.send('Error: Extra or missing inputs; each player must have exactly 1 input!')
            self.done.set()

    @not_time_to_die
    def start_protocol(self):
        "This method starts the protocol thread"
        coin_utils = CoinUtils(Network.get_instance())
        crypto = Crypto()
        self.messages.clear_packets()
        begin_phase = 'Announcement'
        # Make Round
        self.protocol = Round(
            coin_utils, crypto, self.messages,
            self.comm, self.comm, self.logger,
            self.session, begin_phase, self.scale, self.fee,
            self.sk, self.sks, self.all_inputs, self.vk,
            self.players, self.addr_new, self.change, self.coin,
            coin_value = self.coin_value
        )
        if not self.done.is_set():
            self.protocol.start_protocol()

    @not_time_to_die
    def run(self):
        "this method trying to run the round and catch possible problems with it"
        try:
            try:
                err = ERR_SERVER_CONNECT
                self.comm.connect(ctimeout = self.ctimeout)
                err = "Error: cannot register on the pool"
                self.register_on_the_pool()
                err = "Error: cannot complete the pool"
                self.wait_for_announcment()
                err = "Error: cannot share the keys"
                self.share_the_key()
                err = "Error: cannot gather the keys"
                self.gather_the_keys()
            except BadServerPacketError as e:
                self.logger.send(ERR_BAD_SERVER_PREFIX + ": " + str(e))
                return
            except BaseException as e:
                self.print_error("Exception in 'run': {}".format(repr(e)))
                self.logger.send(err)
                return
            if not self.done.is_set():
                self.start_protocol()
        except AbortProtocol as e:
            self.print_error(repr(e))
            self.logger.send("Error: {}".format(e))
        except Exception as e:
            self.print_error("Unexpected exception in 'run'; traceback follows:\n{}".format(traceback.format_exc()))
            self.logger.send("Error: {}".format(e))
        finally:
            self.logger.send("Exit: Scale '{}' Coin '{}'".format(self.scale, self.coin))
            self.comm.close()  # simply force socket close if exiting thread for any reason

    def stop(self):
        "This method stops the protocol threads"
        if self.protocol:
            self.protocol.done = True
        self.done.set()
        self.comm.close()

    def join(self, timeout_ignored=None):
        "This method Joins the protocol thread"
        self.stop()
        if self.is_alive():
            # the below is a work-around to the fact that this whole scheme still has a race condition with respect to the comm class :/
            super().join(2.0)
            if self.is_alive():
                # FIXME -- race condition exists with socket fd after close being reused, thus hanging the recv().
                self.print_error("Could not join after 2.0 seconds. Leaving the daemon thread in the background running :(")
                return
            self.print_error("Joined self")

    def diagnostic_name(self):
        n = super().diagnostic_name()
        return "{} <Scale: {}> ".format(n, self.scale)


class BackgroundShufflingThread(threading.Thread, PrintError):

    scales = (
        100000000000, # 1000.0  BCH ➡
        10000000000,  # 100.0   BCH ➡
        1000000000,   # 10.0    BCH ➡
        100000000,    #  1.0    BCH ➡
        10000000,     #  0.1    BCH ➝
        1000000,      #  0.01   BCH ➟
        100000,       #  0.001  BCH ⇢
        10000,        #  0.0001 BCH →
    )

    # Protocol version. Must be an int. Clients on different versions
    # never get assigned to the same pools and are completely segregated.
    # Version=0  : Very old clients used this version (pre release beta)
    # Version=100: Was for the new fee-270 (fee was 300 before this version).
    # Version=200: Is for the new "shuffle amount gets raised to match lowest
    #              UTXO in shuffle" rules.
    # Version-300: Replaced sha-224 hashing with sha256d (double) hashing
    # Note that testnet instances should specify PROTOCOL_VERSION + 1 to keep
    # keep themselves separated from mainnet shufflers.
    # (In the future this version specifier may be a more dynamic quantity but
    #  for now it's always this value, or this value + 1 for testnet).
    PROTOCOL_VERSION = 300
    # Fee formula should be roughly 270 for first input + 200 for each additional
    # input. Right now we support only 1 input per shuffler, so it's a static 270.
    FEE = 270
    # The below defaults control coin selection and which pools (scales) we use
    SORTED_SCALES = sorted(scales)
    SCALE_ARROWS = ('→','⇢','➟','➝','➡','➡','➡','➡')  # if you add a scale above, add an arrow here, in reverse order from above
    SCALE_ARROW_UNKNOWN = '⇒'  # What the app uses when a scale it sees isn't on the list.
    assert len(SORTED_SCALES) == len(SCALE_ARROWS), "Please add a scale arrow if you modify the scales!"
    SCALE_ARROW_DICT = dict(zip(SORTED_SCALES, SCALE_ARROWS))
    SCALE_0 = SORTED_SCALES[0]
    SCALE_N = SORTED_SCALES[-1]

    DEFAULT_UPPER_BOUND = 9999990000    # (default) 99.99 BCH limit to max shuffle coin
    DEFAULT_LOWER_BOUND = SCALE_0 + FEE # (default) 0.0001 BCH + FEE minimum coin. Note config can never make minimum go below this.

    # The below two get overwritten on the class level from ConfKeys.Global.MIN_COIN_VALUE and MAX_COIN_VALUE in class c'tor
    UPPER_BOUND = DEFAULT_UPPER_BOUND   # minimum: cls.hard_lower_bound()
    LOWER_BOUND = DEFAULT_LOWER_BOUND   # maximum: cls.hard_upper_bound()

    # Some class-level vars that influence fine details of thread operation
    # -- Don't change these unless you know what you are doing!
    STATS_PORT_RECHECK_TIME = 60.0  # re-check the stats port to pick up pool size changes for UI every 1 mins.
    CHECKER_MAX_TIMEOUT = 15.0  # in seconds.. the maximum amount of time to use for stats port checker (applied if proxy mode, otherwise time will be this value divided by 3.0)

    ShuffleSettings = namedtuple("ShuffleSettings", "type, type_name, version, scale, input_amount, fee")
    latest_shuffle_settings = ShuffleSettings(Messages.DEFAULT, Messages.TYPE_NAME_DICT[Messages.DEFAULT], PROTOCOL_VERSION, 0, 0, FEE)

    def __init__(self, window, wallet, network_settings,
                 period = 10.0, logger = None, password=None, timeout=60.0,
                 typ=Messages.DEFAULT  # NB: Only DEFAULT is currently supported
                 ):
        super().__init__()
        cls = type(self)
        self.daemon = True
        self.timeout = timeout
        self.version = cls.PROTOCOL_VERSION + (1 if networks.net.TESTNET else 0)
        self.type = typ
        assert self.type == Messages.DEFAULT, "BackgroundShufflingThread currently only supports DEFAULT shuffles"
        cls.latest_shuffle_settings = cls.ShuffleSettings(self.type, Messages.TYPE_NAME_DICT[self.type], self.version, 0, 0, self.FEE)
        # set UPPER_BOUND and LOWER_BOUND from config keys here. Note all instances will see these changes immediately.
        cls.update_lower_and_upper_bound_from_config()
        self.period = period
        self.logger = logger
        self.wallet = wallet
        self.window = window
        self.host = network_settings.get("host", None)
        self.info_port = network_settings.get("info", None)
        self.port = 1337  # default value -- will get set to real value from server's stat port in run() method
        self.poolSize = 3  # default value -- will get set to real value from server's stat port in run() method
        self.banScore = 0  # comes from stats port -- our own personal ban score
        self.banned = False  # comes from stats port. True if our IP is banned (default ban duration: 30 mins)
        self.ssl = network_settings.get("ssl", None)
        self.lock = threading.RLock()
        self.password = password
        self.threads = {scale:None for scale in self.scales}
        self.shared_chan = Channel(switch_timeout=None)  # threads write a 3-tuple here: (killme_flg, thr, msg)
        self.stop_flg = threading.Event()
        self.last_idle_check = 0.0  # timestamp in seconds unix time
        self.done_utxos = dict()
        self._paused = False
        self._coins_busy_shuffling = set()  # 'prevout_hash:n' (name) set of all coins that are currently being shuffled by a ProtocolThread. Both wallet locks should be held to read/write this.
        self._last_server_check = 0.0  # timestamp in seconds unix time
        self._dummy_address = Address.from_pubkey(EC_KEY(number_to_string(1337, generator_secp256k1.order())).get_public_key())  # dummy address
        # below 4 vars are related to the "delayed unreserve address" mechanism as part of the bug #70 & #97 workaround and the complexity created by it..
        self._delayed_unreserve_new = dict()  # dict of Address -> time.time() timestamp when its shuffle ended
        self._delayed_unreserve_change = dict()  # dict of Address -> time.time() timestamp when its shuffle ended
        self._last_delayed_unreserve_check = 0.0  # timestamp in seconds unix time
        self._delayed_unreserve_check_interval = 60.0  # check these addresses every 60 seconds.
        self._delayed_unreserve_timeout = 600.0  # how long before the delayed-unreserve addresses expire; 10 minutes

    def set_password(self, password):
        with self.lock:
            self.password = password

    def get_password(self):
        with self.lock:
            return self.password

    def diagnostic_name(self):
        n = super().diagnostic_name()
        if self.wallet:
            n = n + " <" + self.wallet.basename() + ">"
        return n

    def set_paused(self, b):
        b = bool(b)
        self.shared_chan.put("pause" if b else "unpause") # don't need a lock since we use this shared_chan queue

    def get_paused(self):
        return self._paused # don't need a lock since python guarantess reads from single vars are atomic, and only the background thread writes

    def tell_gui_to_refresh(self):
        extra = getattr(self.window, 'send_tab_shuffle_extra', None)
        if extra:
            extra.needRefreshSignal.emit()

    def tell_gui_to_save_wallet(self):
        extra = getattr(self.window, 'send_tab_shuffle_extra', None)
        if extra:
            extra.needWalletSaveSignal.emit()

    @classmethod
    def set_lower_and_upper_bound(cls, lower, upper):
        ''' Sets the class level LOWER_BOUND and UPPER_BOUND, and also saves
        it in the config.  Note that all instances across all wallets will see
        this new setting the next time they start a ProtocolThread '''
        lower = max(int(lower), cls.hard_lower_bound())
        upper = min(int(upper), cls.hard_upper_bound())
        assert upper > lower, "Coin upper bound must be strictly larger than the lower bound!"
        get_config().set_key(ConfKeys.Global.MIN_COIN_VALUE, lower)
        get_config().set_key(ConfKeys.Global.MAX_COIN_VALUE, upper, save=True)
        cls.LOWER_BOUND, cls.UPPER_BOUND = lower, upper
        return lower, upper # return back what we actually put in the config, since this value is sanitized to fall within range.

    @classmethod
    def update_lower_and_upper_bound_from_config(cls):
        ''' Returns a lower,upper tuple that comes form the config. Also
        updates cls.LOWER_BOUND and cls.UPPER_BOUND as a side-effect. '''
        lower, upper = cls.LOWER_BOUND, cls.UPPER_BOUND
        v = get_config().get(ConfKeys.Global.MIN_COIN_VALUE, cls.DEFAULT_LOWER_BOUND)
        try: lower = max(int(v), cls.hard_lower_bound())
        except (ValueError, TypeError): pass
        v = get_config().get(ConfKeys.Global.MAX_COIN_VALUE, cls.DEFAULT_UPPER_BOUND)
        try: upper = min(int(v), cls.hard_upper_bound())
        except (ValueError, TypeError): pass
        if upper > lower:
            cls.LOWER_BOUND, cls.UPPER_BOUND = lower, upper
        return cls.LOWER_BOUND, cls.UPPER_BOUND

    @classmethod
    def reset_lower_and_upper_bound_to_defaults(cls):
        for k in (ConfKeys.Global.MIN_COIN_VALUE, ConfKeys.Global.MAX_COIN_VALUE):
            get_config().set_key(k, None, save=True) # clears key from config
        return cls.update_lower_and_upper_bound_from_config()

    @classmethod
    def hard_lower_bound(cls):
        return cls.SCALE_0 + cls.FEE

    @classmethod
    def hard_upper_bound(cls):
        return cls.SCALE_N*10 + cls.FEE

    def run(self):
        try:
            self.print_error("Started")
            self.logger.send("started", "MAINLOG")

            if self.is_offline_mode():  # aka: '--offline' cmdline arg
                # OFFLINE mode: We don't do much. We just process the shared
                # chan for stop events.  We could have suppressed the creation
                # of this thread altogether in this mode, but that would have
                # involved more special case code in qt.py and it was simper
                # just to do this here. -Calin
                self.print_error("Offline mode; thread is alive but will not shuffle any coins.")
                while not self.stop_flg.is_set():
                    self.process_shared_chan()  # this sleeps for up to 10s each time. Its only purpose here is to catch 'stop' signals from rest of app and exit this no-op thread. :)
            else:
                # ONLINE mode: we check coins, check server, start threads, etc.
                self.check_server()

                if not self.is_wallet_ready():
                    time.sleep(3.0) # initial delay to hopefully wait for wallet to be ready

                while not self.stop_flg.is_set():
                    self.check_for_coins()
                    had_a_completion = self.process_shared_chan() # NB: this blocks for up to self.period (default=10) seconds
                    if had_a_completion:
                        # force loop to go back to check_for_coins immediately if a thread just successfully ended with a protocol completion
                        continue
                    self.check_server_if_errored_or_not_checked_in_a_while() # NB: this normally is a noop but if server port is bad or not checked in a while, blocks for up to 10.0 seconds
                    self.check_idle_threads()
                    self.check_delayed_unreserve_addresses()
            self.print_error("Stopped")
        finally:
            self._unreserve_addresses()
            self.logger.send("stopped", "MAINLOG")

    def check_server_if_errored_or_not_checked_in_a_while(self):
        if self.stop_flg.is_set():
            return
        errored = self.window.cashshuffle_get_flag() == 1  # bad server flag is set -- try to rediscover the shuffle port in case it changed
        the_time_has_come = time.time() - self._last_server_check > self.STATS_PORT_RECHECK_TIME  # re-ping stats port every 1 mins to discover poolSize changes for UI
        if errored or the_time_has_come:
            return self.check_server(quick = not errored, ssl_verify = errored)

    def check_server(self, quick = False, ssl_verify = True):
        def _do_check_server(timeout, ssl_verify):
            try:
                self.port, self.poolSize, connections, pools, self.banScore, self.banned = query_server_for_stats(self.host, self.info_port, self.ssl, timeout)
                if self.ssl and ssl_verify and not verify_ssl_socket(self.host, self.port, timeout=timeout):
                    self.print_error("SSL Verification failed")
                    return False
                self.print_error("Server {}:{} told us that it has shufflePort={} poolSize={} connections={}".format(self.host, self.info_port, self.port, self.poolSize, connections))
                return True
            except BaseException as e:
                self.print_error("Exception: {}".format(str(e)))
                self.print_error("Could not query shuffle port for server {}:{} -- defaulting to {}".format(self.host, self.info_port, self.port))
                return False
            finally:
                self._last_server_check = time.time()
        # /_do_check_server
        to_hi, to_lo = self.CHECKER_MAX_TIMEOUT, self.CHECKER_MAX_TIMEOUT/3.0  # 15.0,5.0 secs
        if quick:
            to_hi, to_lo = to_hi*0.6, to_lo*0.6  # 9.0, 3.0 seconds respectively
        timeout = to_hi if (Network.get_instance() and Network.get_instance().get_proxies()) else to_lo
        if not _do_check_server(timeout = timeout, ssl_verify = ssl_verify):
            self.logger.send(ERR_SERVER_CONNECT, "MAINLOG")
            return False
        else:
            self.logger.send(MSG_SERVER_OK, "MAINLOG")
            return True

    def check_idle_threads(self):
        if self.stop_flg.is_set():
            return
        now = time.time()
        if not self.last_idle_check:
            self.last_idle_check = now
            return
        if now - self.last_idle_check > self.timeout:
            self.last_idle_check = now
            for scale, thr in self.threads.items():
                if thr and now - thr.ts > self.timeout:
                    self.print_error("Thread for scale {} idle timed-out (timeout={}), stopping.".format(scale, self.timeout))
                    self.stop_protocol_thread(thr, scale, thr.coin, "Error: Thread idle timed out")

            for utxo, ts in self.done_utxos.copy().items():
                if now - ts > self.timeout:
                    self.done_utxos.pop(utxo, None)
                    self.logger.send("forget {}".format(utxo), "MAINLOG")

    def check_delayed_unreserve_addresses(self):
        ''' Expire addresses put in the "delayed unreserve" dict which are
        >600 seconds old. For shuffled-output addresses, these are given back
        to the wallet and can be used for anything. For change addresses, they
        go back to a pool used for shuffle change only.'''
        if self.stop_flg.is_set():
            return
        now = time.time()
        if not self._last_delayed_unreserve_check:
            self._last_delayed_unreserve_check = now
            return
        if now - self._last_delayed_unreserve_check > self._delayed_unreserve_check_interval:
            self._last_delayed_unreserve_check = now
            ct = 0
            with self.wallet.lock:
                # We use the lock to ensure GUI or other threads don't touch
                # the addresses_cashshuffle_reserved set while we mutate it.
                # This code path is executed very infrequently so it's not really
                # a huge hit.
                for addr, ts in self._delayed_unreserve_new.copy().items():
                    if now - ts > self._delayed_unreserve_timeout:
                        self._delayed_unreserve_new.pop(addr, None)
                        self.wallet.unreserve_change_address(addr)
                        ct += 1
                for addr, ts in self._delayed_unreserve_change.copy().items():
                    if now - ts > self._delayed_unreserve_timeout:
                        self._delayed_unreserve_change.pop(addr, None)
                        self.wallet._addresses_cashshuffle_reserved.discard(addr)
                        ct += 1
            if ct:
                self.print_error("Freed {} 'delayed unreserve' addresses in {:.02f} msec".format(ct, (time.time()-now)*1e3))

    def process_shared_chan(self):
        timeLeft = 0.0 # this variable is modified by _loopCondition() call below
        def _loopCondition(t0):
            if self.stop_flg.is_set():
                # return early if stop_flg is set
                return False
            nonlocal timeLeft
            timeLeft = self.period - (time.time() - t0)
            if timeLeft <= 0.0:
                # if our period for blocking expired, return False
               return False
            return True

        try:
            t0 = time.time()
            while _loopCondition(t0): # _loopCondition modifies timeLeft

                tup = self.shared_chan.get(timeout = timeLeft) # blocking read of the shared msg queue for up to self.period seconds

                if self.stop_flg.is_set(): # check stop flag yet again just to be safe
                    return

                if isinstance(tup, tuple): # may be None on join()
                    ''' Got a message from the ProtocolThread '''

                    killme, thr, message = tup
                    scale, sender = thr.scale, thr.coin
                    if killme:
                        res = self.stop_protocol_thread(thr, scale, sender, message) # implicitly forwards message to gui thread
                        if res:
                            return True # signal calling loop to go to the "check_for_coins" step immediately
                    else:
                        #self.print_error("--> Fwd msg to Qt for: Scale='{}' Sender='{}' Msg='{}'".format(scale, sender, message.strip()))
                        self.logger.send(message, sender)

                elif isinstance(tup, str):
                    ''' Got a pause/unpause command from main (GUI) thread '''

                    s = tup
                    if s == "pause":
                        # GUI pause of CashShuffle -- immediately stop all threads
                        if not self._paused:
                            self._paused = True
                            ct = self.stop_all_protocol_threads("Error: User stop requested")
                            if not ct:  # if we actually stopped one, no need to tell gui as the stop_protocol_thread already signalled a refresh
                                self.tell_gui_to_refresh()

                    elif s == "unpause":
                        # Unpause -- the main loop of this thread will continue to create new threads as coins become available
                        if self._paused:
                            self._paused = False
                            self.tell_gui_to_refresh()
                            return True # signal calling loop to check for coins immediately

        except queue.Empty:
            pass

        return False

    def stop_all_protocol_threads(self, message = "Error: Stop requested"):
        ''' Normally called from our thread context but may be called from other threads after joining this thread '''
        ct = 0
        for scale, thr in self.threads.copy().items():
            if thr:
                self.stop_protocol_thread(thr, scale, thr.coin, message)
                ct += 1
        self._unreserve_addresses()
        if ct:
            self.print_error("Stopped {} extant threads".format(ct))
        return ct

    def _unreserve_addresses(self):
        ''' Normally called from our thread context but may be called from other threads after joining this thread '''
        with self.wallet.lock:
            l = len(self.wallet._addresses_cashshuffle_reserved)
            self.wallet._addresses_cashshuffle_reserved.clear()
            if l: self.print_error("Freed {} reserved addresses".format(l))
            CoinUtils.unfreeze_frozen_by_shuffling(self.wallet)
            self._coins_busy_shuffling.clear()

    def stop_protocol_thread(self, thr, scale, sender, message):
        self.print_error("Stop protocol thread for scale: {}".format(scale))
        retVal = False
        if sender and not thr.already_did_cleanup:
            if message.endswith('complete protocol'):
                # Flag this as no longer being a reshuffle (for UI purposes and
                # sanity as the _reshuffle flag trumps other flags when
                # selecting candidate coins)
                self.wallet._reshuffles.discard(sender)
                # remember this 'just spent' coin for self.timeout amount of
                # time as a guard to ensure that we wait for the tx to show
                # up in the wallet before considerng it again for shuffling
                self.done_utxos[sender] = time.time()
                retVal = True # indicate to interesteed callers that we had a completion. Our thread loop uses this retval to decide to scan for UTXOs to shuffle immediately.
                # Note that when "complete protocol" happens we never unreserve
                # reserved output addresses, as a paranoia measure. This is
                # because technically there are tx's with those addresses "in
                # the wild" which are signed and can be broadcast at any time.
                # A caveat here is if the blockchain is bad or there's lots of
                # reorgs or the user is switching forks -- or the completed
                # protocol tx is never confirmed -- then the strategy here can
                # create gaps in the change addresses.. but that's ok. Next
                # app restart or CashShuffle plugin reload those gaps
                # will go away since the 'reserved address' set will be cleared.
                # The above note is a corner case consideration, though,
                # and it's best to err on the side of caution here. In practice
                # gaps in the change addresses will be a rare occurrence.
            was_fake_change_addr = thr.change_addr == self._dummy_address
            need_to_discard_change_if_errored = not was_fake_change_addr
            with self.wallet.lock:
                if need_to_discard_change_if_errored and thr.protocol and not thr.protocol.did_use_change:
                    # The reserved change output address was definitely not used.
                    # Immediately unreserve this change_addr so that other threads
                    # may reserve it for shuffles immediately.
                    self.wallet._addresses_cashshuffle_reserved.discard(thr.change_addr)
                    need_to_discard_change_if_errored = False
                self.wallet.set_frozen_coin_state([sender], False)
                self._coins_busy_shuffling.discard(sender)
                self.wallet.storage.put(ConfKeys.PerWallet.COINS_FROZEN_BY_SHUFFLING, list(self._coins_busy_shuffling))
                if message.startswith("Error"):
                    if thr.protocol and thr.protocol.did_reach_tentative_stage:
                        # The shuffle got to a stage where maybe the tx will
                        # get broadcast sometime soon by a lagged player
                        # (see #70, #97). Since we don't want the next round to
                        # possibly use the previous round's shuffle addresses
                        # for output again (that would break privacy), we need
                        # to mark these addresses to be unreserved at a later
                        # time rather than right away.
                        now = time.time()
                        self._delayed_unreserve_new[thr.addr_new_addr] = now
                        if need_to_discard_change_if_errored:
                            self._delayed_unreserve_change[thr.change_addr] = now
                        self.print_error("Shuffle of coin {} did reach the 'tentative' stage. Will unreserve its reserved addresses in {} minutes."
                                         .format(sender, self._delayed_unreserve_timeout / 60.0))
                    else:
                        # unreserve addresses that were previously reserved iff error
                        self.wallet.unreserve_change_address(thr.addr_new_addr)
                        if need_to_discard_change_if_errored:
                            self.wallet._addresses_cashshuffle_reserved.discard(thr.change_addr)
            thr.already_did_cleanup = True  # mark this thread as 'cleaned up'. this is necessary because this function may reenter with this thread again later and doing the clean-up twice would create bugs as it would unreserve addresses, etc, that may already be taken
            self.tell_gui_to_refresh()
            self.logger.send(message, sender)
        elif not sender:
            self.print_error("No sender! Thr={}".format(str(thr)))
        if thr is self.threads[scale]:
            self.threads[scale] = None
        elif thr.is_alive():
            self.print_error("WARNING: Stopping thread ({}) which was not in the self.threads dict for scale = {} coin = {}"
                             .format(str(thr), scale, sender))
        if thr.is_alive():
            thr.join()
        else:
            thr.stop()
            self.print_error("Thread already exited; cleaned up.")
        return retVal

    def protocol_thread_callback(self, thr, message):
        ''' This callback runs in the ProtocolThread's thread context '''
        def signal_stop_thread(thr, message):
            ''' Sends the stop request to our run() thread, which will join on this thread context '''
            self.print_error("Signalling stop for scale: {}".format(thr.scale))
            self.shared_chan.send((True, thr, message))
        def fwd_message(thr, message):
            #self.print_error("Fwd msg for: Scale='{}' Msg='{}'".format(thr.scale, message))
            self.shared_chan.send((False, thr, message))
        scale = thr.scale
        thr.ts = time.time()
        self.print_error("Scale: {} Message: '{}'".format(scale, message.strip()))
        if message.startswith("Error") or message.startswith("Exit"):
            signal_stop_thread(thr, message) # sends request to shared channel. our thread will join
        elif (message.startswith("shuffle_txid:")  # TXID message -- forward to GUI so it can call "set_label"
                  or message.startswith('add_tentative_shuffle:')  # tentative shuffle messages.. forward to GUI as well to process their data.
                  or message.startswith('del_tentative_shuffle:')):
            fwd_message(thr, message)
        elif message.endswith("complete protocol"):
            signal_stop_thread(thr, message) # sends request to shared channel
        elif message.startswith("Player"):
            fwd_message(thr, message)  # sends to Qt signal, which will run in main thread
        elif "get session number" in message:
            fwd_message(thr, message)  # sends to Qt signal, which will run in main thread
        elif "begins CoinShuffle protocol" in message:
            fwd_message(thr, message)  # sends to Qt signal, which will run in main thread
        #elif message.startswith("Blame"):
        #    if "insufficient" in message:
        #        pass
        #    elif "wrong hash" in message:
        #        pass
        #    else:
        #        signal_stop_thread(thr, message)

    @staticmethod
    def generate_random_sk():
        G = generator_secp256k1
        _r  = G.order()
        pvk = ecdsa.util.randrange( _r )
        eck = EC_KEY(number_to_string(pvk, _r))
        return eck

    # NB: all locks must be held when this is called
    def _make_protocol_thread(self, scale, coins, scale_lower_bound, scale_upper_bound):
        def get_coin_for_shuffling(scale, coins, scale_lower_bound, scale_upper_bound):
            upper_bound = min(scale_upper_bound, self.UPPER_BOUND)
            lower_bound = max(scale_lower_bound, self.LOWER_BOUND)
            unshuffled_coins_on_scale = [coin for coin in coins
                                         # exclude coins out of range and 'done' coins still in history
                                         # also exclude coinbase coins (see issue #64)
                                         if (coin['value'] < upper_bound
                                             and coin['value'] >= lower_bound) ]
            unshuffled_coins_on_scale.sort(key=lambda x: (x['value'], -x['height']))  # sort by value, preferring older coins on tied value
            if unshuffled_coins_on_scale:
                return unshuffled_coins_on_scale[-1]  # take the largest,oldest on the scale
            return None
        # /
        coin = get_coin_for_shuffling(scale, coins, scale_lower_bound, scale_upper_bound)
        if not coin:
            return
        try:
            private_key = self.wallet.export_private_key(coin['address'], self.get_password())
        except InvalidPassword:
            # This shouldn't normally happen but can if the user JUST changed their password in the GUI thread
            # and we didn't yet get informed of the new password.  In which case we give up for now and 10 seconds later
            # (the next 'period' time), this coin will be picked up again.
            raise RuntimeWarning('Invalid Password caught when trying to export a private key -- if this keeps happening tell the devs!')
        utxo_name = CoinUtils.get_name(coin)
        self.wallet.set_frozen_coin_state([utxo_name], True)
        self._coins_busy_shuffling.add(utxo_name)
        self.wallet.storage.put(ConfKeys.PerWallet.COINS_FROZEN_BY_SHUFFLING, list(self._coins_busy_shuffling))
        inputs = {}
        sks = {}
        public_key = self.wallet.get_public_key(coin['address'])
        sk = regenerate_key(deserialize_privkey(private_key)[1])
        inputs[public_key] = [utxo_name]
        sks[public_key] = sk
        id_sk = self.generate_random_sk()
        id_pub = id_sk.GetPubKey(True).hex()

        output = self.wallet.cashshuffle_get_new_change_address(for_shufflethread=2)
        # Check if we will really use the change address. We definitely won't
        # be receving to it if the change is below dust threshold (see #67).
        # Furthermore, we may not receive change even if this check predicts we
        # will due to #68.
        may_receive_change = coin['value'] - scale - self.FEE >= dust_threshold(Network.get_instance())
        if may_receive_change:
            # We anticipate (maybe) using the change address in the shuffle tx,
            # so reserve this address. Note that due to "smallest player raises
            # shuffle amount" rules in version=200+ (#68) we WON'T necessarily
            # USE this change address. (In that case it will be freed up later
            # after shuffling anyway so no address leaking occurs).
            # We just reserve it if we think we MAY need it.
            change = self.wallet.cashshuffle_get_new_change_address(for_shufflethread=1)
        else:
            # We *definitely* won't receive any change no matter who
            # participates because we are very close to scale.
            # (The leftover dust amount will go to fee.)
            # We still have to specify a change address to the protocol even if
            # it definitely won't be used. :/
            # We'll just take a hard-coded address whose private key is the
            # number 1337 (we do it this way so we don't leak anything
            # identifying every time we shuffle).
            # Don't worry: It's 100% guaranteed we won't be using this address.
            change = self._dummy_address
        self.print_error("Scale {} Coin {} OutAddr {} {} {} make_protocol_thread".format(scale, utxo_name, output.to_storage_string(), "Change" if may_receive_change else "FakeChange", change.to_storage_string()))
        #self.print_error("Reserved addresses:", self.wallet._addresses_cashshuffle_reserved)
        ctimeout = 12.5 if (Network.get_instance() and Network.get_instance().get_proxies()) else 5.0 # allow for 12.5 second connection timeouts if using a proxy server
        thr = ProtocolThread(host=self.host, port=self.port, ssl=self.ssl,
                             comm_timeout=self.timeout, ctimeout=ctimeout,  # comm timeout and connect timeout
                             coin=utxo_name,
                             scale=scale, fee=self.FEE, coin_value=coin['value'],
                             addr_new_addr=output, change_addr=change,
                             sk=id_sk, sks=sks, inputs=inputs, pubk=id_pub,
                             logger=None, version=self.version, typ=self.type)
        thr.logger = ChannelSendLambda(lambda msg: self.protocol_thread_callback(thr, msg))
        cls = type(self)
        cls.latest_shuffle_settings = cls.ShuffleSettings(thr.type, Messages.TYPE_NAME_DICT[thr.type], thr.version, scale, coin['value'], self.FEE)
        self.threads[scale] = thr
        coins.remove(coin)
        thr.start()
        return True

    def is_coin_busy_shuffling(self, utxo_name_or_dict):
        ''' Checks the extant running threads (if any) for a match to coin.
        This is a very accurate real-time indication that a coins is busy
        shuffling. Used by the spendable_coin_filter in qt.py.'''
        if isinstance(utxo_name_or_dict, dict):
            name = CoinUtils.get_name(utxo_name_or_dict)
        else:
            name = utxo_name_or_dict
        # name must be an str at this point!
        with self.wallet.lock:
            return name in self._coins_busy_shuffling

    def is_wallet_ready(self):
        return bool( self.wallet and self.wallet.is_up_to_date()
                     and self.wallet.network and self.wallet.network.is_connected()
                     and self.wallet.verifier and self.wallet.verifier.is_up_to_date()
                     and self.wallet.synchronizer and self.wallet.synchronizer.is_up_to_date()
                     and Network.get_instance() )

    def is_offline_mode(self):
        return bool(not self.wallet or not self.wallet.network)

    def _get_eligible_unshuffled_coins(self):
        if not getattr(self.wallet, "is_coin_shuffled", None):
            raise RuntimeWarning('Wallet lacks is_coin_shuffled method!')
        _get_name = CoinUtils.get_name
        candidates = []
        for c in self.wallet.get_utxos(exclude_frozen=True, confirmed_only=True, mature=True):
            name = _get_name(c)
            is_reshuffle = name in self.wallet._reshuffles
            # pre-filter out coins we know won't apply to any scale.
            if (
                # Note: the 'is False' is intentional -- we are interested
                # in coins that we know for SURE are not shuffled.
                # is_coin_shuffled() also returns None in cases where the tx
                # isn't in the history yet (a rare occurrence)
                (is_reshuffle or self.wallet.is_coin_shuffled(c) is False)
                and c['value'] >= self.LOWER_BOUND  # inside config'd range
                and c['value'] < self.UPPER_BOUND   # inside config'd range
                and name not in self.done_utxos  # coin was not just shuffled
                and not c['coinbase']  # coin is not coinbase coin -- we never shuffle coinbase coins
                and (is_reshuffle or not CoinUtils.is_shuffled_address(self.wallet, c['address'])) # coin is not sitting on a shuffled address
                ):
                    candidates.append(c)
        return candidates

    def check_for_coins(self):
        if self.stop_flg.is_set() or self._paused: return
        need_refresh = False
        shufchg_saved = self.wallet._shuffle_change_shared_with_others.copy()
        with self.wallet.lock:
            if self.is_wallet_ready():
                try:
                    #TODO FIXME XXX -- perhaps also add a mechanism to detect when coins that are in the queue or are being shuffled get reorged or spent
                    coins = None
                    for scale, thr in self.threads.items():
                        if not thr:
                            scale_lower_bound = scale + self.FEE
                            scale_upper_bound = scale*10 + self.FEE  # FIXME -- assumption here is scales are 10x apart. This will break if we ever change scale granularity.
                            if self.LOWER_BOUND >= scale_upper_bound or self.UPPER_BOUND < scale_lower_bound:
                                # our current conf. settings don't permit this scale.
                                # short-circuit abort the creation of this scale's
                                # thread and continue
                                continue
                            if coins is None: # NB: leave this check for None specifically as it has different semantics than coins == []
                                # lazy-init of coins here only if there is actual work to do.
                                coins = self._get_eligible_unshuffled_coins()
                            if not coins: break # coins mutates as we iterate so check that we still have candidate coins
                            did_start = self._make_protocol_thread(scale, coins, scale_lower_bound, scale_upper_bound)
                            need_refresh = need_refresh or did_start # once need_refresh is set to True, it remains True
                except RuntimeWarning as e:
                    self.print_error("check_for_coins error: {}".format(str(e)))
        if need_refresh:
            if shufchg_saved != self.wallet._shuffle_change_shared_with_others:
                # save the change address set used if we actually got a new thread started,
                # since this data needs to be remembered so we don't leak shuffled addresses
                # to peers, see #105. Note the actual write will happen in the refresh of
                # the main thread.
                CoinUtils.store_shuffle_change_shared_with_others(self.wallet)
                self.tell_gui_to_save_wallet()
            # Ok, at least one thread started, so reserved funds for threads have changed. indicate this in GUI
            self.tell_gui_to_refresh()

    def join(self):
        self.set_paused(True) # should auto-kill threads
        self.stop_flg.set()
        self.shared_chan.send(None) # wakes our thread up so it can exit when it sees stop_flg is set
        if self.is_alive():
            self.print_error("Joining still-running thread...")
            super().join()
        self.stop_all_protocol_threads() # no-op if no threads still left running
