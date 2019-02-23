import ecdsa, threading, time, queue
from electroncash.bitcoin import deserialize_privkey, regenerate_key, EC_KEY, generator_secp256k1, number_to_string
from electroncash.address import Address
from electroncash.util import PrintError, InvalidPassword
from electroncash.network import Network

ERR_SERVER_CONNECT = "Error: cannot connect to server"
ERR_BAD_SERVER_PREFIX = "Error: Bad server:"
MSG_SERVER_OK = "Ok: Server is ok"

class PrintErrorThread(PrintError):
    def diagnostic_name(self):
        n = super().diagnostic_name()
        return "{} ({})".format(n, int(threading.get_ident())&0xfffff)

from .coin import Coin
from .crypto import Crypto
from .messages import Messages
from .coin_shuffle import Round
from .comms import Channel, ChannelWithPrint, ChannelSendLambda, Comm, query_server_for_stats, verify_ssl_socket, BadServerPacketError

def get_name(coin):
    return "{}:{}".format(coin['prevout_hash'],coin['prevout_n'])

def unfreeze_frozen_by_shuffling(wallet):
    with wallet.lock, wallet.transaction_lock:
        coins_frozen_by_shuffling = wallet.storage.get("coins_frozen_by_shuffling", list())
        if coins_frozen_by_shuffling:
            l = len(coins_frozen_by_shuffling)
            if l: wallet.print_error("Freed {} frozen-by-shuffling UTXOs".format(l))
            wallet.set_frozen_coin_state(coins_frozen_by_shuffling, False)
        wallet.storage.put("coins_frozen_by_shuffling", None) # deletes key altogether from storage

class ProtocolThread(threading.Thread, PrintErrorThread):
    """
    This class emulate thread with protocol run
    """
    def __init__(self, host, port, coin,
                 amount, fee, sk, sks, inputs, pubk,
                 addr_new_addr, change_addr, logger=None, ssl=False,
                 comm_timeout = 60.0, ctimeout = 5.0, total_amount=0):

        super(ProtocolThread, self).__init__()
        self.daemon = True
        self.messages = Messages()
        self.comm = Comm(host, port, ssl=ssl, timeout = comm_timeout, infoText = "Scale: {}".format(amount))
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
        self.amount = amount
        self.coin = coin
        self.fee = fee
        self.sk = sk
        self.sks = sks
        self.inputs = inputs
        self.total_amount = total_amount
        self.all_inputs = {}
        self.addr_new_addr = addr_new_addr # used by outside code
        self.addr_new = addr_new_addr.to_storage_string() # used by internal protocol code
        self.change_addr = change_addr #outside
        self.change = change_addr.to_storage_string() #inside
        self.protocol = None
        self.tx = None
        self.ts = time.time()
        self.done = threading.Event()

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
        "This method trying to register player on the pool"
        self.messages.make_greeting(self.vk, int(self.amount))
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
            if req is None:
                continue
            try:
                self.messages.packets.ParseFromString(req)
            except:
                continue
            if self.messages.get_phase() == 1:
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
        "This method gather the verification keys from other players in the pool"
        messages = b''
        for _ in range(self.number_of_players):
            messages += self.comm.recv()
        self.messages.packets.ParseFromString(messages)
        for packet in self.messages.packets.packet:
            player_number = packet.packet.number
            player_key = str(packet.packet.from_key.key)
            self.players[player_number] = player_key
            self.all_inputs[player_key] = {}
            for pk,inp in packet.packet.message.inputs.items():
                self.all_inputs[player_key][pk] = inp.coins[:]
        if self.players:
            self.logger.send('Player ' +str(self.number)+ " get " + str(len(self.players))+".\n")
        #check if all keys are different
        if len(set(self.players.values())) is not self.number_of_players:
            self.logger.send('Error: Duplicate keys in player list!')
            self.done.set()
        if self.number_of_players < 3:
            self.logger.send('{} Refusing to play with {} players. Minimum 3 required.'.format(ERR_BAD_SERVER_PREFIX,self.number_of_players))
            self.done.set()

    @not_time_to_die
    def start_protocol(self):
        "This method starts the protocol thread"
        coin = Coin(Network.get_instance())
        crypto = Crypto()
        self.messages.clear_packets()
        # begin_phase = Phase('Announcement')
        begin_phase = 'Announcement'
        # Make Round
        self.protocol = Round(
            coin, crypto, self.messages,
            self.comm, self.comm, self.logger,
            self.session, begin_phase, self.amount, self.fee,
            self.sk, self.sks, self.all_inputs, self.vk,
            self.players, self.addr_new, self.change, total_amount = self.total_amount
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
                self.print_error("Exception in 'run': {}".format(str(e)))
                self.logger.send(err)
                return
            self.start_protocol()
        finally:
            self.logger.send("Exit: Scale '{}' Coin '{}'".format(self.amount, self.coin))
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
        return "{} <Scale: {}> ".format(n, self.amount)


def keys_from_priv(priv_key):
    address, secret, compressed = deserialize_privkey(priv_key)
    sk = regenerate_key(secret)
    pubk = sk.get_public_key(compressed)
    return sk, pubk


def generate_random_sk():
        G = generator_secp256k1
        _r  = G.order()
        pvk = ecdsa.util.randrange( _r )
        eck = EC_KEY(number_to_string(pvk, _r))
        return eck

class BackgroundShufflingThread(threading.Thread, PrintErrorThread):

    scales = (
        100000000, # 1.0    BCH ➡
        10000000,  # 0.1    BCH ➝
        1000000,   # 0.01   BCH ➟
        100000,    # 0.001  BCH ⇢
        10000,     # 0.0001 BCH →
    )

    def __init__(self, window, wallet, network_settings,
                 period = 10.0, logger = None, fee = 300, password=None, timeout=60.0):
        super().__init__()
        self.daemon = True
        self.timeout = timeout
        self.period = period
        self.logger = logger
        self.wallet = wallet
        self.window = window
        self.host = network_settings.get("host", None)
        self.info_port = network_settings.get("info", None)
        self.port = 1337 # default value -- will get set to real value from server's stat port in run() method
        self.poolSize = 3 # default value -- will get set to real value from server's stat port in run() method
        self.ssl = network_settings.get("ssl", None)
        self.fee = fee
        self.lock = threading.RLock()
        self.password = password
        self.threads = {scale:None for scale in self.scales}
        self.shared_chan = Channel(switch_timeout=None) # threads write a 3-tuple here: (killme_flg, thr, msg)
        self.stop_flg = threading.Event()
        self.last_idle_check = 0
        self.done_utxos = dict()
        self._paused = False

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
                    self.check_server_if_errored() # NB: this normally is a noop but if server port is bad, blocks for up to 7.5 seconds
                    self.check_idle_threads()
            self.print_error("Stopped")
        finally:
            self._unreserve_addresses()
            self.logger.send("stopped", "MAINLOG")

    def check_server_if_errored(self):
        if not self.stop_flg.is_set() and self.window.cashshuffle_get_flag() == 1:
            # bad server flag is set -- try to rediscover the shuffle port in case it changed
            return self.check_server(quick = True)

    def check_server(self, quick = False):
        def _do_check_server(timeout):
            try:
                self.port, self.poolSize, connections, pools = query_server_for_stats(self.host, self.info_port, self.ssl, timeout)
                if self.ssl and not verify_ssl_socket(self.host, self.port, timeout=timeout):
                    self.print_error("SSL Verification failed")
                    return False
                self.print_error("Server {}:{} told us that it has shufflePort={} poolSize={} connections={}".format(self.host, self.info_port, self.port, self.poolSize, connections))
                return True
            except BaseException as e:
                self.print_error("Exception: {}".format(str(e)))
                self.print_error("Could not query shuffle port for server {}:{} -- defaulting to {}".format(self.host, self.info_port, self.port))
                return False
        # /_do_check_server
        if quick:
            timeout =  7.5 if (Network.get_instance() and Network.get_instance().get_proxies()) else 2.5
        else:
            timeout = 12.5 if (Network.get_instance() and Network.get_instance().get_proxies()) else 5.0
        if not _do_check_server(timeout = timeout):
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
                    scale, sender = thr.amount, thr.coin
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
        with self.wallet.lock, self.wallet.transaction_lock:
            l = len(self.wallet._addresses_cashshuffle_reserved)
            self.wallet._addresses_cashshuffle_reserved.clear()
            if l: self.print_error("Freed {} reserved addresses".format(l))
            if self.wallet._last_change:
                self.wallet._last_change = None
                self.print_error("Freed 'last_change'")
            unfreeze_frozen_by_shuffling(self.wallet)

    def stop_protocol_thread(self, thr, scale, sender, message):
        self.print_error("Stop protocol thread for scale: {}".format(scale))
        retVal = False
        if sender:
            if message.endswith('complete protocol'):
                # remember this 'just spent' coin for self.timeout amount of
                # time as a guard to ensure that we wait for the tx to show
                # up in the wallet before considerng it again for shuffling
                self.done_utxos[sender] = time.time()
                retVal = True # indicate to interesteed callers that we had a completion. Our thread loop uses this retval to decide to scan for UTXOs to shuffle immediately.
            with self.wallet.lock, self.wallet.transaction_lock:
                self.wallet.set_frozen_coin_state([sender], False)
                coins_for_shuffling = set(self.wallet.storage.get("coins_frozen_by_shuffling",[]))
                coins_for_shuffling -= {sender}
                self.wallet.storage.put("coins_frozen_by_shuffling", list(coins_for_shuffling))
                if message.startswith("Error"):
                    # unreserve addresses that were previously reserved iff error
                    self.wallet._addresses_cashshuffle_reserved -= { thr.addr_new_addr, thr.change_addr }
                    #self.print_error("Unreserving", thr.addr_new_addr, thr.change_addr)
            self.tell_gui_to_refresh()
            self.logger.send(message, sender)
        else:
            self.print_error("No sender! Thr={}".format(str(thr)))
        if thr == self.threads[scale]:
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
            self.print_error("Signalling stop for scale: {}".format(thr.amount))
            self.shared_chan.send((True, thr, message))
        def fwd_message(thr, message):
            #self.print_error("Fwd msg for: Scale='{}' Msg='{}'".format(thr.amount, message))
            self.shared_chan.send((False, thr, message))
        scale = thr.amount
        thr.ts = time.time()
        self.print_error("Scale: {} Message: '{}'".format(scale, message.strip()))
        if message.startswith("Error") or message.startswith("Exit"):
            signal_stop_thread(thr, message) # sends request to shared channel. our thread will join
        elif message.startswith("shuffle_txid:"): # TXID message -- forward to GUI so it can call "set_label"
            fwd_message(thr, message)
        elif message.endswith("complete protocol"):
            signal_stop_thread(thr, message) # sends request to shared channel
        elif message.startswith("Player"):
            fwd_message(thr, message)  # sends to Qt signal, which will run in main thread
        elif "get session number" in message:
            fwd_message(thr, message)  # sends to Qt signal, which will run in main thread
        elif "begins CoinShuffle protocol" in message:
            fwd_message(thr, message)  # sends to Qt signal, which will run in main thread
        elif message.startswith("Blame"):
            if "insufficient" in message:
                pass
            elif "wrong hash" in message:
                pass
            else:
                signal_stop_thread(thr, message)

    # NB: all locks must be held when this is called
    def _make_protocol_thread(self, scale, coins):
        def get_coin_for_shuffling(scale, coins):
            if not getattr(self.wallet, "is_coin_shuffled", None):
                raise RuntimeWarning('Wallet lacks is_coin_shuffled method!')
            unshuffled_coins = [coin for coin in coins
                                # Note: the 'is False' is intentional -- we are interested in coins that we know for SURE are not shuffled.
                                # is_coin_shuffled() also returns None in cases where the tx isn't in the history (a rare occurrence)
                                if self.wallet.is_coin_shuffled(coin) is False]
            upper_amount = scale*10 + self.fee
            lower_amount = scale + self.fee
            unshuffled_coins_on_scale = [coin for coin in unshuffled_coins
                                         if coin['value'] < upper_amount and coin['value'] >= lower_amount and get_name(coin) not in self.done_utxos]
            unshuffled_coins_on_scale.sort(key=lambda x: x['value']*100000000 + (100000000-x['height']))
            if unshuffled_coins_on_scale:
                return unshuffled_coins_on_scale[-1]
            return None
        # /
        coin = get_coin_for_shuffling(scale, coins)
        if not coin:
            return
        try:
            private_key = self.wallet.export_private_key(coin['address'], self.get_password())
        except InvalidPassword:
            # This shouldn't normally happen but can if the user JUST changed their password in the GUI thread
            # and we didn't yet get informed of the new password.  In which case we give up for now and 10 seconds later
            # (the next 'period' time), this coin will be picked up again.
            raise RuntimeWarning('Invalid Password caught when trying to export a private key -- if this keeps happening tell the devs!')
        utxo_name = get_name(coin)
        self.wallet.set_frozen_coin_state([utxo_name], True)
        coins_for_shuffling = set(self.wallet.storage.get("coins_frozen_by_shuffling",[]))
        coins_for_shuffling |= {utxo_name}
        self.wallet.storage.put("coins_frozen_by_shuffling", list(coins_for_shuffling))
        inputs = {}
        sks = {}
        public_key = self.wallet.get_public_key(coin['address'])
        sk = regenerate_key(deserialize_privkey(private_key)[1])
        inputs[public_key] = [utxo_name]
        sks[public_key] = sk
        id_sk = generate_random_sk()
        id_pub = id_sk.GetPubKey(True).hex()

        output = None
        for address in self.wallet.get_unused_addresses():
            if address not in self.wallet._addresses_cashshuffle_reserved:
                output = address
                break
        while not output:
            address = self.wallet.create_new_address(for_change = False)
            if address not in self.wallet._addresses_cashshuffle_reserved:
                output = address
        change = self.wallet.cashshuffle_get_new_change_address(for_shufflethread=True)
        self.wallet._addresses_cashshuffle_reserved |= {output, change} # NB: only modify this when holding wallet locks
        self.print_error("Scale {} Coin {} OutAddr {} Change {} make_protocol_thread".format(scale, utxo_name, output.to_storage_string(), change.to_storage_string()))
        #self.print_error("Reserved addresses:", self.wallet._addresses_cashshuffle_reserved)
        ctimeout = 12.5 if (Network.get_instance() and Network.get_instance().get_proxies()) else 5.0 # allow for 12.5 second connection timeouts if using a proxy server
        thr = ProtocolThread(self.host, self.port, utxo_name,
                             scale, self.fee, id_sk, sks, inputs, id_pub, output, change,
                             logger=None, ssl=self.ssl, comm_timeout = self.timeout, ctimeout = ctimeout, total_amount = coin['value'])
        thr.logger = ChannelSendLambda(lambda msg: self.protocol_thread_callback(thr, msg))
        self.threads[scale] = thr
        coins.remove(coin)
        thr.start()
        return True

    def is_coin_busy_shuffling(self, utxo_name_or_dict):
        ''' Checks the extant running threads (if any) for a match to coin.
        This is a very accurate real-time indication that a coins is busy
        shuffling. Used by the spendable_coin_filter in qt.py.'''
        if isinstance(utxo_name_or_dict, dict):
            name = get_name(utxo_name_or_dict)
        else:
            name = utxo_name_or_dict
        # name must be an str at this point!
        with self.wallet.lock, self.wallet.transaction_lock:
            return any(thr for thr in self.threads.values() if thr and thr.coin == name)

    def is_wallet_ready(self):
        return bool( self.wallet and self.wallet.is_up_to_date()
                     and self.wallet.network and self.wallet.network.is_connected()
                     and self.wallet.verifier and self.wallet.verifier.is_up_to_date()
                     and self.wallet.synchronizer and self.wallet.synchronizer.is_up_to_date()
                     and Network.get_instance() )

    def is_offline_mode(self):
        return bool(not self.wallet or not self.wallet.network)

    def check_for_coins(self):
        if self.stop_flg.is_set() or self._paused: return
        need_refresh = False
        with self.wallet.lock, self.wallet.transaction_lock:
            if self.is_wallet_ready():
                try:
                    #TODO FIXME XXX -- perhaps also add a mechanism to detect when coins that are in the queue or are being shuffled get reorged or spent
                    coins = None
                    for scale, thr in self.threads.items():
                        if not thr:
                            if coins is None: # NB: leave this check for None specifically as it has different semantics than coins == []
                                # lazy-init of coins here only if there is actual work to do.
                                coins = self.wallet.get_utxos(exclude_frozen = True, confirmed_only = True, mature = True)
                            if not coins: break # coins mutates as we iterate so check that we still have candidate coins
                            did_start = self._make_protocol_thread(scale, coins)
                            need_refresh = did_start or need_refresh # once need_refresh is set to True, it remains True
                except RuntimeWarning as e:
                    self.print_error("check_for_threads error: {}".format(str(e)))
        if need_refresh:
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
