import time
import random
import ecdsa
import threading
import requests
from electroncash.bitcoin import deserialize_privkey, regenerate_key, EC_KEY, generator_secp256k1, number_to_string
from electroncash.address import Address
from electroncash.util import PrintError, InvalidPassword

class PrintErrorThread(PrintError):
    def diagnostic_name(self):
        n = super().diagnostic_name()
        return "{} ({})".format(n, threading.get_ident())

from .coin import Coin
from .crypto import Crypto
from .messages import Messages
from .coin_shuffle import Round
from .comms import Channel, ChannelWithPrint, ChannelSendLambda, Comm, query_server_for_shuffle_port

ERR_SERVER_CONNECT = "Error: cannot connect to server"


class ProtocolThread(threading.Thread, PrintErrorThread):
    """
    This class emulate thread with protocol run
    """
    def __init__(self, host, port, network, coin,
                 amount, fee, sk, sks, inputs, pubk,
                 addr_new, change, logger=None, ssl=False, comm_timeout = 300.0):

        super(ProtocolThread, self).__init__()
        self.daemon = True
        self.messages = Messages()
        self.comm = Comm(host, port, ssl=ssl, timeout = comm_timeout)
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
        self.all_inputs = {}
        self.addr_new = addr_new
        self.change = change
        self.protocol = None
        self.network = network
        self.tx = None
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
            for pk in packet.packet.message.inputs:
                self.all_inputs[player_key][pk] = packet.packet.message.inputs[pk].coins[:]
        if self.players:
            self.logger.send('Player ' +str(self.number)+ " get " + str(len(self.players))+".\n")
        #check if all keys are different
        if len(set(self.players.values())) is not self.number_of_players:
            self.logger.send('Error: The same keys appears!')
            self.done.set()

    @not_time_to_die
    def start_protocol(self):
        "This method starts the protocol thread"
        coin = Coin(self.network)
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
            self.players, self.addr_new, self.change
        )
        if not self.done.is_set():
            self.protocol.start_protocol()
            self.done.wait()

    @not_time_to_die
    def run(self):
        "this method trying to run the round and catch possible problems with it"
        try:
            err = ERR_SERVER_CONNECT
            self.comm.connect()
            err = "Error: cannot register on the pool"
            self.register_on_the_pool()
            err = "Error: cannot complete the pool"
            self.wait_for_announcment()
            err = "Error: cannot share the keys"
            self.share_the_key()
            err = "Error: cannot gather the keys"
            self.gather_the_keys()
        except BaseException as e:
            self.print_error("Exception in 'run': {}".format(str(e)))
            self.logger.send(err)
            return
        self.start_protocol()

    def stop(self):
        "This method stops the protocol threads"
        if self.protocol:
            self.protocol.done = True
        self.done.set()
        self.print_error("Closing comm -- subsequent socket errors are to be expected. :)")
        self.comm.close()

    def join(self, timeout=None):
        "This method Joins the protocol thread"
        self.stop()
        if self.is_alive():
            # the below is a work-around to the fact that this whole scheme still has a race condition with respect to the comm class :/
            super().join(2.0)
            if self.is_alive():
                self.print_error("Could not join self after 2 seconds. Trying with infinite timeout...")
                self.stop()
                self.join()
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
        pvk = ecdsa.util.randrange( pow(2,256) ) %_r
        eck = EC_KEY(number_to_string(pvk,_r))
        return eck

class BackgroundShufflingThread(threading.Thread, PrintErrorThread):

    scales = (
        100000000,
        10000000,
        1000000,
        100000,
        10000,
    )

    def __init__(self, wallet, network_settings,
                 period = 10, logger = None, fee=300, password=None, timeout=300):
        super(BackgroundShufflingThread, self).__init__()
        self.daemon = True
        self.timeout = timeout
        self.period = period
        self.logger = logger
        self.wallet = wallet
        self.host = network_settings.get("host", None)
        self.info_port = network_settings.get("info", None)
        self.port = 1337 # default value -- will get set to real value from server's stat port in run() method
        self.ssl = network_settings.get("ssl", None)
        self.network = network_settings.get("network", None)
        self.fee = fee
        self.lock = threading.RLock()
        self.password = password
        self.threads = {scale:None for scale in self.scales}
        self.loggers = {scale:ChannelSendLambda(lambda msg,my_scale=scale: self.protocol_thread_callback(my_scale, msg)) for scale in self.scales}
        self.shared_chan = Channel(switch_timeout=None) # threads write a 3-tuple here: (killme_flg, thr, msg)
        self.stop_flg = threading.Event()
        self.threads_timer = None # will be initialized in run()

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

    def query_server_port(self):
        try:
            self.port = query_server_for_shuffle_port(self.host, self.info_port, self.ssl, timeout=5.0)
            self.print_error("Server {}:{} told us that it has shufflePort={}".format(self.host, self.info_port, self.port))
        except BaseException as e:
            self.print_error("Exception: {}".format(str(e)))
            self.print_error("Could not query shuffle port for server {}:{} -- defaulting to {}".format(self.host, self.info_port, self.port))

    def run(self):
        self.print_error("Started")

        self.query_server_port()

        # NB: these need to be created within this thread to inherit its daemonic property
        self.threads_timer = threading.Timer(self.period, self.check_for_threads)

        self.threads_timer.start()
        if self.logger:
            self.logger.send("started", "MAINLOG")
            self.logger.send(self.get_password(), "MAINLOG")
        while not self.stop_flg.is_set():
            self.process_shared_chan() # NB: this blocks indefinitely until a message arrives or we are stopped so the above while loop is acceptable
        self.print_error("Stopped")

    def process_shared_chan(self):
        tup = self.shared_chan.recv()
        if isinstance(tup, tuple): # may be None on join()
            killme, thr, message = tup
            scale = thr.amount
            sender = thr.coin
            if killme:
                with self.lock:
                    # this is still wonky here. Race conditions aren't avoided 100% of the time. But I suppose this is "good enough" until we rework the whole thread ownership/creation scheme
                    curr_thr = self.threads[scale]
                if thr == curr_thr:
                    self.stop_protocol_thread(scale, message)
                else:
                    self.print_error("WARNING: Stale stop_thread message for Scale: '{}' Coin: '{}', thread not in list, ignoring!".format(scale,sender))
            elif self.logger:
                #self.print_error("--> Fwd msg to Qt for: Scale='{}' Sender='{}' Msg='{}'".format(scale, sender, message.strip()))
                self.logger.send(message, sender)

    def stop_protocol_thread(self, scale, message):
        self.print_error("Stop protocol thread for scale: {}".format(scale))
        with self.lock:
            thr = self.threads[scale]
            sender = thr and list(thr.inputs.values())[0][0]
            if sender:
                with self.wallet.lock:
                    self.wallet.set_frozen_coin_state([sender], False)
                    coins_for_shuffling = set(self.wallet.storage.get("coins_frozen_by_shuffling",[]))
                    coins_for_shuffling -= {sender}
                    self.wallet.storage.put("coins_frozen_by_shuffling", list(coins_for_shuffling))
                self.logger.send(message, sender)
            self.threads[scale] = None
        if thr and thr.is_alive(): thr.join()

    def protocol_thread_callback(self, scale, message):
        ''' This callback runs in the ProtocolThread's thread context '''
        def signal_stop_thread(thr, message):
            ''' Sends the stop request to our run() thread, which will join on this thread context '''
            self.print_error("Signalling stop for scale: {}".format(thr.amount))
            self.shared_chan.send((True, thr, message))
        def fwd_message(thr, message):
            #self.print_error("Fwd msg for: Scale='{}' Msg='{}'".format(thr.amount, message))
            self.shared_chan.send((False, thr, message))
        with self.lock:
            thr = self.threads[scale]
        if not thr:
            self.print_error("WARNING: Thread for scale {} not FOUND! Ignoring...  (Message = '{}')".format(scale, message))
            return
        self.print_error("Scale: {} Message: '{}'".format(scale, message.strip()))
        if message.startswith("Error"):
            if message.find(ERR_SERVER_CONNECT) != -1:
                # tell Qt about failure to connect
                fwd_message(thr, message)
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
            unshuffled_coins_on_scale = [coin for coin in unshuffled_coins if coin['value'] < upper_amount and coin['value'] >= lower_amount]
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
        utxo_name = "{}:{}".format(coin['prevout_hash'],coin['prevout_n'])
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
        addresses_on_threads = [Address.from_string(thr.addr_new)
                                for sc, thr in self.threads.items() if thr]
        output = None
        for address in self.wallet.get_unused_addresses():
            if address not in addresses_on_threads:
                output = address.to_storage_string()
                break
        output = output or self.wallet.create_new_address(for_change = False).to_storage_string()
        change_in_threads = [Address.from_string(thr.change)
                             for sc, thr in self.threads.items() if thr]
        change = None
        for address in self.wallet.get_change_addresses():
            if address not in change_in_threads and not self.wallet.get_address_history(address):
                change = address.to_storage_string()
                break
        change = change or self.wallet.create_new_address(for_change = True).to_storage_string()
        self.print_error("Scale {} Coin {} OutAddr {} Change {} make_protocol_thread".format(scale, utxo_name, output, change))
        self.threads[scale] = ProtocolThread(self.host, self.port, self.network, utxo_name,
                                             scale, self.fee, id_sk, sks, inputs, id_pub, output, change,
                                             logger=self.loggers[scale], ssl=self.ssl, comm_timeout = self.timeout)
        self.threads[scale].start()
        coins.remove(coin)

    def check_for_threads(self):
        if self.stop_flg.is_set(): return
        with self.lock:
            with self.wallet.lock:
                with self.wallet.transaction_lock:
                    try:
                        #TODO FIXME XXX -- perhaps also add a mechanism to detect when coins that are in the queue or are being shuffled get reorged or spent
                        if self.wallet.is_up_to_date() and self.wallet.network and self.wallet.network.is_connected():
                            coins = None
                            for scale in self.scales:
                                thr = self.threads.get(scale)
                                if not thr:
                                    if coins is None: # NB: leave this check for None specifically as it has different semantics than coins == []
                                        # lazy-init of coins here only if there is actual work to do.
                                        coins = self.wallet.get_utxos(exclude_frozen = True, confirmed_only = True, mature = True)
                                    if not coins: break # coins mutates as we iterate so check that we still have candidate coins
                                    self._make_protocol_thread(scale, coins)
                    except RuntimeWarning as e:
                        self.print_error("check_for_threads error: {}".format(str(e)))
                    finally:
                        self.threads_timer = threading.Timer(self.period, self.check_for_threads)
                        self.threads_timer.start()

    def join(self):
        with self.lock:
            self.stop_flg.set()
            self.shared_chan.send(None) # wakes our thread up so it can exit when it sees stop_flg is set
            if self.threads_timer: self.threads_timer.cancel()
            if self.logger:
                self.logger.send("stopped", "MAINLOG")
        for scale in self.scales:
            if self.threads[scale] and self.threads[scale].is_alive():
                self.print_error("Joining ProtocolThread[{}]...".format(scale))
                self.threads[scale].join()
        if self.is_alive():
            self.print_error("Joining self...")
            super().join()
