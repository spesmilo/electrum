import time
import random
import ecdsa
import threading
import requests
from electroncash.bitcoin import deserialize_privkey, regenerate_key, EC_KEY, generator_secp256k1, number_to_string
from electroncash.address import Address
from .coin import Coin
from .crypto import Crypto
from .messages import Messages
from .commutator_thread import Commutator, Channel, ChannelWithPrint
# from .phase import Phase
from .coin_shuffle import Round

class ProtocolThread(threading.Thread):
    """
    This class emulate thread with protocol run
    """
    def __init__(self, host, port, network,
                 amount, fee, sk, sks, inputs, pubk,
                 addr_new, change, logger=None, ssl=False):

        threading.Thread.__init__(self)
        self.host = host
        self.port = port
        self.ssl = ssl
        self.messages = Messages()
        self.income = Channel()
        self.outcome = Channel()
        if not logger:
            self.logger = ChannelWithPrint()
        else:
            self.logger = logger
        self.commutator = Commutator(self.income, self.outcome, ssl=ssl)
        self.vk = pubk
        self.session = None
        self.number = None
        self.number_of_players = None
        self.players = {}
        self.amount = amount
        self.fee = fee
        self.sk = sk
        self.sks = sks
        self.inputs = inputs
        self.all_inputs = {}
        self.addr_new = addr_new
        self.change = change
        self.deamon = True
        self.protocol = None
        self.network = network
        self.tx = None
        self.execution_thread = None
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
        self.income.send(msg)
        req = self.outcome.recv()
        self.messages.packets.ParseFromString(req)
        self.session = self.messages.packets.packet[-1].packet.session
        self.number = self.messages.packets.packet[-1].packet.number
        if self.session != '':
            self.logger.send("Player "  + str(self.number)+" get session number.\n")

    @not_time_to_die
    def wait_for_announcment(self):
        "This method waits for announcement messages from other pool"
        while self.number_of_players is None:
            req = self.outcome.recv()
            if self.done.is_set():
                break
            if req is None:
                time.sleep(0.1)
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
        self.income.send(shared_key_message)

    @not_time_to_die
    def gather_the_keys(self):
        "This method gather the verification keys from other players in the pool"
        messages = b''
        for _ in range(self.number_of_players):
            messages += self.outcome.recv()
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
            self.outcome, self.income, self.logger,
            self.session, begin_phase, self.amount, self.fee,
            self.sk, self.sks, self.all_inputs, self.vk,
            self.players, self.addr_new, self.change
        )
        self.execution_thread = threading.Thread(target=self.protocol.start_protocol)
        self.execution_thread.start()
        self.done.wait()
        self.execution_thread.join()


    def run(self):
        "this method trying to run the round and catch possible problems with it"
        try:
            self.commutator.connect(self.host, self.port)
            self.commutator.start()
        except:
            self.logger.send("Error: cannot connect to server")
        try:
            self.register_on_the_pool()
        except:
            self.logger.send("Error: cannot register on the pool")
        try:
            self.wait_for_announcment()
        except:
            self.logger.send("Error: cannot complete the pool")
        try:
            self.share_the_key()
        except:
            self.logger.send("Error: cannot share the keys")
        try:
            self.gather_the_keys()
        except:
            self.logger.send("Error: cannot gather the keys")
        self.start_protocol()
        if self.commutator.is_alive():
            self.commutator.join()


    def stop(self):
        "This method stops the protocol threads"
        if self.execution_thread:
            self.protocol.done = True
        self.done.set()
        self.outcome.send(None)


    def join(self, timeout=None):
        "This method Joins the protocol thread"
        self.stop()
        threading.Thread.join(self, timeout)


def is_protocol_done(pThread):
    if pThread.protocol:
        return pThread.protocol.done
    else:
        return pThread.done.is_set()

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

class BackgroundShufflingThread(threading.Thread):

    scales = [
        100000000,
        10000000,
        1000000,
        100000,
        10000,
    ]

    def __init__(self, wallet, network_settings,
                 period = 10, logger = None, fee=1000, password=None, watchdog_period=300):
        threading.Thread.__init__(self)
        self.watchdog_period = watchdog_period
        self.period = period
        self.logger = logger
        self.wallet = wallet
        self.host = network_settings.get("host", None)
        self.port = network_settings.get("port", None)
        self.ssl = network_settings.get("ssl", None)
        self.network = network_settings.get("network", None)
        self.fee = fee
        self.password = password
        self.threads = {scale:None for scale in self.scales}
        self.loggers = {scale:Channel(switch_timeout=1) for scale in self.scales}
        self.watchdogs = {scale:threading.Timer(self.watchdog_period, lambda x: self.watchdog_checkout(x), [scale]) for scale in self.scales}
        self.stopper = threading.Event()
        self.threads_timer = threading.Timer(self.period, self.check_for_threads)


    def run(self):
        self.threads_timer.start()
        if self.logger:
            self.logger.send("started", "MAINLOG")
            self.logger.send(self.password, "MAINLOG")
        while not self.stopper.is_set():
            for scale in self.scales:
                if self.threads[scale]:
                    self.prosess_protocol_messages(scale)
            time.sleep(0.01)

    def get_coin_for_shuffling(self, scale):
        if not getattr(self.wallet, "is_coin_shuffled", None):
            self.join()
            return None
        coins = self.wallet.get_utxos(exclude_frozen=True, confirmed_only=True )
        unshuffled_coins = [coin for coin in coins if not self.wallet.is_coin_shuffled(coin)]
        upper_amount = scale*10
        lower_amount = scale + self.fee
        unshuffled_coins_on_scale = [coin for coin in unshuffled_coins if coin['value'] < upper_amount and coin['value'] >= lower_amount]
        unshuffled_coins_on_scale.sort(key=lambda x: x['value']*100000000 + (100000000-x['height']))
        if unshuffled_coins_on_scale:
            return unshuffled_coins_on_scale[-1]
        else:
            return None

    def stop_protocol_thread(self, scale, message):
        sender = list(self.threads[scale].inputs.values())[0][0]
        self.wallet.set_frozen_coin_state([sender], False)
        coins_for_shuffling = set(self.wallet.storage.get("coins_frozen_by_shuffling",[]))
        coins_for_shuffling -= {sender}
        self.wallet.storage.put("coins_frozen_by_shuffling", list(coins_for_shuffling))
        self.logger.send(message, sender)
        self.threads[scale].join()
        while self.threads[scale].is_alive():
            pass
        with self.loggers[scale].mutex:
            self.loggers[scale].queue.clear()
        self.threads[scale] = None


    def prosess_protocol_messages(self, scale):
        # try:
        if self.loggers[scale].empty():
            return None
        else:
            message = None
            try:
                message = self.loggers[scale].recv()
            except Exception as e:
                self.logger.send("{} >> {}".format(type(e).__name__, e), "PROTOCOL")
                return None
            vk = self.threads[scale].vk
            sender = list(self.threads[scale].inputs.values())[0][0]
            if message.startswith("Error"):
                self.stop_protocol_thread(scale, message)
            elif message.endswith("complete protocol"):
                self.stop_protocol_thread(scale, message)
            elif message.startswith("Player"):
                self.logger.send(message, sender)
            elif "get session number" in message:
                self.logger.send(message, sender)
            elif "begins CoinShuffle protocol" in message:
                self.logger.send(message, sender)
            elif message.startswith("Blame"):
                if "insufficient" in message:
                    pass
                elif "wrong hash" in message:
                    pass
                else:
                    self.stop_protocol_thread(scale, message)

    def make_prototocol_thread(self, coin, scale):
        inputs= {}
        sks = {}
        public_key = self.wallet.get_public_key(coin['address'])
        private_key = self.wallet.export_private_key(coin['address'], self.password)
        sk = regenerate_key(deserialize_privkey(private_key)[1])
        inputs[public_key] = ["{}:{}".format(coin['prevout_hash'],coin['prevout_n'])]
        sks[public_key] = sk
        id_sk = generate_random_sk()
        id_pub = id_sk.GetPubKey(True).hex()
        address_on_threads = [Address.from_string(self.threads[scale].protocol.addr_new)
                              for scale in self.threads
                              if self.threads[scale] and self.threads[scale].protocol]
        output = [address for address in self.wallet.get_unused_addresses()
                  if address not in address_on_threads][0].to_ui_string()
        # output = self.wallet.get_unused_addresses()[0].to_ui_string()
        changes_in_threads = [Address.from_string(self.threads[scale].change) for scale in self.threads if self.threads[scale]]
        fresh_changes = [address for address in self.wallet.get_change_addresses()
                         if not self.wallet.get_address_history(address) and
                            address not in changes_in_threads]
        change_addr = fresh_changes[0] if fresh_changes else self.wallet.create_new_address(for_change=True)
        change = change_addr.to_ui_string()
        self.threads[scale] = ProtocolThread(self.host, self.port, self.network,
                                             scale, self.fee, id_sk, sks, inputs, id_pub, output, change,
                                             logger=self.loggers[scale], ssl=self.ssl)
        self.threads[scale].commutator.timeout = 5

    def check_for_threads(self):
        for scale in self.scales:
            if not self.threads[scale]:
                coin = self.get_coin_for_shuffling(scale)
                if coin:
                    coin_to_freeze = coin['prevout_hash'] + ":" + str(coin['prevout_n'])
                    self.wallet.set_frozen_coin_state([coin_to_freeze], True)
                    coins_for_shuffling = set(self.wallet.storage.get("coins_frozen_by_shuffling",[]))
                    coins_for_shuffling |= {coin_to_freeze}
                    self.wallet.storage.put("coins_frozen_by_shuffling", list(coins_for_shuffling))
                    self.make_prototocol_thread(coin, scale)
                    self.threads[scale].start()
                    if self.watchdogs[scale].is_alive():
                        self.watchdogs[scale].cancel()
                    self.watchdogs[scale] = threading.Timer(self.watchdog_period, lambda x: self.watchdog_checkout(x), [scale])
                    self.watchdogs[scale].start()
        self.threads_timer = threading.Timer(self.period, self.check_for_threads)
        self.threads_timer.start()

    def watchdog_checkout(self, scale):
        if self.threads[scale]:
            self.stop_protocol_thread(scale, "restart thread")
        self.watchdogs[scale] = threading.Timer(self.watchdog_period, lambda x: self.watchdog_checkout(x), [scale])
        self.watchdogs[scale].start()

    def join(self):
        self.stopper.set()
        self.threads_timer.cancel()
        for scale in self.watchdogs:
            self.watchdogs[scale].cancel()
        if self.logger:
            self.logger.send("stopped", "MAINLOG")
        for scale in self.scales:
            if self.threads[scale]:
                self.threads[scale].join()
        threading.Thread.join(self)
