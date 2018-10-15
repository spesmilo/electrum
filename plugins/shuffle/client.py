import time
import threading
import requests
from electroncash.bitcoin import deserialize_privkey, regenerate_key
from electroncash.address import Address
from .coin import Coin
from .crypto import Crypto
from .messages import Messages
from .commutator_thread import Commutator, Channel, ChannelWithPrint
from .phase import Phase
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
        begin_phase = Phase('Announcement')
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

def bot_job(stat_endpoint, host, port, network, ssl,
            limit, maximum_per_pool, basic_logger, simple_logger,
            wallet, password, coin, fee, logchan = None, stopper = None):
    job_start_time = time.time()
    pools = []
    pool_size = None
    try:
        res = requests.get(stat_endpoint, verify=False)
        pools = res.json().get("pools", [])
        pool_size = res.json().get("PoolSize", None)
    except:
        basic_logger.send("[CashShuffle Bot] Stat server not respond")
        return
    if len(pools) > 0:
        # Select not full pools with members more then limit
        members = [pool for pool in pools
                   if not pool.get("full", False) and
                   pool.get("members", 0) >= limit]
        # Select unspent outputs in the wallet
        utxos = wallet.get_utxos(exclude_frozen=True, confirmed_only=False)
        # Select fresh inputs
        fresh_outputs = wallet.get_unused_addresses()
        if len(members) == 0:
            basic_logger.send("[CashShuffle] No pools sutisfiying the requirments")
        else:
            basic_logger.send("[CashShuffle] Trying to support {} pools".format(len(members)))
        for member in members:
            number_of_players = member['members']
            threshold = min(number_of_players + maximum_per_pool, pool_size)
            member.update({"addresses" : []})
            amount = member['amount'] + fee
            good_utxos = [utxo for utxo in utxos if utxo['value'] > amount]
            for good_utxo in good_utxos:
                addr = Address.to_string(good_utxo['address'], Address.FMT_LEGACY)
                try:
                    first_utxo = good_utxos[0]
                    if first_utxo:
                        address = {}
                        address.update({"utxo_for_spend": good_utxo['prevout_hash'] + ":" + str(good_utxo['prevout_n'])})
                        address.update({"input_address": good_utxo['address']})
                        address.update({"change_address": addr})
                        address.update({"shuffle_address": Address.to_string(fresh_outputs[0], Address.FMT_LEGACY)})
                        member['addresses'].append(address)
                        del fresh_outputs[0]
                        utxos.remove(good_utxo)
                        number_of_players += 1
                        if number_of_players == threshold:
                            break
                except Exception as e:
                    basic_logger.send("[CashShuffle Bot] {}".format(e))
                    basic_logger.send("[CashShuffle Bot] Network problems")
        # Define Protocol threads
        pThreads = []
        for member in members:
            amount = member["amount"]
            if member.get("addresses", None):
                for address in member.get("addresses"):
                    priv_key = wallet.export_private_key(address["input_address"], password)
                    sk, pubk = keys_from_priv(priv_key)
                    sks = {pubk:sk}
                    inputs = {pubk: [address["utxo_for_spend"]]}
                    new_addr = address["shuffle_address"]
                    change = address["change_address"]
                    logger = simple_logger(logchan=logchan)
                    # (self, host, port, network,
                    #  amount, fee, sk, sks, inputs, pubk,
                    #  addr_new, change, logger=None, ssl=False)
                    pThread = (ProtocolThread(host, port, network, amount, fee, sk, sks, inputs, pubk, new_addr, change, logger=logger, ssl=ssl))
                    logger.pThread = pThread
                    pThreads.append(pThread)
        # start Threads
        for pThread in pThreads:
            pThread.start()
        done = False
        while not done:
            time.sleep(1)
            done = all([is_protocol_done(pThread) for pThread in pThreads])
            if (time.time() - job_start_time) > 300:
                "Protocol execution Time Out"
                done = True
            if stopper:
                if stopper.is_set():
                    done = True
        for pThread in pThreads:
            pThread.join()
    else:
        basic_logger.send("[CashShuffle Bot] Nobody in the pools")

# bot_job(stat_endpoint, host, port, network, ssl, limit, maximum_per_pool, basic_logger, simple_logger, wallet, password, coin, fee, logchan = None):
class BotThread(threading.Thread):

    def __init__(self, stat_endpoint, host, port, network, ssl, limit, maximum_per_pool, logger, wallet, password, fee, logchan, stopper, period):
        threading.Thread.__init__(self)
        self.daemon = True
        self.stat_endpoint = stat_endpoint
        self.host = host
        self.port = port
        self.ssl = ssl
        self.network = network
        self.limit = limit
        self.maximum_per_pool = maximum_per_pool
        self.basic_logger = logger(logchan=logchan)
        self.simple_logger = logger
        self.wallet = wallet
        self.password = password
        self.fee = fee
        self.coin = Coin(network)
        self.logchan = logchan
        if stopper:
            self.stopper = threading.Event()
        else:
            self.stopper = None
        self.period = period * 60

    def check(self):
        bot_job(self.stat_endpoint, self.host, self.port, self.network, self.ssl,
                self.limit, self.maximum_per_pool, self.basic_logger, self.simple_logger,
                self.wallet, self.password, self.coin, self.fee,
                logchan = self.logchan, stopper = self.stopper)
        if not self.stopper.is_set():
            self.t = threading.Timer(self.period, self.check)
            self.t.start()

    def run(self):
        self.t = threading.Timer(self.period, self.check)
        self.t.start()

    def join(self):
        self.t.cancel()
        self.stopper.set()

        threading.Thread.join(self)
