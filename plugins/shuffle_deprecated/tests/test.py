import unittest
import configparser
import subprocess
import os, sys
import random
import ecdsa
import threading
import time

import imp
sys.path.append(os.path.realpath(os.path.dirname(__file__)+"/../../../"))

imp.load_module('electroncash', *imp.find_module('lib'))
imp.load_module('electroncash_gui', *imp.find_module('gui/qt'))
imp.load_module('electroncash_plugins', *imp.find_module('plugins'))


from electroncash.address import Address
from electroncash.util import InvalidPassword
from electroncash_plugins.shuffle_deprecated.client import ProtocolThread
from electroncash_plugins.shuffle_deprecated.comms import (ChannelWithPrint, Channel)
from electroncash_plugins.shuffle_deprecated.coin import Coin
from electroncash_plugins.shuffle_deprecated.crypto import Crypto
# from electroncash_plugins.shuffle_deprecated.phase import Phase
from electroncash_plugins.shuffle_deprecated.round import Round
from electroncash.bitcoin import (regenerate_key, deserialize_privkey, EC_KEY, generator_secp256k1,
                                  number_to_string ,public_key_to_p2pkh, point_to_ser, Hash)



class testNetwork(object):
    "simple class for emulating the network. You can make your own utxo pool for test"
    def __init__(self):
        self.coins = {}
        self.should_be_connected = True

    def add_coin(self, address, value, height = 0, tx_pos = 0, tx_hash = ''):
        if not self.coins.get(address):
            self.coins[address] = []
        self.coins[address].append({ "height" : height, "value": value , "tx_pos": tx_pos , "tx_hash" :tx_hash})

    def synchronous_get(self, command):
        bc_command, addresses = command
        if bc_command == 'blockchain.scripthash.listunspent':
            if len(addresses) > 0:
                result = [self.coins[addr] for addr in self.coins if addr.to_scripthash_hex()==addresses[0]][0]
                return result
        else:
            return []

    def broadcast_transaction(self, tx):
        return True, "done"

    def is_connected(self):
        return self.should_be_connected

class testThread(ProtocolThread):
    def __init__(self, host, port, network, coin_name ,amount, fee, sk, sks, inputs, pubk, addr_new, change, logger = None, ssl = False):
        # host, port, network, amount, fee, sk, sks, inputs, pubk, addr_new, change, logger=None, ssl=False
        super(testThread, self).__init__(host, port, network, coin_name, amount, fee, sk, sks, inputs, pubk, addr_new, change, logger = logger, ssl = ssl)

    @classmethod
    def from_private_key(cls, priv_key, coin_hash, host, port, network, amount, fee, addr_new, change, ssl=False, logger = None):
        address, secret, compressed = deserialize_privkey(priv_key)
        sk = regenerate_key(secret)
        pubk = sk.get_public_key(compressed)
        sks = {pubk:sk}
        inputs = {pubkey:[coin_hash]}
        return cls(host, port, network, coin_hash ,amount, fee, sk, sks, inputs, pubk, addr_new, change, ssl=ssl, logger = logger)

    # @classmethod
    # def from_sk(cls, sk, sks, pubk, inputs, host, port, network, amount, fee, addr_new, change, compressed = True, logger = None):
    #     # pubk = sk.get_public_key(compressed)
    #     # sks = {pubk:sk}
    #     # inputs = {pubk:[coin_hash]}
    #     return cls(host, port, network, amount, fee,
    #                sk, sks, inputs, pubk, addr_new, change, logger=logger)

class random_sk(EC_KEY):

    def __init__(self):
        G = generator_secp256k1
        _r  = G.order()
        pvk = ecdsa.util.randrange( _r )
        eck = EC_KEY.__init__(self, number_to_string(pvk,_r))

def make_fake_public_key(compressed=True, secret_key = None):
    sk = secret_key
    if not secret_key:
        sk = random_sk()
    return sk.GetPubKey(compressed).hex()

def make_fake_address(compressed=True):
    return public_key_to_p2pkh(make_fake_public_key(compressed=compressed))

def fake_hash(address, value):
    return Hash("{}{}".format(address, value)).hex()


class Crypto_cheater(Crypto):
    """
    This class is faking the Crypto. It needs for cheating on encryption decryption phase
    """

    def generate_fake_key_pair(self):
        self.fake_private_key = ecdsa.util.randrange( self._r )
        self.fake_eck = EC_KEY(number_to_string(self.fake_private_key, self._r))
        self.fake_public_key = point_to_ser(self.fake_private_key*self.G,True)

    def export_fake_public_key(self):
        return bytes.hex(self.fake_public_key)

    def decrypt(self, message):
        try:
            return self.eck.decrypt_message(message)
        except InvalidPassword:
            return self.fake_eck.decrypt_message(message)
        # return self.eck.decrypt_message(message)

class Round_wrong_broadcast(Round):
    """
    This Class implements wrong behaviour of protocol
    when cheater player send wrong encryption keys to one of
    the player. All we do here is just redefine the broadcast key function
    """

    def broadcast_new_key(self):
        self.phase = 'Announcement'
        self.crypto.generate_key_pair()
        self.crypto.generate_fake_key_pair()
        victim_key = random.choice([self.players[player] for player in self.players if not self.players[player] == self.vk])
        print('PLAYER ' + str(self.me) + " IS A CHEATER")
        print('CHEATER KEY IS ' + str(self.vk) )
        victim_number = {self.players[player]:player for player in self.players}[victim_key]
        print('VICTIM is ' + str(victim_number))
        print('VICTIM KEY is ' + str(victim_key))
        for player in self.players:
            self.messages.clear_packets()
            if self.players[player] is not victim_key:
                self.messages.add_encryption_key(self.crypto.export_public_key(), self.change)
            else:
                self.messages.add_encryption_key(self.crypto.export_fake_public_key(), self.change)
            self.send_message(destination = self.players[player])

# class for testing of sending of different vectors on pahse 3
class Round_wrong_output_vector(Round):
    """
    This Class implements wrong behaviour of protocol
    when cheater player send wrong output vector to one of
    the player. All we do here is just redefine the process_shuffling function
    """

    def process_shuffling(self):
        phase = self.messages.phases[self.phase]
        if self.me == self.last_player():
            victim_key = random.choice([self.players[player] for player in self.players if not self.players[player] == self.vk])
            victim_number = {self.players[player]:player for player in self.players}[victim_key]
            self.logchan.send("The last player choose Player " + str(victim_number) + " as a VICTIM")
            sender = self.players[self.previous_player(player = self.last_player())]
            self.some_fake_address = '1574vWgV4DAhRBhzx7q2k1p1SeA2wCpiPF'
            if self.inbox[phase].get(sender):
                self.messages.packets.ParseFromString(self.inbox[phase][sender])
                for packet in self.messages.packets.packet:
                    packet.packet.message.str = self.crypto.decrypt(packet.packet.message.str)
                # add the last address
                self.messages.add_str(self.addr_new)
                # shuffle the packets
                self.messages.shuffle_packets()
                # form packet ...
                self.phase = 'BroadcastOutput'
                for player in self.players:
                    if not player == victim_number:
                        self.send_message(destination = self.players[player])
                    else:
                        # find it's own address and change em change some address in the vector
                        addresses = [packet.packet.message.str for packet in self.messages.packets.packet]
                        my_index = addresses.index(self.addr_new)
                        self.messages.packets.packet[my_index].packet.message.str = self.some_fake_address
                        self.send_message(destination = self.players[player])
                        self.messages.packets.packet[my_index].packet.message.str = self.addr_new
                # self.send_message()
                self.logchan.send("Player " + str(self.me) + " encrypt new address")
        else:
            sender = self.players[self.previous_player()]
            if self.inbox[phase].get(sender):
                self.messages.packets.ParseFromString(self.inbox[phase][sender])
                for packet in self.messages.packets.packet:
                    packet.packet.message.str = self.crypto.decrypt(packet.packet.message.str)
                # add encrypted new addres of players
                self.messages.add_str(self.encrypt_new_address())
                # shuffle the packets
                self.messages.shuffle_packets()
                self.send_message(destination = self.players[self.next_player()])
                self.logchan.send("Player " + str(self.me) + " encrypt new address")
                self.phase = 'BroadcastOutput'

    def process_broadcast_output(self):
        phase = self.messages.phases[self.phase]
        sender = self.players[self.last_player()]
        if self.inbox[phase].get(sender):
            # extract addresses from packets
            self.messages.packets.ParseFromString(self.inbox[phase][sender])
            self.new_addresses = self.messages.get_new_addresses()
            #check if player address is in
            if self.addr_new in self.new_addresses or self.some_fake_address in self.new_addresses:
                self.logchan.send("Player "+ str(self.me) + " receive addresses and found itsefs")
            else:
                self.messages.clear_packets()
                self.messages.blame_missing_output(self.vk)
                self.send_message()
                self.logchan.send("Blame: player " + str(self.me) + "  not found itsefs new address")
                raise BlameException("Blame: player " + str(self.me) + "  not found itsefs new address")
            self.phase = 'EquivocationCheck'
            self.logchan.send("Player "+ str(self.me) + " reaches phase 4: ")
            # compute hash
            computed_hash =self.crypto.hash(str(self.new_addresses) + str([self.encryption_keys[self.players[i]] for i in sorted(self.players) ]))
            # create a new message
            self.messages.clear_packets()
            # add new hash
            self.messages.add_hash(computed_hash)
            self.send_message()

class Round_wrong_ciphertexts(Round):
    """
    This Class implements wrong behaviour of protocol
    when cheater player add the same ciphertext in the shuffling phase
    """

    def process_shuffling(self):
        phase = self.messages.phases[self.phase]
        if self.me == self.last_player():
            sender = self.players[self.previous_player(player = self.last_player())]
            if self.inbox[phase].get(sender):
                self.messages.packets.ParseFromString(self.inbox[phase][sender])
                for packet in self.messages.packets.packet:
                    packet.packet.message.str = self.crypto.decrypt(packet.packet.message.str)
                # add the last address
                self.messages.add_str(self.addr_new)
                # shuffle the packets
                self.messages.shuffle_packets()
                # form packet ...
                self.phase = 'BroadcastOutput'
                self.send_message()
                self.logchan.send("Player " + str(self.me) + " encrypt new address")
        else:
            sender = self.players[self.previous_player()]
            if self.inbox[phase].get(sender):
                self.messages.packets.ParseFromString(self.inbox[phase][sender])
                for packet in self.messages.packets.packet:
                    packet.packet.message.str = self.crypto.decrypt(packet.packet.message.str)
                # add encrypted new addres of players
                if not self.different_ciphertexts():
                    encrypted_address = self.encrypt_new_address()
                    packet_index = random.randint(0, len(self.messages.get_new_addresses())-1)
                    self.logchan.send("CHEATER IS " + str(self.me))
                    self.messages.packets.packet[packet_index].packet.message.str = encrypted_address
                    self.messages.add_str(encrypted_address)
                    # shuffle the packets
                    self.messages.shuffle_packets()
                    self.send_message(destination = self.players[self.next_player()])
                    self.logchan.send("Player " + str(self.me) + " encrypt new address")
                    self.phase = 'BroadcastOutput'
                else:
                    self.logchan.send('wrong ciphertext')


class Round_wrong_outputs(Round):
    """
    This Class implements wrong behaviour of protocol
    when cheater change the output for new value
    """

    def process_shuffling(self):
        phase = self.messages.phases[self.phase]
        if self.me == self.last_player():
            sender = self.players[self.previous_player(player = self.last_player())]
            if self.inbox[phase].get(sender):
                self.messages.packets.ParseFromString(self.inbox[phase][sender])
                for packet in self.messages.packets.packet:
                    packet.packet.message.str = self.crypto.decrypt(packet.packet.message.str)
                # add the last address
                self.messages.add_str(self.addr_new)
                # shuffle the packets
                self.messages.shuffle_packets()
                # form packet ...
                self.phase = 'BroadcastOutput'
                self.send_message()
                self.logchan.send("Player " + str(self.me) + " encrypt new address")
        else:
            sender = self.players[self.previous_player()]
            if self.inbox[phase].get(sender):
                self.messages.packets.ParseFromString(self.inbox[phase][sender])
                for packet in self.messages.packets.packet:
                    packet.packet.message.str = self.crypto.decrypt(packet.packet.message.str)
                # add encrypted new addres of players
                if not self.different_ciphertexts():
                    encrypted_address = self.encrypt_new_address()
                    original_address = self.addr_new
                    self.addr_new = '1574vWgV4DAhRBhzx7q2k1p1SeA2wCpiPF'
                    encrypted_address_2 = self.encrypt_new_address()
                    self.addr_new = original_address
                    packet_index = random.randint(0, len(self.messages.get_new_addresses())-1)
                    self.logchan.send("CHEATER IS " + str(self.me))
                    self.messages.packets.packet[packet_index].packet.message.str = encrypted_address_2
                    self.messages.add_str(encrypted_address)
                    # shuffle the packets
                    self.messages.shuffle_packets()
                    self.send_message(destination = self.players[self.next_player()])
                    self.logchan.send("Player " + str(self.me) + " encrypt new address")
                    self.phase = 'BroadcastOutput'
                else:
                    self.logchan.send('wrong ciphertext')


# Rewrite the client class with badass behaviour
class bad_client_wrong_broadcast(ProtocolThread):

    # def __init__(self, host, port, network, amount, fee, sk, pubk, addr_new, change, logger = None, ssl = False):
    #     super(bad_client_wrong_broadcast, self).__init__(host, port, network, amount, fee, sk, pubk, addr_new, change, logger = logger, ssl = False)

    def not_time_to_die(f):
        def wrapper(self):
            if not self.done.is_set():
                f(self)
            else:
                pass
        return wrapper

    @not_time_to_die
    def start_protocol(self):
        coin = Coin(self.network)
        crypto = Crypto_cheater()
        self.messages.clear_packets()
        # begin_phase = Phase('Announcement')
        begin_phase = 'Announcement'
        # Make Round
        self.protocol = Round_wrong_broadcast(
            coin, crypto, self.messages,
            self.outcome, self.income, self.logger,
            self.session, begin_phase, self.amount, self.fee,
            self.sk, self.sks, self.all_inputs, self.vk,
            self.players, self.addr_new, self.change
        )
        # self.execution_thread = threading.Thread(target = self.protocol.protocol_loop)
        self.execution_thread = threading.Thread(target = self.protocol.start_protocol)
        self.execution_thread.start()
        self.done.wait()
        self.execution_thread.join()

class bad_client_output_vector(ProtocolThread):

    # def __init__(self, host, port, network, amount, fee, sk, pubk, addr_new, change, logger = None, ssl = False):
    #     super(bad_client_wrong_broadcast, self).__init__(host, port, network, amount, fee, sk, pubk, addr_new, change, logger = logger, ssl = False)

    def not_time_to_die(f):
        def wrapper(self):
            if not self.done.is_set():
                f(self)
            else:
                pass
        return wrapper

    @not_time_to_die
    def start_protocol(self):
        coin = Coin(self.network)
        crypto = Crypto_cheater()
        self.messages.clear_packets()
        # begin_phase = Phase('Announcement')
        begin_phase = 'Announcement'
        # Make Round
        self.protocol = Round_wrong_output_vector(
            coin, crypto, self.messages,
            self.outcome, self.income, self.logger,
            self.session, begin_phase, self.amount, self.fee,
            self.sk, self.sks, self.all_inputs, self.vk,
            self.players, self.addr_new, self.change
        )
        # self.execution_thread = threading.Thread(target = self.protocol.protocol_loop)
        self.execution_thread = threading.Thread(target = self.protocol.start_protocol)
        self.execution_thread.start()
        self.done.wait()
        self.execution_thread.join()

class bad_client_same_ciphertext(ProtocolThread):

    def not_time_to_die(f):
        def wrapper(self):
            if not self.done.is_set():
                f(self)
            else:
                pass
        return wrapper

    @not_time_to_die
    def start_protocol(self):
        coin = Coin(self.network)
        # crypto = Crypto_cheater()
        crypto = Crypto()
        self.messages.clear_packets()
        # begin_phase = Phase('Announcement')
        begin_phase = 'Announcement'
        # Make Round
        self.protocol = Round_wrong_ciphertexts(
            coin, crypto, self.messages,
            self.outcome, self.income, self.logger,
            self.session, begin_phase, self.amount, self.fee,
            self.sk, self.sks, self.all_inputs, self.vk,
            self.players, self.addr_new, self.change
        )
        # self.execution_thread = threading.Thread(target = self.protocol.protocol_loop)
        self.execution_thread = threading.Thread(target = self.protocol.start_protocol)
        self.execution_thread.start()
        self.done.wait()
        self.execution_thread.join()

class bad_client_changig_the_output(ProtocolThread):

    def not_time_to_die(f):
        def wrapper(self):
            if not self.done.is_set():
                f(self)
            else:
                pass
        return wrapper

    @not_time_to_die
    def start_protocol(self):
        coin = Coin(self.network)
        crypto = Crypto()
        self.messages.clear_packets()
        # begin_phase = Phase('Announcement')
        begin_phase = 'Announcement'
        # Make Round
        self.protocol = Round_wrong_outputs(
            coin, crypto, self.messages,
            self.outcome, self.income, self.logger,
            self.session, begin_phase, self.amount, self.fee,
            self.sk, self.sks, self.all_inputs, self.vk,
            self.players, self.addr_new, self.change
        )
        # self.execution_thread = threading.Thread(target = self.protocol.protocol_loop)
        self.execution_thread = threading.Thread(target = self.protocol.start_protocol)
        self.execution_thread.start()
        self.done.wait()
        self.execution_thread.join()


class TestProtocolCase(unittest.TestCase):

    def __init__(self, *args, **kwargs):
        super(TestProtocolCase,self).__init__(*args, **kwargs)
        config = configparser.ConfigParser()
        config.read_file(open('plugins/shuffle_deprecated/tests/config.ini'))
        self.HOST = config["CashShuffle"]["address"]
        self.PORT = int(config["CashShuffle"]["port"])
        self.fee = int(config["Clients"]["fee"])
        self.amount = int(config["Clients"]["amount"])
        self.number_of_players = int(config["CashShuffle"]["pool_size"])
        self.server_debug = " -d " if {"True":True, "False":False}.get(config["CashShuffle"]["enable_debug"], False) else " "
        self.args = self.server_debug + " -s "+ str(self.number_of_players) + " -p " + str(self.PORT)
        self.casshuffle_path = config["CashShuffle"]["path"]

    def setUp(self):
        self.network = testNetwork()
        self.logger = ChannelWithPrint()
        print("exec " + self.casshuffle_path + self.args)
        self.server = subprocess.Popen("exec " + self.casshuffle_path + self.args, shell = True, preexec_fn=os.setsid)

    def tearDown(self):
        self.server.kill()

    def get_random_address(self):
        return public_key_to_p2pkh(bytes.fromhex(random_sk().get_public_key()))

    def make_bad_client(self, bad_cleint_thread , with_print = False):
        sk = random_sk()
        channel = ChannelWithPrint() if with_print else Channel()
        public_key = sk.get_public_key()
        inputs = {}
        number_of_pubs = random.randint(1,3)
        secret_keys = [random_sk() for _ in range(number_of_pubs)]
        sks = {sk.get_public_key():sk for sk in secret_keys}
        for pubk in sks:
            inputs[pubk]=[]
            number_of_coins = random.randint(1,2)
            addr = public_key_to_p2pkh(bytes.fromhex(pubk))
            for i in range(number_of_coins):
                min_amout_per_input = self.amount // number_of_pubs // number_of_coins
                coin_amount = random.randint(min_amout_per_input + self.fee + 1 , min_amout_per_input + self.fee + 1000)
                coin_hash = fake_hash(addr, coin_amount)
                inputs[pubk].append(coin_hash+":0")
                self.network.add_coin(addr, coin_amount, tx_hash=coin_hash)
        return bad_cleint_thread(self.HOST, self.PORT, self.network,
                                 self.amount, self.fee, sk, sks, inputs , public_key,
                                 self.get_random_address(), self.get_random_address(), logger = channel)

    def make_clients_threads(self, number_of_clients = None, with_print = False):
        if not number_of_clients:
            number_of_clients = self.number_of_players
        players = [{"channel":ChannelWithPrint() if with_print else Channel()}
                   for _ in range(number_of_clients)]
        for player in players:
            number_of_pubs = random.randint(1,3)
            player["secret_keys"] = [random_sk() for _ in range(number_of_pubs)]
            player["sks"] = {sk.get_public_key():sk for sk in player["secret_keys"]}
            player["inputs"] = {}
            for pubk in player["sks"]:
                player["inputs"][pubk]=[]
                number_of_coins = random.randint(1,2)
                addr = public_key_to_p2pkh(bytes.fromhex(pubk))

                for i in range(number_of_coins):
                    min_amout_per_input = self.amount // number_of_pubs // number_of_coins
                    coin_amount = random.randint(min_amout_per_input + self.fee + 1 , min_amout_per_input + self.fee + 1000)
                    coin_hash = fake_hash(addr, coin_amount)
                    player["inputs"][pubk].append(coin_hash+":0")
                    # self.network.add_coin(addr, coin_amount, tx_hash=coin_hash)
                    self.network.add_coin(Address.from_pubkey(pubk), coin_amount, tx_hash=coin_hash)
            player["sk"] = random_sk()
            player["pubk"] = player["sk"].get_public_key()
        protocolThreads = [testThread(self.HOST, self.PORT, self.network, "x" ,self.amount,  self.fee,
                                      player["sk"], player["sks"], player["inputs"], player["pubk"],
                                      self.get_random_address(), self.get_random_address(), logger = player['channel'])
                                      for player in players]
        return protocolThreads


    def start_protocols(self, protocolThreads, delay = 0):
        for pThread in protocolThreads:
            time.sleep(delay)
            pThread.start()

    def stop_protocols(self, protocolThreads):
        for pThread in protocolThreads:
            pThread.join()

    def is_protocol_complete(self, pThread):
        if pThread.protocol:
            return pThread.protocol.done
        else:
            return False

    def is_round_live(sefl, pThread):
        return pThread.execution_thread.is_alive() if pThread.execution_thread else None

    def get_last_logger_message(self, pThread, debug = False):
        message = None
        while not pThread.logger.empty():
            message = pThread.logger.get()
            if debug:
                print(message)
        return message
