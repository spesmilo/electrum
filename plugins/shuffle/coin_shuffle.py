from .client import PrintErrorThread, ERR_BAD_SERVER_PREFIX
from .comms import BadServerPacketError
from electroncash.util import profiler

class ImplementationMissing(RuntimeError):
    pass

class Round(PrintErrorThread):
    """
    A single round of the protocol. It is possible that the players may go through
    several failed rounds until they have eliminated malicious players.
    """

    def __init__(self, coin_utils, crypto, messages,
                 inchan, outchan, logchan,
                 session, phase, scale, fee,
                 sk, sks, inputs, pubkey, players, addr_new, change, utxo,
                 coin_value):
        self.coin_utils = coin_utils
        self.crypto = crypto
        self.inchan = inchan
        self.outchan = outchan
        self.logchan = logchan
        self.session = session
        self.messages = messages
        self.phase = phase
        assert coin_value > 0, 'Coin value must be > 0!'
        self.coin_value = coin_value
        assert scale > 0, 'Scale value must be > 0!'
        self.scale = scale
        self.shuffle_amount = scale # this will grow to be the largest amount possible based on the smallest player participating
        assert fee > 0, 'Fee value must be > 0!'
        self.fee = fee
        self.sk = sk
        self.sks = sks
        self.inputs = inputs
        self.me = None
        self.number_of_players = None
        assert isinstance(players, dict), "Players should be stored in a dict"
        self.players = players
        self.number_of_players = len(players)
        self.vk = pubkey
        self.encryption_keys = dict()
        self.new_addresses = []
        self.addr_new = addr_new
        self.change = change
        self.utxo = utxo
        self.change_addresses = {}
        self.signatures = dict()
        self.inbox = {
            enum_val : dict() # this dict will end up being player_key -> message
            for phase, enum_val in self.messages.phases.items()
        }
        self.debug = False
        self.transaction = None
        self.tx = None
        self.did_use_change = True  # This will get recomputed later as the shuffle proceeds based on actual amounts in shuffle (#68)
        self.done = None
        if self.number_of_players == len(set(players.values())):
            if self.vk in players.values():
                for player, vk in players.items():
                    if self.vk == vk:
                        self.me = player # find 'me'!
                        break
            else:
                self.logchan.send('Error: public key is not in the players list')
                self.done = True
                return
        else:
            self.logchan.send('Error: same public keys appear in the pool!')
            self.done = True
            return

# Entry point of the protocol
    def start_protocol(self):
        """
        This function starts protocol

        It do the follows:
        1. Send the message about beginning to the log channel
        2. Check for sufficient funds of all players
        3. Broadcasts the new key for other players
        4. Starts the main protocol loop
        """
        assert self.scale > 0, "Wrong scale for transaction"
        self.log_message("begins CoinShuffle protocol with {} players."
                         .format(self.number_of_players))
        try:
            if self.check_and_blame_insufficient_funds():  # NB: this may raise AssertionError. If it does, we want the crash reporter.
                self.broadcast_new_key()
            self.protocol_loop()
        except OSError as e: # Socket closed or timed out
            self.print_error(repr(e))
            self.logchan.send("Error: Socket closed or timed out")
        except BadServerPacketError as e:
            self.print_error(repr(e))
            self.logchan.send("{} {}".format(ERR_BAD_SERVER_PREFIX, str(e)))
        except ImplementationMissing as e:
            self.print_error(repr(e))
            self.logchan.send("Error: ImplementationMissing -- original programmer's implentation is incomplete. FIXME!")
        finally:
            self.done = True

# Main Loop
    def protocol_loop(self):
        """
        This function is the  Main protocol loop

        It Checks the incoming channel for new messages (inchan_to_inbox) and if there is in
        it process the the incoming messages (process inbox).
        It does it in the loop until done flag will be rised
        """
        while not self.done:
            if self.inchan_to_inbox():
                self.process_inbox()

# General processing of incoming messages
    def inchan_to_inbox(self):
        """
        This function check incoming channel for messages.

        It does the follows:
            1. reads from incoming channels
            2. trying to parse the incoming message
            3. store the packets from message to inbox[phase][from_key]
        """
        val = self.inchan.recv()
        try:
            self.messages.packets.ParseFromString(val)
        except Exception as error:
            self.print_error("Decoding error: {}".format(str(error)))
            self.logchan.send('Error: Decoding error: {}'.format(str(error)))
            return None
        phase = self.messages.get_phase()
        from_key = self.messages.get_from_key()
        self.check_for_signatures()
        if from_key in self.players.values():
            self.inbox[phase][from_key] = val
        if self.debug:
            self.logchan.send("Player " + str(self.me)+"\n"+str(self.inbox))
        return True

    def process_inbox(self):
        """
        This function check new message in the inbox and start make message processing
        depending of phase field of incoming message.

        For example, if phase field of incoming message is 'shuffling' it
        starts the function 'process_shuffling'.
        """
        if self.check_for_blame():
            self.process_blame()
        else:
            handler = {
                'Announcement' : self.process_announcement,
                'Shuffling' : self.process_shuffling,
                'BroadcastOutput' : self.process_broadcast_output,
                'EquivocationCheck' : self.process_equivocation_check,
                'VerificationAndSubmission' : self.process_verification_and_submission,
                'Blame' : self.process_blame
            }.get(self.phase)
            if handler:
                handler()
            else:
                # Grrr. For some reason Yura didn't implement all the possible inbox handlers. :(
                # FIXME
                raise ImplementationMissing("Could not find a handler for inbox phase: {} -- FIXME!".format(self.phase))

# Processing of normal phases
    def process_announcement(self):
        """
        This function implement processing of messages on announcement phase (phase #1)


        It does the follows:
        1. Check if inbox is complete (it means player got all messages of announcement phase of the protocol
           from all other players including himself)
        2. Parse the messages in the inbox of announcement phase and extracts encryption keys and change addresses
        3. If there are all keys a gathered player goes to the next phase (shuffling)
        4. If player is first player it encrypt his address and send it to the next player.
        5. If player is not first it goes back to the main loop and waits for messages from previous player
        """
        phase = self.messages.phases[self.phase]
        if self.is_inbox_complete(phase):
            messages = self.inbox[phase]
            self.encryption_keys = dict()
            self.change_addresses = {}
            for message in messages:
                self.messages.packets.ParseFromString(messages[message])
                from_key = self.messages.get_from_key()
                self.encryption_keys[from_key] = self.messages.get_encryption_key()
                self.change_addresses[from_key] = self.messages.get_address()
            if len(self.encryption_keys) == self.number_of_players:
                self.log_message("recieved all keys for test")
                self.phase = 'Shuffling'
                self.log_message("reaches phase 2")
                self.messages.clear_packets()
                if self.me == self.first_player():
                    self.messages.add_str(self.encrypt_new_address())
                    self.send_message(destination=self.players[self.next_player()])
                    self.log_message("encrypt new address")
                    self.phase = 'BroadcastOutput'

    def process_shuffling(self):
        """
        This function implements processing of messages on shuffling phase (phase #2)

        It does the follows:
        1. Check if the message is from previous player
        2. decrypt all new addresses with it's own decryptuion key
        3. If player is not last player he add it's own new address to the packet, shuffle it and encrypt it with it's own new address and encrypt it.
           Also player check for different ciphertexts here. If there are the same ciphertexts it goes in Blame phase.
        4. If player is last player he goes to the next phase ("Broadcasts Output") and broadcast the outputs.
        """
        phase = self.messages.phases[self.phase]
        if self.me == self.last_player():
            sender = self.players[self.previous_player(player=self.last_player())]
            if self.inbox[phase].get(sender):
                self.messages.packets.ParseFromString(self.inbox[phase][sender])
                for packet in self.messages.packets.packet:
                    packet.packet.message.str = self.crypto.decrypt(packet.packet.message.str)
                self.messages.add_str(self.addr_new)
                self.messages.shuffle_packets()
                self.phase = 'BroadcastOutput'
                self.send_message()
                self.log_message("encrypt new address")
        else:
            sender = self.players[self.previous_player()]
            if self.inbox[phase].get(sender):
                self.messages.packets.ParseFromString(self.inbox[phase][sender])
                for packet in self.messages.packets.packet:
                    packet.packet.message.str = self.crypto.decrypt(packet.packet.message.str)
                if self.different_ciphertexts():
                    self.messages.add_str(self.encrypt_new_address())
                    self.messages.shuffle_packets()
                    self.send_message(destination=self.players[self.next_player()])
                    self.log_message("encrypt new address")
                    self.phase = 'BroadcastOutput'
                else:
                    self.skipped_equivocation_check(sender)
                    self.log_message("wrong from " + str(sender))

    def process_broadcast_output(self):
        """
        This function performs processing of messages on the "Broadcast Outputs" phase (phase #3)

        It does the folllows:
        1. Check if message is from the last player (only the last playet can broadcast outputs)
        2. got outputs from the message
        3. Check if players address is in new addresses. If it is not run skipped_equivocation_check.
        4. Goes to the next phase ('Equivocation Check').
        5. Compute hash of outputs string and broadcast it.
        """
        phase = self.messages.phases[self.phase]
        sender = self.players[self.last_player()]
        if self.inbox[phase].get(sender):
            self.messages.packets.ParseFromString(self.inbox[phase][sender])
            self.new_addresses = self.messages.get_new_addresses()
            if self.addr_new in self.new_addresses:
                self.log_message("received addresses and found self")
            else:
                self.logchan.send("Blame: Player " + str(self.me) +
                                  " did not find self in new address")
                self.skipped_equivocation_check(sender)
                return
            self.phase = 'EquivocationCheck'
            self.log_message("reaches phase 4")
            computed_hash = self.crypto.hash(str(self.new_addresses) +
                                             str([self.encryption_keys[self.players[i]]
                                                  for i in sorted(self.players)]))
            self.messages.clear_packets()
            self.messages.add_hash(computed_hash)
            self.send_message()

    def process_equivocation_check(self):
        """
        This function implements processing of messages on Equivocation Check phase(phase # 4)

        It does the follows:
        1. Check if inbox for this phase is complete
        2. Verify if hashes from all players are the same. If it is not goes to the blame phase
        3. If hashes are the same it goes to verification and submission phase
        4. It makes a unsigned transaction, compute players inputs signature for this tracnsaction and broadcast it
        """
        phase = self.messages.phases[self.phase]
        if self.is_inbox_complete(phase):
            computed_hash = self.crypto.hash(str(self.new_addresses) +
                                             str([self.encryption_keys[self.players[i]]
                                                  for i in sorted(self.players)]))
            messages = self.inbox[phase]
            for player, player_msg in messages.items():
                self.messages.packets.ParseFromString(player_msg)
                hash_value = self.messages.get_hash()
                if hash_value != computed_hash:
                    phase1 = self.messages.phases["Announcement"]
                    phase3 = self.messages.phases["BroadcastOutput"]
                    phase1_packets = b"".join(list(self.inbox[phase1].values()))
                    phase3_packets = b"".join(list(self.inbox[phase3].values()))
                    for_send = phase1_packets + phase3_packets
                    self.messages.blame_equivocation_failure(player, invalid_packets=for_send)
                    self.phase = "Blame"
                    self.send_message()
                    cheater = [p for p in self.players if self.players[p] == player][0]
                    self.log_message("found bad hash from " + str(cheater))
                    self.logchan.send('Blame: wrong hash computed by player ' + str(cheater))
                    return
            self.phase = 'VerificationAndSubmission'
            self.log_message("reaches phase 5")
            self.transaction = self.coin_utils.make_unsigned_transaction(self.shuffle_amount,
                                                                         self.fee,
                                                                         self.inputs,
                                                                         self.new_addresses,
                                                                         self.change_addresses)
            if not self.transaction:
                self.logchan.send("Error: Could not make unsigned transaction")
                self.done = True
                return
            signatures = self.coin_utils.get_transaction_signature(self.transaction, self.inputs[self.vk], self.sks)
            self.messages.clear_packets()
            self.messages.add_signatures(signatures)
            self.send_message()
            self.log_message("send transction signatures")
            # workaround for issue #70
            self.logchan.send("add_tentative_shuffle: {}".format(self._get_tentative_shuffle_string()))


    def process_verification_and_submission(self):
        """
        This function implements processing of messages on verification and submission phase (phase # 5)

        It does the follows:
        1. Check if all players send its signatures
        2. Verify the tx signature of all players. If there is a wrong signature go to the blame phase.
        3. Make signed transaction and broadcast it
        4. Set done flag.

        Normally protocol should ends here.
        """
        phase = self.messages.phases[self.phase]

        if self.is_inbox_complete(phase):
            self.signatures = {}
            self.log_message("got transction signatures")
            pubkeys = {}
            for vk, vk_pubkeys in self.inputs.items():
                for pubkey, utxos in vk_pubkeys.items():
                    for utxo in utxos:
                        pubkeys[utxo] = pubkey
            for player, vk in self.players.items():
                self.messages.packets.ParseFromString(self.inbox[phase][vk])
                player_signatures = self.messages.get_signatures()
                for utxo, sig in player_signatures.items():
                    if not self.coin_utils.verify_tx_signature(sig, self.transaction, pubkeys[utxo], utxo):
                        self.messages.blame_wrong_transaction_signature(vk)
                        self.send_message()
                        self.logchan.send('Blame: wrong transaction signature from player {}'.format(player))
                        self.done = True
                        return
                    self.signatures.update(player_signatures)
            self.coin_utils.add_transaction_signatures(self.transaction, self.signatures)
            res, status = self.coin_utils.broadcast_transaction(self.transaction)
            if self.transaction.txid():
                # Register the txid as belonging to cashshuffle, unconditionally.
                # This is because even if broadcast failed, maybe one of our peers was able to send it for us,
                # and so we want it to get the appropriate label in the history.
                tot_scale_change_fee = self._get_total_scale_change_fee_str()
                self.logchan.send("del_tentative_shuffle: {}".format(self.utxo))
                self.logchan.send("shuffle_txid: {} {}".format(self.transaction.txid(), tot_scale_change_fee))
            if not res:
                self.logchan.send("Error: blockchain network fault!")
                self.print_error("Error broadcasting tx: res='{}' status='{}'".format(res, status))
            else:
                self.tx = self.transaction
                self.log_message("complete protocol")
            self.done = True

    def _get_total_scale_change_fee_str(self):
        ''' Returns a string that breaks down the actual:
        "total_input scale change fee" used in the shuffle. Useful for the
        shuffle_txid: internal message '''
        fee = self.fee
        chg = self.coin_value - self.shuffle_amount - self.fee
        if not self.did_use_change:
            fee += chg
            chg = 0
        return "{} {} {} {} {}".format(self.coin_value, self.shuffle_amount, chg, fee, self.scale)

    def _get_tentative_shuffle_string(self):
        return "{} {} {}".format(self.utxo, self.addr_new, self._get_total_scale_change_fee_str())

#Processing the Blame phases

    def process_blame(self):
        """
        This function implements processing the messages on the blame phase (phase # 6)

        It does the follows:
        1. get the blame reason from the blame message
        2. process the message depending on the blame reason
        """
        phase = self.messages.phases[self.phase]
        reason = self.messages.get_blame_reason()
        br = self.messages.blame_reason
        handler = {
            br('Insufficient Funds') : self.process_blame_insufficient_funds,
            br('Equivocation failure') : self.process_blame_equivocation_failure,
            br('Shuffle Failure') : self.process_blame_shuffle_failure,
            br('Shuffle and Equivocation Failure') : self.process_blame_shuffle_and_equivocation_failure
        }.get(reason)
        if handler:
            handler(phase, reason)
        else:
            # Grrr. For some reason Yura didn't implement all the possible blame handlers in messages_pb2.py. This codepath is
            # reached on verify signature failure -- but the blame appears to happen elsewhere anyway.
            # TODO: FIXME
            raise ImplementationMissing("Could not find a handler for blame reason: {} in phase: {} -- FIXME!".format(reason, phase))

    def process_blame_insufficient_funds(self, phase, reason):
        """
        This function implements processing of messages on blame phase reasoned by insufficient funds

        It does the follows:
        1. Wait until all players share the blame message
        2. Check if blame reason is the same for messages from all players
        3. Send ban message to server for excluding the player with insufficient funds from round
        4. restart the round with broadcasting the new key
        """
        messages = self.inbox[phase]
        if self.is_inbox_complete(phase):
            for sender, msg in messages.items():
                self.messages.packets.ParseFromString(msg)
                self.check_reasons_and_accused(reason)
            accused = self.messages.get_accused_key()
            del self.inputs[accused]
            self.ban_the_liar(self.messages.get_accused_key())
            self.inbox[self.messages.phases["Blame"]] = {}
            self.broadcast_new_key()

    def process_blame_equivocation_failure(self, phase, reason):
        """
        This function implements processing of messages on blame phase reasoned by equivocation failure

        It does the follows:
        1. Get messages from every player
        2. Restore what messages were sent and what messages was received
        3. Find if some player broadcast not the same values to the different players
        4. If there is a cheater - cheater is banned
        5. Protocol starts without cheater
        """
        messages = self.inbox[phase]
        keys_matrix = {key:set() for key in self.players.values()}
        changes_matrix = {key:set() for key in self.players.values()}
        new_addresses_matrix = {key:set() for key in self.players.values()}
        if self.is_inbox_complete(phase):
            for sender, msg in messages.items():
                self.messages.packets.ParseFromString(msg)
                self.check_reasons_and_accused(reason)
                invalid_packets = self.messages.get_invalid_packets()
                self.messages.packets.ParseFromString(invalid_packets)
                self.check_for_signatures()
                for packet in self.messages.packets.packet:
                    if packet.packet.phase == 1:
                        from_key = packet.packet.from_key.key
                        key = packet.packet.message.key.key
                        address = packet.packet.message.address.address
                        keys_matrix[from_key].add(key)
                        changes_matrix[from_key].add(address)
                    if packet.packet.phase == 3:
                        new_addresses_matrix[sender].add(packet.packet.message.str)
            new_addresses_matrix.update((k, frozenset(v)) for k, v in new_addresses_matrix.items())
            key_cheaters = list(filter(lambda key: len(keys_matrix[key]) > 1, keys_matrix))
            change_cheaters = list(filter(lambda key: len(changes_matrix[key]) > 1, changes_matrix))
            all_cheaters = list(set(key_cheaters + change_cheaters))
            if len(set(new_addresses_matrix.values())) > 1:
                all_cheaters.append(self.players[self.last_player()])
            if len(all_cheaters) > 0:
                self.players = {player:self.players[player]
                                for player in self.players
                                if self.players[player] not in all_cheaters}
                self.number_of_players = len(self.players)
                for phase, pmsg in self.messages.phases.items():
                    if phase != "Announcement":
                        self.inbox[pmsg] = {}
                phase_1 = self.messages.phases["Announcement"]
                self.inbox[phase_1] = {key:self.inbox[phase_1][key]
                                       for key in self.inbox[phase_1]
                                       if key not in all_cheaters}
                phase1_packets = self.inbox[phase_1].copy()
                encryption_keys = list(self.encryption_keys.values())
                for message, pkt_msg in phase1_packets.items():
                    self.messages.packets.ParseFromString(pkt_msg)
                    ec = self.messages.get_encryption_key()
                    if ec in encryption_keys:
                        del self.inbox[phase_1][message]
                for player in all_cheaters:
                    del self.inputs[player]
                    self.ban_the_liar(player)
                if self.vk not in all_cheaters:
                    self.inbox[self.messages.phases["Blame"]] = {}
                    self.broadcast_new_key()

    def process_blame_shuffle_failure(self, phase, reason):
        """
        This function process messages on the blame phase reasoned by shuffle failure

        It does the follows:
        1. If message comes from only one player it performs skipped equivocation check
        2. If message comes from all players it check all hashes from all players.
        3. If hashes is not the same it terminates the protocol with error
        4. If all hashes is the same it process blame and equivocation failure
        """
        phase_blame = self.messages.phases["Blame"]
        if len(self.inbox[phase_blame]) == 1:
            if self.messages.get_from_key() != self.vk:
                self.skipped_equivocation_check(self.messages.get_accused_key())
        elif self.is_inbox_complete(phase_blame):
            hashes = set()
            for player, msg in self.inbox[phase_blame].items():
                self.messages.packets.ParseFromString(msg)
                hashes.add(self.messages.get_hash())
            if len(hashes) == 1:
                accused = self.messages.get_accused_key()
                ec = self.crypto.export_public_key()
                dc = self.crypto.export_private_key()
                phase2 = self.messages.phases["Shuffling"]
                phase2_packets = b"".join(list(self.inbox[phase2].values()))
                self.messages.blame_shuffle_and_equivocation_failure(accused,
                                                                     ec,
                                                                     dc,
                                                                     phase2_packets)
                self.send_message()
                self.inbox[phase_blame] = {}
            else:
                self.logchan.send("Erorr: different hashes appears")
                self.done = True
                return

    def process_blame_shuffle_and_equivocation_failure(self, phase, reason):
        """
        This function implements processing of messages in blame and equivocation failure case

        It does the follows:
        1. It got all messages from other players and checking it for correct shuffling
        2. If there is a cheater it exclude cheater from players, ban it and starts protocol with key broadcastig
        """
        phase_blame = self.messages.phases["Blame"]
        if self.is_inbox_complete(phase_blame):
            cheater = self.check_for_shuffling()
            if cheater:
                if cheater != self.vk:
                    del self.inputs[cheater]
                    self.ban_the_liar(cheater)
                    self.players = {player:vk
                                    for player, vk in self.players.items()
                                    if vk != cheater}
                    self.number_of_players = len(self.players)
                    self.inbox = { enum_val : dict() for phase, enum_val in self.messages.phases.items() }
                    self.broadcast_new_key()

    @profiler
    def check_for_shuffling(self):
        """
        This function implemets checking for shuffling form messages after shuffling failureself.

        It does the follows:
        1. Takes the messages from other players
        2. get it's encryption keys and decryption keys
        3. replays shuffling until it found a broken step
        4. return cheater if broken step was found
        """
        shufflings = {}
        cheater = None
        phase_blame = self.messages.phases["Blame"]
        for player,msg in self.inbox[phase_blame].items():
            self.messages.packets.ParseFromString(msg)
            shufflings[player] = {}
            shufflings[player]['encryption_key'] = self.messages.get_public_key()
            shufflings[player]['decryption_key'] = self.messages.get_decryption_key()
            invalid_packets = self.messages.get_invalid_packets()
            self.messages.packets.ParseFromString(invalid_packets)
            shufflings[player]['strs'] = self.messages.get_strs()
        for player in sorted(self.players)[1:]:
            for i in sorted(self.players):
                if i >= player:
                    strs = shufflings[self.players[player]]['strs']
                    self.crypto.restore_from_privkey(shufflings[self.players[i]]['decryption_key'])
                    shufflings[self.players[player]]['strs'] = list(map(self.crypto.decrypt, strs))
        for pl_out, pl_in in zip(sorted(self.players)[1:-1], sorted(self.players)[2:]):
            out_strs = set(shufflings[self.players[pl_out]]['strs'])
            in_strs = set(shufflings[self.players[pl_in]]['strs'])
            marker = len(out_strs ^ in_strs) == 1
            if not marker:
                cheater = self.players[pl_out]
                self.logchan.send('cheater is ' + str(pl_out))
                break
        return cheater

# Function for working with players

    def first_player(self):
        """Returns the first index of sorted players dict"""
        return min(sorted(self.players))

    def last_player(self):
        """Returns the last index of sorted players dict"""
        return max(sorted(self.players))

    def next_player(self, player=None):
        """
        Returns the index of player next to specified player in the players dict
        Returns None for the last player.
        If player not specified then current players used.

        Keyword arguments:
        player = index of specified player (default None)
        """
        player = self.me if player is None else player
        if player != self.last_player():
            return sorted(self.players)[sorted(self.players).index(player) + 1]
        else:
            return None

    def previous_player(self, player=None):
        """
        Returns the index of player previous to specified player in the players dict
        Returns None for the first player.
        If player not specified then current players used.

        Keyword arguments:
        player = index of specified player (default None)
        """
        player = self.me if player is None else player
        if player is not self.first_player():
            return sorted(self.players)[sorted(self.players).index(player) - 1]
        else:
            return None

    def from_last_to_previous(self):
        """
        Returns indexes of players dict in reversed order form last to previous
        with respect to current player
        """
        index = sorted(self.players).index(self.next_player())
        return reversed(sorted(self.players)[index:])


# Functions for working with messages

    @profiler
    def check_for_signatures(self):
        """
        Check for signature in packets in the messages objec.
        """
        for sig, msg, player in self.messages.get_signatures_and_packets():
            if not self.coin_utils.verify_signature(sig, msg, player):
                self.messages.blame_invalid_signature(player)
                self.send_message()
                self.logchan.send('Blame: player ' + player + ' message with wrong signature!')

    def ban_the_liar(self, accused):
        """Send message to server for banning the player which verification key is accused"""
        self.messages.blame_the_liar(accused)
        self.send_message(destination=self.vk)


    def send_message(self, destination=None):
        """
        Send the message to specified destination
        If destination not specified sends too all

        Keyword arguments:
        destination - verification key of receiver (default None)
        """
        self.messages.form_all_packets(self.sk, self.session, self.me,
                                       self.vk, destination, self.phase)
        self.outchan.send(self.messages.packets.SerializeToString())

    def log_message(self, message):
        """Sends message from current player to log channel"""
        self.logchan.send("Player " + str(self.me) + " " + message)

# Miscellaneous functions
    def check_and_blame_insufficient_funds(self):
        """
        Checks for all players to have a sufficient funds to do the shuffling
        Enter the Blame phase if someone have no funds for shuffling
        """
        offenders = list()
        totals = set()
        self.shuffle_amount = self.scale
        for player, inp in self.inputs.items():
            is_funds_sufficient, tot = self.coin_utils.check_inputs_for_sufficient_funds_and_return_total(inp, self.scale + self.fee)
            if is_funds_sufficient is None:
                self.logchan.send("Error: Check inputs for sufficient funds failed!")
                self.done = True
                return None
            elif not is_funds_sufficient:
                offenders.append(player)
            else:
                assert tot is not None
                totals.add(tot)

        def compute_shuffle_amount():
            assert totals
            self.shuffle_amount = min(totals) - self.fee
            self.log_message("adjusts shuffle amount to {} BCH".format(self.shuffle_amount / 1e8))
            assert self.shuffle_amount >= self.scale
            # recompute did_use_change here.
            self.did_use_change = self.coin_value - self.shuffle_amount - self.fee >= self.coin_utils.dust_threshold()

        if len(offenders) == 0:
            self.log_message("finds sufficient funds")
            compute_shuffle_amount()
            return True
        else:
            self.phase = "Blame"
            old_players = self.players.copy()
            self.players = { player : vk
                             for player, vk in self.players.items()
                             if vk not in offenders}
            # invert the player -> vk map
            offender_names = { v: k for k,v in old_players.items() }
            for offender in offenders:
                if self.vk == offender:
                    # don't blame self.
                    continue
                self.messages.blame_insufficient_funds(offender)
                self.send_message()
                self.logchan.send('Blame: insufficient funds of player ' +
                                  str(offender_names.get(offender)))
            if len(self.players) >= 3:
                self.number_of_players = len(self.players)
                compute_shuffle_amount()
            else:
                self.logchan.send('Error: not enough players with sufficent funds')
                self.done = True
                return False
            if self.vk in offenders:
                self.logchan.send('Error: I appear to lack the funds!')
                self.done = True
                return False
            return False

    @profiler
    def broadcast_new_key(self):
        """Broadcasts the encryption keys for phase 2 (Shufflings)"""
        self.phase = 'Announcement'
        self.crypto.generate_key_pair()
        self.messages.clear_packets()
        self.messages.add_encryption_key(self.crypto.export_public_key(), self.change)
        self.send_message()
        self.log_message("has broadcasted the new encryption key")
        self.log_message("is about to read announcements")

    def encrypt_new_address(self):
        """Encrypts new address with encryption keys of players from last to previous"""
        encrypted = self.addr_new
        for i in self.from_last_to_previous():
            encrypted = self.crypto.encrypt(encrypted, self.encryption_keys[self.players[i]])
        return encrypted

    def different_ciphertexts(self):
        """Checks for the same ciphertexts on phase2(Shufflings)"""
        ciphertexts = self.messages.get_new_addresses()
        return len(ciphertexts) == len(set(ciphertexts))

    def is_inbox_complete(self, phase):
        """Checks if inbox for the selected phase is complete"""
        return len(self.inbox[phase]) == self.number_of_players

    def skipped_equivocation_check(self, accused):
        """Perfoms skipped equivocation check for accused player"""
        string_to_hash = str([self.encryption_keys[self.players[i]] for i in sorted(self.players)])
        computed_hash = self.crypto.hash(string_to_hash)
        self.messages.blame_shuffle_failure(accused, computed_hash)
        self.phase = 'Blame'
        self.send_message()

    def check_for_blame(self):
        """Check for messages in blame phase inbox"""
        return True if self.inbox[7] else False

    def check_reasons_and_accused(self, reason):
        """
        Check if all blame messages from players have the same reason
        and accused player is in the players list
        """
        if self.messages.get_blame_reason() != reason:
            self.logchan.send("Blame: different blame reasons from players")
            self.done = True
            return
        elif self.messages.get_accused_key in self.players.values():
            self.logchan.send("Blame: different blame players from players")
            self.done = True
