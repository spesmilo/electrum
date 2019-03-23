from . import message_pb2 as message_factory

from random import shuffle

class AbortProtocol(RuntimeError):
    ''' If this or a subclass is raised, protocol ends. Pass a message to print
    to debug console. '''
    pass

class Messages:
    # packet phases
    ANNOUNCEMENT                = message_factory.ANNOUNCEMENT
    SHUFFLE                     = message_factory.SHUFFLE
    BROADCAST                   = message_factory.BROADCAST
    EQUIVOCATION_CHECK          = message_factory.EQUIVOCATION_CHECK
    VERIFICATION_AND_SUBMISSION = message_factory.VERIFICATION_AND_SUBMISSION
    SIGNING                     = message_factory.SIGNING
    BLAME                       = message_factory.BLAME

    @classmethod
    def is_valid_phase(cls, phase):
        return phase is not None and phase >= message_factory.NONE and phase <= message_factory.BLAME

    # types
    DEFAULT = message_factory.DEFAULT
    DUST    = message_factory.DUST

    TYPE_NAME_DICT = {
        # These should match the strings returned by the stats port.
        DEFAULT : "DEFAULT", DUST : "DUST"
    }

    # strings -> phase number
    phases = {
        'Announcement'              : ANNOUNCEMENT,
        'Shuffling'                 : SHUFFLE,
        'BroadcastOutput'           : BROADCAST,
        'EquivocationCheck'         : EQUIVOCATION_CHECK,
        'VerificationAndSubmission' : VERIFICATION_AND_SUBMISSION,
        'Signing'                   : SIGNING,
        'Blame'                     : BLAME,
    }

    def check_for_length(f):
        "Wrapper for number of packets in message"
        def wrapper(self):
            if len(self.packets.ListFields()) > 0:
                return f(self)
            else:
                raise AbortProtocol("check_for_length: got 0 packets.ListFields for `{}'".format(f.__qualname__))
        return wrapper

    def __init__(self):
        self.clear_packets()

    def clear_packets(self):
        "clear the packets"
        self.packets = message_factory.Packets()

    def blame_reason(self, name):
        """
        This method returns the number of blame reason by its name
        It is needed for using with protobuf Blame reasons enumerator
        """
        return getattr(message_factory, name.replace(' ', '').upper(), None)

    def make_greeting(self, verification_key, amount, typ, version):
        """
        This method makes a greeting message for entering the pool with verification_key
        Params:
            `amount`: the tier in satoshis
            `typ`: Shuffle type. One of the types above (DEFAULT or DUST)
            `version`: A version integer. Defaults to 0. Use version ints to
            keep clients speaking different versions of the protocol
            or using different 'consensus' rules from interfering with each
            other.
        """
        packet = self.packets.packet.add()
        packet.packet.from_key.key = verification_key
        packet.packet.registration.amount = amount
        packet.packet.registration.type = typ
        packet.packet.registration.version = version

    def form_all_packets(self, eck, session, number, vk_from, vk_to, phase):
        """
        This method forms a packet to send

        eck - elyptic key object (EC_KEY from lib.bitcoin)
        session - session id
        number - number of player in the pool
        vk_from - sender verification key
        vk_to - receiver verification key (None for broadcasted messages)
        phase - phase of the protocol
        """
        compressed = True
        if vk_from.startswith("04"):
            compressed = False
        for packet in self.packets.packet:
            packet.packet.session = session
            packet.packet.phase = self.phases.get(phase)
            packet.packet.number = int(number)
            packet.packet.from_key.key = vk_from
            if vk_to:
                packet.packet.to_key.key = vk_to
            else:
                packet.packet.ClearField('to_key')
            msg = packet.packet.SerializeToString()
            packet.signature.signature = eck.sign_message(msg, compressed)

    def general_blame(self, reason, accused):
        """
        accused is a veryfikation key! of player who accused the Blame
        reason is a reason why
        """
        self.clear_packets()
        # add new packet
        packet = self.packets.packet.add()
        # set blame resaon
        if reason in range(9): # Better to place evident reason states here
            packet.packet.message.blame.reason = reason
        # set blame acused
        packet.packet.message.blame.accused.key = accused
        # set phase (it is 'Blame' here, for real ;) )
        packet.packet.phase = message_factory.BLAME
        # we return nothing here. Message_factory is a state machine, We just update state

    def blame_the_liar(self, accused):
        self.general_blame(message_factory.LIAR, accused)

    def blame_insufficient_funds(self, offender):
        """
        offender is a veryfikation key! of player who have insufficient funds
        """
        self.general_blame(message_factory.INSUFFICIENTFUNDS, offender)

    def blame_equivocation_failure(self, accused, invalid_packets=None):
        """
        accused - is verification key of player with hash mismathc
        """
        self.general_blame(message_factory.EQUIVOCATIONFAILURE, accused)
        if invalid_packets:
            self.packets.packet[-1].packet.message.blame.invalid.invalid = invalid_packets

    def blame_missing_output(self, accused):
        """
        accused - is verification key of player who haven't find his address
        """
        self.general_blame(message_factory.MISSINGOUTPUT, accused)

    def blame_shuffle_failure(self, accused, hash_value):
        self.general_blame(message_factory.SHUFFLEFAILURE, accused)
        self.packets.packet[-1].packet.message.hash.hash = hash_value

    def blame_shuffle_and_equivocation_failure(self, accused, encryption_key,
                                               decryption_key, invalid_packets):
        self.general_blame(message_factory.SHUFFLEANDEQUIVOCATIONFAILURE, accused)
        self.packets.packet[-1].packet.message.blame.key.key = decryption_key
        self.packets.packet[-1].packet.message.blame.key.public = encryption_key
        self.packets.packet[-1].packet.message.blame.invalid.invalid = invalid_packets


    def blame_invalid_signature(self, accused):
        """
        accused - is verification key of player whos signature have failed
        """
        self.general_blame(message_factory.INVALIDSIGNATURE, accused)

    def blame_wrong_transaction_signature(self, accused):
        """
        accused - is verification key of player with wrong signature
        """
        self.general_blame(message_factory.INVALIDSIGNATURE, accused)

    def add_encryption_key(self, ek, change):
        """
        Adds encryption keys at the Announcement stage
        ek - is serialized encryption key
        """
        packet = self.packets.packet.add()
        packet.packet.message.key.key = ek
        if change: packet.packet.message.address.address = change

    def add_inputs(self, inputs):
        """
        Adds an inputs to the NEW packet

        Here inputs is a dict with bitcoin pubkey as a key and array
        utxo transaction id's as a values.

        Example:
        {

            "bitcoinpubkey_1":[
                "tx_hash_1111",
                "tx_hash_1112"
            ],

            "bitcoinpubkey_2":[
                "tx_hash_22221"
                "tx_hash_22222"
            ]
        }
        """
        packet = self.packets.packet.add()
        for k in inputs:
            packet.packet.message.inputs[k].coins[:] = inputs[k]

    def get_new_addresses(self):
        "extract new addresses from packets"
        return [packet.packet.message.str for packet in self.packets.packet]

    def get_hashes(self):
        "extract hashes from packets"
        return {str(packet.packet.from_key.key): packet.packet.message.hash.hash.encode('utf-8')
                for packet in self.packets.packet}

    def add_str(self, string):
        "adds string to NEW packet"
        packet = self.packets.packet.add()
        packet.packet.message.str = string

    def add_hash(self, hash_value):
        "adds hash to NEW packet"
        packet = self.packets.packet.add()
        packet.packet.message.hash.hash = hash_value

    def add_signatures(self, signatures):
        "adds signatures to NEW packet"
        packet = self.packets.packet.add()
        for utxo, sig in signatures.items():
            packet.packet.message.signatures.add()
            packet.packet.message.signatures[-1].utxo = utxo
            packet.packet.message.signatures[-1].signature.signature = sig

    def shuffle_packets(self):
        "shuffle the packets"
        packs = [p for p in self.packets.packet]
        shuffle(packs)
        self.clear_packets()
        for p in packs:
            self.packets.packet.add()
            self.packets.packet[-1].CopyFrom(p)

    def encryption_keys_count(self):
        "counts the number of encryption keys"
        return len([1 for packet in self.packets.packet if len(packet.packet.message.key.key) != 0])

    @check_for_length
    def get_session(self):
        "gets session id from the last packet"
        return self.packets.packet[-1].packet.session

    @check_for_length
    def get_number(self):
        "gets the numbet of player from the last packet"
        return self.packets.packet[-1].packet.number

    @check_for_length
    def get_encryption_key(self):
        "gets the encryption key from the last packet"
        return self.packets.packet[-1].packet.message.key.key

    @check_for_length
    def get_address(self):
        "gets the address from the last packet"
        return self.packets.packet[-1].packet.message.address.address

    @check_for_length
    def get_from_key(self):
        "gets the sender key value from the last packet"
        return self.packets.packet[-1].packet.from_key.key

    @check_for_length
    def get_to_key(self):
        "gets the receiver key valye from the last packet"
        return self.packets.packet[-1].packet.to_key.key

    @check_for_length
    def get_phase(self):
        "gets thr phase value from the last packet"
        return self.packets.packet[-1].packet.phase

    @check_for_length
    def get_hash(self):
        "gets the hash value from the last packet"
        return self.packets.packet[-1].packet.message.hash.hash

    @check_for_length
    def get_str(self):
        "gets the str value from the last packet"
        return self.packets.packet[-1].packet.message.str

    @check_for_length
    def get_inputs(self):
        "gets the inputs from the last packet"
        result = {}
        inputs = self.packets.packet[-1].packet.message.inputs
        for k in inputs:
            result[k] = inputs[k].coins[:]
        return result

    @check_for_length
    def get_signatures(self):
        "gets the signatures from the last packet"
        result = {}
        signatures = self.packets.packet[-1].packet.message.signatures
        for k in signatures:
            result[k.utxo] = k.signature.signature
        return result

    @check_for_length
    def get_blame_reason(self):
        "gets the blame reason from the last packet"
        return self.packets.packet[-1].packet.message.blame.reason

    @check_for_length
    def get_accused_key(self):
        "get the key of player accused for blame from the last packet"
        return self.packets.packet[-1].packet.message.blame.accused.key

    @check_for_length
    def get_invalid_packets(self):
        "get the invalid packets value from the last packet"
        return self.packets.packet[-1].packet.message.blame.invalid.invalid

    @check_for_length
    def get_public_key(self):
        "get the public key from the last packet"
        return self.packets.packet[-1].packet.message.blame.key.public

    @check_for_length
    def get_decryption_key(self):
        "gets the decryption key from the last packet"
        return self.packets.packet[-1].packet.message.blame.key.key

    def get_signatures_and_packets(self):
        "gets signatures and packets"
        return [[packet.signature.signature,
                 packet.packet.SerializeToString(),
                 packet.packet.from_key.key]
                for packet in self.packets.packet]

    def get_players(self):
        "gets players from the packet"
        return {packet.packet.number: str(packet.packet.from_key.key)
                for packet in self.packets.packet}

    def get_blame(self):
        "gets blames from the packet"
        return [packet.packet.message for packet in self.packets.packet]

    def get_strs(self):
        "gets strs values from the packets"
        return [packet.packet.message.str for packet in self.packets.packet]
