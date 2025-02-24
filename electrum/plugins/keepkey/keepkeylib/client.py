# This file is part of the TREZOR project.
#
# Copyright (C) 2012-2016 Marek Palatinus <slush@satoshilabs.com>
# Copyright (C) 2012-2016 Pavol Rusnak <stick@satoshilabs.com>
# Copyright (C) 2016      Jochen Hoenicke <hoenicke@gmail.com>
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this library.  If not, see <http://www.gnu.org/licenses/>.
#
# The script has been modified for KeepKey Device.

from __future__ import print_function, absolute_import

import os
import sys
import time
import binascii
import hashlib
import unicodedata
import json
import getpass
import copy

from mnemonic import Mnemonic

from . import tools
from . import mapping
from . import messages_pb2 as proto
from . import messages_eos_pb2 as eos_proto
from . import messages_nano_pb2 as nano_proto
from . import messages_cosmos_pb2 as cosmos_proto
from . import types_pb2 as types
from . import eos
from . import nano
from .debuglink import DebugLink


# try:
#     from PIL import Image
#     SCREENSHOT = True
# except:
#     SCREENSHOT = False

SCREENSHOT = False

DEFAULT_CURVE = 'secp256k1'

# monkeypatching: text formatting of protobuf messages
tools.monkeypatch_google_protobuf_text_format()

def get_buttonrequest_value(code):
    # Converts integer code to its string representation of ButtonRequestType
    return [ k for k, v in types.ButtonRequestType.items() if v == code][0]

def pprint(msg):
    msg_class = msg.__class__.__name__
    msg_size = msg.ByteSize()
    """
    msg_ser = msg.SerializeToString()
    msg_id = mapping.get_type(msg)
    msg_json = json.dumps(protobuf_json.pb2json(msg))
    """
    if isinstance(msg, proto.FirmwareUpload):
        return "<%s> (%d bytes):\n" % (msg_class, msg_size)
    else:
        return "<%s> (%d bytes):\n%s" % (msg_class, msg_size, msg)

def log(msg):
    sys.stderr.write("%s\n" % msg.encode('utf-8'))
    sys.stderr.flush()

def log_cr(msg):
    sys.stdout.write('\r%s' % msg.encode('utf-8'))
    sys.stdout.flush()

def format_mnemonic(word_pos, character_pos):
    return "WORD %d: %s" % (word_pos, character_pos * '*')

def getch():
    try:
        import termios
    except ImportError:
        # Non-POSIX. Return msvcrt's (Windows') getch.
        import msvcrt
        return msvcrt.getch()

    # POSIX system. Create and return a getch that manipulates the tty.
    import sys, tty
    def _getch():
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            ch = sys.stdin.read(1)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        return ch

    return _getch()

class CallException(Exception):
    def __init__(self, code, message):
        super(CallException, self).__init__()
        self.args = [code, message]

class PinException(CallException):
    pass

class field(object):
    # Decorator extracts single value from
    # protobuf object. If the field is not
    # present, raises an exception.
    def __init__(self, field):
        self.field = field

    def __call__(self, f):
        def wrapped_f(*args, **kwargs):
            ret = f(*args, **kwargs)
            ret.HasField(self.field)
            return getattr(ret, self.field)
        return wrapped_f

class expect(object):
    # Decorator checks if the method
    # returned one of expected protobuf messages
    # or raises an exception
    def __init__(self, *expected):
        self.expected = expected

    def __call__(self, f):
        def wrapped_f(*args, **kwargs):
            ret = f(*args, **kwargs)
            if not isinstance(ret, self.expected):
                raise Exception("Got %s, expected %s" % (ret.__class__, self.expected))
            return ret
        return wrapped_f

def session(f):
    # Decorator wraps a BaseClient method
    # with session activation / deactivation
    def wrapped_f(*args, **kwargs):
        client = args[0]
        try:
            client.transport.session_begin()
            return f(*args, **kwargs)
        finally:
            client.transport.session_end()
    return wrapped_f

def normalize_nfc(txt):
    if sys.version_info[0] < 3:
        if isinstance(txt, unicode):
            return unicodedata.normalize('NFC', txt)
        if isinstance(txt, str):
            return unicodedata.normalize('NFC', txt.decode('utf-8'))
    else:
        if isinstance(txt, bytes):
            return unicodedata.normalize('NFC', txt.decode('utf-8'))
        if isinstance(txt, str):
            return unicodedata.normalize('NFC', txt)

    raise Exception('unicode/str or bytes/str expected')

class BaseClient(object):
    # Implements very basic layer of sending raw protobuf
    # messages to device and getting its response back.
    def __init__(self, transport, **kwargs):
        self.transport = transport
        self.verbose = False
        super(BaseClient, self).__init__()  # *args, **kwargs)

    def cancel(self):
        self.transport.write(proto.Cancel())

    @session
    def call_raw(self, msg):
        self.transport.write(msg)
        return self.transport.read_blocking()

    @session
    def call(self, msg):
        resp = self.call_raw(msg)
        handler_name = "callback_%s" % resp.__class__.__name__
        handler = getattr(self, handler_name, None)

        if handler != None:
            msg = handler(resp)
            if msg == None:
                raise Exception("Callback %s must return protobuf message, not None" % handler)
            resp = self.call(msg)

        return resp

    def callback_Failure(self, msg):
        if msg.code in (types.Failure_PinInvalid,
            types.Failure_PinCancelled, types.Failure_PinExpected):
            raise PinException(msg.code, msg.message)

        raise CallException(msg.code, msg.message)

    def close(self):
        self.transport.close()

class DebugWireMixin(object):
    def call_raw(self, msg):
        log("SENDING " + pprint(msg))
        resp = super(DebugWireMixin, self).call_raw(msg)
        log("RECEIVED " + pprint(resp))
        return resp

class TextUIMixin(object):
    # This class demonstrates easy test-based UI
    # integration between the device and wallet.
    # You can implement similar functionality
    # by implementing your own GuiMixin with
    # graphical widgets for every type of these callbacks.

    def __init__(self, *args, **kwargs):
        super(TextUIMixin, self).__init__(*args, **kwargs)
        self.character_request_first_pass = True

    def callback_ButtonRequest(self, msg):
        # log("Sending ButtonAck for %s " % get_buttonrequest_value(msg.code))
        return proto.ButtonAck()

    def callback_RecoveryMatrix(self, msg):
        if self.recovery_matrix_first_pass:
            self.recovery_matrix_first_pass = False
            log("Use the numeric keypad to describe positions.  For the word list use only left and right keys. The layout is:")
            log("    7 8 9     7 | 9")
            log("    4 5 6     4 | 6")
            log("    1 2 3     1 | 3")
        while True:
            character = getch()
            if character in ('\x03', '\x04'):
                return proto.Cancel()

            if character in ('\x08', '\x7f'):
                return proto.WordAck(word='\x08')

            # ignore middle column if only 6 keys requested.
            if (msg.type == types.WordRequestType_Matrix6 and
                character in ('2', '5', '8')):
                continue

            if (ord(character) >= ord('1') and ord(character) <= ord('9')):
                return proto.WordAck(word=character)

    def callback_PinMatrixRequest(self, msg):
        if msg.type == 1:
            desc = 'current PIN'
        elif msg.type == 2:
            desc = 'new PIN'
        elif msg.type == 3:
            desc = 'new PIN again'
        else:
            desc = 'PIN'

        log("Use the numeric keypad to describe number positions. The layout is:")
        log("    7 8 9")
        log("    4 5 6")
        log("    1 2 3")
        log("Please enter %s: " % desc)
        pin = getpass.getpass('')
        return proto.PinMatrixAck(pin=pin)

    def callback_PassphraseRequest(self, msg):
        log("Passphrase required: ")
        passphrase = getpass.getpass('')
        log("Confirm your Passphrase: ")
        if passphrase == getpass.getpass(''):
            passphrase = normalize_nfc(passphrase)
            return proto.PassphraseAck(passphrase=passphrase)
        else:
            log("Passphrase did not match! ")
            exit()

    def callback_CharacterRequest(self, msg):
        if self.character_request_first_pass:
            self.character_request_first_pass = False
            log("Use recovery cipher on device to input mnemonic. Words are autocompleted at 3 or 4 characters.")
            log("(use spacebar to progress to next word after match, use backspace to correct bad character or word entries)")

        # format mnemonic for console
        formatted_console = format_mnemonic(msg.word_pos + 1, msg.character_pos)

        # clear the runway before we display formatted mnemonic
        log_cr(' ' * 14)
        log_cr(formatted_console)

        while True:
            character = getch().lower()

            # capture escape
            if character in ('\x03', '\x04'):
                return proto.Cancel()

            character_ascii = ord(character)

            if character_ascii >= 97 and character_ascii <= 122 \
            and msg.character_pos != 4:
                # capture characters a-z
                return proto.CharacterAck(character=character)

            elif character_ascii == 32 and msg.word_pos < 23 \
            and msg.character_pos >= 3:
                # capture spaces
                return proto.CharacterAck(character=' ')

            elif character_ascii == 8 or character_ascii == 127 \
            and (msg.word_pos > 0 or msg.character_pos > 0):
                # capture backspaces
                return proto.CharacterAck(delete=True)

            elif character_ascii == 13 and msg.word_pos in (11, 17, 23):
                # capture returns
                log("")
                return proto.CharacterAck(done=True)

class DebugLinkMixin(object):
    # This class implements automatic responses
    # and other functionality for unit tests
    # for various callbacks, created in order
    # to automatically pass unit tests.
    #
    # This mixing should be used only for purposes
    # of unit testing, because it will fail to work
    # without special DebugLink interface provided
    # by the device.

    def __init__(self, *args, **kwargs):
        super(DebugLinkMixin, self).__init__(*args, **kwargs)
        self.debug = None
        self.in_with_statement = 0
        self.button_wait = 0
        self.screenshot_id = 0

        # Always press Yes and provide correct pin
        self.setup_debuglink(True, True)
        self.auto_button = True

        # Do not expect any specific response from device
        self.expected_responses = None

        # Use blank passphrase
        self.set_passphrase('')

    def close(self):
        super(DebugLinkMixin, self).close()
        if self.debug:
            self.debug.close()

    def set_debuglink(self, debug_transport):
        self.debug = DebugLink(debug_transport)

    def set_buttonwait(self, secs):
        self.button_wait = secs

    def __enter__(self):
        # For usage in with/expected_responses
        self.in_with_statement += 1
        return self

    def __exit__(self, _type, value, traceback):
        self.in_with_statement -= 1

        if _type != None:
            # Another exception raised
            return False

        # return isinstance(value, TypeError)
        # Evaluate missed responses in 'with' statement
        if self.expected_responses != None and len(self.expected_responses):
            raise Exception("Some of expected responses didn't come from device: %s" % \
                    [ pprint(x) for x in self.expected_responses ])

        # Cleanup
        self.expected_responses = None
        return False

    def set_expected_responses(self, expected):
        if not self.in_with_statement:
            raise Exception("Must be called inside 'with' statement")
        self.expected_responses = expected

    def setup_debuglink(self, button, pin_correct):
        self.button = button  # True -> YES button, False -> NO button
        self.pin_correct = pin_correct

    def set_passphrase(self, passphrase):
        self.passphrase = normalize_nfc(passphrase)

    def set_mnemonic(self, mnemonic):
        self.mnemonic = normalize_nfc(mnemonic).split(' ')

    def call_raw(self, msg):

        if SCREENSHOT and self.debug:
            layout = self.debug.read_layout()
            im = Image.new("RGB", (128, 64))
            pix = im.load()
            for x in range(128):
                for y in range(64):
                    rx, ry = 127 - x, 63 - y
                    if (ord(layout[rx + (ry / 8) * 128]) & (1 << (ry % 8))) > 0:
                        pix[x, y] = (255, 255, 255)
            im.save('scr%05d.png' % self.screenshot_id)
            self.screenshot_id += 1

        resp = super(DebugLinkMixin, self).call_raw(msg)
        self._check_request(resp)
        return resp

    def _check_request(self, msg):
        if self.expected_responses != None:
            try:
                expected = self.expected_responses.pop(0)
            except IndexError:
                raise CallException(types.Failure_Other,
                        "Got %s, but no message has been expected" % pprint(msg))

            if msg.__class__ != expected.__class__:
                raise CallException(types.Failure_Other,
                            "Expected %s, got %s" % (pprint(expected), pprint(msg)))

            fields = expected.ListFields()  # only filled (including extensions)
            for field, value in fields:
                if not msg.HasField(field.name) or getattr(msg, field.name) != value:
                    raise CallException(types.Failure_Other,
                            "Expected %s, got %s" % (pprint(expected), pprint(msg)))

    def callback_ButtonRequest(self, msg):
        if self.verbose:
            log("ButtonRequest code: " + get_buttonrequest_value(msg.code))

        if self.auto_button:
            if self.verbose:
                log("Pressing button " + str(self.button))
            if self.button_wait:
                if self.verbose:
                    log("Waiting %d seconds " % self.button_wait)
                time.sleep(self.button_wait)
            self.debug.press_button(self.button)

        return proto.ButtonAck()

    def callback_PinMatrixRequest(self, msg):
        if self.pin_correct:
            pin = self.debug.read_pin_encoded()
        else:
            pin = '444222'
        return proto.PinMatrixAck(pin=pin)

    def callback_PassphraseRequest(self, msg):
        if self.verbose:
            log("Provided passphrase: '%s'" % self.passphrase)
        return proto.PassphraseAck(passphrase=self.passphrase)


class ProtocolMixin(object):
    PRIME_DERIVATION_FLAG = 0x80000000
    VENDORS = ('keepkey.com',)

    def __init__(self, *args, **kwargs):
        super(ProtocolMixin, self).__init__(*args, **kwargs)
        self.init_device()
        self.tx_api = None

    def set_tx_api(self, tx_api):
        self.tx_api = tx_api

    def init_device(self):
        self.features = expect(proto.Features)(self.call)(proto.Initialize())
        if str(self.features.vendor) not in self.VENDORS:
            raise Exception("Unsupported device")

    def _get_local_entropy(self):
        return os.urandom(32)

    def _convert_prime(self, n):
        # Convert minus signs to uint32 with flag
        return [ int(abs(x) | self.PRIME_DERIVATION_FLAG) if x < 0 else x for x in n ]

    @staticmethod
    def expand_path(n):
        # Convert string of bip32 path to list of uint32 integers with prime flags
        # 0/-1/1' -> [0, 0x80000001, 0x80000001]
        if not n:
            return []

        n = n.split('/')

        # m/a/b/c => a/b/c
        if n[0] == 'm':
            n = n[1:]

        # coin_name/a/b/c => 44'/SLIP44_constant'/a/b/c
        # https://github.com/satoshilabs/slips/blob/master/slip-0044.md
        coins = {
            "Bitcoin": 0,
            "Testnet": 1,
            "Litecoin": 2,
            "Dogecoin": 3,
            "Dash": 5,
            "Namecoin": 7,
            "Bitsend": 91,
            "Groestlcoin": 17,
            "Zcash": 133,
            "BitcoinCash": 145,
            "Bitcore": 160,
            "Megacoin": 217,
            "Bitcloud": 218,
            "Axe": 4242,
        }

        if n[0] in coins:
            n = ["44'", "%d'" % coins[n[0]] ] + n[1:]

        path = []
        for x in n:
            prime = False
            if x.endswith("'"):
                x = x.replace('\'', '')
                prime = True
            if x.startswith('-'):
                prime = True

            x = abs(int(x))

            if prime:
                x |= ProtocolMixin.PRIME_DERIVATION_FLAG

            path.append(x)

        return path

    @expect(proto.PublicKey)
    def get_public_node(self, n, ecdsa_curve_name=DEFAULT_CURVE, show_display=False, coin_name=None, script_type=types.SPENDADDRESS):
        n = self._convert_prime(n)
        if not ecdsa_curve_name:
            ecdsa_curve_name=DEFAULT_CURVE
        return self.call(proto.GetPublicKey(address_n=n, ecdsa_curve_name=ecdsa_curve_name, show_display=show_display, coin_name=coin_name, script_type=script_type))

    @field('address')
    @expect(proto.Address)
    def get_address(self, coin_name, n, show_display=False, multisig=None, script_type=types.SPENDADDRESS):
        n = self._convert_prime(n)
        if multisig:
            return self.call(proto.GetAddress(address_n=n, coin_name=coin_name, show_display=show_display, multisig=multisig, script_type=script_type))
        else:
            return self.call(proto.GetAddress(address_n=n, coin_name=coin_name, show_display=show_display, script_type=script_type))

    @field('address')
    @expect(proto.EthereumAddress)
    def ethereum_get_address(self, n, show_display=False, multisig=None):
        n = self._convert_prime(n)
        return self.call(proto.EthereumGetAddress(address_n=n, show_display=show_display))

    @session
    def ethereum_sign_tx(self, n, nonce, gas_price, gas_limit, value, to=None, to_n=None, address_type=None, exchange_type=None, data=None, chain_id=None, token_shortcut=None, token_value=None, token_to=None):
        from keepkeylib.tools import int_to_big_endian

        n = self._convert_prime(n)
        if address_type == types.TRANSFER:   #Ethereum transfer transaction
            msg = proto.EthereumSignTx(
                address_n=n,
                nonce=int_to_big_endian(nonce),
                gas_price=int_to_big_endian(gas_price),
                gas_limit=int_to_big_endian(gas_limit),
                value=int_to_big_endian(value),
                to_address_n=to_n,
                address_type=address_type
                )
        elif address_type == types.EXCHANGE and token_to is None:   #Ethereum exchange transaction
            msg = proto.EthereumSignTx(
                address_n=n,
                nonce=int_to_big_endian(nonce),
                gas_price=int_to_big_endian(gas_price),
                gas_limit=int_to_big_endian(gas_limit),
                value=int_to_big_endian(value),
                to_address_n=to_n,
                exchange_type=exchange_type,
                address_type=address_type
                )
        elif address_type == types.EXCHANGE and token_to is not None:
            msg = proto.EthereumSignTx(
                address_n=n,
                nonce=int_to_big_endian(nonce),
                gas_price=int_to_big_endian(gas_price),
                gas_limit=int_to_big_endian(gas_limit),
                value=int_to_big_endian(value),
                to_address_n=to_n,
                exchange_type=exchange_type,
                address_type=address_type,
                token_value=token_value,
                token_to=token_to,
                token_shortcut=token_shortcut,
                )
        else:
            if token_shortcut is None:
                msg = proto.EthereumSignTx(
                    address_n=n,
                    nonce=int_to_big_endian(nonce),
                    gas_price=int_to_big_endian(gas_price),
                    gas_limit=int_to_big_endian(gas_limit),
                    value=int_to_big_endian(value)
                    )
            else:
                #erc20 token transfer
                value_array = bytearray([0]*32)
                for ii,i in enumerate(int_to_big_endian(token_value)[::-1]):
                    value_array[31 - ii] = i
                msg = proto.EthereumSignTx(
                    address_n=n,
                    nonce=int_to_big_endian(nonce),
                    gas_price=int_to_big_endian(gas_price),
                    gas_limit=int_to_big_endian(gas_limit),
                    token_value=bytes(value_array),
                    token_to=token_to,
                    token_shortcut=token_shortcut,
                    )


        if to:
            msg.to = to

        if data:
            msg.data_length = len(data)
            data, chunk = data[1024:], data[:1024]
            msg.data_initial_chunk = chunk

        if chain_id:
            msg.chain_id = chain_id

        response = self.call(msg)

        while response.HasField('data_length'):
            data_length = response.data_length
            data, chunk = data[data_length:], data[:data_length]
            response = self.call(proto.EthereumTxAck(data_chunk=chunk))

        if address_type:
            return response.signature_v, response.signature_r, response.signature_s, response.hash, response.signature_der
        else:
            return response.signature_v, response.signature_r, response.signature_s

    @expect(eos_proto.EosPublicKey)
    def eos_get_public_key(self, address_n, show_display=True, legacy=True):
        msg = eos_proto.EosGetPublicKey(
            address_n=address_n,
            show_display=show_display,
            kind = eos_proto.EOS if legacy else eos_proto.EOS_K1
            )
        return self.call(msg)

    @session
    def eos_sign_tx_raw(self, msg, actions):
        response = self.call(msg)

        for common, action in actions:
            if isinstance(action, eos_proto.EosActionTransfer):
                msg = eos_proto.EosTxActionAck(common=common, transfer=action)
            elif isinstance(action, eos_proto.EosActionDelegate):
                msg = eos_proto.EosTxActionAck(common=common, delegate=action)
            elif isinstance(action, eos_proto.EosActionUndelegate):
                msg = eos_proto.EosTxActionAck(common=common, undelegate=action)
            elif isinstance(action, eos_proto.EosActionRefund):
                msg = eos_proto.EosTxActionAck(common=common, refund=action)
            elif isinstance(action, eos_proto.EosActionBuyRam):
                msg = eos_proto.EosTxActionAck(common=common, buy_ram=action)
            elif isinstance(action, eos_proto.EosActionBuyRamBytes):
                msg = eos_proto.EosTxActionAck(common=common, buy_ram_bytes=action)
            elif isinstance(action, eos_proto.EosActionSellRam):
                msg = eos_proto.EosTxActionAck(common=common, sell_ram=action)
            elif isinstance(action, eos_proto.EosActionVoteProducer):
                msg = eos_proto.EosTxActionAck(common=common, vote_producer=action)
            elif isinstance(action, eos_proto.EosActionUpdateAuth):
                msg = eos_proto.EosTxActionAck(common=common, update_auth=action)
            elif isinstance(action, eos_proto.EosActionDeleteAuth):
                msg = eos_proto.EosTxActionAck(common=common, delete_auth=action)
            elif isinstance(action, eos_proto.EosActionUnlinkAuth):
                msg = eos_proto.EosTxActionAck(common=common, unlink_auth=action)
            elif isinstance(action, eos_proto.EosActionLinkAuth):
                msg = eos_proto.EosTxActionAck(common=common, link_auth=action)
            elif isinstance(action, eos_proto.EosActionNewAccount):
                msg = eos_proto.EosTxActionAck(common=common, new_account=action)
            elif isinstance(action, eos_proto.EosActionUnknown):
                msg = eos_proto.EosTxActionAck(common=common, unknown=action)
            else:
                raise Exception("Unknown EOS Action")

            response = self.call(msg)

        if not isinstance(response, eos_proto.EosSignedTx):
            raise Exception("Unexpected EOS signing response")

        return response

    @session
    def eos_sign_tx(self, n, transaction):
        tx = eos.parse_transaction_json(copy.deepcopy(transaction))

        header = eos_proto.EosTxHeader(
            expiration=tx.expiration,
            ref_block_num=tx.ref_block_num,
            ref_block_prefix=tx.ref_block_prefix,
            max_net_usage_words=tx.net_usage_words,
            max_cpu_usage_ms=tx.max_cpu_usage_ms,
            delay_sec=tx.delay_sec)

        msg = eos_proto.EosSignTx(
            address_n=n,
            chain_id=tx.chain_id,
            header=header,
            num_actions=tx.num_actions)

        response = self.call(msg)

        try:
            while isinstance(response, eos_proto.EosTxActionRequest):
                a = eos.parse_action(tx.actions.pop(0))
                if isinstance(a, list):
                    while len(a) and isinstance(response, eos_proto.EosTxActionRequest):
                        response = self.call(a.pop(0))
                else:
                    response = self.call(a)
        except IndexError:
            # pop from empty list
            raise Exception("Unexpected EOS signing response")

        if not isinstance(response, eos_proto.EosSignedTx):
            raise Exception("Unexpected EOS signing response")

        return response

    @expect(nano_proto.NanoAddress)
    def nano_get_address(self, coin_name, address_n, show_display=False):
        msg = nano_proto.NanoGetAddress(
            coin_name=coin_name,
            address_n=address_n,
            show_display=show_display)
        return self.call(msg)

    @expect(nano_proto.NanoSignedTx)
    def nano_sign_tx(
        self, coin_name, address_n,
        grandparent_hash=None,
        parent_link=None,
        parent_representative=None,
        parent_balance=None,
        link_hash=None,
        link_recipient=None,
        link_recipient_n=None,
        representative=None,
        balance=None,
    ):
        parent_block = None
        if (grandparent_hash is not None or
               parent_link is not None or
               parent_representative is not None or
               parent_balance is not None):
            parent_block = nano_proto.NanoSignTx.ParentBlock(
                parent_hash=grandparent_hash,
                link=parent_link,
                representative=parent_representative,
                balance=nano.encode_balance(parent_balance),
            )

        msg = nano_proto.NanoSignTx(
            coin_name=coin_name,
            address_n=address_n,
            parent_block=parent_block,
            link_hash=link_hash,
            link_recipient=link_recipient,
            link_recipient_n=link_recipient_n,
            representative=representative,
            balance=nano.encode_balance(balance),
        )
        return self.call(msg)

    @field('address')
    @expect(cosmos_proto.CosmosAddress)
    def cosmos_get_address(self, address_n, show_display=False):
        return self.call(
            cosmos_proto.CosmosGetAddress(address_n=address_n, show_display=show_display)
        )

    def cosmos_sign_tx(
        self,
        address_n,
        account_number,
        chain_id,
        fee,
        gas,
        msgs,
        memo,
        sequence,
        exchange_types=None
    ):
        resp = self.call(cosmos_proto.CosmosSignTx(
            address_n=address_n,
            account_number=account_number,
            chain_id=chain_id,
            fee_amount=fee,
            gas=gas,
            memo=memo,
            sequence=sequence,
            msg_count=len(msgs)
        ))

        for (msg, exchange_type) in zip(msgs, exchange_types or [None] * len(msgs)):
            if not isinstance(resp, cosmos_proto.CosmosMsgRequest):
                raise CallException(
                    "Cosmos.ExpectedMsgRequest",
                    "Message request expected but not received.",
                )

            if msg['type'] == "cosmos-sdk/MsgSend":
                if len(msg['value']['amount']) != 1:
                    raise CallException("Cosmos.MsgSend", "Multiple amounts per msg not supported")

                denom = msg['value']['amount'][0]['denom']
                if denom != 'uatom':
                    raise CallException("Cosmos.MsgSend", "Unsupported denomination: " + denom)

                resp = self.call(cosmos_proto.CosmosMsgAck(
                    send=cosmos_proto.CosmosMsgSend(
                        from_address=msg['value']['from_address'],
                        to_address=msg['value']['to_address'],
                        amount=long(msg['value']['amount'][0]['amount']),
                        address_type=types.EXCHANGE if exchange_type is not None else types.SPEND,
                        exchange_type=exchange_type
                    )
                ))
            else:
                raise CallException(
                    "Cosmos.UnknownMsg",
                    "Cosmos message %s is not yet supported" % (msg['type'],)
                )

        if not isinstance(resp, cosmos_proto.CosmosSignedTx):
            raise CallException(
                "Cosmos.UnexpectedEndOfOperations",
                "Reached end of operations without a signature.",
            )

        return resp


    @field('entropy')
    @expect(proto.Entropy)
    def get_entropy(self, size):
        return self.call(proto.GetEntropy(size=size))

    @field('message')
    @expect(proto.Success)
    def ping(self, msg, button_protection=False, pin_protection=False, passphrase_protection=False):
        msg = proto.Ping(message=msg,
                         button_protection=button_protection,
                         pin_protection=pin_protection,
                         passphrase_protection=passphrase_protection)
        return self.call(msg)

    def get_device_id(self):
        return self.features.device_id

    @field('message')
    @expect(proto.Success)
    def apply_settings(self, label=None, language=None, use_passphrase=None, homescreen=None):
        settings = proto.ApplySettings()
        if label != None:
            settings.label = label
        if language:
            settings.language = language
        if use_passphrase != None:
            settings.use_passphrase = use_passphrase

        out = self.call(settings)
        self.init_device()  # Reload Features
        return out

    @field('message')
    @expect(proto.Success)
    def apply_policy(self, policy_name, enabled):
        policy = types.PolicyType(policy_name=policy_name, enabled=enabled)
        apply_policies = proto.ApplyPolicies(policy=[policy])

        out = self.call(apply_policies)
        self.init_device()  # Reload Features
        return out

    @field('message')
    @expect(proto.Success)
    def clear_session(self):
        return self.call(proto.ClearSession())

    @field('message')
    @expect(proto.Success)
    def change_pin(self, remove=False):
        ret = self.call(proto.ChangePin(remove=remove))
        self.init_device()  # Re-read features
        return ret

    @expect(proto.MessageSignature)
    def sign_message(self, coin_name, n, message, script_type=types.SPENDADDRESS):
        n = self._convert_prime(n)
        # Convert message to UTF8 NFC (seems to be a bitcoin-qt standard)
        message = normalize_nfc(message).encode("utf-8")
        return self.call(proto.SignMessage(coin_name=coin_name, address_n=n, message=message, script_type=script_type))

    @expect(proto.SignedIdentity)
    def sign_identity(self, identity, challenge_hidden, challenge_visual, ecdsa_curve_name=DEFAULT_CURVE):
        return self.call(proto.SignIdentity(identity=identity, challenge_hidden=challenge_hidden, challenge_visual=challenge_visual, ecdsa_curve_name=ecdsa_curve_name))


    def verify_message(self, coin_name, address, signature, message):
        # Convert message to UTF8 NFC (seems to be a bitcoin-qt standard)
        message = normalize_nfc(message).encode("utf-8")
        try:
            resp = self.call(proto.VerifyMessage(address=address, signature=signature, message=message, coin_name=coin_name))
        except CallException as e:
            resp = e
        if isinstance(resp, proto.Success):
            return True
        return False

    @field('value')
    @expect(proto.CipheredKeyValue)
    def encrypt_keyvalue(self, n, key, value, ask_on_encrypt=True, ask_on_decrypt=True, iv=b''):
        n = self._convert_prime(n)
        return self.call(proto.CipherKeyValue(address_n=n,
                                              key=key,
                                              value=value,
                                              encrypt=True,
                                              ask_on_encrypt=ask_on_encrypt,
                                              ask_on_decrypt=ask_on_decrypt,
                                              iv=iv))

    @field('value')
    @expect(proto.CipheredKeyValue)
    def decrypt_keyvalue(self, n, key, value, ask_on_encrypt=True, ask_on_decrypt=True, iv=b''):
        n = self._convert_prime(n)
        return self.call(proto.CipherKeyValue(address_n=n,
                                              key=key,
                                              value=value,
                                              encrypt=False,
                                              ask_on_encrypt=ask_on_encrypt,
                                              ask_on_decrypt=ask_on_decrypt,
                                              iv=iv))

    def _prepare_sign_tx(self, coin_name, inputs, outputs):
        tx = types.TransactionType()
        tx.inputs.extend(inputs)
        tx.outputs.extend(outputs)

        txes = {None: tx}
        txes[b''] = tx

        force_bip143 = ['BitcoinGold', 'BitcoinCash', 'BitcoinSV']
        if coin_name in force_bip143:
            return txes

        known_hashes = []
        for inp in inputs:
            if inp.prev_hash in txes:
                continue

            if inp.script_type in (types.SPENDP2SHWITNESS,
                                   types.SPENDWITNESS):
                continue

            if not self.tx_api:
                raise Exception('TX_API not defined')

            prev_tx = self.tx_api.get_tx(binascii.hexlify(inp.prev_hash).decode('utf-8'))
            txes[inp.prev_hash] = prev_tx

        return txes

    @session
    def sign_tx(self, coin_name, inputs, outputs, version=None, lock_time=None, debug_processor=None):

        start = time.time()
        txes = self._prepare_sign_tx(coin_name, inputs, outputs)

        # Prepare and send initial message
        tx = proto.SignTx()
        tx.inputs_count = len(inputs)
        tx.outputs_count = len(outputs)
        tx.coin_name = coin_name
        if version is not None:
            tx.version = version
        if lock_time is not None:
            tx.lock_time = lock_time
        res = self.call(tx)

        # Prepare structure for signatures
        signatures = [None] * len(inputs)
        serialized_tx = b''

        counter = 0
        while True:
            counter += 1

            if isinstance(res, proto.Failure):
                raise CallException("Signing failed")

            if not isinstance(res, proto.TxRequest):
                raise CallException("Unexpected message")

            # If there's some part of signed transaction, let's add it
            if res.HasField('serialized') and res.serialized.HasField('serialized_tx'):
                if self.verbose:
                    log("RECEIVED PART OF SERIALIZED TX (%d BYTES)" % len(res.serialized.serialized_tx))
                serialized_tx += res.serialized.serialized_tx

            if res.HasField('serialized') and res.serialized.HasField('signature_index'):
                if signatures[res.serialized.signature_index] != None:
                    raise Exception("Signature for index %d already filled" % res.serialized.signature_index)
                signatures[res.serialized.signature_index] = res.serialized.signature

            if res.request_type == types.TXFINISHED:
                # Device didn't ask for more information, finish workflow
                break

            # Device asked for one more information, let's process it.
            if not res.details.tx_hash:
                current_tx = txes[None]
            else:
                current_tx = txes[bytes(res.details.tx_hash)]

            if res.request_type == types.TXMETA:
                msg = types.TransactionType()
                msg.version = current_tx.version
                msg.lock_time = current_tx.lock_time
                msg.inputs_cnt = len(current_tx.inputs)
                if res.details.tx_hash:
                    msg.outputs_cnt = len(current_tx.bin_outputs)
                else:
                    msg.outputs_cnt = len(current_tx.outputs)
                msg.extra_data_len = len(current_tx.extra_data) if current_tx.extra_data else 0
                res = self.call(proto.TxAck(tx=msg))
                continue

            elif res.request_type == types.TXINPUT:
                msg = types.TransactionType()
                msg.inputs.extend([current_tx.inputs[res.details.request_index], ])
                if debug_processor is not None:
                    # msg needs to be deep copied so when it's modified
                    # the other messages stay intact
                    from copy import deepcopy
                    msg = deepcopy(msg)
                    # If debug_processor function is provided,
                    # pass thru it the request and prepared response.
                    # This is useful for tests, see test_msg_signtx
                    msg = debug_processor(res, msg)
                res = self.call(proto.TxAck(tx=msg))
                continue

            elif res.request_type == types.TXOUTPUT:
                msg = types.TransactionType()
                if res.details.tx_hash:
                    msg.bin_outputs.extend([current_tx.bin_outputs[res.details.request_index], ])
                else:
                    msg.outputs.extend([current_tx.outputs[res.details.request_index], ])

                if debug_processor != None:
                    # msg needs to be deep copied so when it's modified
                    # the other messages stay intact
                    from copy import deepcopy
                    msg = deepcopy(msg)
                    # If debug_processor function is provided,
                    # pass thru it the request and prepared response.
                    # This is useful for tests, see test_msg_signtx
                    msg = debug_processor(res, msg)

                res = self.call(proto.TxAck(tx=msg))
                continue

            elif res.request_type == types.TXEXTRADATA:
                o, l = res.details.extra_data_offset, res.details.extra_data_len
                msg = types.TransactionType()
                msg.extra_data = current_tx.extra_data[o:o + l]
                res = self.call(proto.TxAck(tx=msg))
                continue

        if None in signatures:
            raise Exception("Some signatures are missing!")

        if self.verbose:
            log("SIGNED IN %.03f SECONDS, CALLED %d MESSAGES, %d BYTES" % \
                (time.time() - start, counter, len(serialized_tx)))

        return (signatures, serialized_tx)

    @field('message')
    @expect(proto.Success)
    def wipe_device(self):
        ret = self.call(proto.WipeDevice())
        self.init_device()
        return ret

    @field('message')
    @expect(proto.Success)
    def recovery_device(self, use_trezor_method, word_count, passphrase_protection, pin_protection, label, language):
        if self.features.initialized:
            raise Exception("Device is initialized already. Call wipe_device() and try again.")
        if use_trezor_method:
            raise Exception("Trezor-style recovery is no longer supported")
        elif word_count not in (12, 18, 24):
            raise Exception("Invalid word count. Use 12/18/24")

        res = self.call(proto.RecoveryDevice(word_count=int(word_count),
                                    passphrase_protection=bool(passphrase_protection),
                                    pin_protection=bool(pin_protection),
                                    label=label,
                                    language=language,
                                    enforce_wordlist=True,
                                    use_character_cipher=True))

        self.init_device()
        return res

    @field('message')
    @expect(proto.Success)
    @session
    def reset_device(self, display_random, strength, passphrase_protection, pin_protection, label, language):
        if self.features.initialized:
            raise Exception("Device is initialized already. Call wipe_device() and try again.")

        # Begin with device reset workflow
        msg = proto.ResetDevice(display_random=display_random,
                                strength=strength,
                                language=language,
                                passphrase_protection=bool(passphrase_protection),
                                pin_protection=bool(pin_protection),
                                label=label)

        resp = self.call(msg)
        if not isinstance(resp, proto.EntropyRequest):
            raise Exception("Invalid response, expected EntropyRequest")

        external_entropy = self._get_local_entropy()
        if self.verbose:
            log("Computer generated entropy: " + binascii.hexlify(external_entropy).decode('ascii'))
        ret = self.call(proto.EntropyAck(entropy=external_entropy))
        self.init_device()
        return ret

    @field('message')
    @expect(proto.Success)
    def load_device_by_mnemonic(self, mnemonic, pin, passphrase_protection, label, language, skip_checksum=False):
        m = Mnemonic('english')
        if not skip_checksum and not m.check(mnemonic):
            raise Exception("Invalid mnemonic checksum")

        # Convert mnemonic to UTF8 NKFD
        mnemonic = Mnemonic.normalize_string(mnemonic)

        # Convert mnemonic to ASCII stream
        mnemonic = normalize_nfc(mnemonic)

        if self.features.initialized:
            raise Exception("Device is initialized already. Call wipe_device() and try again.")

        resp = self.call(proto.LoadDevice(mnemonic=mnemonic, pin=pin,
                                          passphrase_protection=passphrase_protection,
                                          language=language,
                                          label=label,
                                          skip_checksum=skip_checksum))
        self.init_device()
        return resp

    @field('message')
    @expect(proto.Success)
    def load_device_by_xprv(self, xprv, pin, passphrase_protection, label, language):
        if self.features.initialized:
            raise Exception("Device is initialized already. Call wipe_device() and try again.")

        if xprv[0:4] not in ('xprv', 'tprv'):
            raise Exception("Unknown type of xprv")

        if len(xprv) < 100 and len(xprv) > 112:
            raise Exception("Invalid length of xprv")

        node = types.HDNodeType()
        data = binascii.hexlify(tools.b58decode(xprv, None))

        if data[90:92] != b'00':
            raise Exception("Contain invalid private key")

        checksum = binascii.hexlify(hashlib.sha256(hashlib.sha256(binascii.unhexlify(data[:156])).digest()).digest()[:4])
        if checksum != data[156:]:
            raise Exception("Checksum doesn't match")

        # version 0488ade4
        # depth 00
        # fingerprint 00000000
        # child_num 00000000
        # chaincode 873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508
        # privkey   00e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35
        # checksum e77e9d71

        node.depth = int(data[8:10], 16)
        node.fingerprint = int(data[10:18], 16)
        node.child_num = int(data[18:26], 16)
        node.chain_code = binascii.unhexlify(data[26:90])
        node.private_key = binascii.unhexlify(data[92:156])  # skip 0x00 indicating privkey

        resp = self.call(proto.LoadDevice(node=node,
                                          pin=pin,
                                          passphrase_protection=passphrase_protection,
                                          language=language,
                                          label=label))
        self.init_device()
        return resp

    def firmware_update(self, fp):
        if self.features.bootloader_mode == False:
            raise Exception("Device must be in bootloader mode")

        resp = self.call(proto.FirmwareErase())
        if isinstance(resp, proto.Failure) and resp.code == types.Failure_FirmwareError:
            return False

        data = fp.read()
        data_hash = hashlib.sha256(data).digest()

        resp = self.call(proto.FirmwareUpload(payload_hash=data_hash, payload=data))

        if isinstance(resp, proto.Success):
            return True

        elif isinstance(resp, proto.Failure) and resp.code == types.Failure_FirmwareError:
            return False

        raise Exception("Unexpected result %s" % resp)

class KeepKeyClient(ProtocolMixin, TextUIMixin, BaseClient):
    pass

class KeepKeyClientVerbose(ProtocolMixin, TextUIMixin, DebugWireMixin, BaseClient):
    pass

class KeepKeyDebuglinkClient(ProtocolMixin, DebugLinkMixin, BaseClient):
    pass

class KeepKeyDebuglinkClientVerbose(ProtocolMixin, DebugLinkMixin, DebugWireMixin, BaseClient):
    pass
