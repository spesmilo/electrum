from __future__ import print_function

from . import messages_pb2 as proto
from .transport import NotImplementedException

def pin_info(pin, verbose):
    if verbose:
        print("Device asks for PIN %s" % pin)

def button_press(yes_no, verbose):
    if verbose:
        print("User pressed", '"y"' if yes_no else '"n"')

def pprint(msg):
    return "<%s> (%d bytes):\n%s" % (msg.__class__.__name__, msg.ByteSize(), msg)

class DebugLink(object):
    def __init__(self, transport, pin_func=pin_info, button_func=button_press):
        self.transport = transport
        self.verbose = False

        self.pin_func = pin_func
        self.button_func = button_func

    def log(self, what, why):
        if self.verbose:
            self.log(what, why)

    def close(self):
        self.transport.close()

    def _call(self, msg, nowait=False):
        self.log("DEBUGLINK SEND", pprint(msg))
        self.transport.write(msg)
        if nowait:
            return
        ret = self.transport.read_blocking()
        self.log("DEBUGLINK RECV", pprint(ret))
        return ret

    def read_pin(self):
        obj = self._call(proto.DebugLinkGetState())
        self.log("Read PIN:", obj.pin)
        self.log("Read matrix:", obj.matrix)

        return (obj.pin, obj.matrix)

    def read_pin_encoded(self):
        pin, _ = self.read_pin()
        pin_encoded = self.encode_pin(pin)
        self.pin_func(pin_encoded, self.verbose)
        return pin_encoded

    def encode_pin(self, pin):
        _, matrix = self.read_pin()

        # Now we have real PIN and PIN matrix.
        # We have to encode that into encoded pin,
        # because application must send back positions
        # on keypad, not a real PIN.
        pin_encoded = ''.join([str(matrix.index(p) + 1) for p in pin])

        self.log("Encoded PIN:", pin_encoded)
        return pin_encoded

    def read_layout(self):
        obj = self._call(proto.DebugLinkGetState())
        return obj.layout

    def read_mnemonic(self):
        obj = self._call(proto.DebugLinkGetState())
        return obj.mnemonic

    def read_node(self):
        obj = self._call(proto.DebugLinkGetState())
        return obj.node

    def read_recovery_word(self):
        obj = self._call(proto.DebugLinkGetState())
        return (obj.recovery_fake_word, obj.recovery_word_pos)

    def read_reset_word(self):
        obj = self._call(proto.DebugLinkGetState())
        return obj.reset_word

    def read_reset_entropy(self):
        obj = self._call(proto.DebugLinkGetState())
        return obj.reset_entropy

    def read_passphrase_protection(self):
        obj = self._call(proto.DebugLinkGetState())
        return obj.passphrase_protection

    def read_recovery_cipher(self):
        obj = self._call(proto.DebugLinkGetState())
        return obj.recovery_cipher

    def read_recovery_auto_completed_word(self):
        obj = self._call(proto.DebugLinkGetState())
        return obj.recovery_auto_completed_word

    def read_memory_hashes(self):
        obj = self._call(proto.DebugLinkGetState())
        return (obj.firmware_hash, obj.storage_hash)

    def fill_config(self):
         self._call(proto.DebugLinkFillConfig(), nowait=True)

    def press_button(self, yes_no):
        self.log("Pressing", yes_no)
        self.button_func(yes_no, self.verbose)
        self._call(proto.DebugLinkDecision(yes_no=yes_no), nowait=True)

    def press_yes(self):
        self.press_button(True)

    def press_no(self):
        self.press_button(False)

    def stop(self):
        self._call(proto.DebugLinkStop(), nowait=True)
