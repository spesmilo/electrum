import time
from struct import pack

from electrum import ecc
from electrum.i18n import _
from electrum.util import UserCancelled
from electrum.keystore import bip39_normalize_passphrase
from electrum.bip32 import BIP32Node, convert_bip32_path_to_list_of_uint32
from electrum.logging import Logger


class GuiMixin(object):
    # Requires: self.proto, self.device

    def callback_Failure(self, msg):
        # BaseClient's unfortunate call() implementation forces us to
        # raise exceptions on failure in order to unwind the stack.
        # However, making the user acknowledge they cancelled
        # gets old very quickly, so we suppress those.  The NotInitialized
        # one is misnamed and indicates a passphrase request was cancelled.
        if msg.code in (self.types.FailureType.PinCancelled,
                        self.types.FailureType.ActionCancelled,
                        self.types.FailureType.NotInitialized):
            raise UserCancelled()
        raise RuntimeError(msg.message)


class HideezClientBase(GuiMixin, Logger):

    def __init__(self, handler, plugin, proto):
        assert hasattr(self, 'tx_api')  # ProtocolMixin already constructed?
        self.proto = proto
        self.device = plugin.device
        self.handler = handler
        self.tx_api = plugin
        self.types = plugin.types
        self.msg = None
        self.creating_wallet = False
        Logger.__init__(self)
        self.used()

    def __str__(self):
        return "%s/%s" % (self.label(), self.features.device_id)

    def label(self):
        '''The name given by the user to the device.'''
        return self.features.label

    def is_initialized(self):
        '''True if initialized, False if wiped.'''
        return self.features.initialized

    def is_pairable(self):
        return not self.features.bootloader_mode

    def has_usable_connection_with_device(self):
        try:
            res = self.ping("electrum pinging device")
            assert res == "electrum pinging device"
        except BaseException:
            return False
        return True

    def used(self):
        self.last_operation = time.time()

    def prevent_timeouts(self):
        self.last_operation = float('inf')

    def timeout(self, cutoff):
        '''Time out the client if the last operation was before cutoff.'''
        if self.last_operation < cutoff:
            self.logger.info("timed out")
            self.clear_session()

    @staticmethod
    def expand_path(n):
        return convert_bip32_path_to_list_of_uint32(n)

    def cancel(self):
        '''Provided here as in keepkeylib but not trezorlib.'''
        self.transport.write(self.proto.Cancel())

    def i4b(self, x):
        return pack('>I', x)

    def get_xpub(self, bip32_path, xtype):
        address_n = self.expand_path(bip32_path)
        creating = False
        node = self.get_public_node(address_n, creating).node
        return BIP32Node(xtype=xtype,
                         eckey=ecc.ECPubkey(node.public_key),
                         chaincode=node.chain_code,
                         depth=node.depth,
                         fingerprint=self.i4b(node.fingerprint),
                         child_number=self.i4b(node.child_num)).to_xpub()

    def clear_session(self):
        '''Clear the session to force pin (and passphrase if enabled)
        re-entry.  Does not leak exceptions.'''
        self.logger.info(f"clear session: {self}")
        self.prevent_timeouts()
        try:
            super(HideezClientBase, self).clear_session()
        except BaseException as e:
            # If the device was removed it has the same effect...
            self.logger.info(f"clear_session: ignoring error {e}")

    def get_public_node(self, address_n, creating):
        self.creating_wallet = creating
        return super(HideezClientBase, self).get_public_node(address_n)

    def close(self):
        '''Called when Our wallet was closed or the device removed.'''
        self.logger.info("closing client")
        self.clear_session()
        # Release the device
        self.transport.close()

    def firmware_version(self):
        f = self.features
        return (f.major_version, f.minor_version, f.patch_version)

    def atleast_version(self, major, minor=0, patch=0):
        return self.firmware_version() >= (major, minor, patch)

    @staticmethod
    def wrapper(func):
        '''Wrap methods to clear any message box they opened.'''

        def wrapped(self, *args, **kwargs):
            try:
                self.prevent_timeouts()
                return func(self, *args, **kwargs)
            finally:
                self.used()
                self.handler.finished()
                self.creating_wallet = False
                self.msg = None

        return wrapped

    @staticmethod
    def wrap_methods(cls):
        for method in ['get_address', 'get_public_node',
                       'sign_message', 'sign_tx']:
            setattr(cls, method, cls.wrapper(getattr(cls, method)))
