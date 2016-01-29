from sys import stderr

from electrum.i18n import _
from electrum.util import PrintError

from btchip.btchipException import BTChipException

class DeviceLockedError(Exception):
    pass

def ledger_client_class(base_client):
    '''Returns a class dynamically.'''

    class LedgerDevice(base_client, PrintError):

        def __init__(self, transport, handler, plugin, hid_id):
            base_client.__init__(self, transport)
            self.transport = transport
            self.device = plugin.device
            self.handler = handler
            self.hid_id_ = hid_id
	    # Temporary fix
	    self.features = type('Dummy', (object,), { "bootloader_mode": "False" }) 

        def __str__(self):
            return "%s" % (self.hid_id())

        def label(self):
            return None

        def hid_id(self):
            '''The HID ID of the device.'''
            return self.hid_id_

        def is_initialized(self):
            '''True if initialized, False if wiped.'''
            try:
                self.getOperationMode()
            except BTChipException, e:
                if (e.sw == 0x6985):
                    return False
                elif (e.sw == 0x6FAA):
                    msg = "Dongle is temporarily locked - please unplug it and replug it again"
                    self.handler.show_error(msg)
                    raise DeviceLockedError(msg)
                else:
                    raise e
            return True

        def run_perso_wizard(self):
            from btchip.btchipPersoWizard import StartBTChipPersoDialog
            dialog = StartBTChipPersoDialog()
            dialog.exec_()

        # Copied from trezorlib/client.py as there it is not static, sigh
        @staticmethod
        def expand_path(n):
            '''Convert bip32 path to list of uint32 integers with prime flags
            0/-1/1' -> [0, 0x80000001, 0x80000001]'''
            path = []
            for x in n.split('/')[1:]:
                prime = 0
                if x.endswith("'"):
                    x = x.replace('\'', '')
                    prime = TrezorClient.PRIME_DERIVATION_FLAG
                if x.startswith('-'):
                    prime = TrezorClient.PRIME_DERIVATION_FLAG
                path.append(abs(int(x)) | prime)
            return path

        def first_address(self, derivation):
            return self.address_from_derivation(derivation)

        def address_from_derivation(self, derivation):
            splitPath = derivation.split('/')
            if splitPath[0] == 'm':
                splitPath = splitPath[1:]
            nodeData = self.getWalletPublicKey(splitPath)
            return nodeData['address']

        def close(self):
            '''Called when Our wallet was closed or the device removed.'''
            self.print_error("disconnected")
            # Release the device
            self.transport.close()

    def wrapper(func):
        '''Wrap base class methods to show exceptions and clear
        any dialog box it opened.'''

        def wrapped(self, *args, **kwargs):
            try:
                return func(self, *args, **kwargs)
            except BaseException as e:
                self.handler.show_error(str(e))
                raise e
            finally:
                self.handler.finished()

        return wrapped

    cls = LedgerDevice
    for method in ['getWalletPublicKey', 'signMessagePrepare',
                   'signMessageSign', 'getTrustedInput', 'startUntrustedTransaction',
                   'finalizeInput', 'untrustedHashSign']:
        setattr(cls, method, wrapper(getattr(cls, method)))

    return cls
