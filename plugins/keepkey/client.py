from keepkeylib.client import proto, BaseClient, ProtocolMixin
from ..trezor.clientbase import TrezorClientBase

class KeepKeyClient(TrezorClientBase, ProtocolMixin, BaseClient):
    def __init__(self, transport, handler, plugin, hid_id):
        BaseClient.__init__(self, transport)
        ProtocolMixin.__init__(self, transport)
        TrezorClientBase.__init__(self, handler, plugin, hid_id, proto)

    def recovery_device(self, *args):
        ProtocolMixin.recovery_device(self, True, *args)


TrezorClientBase.wrap_methods(KeepKeyClient)
