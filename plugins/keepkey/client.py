from keepkeylib.client import proto, BaseClient, ProtocolMixin
from ..trezor.clientbase import TrezorClientBase

class KeepKeyClient(TrezorClientBase, ProtocolMixin, BaseClient):
    def __init__(self, transport, handler, plugin):
        BaseClient.__init__(self, transport)
        ProtocolMixin.__init__(self, transport)
        TrezorClientBase.__init__(self, handler, plugin, proto)

    def recovery_device(self, *args):
        ProtocolMixin.recovery_device(self, False, *args)


TrezorClientBase.wrap_methods(KeepKeyClient)
