from keepkeylib.client import proto, BaseClient, ProtocolMixin
from .clientbase import KeepKeyClientBase

class KeepKeyClient(KeepKeyClientBase, ProtocolMixin, BaseClient):
    def __init__(self, transport, handler, plugin):
        BaseClient.__init__(self, transport)
        ProtocolMixin.__init__(self, transport)
        KeepKeyClientBase.__init__(self, handler, plugin, proto)

    def recovery_device(self, *args):
        ProtocolMixin.recovery_device(self, False, *args)


KeepKeyClientBase.wrap_methods(KeepKeyClient)
