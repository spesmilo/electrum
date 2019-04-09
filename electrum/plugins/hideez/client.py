from hideezlib.client import proto, BaseClient, ProtocolMixin
from .clientbase import HideezClientBase


class HideezClient(HideezClientBase, ProtocolMixin, BaseClient):
    def __init__(self, transport, handler, plugin):
        BaseClient.__init__(self, transport=transport)
        ProtocolMixin.__init__(self, transport=transport)
        HideezClientBase.__init__(self, handler, plugin, proto)


HideezClientBase.wrap_methods(HideezClient)
