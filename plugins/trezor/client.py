from trezorlib.client import proto, BaseClient, ProtocolMixin
from clientbase import TrezorClientBase

class TrezorClient(TrezorClientBase, ProtocolMixin, BaseClient):
    def __init__(self, transport, handler, plugin, hid_id):
        TrezorClientBase.__init__(self, handler, plugin, hid_id, proto)
        BaseClient.__init__(self, transport)
        ProtocolMixin.__init__(self, transport)


TrezorClientBase.wrap_methods(TrezorClient)
