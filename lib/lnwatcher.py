from .util import PrintError
from .lnutil import funding_output_script
from .bitcoin import redeem_script_to_address

class LNWatcher(PrintError):

    def __init__(self, network):
        self.network = network
        self.watched_channels = {}

    def parse_response(self, response):
        if response.get('error'):
            self.print_error("response error:", response)
            return None, None
        return response['params'], response['result']

    def watch_channel(self, chan, callback):
        script = funding_output_script(chan.local_config, chan.remote_config)
        funding_address = redeem_script_to_address('p2wsh', script)
        self.watched_channels[funding_address] = chan, callback
        self.network.subscribe_to_addresses([funding_address], self.on_address_status)

    def on_address_status(self, response):
        params, result = self.parse_response(response)
        if not params:
            return
        addr = params[0]
        self.network.request_address_utxos(addr, self.on_utxos)

    def on_utxos(self, response):
        params, result = self.parse_response(response)
        if not params:
            return
        addr = params[0]
        chan, callback = self.watched_channels[addr]
        callback(chan, result)
