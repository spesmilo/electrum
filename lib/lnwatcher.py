from .util import PrintError
from .lnbase import Outpoint, funding_output_script
from .bitcoin import redeem_script_to_address

class LNWatcher(PrintError):

    def __init__(self, network, channel_state):
        self.network = network
        self.channel_state = channel_state
        self.channels ={}

    def parse_response(self, response):
        if response.get('error'):
            self.print_error("response error:", response)
            return None, None
        return response['params'], response['result']

    def watch_channel(self, chan):
        script = funding_output_script(chan.local_config, chan.remote_config)
        funding_address = redeem_script_to_address('p2wsh', script)
        self.channels[funding_address] = chan
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
        chan = self.channels[addr]
        outpoints = [Outpoint(x["tx_hash"], x["tx_pos"]) for x in result]
        if chan.funding_outpoint not in outpoints:
            self.channel_state[chan.channel_id] = "CLOSED"
