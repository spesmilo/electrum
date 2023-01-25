#!/usr/bin/python

from electrum.plugin import hook, BasePlugin

class Deniability(BasePlugin):
    def __init__(self, parent, config, name):
        BasePlugin.__init__(self, parent, config, name)

    @hook
    def load_wallet(self, wallet, window):
        budget = float(self.config.get('deniability_budget', 0))

        self.wallet = window.wallet
        utxos = []
        for utxo in self.wallet.get_utxos():
            utxos.append(float(self.config.format_amount(utxo.value_sats())))

        if all(x < budget for x in utxos):
            raise Exception("Error: None of the UTXOs are greater than the deniability budget.")