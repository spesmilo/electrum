#!/usr/bin/python

from electrum.plugin import hook, BasePlugin
from electrum.transaction import PartialTransaction, PartialTxInput, PartialTxOutput

class Deniability(BasePlugin):
    def __init__(self, parent, config, name):
        BasePlugin.__init__(self, parent, config, name)
        self.budget = float(self.config.get('deniability_budget', 0))
        self.rounded_budget = round(self.budget, 2)

    def check_utxos(self, wallet):

        utxos = []
        for utxo in wallet.get_utxos():
            utxos.append(float(self.config.format_amount(utxo.value_sats())))

        if all(x < self.budget for x in utxos):
            raise Exception("Error: None of the UTXOs are greater than the deniability budget.")

    def create_tx(self, wallet):

        # Select the UTXO to use as input
        for utxo in wallet.get_utxos():
            if float(self.config.format_amount(utxo.value_sats())) > self.budget:
                selected_utxo = utxo
                break

        # Create the input for the transaction
        prevout = selected_utxo.prevout
        txin = PartialTxInput(prevout=prevout)
        txin._trusted_value_sats = selected_utxo.value_sats()

        # Create new addressesa
        address1 = wallet.create_new_address()
        address2 = wallet.create_new_address()

        # Create outputs for the transaction
        outputs = [
            (address1, int(self.rounded_budget*100000000)),
            (address2, 0)
        ]
        txout = [PartialTxOutput.from_address_and_value(address, int(amount_btc)) for address, amount_btc in outputs]

        # Create the partial transaction
        tx = PartialTransaction.from_io([txin], txout)

        # Calculate fee
        fee = 1.5*tx.estimated_size()

        # Update the transaction based on fee

        outputs[1] = (address2, selected_utxo.value_sats() - int(self.rounded_budget*100000000) - fee)
        txout = [PartialTxOutput.from_address_and_value(address, int(amount_btc)) for address, amount_btc in outputs]

        self.tx = PartialTransaction.from_io([txin], txout)

        return self.tx

    def sign_tx(self, wallet):

        self.signed_tx = wallet.sign_transaction(self.tx, None)

        self.signed_tx_hex = self.signed_tx.serialize()

        return self.signed_tx

    @hook
    def load_wallet(self, wallet, window):

        self.check_utxos(wallet)

        self.create_tx(wallet)

        self.sign_tx(wallet)