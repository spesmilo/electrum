#!/usr/bin/env bash
export HOME=~
set -eux pipefail
bitcoin-cli generatetoaddress 109 mwLZSJ2hUkvFoSkyadNGgmu9977w6K8wfj > /dev/null
sleep 30
othernode=$(./run_electrum --regtest -D /tmp/elec2 nodeid)
./run_electrum --regtest -D /tmp/elec1 open_channel $othernode 0.15
sleep 3
bitcoin-cli generatetoaddress 6 mwLZSJ2hUkvFoSkyadNGgmu9977w6K8wfj > /dev/null
sleep 12
invoice=$(./run_electrum --regtest -D /tmp/elec2 addinvoice 0.01 invoice_description)
timeout 5 ./run_electrum -D /tmp/elec1 --regtest lnpay $invoice || (cat screenlog*; exit 1)
bitcoin-cli sendrawtransaction $(cat /tmp/elec1/regtest/initial_commitment_tx)
# elec2 should take all funds because breach
sleep 12
bitcoin-cli generatetoaddress 2 mwLZSJ2hUkvFoSkyadNGgmu9977w6K8wfj > /dev/null
sleep 12
balance=$(./run_electrum --regtest -D /tmp/elec2 getbalance | jq '.confirmed | tonumber')
if (( $(echo "$balance < 0.14" | bc -l) )); then
    echo "balance of elec2 insufficient: $balance"
    exit 1
fi
