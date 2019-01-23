#!/usr/bin/env bash
export HOME=~
set -eux pipefail
bitcoin-cli generatetoaddress 100 bcrt1qxcjufgh2jarkp2qkx68azh08w9v5gah8u6es8s > /dev/null
sleep 30
balance_before=$(./run_electrum --regtest -D /tmp/elec1 getbalance | jq -r .confirmed)
othernode=$(./run_electrum --regtest -D /tmp/elec2 nodeid)
./run_electrum --regtest -D /tmp/elec1 open_channel $othernode@localhost 0.15
sleep 12
bitcoin-cli generatetoaddress 6 bcrt1qxcjufgh2jarkp2qkx68azh08w9v5gah8u6es8s > /dev/null
sleep 12
balance_during=$(./run_electrum --regtest -D /tmp/elec1 getbalance | jq -r .confirmed)
if [[ "$balance_during" == "$balance_before" ]]; then
    echo 'balance has not changed'
    ./run_electrum --regtest -D /tmp/elec1 getbalance
    exit 1
fi
for i in $(seq 0 0); do
    invoice=$(./run_electrum --regtest -D /tmp/elec2 addinvoice 0.01 invoice_description$i)
    ./run_electrum -D /tmp/elec1 --regtest lnpay $invoice
done
screen -S elec2 -X quit
sleep 1
ps ax | grep run_electrum
chan_id=$(python3 run_electrum -D /tmp/elec1 --regtest listchannels | jq -r ".[0].channel_point" | cut -d: -f1)
./run_electrum -D /tmp/elec1 --regtest closechannel $chan_id --force
sleep 12
bitcoin-cli generatetoaddress 144 bcrt1qxcjufgh2jarkp2qkx68azh08w9v5gah8u6es8s
sleep 30
bitcoin-cli generatetoaddress 10 bcrt1qxcjufgh2jarkp2qkx68azh08w9v5gah8u6es8s
sleep 12
bitcoin-cli generatetoaddress 10 bcrt1qxcjufgh2jarkp2qkx68azh08w9v5gah8u6es8s
sleep 12
balance_after_elec2=$(./run_electrum --regtest -D /tmp/elec2 getbalance |  jq '[.confirmed, .unconfirmed] | to_entries | map(select(.value != null).value) | map(tonumber) | add ')
if [[ "$balance_after_elec2" != "0" ]]; then
    echo 'elec2 has balance, DO_NOT_SETTLE did not work'
    exit 1
fi
date
./run_electrum --regtest -D /tmp/elec1 history --show_fees
balance_after=$(./run_electrum --regtest -D /tmp/elec1 getbalance |  jq '[.confirmed, .unconfirmed] | to_entries | map(select(.value != null).value) | map(tonumber) | add ')
if (( $(echo "$balance_after - $balance_during < 0.14" | bc -l) || $(echo "$balance_after - $balance_during > 0.15" | bc -l) )); then
    echo "balance of elec1 not between 0.14 and 0.15, to_local and htlcs not redeemed. balance was $balance_before before, $balance_during after channel opening and $balance_after after force closing"
    tail -n 200 screenlog.0
    exit 1
fi
