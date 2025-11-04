#!/bin/bash
alice="./run_electrum --regtest -D /tmp/alice"
bob="./run_electrum --regtest -D /tmp/bob"

$bob load_wallet

while true; do
    event_id=$(hexdump -n32 -e '16/1 "%02x"' /dev/urandom)
    #event_pubkey=$(hexdump -n32 -e '16/1 "%02x"' /dev/urandom)
    fee=$((2 ** (($RANDOM % 9)) ))
    echo "$alice notary_add_request $event_id $fee"
    invoice=$($alice notary_add_request $event_id $fee | jq '.invoice')
    $bob lnpay $invoice --timeout 3
    # sleep random time
    sleep $((2 + $RANDOM % 5))
done
