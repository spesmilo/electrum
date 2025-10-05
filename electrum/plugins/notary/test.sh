#!/bin/bash
alice="./run_electrum --regtest -D /tmp/alice"
bob="./run_electrum --regtest -D /tmp/bob"

$bob load_wallet
$alice load_wallet

while true; do
    event_id=$(hexdump -n32 -e '16/1 "%02x"' /dev/urandom)
    pubkey=$(hexdump -n32 -e '16/1 "%02x"' /dev/urandom)
    log_fee=$(($RANDOM % 5))
    echo "$alice notary_notarize $event_id $pubkey $log_fee"
    invoice=$($alice notary_notarize $event_id $pubkey $log_fee)
    $bob lnpay $invoice --timeout 3
    # sleep random time
    sleep $((2 + $RANDOM % 5))

done
