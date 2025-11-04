#!/bin/bash

# this sends a notarization request to notary.electrum.org
event_id=$(hexdump -n32 -e '16/1 "%02x"' /dev/urandom)
value=$((2 ** (($RANDOM % 9)) ))
request="{\"event_id\":\"$event_id\",\"value\":$value}"

echo "your request"
echo $request | jq --color-output

invoice=$(curl -s -X POST https://swaps.electrum.org/notary/add_request -H 'Content-Type: application/json' -d @<(echo $request))

echo "notary invoice:"
echo $invoice | jq --color-output

proof="{\"error\":\"initializing...\"}"
while error=$(echo $proof|jq '.error') && [[ $error != null ]]; do
    printf "$error\r"
    sleep 1
    proof=$(curl -s -X POST https://swaps.electrum.org/notary/get_proof -H 'Content-Type: application/json' -d @<(echo $invoice))
done
printf "                                                 \r"
echo "proof:"
echo $proof | jq --color-output

echo "proof verification:"
verify=$(curl -s -X POST https://swaps.electrum.org/notary/verify_proof -H 'Content-Type: application/json' -d @<(echo $proof))
echo $verify | jq --color-output
