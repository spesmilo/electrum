#!/usr/bin/env bash
export HOME=~
set -eu

# alice -> bob -> carol

alice="./run_electrum --regtest --lightning -D /tmp/alice"
bob="./run_electrum --regtest --lightning -D /tmp/bob"
carol="./run_electrum --regtest --lightning -D /tmp/carol"

bitcoin_cli="bitcoin-cli -rpcuser=doggman -rpcpassword=donkey -rpcport=18554 -regtest"

function new_blocks()
{
    $bitcoin_cli generatetoaddress $1 $($bitcoin_cli getnewaddress) > /dev/null
}

if [[ $# -eq 0 ]]; then
    echo "syntax: init|start|open|status|pay|close|stop"
    exit 1
fi

if [[ $1 == "init" ]]; then
    rm -rf /tmp/alice/ /tmp/bob/ /tmp/carol/
    $alice create > /dev/null
    $bob create > /dev/null
    $carol create > /dev/null
    $bob setconfig lightning_listen localhost:9735
    $bitcoin_cli sendtoaddress $($alice getunusedaddress) 1
    $bitcoin_cli sendtoaddress $($carol getunusedaddress) 1
    new_blocks 1
fi

# start daemons. Bob is started first because he is listening
if [[ $1 == "start" ]]; then
    $bob daemon -s 127.0.0.1:51001:t start
    $bob daemon load_wallet
    $alice daemon -s 127.0.0.1:51001:t start
    $alice daemon load_wallet
    $carol daemon -s 127.0.0.1:51001:t start
    $carol daemon load_wallet
    sleep 10 # give time to synchronize
fi

if [[ $1 == "stop" ]]; then
    $alice daemon stop || true
    $bob daemon stop || true
    $carol daemon stop || true
fi

if [[ $1 == "open" ]]; then
    bob_node=$($bob nodeid)
    channel_id1=$($alice open_channel $bob_node 0.001 --channel_push 0.001)
    channel_id2=$($carol open_channel $bob_node 0.001 --channel_push 0.001)
    echo "mining 3 blocks"
    new_blocks 3
    sleep 10 # time for channelDB
fi

if [[ $1 == "alice_pays_carol" ]]; then
    request=$($carol addinvoice 0.0001 "blah")
    $alice lnpay $request
    carol_balance=$($carol list_channels | jq -r '.[0].local_balance')
    echo "carol balance: $carol_balance"
    if [[ $carol_balance != 110000 ]]; then
	exit 1
    fi
fi

if [[ $1 == "close" ]]; then
   chan1=$($alice list_channels | jq -r ".[0].channel_point")
   chan2=$($carol list_channels | jq -r ".[0].channel_point")
   $alice close_channel $chan1
   $carol close_channel $chan2
   echo "mining 1 block"
   new_blocks 1
fi

# alice sends two payments, then broadcast ctx after first payment.
# thus, bob needs to redeem both to_local and to_remote

if [[ $1 == "breach" ]]; then
    bob_node=$($bob nodeid)
    channel=$($alice open_channel $bob_node 0.15)
    new_blocks 6
    sleep 10
    request=$($bob addinvoice 0.01 "blah")
    echo "alice pays"
    $alice lnpay $request
    sleep 2
    ctx=$($alice get_channel_ctx $channel | jq '.hex' | tr -d '"')
    request=$($bob addinvoice 0.01 "blah2")
    echo "alice pays"
    $alice lnpay $request
    sleep 2
    echo "alice broadcasts old ctx"
    $bitcoin_cli sendrawtransaction $ctx
    sleep 10
    new_blocks 2
    sleep 10
    balance=$($bob getbalance | jq '.confirmed | tonumber')
    echo "balance of bob after breach: $balance"
    if (( $(echo "$balance < 0.14" | bc -l) )); then
	exit 1
    fi
fi

if [[ $1 == "redeem_htlcs" ]]; then
    $bob daemon stop
    ELECTRUM_DEBUG_LIGHTNING_DO_NOT_SETTLE=1 $bob daemon -s 127.0.0.1:51001:t start
    $bob daemon load_wallet
    sleep 1
    # alice opens channel
    bob_node=$($bob nodeid)
    $alice open_channel $bob_node 0.15
    new_blocks 6
    sleep 10
    # alice pays bob
    invoice=$($bob addinvoice 0.05 "test")
    $alice lnpay $invoice || true
    sleep 1
    settled=$($alice list_channels | jq '.[] | .local_htlcs | .settles | length')
    if [[ "$settled" != "0" ]]; then
	echo 'DO_NOT_SETTLE did not work'
        exit 1
    fi
    # bob goes away
    $bob daemon stop
    echo "alice balance before closing channel:" $($alice getbalance)
    balance_before=$($alice getbalance | jq '[.confirmed, .unconfirmed, .lightning] | to_entries | map(select(.value != null).value) | map(tonumber) | add ')
    # alice force closes the channel
    chan_id=$($alice list_channels | jq -r ".[0].channel_point")
    $alice close_channel $chan_id --force
    new_blocks 1
    sleep 5
    echo "alice balance after closing channel:" $($alice getbalance)
    new_blocks 144
    sleep 10
    new_blocks 1
    sleep 10
    echo "alice balance after 144 blocks:" $($alice getbalance)
    balance_after=$($alice getbalance |  jq '[.confirmed, .unconfirmed] | to_entries | map(select(.value != null).value) | map(tonumber) | add ')
    if (( $(echo "$balance_before - $balance_after > 0.02" | bc -l) )); then
	echo "htlc not redeemed."
	exit 1
    fi
fi
