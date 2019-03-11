#!/usr/bin/env bash

# alice -> bob -> carol

ELECTRUM=./run_electrum

if [[ $# -eq 0 ]]; then
    echo "syntax: init|start|open|status|pay|close|stop"
    exit 1
fi

if [[ $1 == "init" ]]; then
    rm -rf /tmp/alice/ /tmp/bob/ /tmp/carol/
    $ELECTRUM create --regtest -D /tmp/alice/
    $ELECTRUM create --regtest -D /tmp/bob/
    $ELECTRUM create --regtest -D /tmp/carol/
    $ELECTRUM setconfig --regtest -D /tmp/bob/ lightning_listen localhost:9735
    bitcoin-cli -regtest sendtoaddress `$ELECTRUM getunusedaddress --regtest -D /tmp/alice/` 1
    bitcoin-cli -regtest sendtoaddress `$ELECTRUM getunusedaddress --regtest -D /tmp/bob/` 1
    bitcoin-cli -regtest sendtoaddress `$ELECTRUM getunusedaddress --regtest -D /tmp/carol/` 1
    bitcoin-cli -regtest generate 1 > /dev/null
fi

# start daemons. Bob is started first because he is listening
if [[ $1 == "start" ]]; then
    $ELECTRUM daemon --regtest -D /tmp/bob/ -s 127.0.0.1:51001:t start
    $ELECTRUM daemon --regtest -D /tmp/bob/ load_wallet
    $ELECTRUM daemon --regtest -D /tmp/alice/ -s 127.0.0.1:51001:t start
    $ELECTRUM daemon --regtest -D /tmp/alice/ load_wallet
    $ELECTRUM daemon --regtest -D /tmp/carol/ -s 127.0.0.1:51001:t start
    $ELECTRUM daemon --regtest -D /tmp/carol/ load_wallet
    echo "daemons started"
fi

if [[ $1 == "open" ]]; then
    bob_node=$($ELECTRUM --regtest -D /tmp/bob/ nodeid)
    channel_id1=$($ELECTRUM --regtest -D /tmp/alice/ open_channel $bob_node 0.001 --channel_push 0.001)
    echo "Channel ID" $channel_id1
    channel_id2=$($ELECTRUM --regtest -D /tmp/carol/ open_channel $bob_node 0.001 --channel_push 0.001)
    echo "Channel ID" $channel_id2
    echo "mining 3 blocks"
    bitcoin-cli -regtest generate 3
fi

if [[ $1 == "status" ]]; then
    sleep 3
    $ELECTRUM --regtest -D /tmp/bob list_channels
fi

if [[ $1 == "pay" ]]; then
    sleep 3
    request=$($ELECTRUM --regtest -D /tmp/carol/ addinvoice 0.0001 "blah")
    echo $request
    $ELECTRUM --regtest -D /tmp/alice/ lnpay $request
fi

if [[ $1 == "close" ]]; then
   chan1=$($ELECTRUM --regtest -D /tmp/alice/ list_channels | jq -r ".[0].channel_point")
   chan2=$($ELECTRUM --regtest -D /tmp/carol/ list_channels | jq -r ".[0].channel_point")
   echo "Channel ID" $chan1
   echo "Channel ID" $chan2
   $ELECTRUM --regtest -D /tmp/alice/ close_channel $chan1
   $ELECTRUM --regtest -D /tmp/carol/ close_channel $chan2
   echo "mining 1 block"
   bitcoin-cli -regtest generate 1
fi

if [[ $1 == "stop" ]]; then
    $ELECTRUM daemon --regtest -D /tmp/bob/ -s 127.0.0.1:51001:t stop
    $ELECTRUM daemon --regtest -D /tmp/alice/ -s 127.0.0.1:51001:t stop
    $ELECTRUM daemon --regtest -D /tmp/carol/ -s 127.0.0.1:51001:t stop
fi
