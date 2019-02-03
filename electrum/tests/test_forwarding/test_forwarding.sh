# alice -> bob -> carol

ELECTRUM=./run_electrum

HOME=/tmp

if [[ $# -eq 0 ]]; then
    echo "syntax: init|open|status|pay|close"
    exit
fi

if [[ $1 == "init" ]]; then
    rm -rf $HOME/alice/ $HOME/bob/ $HOME/carol/
    $ELECTRUM create --regtest -D $HOME/alice/
    $ELECTRUM create --regtest -D $HOME/bob/
    $ELECTRUM create --regtest -D $HOME/carol/
    $ELECTRUM setconfig --regtest -D $HOME/bob/ lightning_listen localhost:9735
    bitcoin-cli -regtest sendtoaddress `$ELECTRUM getunusedaddress --regtest -D $HOME/alice/` 1
    bitcoin-cli -regtest sendtoaddress `$ELECTRUM getunusedaddress --regtest -D $HOME/bob/` 1
    bitcoin-cli -regtest sendtoaddress `$ELECTRUM getunusedaddress --regtest -D $HOME/carol/` 1
    bitcoin-cli -regtest generate 1 > /dev/null
    exit
fi

# start daemons. Bob is started first because he is listening
$ELECTRUM daemon --regtest -D $HOME/bob/ -s 127.0.0.1:51001:t start
$ELECTRUM daemon --regtest -D $HOME/bob/ load_wallet
$ELECTRUM daemon --regtest -D $HOME/alice/ -s 127.0.0.1:51001:t start
$ELECTRUM daemon --regtest -D $HOME/alice/ load_wallet
$ELECTRUM daemon --regtest -D $HOME/carol/ -s 127.0.0.1:51001:t start
$ELECTRUM daemon --regtest -D $HOME/carol/ load_wallet


if [[ $1 == "open" ]]; then
    bob_node=$($ELECTRUM --regtest -D $HOME/bob/ nodeid)
    channel_id1=$($ELECTRUM --regtest -D $HOME/alice/ open_channel $bob_node 0.001 --channel_push 0.001)
    echo "Channel ID" $channel_id1
    channel_id2=$($ELECTRUM --regtest -D $HOME/carol/ open_channel $bob_node 0.001 --channel_push 0.001)
    echo "Channel ID" $channel_id2
    echo "mining 3 blocks"
    bitcoin-cli -regtest generate 3
fi

if [[ $1 == "status" ]]; then
    sleep 3
    $ELECTRUM --regtest -D $HOME/bob list_channels
fi

if [[ $1 == "pay" ]]; then
    sleep 3
    request=$($ELECTRUM --regtest -D $HOME/carol/ addinvoice 0.0001 "blah")
    echo $request
    $ELECTRUM --regtest -D $HOME/alice/ lnpay $request
    # sleep before stopping nodes
    sleep 3
fi

if [[ $1 == "close" ]]; then
   chan1=$($ELECTRUM --regtest -D $HOME/alice/ list_channels | jq -r ".[0].channel_point")
   chan2=$($ELECTRUM --regtest -D $HOME/carol/ list_channels | jq -r ".[0].channel_point")
   echo "Channel ID" $chan1
   echo "Channel ID" $chan2
   $ELECTRUM --regtest -D $HOME/alice/ close_channel $chan1
   $ELECTRUM --regtest -D $HOME/carol/ close_channel $chan2
   echo "mining 1 block"
   bitcoin-cli -regtest generate 1
fi
   
$ELECTRUM daemon --regtest -D $HOME/alice/ -s 127.0.0.1:51001:t stop
$ELECTRUM daemon --regtest -D $HOME/bob/ -s 127.0.0.1:51001:t stop
$ELECTRUM daemon --regtest -D $HOME/carol/ -s 127.0.0.1:51001:t stop
