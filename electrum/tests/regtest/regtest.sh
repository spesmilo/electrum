#!/usr/bin/env bash
export HOME=~
set -eu

# alice -> bob -> carol

alice="./run_electrum --regtest -D /tmp/alice"
bob="./run_electrum --regtest -D /tmp/bob"
carol="./run_electrum --regtest -D /tmp/carol"

bitcoin_cli="bitcoin-cli -rpcuser=doggman -rpcpassword=donkey -rpcport=18554 -regtest"

function new_blocks()
{
    $bitcoin_cli generatetoaddress $1 $($bitcoin_cli getnewaddress) > /dev/null
}

function wait_for_balance()
{
    msg="wait until $1's balance reaches $2"
    cmd="./run_electrum --regtest -D /tmp/$1"
    while balance=$($cmd getbalance | jq '[.confirmed, .unconfirmed] | to_entries | map(select(.value != null).value) | map(tonumber) | add ') && (( $(echo "$balance < $2" | bc -l) )); do
        sleep 1
	msg="$msg."
	printf "$msg\r"
    done
    printf "\n"
}

function wait_until_channel_open()
{
    msg="wait until $1 sees channel open"
    cmd="./run_electrum --regtest -D /tmp/$1"
    while channel_state=$($cmd list_channels | jq '.[0] | .state' | tr -d '"') && [ $channel_state != "OPEN" ]; do
        sleep 1
	msg="$msg."
	printf "$msg\r"
    done
    printf "\n"
}

function wait_until_channel_closed()
{
    msg="wait until $1 sees channel closed"
    cmd="./run_electrum --regtest -D /tmp/$1"
    while [[ $($cmd list_channels | jq '.[0].state' | tr -d '"') != "CLOSED" ]]; do
        sleep 1
	msg="$msg."
	printf "$msg\r"
    done
    printf "\n"
}

function wait_until_spent()
{
    msg="wait until $1:$2 is spent"
    while [[ $($bitcoin_cli gettxout $1 $2) ]]; do
        sleep 1
	msg="$msg."
	printf "$msg\r"
    done
    printf "\n"
}

if [[ $# -eq 0 ]]; then
    echo "syntax: init|start|open|status|pay|close|stop"
    exit 1
fi

if [[ $1 == "init" ]]; then
    echo "initializing alice, bob and carol"
    rm -rf /tmp/alice/ /tmp/bob/ /tmp/carol/
    $alice create --offline > /dev/null
    $bob   create --offline > /dev/null
    $carol create --offline > /dev/null
    $alice -o init_lightning
    $bob   -o init_lightning
    $carol -o init_lightning
    $alice setconfig --offline log_to_file True
    $bob   setconfig --offline log_to_file True
    $carol setconfig --offline log_to_file True
    $alice setconfig --offline server 127.0.0.1:51001:t
    $bob   setconfig --offline server 127.0.0.1:51001:t
    $carol setconfig --offline server 127.0.0.1:51001:t
    $bob setconfig --offline lightning_listen localhost:9735
    $bob setconfig --offline lightning_forward_payments true
    echo "funding alice and carol"
    $bitcoin_cli sendtoaddress $($alice getunusedaddress -o) 1
    $bitcoin_cli sendtoaddress $($carol getunusedaddress -o) 1
    new_blocks 1
fi

if [[ $1 == "new_block" ]]; then
    new_blocks 1
fi

# start daemons. Bob is started first because he is listening
if [[ $1 == "start" ]]; then
    $bob daemon -d
    $alice daemon -d
    $carol daemon -d
    $bob load_wallet
    $alice load_wallet
    $carol load_wallet
    sleep 10 # give time to synchronize
fi

if [[ $1 == "stop" ]]; then
    $alice stop || true
    $bob stop || true
    $carol stop || true
fi

if [[ $1 == "open" ]]; then
    bob_node=$($bob nodeid)
    channel_id1=$($alice open_channel $bob_node 0.002 --push_amount 0.001)
    channel_id2=$($carol open_channel $bob_node 0.002 --push_amount 0.001)
    echo "mining 3 blocks"
    new_blocks 3
    sleep 10 # time for channelDB
fi

if [[ $1 == "alice_pays_carol" ]]; then
    request=$($carol add_lightning_request 0.0001 -m "blah")
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
    new_blocks 3
    wait_until_channel_open alice
    request=$($bob add_lightning_request 0.01 -m "blah")
    echo "alice pays"
    $alice lnpay $request
    sleep 2
    ctx=$($alice get_channel_ctx $channel)
    request=$($bob add_lightning_request 0.01 -m "blah2")
    echo "alice pays again"
    $alice lnpay $request
    echo "alice broadcasts old ctx"
    $bitcoin_cli sendrawtransaction $ctx
    wait_until_channel_closed bob
    new_blocks 1
    wait_for_balance bob 0.14
    $bob getbalance
fi

if [[ $1 == "redeem_htlcs" ]]; then
    $bob stop
    ELECTRUM_DEBUG_LIGHTNING_SETTLE_DELAY=10 $bob daemon -d
    sleep 1
    $bob load_wallet
    sleep 1
    # alice opens channel
    bob_node=$($bob nodeid)
    $alice open_channel $bob_node 0.15
    new_blocks 6
    sleep 10
    # alice pays bob
    invoice=$($bob add_lightning_request 0.05 -m "test")
    $alice lnpay $invoice --timeout=1 || true
    sleep 1
    settled=$($alice list_channels | jq '.[] | .local_htlcs | .settles | length')
    if [[ "$settled" != "0" ]]; then
        echo 'SETTLE_DELAY did not work'
        exit 1
    fi
    # bob goes away
    $bob stop
    echo "alice balance before closing channel:" $($alice getbalance)
    balance_before=$($alice getbalance | jq '[.confirmed, .unconfirmed, .lightning] | to_entries | map(select(.value != null).value) | map(tonumber) | add ')
    # alice force closes the channel
    chan_id=$($alice list_channels | jq -r ".[0].channel_point")
    $alice close_channel $chan_id --force
    new_blocks 1
    sleep 3
    echo "alice balance after closing channel:" $($alice getbalance)
    new_blocks 150
    sleep 10
    new_blocks 1
    sleep 3
    echo "alice balance after CLTV" $($alice getbalance)
    new_blocks 150
    sleep 10
    new_blocks 1
    sleep 3
    echo "alice balance after CSV" $($alice getbalance)
    # fixme: add local to getbalance
    wait_for_balance alice $(echo "$balance_before - 0.02" | bc -l)
    $alice getbalance
fi


if [[ $1 == "breach_with_unspent_htlc" ]]; then
    $bob stop
    ELECTRUM_DEBUG_LIGHTNING_SETTLE_DELAY=3 $bob daemon -d
    sleep 1
    $bob load_wallet
    wait_for_balance alice 1
    echo "alice opens channel"
    bob_node=$($bob nodeid)
    channel=$($alice open_channel $bob_node 0.15)
    new_blocks 3
    wait_until_channel_open alice
    echo "alice pays bob"
    invoice=$($bob add_lightning_request 0.05 -m "test")
    $alice lnpay $invoice --timeout=1 || true
    settled=$($alice list_channels | jq '.[] | .local_htlcs | .settles | length')
    if [[ "$settled" != "0" ]]; then
        echo "SETTLE_DELAY did not work, $settled != 0"
        exit 1
    fi
    ctx=$($alice get_channel_ctx $channel)
    sleep 5
    settled=$($alice list_channels | jq '.[] | .local_htlcs | .settles | length')
    if [[ "$settled" != "1" ]]; then
        echo "SETTLE_DELAY did not work, $settled != 1"
        exit 1
    fi
    echo "alice breaches with old ctx"
    $bitcoin_cli sendrawtransaction $ctx
    wait_for_balance bob 0.14
fi


if [[ $1 == "breach_with_spent_htlc" ]]; then
    $bob stop
    ELECTRUM_DEBUG_LIGHTNING_SETTLE_DELAY=3 $bob daemon -d
    sleep 1
    $bob load_wallet
    wait_for_balance alice 1
    echo "alice opens channel"
    bob_node=$($bob nodeid)
    channel=$($alice open_channel $bob_node 0.15)
    new_blocks 3
    wait_until_channel_open alice
    echo "alice pays bob"
    invoice=$($bob add_lightning_request 0.05 -m "test")
    $alice lnpay $invoice --timeout=1 || true
    ctx=$($alice get_channel_ctx $channel)
    settled=$($alice list_channels | jq '.[] | .local_htlcs | .settles | length')
    if [[ "$settled" != "0" ]]; then
        echo "SETTLE_DELAY did not work, $settled != 0"
        exit 1
    fi
    cp /tmp/alice/regtest/wallets/default_wallet /tmp/alice/regtest/wallets/toxic_wallet
    sleep 5
    settled=$($alice list_channels | jq '.[] | .local_htlcs | .settles | length')
    if [[ "$settled" != "1" ]]; then
        echo "SETTLE_DELAY did not work, $settled != 1"
        exit 1
    fi
    echo $($bob getbalance)
    echo "bob goes offline"
    $bob stop
    ctx_id=$($bitcoin_cli sendrawtransaction $ctx)
    echo "alice breaches with old ctx:" $ctx_id
    new_blocks 1
    if [[ $($bitcoin_cli gettxout $ctx_id 0 | jq '.confirmations') != "1" ]]; then
        echo "breach tx not confirmed"
        exit 1
    fi
    echo "wait for cltv_expiry blocks"
    # note: this will let alice redeem both to_local and the htlc.
    # (to_local needs to_self_delay blocks; htlc needs whatever we put in invoice)
    new_blocks 150
    $alice stop
    $alice daemon -d
    sleep 1
    $alice load_wallet -w /tmp/alice/regtest/wallets/toxic_wallet
    # wait until alice has spent both ctx outputs
    echo "alice spends to_local and htlc outputs"
    wait_until_spent $ctx_id 0
    wait_until_spent $ctx_id 1
    new_blocks 1
    echo "bob comes back"
    $bob daemon -d
    sleep 1
    $bob load_wallet
    wait_for_balance bob 0.049
    $bob getbalance
fi

if [[ $1 == "watchtower" ]]; then
    # carol is a watchtower of alice
    $alice stop
    $carol stop
    $alice setconfig --offline watchtower_url http://127.0.0.1:12345
    $carol setconfig --offline watchtower_host 127.0.0.1
    $carol setconfig --offline watchtower_port 12345
    $carol daemon -d
    $alice daemon -d
    sleep 1
    $alice load_wallet
    wait_for_balance alice 1
    echo "alice opens channel"
    bob_node=$($bob nodeid)
    channel=$($alice open_channel $bob_node 0.5)
    new_blocks 3
    wait_until_channel_open alice
    echo "alice pays bob"
    invoice1=$($bob add_lightning_request 0.05 -m "invoice1")
    $alice lnpay $invoice1
    invoice2=$($bob add_lightning_request 0.05 -m "invoice2")
    $alice lnpay $invoice2
    invoice3=$($bob add_lightning_request 0.05 -m "invoice3")
    $alice lnpay $invoice3

fi
