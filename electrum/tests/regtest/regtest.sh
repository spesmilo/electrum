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

if [[ $1 == "new_block" ]]; then
    new_blocks 1
fi

if [[ $1 == "init" ]]; then
    echo "initializing $2"
    rm -rf /tmp/$2/
    agent="./run_electrum --regtest -D /tmp/$2"
    $agent create --offline > /dev/null
    $agent setconfig --offline log_to_file True
    $agent setconfig --offline server 127.0.0.1:51001:t
    $agent setconfig --offline lightning_to_self_delay 144
    # alice is funded, bob is listening
    if [[ $2 == "bob" ]]; then
        $bob setconfig --offline lightning_listen localhost:9735
    else
        echo "funding $2"
        $bitcoin_cli sendtoaddress $($agent getunusedaddress -o) 1
    fi
fi


# start daemons. Bob is started first because he is listening
if [[ $1 == "start" ]]; then
    agent="./run_electrum --regtest -D /tmp/$2"
    $agent daemon -d
    $agent load_wallet
    sleep 1 # give time to synchronize
fi

if [[ $1 == "stop" ]]; then
    agent="./run_electrum --regtest -D /tmp/$2"
    $agent stop || true
fi

if [[ $1 == "forwarding" ]]; then
    $bob setconfig lightning_forward_payments true
    bob_node=$($bob nodeid)
    channel_id1=$($alice open_channel $bob_node 0.002 --push_amount 0.001)
    channel_id2=$($carol open_channel $bob_node 0.002 --push_amount 0.001)
    echo "mining 3 blocks"
    new_blocks 3
    sleep 10 # time for channelDB
    request=$($carol add_lightning_request 0.0001 -m "blah" | jq -r ".invoice")
    $carol setconfig test_fail_malformed_htlc true
    $alice lnpay $request
    request2=$($carol add_lightning_request 0.0001 -m "blah" | jq -r ".invoice")
    $carol setconfig test_fail_malformed_htlc false
    $alice lnpay $request2
    carol_balance=$($carol list_channels | jq -r '.[0].local_balance')
    echo "carol balance: $carol_balance"
    if [[ $carol_balance != 110000 ]]; then
        exit 1
    fi
    chan1=$($alice list_channels | jq -r ".[0].channel_point")
    chan2=$($carol list_channels | jq -r ".[0].channel_point")
    $alice close_channel $chan1
    $carol close_channel $chan2
fi

# alice sends two payments, then broadcast ctx after first payment.
# thus, bob needs to redeem both to_local and to_remote


if [[ $1 == "breach" ]]; then
    wait_for_balance alice 1
    echo "alice opens channel"
    bob_node=$($bob nodeid)
    channel=$($alice open_channel $bob_node 0.15)
    new_blocks 3
    wait_until_channel_open alice
    request=$($bob add_lightning_request 0.01 -m "blah" | jq -r ".invoice")
    echo "alice pays"
    $alice lnpay $request
    sleep 2
    ctx=$($alice get_channel_ctx $channel --iknowwhatimdoing)
    request=$($bob add_lightning_request 0.01 -m "blah2" | jq -r ".invoice")
    echo "alice pays again"
    $alice lnpay $request
    echo "alice broadcasts old ctx"
    $bitcoin_cli sendrawtransaction $ctx
    new_blocks 1
    wait_until_channel_closed bob
    new_blocks 1
    wait_for_balance bob 0.14
    $bob getbalance
fi


if [[ $1 == "extract_preimage" ]]; then
    # instead of settling bob will broadcast
    $bob enable_htlc_settle false
    wait_for_balance alice 1
    echo "alice opens channel"
    bob_node=$($bob nodeid)
    $alice open_channel $bob_node 0.15
    new_blocks 3
    wait_until_channel_open alice
    chan_id=$($alice list_channels | jq -r ".[0].channel_point")
    # alice pays bob
    invoice=$($bob add_lightning_request 0.04 -m "test" | jq -r ".invoice")
    screen -S alice_payment -dm -L -Logfile /tmp/alice/screen.log $alice lnpay $invoice --timeout=600
    sleep 1
    unsettled=$($alice list_channels | jq '.[] | .local_unsettled_sent')
    if [[ "$unsettled" == "0" ]]; then
        echo 'enable_htlc_settle did not work'
        exit 1
    fi
    # bob force closes
    $bob close_channel $chan_id --force
    new_blocks 1
    wait_until_channel_closed bob
    sleep 5
    success=$(cat /tmp/alice/screen.log | jq -r ".success")
    if [[ "$success" != "true" ]]; then
        exit 1
    fi
    cat /tmp/alice/screen.log
fi


if [[ $1 == "redeem_htlcs" ]]; then
    $bob enable_htlc_settle false
    wait_for_balance alice 1
    echo "alice opens channel"
    bob_node=$($bob nodeid)
    $alice open_channel $bob_node 0.15
    new_blocks 3
    wait_until_channel_open alice
    # alice pays bob
    invoice=$($bob add_lightning_request 0.04 -m "test" | jq -r ".invoice")
    $alice lnpay $invoice --timeout=1 || true
    unsettled=$($alice list_channels | jq '.[] | .local_unsettled_sent')
    if [[ "$unsettled" == "0" ]]; then
        echo 'enable_htlc_settle did not work'
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
    $bob enable_htlc_settle false
    wait_for_balance alice 1
    echo "alice opens channel"
    bob_node=$($bob nodeid)
    channel=$($alice open_channel $bob_node 0.15)
    new_blocks 3
    wait_until_channel_open alice
    echo "alice pays bob"
    invoice=$($bob add_lightning_request 0.04 -m "test" | jq -r ".invoice")
    $alice lnpay $invoice --timeout=1 || true
    unsettled=$($alice list_channels | jq '.[] | .local_unsettled_sent')
    if [[ "$unsettled" == "0" ]]; then
        echo "enable_htlc_settle did not work, $unsettled"
        exit 1
    fi
    ctx=$($alice get_channel_ctx $channel --iknowwhatimdoing)
    $bob enable_htlc_settle true
    unsettled=$($alice list_channels | jq '.[] | .local_unsettled_sent')
    if [[ "$unsettled" != "0" ]]; then
        echo "enable_htlc_settle did not work, $unsettled"
        exit 1
    fi
    echo "alice breaches with old ctx"
    $bitcoin_cli sendrawtransaction $ctx
    wait_for_balance bob 0.14
fi


if [[ $1 == "breach_with_spent_htlc" ]]; then
    $bob enable_htlc_settle false
    wait_for_balance alice 1
    echo "alice opens channel"
    bob_node=$($bob nodeid)
    channel=$($alice open_channel $bob_node 0.15)
    new_blocks 3
    wait_until_channel_open alice
    echo "alice pays bob"
    invoice=$($bob add_lightning_request 0.04 -m "test" | jq -r ".invoice")
    $alice lnpay $invoice --timeout=1 || true
    ctx=$($alice get_channel_ctx $channel --iknowwhatimdoing)
    unsettled=$($alice list_channels | jq '.[] | .local_unsettled_sent')
    if [[ "$unsettled" == "0" ]]; then
        echo "enable_htlc_settle did not work, $unsettled"
        exit 1
    fi
    cp /tmp/alice/regtest/wallets/default_wallet /tmp/alice/regtest/wallets/toxic_wallet
    $bob enable_htlc_settle true
    unsettled=$($alice list_channels | jq '.[] | .local_unsettled_sent')
    if [[ "$unsettled" != "0" ]]; then
        echo "enable_htlc_settle did not work, $unsettled"
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
    wait_for_balance bob 0.039
    $bob getbalance
fi


if [[ $1 == "configure_test_watchtower" ]]; then
    # carol is the watchtower of bob
    $carol setconfig -o run_local_watchtower true
    $carol setconfig -o watchtower_user wtuser
    $carol setconfig -o watchtower_password wtpassword
    $carol setconfig -o watchtower_address 127.0.0.1:12345
    $bob setconfig -o watchtower_url http://wtuser:wtpassword@127.0.0.1:12345
fi

if [[ $1 == "watchtower" ]]; then
    wait_for_balance alice 1
    echo "alice opens channel"
    bob_node=$($bob nodeid)
    channel=$($alice open_channel $bob_node 0.15)
    echo "channel outpoint: $channel"
    new_blocks 3
    wait_until_channel_open alice
    echo "alice pays bob"
    invoice1=$($bob add_lightning_request 0.01 -m "invoice1" | jq -r ".invoice")
    $alice lnpay $invoice1
    ctx=$($alice get_channel_ctx $channel --iknowwhatimdoing)
    echo "alice pays bob again"
    invoice2=$($bob add_lightning_request 0.01 -m "invoice2" | jq -r ".invoice")
    $alice lnpay $invoice2
    msg="waiting until watchtower is synchronized"
    while watchtower_ctn=$($carol get_watchtower_ctn $channel) && [ $watchtower_ctn != "3" ]; do
        sleep 1
	msg="$msg."
	printf "$msg\r"
    done
    printf "\n"
fi
