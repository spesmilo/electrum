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

function wait_until_htlcs_settled()
{
    msg="wait until $1's local_unsettled_sent is zero"
    cmd="./run_electrum --regtest -D /tmp/$1"
    while unsettled=$($cmd list_channels | jq '.[] | .local_unsettled_sent') && [ $unsettled != "0" ]; do
        sleep 1
        msg="$msg."
        printf "$msg\r"
    done
    printf "\n"
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
    $agent setconfig --offline use_gossip True
    $agent setconfig --offline server 127.0.0.1:51001:t
    $agent setconfig --offline lightning_to_self_delay 144
    $agent setconfig --offline test_force_disable_mpp True
    echo "funding $2"
    # note: changing the funding amount affects all tests, as they rely on "wait_for_balance"
    $bitcoin_cli sendtoaddress $($agent getunusedaddress -o) 1
fi

if [[ $1 == "setconfig" ]]; then
    # use this to set config vars that need to be set before the daemon is started
    agent="./run_electrum --regtest -D /tmp/$2"
    $agent setconfig --offline $3 $4
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


# alice sends two payments, then broadcast ctx after first payment.
# thus, bob needs to redeem both to_local and to_remote


if [[ $1 == "breach" ]]; then
    wait_for_balance alice 1
    echo "alice opens channel"
    bob_node=$($bob nodeid)
    channel=$($alice open_channel $bob_node 0.15 --password='')
    new_blocks 3
    wait_until_channel_open alice
    request=$($bob add_request 0.01 -m "blah" | jq -r ".lightning_invoice")
    echo "alice pays"
    $alice lnpay $request
    sleep 2
    ctx=$($alice get_channel_ctx $channel --iknowwhatimdoing)
    request=$($bob add_request 0.01 -m "blah2" | jq -r ".lightning_invoice")
    echo "alice pays again"
    $alice lnpay $request
    echo "alice broadcasts old ctx"
    $bitcoin_cli sendrawtransaction $ctx
    new_blocks 1
    wait_until_channel_closed bob
    new_blocks 1
    wait_for_balance bob 1.14
    $bob getbalance
fi


if [[ $1 == "backup" ]]; then
    wait_for_balance alice 1
    echo "alice opens channel"
    bob_node=$($bob nodeid)
    channel1=$($alice open_channel $bob_node 0.15 --password='')
    $alice setconfig use_recoverable_channels False
    channel2=$($alice open_channel $bob_node 0.15 --password='')
    new_blocks 3
    wait_until_channel_open alice
    backup=$($alice export_channel_backup $channel2)
    seed=$($alice getseed --password='')
    $alice stop
    mv /tmp/alice/regtest/wallets/default_wallet /tmp/alice/regtest/wallets/default_wallet.old
    $alice -o restore "$seed"
    $alice daemon -d
    $alice load_wallet
    $alice import_channel_backup $backup
    echo "request force close $channel1"
    $alice request_force_close $channel1
    echo "request force close $channel2"
    $alice request_force_close $channel2
    wait_for_balance alice 0.998
fi


if [[ $1 == "backup_local_forceclose" ]]; then
    # Alice does a local-force-close, and then restores from seed before sweeping CSV-locked coins
    wait_for_balance alice 1
    echo "alice opens channel"
    bob_node=$($bob nodeid)
    $alice setconfig use_recoverable_channels False
    channel=$($alice open_channel $bob_node 0.15 --password='')
    new_blocks 3
    wait_until_channel_open alice
    backup=$($alice export_channel_backup $channel)
    echo "local force close $channel"
    $alice close_channel $channel --force
    sleep 0.5
    seed=$($alice getseed --password='')
    $alice stop
    mv /tmp/alice/regtest/wallets/default_wallet /tmp/alice/regtest/wallets/default_wallet.old
    new_blocks 150
    $alice -o restore "$seed"
    $alice daemon -d
    $alice load_wallet
    $alice import_channel_backup $backup
    wait_for_balance alice 0.998
fi


if [[ $1 == "collaborative_close" ]]; then
    wait_for_balance alice 1
    echo "alice opens channel"
    bob_node=$($bob nodeid)
    channel=$($alice open_channel $bob_node 0.15 --password='')
    new_blocks 3
    wait_until_channel_open alice
    echo "alice closes channel"
    request=$($bob close_channel $channel)
fi


if [[ $1 == "swapserver_success" ]]; then
    $bob enable_plugin swapserver
    wait_for_balance alice 1
    echo "alice opens channel"
    bob_node=$($bob nodeid)
    channel=$($alice open_channel $bob_node 0.15 --password='')
    new_blocks 3
    wait_until_channel_open alice
    echo "alice initiates swap"
    dryrun=$($alice reverse_swap 0.02 dryrun)
    onchain_amount=$(echo $dryrun| jq -r ".onchain_amount")
    swap=$($alice reverse_swap 0.02 $onchain_amount)
    echo $swap | jq
    funding_txid=$(echo $swap| jq -r ".funding_txid")
    new_blocks 1
    wait_until_spent $funding_txid 0
    wait_until_htlcs_settled alice
fi


if [[ $1 == "swapserver_refund" ]]; then
    $bob enable_plugin swapserver
    $alice setconfig test_swapserver_refund true
    wait_for_balance alice 1
    echo "alice opens channel"
    bob_node=$($bob nodeid)
    channel=$($alice open_channel $bob_node 0.15 --password='')
    new_blocks 3
    wait_until_channel_open alice
    echo "alice initiates swap"
    dryrun=$($alice reverse_swap 0.02 dryrun)
    onchain_amount=$(echo $dryrun| jq -r ".onchain_amount")
    swap=$($alice reverse_swap 0.02 $onchain_amount)
    echo $swap | jq
    funding_txid=$(echo $swap| jq -r ".funding_txid")
    new_blocks 140
    wait_until_spent $funding_txid 0
    new_blocks 1
    wait_until_htlcs_settled alice
fi


if [[ $1 == "extract_preimage" ]]; then
    # instead of settling bob will broadcast
    $bob enable_htlc_settle false
    wait_for_balance alice 1
    echo "alice opens channel"
    bob_node=$($bob nodeid)
    $alice open_channel $bob_node 0.15 --password=''
    new_blocks 3
    wait_until_channel_open alice
    chan_id=$($alice list_channels | jq -r ".[0].channel_point")
    # alice pays bob
    invoice=$($bob add_request 0.04 -m "test" | jq -r ".lightning_invoice")
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
    $alice open_channel $bob_node 0.15 --password=''
    new_blocks 3
    wait_until_channel_open alice
    # alice pays bob
    invoice=$($bob add_request 0.04 -m "test" | jq -r ".lightning_invoice")
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
    channel=$($alice open_channel $bob_node 0.15 --password='')
    new_blocks 3
    wait_until_channel_open alice
    echo "alice pays bob"
    invoice=$($bob add_request 0.04 -m "test" | jq -r ".lightning_invoice")
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
    wait_for_balance bob 1.14
fi


if [[ $1 == "breach_with_spent_htlc" ]]; then
    $bob enable_htlc_settle false
    wait_for_balance alice 1
    echo "alice opens channel"
    bob_node=$($bob nodeid)
    channel=$($alice open_channel $bob_node 0.15 --password='')
    new_blocks 3
    wait_until_channel_open alice
    echo "alice pays bob"
    invoice=$($bob add_request 0.04 -m "test" | jq -r ".lightning_invoice")
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
    wait_for_balance bob 1.039
    $bob getbalance
fi

if [[ $1 == "watchtower" ]]; then
    wait_for_balance alice 1
    echo "alice opens channel"
    bob_node=$($bob nodeid)
    channel=$($alice open_channel $bob_node 0.15 --password='')
    echo "channel outpoint: $channel"
    new_blocks 3
    wait_until_channel_open alice
    echo "alice pays bob"
    invoice1=$($bob add_request 0.01 -m "invoice1" | jq -r ".lightning_invoice")
    $alice lnpay $invoice1
    ctx=$($alice get_channel_ctx $channel --iknowwhatimdoing)
    echo "alice pays bob again"
    invoice2=$($bob add_request 0.01 -m "invoice2" | jq -r ".lightning_invoice")
    $alice lnpay $invoice2
    alice_ctn=$($alice list_channels | jq '.[0].local_ctn')
    msg="waiting until watchtower is synchronized"
    # watchtower needs to be at latest revoked ctn
    while watchtower_ctn=$($carol get_watchtower_ctn $channel) && [[ $watchtower_ctn != $((alice_ctn-1)) ]]; do
        sleep 0.1
        printf "$msg $alice_ctn $watchtower_ctn\r"
    done
    printf "\n"
    echo "stopping alice and bob"
    $bob stop
    $alice stop
    ctx_id=$($bitcoin_cli sendrawtransaction $ctx)
    echo "alice breaches with old ctx:" $ctx_id
    echo "watchtower publishes justice transaction"
    wait_until_spent $ctx_id 1  # alice's to_local gets punished immediately
fi

if [[ $1 == "just_in_time" ]]; then
    bob_node=$($bob nodeid)
    $alice setconfig zeroconf_trusted_node $bob_node
    $alice setconfig use_recoverable_channels false
    wait_for_balance carol 1
    echo "carol opens channel with bob"
    $carol open_channel $bob_node 0.15 --password=''
    new_blocks 3
    wait_until_channel_open carol
    echo "carol pays alice"
    # note: set amount to 0.001 to test failure: 'payment too low'
    invoice=$($alice add_request 0.01 -m "invoice" | jq -r ".lightning_invoice")
    $carol lnpay $invoice
fi

if [[ $1 == "unixsockets" ]]; then
    # This looks different because it has to run the entire daemon
    # Test domain socket behavior
    ./run_electrum --regtest daemon -d --rpcsock=unix # Start daemon with unix domain socket
    ./run_electrum --regtest stop # Errors if it can't connect
    # Test custom socket path
    f=$(mktemp --dry-run)
    ./run_electrum --regtest daemon -d --rpcsock=unix --rpcsockpath=$f
    [ -S $f ] # filename exists and is socket
    ./run_electrum --regtest stop
    rm $f # clean up
    # Test for regressions in the ordinary TCP functionality.
    ./run_electrum --regtest daemon -d --rpcsock=tcp
    ./run_electrum --regtest stop
fi
