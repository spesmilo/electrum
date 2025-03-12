#!/usr/bin/env bash
export HOME=~
set -eu

TEST_ANCHOR_CHANNELS=True

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
    $agent setconfig --offline enable_anchor_channels $TEST_ANCHOR_CHANNELS
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
    request=$($bob add_request 0.01 --lightning -m "blah" | jq -r ".lightning_invoice")
    echo "alice pays"
    $alice lnpay $request
    sleep 2
    ctx=$($alice get_channel_ctx $channel --iknowwhatimdoing)
    request=$($bob add_request 0.01 --lightning -m "blah2" | jq -r ".lightning_invoice")
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
    new_blocks 1  # cannot open multiple chans with same node in same block
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
    new_blocks 1
    wait_for_balance alice 0.997
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


if [[ $1 == "swapserver_forceclose" ]]; then
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
    $bob close_channel --force $channel
    new_blocks 1
    wait_until_spent $funding_txid 0 # alice reveals preimage
    new_blocks 1
    wait_for_balance bob 0.999
fi


if [[ $1 == "swapserver_refund" ]]; then
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
    # Alice sends htlc1 to Bob.  Bob sends htlc2 to Alice.
    # Neither one of them settles, they hold the htlcs, and Bob force-closes.
    # Bob's ctx contains two htlc outputs: "received" htlc1, and "offered" htlc2.
    # Bob also broadcasts an HTLC-success tx for received htlc1, revealing the preimage.
    # Alice broadcasts a direct-spend of the offered htlc2, revealing the preimage.
    # This test checks that
    # - Alice successfully extracts the preimage for htlc1 from Bob's HTLC-success tx, and
    # - Bob successfully extracts the preimage for htlc2 from Alice's direct spend tx
    # note: actually, due to MPP, there will be more htlcs in the ctx:
    #       we force alice to use MPP, but force bob NOT to use MPP
    $alice setconfig test_force_disable_mpp false
    $alice setconfig test_force_mpp true
    $bob setconfig test_force_disable_mpp true
    $bob setconfig test_force_mpp false
    $alice enable_htlc_settle false
    $bob enable_htlc_settle false
    wait_for_balance alice 1
    echo "alice opens channel"
    bob_node=$($bob nodeid)
    $alice open_channel $bob_node 0.15 --password='' --push_amount=0.075
    new_blocks 3
    wait_until_channel_open alice
    chan_id=$($alice list_channels | jq -r ".[0].channel_point")
    # alice pays bob
    invoice1=$($bob add_request 0.04 --lightning -m "test1" | jq -r ".lightning_invoice")
    screen -S alice_payment -dm -L -Logfile /tmp/alice/screen1.log $alice lnpay $invoice1 --timeout=600
    sleep 1
    unsettled=$($alice list_channels | jq '.[] | .local_unsettled_sent')
    if [[ "$unsettled" == "0" ]]; then
        echo 'enable_htlc_settle did not work (bob settled)'
        exit 1
    fi
    # bob pays alice
    invoice2=$($alice add_request 0.04 --lightning -m "test2" | jq -r ".lightning_invoice")
    screen -S bob_payment -dm -L -Logfile /tmp/bob/screen2.log $bob lnpay $invoice2 --timeout=600
    sleep 1
    unsettled=$($bob list_channels | jq '.[] | .local_unsettled_sent')
    if [[ "$unsettled" == "0" ]]; then
        echo 'enable_htlc_settle did not work (alice settled)'
        exit 1
    fi
    # bob force closes
    $bob close_channel $chan_id --force
    new_blocks 1
    wait_until_channel_closed bob
    wait_until_channel_closed alice
    sleep 5
    # check logs
    alice_log_found=$(grep -rnw "/tmp/alice/regtest/logs/" -e "found preimage in witness of length 5" | wc -l)
    bob_log_found=$(grep -rnw "/tmp/bob/regtest/logs/" -e "found preimage in witness of length 3" | wc -l)
    if [[ "$alice_log_found" != "1" ]]; then exit 1; fi
    if [[ "$bob_log_found" != "1" ]]; then exit 1; fi
    # check both "lnpay" commands succeeded
    success=$(cat /tmp/alice/screen1.log | jq -r ".success")
    if [[ "$success" != "true" ]]; then exit 1; fi
    success=$(cat /tmp/bob/screen2.log | jq -r ".success")
    if [[ "$success" != "true" ]]; then exit 1; fi
    cat /tmp/alice/screen1.log
    cat /tmp/bob/screen2.log
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
    invoice=$($bob add_request 0.04 --lightning -m "test" | jq -r ".lightning_invoice")
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
    invoice=$($bob add_request 0.04 --lightning -m "test" | jq -r ".lightning_invoice")
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
    invoice=$($bob add_request 0.04 --lightning -m "test" | jq -r ".lightning_invoice")
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
    if [ $TEST_ANCHOR_CHANNELS = True ] ; then
        # to_local_anchor/to_remote_anchor: 0 and 1 (both are present due to untrimmed htlcs)
        # htlc: 2, to_local: 3
        wait_until_spent $ctx_id 2
        wait_until_spent $ctx_id 3
    else
        # htlc: 0, to_local: 1
        wait_until_spent $ctx_id 0
        wait_until_spent $ctx_id 1
    fi
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
    invoice1=$($bob add_request 0.01 --lightning -m "invoice1" | jq -r ".lightning_invoice")
    $alice lnpay $invoice1
    ctx=$($alice get_channel_ctx $channel --iknowwhatimdoing)
    echo "alice pays bob again"
    invoice2=$($bob add_request 0.01 --lightning -m "invoice2" | jq -r ".lightning_invoice")
    $alice lnpay $invoice2
    bob_ctn=$($bob list_channels | jq '.[0].local_ctn')
    msg="waiting until watchtower is synchronized"
    # watchtower needs to be at latest revoked ctn
    while watchtower_ctn=$($bob get_watchtower_ctn $channel) && [[ $watchtower_ctn != $((bob_ctn-1)) ]]; do
        sleep 0.1
        printf "$msg $bob_ctn $watchtower_ctn\r"
    done
    printf "\n"
    echo "stopping alice and bob"
    $bob stop
    $alice stop
    ctx_id=$($bitcoin_cli sendrawtransaction $ctx)
    echo "alice breaches with old ctx:" $ctx_id
    echo "watchtower publishes justice transaction"
    if [ $TEST_ANCHOR_CHANNELS = True ] ; then
        output_index=3
    else
        output_index=1
    fi
    wait_until_spent $ctx_id $output_index  # alice's to_local gets punished
fi

if [[ $1 == "just_in_time_no_channel" ]]; then
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
    invoice=$($alice add_request 0.01 --lightning -m "invoice" | jq -r ".lightning_invoice")
    success=$($carol lnpay $invoice | jq -r ".success")
    if [[ "$success" != "true" ]]; then
        echo "jit payment failed"
        exit 1
    fi
    # try again, multiple jit openings should work without issues
    new_blocks 3
    echo "carol pays alice again"
    invoice=$($alice add_request 0.04 --lightning -m "invoice" | jq -r ".lightning_invoice")
    success=$($carol lnpay $invoice | jq -r ".success")
    if [[ "$success" != "true" ]]; then
        echo "jit payment failed"
        exit 1
    fi
    alice_chan_count=$($alice list_channels | jq '. | length')
    if [[ "$alice_chan_count" != "2" ]]; then
        echo "alice should have two jit channels"
        exit 1
    fi
fi

if [[ $1 == "just_in_time_existing_channels" ]]; then
    bob_node=$($bob nodeid)
    alice_node=$($alice nodeid)
    $alice setconfig zeroconf_trusted_node $bob_node
    $alice setconfig use_recoverable_channels false
    wait_for_balance bob 1
    wait_for_balance carol 1
    echo "carol opens channel with bob"
    $carol open_channel $bob_node 0.15 --password=''
    echo "bob opens channel with alice"
    $bob open_channel $alice_node 0.15 --password=''
    new_blocks 3
    wait_until_channel_open carol
    wait_until_channel_open bob
    echo "carol pays alice"
    # this should not open an additional channel
    invoice=$($alice add_request 0.12 --lightning -m "invoice" | jq -r ".lightning_invoice")
    success=$($carol lnpay $invoice | jq -r ".success")
    if [[ "$success" != "true" ]]; then
        echo "jit payment failed"
        exit 1
    fi
    alice_chan_count=$($alice list_channels | jq '. | length')
    if [[ "$alice_chan_count" != "1" ]]; then
        echo "alice should not have an additional channel"
        exit 1
    fi
fi


if [[ $1 == "just_in_time_failed_htlc" ]]; then
    bob_node=$($bob nodeid)
    $alice setconfig zeroconf_trusted_node $bob_node
    $alice setconfig use_recoverable_channels false
    $alice setconfig test_fail_htlcs_with_temp_node_failure true
    wait_for_balance carol 1
    echo "carol opens channel with bob"
    $carol open_channel $bob_node 0.15 --password=''
    new_blocks 3
    wait_until_channel_open carol
    echo "carol tries to pay alice (but alice will fail htlc)"
    invoice=$($alice add_request 0.02 --lightning -m "invoice" | jq -r ".lightning_invoice")
    success=$($carol lnpay $invoice | jq -r ".success") # this will fail

    bob_chan_count=$($bob list_channels | jq '. | length')
    if [[ "$bob_chan_count" != "1" ]]; then  # failed jit channels should be removed directly
        echo "bob should have only one channel\n$($bob list_channels)"
        exit 1
    fi
    alice_chan_state=$($alice list_channels | jq -r '.[0].state')
    if [[ "$alice_chan_state" != "CLOSING" ]]; then
        echo "alice failed JIT channel should be in closing state\n$($alice list_channels)"
        exit 1
    fi
    # after a new block triggers one iteration of update_unfunded_state the channel should be removed
    new_blocks 1
    alice_chan_count=$($alice list_channels | jq '. | length')
    if [[ "$alice_chan_count" != "0" ]]; then
        echo "alice should have no channel\n$($alice list_channels)"
        exit 1
    fi
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
