#!/usr/bin/env bash
export HOME=~
set -eu

TEST_ANCHOR_CHANNELS=True
USE_LEVELDB=--use_levelDB

# alice -> bob -> carol
alice="./run_electrum --regtest -D /tmp/alice"
bob="./run_electrum --regtest -D /tmp/bob"
carol="./run_electrum --regtest -D /tmp/carol"

bitcoin_cli="bitcoin-cli -rpcuser=doggman -rpcpassword=donkey -rpcport=18554 -regtest"

function new_blocks()
{
    printf "mining $1 blocks\n"
    $bitcoin_cli generatetoaddress $1 $($bitcoin_cli getnewaddress) > /dev/null
}

function wait_until_htlcs_settled()
{
    msg="wait until $1's local_unsettled_sent is zero"
    cmd="./run_electrum --regtest -D /tmp/$1"
    declare -i timeout_sec=30
    declare -i elapsed_sec=0

    while unsettled=$($cmd list_channels | jq '.[] | .local_unsettled_sent') && [ $unsettled != "0" ]; do
        if ((elapsed_sec > timeout_sec)); then
            printf "Timeout of %i s exceeded\n" "$elapsed_sec"
            exit 1
        fi

        sleep 1
        elapsed_sec=$((elapsed_sec + 1))
        msg="$msg."
        printf "$msg\r"
    done
    printf "\n"
}


function wait_for_balance()
{
    msg="wait until $1's balance reaches $2"
    cmd="./run_electrum --regtest -D /tmp/$1"
    declare -i timeout_sec=30
    declare -i elapsed_sec=0

    while balance=$($cmd getbalance | jq '[.confirmed, .unconfirmed] | to_entries | map(select(.value != null).value) | map(tonumber) | add ') && (( $(echo "$balance < $2" | bc -l) )); do
        if ((elapsed_sec > timeout_sec)); then
            printf "Timeout of %i s exceeded\n" "$elapsed_sec"
            exit 1
        fi

        sleep 1
        elapsed_sec=$((elapsed_sec + 1))
        msg="$msg."
        printf "$msg\r"
    done
    printf "\n"
}

function wait_until_channel_open()
{
    msg="wait until $1 sees channel open"
    cmd="./run_electrum --regtest -D /tmp/$1"
    declare -i timeout_sec=30
    declare -i elapsed_sec=0

    while channel_state=$($cmd list_channels | jq '.[0] | .state' | tr -d '"') && [ $channel_state != "OPEN" ]; do
        if ((elapsed_sec > timeout_sec)); then
            printf "Timeout of %i s exceeded\n" "$elapsed_sec"
            exit 1
        fi

        sleep 1
        elapsed_sec=$((elapsed_sec + 1))
        msg="$msg."
        printf "$msg\r"
    done
    printf "\n"
}

function wait_until_channel_closed()
{
    msg="wait until $1 sees channel closed"
    cmd="./run_electrum --regtest -D /tmp/$1"
    declare -i timeout_sec=30
    declare -i elapsed_sec=0

    while [[ $($cmd list_channels | jq '.[0].state' | tr -d '"') != "CLOSED" ]]; do
        if ((elapsed_sec > timeout_sec)); then
            printf "Timeout of %i s exceeded\n" "$elapsed_sec"
            exit 1
        fi

        sleep 1
        elapsed_sec=$((elapsed_sec + 1))
        msg="$msg."
        printf "$msg\r"
    done
    printf "\n"
}

function wait_until_preimage()
{
    msg="wait until $1 has preimage for $2"
    cmd="./run_electrum --regtest -D /tmp/$1"
    declare -i timeout_sec=30
    declare -i elapsed_sec=0

    while [[ $($cmd get_invoice $2 | jq '.preimage' | tr -d '"') == "null" ]]; do
        if ((elapsed_sec > timeout_sec)); then
            printf "Timeout of %i s exceeded\n" "$elapsed_sec"
            exit 1
        fi

        sleep 1
        elapsed_sec=$((elapsed_sec + 1))
        msg="$msg."
        printf "$msg\r"
    done
    printf "\n"
}

function wait_until_spent()
{
    msg="wait until $1:$2 is spent"
    declare -i timeout_sec=30
    declare -i elapsed_sec=0

    while [[ $($bitcoin_cli gettxout $1 $2) ]]; do
        if ((elapsed_sec > timeout_sec)); then
            printf "Timeout of %i s exceeded\n" "$elapsed_sec"
            exit 1
        fi

        sleep 1
        elapsed_sec=$((elapsed_sec + 1))
        msg="$msg."
        printf "$msg\r"
    done
    printf "\n"
}

function assert_utxo_exists()
{
    utxo=$($bitcoin_cli gettxout $1 $2)
    if [[ -z "$utxo" ]]; then
        echo "utxo $1:$2 does not exist"
        exit 1
    fi
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
    $agent create --offline $USE_LEVELDB > /dev/null
    $agent setconfig --offline enable_anchor_channels $TEST_ANCHOR_CHANNELS
    $agent setconfig --offline log_to_file True
    $agent setconfig --offline use_gossip True
    $agent setconfig --offline server 127.0.0.1:51001:t
    $agent setconfig --offline lightning_to_self_delay 144
    $agent setconfig --offline test_force_disable_mpp True
    echo "funding $2"
    # note: changing the funding amount affects all tests, as they rely on "wait_for_balance"
    $bitcoin_cli sendtoaddress $($agent getunusedaddress -o -w "/tmp/$2/regtest/wallets/default_wallet") 1
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
    $agent wait_for_sync
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
    request=$($bob add_request 0.01 --lightning | jq -r ".lightning_invoice")
    echo "alice pays"
    $alice lnpay $request
    sleep 2
    ctx=$($alice get_channel_ctx $channel --iknowwhatimdoing)
    request=$($bob add_request 0.01 --lightning | jq -r ".lightning_invoice")
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
    $alice wait_for_sync
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
    prepayment=$(echo $dryrun| jq -r ".prepayment")
    swap=$($alice reverse_swap 0.02 $onchain_amount --prepayment $prepayment)
    echo $swap | jq
    funding_txid=$(echo $swap| jq -r ".funding_txid")
    new_blocks 1
    wait_until_spent $funding_txid 0
    wait_until_htlcs_settled alice
fi


if [[ $1 == "swapserver_forceclose" ]]; then
    # Alice starts reverse-swap with Bob.
    # Alice sends hold-HTLCs via LN, Bob funds locking script onchain.
    # Bob force-closes the channel, before swap-funding-tx gets mined.
    # After swap-funding-tx gets mined, Alice broadcasts onchain claim tx, revealing preimage.
    # Bob finds preimage onchain, and creates HTLC-success tx to spend own ctx htlc output onchain.
    wait_for_balance alice 1
    echo "alice opens channel"
    bob_node=$($bob nodeid)
    channel=$($alice open_channel $bob_node 0.15 --password='')
    new_blocks 3
    wait_until_channel_open alice
    echo "alice initiates swap"
    dryrun=$($alice reverse_swap 0.02 dryrun)
    onchain_amount=$(echo $dryrun| jq -r ".onchain_amount")
    prepayment=$(echo $dryrun| jq -r ".prepayment")
    swap=$($alice reverse_swap 0.02 $onchain_amount --prepayment $prepayment)
    echo $swap | jq
    funding_txid=$(echo $swap| jq -r ".funding_txid")
    ctx_id=$($bob close_channel --force $channel)
    new_blocks 1
    wait_until_spent $funding_txid 0 # alice reveals preimage
    new_blocks 1
    if [ $TEST_ANCHOR_CHANNELS = True ] ; then
        output_index=3  # received_htlc_output in bob's ctx. FIXME index depends on Alice not using MPP
    else
        output_index=1
    fi
    # wait until Bob finds preimage onchain and uses it to create an htlc_success tx
    wait_until_spent $ctx_id $output_index
    new_blocks 144
    wait_for_balance bob 0.999
    # check that the closing tx is in alice's onchain_history. Since this tx does not
    # touch alice's wallet addresses, this test requires accounting_addresses to be set
    $alice stop
    if [[ ! $($alice -o onchain_history| jq --arg txid $ctx_id '.[]|select(.txid == $txid)') ]]; then
       echo "accounting_address not set"
       exit 1
    fi
fi


if [[ $1 == "swapserver_refund" ]]; then
    # Alice starts reverse-swap with Bob.
    # Alice sends hold-HTLCs via LN, Bob funds locking script onchain.
    # Alice never broadcasts onchain claim tx. Bob will use timeout path onchain.
    # Then Bob fails hold-HTLCs via LN.
    # Channel stays open.
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
    prepayment=$(echo $dryrun| jq -r ".prepayment")
    swap=$($alice reverse_swap 0.02 $onchain_amount --prepayment $prepayment)
    echo $swap | jq
    funding_txid=$(echo $swap| jq -r ".funding_txid")
    new_blocks 140
    wait_until_spent $funding_txid 0
    new_blocks 1
    wait_until_htlcs_settled alice
fi


if [[ $1 == "lnwatcher_waits_until_fees_go_down" ]]; then
    # Alice sends two HTLCs to Bob (one for small invoice, one for large invoice), which Bob will hold.
    # Alice requests Bob to force-close the channel, while the HTLCs are pending. Bob force-closes.
    # Fee levels rise, to the point where the small HTLC is not economical to claim.
    #                  Alice sweeps the large HTLC (via onchain timeout), but not the small one.
    # Then, fee levels go back down, and Alice sweeps the small HTLC.
    # This test checks Alice does not abandon channel outputs that are temporarily ~dust due to
    # mempool spikes, and keeps watching the channel in hope of fees going down.
    $alice setconfig test_force_disable_mpp true
    $alice setconfig test_force_mpp false
    wait_for_balance alice 1
    $alice setconfig test_disable_automatic_fee_eta_update true
    $alice test_inject_fee_etas "{2:1000}"
    $bob test_inject_fee_etas "{2:1000}"
    echo "alice opens channel"
    bob_node=$($bob nodeid)
    channel=$($alice open_channel $bob_node 0.15 --password='')
    chan_funding_txid=$(echo "$channel" | cut -d ":" -f 1)
    chan_funding_outidx=$(echo "$channel" | cut -d ":" -f 2)
    new_blocks 3
    wait_until_channel_open alice
    # Alice sends an HTLC to Bob, which Bob will hold indefinitely. Alice's lnpay will time out.
    invoice1=$($bob add_hold_invoice deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbee1 \
                    --amount 0.0004 --min_final_cltv_expiry_delta 300 | jq -r ".invoice")
    invoice2=$($bob add_hold_invoice deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbee2 \
                    --amount 0.04 --min_final_cltv_expiry_delta 300 | jq -r ".invoice")
    set +e
    $alice lnpay $invoice1 --timeout 3
    $alice lnpay $invoice2 --timeout 3
    set -e
    # After a while, Alice gets impatient and gets Bob to close the channel.
    new_blocks 20
    $alice request_force_close $channel
    wait_until_spent $chan_funding_txid $chan_funding_outidx
    $bob stop  # bob closes and then disappears. FIXME this is a hack to prevent Bob claiming the fake-hold-invoice-htlc onchain
    new_blocks 1
    wait_until_channel_closed alice
    ctx_id=$($alice list_channels | jq -r ".[0].closing_txid")
    if [ $TEST_ANCHOR_CHANNELS = True ] ; then
        htlc_output_index1=2
        htlc_output_index2=3
        to_alice_index=4  # Bob's to_remote
        wait_until_spent $ctx_id $to_alice_index
    else
        htlc_output_index1=0
        htlc_output_index2=1
        to_alice_index=2
    fi
    new_blocks 1
    assert_utxo_exists $ctx_id $htlc_output_index1
    assert_utxo_exists $ctx_id $htlc_output_index2
    # fee levels rise. now small htlc is ~dust
    $alice test_inject_fee_etas "{2:300000}"
    new_blocks 300  # this goes past the CLTV of the HTLC-output in ctx
    wait_until_spent $ctx_id $htlc_output_index2
    assert_utxo_exists $ctx_id $htlc_output_index1
    new_blocks 24  # note: >20 blocks depth is considered "DEEP" by lnwatcher
    sleep 1  # give time for Alice to make mistakes, such as abandoning the channel. which it should NOT do.
    new_blocks 1
    # Alice goes offline and comes back later, 1
    $alice stop
    $alice daemon -d
    $alice test_inject_fee_etas "{2:300000}"
    $alice load_wallet
    $alice wait_for_sync
    new_blocks 1
    sleep 1  # give time for Alice to make mistakes
    # Alice goes offline and comes back later, 2
    $alice stop
    $alice daemon -d
    $alice test_inject_fee_etas "{2:300000}"
    $alice load_wallet
    $alice wait_for_sync
    new_blocks 1
    sleep 1  # give time for Alice to make mistakes
    # fee levels go down. time to claim the small htlc
    $alice test_inject_fee_etas "{2:1000}"
    new_blocks 1
    wait_until_spent $ctx_id $htlc_output_index1
    new_blocks 1
    wait_for_balance alice 0.9995
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
    request1=$($bob add_request 0.04 --lightning --memo "test1")
    invoice1=$(echo $request1 | jq -r ".lightning_invoice")
    rhash1=$(echo $request1 | jq -r ".rhash")
    screen -S alice_payment -dm -L -Logfile /tmp/alice/screen1.log $alice lnpay $invoice1 --timeout=600
    sleep 1
    unsettled=$($alice list_channels | jq '.[] | .local_unsettled_sent')
    if [[ "$unsettled" == "0" ]]; then
        echo 'enable_htlc_settle did not work (bob settled)'
        exit 1
    fi
    # bob pays alice
    request2=$($alice add_request 0.04 --lightning --memo "test2")
    invoice2=$(echo $request2 | jq -r ".lightning_invoice")
    rhash2=$(echo $request2 | jq -r ".rhash")
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
    wait_until_preimage alice $rhash1
    wait_until_preimage bob $rhash2
    # check both "lnpay" commands succeeded
    success=$(cat /tmp/alice/screen1.log | jq -r ".success")
    if [[ "$success" != "true" ]]; then echo "alice payment failed"; exit 1; fi
    success=$(cat /tmp/bob/screen2.log | jq -r ".success")
    if [[ "$success" != "true" ]]; then echo "bob payment failed"; exit 1; fi
    cat /tmp/alice/screen1.log
    cat /tmp/bob/screen2.log
fi


if [[ $1 == "redeem_offered_htlcs" ]]; then
    # alice force closes and redeems using htlc timeout
    $bob enable_htlc_settle false
    wait_for_balance alice 1
    echo "alice opens channel"
    bob_node=$($bob nodeid)
    $alice open_channel $bob_node 0.15 --password=''
    new_blocks 3
    wait_until_channel_open alice
    # alice pays bob
    invoice=$($bob add_request 0.04 --lightning --memo "test" | jq -r ".lightning_invoice")
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


if [[ $1 == "redeem_received_htlcs" ]]; then
    # bob force closes and redeems with the preimage
    $bob enable_htlc_settle false
    wait_for_balance alice 1
    echo "alice opens channel"
    bob_node=$($bob nodeid)
    $alice open_channel $bob_node 0.15 --password=''
    new_blocks 3
    wait_until_channel_open alice
    # alice pays bob
    invoice=$($bob add_request 0.04 --lightning --memo "test" | jq -r ".lightning_invoice")
    $alice lnpay $invoice --timeout=1 || true
    unsettled=$($alice list_channels | jq '.[] | .local_unsettled_sent')
    if [[ "$unsettled" == "0" ]]; then
        echo 'enable_htlc_settle did not work'
        exit 1
    fi
    $alice stop
    chan_id=$($bob list_channels | jq -r ".[0].channel_point")
    $bob close_channel $chan_id --force
    # if we exit here, bob GUI will show a warning
    new_blocks 1
    wait_for_balance bob 1.038
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
    invoice=$($bob add_request 0.04 --lightning --memo "test" | jq -r ".lightning_invoice")
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
    new_blocks 1
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
    invoice=$($bob add_request 0.04 --lightning --memo "test" | jq -r ".lightning_invoice")
    $alice lnpay $invoice --timeout=1 || true
    ctx=$($alice get_channel_ctx $channel --iknowwhatimdoing)
    unsettled=$($alice list_channels | jq '.[] | .local_unsettled_sent')
    if [[ "$unsettled" == "0" ]]; then
        echo "enable_htlc_settle did not work, $unsettled"
        exit 1
    fi
    cp -r /tmp/alice/regtest/wallets/default_wallet /tmp/alice/regtest/wallets/toxic_wallet
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
    invoice1=$($bob add_request 0.01 --lightning --memo "invoice1" | jq -r ".lightning_invoice")
    $alice lnpay $invoice1
    ctx=$($alice get_channel_ctx $channel --iknowwhatimdoing)
    echo "alice pays bob again"
    invoice2=$($bob add_request 0.01 --lightning --memo "invoice2" | jq -r ".lightning_invoice")
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

if [[ $1 == "fw_fail_htlc" ]]; then
    $carol enable_htlc_settle false
    bob_node=$($bob nodeid)
    wait_for_balance carol 1
    echo "alice and carol open channels with bob"
    chan_id1=$($alice open_channel $bob_node 0.15 --password='' --push_amount=0.075)
    chan_id2=$($carol open_channel $bob_node 0.15 --password='' --push_amount=0.075)
    new_blocks 3
    wait_until_channel_open alice
    wait_until_channel_open carol
    echo "alice pays carol"
    invoice=$($carol add_request 0.01 --lightning --memo "invoice" | jq -r ".lightning_invoice")
    screen -S alice_payment -dm -L -Logfile /tmp/alice/screen1.log $alice lnpay $invoice --timeout=600
    sleep 1
    unsettled=$($alice list_channels | jq '.[] | .local_unsettled_sent')
    if [[ "$unsettled" == "0" ]]; then
        echo 'enable_htlc_settle did not work (carol settled)'
        exit 1
    fi
    $carol stop
    ctx_id=$($bob close_channel $chan_id2 --force)
    new_blocks 1
    sleep 1
    new_blocks 150 # cltv before bob can broadcast
    # index of htlc
    if [ $TEST_ANCHOR_CHANNELS = True ] ; then
        output_index=2
    else
        output_index=0
    fi
    wait_until_spent $ctx_id $output_index
    new_blocks 1   # confirm 2nd stage.
    sleep 1
    new_blocks 100 # deep
    sleep 5        # give bob time to fail incoming htlc
    unsettled=$($alice list_channels | jq '.[] | .local_unsettled_sent')
    if [[ "$unsettled" != "0" ]]; then
        echo 'alice htlc was not failed'
        exit 1
    fi
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
    invoice=$($alice add_request 0.01 --lightning --memo "invoice" | jq -r ".lightning_invoice")
    success=$($carol lnpay $invoice| jq '.success')
    if [[ $success != "true" ]]; then
	echo "JIT payment failed"
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
