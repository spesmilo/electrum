#!/usr/bin/env bash
export HOME=~
ARG=$1
set -eux pipefail
if [ ! -f deterministic-bitcoind-ef70f9b5 ]; then
    wget -q https://github.com/ysangkok/electrum-lightning-test/releases/download/v1/deterministic-bitcoind-ef70f9b5
    chmod +x deterministic-bitcoind-ef70f9b5
fi
if [ ! -d electrumx ]; then
    rm -f master.zip
    wget -q https://github.com/kyuupichan/electrumx/archive/master.zip
    unzip -q master.zip
    mv electrumx-master electrumx
fi
screen -S bitcoind -X quit || true
killall -9 deterministic-bitcoind-ef70f9b5 || true
sleep 1
ls -ld /.bitcoin/regtest || true
rm -rf /.bitcoin/regtest
ps -ef | grep bitcoin # bitcoin can rename itself to bitcoin-shutoff
screen -S bitcoind -m -d ./deterministic-bitcoind-ef70f9b5 -regtest
block_hash=""
while [[ "$block_hash" == "" ]]; do
    sleep 1
    block_hash=$(bitcoin-cli generatetoaddress 1 mwLZSJ2hUkvFoSkyadNGgmu9977w6K8wfj | jq -r ".[0]" || true)
done
if [[ "$ARG" != "no_determinism" ]]; then
    if [[ "$block_hash" != "40fc46e8bd87c0448ceb490b5339be674b89364c9f557e17b74b437d85b0a99c" ]]; then
        echo 'not using deterministic bitcoind'
        exit 1
    fi
fi
screen -S electrumx -X quit || true
kill -9 $(lsof -i :51001 -Fp | grep ^p | cut -c 2-) || true
sleep 1
screen -S electrumx -m -d bash -c "cd electrumx && rm -rf electrumx-db; mkdir electrumx-db && COIN=BitcoinSegwit TCP_PORT=51001 RPC_PORT=8000 NET=regtest DAEMON_URL=http://doggman:donkey@127.0.0.1:18554 DB_DIRECTORY=\$PWD/electrumx-db ./electrumx_server"
sleep 5
block_header_1="0000002006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f68514a449a154326a7eafa4a6c6fc09639afe2dedde351446a790ec72af01b74dbe5494dffff7f2000000000"
if [[ "$ARG" != "no_determinism" ]]; then
    electrumx_header_1=""
    while [[ "$electrumx_header_1" != "$block_header_1" ]]; do
        sleep 3
        electrumx_header_1=$(printf '{"id": 1, "method": "server.version", "params": ["testing", "1.4"]}\n{"id": 2, "method": "blockchain.block.header", "params": [1]}\n' | nc localhost 51001 | grep -v ElectrumX | jq -r .result)
    done
fi
screen -S elec1 -X quit || true
screen -S elec2 -X quit || true
kill -9 $(ps ax | grep run_electrum | grep -v grep | awk '{print $1}') || true
#kill -9 $(lsof -i :$(cat /tmp/elec1/regtest/daemon | python3 -c 'import ast, sys; print(ast.literal_eval(sys.stdin.read())[0][1])') -Fp | grep ^p | cut -c 2-) || true
#kill -9 $(lsof -i :$(cat /tmp/elec2/regtest/daemon | python3 -c 'import ast, sys; print(ast.literal_eval(sys.stdin.read())[0][1])') -Fp | grep ^p | cut -c 2-) || true
sleep 1
rm -rf /tmp/elec?
./run_electrum --regtest -D /tmp/elec1 restore "escape pumpkin perfect question nice all trigger course dismiss pole swallow burden"
./run_electrum --regtest -D /tmp/elec2 restore "sure razor enrich panda sustain shoe napkin brick song van embark wave"
cat > /tmp/elec2/regtest/config <<EOF
{"lightning_listen": "127.0.0.1:9735"}
EOF
ELECTRUM_DEBUG_LIGHTNING_DANGEROUS=1 screen -L -d -m -S elec1 sh -c './run_electrum --regtest -D /tmp/elec1 daemon -v -s localhost:51001:t 2>&1 | ts'
if [[ "$ARG" == "do_not_settle_elec2" ]]; then
    ELECTRUM_DEBUG_LIGHTNING_DO_NOT_SETTLE=1 ELECTRUM_DEBUG_LIGHTNING_DANGEROUS=1 screen -L -d -m -S elec2 sh -c './run_electrum --regtest -D /tmp/elec2 daemon -v -s localhost:51001:t 2>&1 | ts'
else
    ELECTRUM_DEBUG_LIGHTNING_DANGEROUS=1 screen -L -d -m -S elec2 sh -c './run_electrum --regtest -D /tmp/elec2 daemon -v -s localhost:51001:t 2>&1 | ts'
fi
sleep 3
./run_electrum --regtest -D /tmp/elec1 daemon load_wallet
./run_electrum --regtest -D /tmp/elec2 daemon load_wallet
sleep 3
