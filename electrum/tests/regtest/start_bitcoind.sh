#!/usr/bin/env bash
export HOME=~
set -eux pipefail
mkdir -p ~/.syscoin
cat > ~/.syscoin/syscoin.conf <<EOF
regtest=1
txindex=1
printtoconsole=1
rpcuser=doggman
rpcpassword=donkey
rpcallowip=127.0.0.1
zmqpubrawblock=tcp://127.0.0.1:28332
zmqpubrawtx=tcp://127.0.0.1:28333
[regtest]
rpcbind=0.0.0.0
rpcport=18554
EOF
rm -rf ~/.syscoin/regtest
screen -S syscoind -X quit || true
screen -S syscoind -m -d syscoind -regtest
sleep 6
addr=$(syscoin-cli getnewaddress)
syscoin-cli generatetoaddress 150 $addr > /dev/null
