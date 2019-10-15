#!/usr/bin/env bash
export HOME=~
set -eux pipefail
mkdir -p ~/.groestlcoin
cat > ~/.groestlcoin/groestlcoin.conf <<EOF
regtest=1
txindex=1
printtoconsole=1
rpcuser=doggman
rpcpassword=donkey
rpcallowip=127.0.0.1
zmqpubrawblock=tcp://127.0.0.1:21441
zmqpubrawtx=tcp://127.0.0.1:21441
[regtest]
rpcbind=0.0.0.0
rpcport=18554
EOF
rm -rf ~/.groestlcoin/regtest
screen -S groestlcoind -X quit || true
screen -S groestlcoind -m -d groestlcoind -regtest
sleep 6
addr=$(groestlcoin-cli getnewaddress)
groestlcoin-cli generatetoaddress 150 $addr > /dev/null
