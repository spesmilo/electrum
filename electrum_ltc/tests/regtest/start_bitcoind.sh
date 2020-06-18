#!/usr/bin/env bash
export HOME=~
set -eux pipefail
mkdir -p ~/.litecoin
cat > ~/.litecoin/litecoin.conf <<EOF
regtest=1
txindex=1
printtoconsole=1
rpcuser=doggman
rpcpassword=donkey
rpcallowip=127.0.0.1
zmqpubrawblock=tcp://127.0.0.1:28332
zmqpubrawtx=tcp://127.0.0.1:28333
fallbackfee=0.0002
[regtest]
rpcbind=0.0.0.0
rpcport=18554
EOF
rm -rf ~/.litecoin/regtest
screen -S litecoind -X quit || true
screen -S litecoind -m -d litecoind -regtest
sleep 6
addr=$(litecoin-cli getnewaddress)
litecoin-cli generatetoaddress 150 $addr > /dev/null
