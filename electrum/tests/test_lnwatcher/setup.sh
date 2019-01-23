#!/usr/bin/env bash
set -eux pipefail
#this is downloading so much, and all we need is bitcoin-cli
#if [ ! -f bitcoin-*.tar.gz ]; then
#    wget https://bitcoin.org/bin/bitcoin-core-0.17.0.1/bitcoin-0.17.0.1-x86_64-linux-gnu.tar.gz
#fi
#tar xf bitcoin-*.tar.gz
#sudo mv bitcoin-0.17.0/bin/bitcoin-cli /usr/bin/
sudo wget -qO /usr/bin/bitcoin-cli https://sr.ht/e6-xS.bitcoincli # this is just bitcoin-cli from the 0.17.0.1 release, rehosted
sudo chmod +x /usr/bin/bitcoin-cli
sudo apt-get -qq update
sudo apt-get -qq install libssl1.0.0 jq netcat lsof moreutils

sudo curl "https://bootstrap.pypa.io/get-pip.py" -o "get-pip.py"
sudo python3 get-pip.py
python3 -m pip install plyvel pylru
mkdir ~/.bitcoin
cat > ~/.bitcoin/bitcoin.conf <<EOF
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
echo setup.sh done
