#!/usr/bin/env bash
export HOME=~
set -eux pipefail
cd
rm -rf $HOME/electrumx_db
mkdir $HOME/electrumx_db
COST_SOFT_LIMIT=0 COST_HARD_LIMIT=0 COIN=BitcoinSegwit SERVICES=tcp://:51001,rpc:// NET=regtest DAEMON_URL=http://doggman:donkey@127.0.0.1:18554 DB_DIRECTORY=$HOME/electrumx_db electrumx_server > $HOME/electrumx.log &
