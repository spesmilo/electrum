#!/usr/bin/env bash
export HOME=~
set -eux pipefail
cd
rm -rf $HOME/electrumx_db
mkdir $HOME/electrumx_db

export COST_SOFT_LIMIT=0
export COST_HARD_LIMIT=0
export COIN=Bitcoin
export SERVICES=tcp://:51001,rpc://
export NET=regtest
export DAEMON_URL=http://doggman:donkey@127.0.0.1:18554
export DB_DIRECTORY=$HOME/electrumx_db
export DAEMON_POLL_INTERVAL_BLOCKS=100
export DAEMON_POLL_INTERVAL_MEMPOOL=100

electrumx_server
