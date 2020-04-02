#!/usr/bin/env bash
export HOME=~
set -eux pipefail
cd
rm -rf $HOME/electrumsysx_db
mkdir $HOME/electrumsysx_db
COST_SOFT_LIMIT=0 COST_HARD_LIMIT=0 COIN=Syscoin SERVICES=tcp://:51001,rpc:// NET=regtest DAEMON_URL=http://doggman:donkey@127.0.0.1:18554 DB_DIRECTORY=$HOME/electrumsysx_db electrumsysx_server > $HOME/electrumsysx.log &
