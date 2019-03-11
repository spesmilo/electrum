#!/usr/bin/env bash
export HOME=~
set -eux pipefail
cd
rm -rf electrumx_db
mkdir electrumx_db
COIN=BitcoinSegwit TCP_PORT=51001 RPC_PORT=8000 NET=regtest DAEMON_URL=http://doggman:donkey@127.0.0.1:18554 DB_DIRECTORY=~/electrumx_db electrumx_server > electrumx.log &
