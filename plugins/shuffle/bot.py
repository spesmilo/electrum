import sys
from time import sleep, time
import argparse
import requests
import schedule

import imp
imp.load_module('electroncash', *imp.find_module('lib'))
imp.load_module('electroncash_gui', *imp.find_module('gui'))
imp.load_module('electroncash_plugins', *imp.find_module('plugins'))

from electroncash.network import Network, SimpleConfig
from electroncash.address import Address
from electroncash.bitcoin import deserialize_privkey, regenerate_key
from electroncash.networks import NetworkConstants
from electroncash_plugins.shuffle.client import bot_job
from electroncash_plugins.shuffle.coin import Coin
from electroncash.storage import WalletStorage
from electroncash.wallet import Wallet



def parse_args():
    parser = argparse.ArgumentParser(description="CashShuffle bot")
    parser.add_argument("--testnet", action="store_true", dest="testnet", default=False, help="Use Testnet")
    parser.add_argument("--ssl", action="store_true", dest="ssl", default=False, help="enable ssl")
    parser.add_argument("-P", "--port", help="cashshuffle server port", type=int, required=True)
    parser.add_argument("-I", "--stat-port", help="cashshuffle statistics server port", type=int, required=True)
    parser.add_argument("-S", "--server", help="cashshuffle server port", type=str, required=True)
    parser.add_argument("-F", "--fee", help="fee value", type=int, default=1000)
    parser.add_argument("-L", "--limit", help="minimal number of players to enter the pool", type=int, default=1)
    parser.add_argument("-M", "--maximum-per-pool", help="maximal number of players to support the pool", type=int, default=1)
    parser.add_argument("-W", "--wallet", help="wallet", type=str, required=True)
    parser.add_argument("--password", help="wallet password", type=str, default ="")
    parser.add_argument("-T", "--period", help="period for checking the server in minutes", type=int, default=10)
    return parser.parse_args()

def keys_from_priv(priv_key):
    address, secret, compressed = deserialize_privkey(priv_key)
    sk = regenerate_key(secret)
    pubk = sk.get_public_key(compressed)
    return sk, pubk

def is_protocol_done(pThread):
    if pThread.protocol:
        return pThread.protocol.done
    else:
        return pThread.done.is_set()

class SimpleLogger(object):

    def __init__(self, logchan = None):
        self.pThread = None
        self.logchan = logchan

    def send(self, message):
        if self.logchan == None:
            print("[CashShuffle Bot] {}".format(message))
        if message.startswith("Error"):
            self.pThread.done.set()
        elif message.startswith("Blame"):
            if "insufficient" in message:
                pass
            elif "wrong hash" in message:
                pass
            else:
                self.pThread.done.set()

def job():
    bot_job(stat_endpoint, host, port, network, ssl, args.limit, args.maximum_per_pool, basic_logger, SimpleLogger, wallet, password, coin, fee)

basic_logger = SimpleLogger()
args = parse_args()
# Get network
config = SimpleConfig({})
password = args.password
wallet_path = args.wallet
storage = WalletStorage(wallet_path)
if not storage.file_exists():
    basic_logger.send("Error: Wallet file not found.")
    sys.exit(0)
if storage.is_encrypted():
    storage.decrypt(password)
if args.testnet:
    NetworkConstants.set_testnet()
    config = SimpleConfig({'server':"bch0.kister.net:51002:s"})
network = Network(config)
network.start()
wallet = Wallet(storage)
wallet.start_threads(network)
coin = Coin(network)
# # setup server
port = args.port
host = args.server
stat_port = args.stat_port
ssl = args.ssl
fee = args.fee
secured = ("s" if ssl else "")
stat_endpoint = "http{}://{}:{}/stats".format(secured, host, stat_port)

schedule.every(args.period).minutes.do(job)

while True:
    schedule.run_pending()
    sleep(10)
## Delete later
network.stop()
wallet.stop_threads()
