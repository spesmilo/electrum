import traceback
import sys
import json
import binascii
import asyncio
import time

from lib.bitcoin import sha256
from decimal import Decimal
from lib.constants import set_testnet, set_simnet
from lib.simple_config import SimpleConfig
from lib.network import Network
from lib.storage import WalletStorage
from lib.wallet import Wallet
from lib.lnbase import Peer, node_list
from lib.lightning_payencode.lnaddr import lnencode, LnAddr
import lib.constants as constants

if __name__ == "__main__":
    if len(sys.argv) > 2:
        host, port, pubkey = sys.argv[2:5]
    else:
        host, port, pubkey = node_list[0]
    pubkey = binascii.unhexlify(pubkey)
    port = int(port)
    if sys.argv[1] not in ["simnet", "testnet"]:
        raise Exception("first argument must be simnet or testnet")
    if sys.argv[1] == "simnet":
        set_simnet()
        config = SimpleConfig({'lnbase':True, 'simnet':True})
    else:
        set_testnet()
        config = SimpleConfig({'lnbase':True, 'testnet':True})
    # start network
    network = Network(config)
    network.start()
    asyncio.set_event_loop(network.asyncio_loop)
    # wallet
    storage = WalletStorage(config.get_wallet_path())
    wallet = Wallet(storage)
    wallet.start_threads(network)
    # start peer
    peer = Peer(host, port, pubkey, request_initial_sync=False, network=network)
    network.futures.append(asyncio.run_coroutine_threadsafe(peer.main_loop(), network.asyncio_loop))

    funding_satoshis = 200000
    push_msat = 100000

    # run blocking test
    async def async_test():
        payment_preimage = bytes.fromhex("01"*32)
        RHASH = sha256(payment_preimage)
        channel_id, per_commitment_secret_seed, local_ctx_args, remote_funding_pubkey = await peer.channel_establishment_flow(wallet, config, funding_satoshis, push_msat)
        pay_req = lnencode(LnAddr(RHASH, amount=Decimal("0.00000001")*10, tags=[('d', 'one cup of coffee')]), peer.privkey[:32])
        print("payment request", pay_req)
        last_pcs_index = 2**48 - 1
        expected_received_sat = 10
        await peer.receive_commitment_revoke_ack(channel_id, per_commitment_secret_seed, last_pcs_index, local_ctx_args, expected_received_sat, remote_funding_pubkey, next_commitment_number=1)
        htlc_id = 0 # TODO should correspond with received htlc (when handling more than just one update)
        await peer.fulfill_htlc(channel_id, htlc_id, payment_preimage)
        while True:
            await asyncio.sleep(1)
    fut = asyncio.run_coroutine_threadsafe(async_test(), network.asyncio_loop)
    while not fut.done():
        time.sleep(1)
    if fut.exception():
        try:
            raise fut.exception()
        except:
            traceback.print_exc()
    network.stop()
