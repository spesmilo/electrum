import traceback
import sys
import json
import binascii
import asyncio
import time
import os

from lib.bitcoin import sha256, COIN
from lib.util import bh2u, bfh
from decimal import Decimal
from lib.constants import set_testnet, set_simnet
from lib.simple_config import SimpleConfig
from lib.network import Network
from lib.storage import WalletStorage
from lib.wallet import Wallet
from lib.lnbase import Peer, node_list, Outpoint, ChannelConfig, LocalState, RemoteState, Keypair, OnlyPubkeyKeypair, OpenChannel, ChannelConstraints, RevocationStore
from lib.lightning_payencode.lnaddr import lnencode, LnAddr, lndecode
import lib.constants as constants

is_key = lambda k: k.endswith("_basepoint") or k.endswith("_key")

def maybeDecode(k, v):
    if k in ["short_channel_id", "pubkey", "privkey", "last_per_commitment_point", "next_per_commitment_point", "per_commitment_secret_seed"] and v is not None:
        return binascii.unhexlify(v)
    return v

def decodeAll(v):
    return {i: maybeDecode(i, j) for i, j in v.items()} if isinstance(v, dict) else v

def typeWrap(k, v, local):
    if is_key(k):
        if local:
            return Keypair(**v)
        else:
            return OnlyPubkeyKeypair(**v)
    return v

def reconstruct_namedtuples(openingchannel):
    openingchannel = decodeAll(openingchannel)
    openingchannel=OpenChannel(**openingchannel)
    openingchannel = openingchannel._replace(funding_outpoint=Outpoint(**openingchannel.funding_outpoint))
    new_local_config = {k: typeWrap(k, decodeAll(v), True) for k, v in openingchannel.local_config.items()}
    openingchannel = openingchannel._replace(local_config=ChannelConfig(**new_local_config))
    new_remote_config = {k: typeWrap(k, decodeAll(v), False) for k, v in openingchannel.remote_config.items()}
    openingchannel = openingchannel._replace(remote_config=ChannelConfig(**new_remote_config))
    new_local_state = decodeAll(openingchannel.local_state)
    openingchannel = openingchannel._replace(local_state=LocalState(**new_local_state))
    new_remote_state = decodeAll(openingchannel.remote_state)
    new_remote_state["revocation_store"] = RevocationStore.from_json_obj(new_remote_state["revocation_store"])
    openingchannel = openingchannel._replace(remote_state=RemoteState(**new_remote_state))
    openingchannel = openingchannel._replace(constraints=ChannelConstraints(**openingchannel.constraints))
    return openingchannel

def serialize_channels(channels):
    serialized_channels = []
    for chan in channels:
        namedtuples_to_dict = lambda v: {i: j._asdict() if isinstance(j, tuple) else j for i, j in v._asdict().items()}
        serialized_channels.append({k: namedtuples_to_dict(v) if isinstance(v, tuple) else v for k, v in chan._asdict().items()})
    class MyJsonEncoder(json.JSONEncoder):
        def default(self, o):
            if isinstance(o, bytes):
                return binascii.hexlify(o).decode("ascii")
            if isinstance(o, RevocationStore):
                return o.serialize()
            return super(MyJsonEncoder, self)
    dumped = MyJsonEncoder().encode(serialized_channels)
    roundtripped = json.loads(dumped)
    reconstructed = [reconstruct_namedtuples(x) for x in roundtripped]
    if reconstructed != channels:
        raise Exception("Channels did not roundtrip serialization without changes:\n" + repr(reconstructed) + "\n" + repr(channels))
    return roundtripped

if __name__ == "__main__":
    if len(sys.argv) > 3:
        host, port, pubkey = sys.argv[3:6]
    else:
        host, port, pubkey = node_list[0]
    pubkey = binascii.unhexlify(pubkey)
    port = int(port)
    if not any(x in sys.argv[1] for x in ["new_channel", "reestablish_channel"]):
        raise Exception("first argument must contain new_channel or reestablish_channel")
    if sys.argv[2] not in ["simnet", "testnet"]:
        raise Exception("second argument must be simnet or testnet")
    if sys.argv[2] == "simnet":
        set_simnet()
        config = SimpleConfig({'lnbase':True, 'simnet':True})
    else:
        set_testnet()
        config = SimpleConfig({'lnbase':True, 'testnet':True})
    # start network
    config.set_key('lightning_peers', [])
    network = Network(config)
    network.start()
    asyncio.set_event_loop(network.asyncio_loop)
    # wallet
    storage = WalletStorage(config.get_wallet_path())
    wallet = Wallet(storage)
    wallet.start_threads(network)
    # start peer
    if "new_channel" in sys.argv[1]:
        privkey = sha256(os.urandom(32))
        wallet.storage.put("channels_privkey", bh2u(privkey))
        wallet.storage.write()
    elif "reestablish_channel" in sys.argv[1]:
        privkey = wallet.storage.get("channels_privkey", None)
        assert privkey is not None
        privkey = bfh(privkey)
    peer = Peer(host, port, pubkey, privkey, network, request_initial_sync=True)
    network.futures.append(asyncio.run_coroutine_threadsafe(peer.main_loop(), network.asyncio_loop))

    funding_satoshis = 2000000
    push_msat = 1000000000

    # run blocking test
    async def async_test():
        payment_preimage = os.urandom(32)
        RHASH = sha256(payment_preimage)
        channels = wallet.storage.get("channels", None)

        if "new_channel" in sys.argv[1]:
            openingchannel = await peer.channel_establishment_flow(wallet, config, None, funding_satoshis, push_msat, temp_channel_id=os.urandom(32))
            openchannel = await peer.wait_for_funding_locked(openingchannel, wallet)
            dumped = serialize_channels([openchannel])
            wallet.storage.put("channels", dumped)
            wallet.storage.write()
        elif "reestablish_channel" in sys.argv[1]:
            if channels is None or len(channels) < 1:
                raise Exception("Can't reestablish: No channel saved")
            openchannel = channels[0]
            openchannel = reconstruct_namedtuples(openchannel)
            openchannel = await peer.reestablish_channel(openchannel)

        if "pay" in sys.argv[1]:
            addr = lndecode(sys.argv[6], expected_hrp="sb" if sys.argv[2] == "simnet" else "tb")
            payment_hash = addr.paymenthash
            pubkey = addr.pubkey.serialize()
            amt = int(addr.amount * COIN)
            openchannel = await peer.pay(wallet, openchannel, amt, payment_hash, pubkey, addr.min_final_cltv_expiry)
        elif "get_paid" in sys.argv[1]:
            expected_received_sat = 200000
            pay_req = lnencode(LnAddr(RHASH, amount=1/Decimal(COIN)*expected_received_sat, tags=[('d', 'one cup of coffee')]), peer.privkey[:32])
            print("payment request", pay_req)
            openchannel = await peer.receive_commitment_revoke_ack(openchannel, expected_received_sat, payment_preimage)

        dumped = serialize_channels([openchannel])
        wallet.storage.put("channels", dumped)
        wallet.storage.write()
    fut = asyncio.run_coroutine_threadsafe(async_test(), network.asyncio_loop)
    while not fut.done():
        time.sleep(1)
    try:
        if fut.exception():
            raise fut.exception()
    except:
        traceback.print_exc()
    else:
        print("result", fut.result())
    finally:
        network.stop()

