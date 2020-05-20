import asyncio
import json
import os
from .crypto import sha256, hash_160
from .ecc import ECPrivkey
from .bitcoin import address_to_script, script_to_p2wsh, opcodes
from .transaction import TxOutpoint, PartialTxInput, PartialTxOutput, PartialTransaction, construct_witness
from .transaction import script_GetOp, match_script_against_template, OPPushDataGeneric, OPPushDataPubkey
from .transaction import Transaction
from .util import log_exceptions



API_URL = 'http://ecdsa.org:9001'

WITNESS_TEMPLATE_SWAP = [
    opcodes.OP_SIZE,
    OPPushDataGeneric(None),
    opcodes.OP_EQUAL,
    opcodes.OP_IF,
    opcodes.OP_HASH160,
    OPPushDataGeneric(lambda x: x == 20),
    opcodes.OP_EQUALVERIFY,
    OPPushDataPubkey,
    opcodes.OP_ELSE,
    opcodes.OP_DROP,
    OPPushDataGeneric(None),
    opcodes.OP_CHECKLOCKTIMEVERIFY,
    opcodes.OP_DROP,
    OPPushDataPubkey,
    opcodes.OP_ENDIF,
    opcodes.OP_CHECKSIG
]


def create_claim_tx(txin, witness_script, preimage, privkey:bytes, amount_sat, address, fee):
    pubkey = ECPrivkey(privkey).get_public_key_bytes(compressed=True)
    txin.script_type = 'p2wsh'
    txin.script_sig = b''
    txin.pubkeys = [pubkey]
    txin.num_sig = 1
    txin.witness_script = witness_script
    txin._trusted_value_sats = amount_sat
    txout = PartialTxOutput(scriptpubkey=bytes.fromhex(address_to_script(address)), value=amount_sat - fee)
    tx = PartialTransaction.from_io([txin], [txout], version=2)
    sig = bytes.fromhex(tx.sign_txin(0, privkey))
    witness = construct_witness([sig, preimage, witness_script])
    tx.inputs()[0].witness = bytes.fromhex(witness)
    assert tx.is_complete()
    return tx


@log_exceptions
async def _claim_swap(lnworker, lockup_address, redeem_script, preimage, privkey, onchain_amount, address):
    # add address to lnwatcher
    lnwatcher = lnworker.lnwatcher
    utxos = lnwatcher.get_addr_utxo(lockup_address)
    for txin in list(utxos.values()):
        fee = lnwatcher.config.estimate_fee(136, allow_fallback_to_static_rates=True)
        tx = create_claim_tx(txin, redeem_script, preimage, privkey, onchain_amount, address, fee)
        await lnwatcher.network.broadcast_transaction(tx)


@log_exceptions
async def claim_swap(key, wallet):
    lnworker = wallet.lnworker
    address = wallet.get_unused_address()
    swaps = wallet.db.get_dict('submarine_swaps')
    data = swaps[key]
    onchain_amount = data['onchainAmount']
    redeem_script = bytes.fromhex(data['redeemScript'])
    lockup_address = data['lockupAddress']
    preimage = bytes.fromhex(data['preimage'])
    privkey = bytes.fromhex(data['privkey'])
    callback = lambda: _claim_swap(lnworker, lockup_address, redeem_script, preimage, privkey, onchain_amount, address)
    lnworker.lnwatcher.add_callback(lockup_address, callback)
    return True


@log_exceptions
async def reverse_swap(amount_sat, wallet: 'Abstract_Wallet', network: 'Network'):
    privkey = os.urandom(32)
    pubkey = ECPrivkey(privkey).get_public_key_bytes(compressed=True)
    preimage = os.urandom(32)
    preimage_hash = sha256(preimage)
    address = wallet.get_unused_address()
    request_data = {
        "type": "reversesubmarine",
        "pairId": "BTC/BTC",
        "orderSide": "buy",
        "invoiceAmount": amount_sat,
        "preimageHash": preimage_hash.hex(),
        "claimPublicKey": pubkey.hex()
    }
    response = await network._send_http_on_proxy(
        'post',
        API_URL + '/createswap',
        json=request_data,
        timeout=30)
    data = json.loads(response)
    invoice = data['invoice']
    lockup_address = data['lockupAddress']
    redeem_script = data['redeemScript']
    timeout_block_height = data['timeoutBlockHeight']
    onchain_amount = data["onchainAmount"]
    response_id = data['id']
    # verify redeem_script is built with our pubkey and preimage
    redeem_script = bytes.fromhex(redeem_script)
    parsed_script = [x for x in script_GetOp(redeem_script)]
    assert match_script_against_template(redeem_script, WITNESS_TEMPLATE_SWAP)
    assert script_to_p2wsh(redeem_script.hex()) == lockup_address
    assert hash_160(preimage) == parsed_script[5][1]
    assert pubkey == parsed_script[7][1]
    # verify that we will have enought time to get our tx confirmed
    cltv = int.from_bytes(parsed_script[10][1], byteorder='little')
    assert cltv - network.get_local_height() > 10
    # verify invoice preimage_hash
    lnworker = wallet.lnworker
    lnaddr = lnworker._check_invoice(invoice, amount_sat)
    assert lnaddr.paymenthash == preimage_hash
    # save swap data in wallet in case payment fails
    data['privkey'] = privkey.hex()
    data['preimage'] = preimage.hex()
    # save data to wallet file
    swaps = wallet.db.get_dict('submarine_swaps')
    swaps[response_id] = data
    # add callback to lnwatcher
    callback = lambda: _claim_swap(lnworker, lockup_address, redeem_script, preimage, privkey, onchain_amount, address)
    lnworker.lnwatcher.add_callback(lockup_address, callback)
    # initiate payment.
    success, log = await lnworker._pay(invoice, attempts=5)
    # discard data; this should be done by lnwatcher
    if success:
        swaps.pop(response_id)
    return {
        'id':response_id,
        'success':success,
    }
