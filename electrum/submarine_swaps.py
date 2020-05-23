import asyncio
import json
import os
from .crypto import sha256, hash_160
from .ecc import ECPrivkey
from .bitcoin import address_to_script, script_to_p2wsh, redeem_script_to_address, opcodes, p2wsh_nested_script, push_script, is_segwit_address
from .transaction import TxOutpoint, PartialTxInput, PartialTxOutput, PartialTransaction, construct_witness
from .transaction import script_GetOp, match_script_against_template, OPPushDataGeneric, OPPushDataPubkey
from .transaction import Transaction
from .util import log_exceptions
from .bitcoin import dust_threshold


API_URL = 'http://ecdsa.org:9001'


WITNESS_TEMPLATE_SWAP = [
    opcodes.OP_HASH160,
    OPPushDataGeneric(lambda x: x == 20),
    opcodes.OP_EQUAL,
    opcodes.OP_IF,
    OPPushDataPubkey,
    opcodes.OP_ELSE,
    OPPushDataGeneric(None),
    opcodes.OP_CHECKLOCKTIMEVERIFY,
    opcodes.OP_DROP,
    OPPushDataPubkey,
    opcodes.OP_ENDIF,
    opcodes.OP_CHECKSIG
]


WITNESS_TEMPLATE_REVERSE_SWAP = [
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


def create_claim_tx(txin, witness_script, preimage, privkey:bytes, address, amount_sat, locktime, is_refund):
    pubkey = ECPrivkey(privkey).get_public_key_bytes(compressed=True)
    if is_segwit_address(txin.address):
        txin.script_type = 'p2wsh'
        txin.script_sig = b''
    else:
        txin.script_type = 'p2wsh-p2sh'
        txin.redeem_script = bytes.fromhex(p2wsh_nested_script(witness_script.hex()))
        txin.script_sig = bytes.fromhex(push_script(txin.redeem_script.hex()))
    txin.witness_script = witness_script
    txout = PartialTxOutput(scriptpubkey=bytes.fromhex(address_to_script(address)), value=amount_sat)
    tx = PartialTransaction.from_io([txin], [txout], version=2, locktime=(locktime if is_refund else None))
    tx.set_rbf(True)
    sig = bytes.fromhex(tx.sign_txin(0, privkey))
    witness = [sig, 0, witness_script] if is_refund else [sig, preimage, witness_script]
    txin.witness = bytes.fromhex(construct_witness(witness))
    return tx


@log_exceptions
async def _claim_swap(lnworker, lockup_address, redeem_script, preimage, privkey, address, locktime, is_refund=False):
    lnwatcher = lnworker.lnwatcher
    utxos = lnwatcher.get_addr_utxo(lockup_address)
    delta = lnwatcher.network.get_local_height() - locktime
    for txin in list(utxos.values()):
        fee = lnwatcher.config.estimate_fee(136, allow_fallback_to_static_rates=True)
        amount_sat = txin._trusted_value_sats - fee
        if amount_sat < dust_threshold():
            print('dust')
            continue
        tx = create_claim_tx(txin, redeem_script, preimage, privkey, address, amount_sat, locktime, is_refund)
        if is_refund and delta < 0:
            print('height not reached for refund', delta, locktime)
            print(tx.serialize())
        else:
            await lnwatcher.network.broadcast_transaction(tx)


@log_exceptions
async def claim_swap(key, wallet):
    lnworker = wallet.lnworker
    address = wallet.get_unused_address()
    swaps = wallet.db.get_dict('submarine_swaps')
    data = swaps[key]
    onchain_amount = data['onchainAmount']
    redeem_script = bytes.fromhex(data['redeemScript'])
    locktime = data['timeoutBlockHeight']
    lockup_address = data['lockupAddress']
    preimage = bytes.fromhex(data['preimage'])
    privkey = bytes.fromhex(data['privkey'])
    callback = lambda: _claim_swap(lnworker, lockup_address, redeem_script, preimage, privkey, address, locktime, is_refund=False)
    lnworker.lnwatcher.add_callback(lockup_address, callback)
    return True


@log_exceptions
async def refund_swap(key, wallet):
    lnworker = wallet.lnworker
    address = wallet.get_unused_address()
    swaps = wallet.db.get_dict('submarine_swaps')
    data = swaps[key]
    lockup_address = data['address']
    redeem_script = bytes.fromhex(data['redeemScript'])
    locktime = data['timeoutBlockHeight']
    preimage = bytes.fromhex(data['preimage'])
    privkey = bytes.fromhex(data['privkey'])
    callback = lambda: _claim_swap(lnworker, lockup_address, redeem_script, preimage, privkey, address, locktime, is_refund=True)
    lnworker.lnwatcher.add_callback(lockup_address, callback)
    return True


@log_exceptions
async def normal_swap(amount_sat, wallet: 'Abstract_Wallet', network: 'Network', password):
    lnworker = wallet.lnworker
    privkey = os.urandom(32)
    pubkey = ECPrivkey(privkey).get_public_key_bytes(compressed=True)
    key = await lnworker._add_request_coro(amount_sat, 'swap', expiry=3600)
    request = wallet.get_request(key)
    invoice = request['invoice']
    lnaddr = lnworker._check_invoice(invoice, amount_sat)
    payment_hash = lnaddr.paymenthash
    preimage = lnworker.get_preimage(payment_hash)
    request_data = {
        "type": "submarine",
        "pairId": "BTC/BTC",
        "orderSide": "sell",
        "invoice": invoice,
        "refundPublicKey": pubkey.hex()
    }
    response = await network._send_http_on_proxy(
        'post',
        API_URL + '/createswap',
        json=request_data,
        timeout=30)
    data = json.loads(response)
    response_id = data["id"]
    zeroconf = data["acceptZeroConf"]
    onchain_amount = data["expectedAmount"]
    locktime = data["timeoutBlockHeight"],
    lockup_address = data["address"]
    redeem_script = data["redeemScript"]
    # verify redeem_script is built with our pubkey and preimage
    redeem_script = bytes.fromhex(redeem_script)
    parsed_script = [x for x in script_GetOp(redeem_script)]
    assert match_script_against_template(redeem_script, WITNESS_TEMPLATE_SWAP)
    #assert script_to_p2wsh(redeem_script.hex()) == lockup_address
    assert redeem_script_to_address('p2wsh-p2sh', redeem_script.hex()) == lockup_address 
    assert hash_160(preimage) == parsed_script[1][1]
    assert pubkey == parsed_script[9][1]
    # verify that we will have enought time to get our tx confirmed
    assert locktime == int.from_bytes(parsed_script[6][1], byteorder='little')
    assert locktime - network.get_local_height() == 140
    # save swap data in wallet in case we need a refund
    data['privkey'] = privkey.hex()
    data['preimage'] = preimage.hex()
    swaps = wallet.db.get_dict('submarine_swaps')
    swaps[response_id] = data
    callback = lambda: _claim_swap(lnworker, lockup_address, redeem_script, preimage, privkey, address, locktime, is_refund=True)
    lnworker.lnwatcher.add_callback(lockup_address, callback)
    outputs = [PartialTxOutput.from_address_and_value(lockup_address, onchain_amount)]
    tx = wallet.create_transaction(outputs=outputs, rbf=False, password=password)
    await network.broadcast_transaction(tx)
    #
    attempt = await lnworker.await_payment(payment_hash)
    return {
        'id':response_id,
        'success':attempt.success,
    }


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
    locktime = data['timeoutBlockHeight']
    onchain_amount = data["onchainAmount"]
    response_id = data['id']
    # verify redeem_script is built with our pubkey and preimage
    redeem_script = bytes.fromhex(redeem_script)
    parsed_script = [x for x in script_GetOp(redeem_script)]
    assert match_script_against_template(redeem_script, WITNESS_TEMPLATE_REVERSE_SWAP)
    assert script_to_p2wsh(redeem_script.hex()) == lockup_address
    assert hash_160(preimage) == parsed_script[5][1]
    assert pubkey == parsed_script[7][1]
    # verify that we will have enought time to get our tx confirmed
    assert locktime == int.from_bytes(parsed_script[10][1], byteorder='little')
    assert locktime - network.get_local_height() > 10
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
    callback = lambda: _claim_swap(lnworker, lockup_address, redeem_script, preimage, privkey, address, locktime, is_refund=False)
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


@log_exceptions
async def get_pairs(network):
    response = await network._send_http_on_proxy(
        'get',
        API_URL + '/getpairs',
        timeout=30)
    data = json.loads(response)
    return data
