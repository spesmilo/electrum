import attr
import asyncio
import json
import os
from typing import TYPE_CHECKING

from .crypto import sha256, hash_160
from .ecc import ECPrivkey
from .bitcoin import address_to_script, script_to_p2wsh, redeem_script_to_address, opcodes, p2wsh_nested_script, push_script, is_segwit_address
from .transaction import TxOutpoint, PartialTxInput, PartialTxOutput, PartialTransaction, construct_witness
from .transaction import script_GetOp, match_script_against_template, OPPushDataGeneric, OPPushDataPubkey
from .util import log_exceptions
from .lnutil import REDEEM_AFTER_DOUBLE_SPENT_DELAY
from .bitcoin import dust_threshold
from .logging import Logger
from .lnutil import hex_to_bytes
from .json_db import StoredObject

if TYPE_CHECKING:
    from .network import Network
    from .wallet import Abstract_Wallet


API_URL = 'https://lightning.electrum.org/api'


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


@attr.s
class SwapData(StoredObject):
    is_reverse = attr.ib(type=bool)
    locktime = attr.ib(type=int)
    onchain_amount = attr.ib(type=int)
    lightning_amount = attr.ib(type=int)
    redeem_script = attr.ib(type=bytes, converter=hex_to_bytes)
    preimage = attr.ib(type=bytes, converter=hex_to_bytes)
    privkey = attr.ib(type=bytes, converter=hex_to_bytes)
    lockup_address = attr.ib(type=str)
    funding_txid = attr.ib(type=str)
    spending_txid = attr.ib(type=str)
    is_redeemed = attr.ib(type=bool)


def create_claim_tx(txin, witness_script, preimage, privkey:bytes, address, amount_sat, locktime):
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
    tx = PartialTransaction.from_io([txin], [txout], version=2, locktime=(None if preimage else locktime))
    #tx.set_rbf(True)
    sig = bytes.fromhex(tx.sign_txin(0, privkey))
    witness = [sig, preimage, witness_script]
    txin.witness = bytes.fromhex(construct_witness(witness))
    return tx


class SwapManager(Logger):

    def __init__(self, wallet: 'Abstract_Wallet', network:'Network'):
        Logger.__init__(self)
        self.normal_fee = 0
        self.lockup_fee = 0
        self.percentage = 0
        self.min_amount = 0
        self.max_amount = 0
        self.network = network
        self.wallet = wallet
        self.lnworker = wallet.lnworker
        self.lnwatcher = self.wallet.lnworker.lnwatcher
        self.swaps = self.wallet.db.get_dict('submarine_swaps')
        for swap in self.swaps.values():
            if swap.is_redeemed:
                continue
            self.add_lnwatcher_callback(swap)

    @log_exceptions
    async def _claim_swap(self, swap):
        if not self.lnwatcher.is_up_to_date():
            return
        current_height = self.network.get_local_height()
        delta = current_height - swap.locktime
        if not swap.is_reverse and delta < 0:
            # too early for refund
            return
        txos = self.lnwatcher.get_addr_outputs(swap.lockup_address)
        for txin in txos.values():
            if swap.is_reverse and txin._trusted_value_sats < swap.onchain_amount:
                self.logger.info('amount too low, we should not reveal the preimage')
                continue
            spent_height = txin.spent_height
            if spent_height is not None:
                if spent_height > 0 and current_height - spent_height > REDEEM_AFTER_DOUBLE_SPENT_DELAY:
                    self.logger.info(f'stop watching swap {swap.lockup_address}')
                    self.lnwatcher.remove_callback(swap.lockup_address)
                    swap.is_redeemed = True
                continue
            amount_sat = txin._trusted_value_sats - self.get_claim_fee()
            if amount_sat < dust_threshold():
                self.logger.info('utxo value below dust threshold')
                continue
            address = self.wallet.get_unused_address()
            preimage = swap.preimage if swap.is_reverse else 0
            tx = create_claim_tx(txin, swap.redeem_script, preimage, swap.privkey, address, amount_sat, swap.locktime)
            await self.network.broadcast_transaction(tx)
            # save txid
            swap.spending_txid = tx.txid()

    def get_claim_fee(self):
        return self.lnwatcher.config.estimate_fee(136, allow_fallback_to_static_rates=True)

    def get_swap(self, payment_hash):
        return self.swaps.get(payment_hash.hex())

    def add_lnwatcher_callback(self, swap):
        callback = lambda: self._claim_swap(swap)
        self.lnwatcher.add_callback(swap.lockup_address, callback)

    @log_exceptions
    async def normal_swap(self, lightning_amount, expected_onchain_amount, password):
        privkey = os.urandom(32)
        pubkey = ECPrivkey(privkey).get_public_key_bytes(compressed=True)
        key = await self.lnworker._add_request_coro(lightning_amount, 'swap', expiry=3600*24)
        request = self.wallet.get_request(key)
        invoice = request['invoice']
        lnaddr = self.lnworker._check_invoice(invoice, lightning_amount)
        payment_hash = lnaddr.paymenthash
        preimage = self.lnworker.get_preimage(payment_hash)
        request_data = {
            "type": "submarine",
            "pairId": "BTC/BTC",
            "orderSide": "sell",
            "invoice": invoice,
            "refundPublicKey": pubkey.hex()
        }
        response = await self.network._send_http_on_proxy(
            'post',
            API_URL + '/createswap',
            json=request_data,
            timeout=30)
        data = json.loads(response)
        response_id = data["id"]
        zeroconf = data["acceptZeroConf"]
        onchain_amount = data["expectedAmount"]
        locktime = data["timeoutBlockHeight"]
        lockup_address = data["address"]
        redeem_script = data["redeemScript"]
        # verify redeem_script is built with our pubkey and preimage
        redeem_script = bytes.fromhex(redeem_script)
        parsed_script = [x for x in script_GetOp(redeem_script)]
        assert match_script_against_template(redeem_script, WITNESS_TEMPLATE_SWAP)
        assert script_to_p2wsh(redeem_script.hex()) == lockup_address
        assert hash_160(preimage) == parsed_script[1][1]
        assert pubkey == parsed_script[9][1]
        assert locktime == int.from_bytes(parsed_script[6][1], byteorder='little')
        # check that onchain_amount is what was announced
        assert onchain_amount <= expected_onchain_amount, (onchain_amount, expected_onchain_amount)
        # verify that they are not locking up funds for more than a day
        assert locktime - self.network.get_local_height() < 144
        # create funding tx
        outputs = [PartialTxOutput.from_address_and_value(lockup_address, onchain_amount)]
        tx = self.wallet.create_transaction(outputs=outputs, rbf=False, password=password)
        # save swap data in wallet in case we need a refund
        swap = SwapData(
            redeem_script = redeem_script,
            locktime = locktime,
            privkey = privkey,
            preimage = preimage,
            lockup_address = lockup_address,
            onchain_amount = onchain_amount,
            lightning_amount = lightning_amount,
            is_reverse = False,
            is_redeemed = False,
            funding_txid = tx.txid(),
            spending_txid = None,
        )
        self.swaps[payment_hash.hex()] = swap
        self.add_lnwatcher_callback(swap)
        await self.network.broadcast_transaction(tx)
        return tx.txid()

    @log_exceptions
    async def reverse_swap(self, amount_sat, expected_amount):
        privkey = os.urandom(32)
        pubkey = ECPrivkey(privkey).get_public_key_bytes(compressed=True)
        preimage = os.urandom(32)
        preimage_hash = sha256(preimage)
        request_data = {
            "type": "reversesubmarine",
            "pairId": "BTC/BTC",
            "orderSide": "buy",
            "invoiceAmount": amount_sat,
            "preimageHash": preimage_hash.hex(),
            "claimPublicKey": pubkey.hex()
        }
        response = await self.network._send_http_on_proxy(
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
        assert locktime == int.from_bytes(parsed_script[10][1], byteorder='little')
        # check that the amount is what we expected
        assert onchain_amount >= expected_amount, (onchain_amount, expected_amount)
        # verify that we will have enought time to get our tx confirmed
        assert locktime - self.network.get_local_height() > 10
        # verify invoice preimage_hash
        lnaddr = self.lnworker._check_invoice(invoice, amount_sat)
        assert lnaddr.paymenthash == preimage_hash
        # save swap data to wallet file
        swap = SwapData(
            redeem_script = redeem_script,
            locktime = locktime,
            privkey = privkey,
            preimage = preimage,
            lockup_address = lockup_address,
            onchain_amount = onchain_amount,
            lightning_amount = amount_sat,
            is_reverse = True,
            is_redeemed = False,
            funding_txid = None,
            spending_txid = None,
        )
        self.swaps[preimage_hash.hex()] = swap
        # add callback to lnwatcher
        self.add_lnwatcher_callback(swap)
        # initiate payment.
        success, log = await self.lnworker._pay(invoice, attempts=10)
        return success

    @log_exceptions
    async def get_pairs(self):
        response = await self.network._send_http_on_proxy(
            'get',
            API_URL + '/getpairs',
            timeout=30)
        pairs = json.loads(response)
        fees = pairs['pairs']['BTC/BTC']['fees']
        self.percentage = fees['percentage']
        self.normal_fee = fees['minerFees']['baseAsset']['normal']
        self.lockup_fee = fees['minerFees']['baseAsset']['reverse']['lockup']
        limits = pairs['pairs']['BTC/BTC']['limits']
        self.min_amount = limits['minimal']
        self.max_amount = limits['maximal']

    def get_recv_amount(self, send_amount, is_reverse):
        if send_amount is None:
            return
        if send_amount < self.min_amount or send_amount > self.max_amount:
            return
        x = send_amount
        if is_reverse:
            x = int(x * (100 - self.percentage) / 100)
            x -= self.lockup_fee
            x -= self.get_claim_fee()
        else:
            x -= self.normal_fee
            x = int(x * (100 - self.percentage) / 100)
        if x < 0:
            return
        return x

    def get_send_amount(self, recv_amount, is_reverse):
        if not recv_amount:
            return
        x = recv_amount
        if is_reverse:
            x += self.lockup_fee
            x += self.get_claim_fee()
            x = int(x * 100 / (100 - self.percentage)) + 1
        else:
            x = int(x * 100 / (100 - self.percentage)) + 1
            x += self.normal_fee
        return x

